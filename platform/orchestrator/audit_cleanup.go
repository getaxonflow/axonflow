// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/lib/pq"

	"axonflow/platform/shared/execution"
)

// AuditCleanupService handles periodic cleanup of expired audit log entries
// and execution history purging based on tier-aware limits from LicenseChecker.
type AuditCleanupService struct {
	db             *sql.DB
	licenseChecker LicenseChecker
	executionRepo  execution.ExecutionRepository

	// #2590 retention executor — see CleanupRetentionGovernedAudits.
	//
	// retentionEnforce gates the irreversible DELETEs for the six
	// config-governed audit tables. When false (the DEFAULT), the executor
	// runs in dry-run mode: it COUNTs the rows it WOULD delete and logs them,
	// but mutates nothing. An operator opts into destructive deletes by
	// setting AXONFLOW_AUDIT_RETENTION_ENFORCE=true.
	retentionEnforce bool

	// retentionAdminDB, when set, is the axonflow_platform_admin (BYPASSRLS)
	// pool used for retention reads/deletes. The retention executor crosses
	// orgs and touches FORCE-RLS surfaces (audit_retention_config mig 101,
	// decision_chain mig 101) that the non-BYPASSRLS axonflow_app_role pool
	// cannot see without per-org SET LOCAL. When nil, the executor falls back
	// to s.db (correct under the legacy master-role posture where RLS is
	// dormant; under app_role it silently misses cross-org/forced rows — the
	// run.go wiring logs a WARNING in that case, mirroring NodeMonitor).
	retentionAdminDB *sql.DB
}

// NewAuditCleanupService creates a new audit cleanup service.
func NewAuditCleanupService(db *sql.DB, licenseChecker LicenseChecker) *AuditCleanupService {
	return &AuditCleanupService{
		db:             db,
		licenseChecker: licenseChecker,
	}
}

// SetExecutionRepo sets the execution repository for execution history purging.
func (s *AuditCleanupService) SetExecutionRepo(repo execution.ExecutionRepository) {
	s.executionRepo = repo
}

// SetRetentionEnforce toggles the #2590 retention executor between dry-run
// (false, default — count-and-log only) and destructive (true — real DELETEs).
func (s *AuditCleanupService) SetRetentionEnforce(enforce bool) {
	s.retentionEnforce = enforce
}

// SetRetentionAdminDB injects the axonflow_platform_admin (BYPASSRLS) pool the
// retention executor uses for cross-org + FORCE-RLS surfaces. Pass nil to fall
// back to the service's primary pool.
func (s *AuditCleanupService) SetRetentionAdminDB(adminDB *sql.DB) {
	s.retentionAdminDB = adminDB
}

// StartCleanupWorker starts a background goroutine that periodically removes
// audit log entries older than the tier-configured retention period.
func (s *AuditCleanupService) StartCleanupWorker(ctx context.Context, interval time.Duration) {
	if interval == 0 {
		interval = 1 * time.Hour
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[AuditCleanup] Cleanup worker stopped")
				return
			case <-ticker.C:
				count, err := s.CleanupExpiredAuditLogs(ctx)
				if err != nil {
					log.Printf("[AuditCleanup] Audit log cleanup error: %v", err)
				} else if count > 0 {
					log.Printf("[AuditCleanup] Cleaned up %d expired audit log entries", count)
				}

				purged, err := s.PurgeExcessExecutionHistory(ctx)
				if err != nil {
					log.Printf("[AuditCleanup] Execution history purge error: %v", err)
				} else if purged > 0 {
					log.Printf("[AuditCleanup] Purged %d excess execution history records", purged)
				}

				// #2590: prune the six config-governed audit tables per
				// audit_retention_config / audit_retention_defaults. Dry-run
				// unless AXONFLOW_AUDIT_RETENTION_ENFORCE=true.
				if results, rErr := s.CleanupRetentionGovernedAudits(ctx); rErr != nil {
					log.Printf("[AuditRetention] retention executor error: %v", rErr)
				} else {
					s.logRetentionResults(results)
				}
			}
		}
	}()

	log.Printf("[AuditCleanup] Started cleanup worker (interval: %v, retention: %d days)",
		interval, s.licenseChecker.AuditRetentionDays())
}

// CleanupExpiredAuditLogs removes audit log entries older than the
// applicable retention period. Returns the total number of deleted rows
// across all tenant buckets.
//
// Per ADR-049 §3 + ADR-050 §9 the retention is per-tenant for SaaS
// Plugin tenants — Free=3d, Pro=30d, Premium=90d (locked numbers per
// PRD_TENANT_DURABILITY_AND_CLAIM). Tenants without an active
// `plugin_user_licenses` row (self-hosted, or SaaS Free without an
// explicit row) fall back to the deployment-wide retention from
// `licenseChecker.AuditRetentionDays()`.
//
// Implementation: bucket tenants by retention value, run one DELETE per
// bucket. Bounded to a small number of DELETEs (one per distinct
// retention value) regardless of tenant count. The fallback bucket
// uses `NOT (tenant_id = ANY(...))` so it cleans every audit row that
// doesn't have an explicit per-tenant policy.
func (s *AuditCleanupService) CleanupExpiredAuditLogs(ctx context.Context) (int64, error) {
	if s.db == nil {
		return 0, nil
	}

	// Per-tenant retention from active plugin_user_licenses rows. Returns
	// an empty map + nil error when the table doesn't exist (self-hosted
	// builds without the SaaS schema), which lets the fallback path
	// handle every row uniformly.
	perTenantBuckets, err := s.loadPerTenantRetentionBuckets(ctx)
	if err != nil {
		return 0, fmt.Errorf("load per-tenant retention buckets: %w", err)
	}

	now := time.Now().UTC()
	var totalDeleted int64
	tenantsWithExplicitRetention := make([]string, 0)

	for retentionDays, tenantIDs := range perTenantBuckets {
		if len(tenantIDs) == 0 || retentionDays <= 0 {
			continue
		}
		cutoff := now.AddDate(0, 0, -retentionDays)
		result, dErr := s.db.ExecContext(ctx,
			`DELETE FROM audit_logs WHERE tenant_id = ANY($1) AND timestamp < $2`,
			pq.Array(tenantIDs), cutoff)
		if dErr != nil {
			return totalDeleted, fmt.Errorf("per-tenant audit cleanup (retention=%dd): %w", retentionDays, dErr)
		}
		if n, raErr := result.RowsAffected(); raErr == nil && n > 0 {
			totalDeleted += n
		}
		tenantsWithExplicitRetention = append(tenantsWithExplicitRetention, tenantIDs...)
	}

	// Default bucket — every tenant without an explicit per-tenant policy
	// uses the deployment-wide retention.
	retentionDays := s.licenseChecker.AuditRetentionDays()
	if retentionDays <= 0 {
		return totalDeleted, nil
	}
	cutoff := now.AddDate(0, 0, -retentionDays)

	if len(tenantsWithExplicitRetention) == 0 {
		result, dErr := s.db.ExecContext(ctx,
			`DELETE FROM audit_logs WHERE timestamp < $1`, cutoff)
		if dErr != nil {
			return totalDeleted, fmt.Errorf("default audit cleanup: %w", dErr)
		}
		if n, raErr := result.RowsAffected(); raErr == nil && n > 0 {
			totalDeleted += n
		}
		return totalDeleted, nil
	}

	result, dErr := s.db.ExecContext(ctx,
		`DELETE FROM audit_logs
		  WHERE timestamp < $1
		    AND (tenant_id IS NULL OR NOT tenant_id = ANY($2))`,
		cutoff, pq.Array(tenantsWithExplicitRetention))
	if dErr != nil {
		return totalDeleted, fmt.Errorf("default audit cleanup (excluding explicit tenants): %w", dErr)
	}
	if n, raErr := result.RowsAffected(); raErr == nil && n > 0 {
		totalDeleted += n
	}
	return totalDeleted, nil
}

// loadPerTenantRetentionBuckets queries the `plugin_user_licenses` table
// for active (non-revoked) rows and groups the resulting tenants by
// retention bucket (in days). Returns an empty map + nil error when the
// table doesn't exist (self-hosted deployments without the SaaS schema)
// — that's an expected state, not a fault condition.
func (s *AuditCleanupService) loadPerTenantRetentionBuckets(ctx context.Context) (map[int][]string, error) {
	buckets := map[int][]string{}

	rows, err := s.db.QueryContext(ctx, `
		SELECT tenant_id, tier
		  FROM plugin_user_licenses
		 WHERE revoked_at IS NULL`)
	if err != nil {
		// If the table doesn't exist (self-hosted without SaaS schema),
		// treat it as "no per-tenant retention" rather than a hard
		// error — the fallback bucket will handle every row.
		if isUndefinedTableError(err) {
			return buckets, nil
		}
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var tenantID, tierName string
		if scanErr := rows.Scan(&tenantID, &tierName); scanErr != nil {
			return nil, fmt.Errorf("scan plugin_user_licenses row: %w", scanErr)
		}
		retentionDays := retentionForSaasPluginTier(tierName)
		if retentionDays <= 0 {
			continue
		}
		buckets[retentionDays] = append(buckets[retentionDays], tenantID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return buckets, nil
}

// retentionForSaasPluginTier maps a `plugin_user_licenses.tier` value to
// the retention period (in days) the cleanup loop should use for tenants
// holding that tier. Unknown tier values yield 0 (skipped — falls through
// to the default bucket).
//
// The numbers are duplicated here from `license.{Free,Pro,Premium}Limits`
// (defined under `//go:build enterprise` in tier_support.go) because
// audit_cleanup.go is loaded in BOTH community and enterprise builds.
// Single source of truth: PRD_TENANT_DURABILITY_AND_CLAIM "Free vs Paid
// Boundary" — Free=3d, Pro=30d, Premium=90d. If those numbers change,
// update both here and in tier_support.go in the same PR.
func retentionForSaasPluginTier(tierName string) int {
	switch tierName {
	case "Free":
		return 3
	case "Pro":
		return 30
	case "Premium":
		return 90
	default:
		return 0
	}
}

// isUndefinedTableError reports whether err is the postgres
// "relation does not exist" error code 42P01. We fall back gracefully
// when the SaaS schema isn't present (self-hosted deployments).
func isUndefinedTableError(err error) bool {
	if err == nil {
		return false
	}
	// We don't import pq's error codes directly to keep the dependency
	// surface narrow. The error text is stable across recent PG versions.
	return strings.Contains(err.Error(), "does not exist") &&
		strings.Contains(err.Error(), "plugin_user_licenses")
}

// RetentionCutoff returns the earliest timestamp that should be visible
// based on the current tier's retention policy.
func (s *AuditCleanupService) RetentionCutoff() time.Time {
	retentionDays := s.licenseChecker.AuditRetentionDays()
	if retentionDays <= 0 {
		return time.Time{} // no cutoff
	}
	return time.Now().UTC().AddDate(0, 0, -retentionDays)
}

// PurgeExcessExecutionHistory removes execution history records that exceed
// the tier-based MaxExecutionHistory limit per tenant.
func (s *AuditCleanupService) PurgeExcessExecutionHistory(ctx context.Context) (int64, error) {
	if s.executionRepo == nil || s.db == nil {
		return 0, nil
	}

	maxHistory := s.licenseChecker.MaxExecutionHistory()
	if maxHistory <= 0 {
		return 0, nil // unlimited
	}

	// v9 Phase 8 #2384 PR-C1 DoD-closure D-4: PurgeOldest now requires both
	// orgID + tenantID for the WithOrgAndTenantScope wrap (mig 042 RLS).
	// Fetch (org_id, tenant_id) pairs so each PurgeOldest call can pin the
	// right scope. Under axonflow_app_role this outer SELECT is itself
	// gated by mig 042's USING and returns zero rows when run with no
	// app.current_tenant_id pinned — so the whole AuditCleanupService
	// caller path MUST route on the platform_admin pool (BYPASSRLS) to
	// see all tenants. That admin-pool routing is tracked separately
	// (sister to the tenant_delete.go #2397 follow-up); this PR closes the
	// signature mismatch so the build is consistent.
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT org_id, tenant_id FROM execution_history WHERE tenant_id != '' AND org_id != ''`)
	if err != nil {
		return 0, fmt.Errorf("failed to query tenant IDs: %w", err)
	}
	defer rows.Close()

	var totalPurged int64
	for rows.Next() {
		var orgID, tenantID string
		if err := rows.Scan(&orgID, &tenantID); err != nil {
			continue
		}
		purged, err := s.executionRepo.PurgeOldest(ctx, orgID, tenantID, maxHistory)
		if err != nil {
			log.Printf("[AuditCleanup] Failed to purge execution history for tenant %s (org %s): %v", tenantID, orgID, err)
			continue
		}
		totalPurged += purged
	}

	return totalPurged, nil
}

// =============================================================================
// #2590 — config-governed audit retention executor
// =============================================================================
//
// Background. Migration 026 created `audit_retention_config` /
// `audit_retention_defaults` and a PL/pgSQL `cleanup_expired_audit_records()`,
// but (a) that function only ever archived/deleted `policy_violations`, and
// (b) nothing in the codebase ever invokes it. The audit/decision-log northstar
// design (axonflow-internal-docs AUDIT_LOG_NORTHSTAR.md; epic #2585) inventoried
// the gap: SIX tables carry a retention config row but have NO executing
// archive/delete branch — so their data is retained indefinitely past the
// configured window. That is a live compliance exposure (UU PDP / DPA deletion
// obligations, GDPR-style erasure): any "we delete after N days" commitment is
// unenforced. See #2590.
//
// `audit_logs` (the canonical decision surface) already has the tier-based Go
// worker above; `policy_violations` has the (uncalled) SQL-function branch and
// is tracked separately under the northstar Phase-3 convergence. This executor
// closes the gap for exactly the six tables named in the design doc.
//
// Design choices, deliberately conservative because deletion is irreversible:
//   - Dry-run by DEFAULT. Real DELETEs require an explicit operator opt-in
//     (AXONFLOW_AUDIT_RETENTION_ENFORCE=true). Dry-run COUNTs the exact same
//     predicate it would DELETE, so the logged "would delete" count equals the
//     eventual delete count.
//   - Effective retention per (org, table) follows get_effective_retention_days()
//     — an ACTIVE per-org override in audit_retention_config wins; otherwise the
//     system default in audit_retention_defaults; otherwise the 1825-day (5y
//     SEBI) floor; inactive override rows are ignored (org uses the default),
//     never treated as "keep forever" — BUT WITH a regulatory floor clamp the
//     SQL function lacks: the effective window is max(override, floor) where the
//     floor is the data_type's mandated default (1825d SEBI / 2555d EU AI Act).
//     An override may only EXTEND retention beyond the floor, never shorten it,
//     so the executor can NEVER delete a row still inside its mandated retention
//     window. (The SQL source has the same unclamped gap — follow-up.)
//   - Per-table column metadata is explicit (see retentionGovernedTables) because
//     the tables disagree on their age column: agent/orchestrator audit logs key
//     on `timestamp`, the rest on `created_at`. Using the wrong column would
//     delete by the wrong clock.
//   - RLS-safe: reads/deletes route through the BYPASSRLS admin pool when wired
//     (retentionAdminDB); explicit `org_id = ...` / `org_id <> ANY(...)` scoping
//     provides the isolation. Without the admin pool the executor still prunes
//     the org-unscoped tables; FORCE-RLS surfaces (audit_retention_config reads,
//     decision_chain) just go unseen under app_role — run.go logs that.
//
// NOTE: this executor performs hard DELETEs (no archive-to-cold-storage). For
// the deletion/erasure obligations that motivate #2590 that is the correct
// posture — archiving would *preserve* the data and defeat the obligation.
// Archive-before-delete for SEBI-style preservation remains a northstar Phase-3
// concern, decoupled from the deletion bug fixed here.

// EnvAuditRetentionEnforce gates the destructive path of the retention executor.
// Unset / falsy ⇒ dry-run (count + log only). Truthy ⇒ real DELETEs.
const EnvAuditRetentionEnforce = "AXONFLOW_AUDIT_RETENTION_ENFORCE"

// defaultRetentionDaysFallback is the ultimate fallback when neither an org
// override nor a system default exists for a data_type. Matches the 1825-day
// (5-year SEBI) floor in get_effective_retention_days() (migration 026).
const defaultRetentionDaysFallback = 1825

// retentionGovernedTable describes one of the six config-governed audit tables:
// its physical name, the column used as the age cutoff, and the org-scoping
// column (empty when the table has none, e.g. gateway_contexts, which is
// client_id-keyed). `dataType` is the audit_retention_config / _defaults key.
type retentionGovernedTable struct {
	dataType  string
	table     string
	tsColumn  string
	orgColumn string // "" when the table has no org/tenant column
}

// retentionGovernedTables is the SIX tables that #2585 / #2590 found configured
// but not executing. Column names verified against migrations/core:
//
//	agent_audit_logs        011 — ts `timestamp`,  org_id nullable
//	orchestrator_audit_logs 011 — ts `timestamp`,  org_id nullable
//	llm_call_audits         020 — ts `created_at`, org_id nullable (added mig 089)
//	gateway_contexts        020 — ts `created_at`, NO org column (client_id-keyed)
//	decision_chain          025 — ts `created_at`, org_id NOT NULL (FORCE RLS mig 101)
//	hitl_approval_history    025 — ts `created_at`, org_id NOT NULL (data_type "hitl_oversight")
//
// policy_violations and audit_logs are intentionally absent (handled elsewhere).
var retentionGovernedTables = []retentionGovernedTable{
	{dataType: "agent_audit_logs", table: "agent_audit_logs", tsColumn: "timestamp", orgColumn: "org_id"},
	{dataType: "orchestrator_audit_logs", table: "orchestrator_audit_logs", tsColumn: "timestamp", orgColumn: "org_id"},
	{dataType: "llm_call_audits", table: "llm_call_audits", tsColumn: "created_at", orgColumn: "org_id"},
	{dataType: "gateway_contexts", table: "gateway_contexts", tsColumn: "created_at", orgColumn: ""},
	{dataType: "decision_chain", table: "decision_chain", tsColumn: "created_at", orgColumn: "org_id"},
	{dataType: "hitl_oversight", table: "hitl_approval_history", tsColumn: "created_at", orgColumn: "org_id"},
}

// RetentionPruneResult reports the outcome for one governed table.
type RetentionPruneResult struct {
	DataType string
	Table    string
	Enforced bool  // false ⇒ dry-run (Rows is "would delete"); true ⇒ Rows actually deleted
	Rows     int64 // rows deleted (enforce) or that would be deleted (dry-run)
}

// auditRetentionEnforceEnabled reports whether destructive retention deletes are
// enabled via AXONFLOW_AUDIT_RETENTION_ENFORCE. Default (unset/falsy) is dry-run.
func auditRetentionEnforceEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvAuditRetentionEnforce))) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// retentionDB returns the pool the executor should use: the BYPASSRLS admin pool
// when wired, otherwise the service's primary pool.
func (s *AuditCleanupService) retentionDB() *sql.DB {
	if s.retentionAdminDB != nil {
		return s.retentionAdminDB
	}
	return s.db
}

// CleanupRetentionGovernedAudits prunes the six config-governed audit tables per
// their effective retention. In dry-run mode (the default) it COUNTs and returns
// the rows it WOULD delete without mutating anything; in enforce mode it DELETEs
// them. Returns one RetentionPruneResult per governed table (the slice is in the
// canonical order even when a table contributes zero rows).
func (s *AuditCleanupService) CleanupRetentionGovernedAudits(ctx context.Context) ([]RetentionPruneResult, error) {
	if s.db == nil {
		return nil, nil
	}

	db := s.retentionDB()
	enforce := s.retentionEnforce
	now := time.Now().UTC()

	results := make([]RetentionPruneResult, 0, len(retentionGovernedTables))
	for _, rt := range retentionGovernedTables {
		defaultDays, err := s.effectiveRetentionDefault(ctx, db, rt.dataType)
		if err != nil {
			return results, fmt.Errorf("retention default for %s: %w", rt.dataType, err)
		}

		overrides, err := s.loadActiveRetentionOverrides(ctx, db, rt.dataType)
		if err != nil {
			return results, fmt.Errorf("retention overrides for %s: %w", rt.dataType, err)
		}

		var tableRows int64

		// Per-org overrides — only meaningful for org-scoped tables.
		overrideOrgs := make([]string, 0, len(overrides))
		if rt.orgColumn != "" {
			for orgID, days := range overrides {
				overrideOrgs = append(overrideOrgs, orgID)

				// Regulatory floor clamp. All six governed tables are
				// SEBI / EU-AI-Act audit surfaces; their audit_retention_defaults
				// value IS the mandated minimum (1825d SEBI / 2555d EU AI Act).
				// A per-org override may only EXTEND retention beyond that floor,
				// never shorten below it — so an aggressive override can NEVER
				// erase records still inside a mandated retention window. UU PDP
				// erasure resumes the instant the floor passes. (Without this,
				// a 30-day override would delete 5-year-mandated rows. The SQL
				// source get_effective_retention_days() in migration 026 has the
				// identical unclamped gap — tracked as a follow-up.)
				effDays := max(days, defaultDays)
				if effDays != days {
					log.Printf("[AuditRetention] %s: org %q override %dd is below the %dd regulatory floor — clamping to floor", rt.dataType, orgID, days, defaultDays)
				}
				if effDays <= 0 {
					// Both override and floor non-positive (no default seeded and a
					// non-positive override). Nothing to prune; keep the org
					// excluded from the default bucket so its data is preserved,
					// never over-deleted.
					log.Printf("[AuditRetention] %s: org %q has non-positive effective retention — skipping prune", rt.dataType, orgID)
					continue
				}
				cutoff := now.AddDate(0, 0, -effDays)
				whereSQL := fmt.Sprintf("%s = $1 AND %s < $2", rt.orgColumn, rt.tsColumn)
				n, err := s.execRetention(ctx, db, rt.table, whereSQL, []interface{}{orgID, cutoff}, enforce)
				if err != nil {
					return results, fmt.Errorf("%s prune (org=%s): %w", rt.table, orgID, err)
				}
				tableRows += n
			}
		} else if len(overrides) > 0 {
			// gateway_contexts has no org column, so per-org overrides cannot be
			// scoped. Apply the default window globally and say so loudly.
			log.Printf("[AuditRetention] %s: %d per-org override(s) configured but %s has no org column — overrides cannot be honored; applying default %dd globally",
				rt.dataType, len(overrides), rt.table, defaultDays)
		}

		// Default bucket — every org without an active override.
		if defaultDays > 0 {
			cutoff := now.AddDate(0, 0, -defaultDays)
			var whereSQL string
			var args []interface{}
			if rt.orgColumn != "" && len(overrideOrgs) > 0 {
				// NULL-safe exclusion: rows with NULL org_id have no override, so
				// they belong to the default bucket and ARE pruned.
				whereSQL = fmt.Sprintf("%s < $1 AND (%s IS NULL OR NOT %s = ANY($2))", rt.tsColumn, rt.orgColumn, rt.orgColumn)
				args = []interface{}{cutoff, pq.Array(overrideOrgs)}
			} else {
				whereSQL = fmt.Sprintf("%s < $1", rt.tsColumn)
				args = []interface{}{cutoff}
			}
			n, err := s.execRetention(ctx, db, rt.table, whereSQL, args, enforce)
			if err != nil {
				return results, fmt.Errorf("%s prune (default): %w", rt.table, err)
			}
			tableRows += n
		}

		results = append(results, RetentionPruneResult{
			DataType: rt.dataType,
			Table:    rt.table,
			Enforced: enforce,
			Rows:     tableRows,
		})
	}

	return results, nil
}

// execRetention runs the retention predicate against `table`: a DELETE in
// enforce mode, a COUNT in dry-run mode. Both use the identical WHERE so the
// dry-run count equals the eventual delete count. `table` and `whereSQL` are
// built only from in-code constants (table/column names from
// retentionGovernedTables), never caller input — safe from injection; `args`
// carry the values.
func (s *AuditCleanupService) execRetention(ctx context.Context, db *sql.DB, table, whereSQL string, args []interface{}, enforce bool) (int64, error) {
	if enforce {
		result, err := db.ExecContext(ctx, "DELETE FROM "+table+" WHERE "+whereSQL, args...) //nolint:gosec // table/where are in-code constants
		if err != nil {
			return 0, err
		}
		n, raErr := result.RowsAffected()
		if raErr != nil {
			return 0, nil
		}
		return n, nil
	}

	var n int64
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE "+whereSQL, args...).Scan(&n) //nolint:gosec // table/where are in-code constants
	if err != nil {
		return 0, err
	}
	return n, nil
}

// effectiveRetentionDefault returns the system-default retention (days) for a
// data_type from audit_retention_defaults, falling back to the 1825-day floor
// when there is no row or the table is absent (self-hosted without mig 026).
func (s *AuditCleanupService) effectiveRetentionDefault(ctx context.Context, db *sql.DB, dataType string) (int, error) {
	var days int
	err := db.QueryRowContext(ctx,
		`SELECT retention_days FROM audit_retention_defaults WHERE data_type = $1`, dataType).Scan(&days)
	switch {
	case err == sql.ErrNoRows:
		return defaultRetentionDaysFallback, nil
	case err != nil && isRelationDoesNotExist(err):
		return defaultRetentionDaysFallback, nil
	case err != nil:
		return 0, err
	}
	return days, nil
}

// loadActiveRetentionOverrides returns org_id → retention_days for the ACTIVE
// audit_retention_config rows of a data_type (matching the is_active=true gate
// of get_effective_retention_days). Returns an empty map when the table is
// absent. Under app_role without the admin pool this FORCE-RLS table yields no
// rows (no org context) — a safe degradation: every org uses the default.
func (s *AuditCleanupService) loadActiveRetentionOverrides(ctx context.Context, db *sql.DB, dataType string) (map[string]int, error) {
	overrides := map[string]int{}
	rows, err := db.QueryContext(ctx,
		`SELECT org_id, retention_days FROM audit_retention_config WHERE data_type = $1 AND is_active = true`, dataType)
	if err != nil {
		if isRelationDoesNotExist(err) {
			return overrides, nil
		}
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var orgID string
		var days int
		if scanErr := rows.Scan(&orgID, &days); scanErr != nil {
			return nil, fmt.Errorf("scan audit_retention_config row: %w", scanErr)
		}
		overrides[orgID] = days
	}
	return overrides, rows.Err()
}

// logRetentionResults emits a concise summary of a retention pass.
func (s *AuditCleanupService) logRetentionResults(results []RetentionPruneResult) {
	var total int64
	for _, r := range results {
		total += r.Rows
	}
	if total == 0 {
		return
	}
	verb := "would delete (dry-run)"
	if s.retentionEnforce {
		verb = "deleted"
	}
	log.Printf("[AuditRetention] %s %d expired audit row(s) across %d governed table(s)", verb, total, len(results))
	for _, r := range results {
		if r.Rows > 0 {
			log.Printf("[AuditRetention]   %s: %d", r.Table, r.Rows)
		}
	}
}

// isRelationDoesNotExist reports whether err is the postgres "relation does not
// exist" error (SQLSTATE 42P01) for ANY table. Mirrors isUndefinedTableError but
// is not pinned to a specific relation name — used by the retention executor so
// a self-hosted build missing migration 026 degrades to defaults instead of
// erroring.
func isRelationDoesNotExist(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "does not exist") &&
		(strings.Contains(msg, "42P01") || strings.Contains(msg, "relation"))
}
