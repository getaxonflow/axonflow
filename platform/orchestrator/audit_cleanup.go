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
