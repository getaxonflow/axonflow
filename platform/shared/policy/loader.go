package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"time"

	"axonflow/platform/agent/rls"
)

// globalTenantSentinel is the tenant_id/org_id wildcard used by system-seeded
// policies that apply across all tenants (mig 010's DEFAULT 'global'; mig 153
// backfilled org_id='global' onto those rows so they are reachable under a
// 'global'-scoped RLS read).
const globalTenantSentinel = "global"

// ErrEmptySystemPolicySet is returned by a SUCCESSFUL policy load whose result
// contains ZERO system-tier (tier='system' / tenant_id='global') policies.
//
// Every migrated deployment seeds system static policies (mig 010/031/035/059/
// 116/...), and system-tier policies cannot be disabled via the API — so a
// clean zero-system-row load is an impossible state on a healthy deployment.
// It is exactly how #3048 (and #2689 before it) escaped the gates: RLS-blind
// reads returned zero rows WITHOUT an error, the engine evaluated nothing, and
// the content planes allowed everything. Callers (EvaluateRequest #2862,
// EvaluateResponse #2820) treat this error like any other load failure and
// fail CLOSED; the distinct sentinel + the policy_load_empty_system_set log
// line/metric let operators tell "policy data unreachable" apart from
// "database unavailable".
var ErrEmptySystemPolicySet = errors.New(
	"policy_load_empty_system_set: policy load succeeded but returned zero system-tier policies " +
		"(migration-seeded system policies are unreachable — likely an RLS-scoped read on a mis-provisioned " +
		"deployment or missing migrations); failing closed")

// PolicyLoader loads policies from the database with caching.
//
// Decision 5 (#3490) removed two unused query templates that used to live on
// this struct (queryRequestPhase / queryResponsePhase, built by an initQueries
// method). Both carried the `tenant_id = $1 OR tenant_id = 'global'` predicate
// this change retires - and neither was ever executed: nothing outside
// initQueries read either field, and loadFromDatabase has always built its own
// query. They are deleted rather than rewritten, because rewriting a query no
// caller runs would have produced a second, untested definition of the
// selection rule that the next reader would have to reconcile against the real
// one.
type PolicyLoader struct {
	db    *sql.DB
	cache *PolicyCache
}

// NewPolicyLoader creates a new policy loader.
func NewPolicyLoader(db *sql.DB, cache *PolicyCache) *PolicyLoader {
	return &PolicyLoader{
		db:    db,
		cache: cache,
	}
}

// GetPolicies retrieves policies for a tenant and phase from cache or database.
//
// Caching/staleness contract (#3048 item-10 guard): a load that fails —
// including ErrEmptySystemPolicySet — is NEVER cached, so the fail-closed
// state does not stick for the TTL after the DB recovers; every subsequent
// request re-attempts the load. Conversely a previously cached GOOD set is
// never invalidated by one bad refresh: Set only runs on success, and the
// good entry serves until its own TTL expires. After expiry, requests fail
// closed until the next successful load.
func (l *PolicyLoader) GetPolicies(ctx context.Context, tenantID string, orgID *string, phase Phase) ([]CompiledPolicy, error) {
	// Check cache first
	if policies, found := l.cache.Get(tenantID, orgID, phase); found {
		return policies, nil
	}

	// Load from database
	policies, err := l.loadFromDatabase(ctx, tenantID, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	// Cache the policies
	l.cache.Set(tenantID, orgID, policies)

	// Return filtered by phase
	return l.filterByPhase(policies, phase), nil
}

// loadFromDatabase loads all policies applicable to a caller's ORGANIZATION.
//
// static_policies is RLS-enabled (mig 018, org_id = get_current_org_id()).
// The old single bare read admitted the tenant's rows AND the 'global'
// wildcard rows in SQL — but under axonflow_app_role the unset GUC made RLS
// match ZERO rows silently, so the unified engine loaded nothing and both
// content planes evaluated nothing (#3048; observed live: check-input with
// `DROP TABLE` + SSN returned allowed with policies_evaluated=0). A single
// GUC can only unlock one org's rows at a time, so the read is two DISJOINT
// scoped passes - the caller's org scope and the 'global' scope - merged and
// re-sorted.
//
// Decision 5 (#3490): the per-pass predicate is now `org_id = $1`, not
// `tenant_id = $1`. tenant_id is the Basic-auth USERNAME (db_auth.go's
// Client.TenantID), validated by nothing, so keying selection on it let any
// caller choose which policy set it was governed by - including a name no
// policy targets, which evaded every tenant-tier policy in the org. org_id
// comes from the signed license payload and is the key RLS already isolates
// on, so selection and isolation now agree.
//
// The predicate is EXPLICIT rather than delegated to RLS. On an app-role
// deployment `WithOrgScope` would bound the read on its own; on an
// owner-pool deployment (the local-dev and self-hosted default -
// AXONFLOW_DB_USE_APP_ROLE defaults to false) RLS is bypassed entirely and
// this WHERE clause is the whole boundary. Dropping the predicate and
// "relying on the RLS scope" would have turned the org pass into an
// unfiltered cross-ORG read on exactly those deployments. It also keeps the
// two passes disjoint, so nothing double-counts (mirrors #3040's
// PolicyRepository.List shape).
//
// tenantID survives only as the cache key's first component (see GetPolicies)
// and as row attribution; it no longer decides which rows are read.
//
// segment_id is SELECTed but deliberately NOT filtered on (#3266): unlike
// StaticPolicyRepository.GetEffective (platform/agent/
// static_policy_repository.go), which filters `sp.segment_id IS NULL OR
// sp.segment_id = ANY($N)` in SQL because it is called per-caller, this
// loader's result is cached PER-(tenant, org) and shared across every
// caller in that scope regardless of segment membership - filtering here
// would fragment the cache key by segment set. Instead every row loads
// (segment-scoped or not) and UnifiedPolicyEngine.filterBySegments
// applies the identical applicability rule at evaluation time, per
// request, using each caller's own EvalOptions.Segments.
func (l *PolicyLoader) loadFromDatabase(ctx context.Context, tenantID string, orgID *string) ([]CompiledPolicy, error) {
	if l.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	// $1 is filled with the org scope being read, so the org pass and the
	// global pass return disjoint sets with or without RLS enforcement.
	query := `
		SELECT
			id, policy_id, name, category, tier, pattern, severity,
			description, phase, action_request, action_response,
			enabled, priority, tenant_id, segment_id, metadata,
			created_at
		FROM static_policies
		WHERE enabled = true
		  AND deleted_at IS NULL
		  AND org_id = $1
		ORDER BY priority DESC, created_at ASC
	`

	// The license org when the caller supplied one; otherwise the
	// org_id == tenant_id identity every v9 backfill (mig 094) and every
	// agent write path preserves for single-tenant orgs. Migration 165
	// guarantees no row reaches here with a NULL or empty org_id.
	scopeOrg := tenantID
	if orgID != nil && *orgID != "" {
		scopeOrg = *orgID
	}

	// An empty scope selects nothing and is not a valid org scope key
	// (WithOrgScope rejects it), so an unbound caller degrades to the global
	// baseline alone rather than issuing an unscoped read. The 'global'
	// sentinel is excluded here because the pass below already reads it;
	// admitting it twice would double-count on an owner-pool deployment.
	var rows []policyRow
	var err error
	if scopeOrg != "" && scopeOrg != globalTenantSentinel {
		rows, err = l.scopedPolicyRows(ctx, query, scopeOrg)
		if err != nil {
			return nil, err
		}
	}
	globalRows, gErr := l.scopedPolicyRows(ctx, query, globalTenantSentinel)
	if gErr != nil {
		return nil, gErr
	}
	rows = append(rows, globalRows...)

	// Re-establish the single-query ORDER BY (priority DESC, created_at ASC)
	// across the merged tenant+global sets — evaluation order decides which
	// policy reports a block first.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Priority != rows[j].Priority {
			return rows[i].Priority > rows[j].Priority
		}
		return rows[i].CreatedAt.Before(rows[j].CreatedAt)
	})

	var policies []CompiledPolicy
	systemCount := 0
	for _, p := range rows {
		compiled, cErr := l.compilePolicy(p)
		if cErr != nil {
			log.Printf("[PolicyLoader] Error compiling policy %s: %v", p.PolicyID, cErr)
			continue
		}
		if compiled.Tier == "system" || compiled.TenantID == globalTenantSentinel {
			systemCount++
		}
		policies = append(policies, *compiled)
	}

	// #3048 item-10 invariant guard: a successful load with ZERO system-tier
	// policies is an impossible state on a healthy migrated deployment (the
	// mig-010/031/... seeds always exist and cannot be disabled via API), so
	// it must fail the load — routing through the same fail-closed paths as a
	// DB outage (#2862 request plane, #2820 response plane) — rather than let
	// the gates evaluate nothing and allow everything. Distinct log + error
	// so operators can tell it apart from an unavailable DB.
	if systemCount == 0 {
		log.Printf("[PolicyLoader] policy_load_empty_system_set: load for tenant=%s scope=%s returned %d policies but 0 system-tier — failing closed (#3048)",
			tenantID, scopeOrg, len(policies))
		return nil, ErrEmptySystemPolicySet
	}

	return policies, nil
}

// scopedPolicyRows runs the org-predicated policy query inside a WithOrgScope
// transaction (SET LOCAL app.current_org_id = scopeOrg) and returns the
// scanned rows.
//
// Decision 5 (#3490): scopeOrg fills BOTH the RLS GUC and the query's $1
// org_id predicate, and there is deliberately no second argument to let them
// diverge. The pre-Decision-5 signature took the GUC and the predicate value
// separately (scopeOrg, tenantArg) because they keyed different columns; with
// one key there is no legitimate call that wants them different, and a
// parameter that admits one is a parameter a future caller will use.
func (l *PolicyLoader) scopedPolicyRows(ctx context.Context, query, scopeOrg string) ([]policyRow, error) {
	var out []policyRow
	err := rls.WithOrgScope(ctx, l.db, scopeOrg, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, scopeOrg)
		if qErr != nil {
			return fmt.Errorf("query failed: %w", qErr)
		}
		defer rows.Close()

		for rows.Next() {
			var p policyRow
			if sErr := rows.Scan(
				&p.ID, &p.PolicyID, &p.Name, &p.Category, &p.Tier, &p.Pattern,
				&p.Severity, &p.Description, &p.Phase, &p.ActionRequest, &p.ActionResponse,
				&p.Enabled, &p.Priority, &p.TenantID, &p.SegmentID, &p.Metadata,
				&p.CreatedAt,
			); sErr != nil {
				log.Printf("[PolicyLoader] Error scanning row: %v", sErr)
				continue
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// policyRow represents a row from the static_policies table.
type policyRow struct {
	ID             string
	PolicyID       string
	Name           string
	Category       string
	Tier           string
	Pattern        string
	Severity       string
	Description    sql.NullString
	Phase          sql.NullString
	ActionRequest  sql.NullString
	ActionResponse sql.NullString
	Enabled        bool
	Priority       int
	TenantID       string
	SegmentID      sql.NullString
	Metadata       json.RawMessage
	CreatedAt      time.Time
}

// compilePolicy converts a database row to a CompiledPolicy.
func (l *PolicyLoader) compilePolicy(row policyRow) (*CompiledPolicy, error) {
	// Compile regex pattern
	re, err := regexp.Compile(row.Pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}

	// Parse phase
	phase := PhaseBoth
	if row.Phase.Valid {
		phase = Phase(row.Phase.String)
	}

	// Parse actions
	var actionRequest, actionResponse Action
	if row.ActionRequest.Valid {
		actionRequest = Action(row.ActionRequest.String)
	}
	if row.ActionResponse.Valid {
		actionResponse = Action(row.ActionResponse.String)
	}

	// Parse segment ID (#3266): "" (NULL) means not segment-scoped, matching
	// the zero-value contract CompiledPolicy.AppliesToSegments relies on.
	segmentID := ""
	if row.SegmentID.Valid {
		segmentID = row.SegmentID.String
	}

	// Get description
	description := ""
	if row.Description.Valid {
		description = row.Description.String
	}

	return &CompiledPolicy{
		ID:             row.ID,
		PolicyID:       row.PolicyID,
		Name:           row.Name,
		Category:       PolicyCategory(row.Category),
		Tier:           row.Tier,
		Pattern:        re,
		PatternStr:     row.Pattern,
		Severity:       Severity(row.Severity),
		Description:    description,
		Phase:          phase,
		ActionRequest:  actionRequest,
		ActionResponse: actionResponse,
		Enabled:        row.Enabled,
		Priority:       row.Priority,
		TenantID:       row.TenantID,
		SegmentID:      segmentID,
		Validator:      l.getValidatorForPolicy(row.PolicyID, PolicyCategory(row.Category)),
	}, nil
}

// getValidatorForPolicy returns the appropriate validator for a policy.
//
// Selection is by PII-type token within the policy ID (so "sys_pii_email" → the
// email validator), falling back to the category default only when no token
// matches. The previous exact-match GetValidatorByType(policyID) never matched a
// "sys_pii_*" ID against the bare type-keyed registry, so EVERY pii-global policy
// fell back to the category default (the credit-card validator) and email/phone/ip
// detection was inert on every DB-loaded path. See ValidatorForPolicyID for the
// full per-policy resolution change (incl. PAN and the two locale phone policies).
func (l *PolicyLoader) getValidatorForPolicy(policyID string, category PolicyCategory) ValidatorFunc {
	if validator := ValidatorForPolicyID(policyID); validator != nil {
		return validator
	}
	return GetValidatorForCategory(category)
}

// filterByPhase filters policies by evaluation phase.
func (l *PolicyLoader) filterByPhase(policies []CompiledPolicy, phase Phase) []CompiledPolicy {
	var filtered []CompiledPolicy

	for _, p := range policies {
		switch phase {
		case PhaseRequest:
			if p.Phase == PhaseRequest || p.Phase == PhaseBoth {
				filtered = append(filtered, p)
			}
		case PhaseResponse:
			if p.Phase == PhaseResponse || p.Phase == PhaseBoth {
				filtered = append(filtered, p)
			}
		case PhaseBoth:
			filtered = append(filtered, p)
		}
	}

	return filtered
}

// RefreshAll refreshes the cache for all tenants.
func (l *PolicyLoader) RefreshAll(ctx context.Context) error {
	startTime := time.Now()

	// Get list of all tenants from cache
	// In a real implementation, this would query for active tenants
	l.cache.InvalidateAll()

	// Record refresh time
	l.cache.SetLastRefresh(time.Since(startTime))

	return nil
}

// LoadSystemPolicies loads system-tier policies (global, immutable).
//
// System-tier rows carry tenant_id='global' + org_id='global' (mig 153), so
// under app-role RLS the read runs in the 'global' org scope (#3048). No
// disjointness concern — this is a single-scope read; the tier predicate is
// unchanged for owner-pool deployments.
func (l *PolicyLoader) LoadSystemPolicies(ctx context.Context) ([]CompiledPolicy, error) {
	if l.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	// segment_id is SELECTed for consistency with the other static_policies
	// readers (#3266), though system-tier rows are never segment-scoped in
	// practice — StaticPolicyRepository.GetEffective only applies the
	// segment predicate to organization/tenant-tier rows.
	query := `
		SELECT
			id, policy_id, name, category, tier, pattern, severity,
			description, phase, action_request, action_response,
			enabled, priority, tenant_id, segment_id, metadata
		FROM static_policies
		WHERE enabled = true
		  AND deleted_at IS NULL
		  AND tier = 'system'
		ORDER BY priority DESC, created_at ASC
	`

	var policies []CompiledPolicy
	err := rls.WithOrgScope(ctx, l.db, globalTenantSentinel, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query)
		if qErr != nil {
			return fmt.Errorf("query failed: %w", qErr)
		}
		defer rows.Close()

		for rows.Next() {
			var p policyRow
			if sErr := rows.Scan(
				&p.ID, &p.PolicyID, &p.Name, &p.Category, &p.Tier, &p.Pattern,
				&p.Severity, &p.Description, &p.Phase, &p.ActionRequest, &p.ActionResponse,
				&p.Enabled, &p.Priority, &p.TenantID, &p.SegmentID, &p.Metadata,
			); sErr != nil {
				continue
			}

			compiled, cErr := l.compilePolicy(p)
			if cErr != nil {
				continue
			}

			policies = append(policies, *compiled)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return policies, nil
}

// =============================================================================
// Effective-policy read (#3296 Slice 2 Step B/E) -- the tier-hierarchy read
// StaticPolicyRepository.GetEffective (platform/agent) needs.
//
// GetEffective additionally needs tags/version/audit-trail columns the
// pattern-matching CompiledPolicy shape does not carry, and applies its own
// tier-specific WHERE predicate per pass (system / organization+segment /
// tenant+segment) plus SQL-level segment_id filtering (unlike loadFromDatabase
// above, which selects but does not filter segment_id in SQL -- see that
// method's doc for why: GetEffective is a per-caller read, not a
// per-(tenant,org) cached read, so filtering in SQL here does not fragment
// any cache). This is the SINGLE place static_policies is queried for the
// effective-policy path -- StaticPolicyRepository must not issue its own SQL
// against static_policies; policy_overrides (a DIFFERENT table) is read
// separately by StaticPolicyRepository itself and reconciled via
// EffectiveOverride (see override.go).
// =============================================================================

// effectivePolicyColumns lists, in order, the columns EffectivePolicyRow scans.
const effectivePolicyColumns = `
	sp.id, sp.policy_id, sp.name, sp.category, sp.pattern, sp.severity,
	sp.description, sp.action, sp.tier, sp.priority, sp.enabled,
	sp.tenant_id, sp.org_id, sp.segment_id,
	sp.tags, sp.metadata, sp.version,
	sp.created_at, sp.updated_at, sp.created_by, sp.updated_by
`

// effectivePolicyQueryTemplate is GetEffective's per-pass query shape. %s is
// filled with the caller-supplied tier predicate (see ScanEffectivePolicyRows).
const effectivePolicyQueryTemplate = `
	SELECT` + effectivePolicyColumns + `
	FROM static_policies sp
	WHERE sp.deleted_at IS NULL
	  AND sp.enabled = true
	  AND %s
`

// EffectivePolicyColumnNames returns, in order, the unqualified column names
// this query selects and ScanEffectivePolicyRows scans.
//
// It exists so a sqlmock fixture can DERIVE its column list instead of
// hand-copying it. A hand-copied list is a second, unowned statement of the
// column order that drifts silently: when #3334 retired the legacy
// organization_id column from the SELECT, one fixture kept naming it at index
// 11, so the scan read a NULL organization_id into TenantID (a value-typed
// string) and every row failed with
//
//	sql: Scan error on column index 11, name "organization_id":
//	converting NULL to string is unsupported
//
// A positional scan list is silently wrong the moment a column list changes,
// and the two readers that swallow the scan error (this one logs and
// continues, StaticPolicyRepository's list path continues without logging)
// turn that into "zero policies" rather than a failure.
func EffectivePolicyColumnNames() []string {
	raw := strings.Split(effectivePolicyColumns, ",")
	out := make([]string, 0, len(raw))
	for _, c := range raw {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		out = append(out, strings.TrimPrefix(c, "sp."))
	}
	return out
}

// EffectivePolicyRow is one static_policies row as read for the GetEffective
// (tier-hierarchy admin/API) path. Column set and nullability mirror the
// pre-#3296 StaticPolicyRepository.GetEffective query exactly, so existing
// callers' sqlmock expectations (column order, arg order) keep matching
// verbatim after the read moved here.
type EffectivePolicyRow struct {
	ID          string
	PolicyID    string
	Name        string
	Category    string
	Pattern     string
	Severity    string
	Description sql.NullString
	Action      string
	Tier        string
	Priority    int
	Enabled     bool
	TenantID    string
	OrgID       sql.NullString
	SegmentID   sql.NullString
	Tags        sql.NullString
	Metadata    sql.NullString
	Version     int
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CreatedBy   sql.NullString
	UpdatedBy   sql.NullString
}

// ScanEffectivePolicyRows executes GetEffective's per-pass static_policies
// query against an ALREADY-OPEN transaction and returns the scanned rows.
// tierPredicate is the caller-supplied (hardcoded, never request-derived)
// WHERE fragment selecting one tier scope (system / organization / tenant) --
// GetEffective's tier semantics live at the call site, unchanged; only SQL
// execution moved here.
//
// Deliberately tx-scoped rather than db-owning: the caller (StaticPolicyRepository
// .GetEffective) wraps this in rls.WithOrgScope itself so it can read
// policy_overrides (a different table) inside the SAME transaction/RLS scope,
// exactly as the pre-#3296 single-file implementation did -- this preserves
// that atomicity and, not incidentally, keeps every existing sqlmock
// Begin/Query/Query/Commit expectation shape unchanged.
func ScanEffectivePolicyRows(ctx context.Context, tx *sql.Tx, tierPredicate string, args ...interface{}) ([]EffectivePolicyRow, error) {
	query := fmt.Sprintf(effectivePolicyQueryTemplate, tierPredicate)
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var out []EffectivePolicyRow
	for rows.Next() {
		var p EffectivePolicyRow
		if sErr := rows.Scan(
			&p.ID, &p.PolicyID, &p.Name, &p.Category, &p.Pattern, &p.Severity,
			&p.Description, &p.Action, &p.Tier, &p.Priority, &p.Enabled,
			&p.TenantID, &p.OrgID, &p.SegmentID,
			&p.Tags, &p.Metadata, &p.Version,
			&p.CreatedAt, &p.UpdatedAt, &p.CreatedBy, &p.UpdatedBy,
		); sErr != nil {
			log.Printf("[PolicyLoader] Error scanning effective-policy row: %v", sErr)
			continue
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CountActive counts active (enabled=true) dynamic_policies rows for a
// tenant, RLS-scoped identically to the bespoke read it replaces
// (platform/agent/mcp_v1_pro_tools.go's deleted countActiveTenantPolicies).
//
// #3296 Step E / epic #3293 item #22: the substrate (this package) is a
// shared library that spans the agent and orchestrator services, so this is
// an IN-PROCESS method call from the agent, never a cross-service RPC. It
// counts dynamic_policies (NOT static_policies -- the Free-tier
// active_policies quota this backs is about custom dynamic policies, per the
// original bespoke read's own doc comment), so it lives on PolicyLoader as an
// additive capability rather than folding into the static effective-policy
// read above.
//
// Callers MUST keep the fail-open contract the bespoke read had (return 0 on
// error so a transient DB blip does not block a Free user) but MUST also
// observe the returned error to emit a metric -- a silent fail-open is a
// silent quota bypass (#3039/#2230 family). This method itself returns the
// error rather than swallowing it, so the metric emission stays at the
// call site (platform/agent, which owns the metric registration).
func (l *PolicyLoader) CountActive(ctx context.Context, tenantID string) (int, error) {
	if l.db == nil {
		return 0, fmt.Errorf("database connection not available")
	}
	var count int
	err := rls.WithOrgScope(ctx, l.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM dynamic_policies WHERE tenant_id = $1 AND enabled = true`,
			tenantID).Scan(&count)
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// =============================================================================
// Dynamic-policy gate-cache read (#3319 / epic #3293) -- the verdict-path
// read DatabaseDynamicPolicyEngine (platform/orchestrator) needs to rebuild
// its in-process policy cache. This is the SINGLE place dynamic_policies is
// queried on a verdict path; policy_api_repository.go and
// overrides_handler.go (platform/orchestrator) issue their own SQL against
// dynamic_policies too, but only for admin CRUD / override lookups, never
// for a gate-eval verdict.
// =============================================================================

// DynamicPolicyRow is one dynamic_policies row as read by
// RefreshDynamicPolicies or counted by CountAllDynamicPolicies. The column
// set mirrors exactly what DatabaseDynamicPolicyEngine.refreshPolicies
// needs to rebuild its cache: ADR-044's RiskLevel/AllowOverride for override
// enforcement, Description/ID for AppliedPoliciesDetail, SegmentID
// (ADR-060 #2989 P3b) when the caller's deployment has migration 159, and
// CreatedAt (#3321 follow-up) so the cache can reproduce this query's own
// `ORDER BY priority DESC, created_at DESC` at evaluation time instead of
// discarding it the moment rows land in a map -- see
// DatabaseDynamicPolicyEngine's sortedDynamicPolicyEntries.
//
// SegmentID is only scanned when the caller uses withSegment=true in
// RefreshDynamicPolicies -- on a withSegment=false call it is always the
// zero value (Valid=false), which the caller already treats identically to
// a genuine SQL NULL ("not segment-scoped").
type DynamicPolicyRow struct {
	ID          string
	Name        string
	Description string
	Conditions  string
	Actions     string
	TenantID    sql.NullString
	// OrgID is the row's org_id -- the key Decision 5 (#3490) made the
	// dynamic gate's applicability test read instead of TenantID. It is
	// selected unconditionally (mig 010 declared the column, so unlike
	// SegmentID it needs no missing-column retry) and migration 165
	// guarantees it is neither NULL nor empty on any row this query can
	// return. It is typed NullString anyway so a row written by a
	// pre-165 deployment mid-upgrade scans rather than erroring the whole
	// refresh; the caller treats an invalid OrgID as "applies to nobody".
	OrgID         sql.NullString
	Priority      int
	PolicyID      string
	PolicyType    string
	Category      string
	RiskLevel     string
	AllowOverride bool
	CreatedAt     sql.NullTime
	SegmentID     sql.NullString
}

// dynamicPoliciesQueryWithSegment / dynamicPoliciesQueryWithoutSegment: two
// shapes of the same SELECT, relocated byte-identically from the orchestrator
// (#3319/#3293 convergence) so RefreshDynamicPolicies can retry column-less
// against a not-yet-migrated dynamic_policies table -- see the caller's
// isMissingColumnError doc (platform/orchestrator/segment_column_probe.go,
// H3 / #3239 round 2) for why this tolerance exists.
//
// created_at (#3321 follow-up) is now SELECTed, not just ORDERed BY: the
// ORDER BY here has always matched the retired in-memory engine's
// (slice-backed, so its order was deterministic), but DatabaseDynamicPolicyEngine
// lands rows in a map and re-evaluates them via a plain `range`, which Go
// randomizes -- so the ordering this query expresses was being computed and
// then thrown away. Carrying created_at into the row lets the cache
// reproduce it.
const dynamicPoliciesQueryWithSegment = `
	SELECT id::text, name, COALESCE(description, '') AS description,
	       conditions, actions, tenant_id, org_id, priority, policy_id,
	       COALESCE(policy_type, 'content') as policy_type,
	       COALESCE(category, '') as category,
	       COALESCE(risk_level, 'medium') as risk_level,
	       COALESCE(allow_override, false) as allow_override,
	       created_at,
	       segment_id
	FROM dynamic_policies
	WHERE enabled = true
	ORDER BY priority DESC, created_at DESC
`

const dynamicPoliciesQueryWithoutSegment = `
	SELECT id::text, name, COALESCE(description, '') AS description,
	       conditions, actions, tenant_id, org_id, priority, policy_id,
	       COALESCE(policy_type, 'content') as policy_type,
	       COALESCE(category, '') as category,
	       COALESCE(risk_level, 'medium') as risk_level,
	       COALESCE(allow_override, false) as allow_override,
	       created_at
	FROM dynamic_policies
	WHERE enabled = true
	ORDER BY priority DESC, created_at DESC
`

// RowIterationError wraps a rows.Err() failure seen AFTER a successful
// Query/QueryContext call, so a caller of RefreshDynamicPolicies can tell
// "the SELECT itself failed" (returned directly, unwrapped -- checked with
// isMissingColumnError for the segment-less retry) apart from "the SELECT
// succeeded but iterating the result set failed" (wrapped in this type).
// DatabaseDynamicPolicyEngine.refreshPolicies uses errors.As to route the
// latter to its own reasonRowIterationFailed metric, distinct from
// reasonQueryFailed.
type RowIterationError struct {
	Err error
}

func (e *RowIterationError) Error() string { return e.Err.Error() }
func (e *RowIterationError) Unwrap() error { return e.Err }

// RefreshDynamicPolicies executes the gate-cache refresh SELECT against db
// and returns the scanned rows -- the DatabaseDynamicPolicyEngine
// equivalent of the static-policy loadFromDatabase above.
//
// This is a deliberate ALL-TENANTS, unfiltered-by-org read: unlike every
// other read in this file it carries no tenant/org predicate and opens no
// rls.WithOrgScope wrap. The caller MUST pass a BYPASSRLS connection (the
// platform-admin pool) on an app-role deployment -- under
// AXONFLOW_DB_USE_APP_ROLE=true, an app-role connection with no org GUC set
// matches ZERO rows and returns NO error for this exact query
// (get_current_org_id() -> NULL, and "org_id = NULL" is never true in SQL),
// which silently empties the caller's gate cache and stops tenant dynamic
// policies from being enforced (#3039). This function does not and cannot
// enforce that pool choice itself -- it only issues SQL on whatever *sql.DB
// it is given. See DatabaseDynamicPolicyEngine.crossOrgDB
// (platform/orchestrator/db_dynamic_policies.go), which is the pool-
// selection logic that provides the guarantee, for the call site that must
// keep passing the admin pool here.
//
// withSegment selects between dynamicPoliciesQueryWithSegment and
// dynamicPoliciesQueryWithoutSegment. The caller owns the retry decision
// (query withSegment=true first; on a "column does not exist" error, retry
// withSegment=false) because that decision needs isMissingColumnError, an
// orchestrator-local Postgres-error-shape helper this package must not
// depend on -- see this package's "no orchestrator/agent import" invariant
// (#3293).
func RefreshDynamicPolicies(ctx context.Context, db *sql.DB, withSegment bool) ([]DynamicPolicyRow, error) {
	query := dynamicPoliciesQueryWithoutSegment
	if withSegment {
		query = dynamicPoliciesQueryWithSegment
	}

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []DynamicPolicyRow
	for rows.Next() {
		var p DynamicPolicyRow
		var scanErr error
		if withSegment {
			scanErr = rows.Scan(&p.ID, &p.Name, &p.Description, &p.Conditions, &p.Actions, &p.TenantID, &p.OrgID, &p.Priority, &p.PolicyID, &p.PolicyType, &p.Category, &p.RiskLevel, &p.AllowOverride, &p.CreatedAt, &p.SegmentID)
		} else {
			scanErr = rows.Scan(&p.ID, &p.Name, &p.Description, &p.Conditions, &p.Actions, &p.TenantID, &p.OrgID, &p.Priority, &p.PolicyID, &p.PolicyType, &p.Category, &p.RiskLevel, &p.AllowOverride, &p.CreatedAt)
		}
		if scanErr != nil {
			log.Printf("[PolicyLoader] Error scanning dynamic-policy row: %v", scanErr)
			continue
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return out, &RowIterationError{Err: err}
	}
	return out, nil
}

// CountAllDynamicPolicies returns the total dynamic_policies row count
// across every tenant -- the orchestrator's boot-time seed check (has this
// deployment ever had a dynamic policy row?
// DatabaseDynamicPolicyEngine.seedDefaultData). Same ALL-TENANTS, BYPASSRLS-
// pool contract as RefreshDynamicPolicies above: db must be a cross-org-
// capable connection (the admin pool) or this reads 0 under RLS on an
// app-role deployment, which would re-attempt the sample-policy seed on
// every boot.
func CountAllDynamicPolicies(ctx context.Context, db *sql.DB) (int, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dynamic_policies`).Scan(&count)
	return count, err
}

// GetPolicyByID retrieves a single policy by ID.
//
// This is a by-id DISCOVERY read: the caller does not know which org owns the
// policy, so no single org scope can be set up front. The bare read serves
// owner-pool deployments (RLS bypassed) unchanged; under app-role it matches
// zero rows, so a 'global'-scoped retry recovers the system-tier rows
// (#3048). Tenant-tier lookups by bare policy_id have no org context on this
// signature — the loader has no authenticated caller identity — and remain
// owner-pool-only; the loader currently has no callers that need them (the
// agent's StaticPolicyRepository.GetByID is the authenticated by-id surface).
func (l *PolicyLoader) GetPolicyByID(ctx context.Context, policyID string) (*CompiledPolicy, error) {
	if l.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	// segment_id is SELECTed for consistency with the other static_policies
	// readers (#3266); see loadFromDatabase's doc for why it is scanned, not
	// filtered, at load time.
	query := `
		SELECT
			id, policy_id, name, category, tier, pattern, severity,
			description, phase, action_request, action_response,
			enabled, priority, tenant_id, segment_id, metadata
		FROM static_policies
		WHERE policy_id = $1
		  AND deleted_at IS NULL
		LIMIT 1
	`

	var p policyRow
	scan := func(row *sql.Row) error {
		return row.Scan(
			&p.ID, &p.PolicyID, &p.Name, &p.Category, &p.Tier, &p.Pattern,
			&p.Severity, &p.Description, &p.Phase, &p.ActionRequest, &p.ActionResponse,
			&p.Enabled, &p.Priority, &p.TenantID, &p.SegmentID, &p.Metadata,
		)
	}

	err := scan(l.db.QueryRowContext(ctx, query, policyID))
	if err == sql.ErrNoRows {
		// App-role pools see nothing bare — retry in the 'global' scope for
		// the system-tier rows (org_id='global', mig 153).
		err = rls.WithOrgScope(ctx, l.db, globalTenantSentinel, func(tx *sql.Tx) error {
			return scan(tx.QueryRowContext(ctx, query, policyID))
		})
	}
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	return l.compilePolicy(p)
}
