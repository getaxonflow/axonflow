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
type PolicyLoader struct {
	db    *sql.DB
	cache *PolicyCache

	// Query templates
	queryRequestPhase  string
	queryResponsePhase string
}

// NewPolicyLoader creates a new policy loader.
func NewPolicyLoader(db *sql.DB, cache *PolicyCache) *PolicyLoader {
	l := &PolicyLoader{
		db:    db,
		cache: cache,
	}
	l.initQueries()
	return l
}

// initQueries initializes the SQL query templates.
func (l *PolicyLoader) initQueries() {
	// Query for request-phase policies
	l.queryRequestPhase = `
		SELECT
			id, policy_id, name, category, tier, pattern, severity,
			description, phase, action_request, action_response,
			enabled, priority, tenant_id, organization_id, metadata
		FROM static_policies
		WHERE enabled = true
		  AND deleted_at IS NULL
		  AND phase IN ('request', 'both')
		  AND (tenant_id = $1 OR tenant_id = 'global')
		ORDER BY priority DESC, created_at ASC
	`

	// Query for response-phase policies
	l.queryResponsePhase = `
		SELECT
			id, policy_id, name, category, tier, pattern, severity,
			description, phase, action_request, action_response,
			enabled, priority, tenant_id, organization_id, metadata
		FROM static_policies
		WHERE enabled = true
		  AND deleted_at IS NULL
		  AND phase IN ('response', 'both')
		  AND (tenant_id = $1 OR tenant_id = 'global')
		ORDER BY priority DESC, created_at ASC
	`
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

// loadFromDatabase loads all policies for a tenant from the database.
//
// static_policies is RLS-enabled (mig 018, org_id = get_current_org_id()).
// The old single bare read admitted the tenant's rows AND the 'global'
// wildcard rows in SQL — but under axonflow_app_role the unset GUC made RLS
// match ZERO rows silently, so the unified engine loaded nothing and both
// content planes evaluated nothing (#3048; observed live: check-input with
// `DROP TABLE` + SSN returned allowed with policies_evaluated=0). A single
// GUC can only unlock one org's rows at a time, so the read is now two
// DISJOINT scoped passes — the tenant scope with `tenant_id = $1` and the
// 'global' scope with `tenant_id = 'global'` — merged and re-sorted. The
// per-scope tenancy predicates keep the sets disjoint on deployments where
// the pool bypasses RLS (owner/master connections), so nothing double-counts
// (mirrors #3040's PolicyRepository.List shape).
//
// The tenant pass is scoped by orgID when the caller supplied one (an org
// that owns multiple tenants stamps rows with its org_id, not the tenant id);
// otherwise by tenantID — the org_id==tenant_id identity every v9 backfill
// (mig 094) and every agent write path preserves for single-tenant orgs.
func (l *PolicyLoader) loadFromDatabase(ctx context.Context, tenantID string, orgID *string) ([]CompiledPolicy, error) {
	if l.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	// Per-scope tenancy predicate: $1 is filled with the scope being read so
	// the tenant pass and the global pass return disjoint sets even without
	// RLS enforcement.
	query := `
		SELECT
			id, policy_id, name, category, tier, pattern, severity,
			description, phase, action_request, action_response,
			enabled, priority, tenant_id, organization_id, metadata,
			created_at
		FROM static_policies
		WHERE enabled = true
		  AND deleted_at IS NULL
		  AND tenant_id = $1
		ORDER BY priority DESC, created_at ASC
	`

	scopeOrg := tenantID
	if orgID != nil && *orgID != "" {
		scopeOrg = *orgID
	}

	// A blank tenant historically matched nothing on the tenant leg of the
	// old `tenant_id = $1 OR tenant_id = 'global'` predicate (no rows carry
	// an empty tenant_id), so it degrades to the global pass alone — and an
	// empty string is not a valid org scope key (WithOrgScope rejects it).
	var rows []policyRow
	var err error
	if tenantID != "" && tenantID != globalTenantSentinel {
		rows, err = l.scopedPolicyRows(ctx, query, scopeOrg, tenantID)
		if err != nil {
			return nil, err
		}
	}
	globalRows, gErr := l.scopedPolicyRows(ctx, query, globalTenantSentinel, globalTenantSentinel)
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

// scopedPolicyRows runs the tenancy-predicated policy query inside a
// WithOrgScope transaction (SET LOCAL app.current_org_id = scopeOrg) and
// returns the scanned rows. tenantArg fills the query's $1 tenancy predicate.
func (l *PolicyLoader) scopedPolicyRows(ctx context.Context, query, scopeOrg, tenantArg string) ([]policyRow, error) {
	var out []policyRow
	err := rls.WithOrgScope(ctx, l.db, scopeOrg, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, tenantArg)
		if qErr != nil {
			return fmt.Errorf("query failed: %w", qErr)
		}
		defer rows.Close()

		for rows.Next() {
			var p policyRow
			if sErr := rows.Scan(
				&p.ID, &p.PolicyID, &p.Name, &p.Category, &p.Tier, &p.Pattern,
				&p.Severity, &p.Description, &p.Phase, &p.ActionRequest, &p.ActionResponse,
				&p.Enabled, &p.Priority, &p.TenantID, &p.OrganizationID, &p.Metadata,
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
	OrganizationID sql.NullString
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

	// Parse organization ID
	var orgID *string
	if row.OrganizationID.Valid {
		orgID = &row.OrganizationID.String
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
		OrganizationID: orgID,
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

	query := `
		SELECT
			id, policy_id, name, category, tier, pattern, severity,
			description, phase, action_request, action_response,
			enabled, priority, tenant_id, organization_id, metadata
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
				&p.Enabled, &p.Priority, &p.TenantID, &p.OrganizationID, &p.Metadata,
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

	query := `
		SELECT
			id, policy_id, name, category, tier, pattern, severity,
			description, phase, action_request, action_response,
			enabled, priority, tenant_id, organization_id, metadata
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
			&p.Enabled, &p.Priority, &p.TenantID, &p.OrganizationID, &p.Metadata,
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
