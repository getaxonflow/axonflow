// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"axonflow/platform/agent/license"
	sharedpolicy "axonflow/platform/shared/policy"
)

// Static policy limits
const (
	// MaxTenantPoliciesCommunity is the maximum number of custom tenant policies
	// allowed in Community edition.
	MaxTenantPoliciesCommunity = 20

	// MaxVersionHistoryCommunity is the maximum number of version history entries
	// returned in Community edition.
	MaxVersionHistoryCommunity = 5

	// DefaultPageSize is the default number of items per page for listing.
	DefaultPageSize = 20

	// MaxPageSize is the maximum number of items per page for listing.
	MaxPageSize = 100
)

// GlobalOrgSentinel is the org_id/tenant_id wildcard carried by system-seeded
// policies that apply across all tenants (mig 010's DEFAULT 'global'; mig 153
// backfilled org_id='global' so the rows are reachable under a 'global'-scoped
// RLS read). Mirrors the orchestrator's GlobalTenantSentinel (#3040/#3048).
const GlobalOrgSentinel = "global"

// ErrSystemPolicyModification is returned when attempting to modify a system policy.
var ErrSystemPolicyModification = errors.New("system policies cannot be modified")

// ErrSystemPolicyDeletion is returned when attempting to delete a system policy.
var ErrSystemPolicyDeletion = errors.New("system policies cannot be deleted")

// ErrPolicyNotFound is returned when a policy is not found.
var ErrPolicyNotFound = errors.New("policy not found")

// ErrTenantPolicyLimitReached is returned when the tenant policy limit is reached.
var ErrTenantPolicyLimitReached = errors.New("tenant policy limit reached")

// ErrOrgTierRequiresEnterprise is returned when trying to create an org-tier policy
// without an Enterprise license.
var ErrOrgTierRequiresEnterprise = errors.New("organization tier requires Enterprise license")

// ErrInvalidPattern is returned when a regex pattern is invalid.
var ErrInvalidPattern = errors.New("invalid regex pattern")

// ErrInvalidCategory is returned when a policy category is invalid.
var ErrInvalidCategory = errors.New("invalid policy category")

// ErrInvalidTier is returned when a policy tier is invalid.
var ErrInvalidTier = errors.New("invalid policy tier")

// ErrSystemTierCreation is returned when attempting to create a system-tier policy.
var ErrSystemTierCreation = errors.New("system tier policies cannot be created via API")

// StaticPolicyRepository provides CRUD operations for static policies.
type StaticPolicyRepository struct {
	db *sql.DB
}

// NewStaticPolicyRepository creates a new static policy repository.
func NewStaticPolicyRepository(db *sql.DB) *StaticPolicyRepository {
	return &StaticPolicyRepository{db: db}
}

// Create creates a new static policy with tier validation.
// System tier: REJECT (cannot create system policies via API)
// Organization tier: Requires Enterprise license, must have org_id
// Tenant tier: Respects 30 limit for Community
func (r *StaticPolicyRepository) Create(ctx context.Context, policy *StaticPolicy, createdBy string) error {
	// Validate tier
	if policy.Tier == TierSystem {
		return ErrSystemTierCreation
	}

	if !IsValidTier(policy.Tier) {
		return ErrInvalidTier
	}

	// Validate category
	if !IsValidStaticCategory(PolicyCategory(policy.Category)) {
		return ErrInvalidCategory
	}

	// Validate pattern (RE2 syntax with additional safety checks)
	if err := validatePatternWithLimits(policy.Pattern); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPattern, err)
	}

	// Check tier-specific constraints
	if policy.Tier == TierOrganization {
		// Check Enterprise license
		isEnterprise, err := r.isEnterpriseLicense(ctx, policy.TenantID)
		if err != nil {
			return fmt.Errorf("failed to check license: %w", err)
		}
		if !isEnterprise {
			return ErrOrgTierRequiresEnterprise
		}
		// Organization tier requires organization_id
		if policy.OrganizationID == nil || *policy.OrganizationID == "" {
			return fmt.Errorf("organization_id is required for organization tier policies")
		}
	}

	if policy.Tier == TierTenant {
		// Check tenant policy limit for Community
		isEnterprise, err := r.isEnterpriseLicense(ctx, policy.TenantID)
		if err != nil {
			return fmt.Errorf("failed to check license: %w", err)
		}
		if !isEnterprise {
			count, err := r.countTenantPolicies(ctx, policy.TenantID)
			if err != nil {
				return fmt.Errorf("failed to count tenant policies: %w", err)
			}
			if count >= MaxTenantPoliciesCommunity {
				return ErrTenantPolicyLimitReached
			}
		}
	}

	// Generate IDs
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	if policy.PolicyID == "" {
		policy.PolicyID = "custom_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	}

	// Set defaults
	policy.Version = 1
	policy.CreatedAt = time.Now().UTC()
	policy.UpdatedAt = policy.CreatedAt
	policy.CreatedBy = createdBy
	policy.UpdatedBy = createdBy

	// Set default priority if not specified
	if policy.Priority == 0 {
		policy.Priority = 50 // Default priority
	}

	// Convert tags to JSON
	tagsJSON := "[]"
	if len(policy.Tags) > 0 {
		tagsBytes, err := json.Marshal(policy.Tags)
		if err != nil {
			return fmt.Errorf("failed to marshal tags: %w", err)
		}
		tagsJSON = string(tagsBytes)
	}

	// Issue #1081: Derive phase and action_request from action for policy evaluation
	// This ensures policies created via SDK are properly evaluated by the PolicyLoader
	// which expects phase and action_request columns to be populated.
	phase := "both" // Default phase - evaluated in both request and response phases
	actionRequest := policy.Action
	actionResponse := policy.Action

	// For require_approval (HITL), we only need request phase evaluation
	// This triggers human approval before the LLM call proceeds
	if policy.Action == "require_approval" {
		phase = "request"
		actionResponse = "" // No response phase action needed for HITL
	}

	// Insert into database
	// v9 compat (Epic #2230 Phase 2/4): client_id mirrors tenant_id with the
	// same value. Migration 090 added client_id to static_policies as the
	// v9 credential-scope column; tenant_id remains the deprecated alias
	// until v10. The 'global' wildcard sentinel (per migration 090's
	// design intent) preserves verbatim — a row with tenant_id='global'
	// gets client_id='global', keeping SELECT-path wildcard semantics
	// consistent with the application-layer tenant-scoping predicates this
	// repository and db_dynamic_policies.go apply (the historical cite here,
	// migration 010's get_dynamic_policies_for_tenant() helper function, was
	// dropped as dead unused code by migration 159 — #3239 round 2, M7).
	query := `
		INSERT INTO static_policies (
			id, policy_id, name, category, pattern, severity,
			description, action, tier, priority, enabled,
			organization_id, tenant_id, client_id, org_id,
			tags, metadata, version,
			phase, action_request, action_response,
			created_at, updated_at, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $13, $14,
			$15::jsonb, $16::jsonb, $17,
			$18, $19, $20,
			$21, $22, $23, $24
		)
	`

	metadataJSON := "{}"
	if policy.Metadata != nil {
		metadataJSON = string(policy.Metadata)
	}

	// v9 Phase 8 #2384 PR-C1: static_policies is ENABLE-RLS (mig 018) — under
	// axonflow_app_role the INSERT WITH CHECK predicate
	// org_id = current_setting('app.current_org_id') fires. Wrap in
	// WithOrgScope so SET LOCAL matches the row's org_id at INSERT time.
	if policy.OrgID == "" {
		return fmt.Errorf("Create: policy.OrgID must be non-empty (RLS enforced by mig 018)")
	}
	err := WithOrgScope(ctx, r.db, policy.OrgID, func(tx *sql.Tx) error {
		_, exErr := tx.ExecContext(ctx, query,
			policy.ID, policy.PolicyID, policy.Name, policy.Category, policy.Pattern, policy.Severity,
			policy.Description, policy.Action, string(policy.Tier), policy.Priority, policy.Enabled,
			policy.OrganizationID, policy.TenantID, policy.OrgID,
			tagsJSON, metadataJSON, policy.Version,
			phase, actionRequest, toNullString(actionResponse),
			policy.CreatedAt, policy.UpdatedAt, policy.CreatedBy, policy.UpdatedBy,
		)
		return exErr
	})
	if err != nil {
		return fmt.Errorf("failed to insert policy: %w", err)
	}

	// Record version history (best effort - log but don't fail the create)
	// Version history is for audit purposes, not critical path
	if err := r.recordVersion(ctx, policy, "create", "Policy created", createdBy); err != nil {
		log.Printf("[StaticPolicyRepository] Warning: failed to record version history for policy %s: %v", policy.PolicyID, err)
	}

	return nil
}

// Update updates an existing static policy with tier enforcement.
// callerOrgOwnsStaticPolicy reports whether the authenticated caller's org owns
// (may access) the given policy — the org-match half of the tenant-isolation
// guard enforced in GetByID (see there for how read vs write are covered and why
// this matters). It is intentionally org-agnostic about tier; the tier exception
// for the shared system baseline lives at the call site.
//
// Returns true (allow) when the caller org is genuinely unknown (single-tenant /
// community contexts that do not populate an org) or the row predates the org
// column — mirroring the existing WithOrgScope skip on an empty OrgID. The
// empty-caller-org branch is not reachable by a real multi-tenant caller: portal
// login always sets a session org (forwarded as X-Org-ID) and license auth
// carries an org from the license, so callerOrg is populated wherever a second
// tenant exists to protect; and the v9 org backfill (mig 094) set org_id on all
// existing static_policies rows, so policy.OrgID is populated post-migration.
func callerOrgOwnsStaticPolicy(ctx context.Context, policy *StaticPolicy) bool {
	callerOrg := OrgIDFromContext(ctx)
	if callerOrg == "" || policy.OrgID == "" {
		return true
	}
	return policy.OrgID == callerOrg
}

// isGlobalBaselineRow reports whether a policy row is part of the shared
// deployment-wide baseline: the 'global' wildcard on either tenancy key.
// Covers system-tier seeds, the mig-010 seeds demoted to tier='tenant' by
// mig 031 (drop_table_prevention, sql_injection_*, pii_ssn_detection, ...),
// the mig-014 eu_ai_act_* templates, and the mig-060/064 int_* integration
// policies — all carry tenant_id='global' (and org_id='global' post mig
// 153/154). Both keys are checked so pre-backfill rows (org_id NULL) on
// legacy owner-pool deployments are protected too.
func isGlobalBaselineRow(policy *StaticPolicy) bool {
	return policy.TenantID == GlobalOrgSentinel || policy.OrgID == GlobalOrgSentinel
}

// rejectGlobalBaselineWrite is the write-side counterpart of GetByID's
// global-wildcard READ exemption (#3048 R3 BLOCKER-1). The exemption lets
// every org SEE the shared baseline rows; without this guard it would also
// let every org's admin MUTATE them — the write paths run under
// WithOrgScope(policy.OrgID), i.e. the 'global' scope, so RLS passes and a
// single tenant could soft-delete / disable / rewrite drop_table_prevention
// DEPLOYMENT-WIDE. Global-wildcard rows get the same protection class as
// system-tier rows: only the global/system caller context (the deployment
// operator's own tooling, never a tenant identity) may write them.
func rejectGlobalBaselineWrite(ctx context.Context, policy *StaticPolicy) bool {
	return isGlobalBaselineRow(policy) && OrgIDFromContext(ctx) != GlobalOrgSentinel
}

// System tier policies cannot be modified.
func (r *StaticPolicyRepository) Update(ctx context.Context, policyID string, update *UpdateStaticPolicyRequest, updatedBy string) (*StaticPolicy, error) {
	// Get existing policy
	policy, err := r.GetByID(ctx, policyID)
	if err != nil {
		return nil, err
	}

	// Check if system tier
	if policy.Tier == TierSystem {
		return nil, ErrSystemPolicyModification
	}
	// #3048 R3 BLOCKER-1: shared 'global'-wildcard baseline rows are
	// read-visible to every org but writable by none of them.
	if rejectGlobalBaselineWrite(ctx, policy) {
		return nil, ErrSystemPolicyModification
	}
	// Cross-org writes are already blocked: GetByID above returns ErrPolicyNotFound
	// for a non-system policy owned by a different org than the caller.

	// Build update query dynamically based on what's being updated
	updates := []string{}
	args := []interface{}{}
	argNum := 1

	if update.Name != nil {
		updates = append(updates, fmt.Sprintf("name = $%d", argNum))
		args = append(args, *update.Name)
		argNum++
	}

	if update.Description != nil {
		updates = append(updates, fmt.Sprintf("description = $%d", argNum))
		args = append(args, *update.Description)
		argNum++
	}

	if update.Pattern != nil {
		// Validate pattern with safety checks
		if err := validatePatternWithLimits(*update.Pattern); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidPattern, err)
		}
		updates = append(updates, fmt.Sprintf("pattern = $%d", argNum))
		args = append(args, *update.Pattern)
		argNum++
	}

	if update.Action != nil {
		updates = append(updates, fmt.Sprintf("action = $%d", argNum))
		args = append(args, *update.Action)
		argNum++
	}

	if update.Severity != nil {
		updates = append(updates, fmt.Sprintf("severity = $%d", argNum))
		args = append(args, *update.Severity)
		argNum++
	}

	if update.Priority != nil {
		updates = append(updates, fmt.Sprintf("priority = $%d", argNum))
		args = append(args, *update.Priority)
		argNum++
	}

	if update.Enabled != nil {
		updates = append(updates, fmt.Sprintf("enabled = $%d", argNum))
		args = append(args, *update.Enabled)
		argNum++
	}

	if len(update.Tags) > 0 {
		tagsBytes, err := json.Marshal(update.Tags)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal tags: %w", err)
		}
		updates = append(updates, fmt.Sprintf("tags = $%d::jsonb", argNum))
		args = append(args, string(tagsBytes))
		argNum++
	}

	if len(updates) == 0 {
		return policy, nil // Nothing to update
	}

	// Always update version, updated_at, updated_by
	updates = append(updates, "version = version + 1")
	updates = append(updates, fmt.Sprintf("updated_at = $%d", argNum))
	args = append(args, time.Now().UTC())
	argNum++
	updates = append(updates, fmt.Sprintf("updated_by = $%d", argNum))
	args = append(args, updatedBy)
	argNum++

	// Add WHERE clause
	query := fmt.Sprintf(`
		UPDATE static_policies
		SET %s
		WHERE id = $%d AND deleted_at IS NULL
		RETURNING id, policy_id, name, category, pattern, severity,
			description, action, tier, priority, enabled,
			organization_id, tenant_id, org_id,
			version, created_at, updated_at, created_by, updated_by
	`, strings.Join(updates, ", "), argNum)
	args = append(args, policy.ID) // Use the actual UUID from fetched policy, not the string param

	var updatedPolicy StaticPolicy
	var description sql.NullString
	var orgIDOut sql.NullString

	// v9 Phase 8 #2384 PR-C1: static_policies is ENABLE-RLS (mig 018) — under
	// axonflow_app_role the UPDATE USING predicate gates the row before
	// RETURNING runs. Wrap in WithOrgScope using policy.OrgID (fetched by
	// the GetByID lookup above) so the UPDATE actually sees the row.
	if policy.OrgID == "" {
		return nil, fmt.Errorf("Update: existing policy.OrgID missing (RLS enforced by mig 018)")
	}
	err = WithOrgScope(ctx, r.db, policy.OrgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, args...).Scan(
			&updatedPolicy.ID, &updatedPolicy.PolicyID, &updatedPolicy.Name, &updatedPolicy.Category,
			&updatedPolicy.Pattern, &updatedPolicy.Severity, &description, &updatedPolicy.Action,
			&updatedPolicy.Tier, &updatedPolicy.Priority, &updatedPolicy.Enabled,
			&updatedPolicy.OrganizationID, &updatedPolicy.TenantID, &orgIDOut,
			&updatedPolicy.Version, &updatedPolicy.CreatedAt, &updatedPolicy.UpdatedAt,
			&updatedPolicy.CreatedBy, &updatedPolicy.UpdatedBy,
		)
	})
	if err == sql.ErrNoRows {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}

	if description.Valid {
		updatedPolicy.Description = description.String
	}
	if orgIDOut.Valid {
		updatedPolicy.OrgID = orgIDOut.String
	}

	// Record version history (best effort - don't fail on error)
	changeSummary := fmt.Sprintf("Policy updated by %s", updatedBy)
	_ = r.recordVersion(ctx, &updatedPolicy, "update", changeSummary, updatedBy)

	return &updatedPolicy, nil
}

// Delete performs a soft delete on a static policy.
// System tier policies cannot be deleted.
func (r *StaticPolicyRepository) Delete(ctx context.Context, policyID string, deletedBy string) error {
	// Get existing policy to check tier
	policy, err := r.GetByID(ctx, policyID)
	if err != nil {
		return err
	}

	// Check if system tier
	if policy.Tier == TierSystem {
		return ErrSystemPolicyDeletion
	}
	// #3048 R3 BLOCKER-1: the shared 'global'-wildcard baseline is not
	// deletable by any tenant caller (see rejectGlobalBaselineWrite).
	if rejectGlobalBaselineWrite(ctx, policy) {
		return ErrSystemPolicyDeletion
	}
	// Cross-org deletes are already blocked by the GetByID tenant-isolation guard.

	// Soft delete
	query := `
		UPDATE static_policies
		SET deleted_at = $1, updated_by = $2, version = version + 1
		WHERE id = $3 AND deleted_at IS NULL
	`

	// v9 Phase 8 #2384 PR-C1: wrap soft-delete UPDATE in WithOrgScope so
	// the USING predicate sees the row under app_role.
	if policy.OrgID == "" {
		return fmt.Errorf("Delete: existing policy.OrgID missing (RLS enforced by mig 018)")
	}
	var rowsAffected int64
	err = WithOrgScope(ctx, r.db, policy.OrgID, func(tx *sql.Tx) error {
		result, exErr := tx.ExecContext(ctx, query, time.Now().UTC(), deletedBy, policy.ID)
		if exErr != nil {
			return fmt.Errorf("failed to delete policy: %w", exErr)
		}
		var raErr error
		rowsAffected, raErr = result.RowsAffected()
		if raErr != nil {
			return fmt.Errorf("failed to get affected rows: %w", raErr)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrPolicyNotFound
	}

	// Record deletion in version history (best effort - don't fail on error)
	_ = r.recordVersion(ctx, policy, "delete", "Policy deleted", deletedBy)

	return nil
}

// GetByID retrieves a static policy by its ID.
func (r *StaticPolicyRepository) GetByID(ctx context.Context, id string) (*StaticPolicy, error) {
	query := `
		SELECT
			id, policy_id, name, category, pattern, severity,
			description, action, tier, priority, enabled,
			organization_id, tenant_id, org_id,
			tags, metadata, version,
			created_at, updated_at, created_by, updated_by, deleted_at
		FROM static_policies
		WHERE (id::text = $1 OR policy_id = $1) AND deleted_at IS NULL
	`

	var policy StaticPolicy
	var description, createdBy, updatedBy sql.NullString
	var orgID sql.NullString
	var tagsJSON, metadataJSON sql.NullString
	var deletedAt sql.NullTime

	scan := func(row *sql.Row) error {
		return row.Scan(
			&policy.ID, &policy.PolicyID, &policy.Name, &policy.Category,
			&policy.Pattern, &policy.Severity, &description, &policy.Action,
			&policy.Tier, &policy.Priority, &policy.Enabled,
			&policy.OrganizationID, &policy.TenantID, &orgID,
			&tagsJSON, &metadataJSON, &policy.Version,
			&policy.CreatedAt, &policy.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
		)
	}

	// #3048: static_policies is RLS-enabled (mig 018, org_id =
	// get_current_org_id()). This is a by-id DISCOVERY read — the row itself
	// establishes which org owns the policy — so under axonflow_app_role the
	// old bare read matched ZERO rows and every by-id access (portal unified
	// GET, ResolvePolicySource, Update/Delete/Toggle read-modify-write) 404'd.
	// A single GUC unlocks one org at a time: read under the caller's org
	// scope first (their own tenant/org-tier rows), then fall back to the
	// 'global' scope for the shared system-tier rows (org_id='global', mig
	// 153). When the caller org is genuinely unknown (single-tenant /
	// community contexts — see callerOrgOwnsStaticPolicy) the legacy bare
	// read is kept: those deployments connect as the table owner and bypass
	// RLS. The tenant-isolation guard below post-authorizes either way.
	var err error
	callerOrg := OrgIDFromContext(ctx)
	if callerOrg == "" {
		err = scan(r.db.QueryRowContext(ctx, query, id))
	} else {
		err = WithOrgScope(ctx, r.db, callerOrg, func(tx *sql.Tx) error {
			return scan(tx.QueryRowContext(ctx, query, id))
		})
		if err == sql.ErrNoRows && callerOrg != GlobalOrgSentinel {
			err = WithOrgScope(ctx, r.db, GlobalOrgSentinel, func(tx *sql.Tx) error {
				return scan(tx.QueryRowContext(ctx, query, id))
			})
		}
	}
	if err == sql.ErrNoRows {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	if description.Valid {
		policy.Description = description.String
	}
	if orgID.Valid {
		policy.OrgID = orgID.String
	}
	if createdBy.Valid {
		policy.CreatedBy = createdBy.String
	}
	if updatedBy.Valid {
		policy.UpdatedBy = updatedBy.String
	}
	if tagsJSON.Valid && tagsJSON.String != "" {
		if err := json.Unmarshal([]byte(tagsJSON.String), &policy.Tags); err != nil {
			policy.Tags = []string{}
		}
	}
	if metadataJSON.Valid && metadataJSON.String != "" {
		policy.Metadata = json.RawMessage(metadataJSON.String)
	}
	if deletedAt.Valid {
		policy.DeletedAt = &deletedAt.Time
	}

	// Tenant-isolation guard (defense in depth), applied at the single point every
	// by-id access flows through — the read handler (HandleGetStaticPolicy), the
	// portal's GET /unified-policies/{id} → fetchStaticPolicy, ResolvePolicySource,
	// and the Update/Delete/ToggleEnabled write methods that fetch through here.
	//
	// GetByID resolves ANY id: its WHERE is `id/policy_id + deleted_at IS NULL`,
	// with no org predicate and no WithOrgScope. static_policies RLS only isolates
	// rows when the Agent runs under a non-owner app_role; a deployment on the
	// table owner (AXONFLOW_DB_USE_APP_ROLE unset/false — the docker-compose /
	// pre-provision default, and any non-flipped install) bypasses RLS entirely.
	// Without this guard one org could read (and, via the write methods, mutate)
	// another org's custom static policy by id — reachable once the portal's
	// unified dispatcher (#2774) made the static read+write paths live.
	//
	// System-tier policies are the shared baseline every tenant may see, so they
	// are exempt; only tenant/organization-tier rows are org-private. In a
	// correctly configured app_role deployment RLS already scopes this query, so
	// the guard is a no-op there.
	//
	// #3048: rows carrying the 'global' wildcard org are ALSO the shared
	// baseline regardless of tier — the mig-010 seeds predate the tier column
	// (tier defaulted to 'tenant') and mig 153 backfilled org_id='global'
	// onto them; without this exemption the backfill would have flipped
	// those rows from visible (org_id NULL → guard allows) to hidden for
	// every org caller.
	if policy.Tier != TierSystem && policy.OrgID != GlobalOrgSentinel && !callerOrgOwnsStaticPolicy(ctx, &policy) {
		return nil, ErrPolicyNotFound
	}

	return &policy, nil
}

// List retrieves static policies with filtering and pagination.
func (r *StaticPolicyRepository) List(ctx context.Context, tenantID string, params *ListStaticPoliciesParams) (*StaticPoliciesListResponse, error) {
	if params == nil {
		params = &ListStaticPoliciesParams{}
	}

	// Set defaults
	if params.Page < 1 {
		params.Page = 1
	}
	if params.PageSize < 1 {
		params.PageSize = DefaultPageSize
	}
	if params.PageSize > MaxPageSize {
		params.PageSize = MaxPageSize
	}

	// Build the shared (non-tenancy) filter clauses. The tenancy predicate is
	// added PER SCOPE below so the tenant pass and the global pass return
	// disjoint sets on every deployment — with or without RLS (#3048).
	where := []string{"deleted_at IS NULL"}
	args := []interface{}{}
	argNum := 1

	if params.Tier != nil {
		where = append(where, fmt.Sprintf("tier = $%d", argNum))
		args = append(args, string(*params.Tier))
		argNum++
	}

	if params.Category != nil {
		where = append(where, fmt.Sprintf("category = $%d", argNum))
		args = append(args, string(*params.Category))
		argNum++
	}

	if params.Enabled != nil {
		where = append(where, fmt.Sprintf("enabled = $%d", argNum))
		args = append(args, *params.Enabled)
		argNum++
	}

	if params.Search != "" {
		where = append(where, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argNum, argNum+1))
		searchPattern := "%" + params.Search + "%"
		args = append(args, searchPattern, searchPattern)
		argNum += 2
	}

	// scopedList runs the list query for ONE org scope. static_policies is
	// RLS-enabled (mig 018) and a single GUC unlocks one org's rows at a
	// time, so under axonflow_app_role the old bare read returned 0 rows and
	// the portal showed "Static (Read-only) 0" while enforcement loaded
	// nothing (#3048). Each pass carries an explicit tenancy predicate so the
	// two result sets are disjoint on every deployment — with or without RLS
	// (owner pools bypass RLS entirely and would otherwise double-count).
	scopedList := func(scopeOrg, tenancyClause string, tenancyArgs ...interface{}) ([]StaticPolicy, error) {
		scopeWhere := strings.Join(append(append([]string{}, where...), tenancyClause), " AND ")
		scopeArgs := append(append([]interface{}{}, args...), tenancyArgs...)
		query := fmt.Sprintf(`
			SELECT
				id, policy_id, name, category, pattern, severity,
				description, action, tier, priority, enabled,
				organization_id, tenant_id, org_id,
				tags, metadata, version,
				created_at, updated_at, created_by, updated_by
			FROM static_policies
			WHERE %s
		`, scopeWhere)

		var out []StaticPolicy
		err := WithOrgScope(ctx, r.db, scopeOrg, func(tx *sql.Tx) error {
			rows, qErr := tx.QueryContext(ctx, query, scopeArgs...)
			if qErr != nil {
				return qErr
			}
			defer rows.Close()

			for rows.Next() {
				var policy StaticPolicy
				var description, createdBy, updatedBy sql.NullString
				var orgID sql.NullString
				var tagsJSON, metadataJSON sql.NullString

				if sErr := rows.Scan(
					&policy.ID, &policy.PolicyID, &policy.Name, &policy.Category,
					&policy.Pattern, &policy.Severity, &description, &policy.Action,
					&policy.Tier, &policy.Priority, &policy.Enabled,
					&policy.OrganizationID, &policy.TenantID, &orgID,
					&tagsJSON, &metadataJSON, &policy.Version,
					&policy.CreatedAt, &policy.UpdatedAt, &createdBy, &updatedBy,
				); sErr != nil {
					continue
				}

				if description.Valid {
					policy.Description = description.String
				}
				if orgID.Valid {
					policy.OrgID = orgID.String
				}
				if createdBy.Valid {
					policy.CreatedBy = createdBy.String
				}
				if updatedBy.Valid {
					policy.UpdatedBy = updatedBy.String
				}
				if tagsJSON.Valid && tagsJSON.String != "" {
					if uErr := json.Unmarshal([]byte(tagsJSON.String), &policy.Tags); uErr != nil {
						policy.Tags = []string{}
					}
				}
				if metadataJSON.Valid && metadataJSON.String != "" {
					policy.Metadata = json.RawMessage(metadataJSON.String)
				}

				out = append(out, policy)
			}
			return rows.Err()
		})
		if err != nil {
			return nil, err
		}
		return out, nil
	}

	policies := make([]StaticPolicy, 0)
	if tenantID != "" {
		// Tenant/org-tier rows: scope by the caller's org when known (an org
		// owning multiple tenants stamps rows with its org_id — same key
		// Create uses), else the org_id==tenant_id identity.
		scopeOrg := OrgIDFromContext(ctx)
		if scopeOrg == "" {
			scopeOrg = tenantID
		}
		tenantRows, err := scopedList(scopeOrg,
			fmt.Sprintf("(tier <> 'system' AND tenant_id = $%d)", argNum), tenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to list policies: %w", err)
		}
		// System-tier rows live in the 'global' scope (org_id='global',
		// mig 153). Disjoint from the pass above by the tier predicate.
		globalRows, err := scopedList(GlobalOrgSentinel, "tier = 'system'")
		if err != nil {
			return nil, fmt.Errorf("failed to list global policies: %w", err)
		}
		policies = append(append(policies, tenantRows...), globalRows...)
	} else {
		// Filterless call: a deliberate cross-tenant listing (ops path on
		// owner-pool deployments — under app-role RLS it reads zero rows,
		// same as before #3048; cross-org work belongs on the admin role).
		bareRows, err := scopedListBare(ctx, r.db, where, args)
		if err != nil {
			return nil, fmt.Errorf("failed to list policies: %w", err)
		}
		policies = bareRows
	}

	// Sort the merged tenant+global sets in memory, mirroring the ORDER BY
	// the single query used, then paginate.
	sortStaticPolicies(policies, params.SortBy, params.SortDir)

	totalItems := len(policies)
	totalPages := (totalItems + params.PageSize - 1) / params.PageSize
	offset := (params.Page - 1) * params.PageSize
	end := offset + params.PageSize
	if offset > totalItems {
		offset = totalItems
	}
	if end > totalItems {
		end = totalItems
	}

	return &StaticPoliciesListResponse{
		Policies: policies[offset:end],
		Pagination: PaginationInfo{
			Page:       params.Page,
			PageSize:   params.PageSize,
			TotalItems: totalItems,
			TotalPages: totalPages,
		},
	}, nil
}

// scopedListBare is the legacy unscoped list read used by the filterless
// (tenantID == "") cross-tenant listing path. Kept bare deliberately: it is
// only meaningful on deployments whose pool bypasses RLS.
func scopedListBare(ctx context.Context, db *sql.DB, where []string, args []interface{}) ([]StaticPolicy, error) {
	query := fmt.Sprintf(`
		SELECT
			id, policy_id, name, category, pattern, severity,
			description, action, tier, priority, enabled,
			organization_id, tenant_id, org_id,
			tags, metadata, version,
			created_at, updated_at, created_by, updated_by
		FROM static_policies
		WHERE %s
	`, strings.Join(where, " AND "))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]StaticPolicy, 0)
	for rows.Next() {
		var policy StaticPolicy
		var description, createdBy, updatedBy sql.NullString
		var orgID sql.NullString
		var tagsJSON, metadataJSON sql.NullString

		if sErr := rows.Scan(
			&policy.ID, &policy.PolicyID, &policy.Name, &policy.Category,
			&policy.Pattern, &policy.Severity, &description, &policy.Action,
			&policy.Tier, &policy.Priority, &policy.Enabled,
			&policy.OrganizationID, &policy.TenantID, &orgID,
			&tagsJSON, &metadataJSON, &policy.Version,
			&policy.CreatedAt, &policy.UpdatedAt, &createdBy, &updatedBy,
		); sErr != nil {
			continue
		}

		if description.Valid {
			policy.Description = description.String
		}
		if orgID.Valid {
			policy.OrgID = orgID.String
		}
		if createdBy.Valid {
			policy.CreatedBy = createdBy.String
		}
		if updatedBy.Valid {
			policy.UpdatedBy = updatedBy.String
		}
		if tagsJSON.Valid && tagsJSON.String != "" {
			if uErr := json.Unmarshal([]byte(tagsJSON.String), &policy.Tags); uErr != nil {
				policy.Tags = []string{}
			}
		}
		if metadataJSON.Valid && metadataJSON.String != "" {
			policy.Metadata = json.RawMessage(metadataJSON.String)
		}

		out = append(out, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating policies: %w", err)
	}
	return out, nil
}

// sortStaticPolicies orders the merged tenant+global result set by the
// validated sort column, mirroring the ORDER BY the per-scope queries used
// (default: priority DESC, name ASC).
func sortStaticPolicies(policies []StaticPolicy, sortBy, sortDir string) {
	allowedSorts := map[string]bool{
		"name": true, "category": true, "tier": true,
		"severity": true, "priority": true, "created_at": true, "updated_at": true,
	}
	if !allowedSorts[sortBy] {
		// Default composite order: priority DESC, name ASC.
		sort.SliceStable(policies, func(i, j int) bool {
			if policies[i].Priority != policies[j].Priority {
				return policies[i].Priority > policies[j].Priority
			}
			return policies[i].Name < policies[j].Name
		})
		return
	}

	desc := strings.EqualFold(sortDir, "DESC")
	less := func(i, j int) bool {
		var l bool
		switch sortBy {
		case "name":
			l = policies[i].Name < policies[j].Name
		case "category":
			l = policies[i].Category < policies[j].Category
		case "tier":
			l = policies[i].Tier < policies[j].Tier
		case "severity":
			l = policies[i].Severity < policies[j].Severity
		case "priority":
			l = policies[i].Priority < policies[j].Priority
		case "updated_at":
			l = policies[i].UpdatedAt.Before(policies[j].UpdatedAt)
		default: // created_at
			l = policies[i].CreatedAt.Before(policies[j].CreatedAt)
		}
		if desc {
			return !l && !staticPolicySortEqual(policies[i], policies[j], sortBy)
		}
		return l
	}
	sort.SliceStable(policies, less)
}

func staticPolicySortEqual(a, b StaticPolicy, sortBy string) bool {
	switch sortBy {
	case "name":
		return a.Name == b.Name
	case "category":
		return a.Category == b.Category
	case "tier":
		return a.Tier == b.Tier
	case "severity":
		return a.Severity == b.Severity
	case "priority":
		return a.Priority == b.Priority
	case "updated_at":
		return a.UpdatedAt.Equal(b.UpdatedAt)
	default:
		return a.CreatedAt.Equal(b.CreatedAt)
	}
}

// GetEffective returns effective policies for a tenant with tier hierarchy applied.
// Inheritance order: System policies → Organization policies → Tenant policies
// Higher tier policies can shadow lower tier by policy name/category.
//
// Library-contract changes in #3048 (behavioral, deliberate):
//   - An empty tenantID with no org (param or context) now returns an ERROR
//     (WithOrgScope rejects an empty scope key) where the old single bare
//     query silently returned the system baseline. Every production caller
//     (HandleGetEffectivePolicies, TierAwarePolicyEngine) guards a non-empty
//     tenant before calling.
//   - Multiple live overrides on one policy now collapse to the
//     latest-created override (one row per policy), where the old LEFT JOIN
//     emitted a duplicate EffectiveStaticPolicy per override row.
//
// segmentIDs (ADR-060 #2989 P3, Decision 2 — LOCKED) is the caller's resolved
// governance-segment set. Selection is additive and orthogonal to tier: the
// EXISTING tier predicates on both RLS passes below (system/organization/
// tenant) are UNCHANGED — they still decide which rows are candidates at all
// — and a second, independent filter narrows that candidate set on EVERY
// pass:
//   - segment_id IS NULL rows (the overwhelming majority — every policy that
//     predates P3, and every policy an org never scopes to a segment) pass
//     through UNCONDITIONALLY, regardless of segmentIDs. This is what makes
//     an org with no segment-scoped policies byte-identical to pre-P3
//     behavior: segmentIDs being empty, nil, or non-empty can never change
//     the result for such an org.
//   - segment_id IS NOT NULL rows (already tier-scoped like any other row)
//     are ADDITIONALLY required to have their segment_id in segmentIDs.
//
// A nil/empty segmentIDs excludes every segment-scoped row (the fail-closed
// caller contract lives one layer up — see resolveSegmentsForPolicy in
// run.go: a genuine segment-RESOLUTION error must deny the whole request
// before ever reaching here, never silently call this with an empty set as
// if the caller had zero segments).
//
// Override-downgrade path (Enterprise policy_overrides, applied in Go from
// the pass-A override map): segment-scoped policies do NOT participate in it
// (ADR-060 Decision 1) — the map lookup below is gated on
// policy.SegmentID == nil regardless of what the override map contains for
// that policy ID — because the combiner (see tier_aware_policy_engine.go)
// treats a segment policy's action as an unconditional, un-downgradable
// restriction candidate.
func (r *StaticPolicyRepository) GetEffective(ctx context.Context, tenantID string, orgID *string, segmentIDs []string) ([]EffectiveStaticPolicy, error) {
	orgIDStr := ""
	if orgID != nil {
		orgIDStr = *orgID
	}

	// #3048: static_policies AND policy_overrides are RLS-enabled (mig 018 /
	// mig 110, org_id = app.current_org_id) and a single GUC unlocks one org
	// at a time — the old bare single-query read matched ZERO rows under
	// axonflow_app_role, so the portal's unified view showed 0 static
	// policies. The read is now:
	//   pass A (caller org scope): tenant/org-tier rows + the caller's live
	//     static overrides (both org-owned rows, same scope);
	//   pass B ('global' scope): system-tier rows (org_id='global', mig 153).
	// The per-pass tier predicates keep the sets disjoint on owner-pool
	// deployments (no RLS), so nothing double-counts.
	//
	// #3296 Step B: the static_policies read for both passes now goes
	// through sharedpolicy.ScanEffectivePolicyRows (platform/shared/policy/
	// loader.go) — the SAME loader that backs the agent's Phase-1 shared
	// engine read — so static_policies has exactly one reader across both
	// evaluation paths. This method still owns the policy_overrides read
	// (a DIFFERENT table) and the override-precedence resolution, now via
	// policy.EffectiveOverride (#3296 Step C — see applyEffectiveOverride).
	scopeOrg := orgIDStr
	if scopeOrg == "" {
		scopeOrg = OrgIDFromContext(ctx)
	}
	if scopeOrg == "" {
		scopeOrg = tenantID
	}

	// pq.Array over a nil/empty slice still serializes to a valid empty
	// Postgres array literal ('{}'), never SQL NULL, so `= ANY($N::text[])`
	// correctly evaluates to false for every segment-scoped row (rather than
	// NULL, which would also be non-true but is worth being explicit about).
	segArg := segmentIDs
	if segArg == nil {
		segArg = []string{}
	}

	overridesByPolicy := make(map[string][]staticOverrideRow)

	// Pass A: the caller org's tenant/org-tier policies + live overrides.
	var tenantPolicies []StaticPolicy
	err := WithOrgScope(ctx, r.db, scopeOrg, func(tx *sql.Tx) error {
		rows, pErr := sharedpolicy.ScanEffectivePolicyRows(ctx, tx, `(
			(sp.tier = 'organization' AND sp.organization_id::text = $2)
			OR (sp.tier = 'tenant' AND sp.tenant_id = $1)
		  )
		  AND (sp.segment_id IS NULL OR sp.segment_id = ANY($3::text[]))`, tenantID, orgIDStr, pq.Array(segArg))
		if pErr != nil {
			return pErr
		}
		tenantPolicies = make([]StaticPolicy, 0, len(rows))
		for _, row := range rows {
			tenantPolicies = append(tenantPolicies, effectiveRowToStaticPolicy(row))
		}

		// Live static overrides scoped to (tenant, org). #3296 Step C: also
		// selects po.tenant_id so each row's SCOPE (tenant vs org) can be
		// determined — previously unread, which is exactly how the
		// tenant-beats-org precedence bug (below) went unnoticed: the old
		// code could not tell scopes apart and resolved precedence by
		// created_at order alone. ORDER BY created_at is kept so a same-scope
		// tie (two rows at the identical scope for one policy — should not
		// happen given PolicyOverrideRepository.Create's duplicate check, but
		// not schema-enforced) still prefers the latest row for the
		// non-precedence metadata fields (enabled/expires_at/reason); see
		// applyEffectiveOverride.
		oRows, oErr := tx.QueryContext(ctx, `
			SELECT po.id, po.policy_id::text, po.action_override, po.enabled_override,
			       po.expires_at, po.override_reason, po.tenant_id
			FROM policy_overrides po
			WHERE po.policy_type = 'static'
			  AND (po.expires_at IS NULL OR po.expires_at > NOW())
			  AND (
				(po.tenant_id = $1)
				OR (po.organization_id IS NOT NULL AND po.organization_id::text = $2 AND po.tenant_id IS NULL)
			  )
			ORDER BY po.created_at ASC
		`, tenantID, orgIDStr)
		if oErr != nil {
			return oErr
		}
		defer oRows.Close()
		for oRows.Next() {
			var policyUUID string
			var o staticOverrideRow
			var rowTenantID sql.NullString
			if sErr := oRows.Scan(&o.id, &policyUUID, &o.action, &o.enabled, &o.expiresAt, &o.reason, &rowTenantID); sErr != nil {
				continue
			}
			// The WHERE clause above admits exactly two disjoint shapes: a
			// tenant_id match (tenant scope) or an organization_id match with
			// tenant_id IS NULL (org scope) — so tenant_id validity alone
			// determines which branch produced this row.
			o.scope = sharedpolicy.OverrideScopeOrg
			if rowTenantID.Valid && rowTenantID.String != "" {
				o.scope = sharedpolicy.OverrideScopeTenant
			}
			overridesByPolicy[policyUUID] = append(overridesByPolicy[policyUUID], o)
		}
		return oRows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get effective policies: %w", err)
	}

	// Pass B: shared system-tier baseline from the 'global' scope.
	var systemPolicies []StaticPolicy
	err = WithOrgScope(ctx, r.db, GlobalOrgSentinel, func(tx *sql.Tx) error {
		rows, pErr := sharedpolicy.ScanEffectivePolicyRows(ctx, tx,
			`sp.tier = 'system' AND (sp.segment_id IS NULL OR sp.segment_id = ANY($1::text[]))`,
			pq.Array(segArg))
		if pErr != nil {
			return pErr
		}
		systemPolicies = make([]StaticPolicy, 0, len(rows))
		for _, row := range rows {
			systemPolicies = append(systemPolicies, effectiveRowToStaticPolicy(row))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get effective system policies: %w", err)
	}

	merged := append(systemPolicies, tenantPolicies...)

	// Re-establish the single-query ORDER BY: tier (system → organization →
	// tenant), priority DESC, name ASC.
	tierRank := func(t PolicyTier) int {
		switch t {
		case TierSystem:
			return 1
		case TierOrganization:
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(merged, func(i, j int) bool {
		if tierRank(merged[i].Tier) != tierRank(merged[j].Tier) {
			return tierRank(merged[i].Tier) < tierRank(merged[j].Tier)
		}
		if merged[i].Priority != merged[j].Priority {
			return merged[i].Priority > merged[j].Priority
		}
		return merged[i].Name < merged[j].Name
	})

	policies := make([]EffectiveStaticPolicy, 0, len(merged))
	for _, policy := range merged {
		policies = append(policies, applyEffectiveOverride(policy, overridesByPolicy[policy.ID]))
	}

	return policies, nil
}

// effectiveRowToStaticPolicy converts one sharedpolicy.EffectivePolicyRow
// (the shared loader's GetEffective read shape) into the agent's StaticPolicy
// type, replicating the pre-#3296 inline scan's NULL-unwrapping exactly.
func effectiveRowToStaticPolicy(row sharedpolicy.EffectivePolicyRow) StaticPolicy {
	var policy StaticPolicy
	policy.ID = row.ID
	policy.PolicyID = row.PolicyID
	policy.Name = row.Name
	policy.Category = row.Category
	policy.Pattern = row.Pattern
	policy.Severity = row.Severity
	if row.Description.Valid {
		policy.Description = row.Description.String
	}
	policy.Action = row.Action
	policy.Tier = PolicyTier(row.Tier)
	policy.Priority = row.Priority
	policy.Enabled = row.Enabled
	policy.OrganizationID = row.OrganizationID
	policy.TenantID = row.TenantID
	if row.OrgID.Valid {
		policy.OrgID = row.OrgID.String
	}
	if row.SegmentID.Valid && row.SegmentID.String != "" {
		sid := row.SegmentID.String
		policy.SegmentID = &sid
	}
	if row.Tags.Valid && row.Tags.String != "" {
		if uErr := json.Unmarshal([]byte(row.Tags.String), &policy.Tags); uErr != nil {
			policy.Tags = []string{}
		}
	}
	if row.Metadata.Valid && row.Metadata.String != "" {
		policy.Metadata = json.RawMessage(row.Metadata.String)
	}
	policy.Version = row.Version
	policy.CreatedAt = row.CreatedAt
	policy.UpdatedAt = row.UpdatedAt
	if row.CreatedBy.Valid {
		policy.CreatedBy = row.CreatedBy.String
	}
	if row.UpdatedBy.Valid {
		policy.UpdatedBy = row.UpdatedBy.String
	}
	return policy
}

// staticOverrideRow is one policy_overrides row relevant to a static policy's
// GetEffective override resolution (Mechanism A — admin tier-downgrade — see
// platform/shared/policy/override.go's package doc for the mechanism split).
type staticOverrideRow struct {
	id        string
	action    sql.NullString
	enabled   sql.NullBool
	expiresAt sql.NullTime
	reason    sql.NullString
	scope     sharedpolicy.OverrideScope
}

// applyEffectiveOverride resolves policy's override precedence from every
// policy_overrides row known for it (rowsForPolicy, spanning both the tenant
// and org scope, ORDER BY created_at ASC) and returns the EffectiveStaticPolicy.
//
// #3296 Step C / #3320: precedence is delegated to
// sharedpolicy.EffectiveOverride, which resolves the action_override and
// enabled_override columns as two INDEPENDENT attributes — each nullable,
// each tenant-beats-org, each latest-within-scope — rather than assuming a
// single row is "the" override for a policy. This fixes two live bugs the
// single-winner model had:
//   - a disable-only row (action_override NULL, enabled_override=false) used
//     to be silently dropped (the old code only recognized rows with a
//     non-empty action), so a tenant that deliberately disabled a policy saw
//     it re-enabled;
//   - an action-less tenant row used to force scope resolution to "tenant"
//     and then fail to find any tenant row whose action matched, discarding
//     a valid org-level action override in the process.
//
// Segment-scoped policies (policy.SegmentID != nil) never enter the
// override-downgrade path at all (ADR-060 Decision 1) — checked here before
// EffectiveOverride is even consulted, mirroring the pre-#3296 gate exactly;
// EffectiveOverride's own segmentID!="" check is redundant defense-in-depth
// for callers that do not pre-gate.
//
// OverrideReason/OverrideExpiresAt are legacy single-value fields kept for
// wire compatibility; they are populated from ONE representative
// contribution (the action contribution if there is one, else the enabled
// contribution). OverrideContributions carries the full per-row attribution
// and must be preferred by any new caller that needs it, since more than one
// row may be in effect simultaneously — see
// TestGetEffective_TenantOverrideBeatsLaterCreatedOrgOverride and the Fix-1
// tests in static_policy_repository_test.go for the precedence coverage.
func applyEffectiveOverride(policy StaticPolicy, rowsForPolicy []staticOverrideRow) EffectiveStaticPolicy {
	effective := EffectiveStaticPolicy{StaticPolicy: policy}
	if policy.SegmentID != nil || len(rowsForPolicy) == 0 {
		return effective
	}

	orRows := make([]sharedpolicy.OverrideRow, 0, len(rowsForPolicy))
	for _, o := range rowsForPolicy {
		action := ""
		if o.action.Valid {
			action = o.action.String
		}
		var enabled *bool
		if o.enabled.Valid {
			b := o.enabled.Bool
			enabled = &b
		}
		var expiresAt *time.Time
		if o.expiresAt.Valid {
			t := o.expiresAt.Time
			expiresAt = &t
		}
		reason := ""
		if o.reason.Valid {
			reason = o.reason.String
		}
		orRows = append(orRows, sharedpolicy.OverrideRow{
			PolicyID:  policy.ID,
			RowID:     o.id,
			Scope:     o.scope,
			Action:    action,
			Enabled:   enabled,
			Reason:    reason,
			ExpiresAt: expiresAt,
		})
	}

	res := sharedpolicy.EffectiveOverride(policy.ID, "", orRows)
	if !res.HasOverride {
		return effective
	}

	effective.HasOverride = true
	effective.OverrideContributions = res.Contributions
	if res.HasAction {
		action := OverrideAction(res.Action)
		effective.OverrideAction = &action
	}
	if res.HasEnabled {
		enabled := res.Enabled
		effective.OverrideEnabled = &enabled
	}

	// Legacy single-value reason/expiry: prefer the contribution that
	// supplied the action (matches pre-Fix-1 behavior when only one row was
	// ever in effect), else fall back to the one that supplied enabled.
	var primary *sharedpolicy.OverrideContribution
	for i := range res.Contributions {
		if res.Contributions[i].HasAction {
			primary = &res.Contributions[i]
			break
		}
	}
	if primary == nil && len(res.Contributions) > 0 {
		primary = &res.Contributions[0]
	}
	if primary != nil {
		effective.OverrideReason = primary.Reason
		effective.OverrideExpiresAt = primary.ExpiresAt
	}

	return effective
}

// GetVersions retrieves version history for a policy.
// Community: Returns last 5 versions
// Enterprise: Returns all versions
func (r *StaticPolicyRepository) GetVersions(ctx context.Context, policyID string, tenantID string) ([]StaticPolicyVersion, error) {
	// Check if Enterprise
	isEnterprise, err := r.isEnterpriseLicense(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to check license: %w", err)
	}

	limit := MaxVersionHistoryCommunity
	if isEnterprise {
		limit = 1000 // Effectively unlimited for practical purposes
	}

	// The parent-ownership predicate is load-bearing on deployments where the
	// pool bypasses RLS (owner/master): without it any tenant could read any
	// policy's full version snapshots by ID (#3048 — mirrors the orchestrator
	// GetVersions fix in #3040). System-tier parents are the shared baseline
	// every tenant may see; tenant-tier parents must belong to the caller's
	// tenant; organization-tier parents to the caller's org (R3 MEDIUM-5 —
	// mirrors GetEffective's pass-A predicate). Under app-role RLS the same
	// predicate evaluates against the transaction's org GUC.
	query := `
		SELECT v.id, v.policy_id, v.version, v.snapshot, v.change_type, v.change_summary, v.changed_by, v.changed_at
		FROM static_policy_versions v
		WHERE v.policy_id = $1
		  AND EXISTS (
			SELECT 1 FROM static_policies sp
			WHERE sp.id::text = v.policy_id::text
			  AND (
				sp.tier = 'system'
				OR sp.tenant_id = $2
				OR (sp.tier = 'organization' AND sp.organization_id::text = $3)
			  )
		  )
		ORDER BY v.version DESC
		LIMIT $4
	`

	// static_policy_versions is RLS-enabled keyed on app.current_org_id (mig
	// 110); version rows carry the parent policy's org_id (recordVersion
	// wraps its INSERT in the same scope). Read under the caller's org scope
	// first, falling back to the 'global' scope for system-policy version
	// rows (#3048). Empty caller org keeps the legacy bare read
	// (single-tenant/community owner-pool contexts).
	callerOrgArg := OrgIDFromContext(ctx)
	scanVersions := func(q func(query string, args ...interface{}) (*sql.Rows, error)) ([]StaticPolicyVersion, error) {
		rows, qErr := q(query, policyID, tenantID, callerOrgArg, limit)
		if qErr != nil {
			return nil, fmt.Errorf("failed to get versions: %w", qErr)
		}
		defer rows.Close()

		out := make([]StaticPolicyVersion, 0)
		for rows.Next() {
			var v StaticPolicyVersion
			var changeSummary, changedBy sql.NullString

			if sErr := rows.Scan(
				&v.ID, &v.PolicyID, &v.Version, &v.Snapshot,
				&v.ChangeType, &changeSummary, &changedBy, &v.ChangedAt,
			); sErr != nil {
				continue
			}

			if changeSummary.Valid {
				v.ChangeSummary = changeSummary.String
			}
			if changedBy.Valid {
				v.ChangedBy = changedBy.String
			}

			out = append(out, v)
		}
		if rErr := rows.Err(); rErr != nil {
			return nil, fmt.Errorf("error iterating versions: %w", rErr)
		}
		return out, nil
	}

	scopedVersions := func(scopeOrg string) ([]StaticPolicyVersion, error) {
		var out []StaticPolicyVersion
		err := WithOrgScope(ctx, r.db, scopeOrg, func(tx *sql.Tx) error {
			var sErr error
			out, sErr = scanVersions(func(q string, args ...interface{}) (*sql.Rows, error) {
				return tx.QueryContext(ctx, q, args...)
			})
			return sErr
		})
		return out, err
	}

	scopeOrg := OrgIDFromContext(ctx)
	if scopeOrg == "" {
		scopeOrg = tenantID
	}

	var versions []StaticPolicyVersion
	if scopeOrg == "" {
		versions, err = scanVersions(func(q string, args ...interface{}) (*sql.Rows, error) {
			return r.db.QueryContext(ctx, q, args...)
		})
	} else {
		versions, err = scopedVersions(scopeOrg)
		if err == nil && len(versions) == 0 && scopeOrg != GlobalOrgSentinel {
			versions, err = scopedVersions(GlobalOrgSentinel)
		}
	}
	if err != nil {
		return nil, err
	}

	return versions, nil
}

// ToggleEnabled enables or disables a policy.
func (r *StaticPolicyRepository) ToggleEnabled(ctx context.Context, policyID string, enabled bool, updatedBy string) error {
	// Get existing policy to check tier
	policy, err := r.GetByID(ctx, policyID)
	if err != nil {
		return err
	}

	// System tier policies cannot be disabled
	if policy.Tier == TierSystem && !enabled {
		return ErrSystemPolicyModification
	}
	// #3048 R3 BLOCKER-1: no tenant caller may toggle the shared
	// 'global'-wildcard baseline in EITHER direction — disabling kills a
	// deployment-wide protection; enabling flips integration policies
	// (int_*) for every org, which is the activation flow's job, not a
	// tenant admin's (see rejectGlobalBaselineWrite).
	if rejectGlobalBaselineWrite(ctx, policy) {
		return ErrSystemPolicyModification
	}
	// Cross-org toggles are already blocked by the GetByID tenant-isolation guard.

	query := `
		UPDATE static_policies
		SET enabled = $1, updated_at = $2, updated_by = $3, version = version + 1
		WHERE id = $4 AND deleted_at IS NULL
	`

	// v9 Phase 8 #2384 PR-C1: wrap ToggleEnabled UPDATE in WithOrgScope so
	// the USING predicate sees the row under app_role.
	if policy.OrgID == "" {
		return fmt.Errorf("ToggleEnabled: existing policy.OrgID missing (RLS enforced by mig 018)")
	}
	var rowsAffected int64
	err = WithOrgScope(ctx, r.db, policy.OrgID, func(tx *sql.Tx) error {
		result, exErr := tx.ExecContext(ctx, query, enabled, time.Now().UTC(), updatedBy, policy.ID)
		if exErr != nil {
			return fmt.Errorf("failed to toggle enabled: %w", exErr)
		}
		var raErr error
		rowsAffected, raErr = result.RowsAffected()
		if raErr != nil {
			return fmt.Errorf("failed to get affected rows: %w", raErr)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrPolicyNotFound
	}

	// Record version history
	changeType := "enable"
	if !enabled {
		changeType = "disable"
	}
	// Record version history (best effort - don't fail on error)
	_ = r.recordVersion(ctx, policy, changeType, fmt.Sprintf("Policy %sd", changeType), updatedBy)

	return nil
}

// Helper methods

// recordVersion records a version history entry for a policy.
func (r *StaticPolicyRepository) recordVersion(ctx context.Context, policy *StaticPolicy, changeType, changeSummary, changedBy string) error {
	// Create snapshot
	snapshot, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy snapshot: %w", err)
	}

	// v9 Phase 8 PR-C1 (#2384): mig 110 (landed via PR-C2) normalized
	// static_policy_versions's RLS policy from the legacy app.tenant_id GUC
	// to app.current_org_id — the table now requires the wrap-and-org_id-col
	// pair under axonflow_app_role. Without it, the INSERT here would fail
	// 42501 the moment app_role flips on (the outer Create/Update/Delete
	// wraps COMMIT before recordVersion runs, so app.current_org_id is
	// cleared by the time we get here — a fresh wrap is required).
	if policy.OrgID == "" {
		return fmt.Errorf("recordVersion: policy.OrgID must be non-empty (RLS on static_policy_versions post mig 110)")
	}
	query := `
		INSERT INTO static_policy_versions (
			id, policy_id, version, snapshot, change_type, change_summary, changed_by, changed_at
		) VALUES (
			$1, $2, $3, $4::jsonb, $5, $6, $7, $8
		)
	`

	err = WithOrgScope(ctx, r.db, policy.OrgID, func(tx *sql.Tx) error {
		_, exErr := tx.ExecContext(ctx, query,
			uuid.New().String(),
			policy.ID,
			policy.Version,
			string(snapshot),
			changeType,
			changeSummary,
			changedBy,
			time.Now().UTC(),
		)
		return exErr
	})
	if err != nil {
		return fmt.Errorf("failed to record version: %w", err)
	}

	return nil
}

// countTenantPolicies counts the number of tenant-tier policies for a tenant.
func (r *StaticPolicyRepository) countTenantPolicies(ctx context.Context, tenantID string) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM static_policies
		WHERE tenant_id = $1 AND tier = 'tenant' AND deleted_at IS NULL
	`

	// Org-scoped (#3048): under axonflow_app_role the bare COUNT read 0
	// through mig 018's RLS, so the Community tenant-policy limit never
	// engaged. Same scope key Create uses for the row's org_id.
	scopeOrg := OrgIDFromContext(ctx)
	if scopeOrg == "" {
		scopeOrg = tenantID
	}
	var count int
	err := WithOrgScope(ctx, r.db, scopeOrg, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, tenantID).Scan(&count)
	})
	if err != nil {
		return 0, err
	}

	return count, nil
}

// isEnterpriseLicense checks if the tenant has an Enterprise license.
func (r *StaticPolicyRepository) isEnterpriseLicense(ctx context.Context, tenantID string) (bool, error) {
	// Check license via AXONFLOW_LICENSE_KEY environment variable
	if license.IsEnterpriseTier(ctx) {
		return true, nil
	}

	// Fall back to database lookup for license tier
	// Query the client/tenant for license tier
	query := `
		SELECT license_tier
		FROM clients
		WHERE tenant_id = $1 AND enabled = true
		LIMIT 1
	`

	var tier sql.NullString
	err := r.db.QueryRowContext(ctx, query, tenantID).Scan(&tier)
	if err == sql.ErrNoRows {
		// No client found, default to Community
		return false, nil
	}
	if err != nil {
		// If the clients table doesn't exist (development/testing), default to Community
		if strings.Contains(err.Error(), "relation") && strings.Contains(err.Error(), "does not exist") {
			return false, nil
		}
		return false, err
	}

	if tier.Valid {
		tierVal := license.Tier(tier.String)
		return tierVal == license.TierEnterprise || tierVal == license.TierEnterprisePlus, nil
	}

	return false, nil
}

// Note: validateRE2Pattern is defined in pattern_validator.go

// toNullString converts a string to sql.NullString.
// Empty strings are converted to NULL.
func toNullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}
