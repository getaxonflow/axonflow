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
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent"
)

// GlobalTenantSentinel is the tenant_id/org_id wildcard used by system-seeded
// policies that apply across all tenants (mig 090's 'global' sentinel).
const GlobalTenantSentinel = "global"

// PolicyRepository handles database operations for policies
type PolicyRepository struct {
	db *sql.DB
	// crossOrgDB serves deliberate cross-tenant reads (CountOrgPolicies).
	// Optional: when unset those reads run on db, which is only correct on
	// deployments where db bypasses RLS (AXONFLOW_DB_USE_APP_ROLE=false).
	// See #3039.
	crossOrgDB *sql.DB
}

// NewPolicyRepository creates a new policy repository
func NewPolicyRepository(db *sql.DB) *PolicyRepository {
	return &PolicyRepository{db: db}
}

// SetCrossOrgDB installs a BYPASSRLS (axonflow_platform_admin) pool for the
// repository's deliberate cross-tenant reads. Under axonflow_app_role those
// reads silently count 0 rows through RLS (#3039).
func (r *PolicyRepository) SetCrossOrgDB(db *sql.DB) {
	r.crossOrgDB = db
}

func (r *PolicyRepository) crossOrg() *sql.DB {
	if r.crossOrgDB != nil {
		return r.crossOrgDB
	}
	return r.db
}

// Create inserts a new policy into the database
func (r *PolicyRepository) Create(ctx context.Context, policy *PolicyResource) error {
	conditionsJSON, err := json.Marshal(policy.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	actionsJSON, err := json.Marshal(policy.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	// Generate UUID if not provided
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}

	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now
	policy.Version = 1

	// Default tier to tenant if not specified
	tier := policy.Tier
	if tier == "" {
		tier = TierTenant
	}

	// Decision 5 (#3490) R3 BLOCKER: org_id is written from the AUTHENTICATED
	// organisation, not from the tenant. It used to be bound to $9 alongside
	// tenant_id and client_id - all three the Basic-auth username - and once
	// org_id became the selection key that made every policy created here
	// either unenforceable (stamped with an organisation nobody authenticates
	// as, in any deployment whose licence org differs from the tenant string)
	// or, on a forged username, injectable into somebody else's organisation.
	// The GUC below is set from the same value, so the two cannot disagree.
	//
	// Refused rather than defaulted when absent. A silent fallback to the
	// tenant is precisely the behaviour being removed, and it fails in the
	// quietest possible way: a 201, a row in the CRUD listing, and no
	// enforcement anywhere.
	//
	// #3334 removes the legacy organization_id column (migration core/166)
	// and with it the empty-string-to-nil dance this INSERT used to do for a
	// column typed uuid until core/133. The refusal above is what makes that
	// removal safe: there is no longer a second organisation column to
	// disagree with, and the one that remains can never be blank.
	if strings.TrimSpace(policy.OrganizationID) == "" {
		return fmt.Errorf("Create: policy.OrganizationID must be non-empty (it is the org_id that selects this policy; #3490)")
	}

	// v9 compat (Epic #2230 Phase 2/4): client_id mirrors tenant_id ($9)
	// during v9 compat window. Migration 090 added client_id to
	// dynamic_policies. 'global' wildcard sentinel preserves verbatim.
	//
	// v9 Phase 8 PR-C2 (#2384): dynamic_policies is mig 018 ENABLE RLS with
	// policy `org_id = get_current_org_id()`. The legacy INSERT omitted the
	// `org_id` column (only set tenant_id + organization_id UUID), which left
	// org_id NULL on inserted rows - under axonflow_app_role the WITH CHECK
	// rejected the INSERT outright. Fix: add org_id col, populate with
	// policy.TenantID (== orgID at this writer post-Phase-6 collapse), wrap
	// in WithOrgScope so the GUC + INSERT col match.
	query := `
		INSERT INTO dynamic_policies (
			policy_id, name, description, policy_type, category, tier,
			conditions, actions, tenant_id, client_id, org_id,
			priority, enabled, version, created_by, updated_by,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`

	if err := agent.WithOrgScope(ctx, r.db, policy.OrganizationID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			policy.ID, policy.Name, policy.Description, string(policy.Type), policy.Category, string(tier),
			conditionsJSON, actionsJSON, policy.TenantID, policy.OrganizationID,
			policy.Priority, policy.Enabled, policy.Version, policy.CreatedBy, policy.UpdatedBy,
			policy.CreatedAt, policy.UpdatedAt,
		)
		if execErr != nil {
			return execErr
		}
		// policy_versions INSERT is gated by `policy_id IN (SELECT FROM dynamic_policies
		// WHERE [implicit RLS])`. Running it inside the same wrap tx lets the
		// subquery see the freshly-inserted parent row under app_role. Pass the
		// full PolicyResource so the snapshot preserves Category/Tier/etc.
		return r.createVersionEntryTx(ctx, tx, policy, policy.UpdatedBy, "create", "Policy created")
	}); err != nil {
		return fmt.Errorf("failed to insert policy: %w", err)
	}

	return nil
}

// GetByID retrieves a policy by its ID
// crudScope picks the value bound to app.current_org_id for this repository's
// CRUD statements.
//
// Decision 5 (#3490) R3: Create and ImportBulk now write org_id from the
// AUTHENTICATED organisation and set the GUC from the same value, while every
// reader and the Update/Delete writers still set it from the TENANT. Under
// axonflow_app_role that is a real divergence and not a cosmetic one: mig 018's
// USING clause is `org_id = get_current_org_id()`, so a policy created with
// org_id = "acme" is invisible to a connection whose GUC says "team-a" - the
// create returns 201, the read-back 404s, Update reports zero rows affected and
// Delete silently removes nothing. That is the #3039 failure shape, arriving
// again by a different route, and the SaaS stacks are app-role provisioned.
//
// The org is used when the caller has one and the tenant otherwise. The tenant
// fallback is not a second selection key: the WHERE clauses in this file remain
// tenant-scoped exactly as before, so this changes only which rows RLS unlocks,
// never which rows are asked for. Where no org is available the behaviour is
// byte-for-byte what it was.
func crudScope(tenantID, orgID string) string {
	if s := strings.TrimSpace(orgID); s != "" {
		return s
	}
	return tenantID
}

func (r *PolicyRepository) GetByID(ctx context.Context, tenantID, orgID, policyID string) (*PolicyResource, error) {
	query := `
		SELECT policy_id, name, description, policy_type,
		       COALESCE(category, ''), COALESCE(tier, 'tenant'),
		       conditions, actions, tenant_id, COALESCE(org_id, ''),
		       priority, enabled, COALESCE(version, 1),
		       COALESCE(created_by, ''), COALESCE(updated_by, ''),
		       created_at, updated_at
		FROM dynamic_policies
		WHERE policy_id = $1 AND (tenant_id = $2 OR tenant_id = 'global')
	`

	policy := &PolicyResource{}
	var conditionsJSON, actionsJSON []byte
	var policyType, category, tier, rowOrgID string

	// dynamic_policies is RLS-enabled (mig 018, org_id = get_current_org_id()).
	// The writers in this repository already wrap in WithOrgScope; the readers
	// never did, so under axonflow_app_role a freshly created policy 404'd on
	// read-back (#3039). The WHERE admits both the tenant's rows and the
	// 'global' wildcard rows, but a single GUC can only unlock one org's rows
	// at a time — read under the tenant scope first, then fall back to the
	// 'global' scope so system-tier wildcard policies stay retrievable.
	scopedGet := func(scopeOrg string) error {
		return agent.WithOrgScope(ctx, r.db, scopeOrg, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, query, policyID, tenantID).Scan(
				&policy.ID, &policy.Name, &policy.Description, &policyType,
				&category, &tier,
				&conditionsJSON, &actionsJSON, &policy.TenantID, &rowOrgID,
				&policy.Priority, &policy.Enabled, &policy.Version,
				&policy.CreatedBy, &policy.UpdatedBy,
				&policy.CreatedAt, &policy.UpdatedAt,
			)
		})
	}
	err := scopedGet(crudScope(tenantID, orgID))
	if err == sql.ErrNoRows && crudScope(tenantID, orgID) != GlobalTenantSentinel {
		err = scopedGet(GlobalTenantSentinel)
	}

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	policy.Type = string(policyType)
	policy.Category = category
	policy.Tier = PolicyTier(tier)
	policy.OrganizationID = rowOrgID

	if err := json.Unmarshal(conditionsJSON, &policy.Conditions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal conditions: %w", err)
	}

	if err := json.Unmarshal(actionsJSON, &policy.Actions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal actions: %w", err)
	}

	return policy, nil
}

// List retrieves policies with filtering and pagination
func (r *PolicyRepository) List(ctx context.Context, tenantID, orgID string, params ListPoliciesParams) ([]PolicyResource, int, error) {
	// Build dynamic query
	// Include both tenant-specific and system/global policies. The tenancy
	// predicate is a $1 placeholder filled PER SCOPE below (tenant pass reads
	// tenant_id = tenantID, global pass reads tenant_id = 'global') so the
	// two scoped queries return disjoint sets on every deployment — with or
	// without RLS enforcement (#3039).
	whereConditions := []string{"tenant_id = $1"}
	args := []interface{}{tenantID}
	argIndex := 2

	if params.Type != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("policy_type = $%d", argIndex))
		args = append(args, params.Type)
		argIndex++
	}

	if params.Category != "" {
		if strings.Contains(params.Category, "%") {
			whereConditions = append(whereConditions, fmt.Sprintf("category LIKE $%d", argIndex))
		} else {
			whereConditions = append(whereConditions, fmt.Sprintf("category = $%d", argIndex))
		}
		args = append(args, params.Category)
		argIndex++
	}

	if params.Enabled != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("enabled = $%d", argIndex))
		args = append(args, *params.Enabled)
		argIndex++
	}

	// Tier filter (system / organization / tenant). The handler only sets
	// params.Tier when the caller supplied ?tier=... in the query string,
	// so a nil pointer means "no tier filter" rather than "tier=''".
	if params.Tier != nil && *params.Tier != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("tier = $%d", argIndex))
		args = append(args, string(*params.Tier))
		argIndex++
	}

	if params.Search != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, "%"+params.Search+"%")
	}

	whereClause := strings.Join(whereConditions, " AND ")

	// Sort and pagination
	sortBy := "created_at"
	if params.SortBy != "" {
		// Validate sort field
		validSorts := map[string]bool{"name": true, "priority": true, "created_at": true, "updated_at": true}
		if validSorts[params.SortBy] {
			sortBy = params.SortBy
		}
	}

	sortDir := "DESC"
	if params.SortDir == "asc" {
		sortDir = "ASC"
	}

	// Default pagination
	if params.Page < 1 {
		params.Page = 1
	}
	if params.PageSize < 1 || params.PageSize > 100 {
		params.PageSize = 20
	}

	offset := (params.Page - 1) * params.PageSize

	// The WHERE admits both the tenant's rows and the 'global' wildcard rows,
	// but dynamic_policies is RLS-enabled (mig 018, org_id =
	// get_current_org_id()) and a single GUC unlocks one org's rows at a time.
	// Under axonflow_app_role the old bare read returned 0 rows (#3039).
	// Query each scope in its own WithOrgScope wrap (RLS does the row
	// filtering per scope; the SQL filter keeps deployments without app-role
	// on the same result shape), merge, sort, and paginate in memory. Policy
	// counts are tier-capped, so the full-set read stays small.
	query := fmt.Sprintf(`
		SELECT policy_id, name, description, policy_type,
		       COALESCE(category, ''), COALESCE(tier, 'tenant'),
		       conditions, actions, tenant_id, COALESCE(org_id, ''),
		       priority, enabled, COALESCE(version, 1),
		       COALESCE(created_by, ''), COALESCE(updated_by, ''),
		       created_at, updated_at
		FROM dynamic_policies
		WHERE %s
		ORDER BY %s %s
	`, whereClause, sortBy, sortDir)

	scopedList := func(scopeOrg string) ([]PolicyResource, error) {
		// Per-scope tenancy arg: $1 = the scope being read, so the tenant
		// pass and the global pass return disjoint sets even without RLS.
		scopeArgs := make([]interface{}, len(args))
		copy(scopeArgs, args)
		scopeArgs[0] = scopeOrg
		var out []PolicyResource
		scopeErr := agent.WithOrgScope(ctx, r.db, scopeOrg, func(tx *sql.Tx) error {
			rows, qErr := tx.QueryContext(ctx, query, scopeArgs...)
			if qErr != nil {
				return qErr
			}
			defer func() { _ = rows.Close() }()

			for rows.Next() {
				var policy PolicyResource
				var conditionsJSON, actionsJSON []byte
				var policyType, category, tier, orgID string

				if sErr := rows.Scan(
					&policy.ID, &policy.Name, &policy.Description, &policyType,
					&category, &tier,
					&conditionsJSON, &actionsJSON, &policy.TenantID, &orgID,
					&policy.Priority, &policy.Enabled, &policy.Version,
					&policy.CreatedBy, &policy.UpdatedBy,
					&policy.CreatedAt, &policy.UpdatedAt,
				); sErr != nil {
					return fmt.Errorf("failed to scan policy: %w", sErr)
				}

				policy.Type = string(policyType)
				policy.Category = category
				policy.Tier = PolicyTier(tier)
				policy.OrganizationID = orgID

				if uErr := json.Unmarshal(conditionsJSON, &policy.Conditions); uErr != nil {
					return fmt.Errorf("failed to unmarshal conditions: %w", uErr)
				}
				if uErr := json.Unmarshal(actionsJSON, &policy.Actions); uErr != nil {
					return fmt.Errorf("failed to unmarshal actions: %w", uErr)
				}
				out = append(out, policy)
			}
			return rows.Err()
		})
		if scopeErr != nil {
			return nil, scopeErr
		}
		return out, nil
	}

	policies, err := scopedList(crudScope(tenantID, orgID))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list policies: %w", err)
	}
	if crudScope(tenantID, orgID) != GlobalTenantSentinel {
		globalPolicies, gErr := scopedList(GlobalTenantSentinel)
		if gErr != nil {
			return nil, 0, fmt.Errorf("failed to list global policies: %w", gErr)
		}
		policies = append(policies, globalPolicies...)
	}

	sortPolicyResources(policies, sortBy, sortDir)

	total := len(policies)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + params.PageSize
	if end > total {
		end = total
	}
	return policies[offset:end], total, nil
}

// sortPolicyResources orders the merged tenant+global result set by the
// validated sort column, mirroring the ORDER BY the per-scope queries used.
func sortPolicyResources(policies []PolicyResource, sortBy, sortDir string) {
	asc := strings.EqualFold(sortDir, "ASC")
	sort.SliceStable(policies, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "name":
			less = policies[i].Name < policies[j].Name
		case "priority":
			less = policies[i].Priority < policies[j].Priority
		case "updated_at":
			less = policies[i].UpdatedAt.Before(policies[j].UpdatedAt)
		default: // created_at
			less = policies[i].CreatedAt.Before(policies[j].CreatedAt)
		}
		if asc {
			return less
		}
		return !less && !policyResourceSortEqual(policies[i], policies[j], sortBy)
	})
}

func policyResourceSortEqual(a, b PolicyResource, sortBy string) bool {
	switch sortBy {
	case "name":
		return a.Name == b.Name
	case "priority":
		return a.Priority == b.Priority
	case "updated_at":
		return a.UpdatedAt.Equal(b.UpdatedAt)
	default:
		return a.CreatedAt.Equal(b.CreatedAt)
	}
}

// Update modifies an existing policy
func (r *PolicyRepository) Update(ctx context.Context, tenantID, orgID, policyID string, req *UpdatePolicyRequest, updatedBy string) (*PolicyResource, error) {
	// Get current policy for version history
	current, err := r.GetByID(ctx, tenantID, orgID, policyID)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, nil
	}

	// Build dynamic update
	updates := []string{}
	args := []interface{}{}
	argIndex := 1

	if req.Name != nil {
		updates = append(updates, fmt.Sprintf("name = $%d", argIndex))
		args = append(args, *req.Name)
		argIndex++
	}

	if req.Description != nil {
		updates = append(updates, fmt.Sprintf("description = $%d", argIndex))
		args = append(args, *req.Description)
		argIndex++
	}

	if req.Type != nil {
		updates = append(updates, fmt.Sprintf("policy_type = $%d", argIndex))
		args = append(args, string(*req.Type))
		argIndex++
	}

	if req.Conditions != nil {
		conditionsJSON, err := json.Marshal(req.Conditions)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal conditions: %w", err)
		}
		updates = append(updates, fmt.Sprintf("conditions = $%d", argIndex))
		args = append(args, conditionsJSON)
		argIndex++
	}

	if req.Actions != nil {
		actionsJSON, err := json.Marshal(req.Actions)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal actions: %w", err)
		}
		updates = append(updates, fmt.Sprintf("actions = $%d", argIndex))
		args = append(args, actionsJSON)
		argIndex++
	}

	if req.Priority != nil {
		updates = append(updates, fmt.Sprintf("priority = $%d", argIndex))
		args = append(args, *req.Priority)
		argIndex++
	}

	if req.Enabled != nil {
		updates = append(updates, fmt.Sprintf("enabled = $%d", argIndex))
		args = append(args, *req.Enabled)
		argIndex++
	}

	if len(updates) == 0 {
		return current, nil // Nothing to update
	}

	// Always update version, updated_by, updated_at
	newVersion := current.Version + 1
	updates = append(updates, fmt.Sprintf("version = $%d", argIndex))
	args = append(args, newVersion)
	argIndex++

	updates = append(updates, fmt.Sprintf("updated_by = $%d", argIndex))
	args = append(args, updatedBy)
	argIndex++

	updates = append(updates, fmt.Sprintf("updated_at = $%d", argIndex))
	args = append(args, time.Now())
	argIndex++

	// Add WHERE clause parameters
	args = append(args, policyID, tenantID)

	query := fmt.Sprintf(`
		UPDATE dynamic_policies
		SET %s
		WHERE policy_id = $%d AND tenant_id = $%d
	`, strings.Join(updates, ", "), argIndex, argIndex+1)

	// v9 Phase 8 PR-C2 (#2384): wrap so both the UPDATE (gated by mig 018
	// USING `org_id = get_current_org_id()`) and the policy_versions INSERT
	// downstream see the same app.current_org_id GUC under app_role.
	var rowsAffected int64
	if wrapErr := agent.WithOrgScope(ctx, r.db, crudScope(tenantID, orgID), func(tx *sql.Tx) error {
		result, execErr := tx.ExecContext(ctx, query, args...)
		if execErr != nil {
			return fmt.Errorf("failed to update policy: %w", execErr)
		}
		rowsAffected, _ = result.RowsAffected()
		if rowsAffected == 0 {
			return nil
		}

		// Create version history entry within the same tx so the policy_versions
		// WITH CHECK subquery sees the just-updated dynamic_policies row.
		// Snapshot is the full PolicyResource — start from `current` (preserves
		// Category, Tier, OrganizationID, TenantID, ClientID, CreatedBy,
		// CreatedAt) and patch the mutated fields.
		snapshot := *current // shallow copy ok; slices/maps are replaced wholesale below
		snapshot.Version = newVersion
		snapshot.UpdatedBy = updatedBy
		snapshot.UpdatedAt = time.Now()
		if req.Name != nil {
			snapshot.Name = *req.Name
		}
		if req.Description != nil {
			snapshot.Description = *req.Description
		}
		if req.Type != nil {
			snapshot.Type = string(*req.Type)
		}
		if req.Conditions != nil {
			snapshot.Conditions = req.Conditions
		}
		if req.Actions != nil {
			snapshot.Actions = req.Actions
		}
		if req.Priority != nil {
			snapshot.Priority = *req.Priority
		}
		if req.Enabled != nil {
			snapshot.Enabled = *req.Enabled
		}

		changeType := "update"
		if req.Enabled != nil && !*req.Enabled && current.Enabled {
			changeType = "disable"
		} else if req.Enabled != nil && *req.Enabled && !current.Enabled {
			changeType = "enable"
		}
		return r.createVersionEntryTx(ctx, tx, &snapshot, updatedBy, changeType, fmt.Sprintf("Policy updated to version %d", newVersion))
	}); wrapErr != nil {
		return nil, wrapErr
	}
	if rowsAffected == 0 {
		return nil, nil
	}

	// Re-read after the wrap commits. Note: under axonflow_app_role this
	// SELECT runs WITHOUT the wrap's transaction-local GUC (already dropped
	// by COMMIT) and is gated by mig 018's USING `org_id = get_current_org_id()`
	// policy. If the caller's connection has no app.current_org_id set at
	// session level, GetByID returns nil — the audit/version write inside the
	// wrap still succeeded, but the response shaping degrades to "no body".
	// Resolution lives in the broader read-path work (orchestrator handler
	// wraps that bracket Update+GetByID together). PR-C2 keeps this read
	// post-commit to match the v8 contract; PR-D's audit walker will not
	// flag this site as a write.
	updated, _ := r.GetByID(ctx, tenantID, orgID, policyID)
	return updated, nil
}

// Delete removes a policy.
//
// v9 Phase 8 PR-C2 (#2384): wrap so the policy_versions audit INSERT + the
// dynamic_policies DELETE land under the same app.current_org_id GUC. The
// DELETE USING policy `org_id = get_current_org_id()` is silent under app_role
// without the GUC (zero rows affected, no error). The wrap also ensures
// FK CASCADE from dynamic_policies → policy_versions sees the parent's RLS
// context.
func (r *PolicyRepository) Delete(ctx context.Context, tenantID, orgID, policyID string, deletedBy string) error {
	// Get current policy for version history
	current, err := r.GetByID(ctx, tenantID, orgID, policyID)
	if err != nil {
		return err
	}
	if current == nil {
		return nil
	}

	return agent.WithOrgScope(ctx, r.db, crudScope(tenantID, orgID), func(tx *sql.Tx) error {
		// Create delete version entry inside the wrap tx (was: best-effort outside-tx
		// call that swallowed errors). Under app_role this MUST succeed before the
		// DELETE because once dynamic_policies row is gone the policy_versions FK
		// subquery has nothing to anchor on.
		// Snapshot the FULL current state (Category/Tier/OrganizationID/etc.)
		// so the audit row reflects what was deleted, not a CreatePolicyRequest-
		// shaped subset.
		if vErr := r.createVersionEntryTx(ctx, tx, current, deletedBy, "delete", "Policy deleted"); vErr != nil {
			return vErr
		}

		query := `DELETE FROM dynamic_policies WHERE policy_id = $1 AND tenant_id = $2`
		if _, dErr := tx.ExecContext(ctx, query, policyID, tenantID); dErr != nil {
			return fmt.Errorf("failed to delete policy: %w", dErr)
		}
		return nil
	})
}

// GetVersions retrieves version history for a policy
func (r *PolicyRepository) GetVersions(ctx context.Context, tenantID, policyID string) ([]PolicyVersionEntry, error) {
	// The parent-ownership predicate is load-bearing on deployments where
	// the pool bypasses RLS (superuser/master): without it any tenant could
	// read any policy's full version snapshots by ID. Under app-role RLS
	// the same subquery evaluates against the transaction's org GUC.
	query := `
		SELECT version, snapshot, COALESCE(changed_by, ''), changed_at,
		       change_type, COALESCE(change_summary, '')
		FROM policy_versions
		WHERE policy_id = $1
		  AND policy_id IN (
			SELECT policy_id FROM dynamic_policies
			WHERE tenant_id = $2 OR tenant_id = 'global'
		  )
		ORDER BY version DESC
	`

	// policy_versions is RLS-enabled (mig 022, re-keyed to org_id in mig 110)
	// — read under the tenant scope, falling back to the 'global' scope for
	// system-seeded wildcard policies (#3039).
	scopedVersions := func(scopeOrg string) ([]PolicyVersionEntry, error) {
		var out []PolicyVersionEntry
		scopeErr := agent.WithOrgScope(ctx, r.db, scopeOrg, func(tx *sql.Tx) error {
			rows, qErr := tx.QueryContext(ctx, query, policyID, tenantID)
			if qErr != nil {
				return qErr
			}
			defer func() { _ = rows.Close() }()

			for rows.Next() {
				var entry PolicyVersionEntry
				var snapshotJSON []byte

				if sErr := rows.Scan(&entry.Version, &snapshotJSON, &entry.ChangedBy,
					&entry.ChangedAt, &entry.ChangeType, &entry.ChangeSummary); sErr != nil {
					return fmt.Errorf("failed to scan version: %w", sErr)
				}
				if uErr := json.Unmarshal(snapshotJSON, &entry.Snapshot); uErr != nil {
					return fmt.Errorf("failed to unmarshal snapshot: %w", uErr)
				}
				out = append(out, entry)
			}
			return rows.Err()
		})
		if scopeErr != nil {
			return nil, scopeErr
		}
		return out, nil
	}

	versions, err := scopedVersions(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get versions: %w", err)
	}
	if len(versions) == 0 && tenantID != GlobalTenantSentinel {
		if versions, err = scopedVersions(GlobalTenantSentinel); err != nil {
			return nil, fmt.Errorf("failed to get versions: %w", err)
		}
	}

	return versions, nil
}

// ExportAll exports all policies for a tenant.
//
// Pages through List in max-page-size chunks: the old single call passed
// PageSize 1000, which List's clamp silently reset to 20 — exports were
// truncated to 20 policies (#3039 R3 finding).
func (r *PolicyRepository) ExportAll(ctx context.Context, tenantID, orgID string) ([]PolicyResource, error) {
	var all []PolicyResource
	for page := 1; ; page++ {
		policies, total, err := r.List(ctx, tenantID, orgID, ListPoliciesParams{Page: page, PageSize: 100})
		if err != nil {
			return nil, err
		}
		all = append(all, policies...)
		if len(policies) == 0 || len(all) >= total {
			return all, nil
		}
	}
}

// ImportBulk imports multiple policies within a transaction.
//
// v9 Phase 8 PR-C2 (#2384): wraps the import tx with WithOrgScope so every
// child INSERT into dynamic_policies + policy_versions sees the
// app.current_org_id GUC set before WITH CHECK fires.
//
// Decision 5 (#3490): that GUC, and the org_id every child INSERT writes, come
// from the AUTHENTICATED organisation rather than from the tenant. This is the
// second write path into dynamic_policies and it had exactly the defect Create
// was fixed for: org_id was bound to the same $7 as tenant_id and client_id -
// the Basic-auth username - so in any deployment whose licence org differs
// from that string, every bulk-imported policy was stamped with an
// organisation nobody authenticates as. It enforced on NOBODY while returning
// 200 and appearing in the CRUD listing, and on a forged username it was
// injectable into another organisation. Both routes that reach here
// (/api/v1/policies/import and /api/v1/dynamic-policies/import) are proxied by
// the agent, which Sets X-Org-ID from the validated licence, so the org is
// present on the real path and is refused rather than defaulted when it is not.
func (r *PolicyRepository) ImportBulk(ctx context.Context, tenantID, orgID string, policies []CreatePolicyRequest, mode string, importedBy string) (*ImportPoliciesResponse, error) {
	response := &ImportPoliciesResponse{}

	if strings.TrimSpace(orgID) == "" {
		return nil, fmt.Errorf("ImportBulk: orgID must be non-empty (it is the org_id that selects every imported policy; #3490)")
	}

	wrapErr := agent.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		for _, req := range policies {
			// Check if policy already exists by name
			existing, checkErr := r.findByNameTx(ctx, tx, tenantID, orgID, req.Name)
			if checkErr != nil {
				response.Errors = append(response.Errors, fmt.Sprintf("Error checking policy %s: %v", req.Name, checkErr))
				continue
			}

			if existing != nil {
				switch mode {
				case "skip":
					response.Skipped++
					continue
				case "error":
					response.Errors = append(response.Errors, fmt.Sprintf("Policy %s already exists", req.Name))
					continue
				case "overwrite":
					// Update existing within transaction
					updateErr := r.updatePolicyTx(ctx, tx, tenantID, orgID, existing.ID, &req, importedBy)
					if updateErr != nil {
						response.Errors = append(response.Errors, fmt.Sprintf("Error updating policy %s: %v", req.Name, updateErr))
					} else {
						response.Updated++
					}
					continue
				}
			}

			// Create new policy within transaction
			createErr := r.createPolicyTx(ctx, tx, tenantID, orgID, &req, importedBy)
			if createErr != nil {
				response.Errors = append(response.Errors, fmt.Sprintf("Error creating policy %s: %v", req.Name, createErr))
			} else {
				response.Created++
			}
		}
		return nil
	})
	if wrapErr != nil {
		return nil, fmt.Errorf("failed to commit import transaction: %w", wrapErr)
	}

	log.Printf("[PolicyAPI] Import completed: created=%d, updated=%d, skipped=%d, errors=%d",
		response.Created, response.Updated, response.Skipped, len(response.Errors))

	return response, nil
}

// createPolicyTx creates a policy within a transaction.
//
// v9 Phase 8 PR-C2 (#2384): caller (ImportBulk) wraps with WithOrgScope so the
// app.current_org_id GUC is already set; the INSERT must now populate the
// org_id column to satisfy the mig 018 ENABLE RLS WITH CHECK
// (`org_id = get_current_org_id()`).
//
// Decision 5 (#3490): org_id is now its OWN parameter ($8), taken from the
// authenticated organisation. client_id still mirrors tenant_id ($7) per the
// historical schema collapse; org_id no longer does, because it is what
// selects the policy while tenant_id is a value the caller types.
func (r *PolicyRepository) createPolicyTx(ctx context.Context, tx *sql.Tx, tenantID, orgID string, req *CreatePolicyRequest, createdBy string) error {
	conditionsJSON, err := json.Marshal(req.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	actionsJSON, err := json.Marshal(req.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	policyID := uuid.New().String()
	now := time.Now()

	query := `
		INSERT INTO dynamic_policies (
			policy_id, name, description, policy_type, conditions, actions,
			tenant_id, client_id, org_id, priority, enabled, version, created_by, updated_by,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	_, err = tx.ExecContext(ctx, query,
		policyID, req.Name, req.Description, req.Type,
		conditionsJSON, actionsJSON, tenantID, orgID, req.Priority,
		req.Enabled, 1, createdBy, createdBy, now, now,
	)

	if err != nil {
		return fmt.Errorf("failed to insert policy: %w", err)
	}

	// Create version entry within transaction. Errors abort the wrap tx — the
	// only realistic failure under app_role is the policy_versions RLS subquery
	// rejecting the new row, which would leave Postgres in an aborted-tx state
	// the caller can't recover from anyway. The snapshot mirrors what was
	// INSERTed above (CreatePolicyRequest fields plus the row's identity).
	snapshot := &PolicyResource{
		ID:             policyID,
		Name:           req.Name,
		Description:    req.Description,
		Type:           req.Type,
		Conditions:     req.Conditions,
		Actions:        req.Actions,
		Priority:       req.Priority,
		Enabled:        req.Enabled,
		Version:        1,
		TenantID:       tenantID,
		OrganizationID: orgID,
		CreatedBy:      createdBy,
		UpdatedBy:      createdBy,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	return r.createVersionEntryTx(ctx, tx, snapshot, createdBy, "create", "Policy created via import")
}

// updatePolicyTx updates a policy within a transaction
// Decision 5 (#3490): the WHERE narrows on org_id as well as tenant_id. On an
// owner-pool deployment (AXONFLOW_DB_USE_APP_ROLE defaults false) RLS is
// bypassed, so this clause is the whole boundary, and an overwrite-mode import
// whose caller presented another organisation's tenant string could otherwise
// rewrite that organisation's policy. Narrowing only: a row belonging to the
// caller's own org and tenant matches exactly as before.
func (r *PolicyRepository) updatePolicyTx(ctx context.Context, tx *sql.Tx, tenantID, orgID, policyID string, req *CreatePolicyRequest, updatedBy string) error {
	conditionsJSON, err := json.Marshal(req.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	actionsJSON, err := json.Marshal(req.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	query := `
		UPDATE dynamic_policies
		SET name = $1, description = $2, policy_type = $3, conditions = $4, actions = $5,
		    priority = $6, enabled = $7, version = version + 1, updated_by = $8, updated_at = $9
		WHERE policy_id = $10 AND tenant_id = $11 AND org_id = $12
	`

	_, err = tx.ExecContext(ctx, query,
		req.Name, req.Description, req.Type, conditionsJSON, actionsJSON,
		req.Priority, req.Enabled, updatedBy, time.Now(), policyID, tenantID, orgID,
	)

	return err
}

// findByNameTx finds a policy by name within a transaction.
//
// Decision 5 (#3490): scoped by org_id as well as tenant_id, for the same
// reason as updatePolicyTx - this lookup's answer decides whether an
// overwrite-mode import UPDATEs an existing row or INSERTs a new one, so on an
// owner-pool deployment it must not be able to find another organisation's.
func (r *PolicyRepository) findByNameTx(ctx context.Context, tx *sql.Tx, tenantID, orgID, name string) (*PolicyResource, error) {
	query := `
		SELECT policy_id, name, description, policy_type,
		       COALESCE(category, ''), COALESCE(tier, 'tenant'),
		       conditions, actions, tenant_id, COALESCE(org_id, ''),
		       priority, enabled, COALESCE(version, 1),
		       COALESCE(created_by, ''), COALESCE(updated_by, ''),
		       created_at, updated_at
		FROM dynamic_policies
		WHERE name = $1 AND tenant_id = $2 AND org_id = $3
		LIMIT 1
	`

	policy := &PolicyResource{}
	var conditionsJSON, actionsJSON []byte
	var policyType, category, tier, rowOrgID string

	err := tx.QueryRowContext(ctx, query, name, tenantID, orgID).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policyType,
		&category, &tier,
		&conditionsJSON, &actionsJSON, &policy.TenantID, &rowOrgID,
		&policy.Priority, &policy.Enabled, &policy.Version,
		&policy.CreatedBy, &policy.UpdatedBy,
		&policy.CreatedAt, &policy.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	policy.Type = policyType
	policy.Category = category
	policy.Tier = PolicyTier(tier)
	policy.OrganizationID = rowOrgID
	_ = json.Unmarshal(conditionsJSON, &policy.Conditions)
	_ = json.Unmarshal(actionsJSON, &policy.Actions)

	return policy, nil
}

// createVersionEntryTx creates a version entry within a transaction.
//
// v9 Phase 8 PR-C2 (#2384): returns an error now (previously void with
// warning-only logging). Under axonflow_app_role the policy_versions WITH
// CHECK subquery references dynamic_policies, so the INSERT can fail with
// 42501 if the caller's wrap tx hasn't `SELECT set_config('app.current_org_id', ...)`
// before this. Callers MUST propagate the error so the wrap rolls back —
// silently swallowing it would leave Postgres in an aborted-tx state that
// the rest of the wrap couldn't recover from anyway.
//
// The snapshot argument is a fully-hydrated PolicyResource — Category, Tier,
// OrganizationID, TenantID, CreatedBy/UpdatedBy/CreatedAt/UpdatedAt are
// preserved verbatim so the audit row matches the dynamic_policies row at
// the time of the change. (Pre-PR-C2 the old createVersionEntry marshalled
// the whole *PolicyResource; the intermediate signature that took a
// CreatePolicyRequest dropped those fields silently.)
func (r *PolicyRepository) createVersionEntryTx(ctx context.Context, tx *sql.Tx, snapshot *PolicyResource, changedBy, changeType, summary string) error {
	if snapshot == nil {
		return fmt.Errorf("createVersionEntryTx: snapshot is nil")
	}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("createVersionEntryTx: marshal snapshot: %w", err)
	}

	query := `
		INSERT INTO policy_versions (
			id, policy_id, version, snapshot, changed_by, changed_at, change_type, change_summary
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err = tx.ExecContext(ctx, query,
		uuid.New().String(), snapshot.ID, snapshot.Version, snapshotJSON,
		changedBy, time.Now(), changeType, summary,
	)

	if err != nil {
		return fmt.Errorf("createVersionEntryTx: insert policy_version: %w", err)
	}
	return nil
}

// findByName finds a policy by name within a tenant
//
//nolint:unused // Used in tests
func (r *PolicyRepository) findByName(ctx context.Context, tenantID, name string) (*PolicyResource, error) {
	query := `
		SELECT policy_id, name, description, policy_type,
		       COALESCE(category, ''), COALESCE(tier, 'tenant'),
		       conditions, actions, tenant_id, COALESCE(org_id, ''),
		       priority, enabled, COALESCE(version, 1),
		       COALESCE(created_by, ''), COALESCE(updated_by, ''),
		       created_at, updated_at
		FROM dynamic_policies
		WHERE name = $1 AND tenant_id = $2
		LIMIT 1
	`

	policy := &PolicyResource{}
	var conditionsJSON, actionsJSON []byte
	var policyType, category, tier, orgID string

	// Org-scoped for the same RLS reason as GetByID (#3039).
	err := agent.WithOrgScope(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, name, tenantID).Scan(
			&policy.ID, &policy.Name, &policy.Description, &policyType,
			&category, &tier,
			&conditionsJSON, &actionsJSON, &policy.TenantID, &orgID,
			&policy.Priority, &policy.Enabled, &policy.Version,
			&policy.CreatedBy, &policy.UpdatedBy,
			&policy.CreatedAt, &policy.UpdatedAt,
		)
	})

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	policy.Type = policyType
	policy.Category = category
	policy.Tier = PolicyTier(tier)
	policy.OrganizationID = orgID
	_ = json.Unmarshal(conditionsJSON, &policy.Conditions)
	_ = json.Unmarshal(actionsJSON, &policy.Actions)

	return policy, nil
}

// CountByTenant counts active tenant-created policies for limit enforcement.
// System-tier policies (seeded by migrations) are excluded — they should not
// consume the tenant's policy quota.
func (r *PolicyRepository) CountByTenant(ctx context.Context, tenantID, orgID string) (int, error) {
	query := `SELECT COUNT(*) FROM dynamic_policies WHERE tenant_id = $1 AND deleted_at IS NULL AND tier != 'system'`
	var count int
	// Org-scoped read: under axonflow_app_role the bare COUNT read 0 through
	// RLS, so tier-limit enforcement undercounted (#3039).
	if err := agent.WithOrgScope(ctx, r.db, crudScope(tenantID, orgID), func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, tenantID).Scan(&count)
	}); err != nil {
		return 0, fmt.Errorf("failed to count policies: %w", err)
	}
	return count, nil
}

// CountOrgPolicies counts organization-tier policies across all tenants (for Basic tier limit enforcement).
// Cross-tenant by design — runs on the BYPASSRLS cross-org pool when
// installed (SetCrossOrgDB); on the app-role pool RLS filters every row and
// the limit check undercounts to 0 (#3039).
func (r *PolicyRepository) CountOrgPolicies(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM dynamic_policies WHERE tier = 'organization' AND deleted_at IS NULL`
	var count int
	if err := r.crossOrg().QueryRowContext(ctx, query).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count organization policies: %w", err)
	}
	return count, nil
}
