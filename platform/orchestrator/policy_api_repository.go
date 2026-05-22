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
	"strings"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent"
)

// PolicyRepository handles database operations for policies
type PolicyRepository struct {
	db *sql.DB
}

// NewPolicyRepository creates a new policy repository
func NewPolicyRepository(db *sql.DB) *PolicyRepository {
	return &PolicyRepository{db: db}
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

	// Handle organization_id - convert empty string to nil for UUID column
	var orgID interface{}
	if policy.OrganizationID != "" {
		orgID = policy.OrganizationID
	}

	// v9 compat (Epic #2230 Phase 2/4): client_id mirrors tenant_id ($9)
	// during v9 compat window. Migration 090 added client_id to
	// dynamic_policies. 'global' wildcard sentinel preserves verbatim.
	//
	// v9 Phase 8 PR-C2 (#2384): dynamic_policies is mig 018 ENABLE RLS with
	// policy `org_id = get_current_org_id()`. The legacy INSERT omitted the
	// `org_id` column (only set tenant_id + organization_id UUID), which left
	// org_id NULL on inserted rows — under axonflow_app_role the WITH CHECK
	// rejected the INSERT outright. Fix: add org_id col, populate with
	// policy.TenantID (== orgID at this writer post-Phase-6 collapse), wrap
	// in WithOrgScope so the GUC + INSERT col match.
	query := `
		INSERT INTO dynamic_policies (
			policy_id, name, description, policy_type, category, tier,
			conditions, actions, tenant_id, client_id, organization_id, org_id,
			priority, enabled, version, created_by, updated_by,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $10, $9, $11, $12, $13, $14, $15, $16, $17)
	`

	if err := agent.WithOrgScope(ctx, r.db, policy.TenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			policy.ID, policy.Name, policy.Description, string(policy.Type), policy.Category, string(tier),
			conditionsJSON, actionsJSON, policy.TenantID, orgID,
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
func (r *PolicyRepository) GetByID(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
	query := `
		SELECT policy_id, name, description, policy_type,
		       COALESCE(category, ''), COALESCE(tier, 'tenant'),
		       conditions, actions, tenant_id, COALESCE(organization_id::text, ''),
		       priority, enabled, COALESCE(version, 1),
		       COALESCE(created_by, ''), COALESCE(updated_by, ''),
		       created_at, updated_at
		FROM dynamic_policies
		WHERE policy_id = $1 AND (tenant_id = $2 OR tenant_id = 'global')
	`

	policy := &PolicyResource{}
	var conditionsJSON, actionsJSON []byte
	var policyType, category, tier, orgID string

	err := r.db.QueryRowContext(ctx, query, policyID, tenantID).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policyType,
		&category, &tier,
		&conditionsJSON, &actionsJSON, &policy.TenantID, &orgID,
		&policy.Priority, &policy.Enabled, &policy.Version,
		&policy.CreatedBy, &policy.UpdatedBy,
		&policy.CreatedAt, &policy.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	policy.Type = string(policyType)
	policy.Category = category
	policy.Tier = PolicyTier(tier)
	policy.OrganizationID = orgID

	if err := json.Unmarshal(conditionsJSON, &policy.Conditions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal conditions: %w", err)
	}

	if err := json.Unmarshal(actionsJSON, &policy.Actions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal actions: %w", err)
	}

	return policy, nil
}

// List retrieves policies with filtering and pagination
func (r *PolicyRepository) List(ctx context.Context, tenantID string, params ListPoliciesParams) ([]PolicyResource, int, error) {
	// Build dynamic query
	// Include both tenant-specific and system/global policies
	whereConditions := []string{"(tenant_id = $1 OR tenant_id = 'global')"}
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

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM dynamic_policies WHERE %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count policies: %w", err)
	}

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

	query := fmt.Sprintf(`
		SELECT policy_id, name, description, policy_type,
		       COALESCE(category, ''), COALESCE(tier, 'tenant'),
		       conditions, actions, tenant_id, COALESCE(organization_id::text, ''),
		       priority, enabled, COALESCE(version, 1),
		       COALESCE(created_by, ''), COALESCE(updated_by, ''),
		       created_at, updated_at
		FROM dynamic_policies
		WHERE %s
		ORDER BY %s %s
		LIMIT %d OFFSET %d
	`, whereClause, sortBy, sortDir, params.PageSize, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list policies: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var policies []PolicyResource
	for rows.Next() {
		var policy PolicyResource
		var conditionsJSON, actionsJSON []byte
		var policyType, category, tier, orgID string

		err := rows.Scan(
			&policy.ID, &policy.Name, &policy.Description, &policyType,
			&category, &tier,
			&conditionsJSON, &actionsJSON, &policy.TenantID, &orgID,
			&policy.Priority, &policy.Enabled, &policy.Version,
			&policy.CreatedBy, &policy.UpdatedBy,
			&policy.CreatedAt, &policy.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan policy: %w", err)
		}

		policy.Type = string(policyType)
		policy.Category = category
		policy.Tier = PolicyTier(tier)
		policy.OrganizationID = orgID

		if err := json.Unmarshal(conditionsJSON, &policy.Conditions); err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal conditions: %w", err)
		}

		if err := json.Unmarshal(actionsJSON, &policy.Actions); err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal actions: %w", err)
		}

		policies = append(policies, policy)
	}

	return policies, total, nil
}

// Update modifies an existing policy
func (r *PolicyRepository) Update(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, updatedBy string) (*PolicyResource, error) {
	// Get current policy for version history
	current, err := r.GetByID(ctx, tenantID, policyID)
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
	if wrapErr := agent.WithOrgScope(ctx, r.db, tenantID, func(tx *sql.Tx) error {
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
	updated, _ := r.GetByID(ctx, tenantID, policyID)
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
func (r *PolicyRepository) Delete(ctx context.Context, tenantID, policyID string, deletedBy string) error {
	// Get current policy for version history
	current, err := r.GetByID(ctx, tenantID, policyID)
	if err != nil {
		return err
	}
	if current == nil {
		return nil
	}

	return agent.WithOrgScope(ctx, r.db, tenantID, func(tx *sql.Tx) error {
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
	query := `
		SELECT version, snapshot, COALESCE(changed_by, ''), changed_at,
		       change_type, COALESCE(change_summary, '')
		FROM policy_versions
		WHERE policy_id = $1
		ORDER BY version DESC
	`

	rows, err := r.db.QueryContext(ctx, query, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get versions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var versions []PolicyVersionEntry
	for rows.Next() {
		var entry PolicyVersionEntry
		var snapshotJSON []byte

		err := rows.Scan(&entry.Version, &snapshotJSON, &entry.ChangedBy,
			&entry.ChangedAt, &entry.ChangeType, &entry.ChangeSummary)
		if err != nil {
			return nil, fmt.Errorf("failed to scan version: %w", err)
		}

		if err := json.Unmarshal(snapshotJSON, &entry.Snapshot); err != nil {
			return nil, fmt.Errorf("failed to unmarshal snapshot: %w", err)
		}

		versions = append(versions, entry)
	}

	return versions, nil
}

// ExportAll exports all policies for a tenant
func (r *PolicyRepository) ExportAll(ctx context.Context, tenantID string) ([]PolicyResource, error) {
	params := ListPoliciesParams{PageSize: 1000, Page: 1}
	policies, _, err := r.List(ctx, tenantID, params)
	return policies, err
}

// ImportBulk imports multiple policies within a transaction.
//
// v9 Phase 8 PR-C2 (#2384): wraps the import tx with WithOrgScope so every
// child INSERT into dynamic_policies + policy_versions sees the
// app.current_org_id GUC set before WITH CHECK fires. All imported policies
// share a single tenant scope (the caller's tenantID).
func (r *PolicyRepository) ImportBulk(ctx context.Context, tenantID string, policies []CreatePolicyRequest, mode string, importedBy string) (*ImportPoliciesResponse, error) {
	response := &ImportPoliciesResponse{}

	wrapErr := agent.WithOrgScope(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		for _, req := range policies {
			// Check if policy already exists by name
			existing, checkErr := r.findByNameTx(ctx, tx, tenantID, req.Name)
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
					updateErr := r.updatePolicyTx(ctx, tx, tenantID, existing.ID, &req, importedBy)
					if updateErr != nil {
						response.Errors = append(response.Errors, fmt.Sprintf("Error updating policy %s: %v", req.Name, updateErr))
					} else {
						response.Updated++
					}
					continue
				}
			}

			// Create new policy within transaction
			createErr := r.createPolicyTx(ctx, tx, tenantID, &req, importedBy)
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
// (`org_id = get_current_org_id()`). client_id + org_id both mirror tenant_id
// ($7) at this writer per the historical schema collapse.
func (r *PolicyRepository) createPolicyTx(ctx context.Context, tx *sql.Tx, tenantID string, req *CreatePolicyRequest, createdBy string) error {
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
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err = tx.ExecContext(ctx, query,
		policyID, req.Name, req.Description, req.Type,
		conditionsJSON, actionsJSON, tenantID, req.Priority,
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
		ID:          policyID,
		Name:        req.Name,
		Description: req.Description,
		Type:        req.Type,
		Conditions:  req.Conditions,
		Actions:     req.Actions,
		Priority:    req.Priority,
		Enabled:     req.Enabled,
		Version:     1,
		TenantID:    tenantID,
		CreatedBy:   createdBy,
		UpdatedBy:   createdBy,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	return r.createVersionEntryTx(ctx, tx, snapshot, createdBy, "create", "Policy created via import")
}

// updatePolicyTx updates a policy within a transaction
func (r *PolicyRepository) updatePolicyTx(ctx context.Context, tx *sql.Tx, tenantID, policyID string, req *CreatePolicyRequest, updatedBy string) error {
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
		WHERE policy_id = $10 AND tenant_id = $11
	`

	_, err = tx.ExecContext(ctx, query,
		req.Name, req.Description, req.Type, conditionsJSON, actionsJSON,
		req.Priority, req.Enabled, updatedBy, time.Now(), policyID, tenantID,
	)

	return err
}

// findByNameTx finds a policy by name within a transaction
func (r *PolicyRepository) findByNameTx(ctx context.Context, tx *sql.Tx, tenantID, name string) (*PolicyResource, error) {
	query := `
		SELECT policy_id, name, description, policy_type,
		       COALESCE(category, ''), COALESCE(tier, 'tenant'),
		       conditions, actions, tenant_id, COALESCE(organization_id::text, ''),
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

	err := tx.QueryRowContext(ctx, query, name, tenantID).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policyType,
		&category, &tier,
		&conditionsJSON, &actionsJSON, &policy.TenantID, &orgID,
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
	policy.OrganizationID = orgID
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
		       conditions, actions, tenant_id, COALESCE(organization_id::text, ''),
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

	err := r.db.QueryRowContext(ctx, query, name, tenantID).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policyType,
		&category, &tier,
		&conditionsJSON, &actionsJSON, &policy.TenantID, &orgID,
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
	policy.OrganizationID = orgID
	_ = json.Unmarshal(conditionsJSON, &policy.Conditions)
	_ = json.Unmarshal(actionsJSON, &policy.Actions)

	return policy, nil
}

// CountByTenant counts active tenant-created policies for limit enforcement.
// System-tier policies (seeded by migrations) are excluded — they should not
// consume the tenant's policy quota.
func (r *PolicyRepository) CountByTenant(ctx context.Context, tenantID string) (int, error) {
	query := `SELECT COUNT(*) FROM dynamic_policies WHERE tenant_id = $1 AND deleted_at IS NULL AND tier != 'system'`
	var count int
	if err := r.db.QueryRowContext(ctx, query, tenantID).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count policies: %w", err)
	}
	return count, nil
}

// CountOrgPolicies counts organization-tier policies across all tenants (for Basic tier limit enforcement).
func (r *PolicyRepository) CountOrgPolicies(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM dynamic_policies WHERE tier = 'organization' AND deleted_at IS NULL`
	var count int
	if err := r.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count organization policies: %w", err)
	}
	return count, nil
}
