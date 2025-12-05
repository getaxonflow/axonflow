// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
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

	query := `
		INSERT INTO dynamic_policies (
			policy_id, name, description, policy_type, conditions, actions,
			tenant_id, priority, enabled, version, created_by, updated_by,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err = r.db.ExecContext(ctx, query,
		policy.ID, policy.Name, policy.Description, string(policy.Type),
		conditionsJSON, actionsJSON, policy.TenantID, policy.Priority,
		policy.Enabled, policy.Version, policy.CreatedBy, policy.UpdatedBy,
		policy.CreatedAt, policy.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to insert policy: %w", err)
	}

	// Create version history entry
	if err := r.createVersionEntry(ctx, policy, "create", "Policy created"); err != nil {
		// Log but don't fail the creation
		log.Printf("[PolicyAPI] Warning: failed to create version entry for policy %s: %v", policy.ID, err)
	}

	return nil
}

// GetByID retrieves a policy by its ID
func (r *PolicyRepository) GetByID(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
	query := `
		SELECT policy_id, name, description, policy_type, conditions, actions,
		       tenant_id, priority, enabled, COALESCE(version, 1),
		       COALESCE(created_by, ''), COALESCE(updated_by, ''),
		       created_at, updated_at
		FROM dynamic_policies
		WHERE policy_id = $1 AND tenant_id = $2
	`

	policy := &PolicyResource{}
	var conditionsJSON, actionsJSON []byte
	var policyType string

	err := r.db.QueryRowContext(ctx, query, policyID, tenantID).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policyType,
		&conditionsJSON, &actionsJSON, &policy.TenantID, &policy.Priority,
		&policy.Enabled, &policy.Version, &policy.CreatedBy, &policy.UpdatedBy,
		&policy.CreatedAt, &policy.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	policy.Type = string(policyType)

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
	whereConditions := []string{"tenant_id = $1"}
	args := []interface{}{tenantID}
	argIndex := 2

	if params.Type != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("policy_type = $%d", argIndex))
		args = append(args, params.Type)
		argIndex++
	}

	if params.Enabled != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("enabled = $%d", argIndex))
		args = append(args, *params.Enabled)
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
		SELECT policy_id, name, description, policy_type, conditions, actions,
		       tenant_id, priority, enabled, COALESCE(version, 1),
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
		var policyType string

		err := rows.Scan(
			&policy.ID, &policy.Name, &policy.Description, &policyType,
			&conditionsJSON, &actionsJSON, &policy.TenantID, &policy.Priority,
			&policy.Enabled, &policy.Version, &policy.CreatedBy, &policy.UpdatedBy,
			&policy.CreatedAt, &policy.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan policy: %w", err)
		}

		policy.Type = string(policyType)

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

	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return nil, nil
	}

	// Create version history entry
	updated, _ := r.GetByID(ctx, tenantID, policyID)
	if updated != nil {
		changeType := "update"
		if req.Enabled != nil && !*req.Enabled && current.Enabled {
			changeType = "disable"
		} else if req.Enabled != nil && *req.Enabled && !current.Enabled {
			changeType = "enable"
		}
		_ = r.createVersionEntry(ctx, updated, changeType, fmt.Sprintf("Policy updated to version %d", newVersion))
	}

	return updated, nil
}

// Delete removes a policy
func (r *PolicyRepository) Delete(ctx context.Context, tenantID, policyID string, deletedBy string) error {
	// Get current policy for version history
	current, err := r.GetByID(ctx, tenantID, policyID)
	if err != nil {
		return err
	}
	if current == nil {
		return nil
	}

	// Create delete version entry before deleting
	_ = r.createVersionEntry(ctx, current, "delete", "Policy deleted")

	query := `DELETE FROM dynamic_policies WHERE policy_id = $1 AND tenant_id = $2`
	_, err = r.db.ExecContext(ctx, query, policyID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	return nil
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

// createVersionEntry creates a version history entry
func (r *PolicyRepository) createVersionEntry(ctx context.Context, policy *PolicyResource, changeType, summary string) error {
	snapshotJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	query := `
		INSERT INTO policy_versions (
			id, policy_id, version, snapshot, changed_by, changed_at, change_type, change_summary
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err = r.db.ExecContext(ctx, query,
		uuid.New().String(), policy.ID, policy.Version, snapshotJSON,
		policy.UpdatedBy, time.Now(), changeType, summary,
	)

	return err
}

// ExportAll exports all policies for a tenant
func (r *PolicyRepository) ExportAll(ctx context.Context, tenantID string) ([]PolicyResource, error) {
	params := ListPoliciesParams{PageSize: 1000, Page: 1}
	policies, _, err := r.List(ctx, tenantID, params)
	return policies, err
}

// ImportBulk imports multiple policies within a transaction
func (r *PolicyRepository) ImportBulk(ctx context.Context, tenantID string, policies []CreatePolicyRequest, mode string, importedBy string) (*ImportPoliciesResponse, error) {
	response := &ImportPoliciesResponse{}

	// Start transaction for atomic import
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Create a transaction-aware repository for the import
	txRepo := &PolicyRepository{db: nil} // We'll use tx directly

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

	// Commit transaction if no critical errors
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	_ = txRepo // Suppress unused warning

	log.Printf("[PolicyAPI] Import completed: created=%d, updated=%d, skipped=%d, errors=%d",
		response.Created, response.Updated, response.Skipped, len(response.Errors))

	return response, nil
}

// createPolicyTx creates a policy within a transaction
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
			tenant_id, priority, enabled, version, created_by, updated_by,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err = tx.ExecContext(ctx, query,
		policyID, req.Name, req.Description, req.Type,
		conditionsJSON, actionsJSON, tenantID, req.Priority,
		req.Enabled, 1, createdBy, createdBy, now, now,
	)

	if err != nil {
		return fmt.Errorf("failed to insert policy: %w", err)
	}

	// Create version entry within transaction
	r.createVersionEntryTx(ctx, tx, policyID, 1, req, createdBy, "create", "Policy created via import")

	return nil
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
		SELECT policy_id, name, description, policy_type, conditions, actions,
		       tenant_id, priority, enabled, COALESCE(version, 1),
		       COALESCE(created_by, ''), COALESCE(updated_by, ''),
		       created_at, updated_at
		FROM dynamic_policies
		WHERE name = $1 AND tenant_id = $2
		LIMIT 1
	`

	policy := &PolicyResource{}
	var conditionsJSON, actionsJSON []byte
	var policyType string

	err := tx.QueryRowContext(ctx, query, name, tenantID).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policyType,
		&conditionsJSON, &actionsJSON, &policy.TenantID, &policy.Priority,
		&policy.Enabled, &policy.Version, &policy.CreatedBy, &policy.UpdatedBy,
		&policy.CreatedAt, &policy.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	policy.Type = policyType
	_ = json.Unmarshal(conditionsJSON, &policy.Conditions)
	_ = json.Unmarshal(actionsJSON, &policy.Actions)

	return policy, nil
}

// createVersionEntryTx creates a version entry within a transaction
func (r *PolicyRepository) createVersionEntryTx(ctx context.Context, tx *sql.Tx, policyID string, version int, req *CreatePolicyRequest, changedBy, changeType, summary string) {
	// Create snapshot from request
	snapshot := PolicyResource{
		ID:          policyID,
		Name:        req.Name,
		Description: req.Description,
		Type:        req.Type,
		Conditions:  req.Conditions,
		Actions:     req.Actions,
		Priority:    req.Priority,
		Enabled:     req.Enabled,
		Version:     version,
	}

	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		log.Printf("[PolicyAPI] Warning: failed to marshal version snapshot: %v", err)
		return
	}

	query := `
		INSERT INTO policy_versions (
			id, policy_id, version, snapshot, changed_by, changed_at, change_type, change_summary
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err = tx.ExecContext(ctx, query,
		uuid.New().String(), policyID, version, snapshotJSON,
		changedBy, time.Now(), changeType, summary,
	)

	if err != nil {
		log.Printf("[PolicyAPI] Warning: failed to create version entry: %v", err)
	}
}

// findByName finds a policy by name within a tenant
//
//nolint:unused // Used in tests
func (r *PolicyRepository) findByName(ctx context.Context, tenantID, name string) (*PolicyResource, error) {
	query := `
		SELECT policy_id, name, description, policy_type, conditions, actions,
		       tenant_id, priority, enabled, COALESCE(version, 1),
		       COALESCE(created_by, ''), COALESCE(updated_by, ''),
		       created_at, updated_at
		FROM dynamic_policies
		WHERE name = $1 AND tenant_id = $2
		LIMIT 1
	`

	policy := &PolicyResource{}
	var conditionsJSON, actionsJSON []byte
	var policyType string

	err := r.db.QueryRowContext(ctx, query, name, tenantID).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policyType,
		&conditionsJSON, &actionsJSON, &policy.TenantID, &policy.Priority,
		&policy.Enabled, &policy.Version, &policy.CreatedBy, &policy.UpdatedBy,
		&policy.CreatedAt, &policy.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	policy.Type = policyType
	_ = json.Unmarshal(conditionsJSON, &policy.Conditions)
	_ = json.Unmarshal(actionsJSON, &policy.Actions)

	return policy, nil
}
