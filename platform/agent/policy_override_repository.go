// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrOverrideNotFound is returned when an override is not found.
var ErrOverrideNotFound = errors.New("override not found")

// PolicyOverrideRepository reads the per-policy overrides recorded in
// policy_overrides. It writes none: a tenant's per-policy override routes answer
// the retirement (PRD v11 §1.5, legacyfreeze.RefuseOverride), and so, since
// #4252, do the ADR-044 session override routes: nothing writes the table.
type PolicyOverrideRepository struct {
	db *sql.DB
}

// NewPolicyOverrideRepository creates a new policy override repository.
func NewPolicyOverrideRepository(db *sql.DB) *PolicyOverrideRepository {
	return &PolicyOverrideRepository{db: db}
}

// GetOverrideForPolicy returns the override for a policy at the given scope.
func (r *PolicyOverrideRepository) GetOverrideForPolicy(
	ctx context.Context,
	policyID string,
	tenantID *string,
	orgID *string,
) (*PolicyOverride, error) {
	// #3334: org_id is SELECTed. With org_id the only organisation key, a
	// fetched override that cannot say which org it belongs to is a gap.
	query := `
		SELECT
			id, policy_id, policy_type,
			tenant_id, org_id,
			action_override, enabled_override,
			override_reason, expires_at,
			created_by, created_at, updated_by, updated_at
		FROM policy_overrides
		WHERE policy_id = $1
	`
	args := []interface{}{policyID}
	argNum := 2

	if tenantID != nil {
		query += fmt.Sprintf(" AND tenant_id = $%d", argNum)
		args = append(args, *tenantID)
	} else if orgID != nil {
		query += fmt.Sprintf(" AND org_id = $%d AND tenant_id IS NULL", argNum)
		args = append(args, *orgID)
	}

	query += " LIMIT 1"

	var override PolicyOverride
	var actionOverride sql.NullString
	var enabledOverride sql.NullBool
	var expiresAt sql.NullTime
	var createdBy, updatedBy sql.NullString

	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&override.ID, &override.PolicyID, &override.PolicyType,
		&override.TenantID, &override.OrgID,
		&actionOverride, &enabledOverride,
		&override.OverrideReason, &expiresAt,
		&createdBy, &override.CreatedAt, &updatedBy, &override.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrOverrideNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get override: %w", err)
	}

	if actionOverride.Valid {
		action := OverrideAction(actionOverride.String)
		override.ActionOverride = &action
	}
	if enabledOverride.Valid {
		override.EnabledOverride = &enabledOverride.Bool
	}
	if expiresAt.Valid {
		override.ExpiresAt = &expiresAt.Time
	}
	if createdBy.Valid {
		override.CreatedBy = createdBy.String
	}
	if updatedBy.Valid {
		override.UpdatedBy = updatedBy.String
	}

	return &override, nil
}

// ListOverridesForTenant returns all overrides applicable to a tenant.
func (r *PolicyOverrideRepository) ListOverridesForTenant(
	ctx context.Context,
	tenantID string,
	orgID *string,
	includeExpired bool,
) ([]PolicyOverride, error) {
	// Build query based on whether orgID is provided
	var query string
	var args []interface{}

	if orgID != nil && *orgID != "" {
		// Include both tenant-level and org-level overrides
		query = `
			SELECT
				id, policy_id, policy_type,
				tenant_id,
				action_override, enabled_override,
				override_reason, expires_at,
				created_by, created_at, updated_by, updated_at
			FROM policy_overrides
			WHERE (tenant_id = $1 OR (org_id = $2 AND tenant_id IS NULL))
		`
		args = []interface{}{tenantID, *orgID}
	} else {
		// Only tenant-level overrides (no org filter)
		query = `
			SELECT
				id, policy_id, policy_type,
				tenant_id,
				action_override, enabled_override,
				override_reason, expires_at,
				created_by, created_at, updated_by, updated_at
			FROM policy_overrides
			WHERE tenant_id = $1
		`
		args = []interface{}{tenantID}
	}

	if !includeExpired {
		query += " AND (expires_at IS NULL OR expires_at > NOW())"
	}

	query += " ORDER BY tenant_id NULLS LAST, created_at DESC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list overrides: %w", err)
	}
	defer rows.Close()

	overrides := make([]PolicyOverride, 0)
	for rows.Next() {
		var override PolicyOverride
		var actionOverride sql.NullString
		var enabledOverride sql.NullBool
		var expiresAt sql.NullTime
		var createdBy, updatedBy sql.NullString

		err := rows.Scan(
			&override.ID, &override.PolicyID, &override.PolicyType,
			&override.TenantID,
			&actionOverride, &enabledOverride,
			&override.OverrideReason, &expiresAt,
			&createdBy, &override.CreatedAt, &updatedBy, &override.UpdatedAt,
		)
		if err != nil {
			continue
		}

		if actionOverride.Valid {
			action := OverrideAction(actionOverride.String)
			override.ActionOverride = &action
		}
		if enabledOverride.Valid {
			override.EnabledOverride = &enabledOverride.Bool
		}
		if expiresAt.Valid {
			override.ExpiresAt = &expiresAt.Time
		}
		if createdBy.Valid {
			override.CreatedBy = createdBy.String
		}
		if updatedBy.Valid {
			override.UpdatedBy = updatedBy.String
		}

		overrides = append(overrides, override)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating overrides: %w", err)
	}

	return overrides, nil
}
