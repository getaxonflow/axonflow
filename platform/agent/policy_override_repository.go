// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/license"
)

// Override repository errors
var (
	// ErrOverrideRequiresEnterprise is returned when trying to create an override
	// without an Enterprise license.
	ErrOverrideRequiresEnterprise = errors.New("policy overrides require Enterprise license")

	// ErrOnlySystemPoliciesOverridable is returned when trying to override
	// a non-system policy.
	ErrOnlySystemPoliciesOverridable = errors.New("only system policies can be overridden")

	// ErrOverrideNotFound is returned when an override is not found.
	ErrOverrideNotFound = errors.New("override not found")

	// ErrOverrideReasonRequired is returned when creating an override without a reason.
	ErrOverrideReasonRequired = errors.New("override reason is required")

	// ErrInvalidOverrideAction is returned when an invalid override action is specified.
	ErrInvalidOverrideAction = errors.New("invalid override action")

	// ErrOverrideAlreadyExists is returned when trying to create a duplicate override.
	ErrOverrideAlreadyExists = errors.New("override already exists for this policy and scope")
)

// PolicyOverrideRepository provides CRUD operations for policy overrides.
type PolicyOverrideRepository struct {
	db               *sql.DB
	staticPolicyRepo *StaticPolicyRepository
}

// NewPolicyOverrideRepository creates a new policy override repository.
func NewPolicyOverrideRepository(db *sql.DB) *PolicyOverrideRepository {
	return &PolicyOverrideRepository{
		db:               db,
		staticPolicyRepo: NewStaticPolicyRepository(db),
	}
}

// Create creates a new policy override.
// - REQUIRES Enterprise license
// - ONLY allows overriding system tier policies
// - REQUIRES reason (audit trail)
func (r *PolicyOverrideRepository) Create(ctx context.Context, override *PolicyOverride, createdBy string) error {
	// Validate reason is provided
	if override.OverrideReason == "" {
		return ErrOverrideReasonRequired
	}

	// Validate action if provided
	if override.ActionOverride != nil && !IsValidOverrideAction(*override.ActionOverride) {
		return ErrInvalidOverrideAction
	}

	// Get tenant ID for license check
	tenantID := ""
	if override.TenantID != nil {
		tenantID = *override.TenantID
	} else if override.OrganizationID != nil {
		// For org-level overrides, we need to get a tenant from the org
		tenantID = *override.OrganizationID // Use org ID as tenant for license check
	}

	// Check Enterprise license
	isEnterprise, err := r.isEnterpriseLicense(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to check license: %w", err)
	}
	if !isEnterprise {
		return ErrOverrideRequiresEnterprise
	}

	// Get the policy being overridden
	policy, err := r.staticPolicyRepo.GetByID(ctx, override.PolicyID)
	if err != nil {
		return fmt.Errorf("policy not found: %w", err)
	}

	// Only system policies can be overridden
	if policy.Tier != TierSystem {
		return ErrOnlySystemPoliciesOverridable
	}

	// Check for existing override
	exists, err := r.overrideExists(ctx, override.PolicyID, override.TenantID, override.OrganizationID)
	if err != nil {
		return fmt.Errorf("failed to check existing override: %w", err)
	}
	if exists {
		return ErrOverrideAlreadyExists
	}

	// Generate ID
	if override.ID == "" {
		override.ID = uuid.New().String()
	}

	// Set timestamps
	override.CreatedAt = time.Now().UTC()
	override.UpdatedAt = override.CreatedAt
	override.CreatedBy = createdBy
	override.UpdatedBy = createdBy

	// Set policy type
	override.PolicyType = TypeStatic

	// Insert into database
	query := `
		INSERT INTO policy_overrides (
			id, policy_id, policy_type,
			organization_id, tenant_id,
			action_override, enabled_override,
			override_reason, expires_at,
			created_by, created_at, updated_by, updated_at
		) VALUES (
			$1, $2, $3,
			$4, $5,
			$6, $7,
			$8, $9,
			$10, $11, $12, $13
		)
	`

	var actionStr *string
	if override.ActionOverride != nil {
		s := string(*override.ActionOverride)
		actionStr = &s
	}

	_, err = r.db.ExecContext(ctx, query,
		override.ID, override.PolicyID, string(override.PolicyType),
		override.OrganizationID, override.TenantID,
		actionStr, override.EnabledOverride,
		override.OverrideReason, override.ExpiresAt,
		override.CreatedBy, override.CreatedAt, override.UpdatedBy, override.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create override: %w", err)
	}

	return nil
}

// Delete removes a policy override.
func (r *PolicyOverrideRepository) Delete(ctx context.Context, overrideID string, deletedBy string) error {
	// Check if override exists
	_, err := r.GetByID(ctx, overrideID)
	if err != nil {
		return err
	}

	query := `
		DELETE FROM policy_overrides
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, overrideID)
	if err != nil {
		return fmt.Errorf("failed to delete override: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}
	if rowsAffected == 0 {
		return ErrOverrideNotFound
	}

	return nil
}

// DeleteByPolicyID deletes the override for a specific policy and scope.
// The policyID can be either the UUID (id column) or policy_id from static_policies table.
func (r *PolicyOverrideRepository) DeleteByPolicyID(ctx context.Context, policyID string, tenantID *string, orgID *string, deletedBy string) error {
	// The policyID passed in is what the SDK sees (could be ID or PolicyID)
	// The override table stores the UUID (ID field), not the human-readable PolicyID
	resolvedPolicyID := policyID

	// Try to get the policy to resolve the actual UUID
	policy, err := r.staticPolicyRepo.GetByID(ctx, policyID)
	if err == nil && policy != nil {
		// Use the ID (UUID) from the resolved policy, not PolicyID
		// ID is the actual UUID stored in policy_overrides.policy_id
		resolvedPolicyID = policy.ID
	}
	// If policy not found, continue with the original policyID
	// (it might already be the correct UUID)

	query := `
		DELETE FROM policy_overrides
		WHERE policy_id = $1
	`
	args := []interface{}{resolvedPolicyID}
	argNum := 2

	if tenantID != nil {
		query += fmt.Sprintf(" AND tenant_id = $%d", argNum)
		args = append(args, *tenantID)
	} else if orgID != nil {
		query += fmt.Sprintf(" AND organization_id = $%d AND tenant_id IS NULL", argNum)
		args = append(args, *orgID)
	}

	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to delete override: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}
	if rowsAffected == 0 {
		return ErrOverrideNotFound
	}

	return nil
}

// GetByID retrieves an override by its ID.
func (r *PolicyOverrideRepository) GetByID(ctx context.Context, id string) (*PolicyOverride, error) {
	query := `
		SELECT
			id, policy_id, policy_type,
			organization_id, tenant_id,
			action_override, enabled_override,
			override_reason, expires_at,
			created_by, created_at, updated_by, updated_at
		FROM policy_overrides
		WHERE id = $1
	`

	var override PolicyOverride
	var actionOverride sql.NullString
	var enabledOverride sql.NullBool
	var expiresAt sql.NullTime
	var createdBy, updatedBy sql.NullString

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&override.ID, &override.PolicyID, &override.PolicyType,
		&override.OrganizationID, &override.TenantID,
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

// GetEffectiveAction returns the effective action for a policy considering overrides.
// Order of precedence:
// 1. Tenant-level override (most specific)
// 2. Org-level override
// 3. Original policy action (if no override)
// Expired overrides are ignored.
func (r *PolicyOverrideRepository) GetEffectiveAction(
	ctx context.Context,
	policyID, tenantID string,
	orgID *string,
) (OverrideAction, bool, error) {
	// First, check for tenant-level override
	query := `
		SELECT action_override, enabled_override, expires_at
		FROM policy_overrides
		WHERE policy_id = $1
		  AND tenant_id = $2
		  AND (expires_at IS NULL OR expires_at > NOW())
		LIMIT 1
	`

	var actionOverride sql.NullString
	var enabledOverride sql.NullBool
	var expiresAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, policyID, tenantID).Scan(
		&actionOverride, &enabledOverride, &expiresAt,
	)
	if err == nil && actionOverride.Valid {
		return OverrideAction(actionOverride.String), true, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return "", false, fmt.Errorf("failed to get tenant override: %w", err)
	}

	// Check for org-level override if orgID provided
	if orgID != nil && *orgID != "" {
		query = `
			SELECT action_override, enabled_override, expires_at
			FROM policy_overrides
			WHERE policy_id = $1
			  AND organization_id = $2
			  AND tenant_id IS NULL
			  AND (expires_at IS NULL OR expires_at > NOW())
			LIMIT 1
		`

		err = r.db.QueryRowContext(ctx, query, policyID, *orgID).Scan(
			&actionOverride, &enabledOverride, &expiresAt,
		)
		if err == nil && actionOverride.Valid {
			return OverrideAction(actionOverride.String), true, nil
		}
		if err != nil && err != sql.ErrNoRows {
			return "", false, fmt.Errorf("failed to get org override: %w", err)
		}
	}

	// No override found
	return "", false, nil
}

// GetOverrideForPolicy returns the override for a policy at the given scope.
func (r *PolicyOverrideRepository) GetOverrideForPolicy(
	ctx context.Context,
	policyID string,
	tenantID *string,
	orgID *string,
) (*PolicyOverride, error) {
	query := `
		SELECT
			id, policy_id, policy_type,
			organization_id, tenant_id,
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
		query += fmt.Sprintf(" AND organization_id = $%d AND tenant_id IS NULL", argNum)
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
		&override.OrganizationID, &override.TenantID,
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
				organization_id, tenant_id,
				action_override, enabled_override,
				override_reason, expires_at,
				created_by, created_at, updated_by, updated_at
			FROM policy_overrides
			WHERE (tenant_id = $1 OR (organization_id = $2 AND tenant_id IS NULL))
		`
		args = []interface{}{tenantID, *orgID}
	} else {
		// Only tenant-level overrides (no org filter)
		query = `
			SELECT
				id, policy_id, policy_type,
				organization_id, tenant_id,
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
			&override.OrganizationID, &override.TenantID,
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

// CleanupExpiredOverrides removes overrides that have expired.
// This can be called periodically to clean up the database.
func (r *PolicyOverrideRepository) CleanupExpiredOverrides(ctx context.Context) (int, error) {
	query := `
		DELETE FROM policy_overrides
		WHERE expires_at IS NOT NULL AND expires_at <= NOW()
	`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired overrides: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get affected rows: %w", err)
	}

	return int(rowsAffected), nil
}

// Helper methods

// overrideExists checks if an override already exists for the given scope.
func (r *PolicyOverrideRepository) overrideExists(ctx context.Context, policyID string, tenantID *string, orgID *string) (bool, error) {
	query := `
		SELECT COUNT(*)
		FROM policy_overrides
		WHERE policy_id = $1
	`
	args := []interface{}{policyID}
	argNum := 2

	if tenantID != nil {
		query += fmt.Sprintf(" AND tenant_id = $%d", argNum)
		args = append(args, *tenantID)
	} else if orgID != nil {
		query += fmt.Sprintf(" AND organization_id = $%d AND tenant_id IS NULL", argNum)
		args = append(args, *orgID)
	}

	var count int
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// isEnterpriseLicense checks if the tenant has an Enterprise license.
func (r *PolicyOverrideRepository) isEnterpriseLicense(ctx context.Context, tenantID string) (bool, error) {
	// First, check DEPLOYMENT_MODE environment variable
	// Enterprise modes include: saas, enterprise, banking, travel, healthcare, etc.
	deploymentMode := strings.ToLower(os.Getenv("DEPLOYMENT_MODE"))
	if deploymentMode != "" && deploymentMode != "community" {
		return true, nil
	}

	// Fall back to database lookup for license tier
	query := `
		SELECT license_tier
		FROM clients
		WHERE tenant_id = $1 AND enabled = true
		LIMIT 1
	`

	var tier sql.NullString
	err := r.db.QueryRowContext(ctx, query, tenantID).Scan(&tier)
	if err == sql.ErrNoRows {
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
