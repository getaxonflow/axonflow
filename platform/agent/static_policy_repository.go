// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/license"
)

// Static policy limits
const (
	// MaxTenantPoliciesCommunity is the maximum number of custom tenant policies
	// allowed in Community edition.
	MaxTenantPoliciesCommunity = 30

	// MaxVersionHistoryCommunity is the maximum number of version history entries
	// returned in Community edition.
	MaxVersionHistoryCommunity = 5

	// DefaultPageSize is the default number of items per page for listing.
	DefaultPageSize = 20

	// MaxPageSize is the maximum number of items per page for listing.
	MaxPageSize = 100
)

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

	// Insert into database
	query := `
		INSERT INTO static_policies (
			id, policy_id, name, category, pattern, severity,
			description, action, tier, priority, enabled,
			organization_id, tenant_id, org_id,
			tags, metadata, version,
			created_at, updated_at, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14,
			$15::jsonb, $16::jsonb, $17,
			$18, $19, $20, $21
		)
	`

	metadataJSON := "{}"
	if policy.Metadata != nil {
		metadataJSON = string(policy.Metadata)
	}

	_, err := r.db.ExecContext(ctx, query,
		policy.ID, policy.PolicyID, policy.Name, policy.Category, policy.Pattern, policy.Severity,
		policy.Description, policy.Action, string(policy.Tier), policy.Priority, policy.Enabled,
		policy.OrganizationID, policy.TenantID, policy.OrgID,
		tagsJSON, metadataJSON, policy.Version,
		policy.CreatedAt, policy.UpdatedAt, policy.CreatedBy, policy.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to insert policy: %w", err)
	}

	// Record version history
	if err := r.recordVersion(ctx, policy, "create", "Policy created", createdBy); err != nil {
		// Log but don't fail the create operation
		// Version history is for audit purposes, not critical path
		return nil
	}

	return nil
}

// Update updates an existing static policy with tier enforcement.
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
	var orgID sql.NullString

	err = r.db.QueryRowContext(ctx, query, args...).Scan(
		&updatedPolicy.ID, &updatedPolicy.PolicyID, &updatedPolicy.Name, &updatedPolicy.Category,
		&updatedPolicy.Pattern, &updatedPolicy.Severity, &description, &updatedPolicy.Action,
		&updatedPolicy.Tier, &updatedPolicy.Priority, &updatedPolicy.Enabled,
		&updatedPolicy.OrganizationID, &updatedPolicy.TenantID, &orgID,
		&updatedPolicy.Version, &updatedPolicy.CreatedAt, &updatedPolicy.UpdatedAt,
		&updatedPolicy.CreatedBy, &updatedPolicy.UpdatedBy,
	)
	if err == sql.ErrNoRows {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}

	if description.Valid {
		updatedPolicy.Description = description.String
	}
	if orgID.Valid {
		updatedPolicy.OrgID = orgID.String
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

	// Soft delete
	query := `
		UPDATE static_policies
		SET deleted_at = $1, updated_by = $2, version = version + 1
		WHERE id = $3 AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, time.Now().UTC(), deletedBy, policy.ID)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
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

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&policy.ID, &policy.PolicyID, &policy.Name, &policy.Category,
		&policy.Pattern, &policy.Severity, &description, &policy.Action,
		&policy.Tier, &policy.Priority, &policy.Enabled,
		&policy.OrganizationID, &policy.TenantID, &orgID,
		&tagsJSON, &metadataJSON, &policy.Version,
		&policy.CreatedAt, &policy.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
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

	// Build WHERE clause
	where := []string{"deleted_at IS NULL"}
	args := []interface{}{}
	argNum := 1

	// Tenant filter - include system policies + tenant's policies
	if tenantID != "" {
		where = append(where, fmt.Sprintf("(tier = 'system' OR tenant_id = $%d)", argNum))
		args = append(args, tenantID)
		argNum++
	}

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

	whereClause := strings.Join(where, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM static_policies WHERE %s", whereClause)
	var totalItems int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&totalItems); err != nil {
		return nil, fmt.Errorf("failed to count policies: %w", err)
	}

	// Order by
	orderBy := "priority DESC, name ASC"
	if params.SortBy != "" {
		dir := "ASC"
		if strings.ToUpper(params.SortDir) == "DESC" {
			dir = "DESC"
		}
		// Whitelist allowed sort columns
		allowedSorts := map[string]bool{
			"name": true, "category": true, "tier": true,
			"severity": true, "priority": true, "created_at": true, "updated_at": true,
		}
		if allowedSorts[params.SortBy] {
			orderBy = fmt.Sprintf("%s %s", params.SortBy, dir)
		}
	}

	// Main query with pagination
	offset := (params.Page - 1) * params.PageSize
	query := fmt.Sprintf(`
		SELECT
			id, policy_id, name, category, pattern, severity,
			description, action, tier, priority, enabled,
			organization_id, tenant_id, org_id,
			tags, metadata, version,
			created_at, updated_at, created_by, updated_by
		FROM static_policies
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argNum, argNum+1)
	args = append(args, params.PageSize, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}
	defer rows.Close()

	policies := make([]StaticPolicy, 0)
	for rows.Next() {
		var policy StaticPolicy
		var description, createdBy, updatedBy sql.NullString
		var orgID sql.NullString
		var tagsJSON, metadataJSON sql.NullString

		err := rows.Scan(
			&policy.ID, &policy.PolicyID, &policy.Name, &policy.Category,
			&policy.Pattern, &policy.Severity, &description, &policy.Action,
			&policy.Tier, &policy.Priority, &policy.Enabled,
			&policy.OrganizationID, &policy.TenantID, &orgID,
			&tagsJSON, &metadataJSON, &policy.Version,
			&policy.CreatedAt, &policy.UpdatedAt, &createdBy, &updatedBy,
		)
		if err != nil {
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
			if err := json.Unmarshal([]byte(tagsJSON.String), &policy.Tags); err != nil {
				policy.Tags = []string{}
			}
		}
		if metadataJSON.Valid && metadataJSON.String != "" {
			policy.Metadata = json.RawMessage(metadataJSON.String)
		}

		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating policies: %w", err)
	}

	totalPages := (totalItems + params.PageSize - 1) / params.PageSize

	return &StaticPoliciesListResponse{
		Policies: policies,
		Pagination: PaginationInfo{
			Page:       params.Page,
			PageSize:   params.PageSize,
			TotalItems: totalItems,
			TotalPages: totalPages,
		},
	}, nil
}

// GetEffective returns effective policies for a tenant with tier hierarchy applied.
// Inheritance order: System policies → Organization policies → Tenant policies
// Higher tier policies can shadow lower tier by policy name/category.
func (r *StaticPolicyRepository) GetEffective(ctx context.Context, tenantID string, orgID *string) ([]EffectiveStaticPolicy, error) {
	// Query all applicable policies
	query := `
		SELECT
			sp.id, sp.policy_id, sp.name, sp.category, sp.pattern, sp.severity,
			sp.description, sp.action, sp.tier, sp.priority, sp.enabled,
			sp.organization_id, sp.tenant_id, sp.org_id,
			sp.tags, sp.metadata, sp.version,
			sp.created_at, sp.updated_at, sp.created_by, sp.updated_by,
			po.id as override_id, po.action_override, po.enabled_override,
			po.expires_at, po.override_reason
		FROM static_policies sp
		LEFT JOIN policy_overrides po ON (
			sp.id::text = po.policy_id::text
			AND po.policy_type = 'static'
			AND (po.expires_at IS NULL OR po.expires_at > NOW())
			AND (
				(po.tenant_id = $1)
				OR (po.organization_id IS NOT NULL AND po.organization_id::text = $2 AND po.tenant_id IS NULL)
			)
		)
		WHERE sp.deleted_at IS NULL
		  AND sp.enabled = true
		  AND (
			sp.tier = 'system'
			OR (sp.tier = 'organization' AND sp.organization_id::text = $2)
			OR (sp.tier = 'tenant' AND sp.tenant_id = $1)
		  )
		ORDER BY
			CASE sp.tier
				WHEN 'system' THEN 1
				WHEN 'organization' THEN 2
				WHEN 'tenant' THEN 3
			END,
			sp.priority DESC,
			sp.name ASC
	`

	orgIDStr := ""
	if orgID != nil {
		orgIDStr = *orgID
	}

	rows, err := r.db.QueryContext(ctx, query, tenantID, orgIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to get effective policies: %w", err)
	}
	defer rows.Close()

	policies := make([]EffectiveStaticPolicy, 0)
	for rows.Next() {
		var policy StaticPolicy
		var effective EffectiveStaticPolicy
		var description, createdBy, updatedBy sql.NullString
		var policyOrgID sql.NullString
		var tagsJSON, metadataJSON sql.NullString

		// Override fields
		var overrideID sql.NullString
		var actionOverride sql.NullString
		var enabledOverride sql.NullBool
		var expiresAt sql.NullTime
		var overrideReason sql.NullString

		err := rows.Scan(
			&policy.ID, &policy.PolicyID, &policy.Name, &policy.Category,
			&policy.Pattern, &policy.Severity, &description, &policy.Action,
			&policy.Tier, &policy.Priority, &policy.Enabled,
			&policy.OrganizationID, &policy.TenantID, &policyOrgID,
			&tagsJSON, &metadataJSON, &policy.Version,
			&policy.CreatedAt, &policy.UpdatedAt, &createdBy, &updatedBy,
			&overrideID, &actionOverride, &enabledOverride,
			&expiresAt, &overrideReason,
		)
		if err != nil {
			continue
		}

		if description.Valid {
			policy.Description = description.String
		}
		if policyOrgID.Valid {
			policy.OrgID = policyOrgID.String
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

		effective.StaticPolicy = policy

		// Apply override if present
		if overrideID.Valid {
			effective.HasOverride = true
			if actionOverride.Valid {
				action := OverrideAction(actionOverride.String)
				effective.OverrideAction = &action
			}
			if enabledOverride.Valid {
				effective.OverrideEnabled = &enabledOverride.Bool
			}
			if expiresAt.Valid {
				effective.OverrideExpiresAt = &expiresAt.Time
			}
			if overrideReason.Valid {
				effective.OverrideReason = overrideReason.String
			}
		}

		policies = append(policies, effective)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating effective policies: %w", err)
	}

	return policies, nil
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

	query := `
		SELECT id, policy_id, version, snapshot, change_type, change_summary, changed_by, changed_at
		FROM static_policy_versions
		WHERE policy_id = $1
		ORDER BY version DESC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, policyID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get versions: %w", err)
	}
	defer rows.Close()

	versions := make([]StaticPolicyVersion, 0)
	for rows.Next() {
		var v StaticPolicyVersion
		var changeSummary, changedBy sql.NullString

		err := rows.Scan(
			&v.ID, &v.PolicyID, &v.Version, &v.Snapshot,
			&v.ChangeType, &changeSummary, &changedBy, &v.ChangedAt,
		)
		if err != nil {
			continue
		}

		if changeSummary.Valid {
			v.ChangeSummary = changeSummary.String
		}
		if changedBy.Valid {
			v.ChangedBy = changedBy.String
		}

		versions = append(versions, v)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating versions: %w", err)
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

	query := `
		UPDATE static_policies
		SET enabled = $1, updated_at = $2, updated_by = $3, version = version + 1
		WHERE id = $4 AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, enabled, time.Now().UTC(), updatedBy, policy.ID)
	if err != nil {
		return fmt.Errorf("failed to toggle enabled: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
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

	query := `
		INSERT INTO static_policy_versions (
			id, policy_id, version, snapshot, change_type, change_summary, changed_by, changed_at
		) VALUES (
			$1, $2, $3, $4::jsonb, $5, $6, $7, $8
		)
	`

	_, err = r.db.ExecContext(ctx, query,
		uuid.New().String(),
		policy.ID,
		policy.Version,
		string(snapshot),
		changeType,
		changeSummary,
		changedBy,
		time.Now().UTC(),
	)
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

	var count int
	err := r.db.QueryRowContext(ctx, query, tenantID).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// isEnterpriseLicense checks if the tenant has an Enterprise license.
func (r *StaticPolicyRepository) isEnterpriseLicense(ctx context.Context, tenantID string) (bool, error) {
	// First, check DEPLOYMENT_MODE environment variable
	// Enterprise modes include: saas, enterprise, banking, travel, healthcare, etc.
	deploymentMode := strings.ToLower(os.Getenv("DEPLOYMENT_MODE"))
	if deploymentMode != "" && deploymentMode != "community" {
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
