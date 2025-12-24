// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"time"
)

// StaticPolicy represents a static policy with full tier/category support.
// This struct is used for database operations and API responses.
type StaticPolicy struct {
	// Core identification
	ID       string `json:"id" db:"id"`
	PolicyID string `json:"policy_id" db:"policy_id"`
	Name     string `json:"name" db:"name"`

	// Classification (strings for database compatibility, use typed getters for validation)
	Category string     `json:"category" db:"category"` // security-sqli, pii-global, etc.
	Tier     PolicyTier `json:"tier" db:"tier"`         // system, organization, tenant

	// Pattern and behavior
	Pattern     string `json:"pattern" db:"pattern"`
	Severity    string `json:"severity" db:"severity"`
	Description string `json:"description,omitempty" db:"description"`
	Action      string `json:"action" db:"action"`
	Priority    int    `json:"priority" db:"priority"`
	Enabled     bool   `json:"enabled" db:"enabled"`

	// Multi-tenancy
	OrganizationID *string `json:"organization_id,omitempty" db:"organization_id"`
	TenantID       string  `json:"tenant_id" db:"tenant_id"`
	OrgID          string  `json:"org_id,omitempty" db:"org_id"` // RLS column

	// Flexible metadata
	Tags     []string        `json:"tags,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty" db:"metadata"`

	// Versioning
	Version int `json:"version" db:"version"`

	// Audit trail
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy string     `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy string     `json:"updated_by,omitempty" db:"updated_by"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}

// GetCategory returns the policy category as a typed PolicyCategory.
func (p *StaticPolicy) GetCategory() PolicyCategory {
	return PolicyCategory(p.Category)
}

// SetCategory sets the policy category from a typed PolicyCategory.
func (p *StaticPolicy) SetCategory(category PolicyCategory) {
	p.Category = string(category)
}

// IsSystem returns true if this is a system-tier policy.
func (p *StaticPolicy) IsSystem() bool {
	return p.Tier == TierSystem
}

// IsOrganization returns true if this is an organization-tier policy.
func (p *StaticPolicy) IsOrganization() bool {
	return p.Tier == TierOrganization
}

// IsTenant returns true if this is a tenant-tier policy.
func (p *StaticPolicy) IsTenant() bool {
	return p.Tier == TierTenant
}

// CanModify returns true if the policy pattern can be modified.
// System tier policies cannot have their pattern modified.
func (p *StaticPolicy) CanModify() bool {
	return p.Tier != TierSystem
}

// CanDelete returns true if the policy can be deleted.
// System tier policies cannot be deleted.
func (p *StaticPolicy) CanDelete() bool {
	return p.Tier != TierSystem
}

// PolicyOverride represents an override for a system policy.
// Enterprise customers can override actions without modifying the pattern.
type PolicyOverride struct {
	ID string `json:"id" db:"id"`

	// Reference to the policy being overridden
	PolicyID   string     `json:"policy_id" db:"policy_id"`
	PolicyType PolicyType `json:"policy_type" db:"policy_type"`

	// Scope of the override
	OrganizationID *string `json:"organization_id,omitempty" db:"organization_id"`
	TenantID       *string `json:"tenant_id,omitempty" db:"tenant_id"`

	// Override values
	ActionOverride  *OverrideAction `json:"action_override,omitempty" db:"action_override"`
	EnabledOverride *bool           `json:"enabled_override,omitempty" db:"enabled_override"`

	// Governance
	OverrideReason string     `json:"override_reason" db:"override_reason"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty" db:"expires_at"`

	// Audit trail
	CreatedBy string    `json:"created_by,omitempty" db:"created_by"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedBy string    `json:"updated_by,omitempty" db:"updated_by"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// IsExpired returns true if the override has expired.
func (o *PolicyOverride) IsExpired() bool {
	if o.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*o.ExpiresAt)
}

// IsOrgLevel returns true if this is an organization-level override.
func (o *PolicyOverride) IsOrgLevel() bool {
	return o.OrganizationID != nil && o.TenantID == nil
}

// IsTenantLevel returns true if this is a tenant-level override.
func (o *PolicyOverride) IsTenantLevel() bool {
	return o.TenantID != nil
}

// StaticPolicyVersion represents a version snapshot of a static policy.
type StaticPolicyVersion struct {
	ID       string `json:"id" db:"id"`
	PolicyID string `json:"policy_id" db:"policy_id"`
	Version  int    `json:"version" db:"version"`

	// Complete policy state at this version
	Snapshot json.RawMessage `json:"snapshot" db:"snapshot"`

	// Change metadata
	ChangeType    string `json:"change_type" db:"change_type"`
	ChangeSummary string `json:"change_summary,omitempty" db:"change_summary"`
	ChangedBy     string `json:"changed_by,omitempty" db:"changed_by"`
	ChangedAt     time.Time `json:"changed_at" db:"changed_at"`
}

// EffectivePolicies represents the computed effective policies for a tenant.
// This includes system, organization, and tenant policies with overrides applied.
type EffectivePolicies struct {
	Static  []EffectiveStaticPolicy `json:"static"`
	Dynamic []EffectiveDynamicPolicy `json:"dynamic"`

	// Metadata
	TenantID       string    `json:"tenant_id"`
	OrganizationID string    `json:"organization_id,omitempty"`
	ComputedAt     time.Time `json:"computed_at"`
}

// EffectiveStaticPolicy is a static policy with any overrides applied.
type EffectiveStaticPolicy struct {
	StaticPolicy

	// Override information (if any)
	HasOverride       bool            `json:"has_override"`
	OverrideAction    *OverrideAction `json:"override_action,omitempty"`
	OverrideEnabled   *bool           `json:"override_enabled,omitempty"`
	OverrideExpiresAt *time.Time      `json:"override_expires_at,omitempty"`
	OverrideReason    string          `json:"override_reason,omitempty"`
}

// EffectiveAction returns the effective action considering any override.
func (p *EffectiveStaticPolicy) EffectiveAction() string {
	if p.HasOverride && p.OverrideAction != nil {
		return string(*p.OverrideAction)
	}
	return p.Action
}

// EffectiveEnabled returns the effective enabled state considering any override.
func (p *EffectiveStaticPolicy) EffectiveEnabled() bool {
	if p.HasOverride && p.OverrideEnabled != nil {
		return *p.OverrideEnabled
	}
	return p.Enabled
}

// EffectiveDynamicPolicy is a dynamic policy with any overrides applied.
type EffectiveDynamicPolicy struct {
	ID          string          `json:"id"`
	PolicyID    string          `json:"policy_id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Type        string          `json:"type"`
	Category    string          `json:"category"` // dynamic-risk, dynamic-compliance, etc.
	Tier        PolicyTier      `json:"tier"`
	Conditions  json.RawMessage `json:"conditions"`
	Actions     json.RawMessage `json:"actions"`
	Priority    int             `json:"priority"`
	Enabled     bool            `json:"enabled"`

	// Multi-tenancy
	OrganizationID *string `json:"organization_id,omitempty"`
	TenantID       string  `json:"tenant_id"`

	// Override information (if any)
	HasOverride       bool            `json:"has_override"`
	OverrideAction    *OverrideAction `json:"override_action,omitempty"`
	OverrideEnabled   *bool           `json:"override_enabled,omitempty"`
	OverrideExpiresAt *time.Time      `json:"override_expires_at,omitempty"`
	OverrideReason    string          `json:"override_reason,omitempty"`
}

// CreateStaticPolicyRequest is the request body for creating a static policy.
type CreateStaticPolicyRequest struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Category    string     `json:"category"` // security-sqli, pii-global, etc.
	Tier        PolicyTier `json:"tier"`     // Only 'organization' or 'tenant' allowed via API
	Pattern     string     `json:"pattern"`
	Action      string     `json:"action"`
	Severity    string     `json:"severity"`
	Priority    int        `json:"priority,omitempty"`
	Enabled     bool       `json:"enabled"`
	Tags        []string   `json:"tags,omitempty"`
}

// UpdateStaticPolicyRequest is the request body for updating a static policy.
type UpdateStaticPolicyRequest struct {
	Name        *string  `json:"name,omitempty"`
	Description *string  `json:"description,omitempty"`
	Pattern     *string  `json:"pattern,omitempty"` // Only allowed for non-system policies
	Action      *string  `json:"action,omitempty"`
	Severity    *string  `json:"severity,omitempty"`
	Priority    *int     `json:"priority,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// CreateOverrideRequest is the request body for creating a policy override.
type CreateOverrideRequest struct {
	ActionOverride  *OverrideAction `json:"action_override,omitempty"`
	EnabledOverride *bool           `json:"enabled_override,omitempty"`
	OverrideReason  string          `json:"override_reason"`
	ExpiresAt       *time.Time      `json:"expires_at,omitempty"`
}

// ListStaticPoliciesParams for filtering static policies.
type ListStaticPoliciesParams struct {
	Tier           *PolicyTier     `json:"tier,omitempty"`
	Category       *PolicyCategory `json:"category,omitempty"`
	Enabled        *bool           `json:"enabled,omitempty"`
	Search         string          `json:"search,omitempty"`
	IncludeDeleted bool            `json:"include_deleted,omitempty"`
	Page           int             `json:"page,omitempty"`
	PageSize       int             `json:"page_size,omitempty"`
	SortBy         string          `json:"sort_by,omitempty"`
	SortDir        string          `json:"sort_dir,omitempty"`
}

// StaticPoliciesListResponse for paginated list of static policies.
type StaticPoliciesListResponse struct {
	Policies   []StaticPolicy `json:"policies"`
	Pagination PaginationInfo `json:"pagination"`
}

// PaginationInfo contains pagination metadata.
type PaginationInfo struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalItems int `json:"total_items"`
	TotalPages int `json:"total_pages"`
}

// TestPatternRequest is the request body for testing a pattern.
type TestPatternRequest struct {
	Pattern string `json:"pattern"`
	Input   string `json:"input"`
}

// TestPatternResponse is the response for pattern testing.
type TestPatternResponse struct {
	Matched bool     `json:"matched"`
	Matches []string `json:"matches,omitempty"`
	Error   string   `json:"error,omitempty"`
}
