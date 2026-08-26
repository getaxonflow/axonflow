// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"time"

	sharedpolicy "axonflow/platform/shared/policy"
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

	// Risk and override semantics (ADR-044)
	RiskLevel     string `json:"risk_level" db:"risk_level"`         // low|medium|high|critical. Default "medium".
	AllowOverride bool   `json:"allow_override" db:"allow_override"` // Session override allowed? Forced false for critical risk.

	// Multi-tenancy.
	//
	// #3334: the legacy `organization_id` column and its field are gone
	// (migration core/166). It was a second, differently-typed organisation
	// key that no shipped migration ever populated, and since #3490 nothing
	// selects on it. OrgID is the organisation key - for isolation AND for
	// selection - and TenantID is attribution.
	TenantID string `json:"tenant_id" db:"tenant_id"`
	OrgID    string `json:"org_id,omitempty" db:"org_id"` // RLS column

	// SegmentID is the ADR-060 (#2989 P3) governance-segment targeting key:
	// the stable scim_groups.id (never display_name), scoped under OrgID
	// above (never the retired organization_id column or TenantID - #2791,
	// #3334).
	// Orthogonal to Tier (Decision 2, locked): nil means "not segment-scoped"
	// — the pre-P3, backward-compatible default, independent of which tier
	// the policy is authored at. Populated only by GetEffective's segment
	// selection (migrations/core/157); the Create/Update API surface does
	// not expose it yet (portal write path is P6, #2989).
	SegmentID *string `json:"segment_id,omitempty" db:"segment_id"`

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

	// Scope of the override. #3334 retired the legacy organization_id column
	// (migration core/166); OrgID below is the organisation key, and a NULL
	// TenantID is what makes a row org-scoped rather than tenant-scoped.
	TenantID *string `json:"tenant_id,omitempty" db:"tenant_id"`
	// OrgID is the multi-tenant scope key for RLS. Mig 110 (v9 Phase 8
	// PR-C2) added policy_overrides.org_id NOT NULL + switched the RLS
	// policy from app.tenant_id to app.current_org_id; callers must
	// populate this before write.
	OrgID string `json:"org_id" db:"org_id"`

	// Override values
	ActionOverride  *OverrideAction `json:"action_override,omitempty" db:"action_override"`
	EnabledOverride *bool           `json:"enabled_override,omitempty" db:"enabled_override"`

	// Governance
	OverrideReason string     `json:"override_reason" db:"override_reason"` // Mandatory free-text justification (ADR-044)
	ExpiresAt      *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	ToolSignature  *string    `json:"tool_signature,omitempty" db:"tool_signature"` // Optional: restrict override to a specific tool

	// Audit trail
	CreatedBy string     `json:"created_by,omitempty" db:"created_by"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedBy string     `json:"updated_by,omitempty" db:"updated_by"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	RevokedBy *string    `json:"revoked_by,omitempty" db:"revoked_by"`
}

// IsRevoked returns true if the override has been explicitly revoked.
func (o *PolicyOverride) IsRevoked() bool {
	return o.RevokedAt != nil
}

// IsActive returns true if the override is neither expired nor revoked.
func (o *PolicyOverride) IsActive() bool {
	return !o.IsExpired() && !o.IsRevoked()
}

// MatchesTool returns true if the override applies to the given tool signature.
// An override with no ToolSignature matches any tool.
func (o *PolicyOverride) MatchesTool(toolSignature string) bool {
	if o.ToolSignature == nil {
		return true
	}
	return *o.ToolSignature == toolSignature
}

// IsExpired returns true if the override has expired.
func (o *PolicyOverride) IsExpired() bool {
	if o.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*o.ExpiresAt)
}

// IsOrgLevel returns true if this is an organization-level override.
//
// #3334: this used to read `OrganizationID != nil && TenantID == nil`, which
// tested the retired legacy column. The two conjuncts were never independent
// in practice - the schema's own valid_override_scope CHECK required an
// organization_id exactly when tenant_id was NULL - so a NULL tenant IS the
// org-scoped shape, and migration core/165 guarantees OrgID is populated on
// every row besides.
func (o *PolicyOverride) IsOrgLevel() bool {
	return o.TenantID == nil
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
	ChangeType    string    `json:"change_type" db:"change_type"`
	ChangeSummary string    `json:"change_summary,omitempty" db:"change_summary"`
	ChangedBy     string    `json:"changed_by,omitempty" db:"changed_by"`
	ChangedAt     time.Time `json:"changed_at" db:"changed_at"`
}

// EffectivePolicies represents the computed effective policies for a tenant.
// This includes system, organization, and tenant policies with overrides applied.
type EffectivePolicies struct {
	Static  []EffectiveStaticPolicy  `json:"static"`
	Dynamic []EffectiveDynamicPolicy `json:"dynamic"`

	// Metadata
	TenantID       string    `json:"tenant_id"`
	OrganizationID string    `json:"organization_id,omitempty"`
	ComputedAt     time.Time `json:"computed_at"`
}

// EffectiveStaticPolicy is a static policy with any overrides applied.
//
// action_override and enabled_override are independently-nullable columns on
// policy_overrides (see platform/shared/policy/override.go's package doc):
// a tenant row can disable a policy while a DIFFERENT org row downgrades its
// action, both in effect at once. OverrideAction/OverrideEnabled below carry
// the resolved value of each attribute independently (either may be set
// without the other). OverrideReason/OverrideExpiresAt remain single legacy
// fields for wire compatibility and are populated from ONE representative
// contributing row (the action row if there is one, else the enabled row) —
// they must not be read as "the" override when more than one row
// contributed; OverrideContributions carries the full, per-row attribution
// (one entry per contributing row, each with its own reason and expiry).
type EffectiveStaticPolicy struct {
	StaticPolicy

	// Override information (if any)
	HasOverride       bool            `json:"has_override"`
	OverrideAction    *OverrideAction `json:"override_action,omitempty"`
	OverrideEnabled   *bool           `json:"override_enabled,omitempty"`
	OverrideExpiresAt *time.Time      `json:"override_expires_at,omitempty"`
	OverrideReason    string          `json:"override_reason,omitempty"`
	// OverrideContributions is every policy_overrides row that contributed
	// to HasOverride/OverrideAction/OverrideEnabled above, each attributed
	// with its own reason and expiry (see sharedpolicy.OverrideContribution).
	// One or two entries when HasOverride is true (a policy has at most one
	// contributing tenant-scope decision and one contributing org-scope
	// decision, per attribute); empty otherwise.
	OverrideContributions []sharedpolicy.OverrideContribution `json:"override_contributions,omitempty"`
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

	// Multi-tenancy. #3334: organization_id retired with migration core/166.
	TenantID string `json:"tenant_id"`

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
	// #3334 (BREAKING): the organization_id request field is removed. It was
	// the only writer the retired legacy column ever had, and migration
	// core/166 drops that column. A policy's organisation is the AUTHENTICATED
	// caller's, resolved from the licence - it was never something a request
	// body should have been able to name, which is the sharper reason to drop
	// the field rather than quietly ignore it. A body that still sends it is
	// accepted and the value is ignored, exactly as any other unknown field
	// is; nothing 400s on it.
	Pattern  string   `json:"pattern"`
	Action   string   `json:"action"`
	Severity string   `json:"severity"`
	Priority int      `json:"priority,omitempty"`
	Enabled  bool     `json:"enabled"`
	Tags     []string `json:"tags,omitempty"`
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
