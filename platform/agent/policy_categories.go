// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// PolicyCategory represents the category classification for policies.
// Categories are used for organizing and filtering policies in the UI and API.
type PolicyCategory string

const (
	// Static policy categories - Security

	// CategorySecuritySQLi covers SQL injection detection patterns.
	CategorySecuritySQLi PolicyCategory = "security-sqli"
	// CategorySecurityAdmin covers admin access control patterns.
	CategorySecurityAdmin PolicyCategory = "security-admin"

	// Static policy categories - PII Detection

	// CategoryPIIGlobal covers globally applicable PII patterns.
	// Includes: credit card, email, phone, IP address, passport, DOB, booking reference.
	CategoryPIIGlobal PolicyCategory = "pii-global"
	// CategoryPIIUS covers US-specific PII patterns.
	// Includes: SSN, bank account.
	CategoryPIIUS PolicyCategory = "pii-us"
	// CategoryPIIEU covers EU-specific PII patterns.
	// Includes: IBAN.
	CategoryPIIEU PolicyCategory = "pii-eu"
	// CategoryPIIIndia covers India-specific PII patterns.
	// Includes: PAN, Aadhaar.
	CategoryPIIIndia PolicyCategory = "pii-india"

	// Dynamic policy categories

	// CategoryDynamicRisk covers risk-based dynamic policies.
	// Examples: Block High-Risk Queries, Anomalous Access Detection.
	CategoryDynamicRisk PolicyCategory = "dynamic-risk"
	// CategoryDynamicCompliance covers compliance-related dynamic policies.
	// Examples: HIPAA Compliance, GDPR Compliance, Financial Data Protection.
	CategoryDynamicCompliance PolicyCategory = "dynamic-compliance"
	// CategoryDynamicSecurity covers security-related dynamic policies.
	// Examples: Tenant Isolation, Debug Mode Restriction.
	CategoryDynamicSecurity PolicyCategory = "dynamic-security"
	// CategoryDynamicCost covers cost-related dynamic policies.
	// Examples: Expensive Query Limit, LLM Cost Optimization.
	CategoryDynamicCost PolicyCategory = "dynamic-cost"
	// CategoryDynamicAccess covers access control dynamic policies.
	// Examples: Sensitive Data Control.
	CategoryDynamicAccess PolicyCategory = "dynamic-access"
)

// StaticPolicyCategories returns all valid static policy categories.
func StaticPolicyCategories() []PolicyCategory {
	return []PolicyCategory{
		CategorySecuritySQLi,
		CategorySecurityAdmin,
		CategoryPIIGlobal,
		CategoryPIIUS,
		CategoryPIIEU,
		CategoryPIIIndia,
	}
}

// DynamicPolicyCategories returns all valid dynamic policy categories.
func DynamicPolicyCategories() []PolicyCategory {
	return []PolicyCategory{
		CategoryDynamicRisk,
		CategoryDynamicCompliance,
		CategoryDynamicSecurity,
		CategoryDynamicCost,
		CategoryDynamicAccess,
	}
}

// AllPolicyCategories returns all valid policy categories.
func AllPolicyCategories() []PolicyCategory {
	categories := StaticPolicyCategories()
	return append(categories, DynamicPolicyCategories()...)
}

// IsValidStaticCategory returns true if the category is valid for static policies.
func IsValidStaticCategory(category PolicyCategory) bool {
	for _, c := range StaticPolicyCategories() {
		if c == category {
			return true
		}
	}
	return false
}

// IsValidDynamicCategory returns true if the category is valid for dynamic policies.
func IsValidDynamicCategory(category PolicyCategory) bool {
	for _, c := range DynamicPolicyCategories() {
		if c == category {
			return true
		}
	}
	return false
}

// PolicyTier represents the tier level in the policy hierarchy.
// Policies are organized into three tiers: system, organization, and tenant.
type PolicyTier string

const (
	// TierSystem represents AxonFlow-managed, immutable policies.
	// Pattern/condition cannot be modified; action can be overridden (Enterprise only).
	TierSystem PolicyTier = "system"

	// TierOrganization represents organization-wide policies (Enterprise only).
	// Full CRUD available, applies to all tenants in the organization.
	TierOrganization PolicyTier = "organization"

	// TierTenant represents team-specific policies.
	// Full CRUD available, cannot override to less restrictive than org/system.
	TierTenant PolicyTier = "tenant"
)

// AllPolicyTiers returns all valid policy tiers.
func AllPolicyTiers() []PolicyTier {
	return []PolicyTier{
		TierSystem,
		TierOrganization,
		TierTenant,
	}
}

// IsValidTier returns true if the tier is valid.
func IsValidTier(tier PolicyTier) bool {
	for _, t := range AllPolicyTiers() {
		if t == tier {
			return true
		}
	}
	return false
}

// OverrideAction represents the action that can override a system policy.
// Enterprise customers can override system policy actions to adjust enforcement behavior.
type OverrideAction string

const (
	// ActionBlock rejects the request immediately (default for critical policies).
	ActionBlock OverrideAction = "block"

	// ActionRedact masks/redacts matched content instead of blocking.
	// Useful for PII protection where data should be anonymized, not blocked.
	ActionRedact OverrideAction = "redact"

	// ActionWarn allows the request but logs a warning.
	// Useful for testing/rollout phase to monitor false positive rates.
	ActionWarn OverrideAction = "warn"

	// ActionLog allows the request and logs for audit purposes only.
	// Useful for monitoring without any user-visible impact.
	ActionLog OverrideAction = "log"
)

// AllOverrideActions returns all valid override actions.
func AllOverrideActions() []OverrideAction {
	return []OverrideAction{
		ActionBlock,
		ActionRedact,
		ActionWarn,
		ActionLog,
	}
}

// IsValidOverrideAction returns true if the action is valid.
func IsValidOverrideAction(action OverrideAction) bool {
	for _, a := range AllOverrideActions() {
		if a == action {
			return true
		}
	}
	return false
}

// ActionRestrictiveness returns the restrictiveness level of an action.
// Higher values indicate more restrictive actions.
// Used to enforce that overrides cannot weaken policies.
// Levels: block(4) > redact(3) > warn(2) > log(1)
func ActionRestrictiveness(action OverrideAction) int {
	switch action {
	case ActionBlock:
		return 4
	case ActionRedact:
		return 3
	case ActionWarn:
		return 2
	case ActionLog:
		return 1
	default:
		return 0
	}
}

// IsMoreRestrictive returns true if newAction is more restrictive than baseAction.
func IsMoreRestrictive(newAction, baseAction OverrideAction) bool {
	return ActionRestrictiveness(newAction) >= ActionRestrictiveness(baseAction)
}

// PolicyType represents the type of policy (static vs dynamic).
type PolicyType string

const (
	// TypeStatic represents pattern-based policies evaluated by the Agent.
	TypeStatic PolicyType = "static"

	// TypeDynamic represents condition-based policies evaluated by the Orchestrator.
	TypeDynamic PolicyType = "dynamic"
)

// Severity levels for policies.
type PolicySeverity string

const (
	SeverityCritical PolicySeverity = "critical"
	SeverityHigh     PolicySeverity = "high"
	SeverityMedium   PolicySeverity = "medium"
	SeverityLow      PolicySeverity = "low"
)

// AllSeverities returns all valid severity levels in order of criticality.
func AllSeverities() []PolicySeverity {
	return []PolicySeverity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
	}
}

// IsValidSeverity returns true if the severity is valid.
func IsValidSeverity(severity PolicySeverity) bool {
	for _, s := range AllSeverities() {
		if s == severity {
			return true
		}
	}
	return false
}
