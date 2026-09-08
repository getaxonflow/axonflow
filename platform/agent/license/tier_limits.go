// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// This file is deliberately identical apart from its build constraint between
// `platform/agent/license/tier_limits.go` and `ee/platform/agent/license/tier_limits.go`:
// the platform copy serves both build tags and carries no constraint; the ee
// copy sits in an enterprise-only package and must carry `//go:build
// enterprise`. The shipped enterprise image overlays the ee copy onto the
// platform one (platform/agent/Dockerfile, EDITION=enterprise), and
// tests/regression-test-required/license_pair_byte_identity_test.sh holds the two
// identical after stripping that one line.

package license

// This file is the ONE declaration of the self-hosted tier limits table (#3593,
// decision D4 of the v11.0.0 plan).
//
// Before it, TierLimits and the three self-hosted tables were declared THREE
// times: tier.go (community build), tier_support.go (enterprise build, platform
// copy) and ee/.../tier_support.go (enterprise build, the copy the shipped
// image runs). #3823 measured 84 code lines of drift between the last two.
// Measured before this file was written, the drift was FORMATTING ONLY - the
// three tables carried the same values - but nothing held them equal, and a
// dimension added to one and forgotten in another would have shipped a limit
// the platform tests never saw. One declaration, byte-identical across the
// pair and guarded, cannot drift.
//
// The SaaS Plugin tables (FreeLimits, ProLimits, PremiumLimits) are NOT here:
// they exist only in the enterprise build and remain in tier_support.go, where
// #3823 still tracks their fork.
//
// # HOW A LIMIT IS READ
//
// Callers do not read these variables to decide anything about THIS
// deployment. They call ReadCurrentTier (tier_read.go) - the one verified read
// of AXONFLOW_LICENSE_KEY - and index GetTierLimits with the tier it returns.
// An absent, forged or expired key resolves to TierCommunity there, so every
// limit below applies at its Community value on such a deployment. The
// deployment mode (DEPLOYMENT_MODE) is not an input at any step: mode may
// narrow what a build registers, it never grants a limit (operator ruling,
// 2026-09-07, #3593).
//
// # THE SENTINEL
//
// -1 means unlimited. 0 means NONE: a dimension whose limit is 0 admits nothing
// on that tier (OrgPolicies on Community and Evaluation is the live example).
// The two are never interchangeable, and platform/agent/license/admission
// tests both values on every dimension it enforces.

// TierLimits defines the resource limits for a license tier.
type TierLimits struct {
	TenantPolicies int `json:"tenant_policies"`
	// OrgPolicies is the number of organization-root policies a deployment
	// may author. RULED 2026-09-07 (#3593, D4): 0 on Community AND on
	// Evaluation (Evaluation moved from 5 to 0), unlimited on Enterprise.
	// Organization-root authoring is an Enterprise capability under ee/.
	OrgPolicies            int  `json:"org_policies"`
	CustomPolicyConnectors int  `json:"custom_policy_connectors"`
	AuditRetentionDays     int  `json:"audit_retention_days"`
	MaxLLMProviders        int  `json:"max_llm_providers"`
	MaxExecutionHistory    int  `json:"max_execution_history"`
	MaxConcurrentExec      int  `json:"max_concurrent_executions"`
	MaxPlans               int  `json:"max_plans"`
	MaxVersionsPerPlan     int  `json:"max_versions_per_plan"`
	MaxSSEConnections      int  `json:"max_sse_connections"`
	MaxCostEstimatesPerDay int  `json:"max_cost_estimates_per_day"`
	MaxPendingApprovals    int  `json:"max_pending_approvals"`
	MediaGovernanceEnabled bool `json:"media_governance_enabled"`

	// Scale boundaries, RULED 2026-09-07 (#3593, decision D4 of the v11.0.0
	// plan). These are read from the signed licence through the ONE reader
	// above and enforced by platform/agent/license/admission, which ships in
	// the community binary: the restriction is what makes Community and
	// Evaluation smaller, so it must exist where those editions run. Every
	// admission is one row in principal_admissions (migrations/core/171), and
	// a principal admitted once is never refused again, whatever happens to
	// the ledger afterwards.
	//
	// MaxHumanPrincipals: distinct human principals (users) an organization
	// may admit. 25 Community / 75 Evaluation / unlimited Enterprise.
	MaxHumanPrincipals int `json:"max_human_principals"`
	// MaxServicePrincipals: distinct service principals (API credentials,
	// service accounts, registered MCP clients) an organization may admit.
	// 5 Community / 25 Evaluation / unlimited Enterprise.
	MaxServicePrincipals int `json:"max_service_principals"`
	// MaxNodes: distinct agent nodes an organization may admit. 1 Community /
	// unlimited Evaluation / unlimited Enterprise.
	//
	// This is the "max nodes" idea given its first REFUSING reader rather than
	// a fourth carrier of the number. Measured 2026-09-08, the three existing
	// carriers are: ValidationResult.MaxNodes, which is only stored, copied or
	// printed and is never compared to anything; PricingTierInfo.MaxNodes,
	// which has no construction site and no read at all; and
	// organizations.max_nodes, which IS read and compared against a live node
	// count - by node_enforcement.NodeMonitor on the enterprise build (opt-in,
	// ENABLE_NODE_MONITOR) and by the customer-portal node-status endpoints -
	// but only to raise an alert or label a dashboard response VIOLATION.
	// None of the three refuses anything. Admit does: over the ceiling is
	// HTTP 402 and the node does not run.
	MaxNodes int `json:"max_nodes"`

	// SaaS Plugin daily write-quota — governed events per tenant per UTC
	// day. -1 = unlimited (self-hosted tiers; the env-var fallback in
	// community_saas_ratelimit covers callers that never resolve to a
	// SaaS Plugin tier). Per PRD_TENANT_DURABILITY_AND_CLAIM "Free vs
	// Paid Boundary" (V1 Plugin Pro umbrella #1958): Free=200,
	// Pro=2,000 (bumped from 1,000 in #1958), Premium=5,000.
	DailyEventQuota int `json:"daily_event_quota"`

	// V1 Plugin Pro graduated-freemium fields (umbrella #1958). Free
	// tier exposes a "taste" of these capabilities — Pro tier removes
	// the caps. -1 = unlimited (Pro / Premium / self-hosted higher
	// tiers). Same semantics as DailyEventQuota: -1 means n/a / not a
	// SaaS Plugin tier.
	MaxActiveCustomPolicies int `json:"max_active_custom_policies"`
	MaxHITLApprovalsPerWeek int `json:"max_hitl_approvals_per_week"`

	// V1.1 decision-list (issue #1982 / project_v1_1_decision_record_2026_05_07).
	// Govern GET /api/v1/decisions: how far back the lookback window extends
	// and how many rows a single response page may carry. -1 = unbounded.
	// Window measured in hours so SaaS Pro's 30 days renders as 720 — staying
	// in int means the schema doesn't grow a Duration type for one field.
	DecisionListWindowHours int `json:"decision_list_window_hours"`
	DecisionListMaxPage     int `json:"decision_list_max_page"`

	// Evaluation tier feature gates
	HITLApprovalEnabled      bool `json:"hitl_approval_enabled"`
	HITLExpiryHours          int  `json:"hitl_expiry_hours"`
	PolicySimulationEnabled  bool `json:"policy_simulation_enabled"`
	MaxSimulationsPerDay     int  `json:"max_simulations_per_day"`
	MaxImpactReportInputs    int  `json:"max_impact_report_inputs"`
	EvidenceExportEnabled    bool `json:"evidence_export_enabled"`
	MaxEvidenceExportRecords int  `json:"max_evidence_export_records"`
	MaxEvidenceWindowDays    int  `json:"max_evidence_window_days"`
	MaxEvidenceExportsPerDay int  `json:"max_evidence_exports_per_day"`
}

// Self-hosted tier limits. These three are the values a deployment's signed
// licence resolves to; see the file comment for how they are read.
var (
	CommunityLimits = TierLimits{
		TenantPolicies:         20,
		OrgPolicies:            0,
		CustomPolicyConnectors: 2,
		AuditRetentionDays:     3,
		MaxLLMProviders:        2,
		MaxExecutionHistory:    50,
		MaxConcurrentExec:      5,
		MaxPlans:               25,
		MaxVersionsPerPlan:     10,
		MaxSSEConnections:      5,
		MaxCostEstimatesPerDay: 10,
		MaxPendingApprovals:    5,
		MediaGovernanceEnabled: false, // Opt-in via MEDIA_GOVERNANCE_ENABLED=true
		// Scale boundaries (ruled 2026-09-07, #3593 D4).
		MaxHumanPrincipals:   25,
		MaxServicePrincipals: 5,
		MaxNodes:             1,
		DailyEventQuota:      -1, // not a SaaS Plugin tier; daily quota n/a
		// V1 Plugin Pro fields: -1 = n/a (community build never resolves
		// to a SaaS Plugin tier; cross-build struct-shape parity only).
		MaxActiveCustomPolicies: -1,
		MaxHITLApprovalsPerWeek: -1,
		// V1.1 decision-list: 24h / 5 per page (matches SaaS Free).
		DecisionListWindowHours: 24,
		DecisionListMaxPage:     5,
		// Evaluation features disabled
		HITLApprovalEnabled:      false,
		HITLExpiryHours:          0,
		PolicySimulationEnabled:  false,
		MaxSimulationsPerDay:     0,
		MaxImpactReportInputs:    0,
		EvidenceExportEnabled:    false,
		MaxEvidenceExportRecords: 0,
		MaxEvidenceWindowDays:    0,
		MaxEvidenceExportsPerDay: 0,
	}
	EvaluationLimits = TierLimits{
		TenantPolicies: 50,
		// 0, not 5: organization-root authoring is Enterprise-only (ruled
		// 2026-09-07, #3593 D4). The 5 this carried until then was never
		// backed by an Enterprise-free authoring path.
		OrgPolicies:            0,
		CustomPolicyConnectors: 5,
		AuditRetentionDays:     14,
		MaxLLMProviders:        3,
		MaxExecutionHistory:    500,
		MaxConcurrentExec:      25,
		MaxPlans:               100,
		MaxVersionsPerPlan:     25,
		MaxSSEConnections:      25,
		MaxCostEstimatesPerDay: 100,
		MaxPendingApprovals:    25,
		MediaGovernanceEnabled: true,
		// Scale boundaries (ruled 2026-09-07, #3593 D4).
		MaxHumanPrincipals:   75,
		MaxServicePrincipals: 25,
		MaxNodes:             -1, // unlimited: only Community is single-node
		DailyEventQuota:      -1, // not a SaaS Plugin tier; daily quota n/a
		// V1 Plugin Pro fields: -1 = n/a (Evaluation is self-hosted, not SaaS Plugin)
		MaxActiveCustomPolicies: -1,
		MaxHITLApprovalsPerWeek: -1,
		// V1.1 decision-list: 14d / 100 per page.
		DecisionListWindowHours: 336,
		DecisionListMaxPage:     100,
		// Evaluation features enabled with limits
		// HITL IS ENTERPRISE-ONLY (operator decision, 2026-08-26). Evaluation
		// was entitled until then; it is not now. The entitled set is
		// Professional | Enterprise | Enterprise Plus, i.e. the tiers
		// GetTierLimits maps onto EnterpriseLimits.
		HITLApprovalEnabled: false,
		// INERT while HITLApprovalEnabled is false - the gate refuses before
		// any cap is read. Kept FINITE rather than set to 0 for two reasons:
		// 0 means "unlimited" to queue.Enqueuer (`maxPending > 0`), so zeroing
		// it would point the fail-safe direction the wrong way if the gate
		// ever regressed; and aligning it with the enterprise copy retires a
		// live divergence (this copy said 100, both enterprise copies said 25
		// - #3416 item 2) rather than leaving two dead numbers disagreeing.
		HITLExpiryHours:          24,
		PolicySimulationEnabled:  true,
		MaxSimulationsPerDay:     300,
		MaxImpactReportInputs:    50,
		EvidenceExportEnabled:    true,
		MaxEvidenceExportRecords: 5000,
		MaxEvidenceWindowDays:    14,
		MaxEvidenceExportsPerDay: 3,
	}
	EnterpriseLimits = TierLimits{
		TenantPolicies:         -1,   // Unlimited
		OrgPolicies:            -1,   // Unlimited
		CustomPolicyConnectors: -1,   // Unlimited
		AuditRetentionDays:     3650, // ~10 years, configurable
		MaxLLMProviders:        -1,   // Unlimited
		MaxExecutionHistory:    -1,   // Unlimited
		MaxConcurrentExec:      -1,   // Unlimited
		MaxPlans:               -1,   // Unlimited
		MaxVersionsPerPlan:     -1,   // Unlimited
		MaxSSEConnections:      -1,   // Unlimited
		MaxCostEstimatesPerDay: -1,   // Unlimited
		MaxPendingApprovals:    -1,   // Unlimited
		MediaGovernanceEnabled: true,
		// Scale boundaries: contract or unlimited on every Enterprise tier
		// (ruled 2026-09-07, #3593 D4). admission.Admit returns before any
		// I/O when the limit is -1, so an outage cannot reach Enterprise.
		MaxHumanPrincipals:   -1,
		MaxServicePrincipals: -1,
		MaxNodes:             -1,
		DailyEventQuota:      -1, // not a SaaS Plugin tier; daily quota n/a
		// V1 Plugin Pro fields: -1 = n/a (Enterprise is self-hosted, not SaaS Plugin)
		MaxActiveCustomPolicies: -1,
		MaxHITLApprovalsPerWeek: -1,
		// V1.1 decision-list: full retention / 1000 per page.
		DecisionListWindowHours: -1, // unbounded — only audit retention bounds the lookback
		DecisionListMaxPage:     1000,
		// Enterprise features enabled, unlimited
		HITLApprovalEnabled:      true,
		HITLExpiryHours:          24,
		PolicySimulationEnabled:  true,
		MaxSimulationsPerDay:     -1, // Unlimited
		MaxImpactReportInputs:    100,
		EvidenceExportEnabled:    true,
		MaxEvidenceExportRecords: -1, // Unlimited
		MaxEvidenceWindowDays:    -1, // Unlimited
		MaxEvidenceExportsPerDay: -1, // Unlimited
	}
)
