//go:build enterprise

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

package license

import (
	"context"
	"os"
	"time"
)

// TierLimits defines the resource limits for a license tier.
type TierLimits struct {
	TenantPolicies         int  `json:"tenant_policies"`
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

// Default tier limits
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
		MediaGovernanceEnabled: false,
		DailyEventQuota:        -1, // not a SaaS Plugin tier; daily quota n/a
		// V1 Plugin Pro fields: -1 = n/a (Community is self-hosted, not SaaS Plugin)
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
		TenantPolicies:         50,
		OrgPolicies:            5,
		CustomPolicyConnectors: 5,
		AuditRetentionDays:     14,
		MaxLLMProviders:        3,
		MaxExecutionHistory:    500,
		MaxConcurrentExec:      25,
		MaxPlans:               100,
		MaxVersionsPerPlan:     25,
		MaxSSEConnections:      25,
		MaxCostEstimatesPerDay: 100,
		// MaxPendingApprovals: aligned with the rest of the evaluation
		// tier caps (25, matching MaxConcurrentExec / MaxSSEConnections /
		// MaxVersionsPerPlan). The previous value of 100 was an outlier
		// and contradicted TestTierBoundary_EvaluationLimitsValues.
		MaxPendingApprovals:    25,
		MediaGovernanceEnabled: true,
		DailyEventQuota:        -1, // not a SaaS Plugin tier; daily quota n/a
		// V1 Plugin Pro fields: -1 = n/a (Evaluation is self-hosted, not SaaS Plugin)
		MaxActiveCustomPolicies: -1,
		MaxHITLApprovalsPerWeek: -1,
		// V1.1 decision-list: 14d / 100 per page.
		DecisionListWindowHours: 336,
		DecisionListMaxPage:     100,
		// Evaluation features enabled with limits
		HITLApprovalEnabled:      true,
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
		DailyEventQuota:        -1, // not a SaaS Plugin tier; daily quota n/a
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

	// FreeLimits is the SaaS Plugin Free baseline applied when a request
	// arrives without an X-License-Token header. Per
	// PRD_TENANT_DURABILITY_AND_CLAIM "Free vs Paid Boundary" (locked
	// 2026-05-05): 3-day audit retention + 200 events/day quota.
	//
	// Non-tenant-scoped fields (MaxLLMProviders, MaxExecutionHistory, …)
	// are deployment-scoped per ADR-050 §9 and read from the deployment
	// ceiling (the SaaS deployment runs Enterprise-tier license, so these
	// are effectively unlimited at runtime). Mirroring CommunityLimits
	// here is a safe default for any caller that reads them directly.
	FreeLimits = TierLimits{
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
		MediaGovernanceEnabled: false,
		DailyEventQuota:        200,
		// V1 Plugin Pro graduated-freemium teasers (umbrella #1958):
		// Free tier gets a TASTE of Pro capabilities — 4 active custom
		// policies and 2 HITL approvals per rolling 7-day window. Hitting
		// either limit returns the structured upgrade envelope per
		// PRD_TENANT_DURABILITY_AND_CLAIM §"Customer-facing copy".
		MaxActiveCustomPolicies:  4,
		MaxHITLApprovalsPerWeek:  2,
		// V1.1 decision-list: 24h / 5 per page (Free tier — same as
		// self-host Community per locked V1.1 tier matrix).
		DecisionListWindowHours:  24,
		DecisionListMaxPage:      5,
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

	// ProLimits is the SaaS Plugin V1 paid tier ($9.99 / 90 days).
	// Per V1 Plugin Pro umbrella #1958: 30-day audit retention,
	// 2,000 events/day daily quota (bumped from 1,000 in #1958 — gives
	// 10x headroom over Free's 200, validated against the heaviest
	// observed Free-tier daily volume of ~780 events/day on prod).
	// Custom-policy + HITL caps raised to generous-but-finite ceilings
	// (50 policies, 20 HITL/week). Other tenant-scoped capability gates
	// (LLM cost pre-flight, evidence export) are gated at the MCP-tool
	// dispatch layer per PR2.
	ProLimits = TierLimits{
		TenantPolicies:           20,
		OrgPolicies:              0,
		CustomPolicyConnectors:   2,
		AuditRetentionDays:       30,
		MaxLLMProviders:          2,
		MaxExecutionHistory:      50,
		MaxConcurrentExec:        5,
		MaxPlans:                 25,
		MaxVersionsPerPlan:       10,
		MaxSSEConnections:        5,
		MaxCostEstimatesPerDay:   10,
		MaxPendingApprovals:      5,
		MediaGovernanceEnabled:   false,
		DailyEventQuota:          2000,
		MaxActiveCustomPolicies:  50,
		MaxHITLApprovalsPerWeek:  20,
		// V1.1 decision-list: 30d (720h) / 100 per page.
		DecisionListWindowHours:  720,
		DecisionListMaxPage:      100,
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

	// PremiumLimits is the SaaS Plugin Premium tier — placeholder for a
	// future expensive higher tier (~$19.99/month subscription, TBD).
	// NOT sold V1; populated so the schema reserves the constant + the
	// downstream `audit_cleanup` / `community_saas_ratelimit` paths can be
	// tested end-to-end without waiting on the Premium product launch.
	// 90-day retention + 5000 events/day quota per the PRD's placeholder
	// numbers — adjust when Premium PRD locks the real values.
	PremiumLimits = TierLimits{
		TenantPolicies:         20,
		OrgPolicies:            0,
		CustomPolicyConnectors: 2,
		AuditRetentionDays:     90,
		MaxLLMProviders:        2,
		MaxExecutionHistory:    50,
		MaxConcurrentExec:      5,
		MaxPlans:               25,
		MaxVersionsPerPlan:     10,
		MaxSSEConnections:      5,
		MaxCostEstimatesPerDay: 10,
		MaxPendingApprovals:    5,
		MediaGovernanceEnabled: false,
		DailyEventQuota:        5000,
		// V1 Plugin Pro fields: -1 = unlimited (Premium also removes Free caps).
		MaxActiveCustomPolicies:  -1,
		MaxHITLApprovalsPerWeek:  -1,
		// V1.1 decision-list: matches Pro until Premium PRD locks
		// distinct values (placeholder tier; not sold V1).
		DecisionListWindowHours:  720,
		DecisionListMaxPage:      100,
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
)

// GetTierLimits returns the resource limits for a given tier.
func GetTierLimits(tier Tier) TierLimits {
	switch tier {
	case TierEvaluation:
		return EvaluationLimits
	case TierProfessional, TierEnterprise, TierEnterprisePlus:
		return EnterpriseLimits
	case TierFree:
		return FreeLimits
	case TierPro:
		return ProLimits
	case TierPremium:
		return PremiumLimits
	default:
		return CommunityLimits
	}
}

// GetCurrentTier returns the current license tier based on AXONFLOW_LICENSE_KEY.
// Returns TierCommunity if no valid license is found or if the license is expired.
func GetCurrentTier(ctx context.Context) Tier {
	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
	if licenseKey == "" {
		return TierCommunity
	}
	result, err := ValidateLicense(ctx, licenseKey)
	if err != nil || result == nil || !result.Valid {
		return TierCommunity
	}
	if time.Now().After(result.ExpiresAt) {
		return TierCommunity
	}
	return result.Tier
}

// GetCurrentLimits returns the resource limits based on the current license.
// If the license is expired, returns Community limits (graceful degradation).
func GetCurrentLimits(ctx context.Context) TierLimits {
	tier := GetCurrentTier(ctx)
	return GetTierLimits(tier)
}

// IsEvaluationOrHigherTier checks if the AXONFLOW_LICENSE_KEY environment variable
// contains a valid Evaluation, Enterprise, or EnterprisePlus license.
func IsEvaluationOrHigherTier(ctx context.Context) bool {
	tier := GetCurrentTier(ctx)
	return tier == TierEvaluation || tier == TierProfessional || tier == TierEnterprise || tier == TierEnterprisePlus
}
