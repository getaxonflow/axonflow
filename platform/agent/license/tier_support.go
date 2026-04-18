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
	TenantPolicies          int  `json:"tenant_policies"`
	OrgPolicies             int  `json:"org_policies"`
	CustomPolicyConnectors  int  `json:"custom_policy_connectors"`
	AuditRetentionDays      int  `json:"audit_retention_days"`
	MaxLLMProviders         int  `json:"max_llm_providers"`
	MaxExecutionHistory     int  `json:"max_execution_history"`
	MaxConcurrentExec       int  `json:"max_concurrent_executions"`
	MaxPlans                int  `json:"max_plans"`
	MaxVersionsPerPlan      int  `json:"max_versions_per_plan"`
	MaxSSEConnections       int  `json:"max_sse_connections"`
	MaxCostEstimatesPerDay  int  `json:"max_cost_estimates_per_day"`
	MaxPendingApprovals     int  `json:"max_pending_approvals"`
	MediaGovernanceEnabled  bool `json:"media_governance_enabled"`

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

// GetTierLimits returns the resource limits for a given tier.
func GetTierLimits(tier Tier) TierLimits {
	switch tier {
	case TierEvaluation:
		return EvaluationLimits
	case TierProfessional, TierEnterprise, TierEnterprisePlus:
		return EnterpriseLimits
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
