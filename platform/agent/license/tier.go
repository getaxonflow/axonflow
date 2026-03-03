//go:build !enterprise

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

// Package license provides license tier types, constants, validation, and
// helpers shared across community and enterprise builds.
package license

import (
	"crypto/ed25519"
	"time"
)

// Tier represents the license tier
type Tier string

const (
	TierProfessional   Tier = "Professional"
	TierEnterprise     Tier = "Enterprise"
	TierEnterprisePlus Tier = "Plus"
	TierEvaluation     Tier = "Evaluation" // Evaluation tier - free license with elevated limits
	TierCommunity      Tier = "Community"  // Community tier - no license required
)

// IsPaidTier returns true if the tier is a paid tier (Professional, Enterprise, Plus).
func IsPaidTier(t Tier) bool {
	return t == TierProfessional || t == TierEnterprise || t == TierEnterprisePlus
}

// IsEvaluationOrHigher returns true if the tier is Evaluation or any paid tier.
func IsEvaluationOrHigher(t Tier) bool {
	return t == TierEvaluation || IsPaidTier(t)
}

// tierRank returns the numeric rank of a tier for comparison.
func tierRank(t Tier) int {
	switch t {
	case TierCommunity:
		return 0
	case TierEvaluation:
		return 0
	case TierProfessional:
		return 1
	case TierEnterprise:
		return 2
	case TierEnterprisePlus:
		return 3
	default:
		return 0
	}
}

// TierSatisfiesRequirement returns true if the current tier meets or exceeds
// the required tier level. Used for provider access gating.
func TierSatisfiesRequirement(current, required Tier) bool {
	return tierRank(current) >= tierRank(required)
}

// normalizeTier validates that a tier string matches one of the canonical
// Tier constants. Returns the tier as-is if valid, or Tier(raw) for unknown
// values (which will fail downstream validation).
func normalizeTier(raw string) Tier {
	switch raw {
	case string(TierProfessional):
		return TierProfessional
	case string(TierEnterprise):
		return TierEnterprise
	case string(TierEnterprisePlus):
		return TierEnterprisePlus
	case string(TierEvaluation):
		return TierEvaluation
	default:
		return Tier(raw)
	}
}

// TierLimits defines the resource limits for a license tier.
type TierLimits struct {
	TenantPolicies         int `json:"tenant_policies"`
	OrgPolicies            int `json:"org_policies"`
	CustomPolicyConnectors int `json:"custom_policy_connectors"`
	AuditRetentionDays     int `json:"audit_retention_days"`
	MaxLLMProviders        int `json:"max_llm_providers"`
	MaxExecutionHistory    int `json:"max_execution_history"`
	MaxConcurrentExec      int `json:"max_concurrent_executions"`
	MaxPlans               int `json:"max_plans"`
	MaxVersionsPerPlan     int `json:"max_versions_per_plan"`
	MaxSSEConnections      int `json:"max_sse_connections"`
	MaxCostEstimatesPerDay int  `json:"max_cost_estimates_per_day"`
	MaxPendingApprovals    int  `json:"max_pending_approvals"`
	MediaGovernanceEnabled bool `json:"media_governance_enabled"`

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
		MediaGovernanceEnabled: false, // Opt-in via MEDIA_GOVERNANCE_ENABLED=true
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
		MaxPendingApprovals:    100,
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

// Ed25519 public keys for license signature verification.
// These are embedded in the binary — the corresponding private keys
// never leave our infrastructure (AWS Secrets Manager / CF Worker).
// Generated by scripts/generate-license-keypair.sh on 2026-02-09.

// evaluationPublicKey verifies Evaluation tier licenses.
var evaluationPublicKey = ed25519.PublicKey{
	0x99, 0xbe, 0xd4, 0xd7, 0xa2, 0x50, 0xd8, 0xa0,
	0x8b, 0x2a, 0x79, 0x71, 0x4f, 0x52, 0xf0, 0x59,
	0xd5, 0x79, 0xa0, 0x7a, 0xf8, 0x16, 0x3f, 0x3e,
	0x85, 0x4f, 0x4b, 0x5e, 0x7f, 0xf6, 0x2a, 0x85,
}

// enterprisePublicKey verifies Professional, Enterprise, and Plus tier licenses.
var enterprisePublicKey = ed25519.PublicKey{
	0x9a, 0xb6, 0xf6, 0xb2, 0xde, 0xc1, 0xcd, 0xbb,
	0x66, 0x26, 0x6c, 0xcd, 0xa0, 0x5f, 0xfb, 0x0b,
	0xa7, 0x2b, 0x14, 0xc0, 0x52, 0xa5, 0xcb, 0x58,
	0x79, 0xf8, 0xcf, 0xdd, 0xd0, 0x06, 0x8a, 0xd3,
}

// ValidationResult contains the result of license validation
type ValidationResult struct {
	Valid           bool
	Tier            Tier
	OrgID           string
	MaxNodes        int
	ExpiresAt       time.Time
	DaysUntilExpiry int
	GracePeriodDays int
	Error           string
	Message         string
	Features        map[string]bool
	Limits          TierLimits // Tier-specific resource limits

	// Service identity fields (optional - only for service licenses)
	ServiceName string   `json:"service_name,omitempty"`
	ServiceType string   `json:"service_type,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Email       string   `json:"email,omitempty"`
	LicenseID   string   `json:"license_id,omitempty"`
}

// ServiceLicensePayload represents the JSON payload in an Ed25519-signed license.
type ServiceLicensePayload struct {
	LicenseID   string      `json:"id,omitempty"`
	Tier        string      `json:"tier"`
	TenantID    string      `json:"tenant_id"`
	ServiceName string      `json:"service_name,omitempty"`
	ServiceType string      `json:"service_type,omitempty"`
	Permissions []string    `json:"permissions,omitempty"`
	IssuedAt    string      `json:"issued_at,omitempty"` // Format: YYYYMMDD
	ExpiresAt   string      `json:"expires_at"`          // Format: YYYYMMDD
	Email       string      `json:"email,omitempty"`
	Email2      string      `json:"email2,omitempty"`
	Limits      *TierLimits `json:"limits,omitempty"`
}

// ValidateHMACSecretAtStartup is a no-op — HMAC is no longer used.
// Kept for interface compatibility during migration. Will be removed.
func ValidateHMACSecretAtStartup() error {
	return nil
}

// verifyEd25519Signature verifies the Ed25519 signature of a license payload.
// Selects the appropriate public key based on the license tier.
func verifyEd25519Signature(payload, signature []byte, tier Tier) bool {
	var pubKey ed25519.PublicKey
	switch tier {
	case TierEvaluation:
		pubKey = evaluationPublicKey
	default: // Professional, Enterprise, Plus
		pubKey = enterprisePublicKey
	}
	return ed25519.Verify(pubKey, payload, signature)
}
