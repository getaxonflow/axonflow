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

	// SaaS Plugin tier constants (per ADR-050 §1) — duplicated here for
	// the community build because `auth.go` references `TierFree` and
	// `auth.go` is loaded in BOTH build tags. The enterprise validation.go
	// declares the same constants under `//go:build enterprise`; both
	// share the same string values so the rendered DB rows / API responses
	// are identical regardless of which build resolves the symbol.
	TierFree    Tier = "Free"
	TierPro     Tier = "Pro"
	TierPremium Tier = "Premium"
)

// IsPaidTier returns true if the tier is a paid tier (Professional, Enterprise, Plus).
func IsPaidTier(t Tier) bool {
	return t == TierProfessional || t == TierEnterprise || t == TierEnterprisePlus
}

// IsEvaluationOrHigher returns true if the tier is Evaluation or any paid tier.
func IsEvaluationOrHigher(t Tier) bool {
	return t == TierEvaluation || IsPaidTier(t)
}

// tierRank returns the numeric rank of a tier for comparison. Returns -1
// for any unknown tier so rank-based comparisons fail closed (GAP-3).
// Pre-fix the default returned 0 (== Community), silently treating unknown
// tiers as the lowest valid tier — a footgun for any future tier added
// without updating this switch. Mirrors the enterprise-build version in
// validation.go.
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
		return -1
	}
}

// TierSatisfiesRequirement returns true if the current tier meets or exceeds
// the required tier level. Used for provider access gating.
//
// Fails closed when EITHER tier has rank -1 (unknown tier — GAP-3).
func TierSatisfiesRequirement(current, required Tier) bool {
	cr := tierRank(current)
	rr := tierRank(required)
	if cr < 0 || rr < 0 {
		return false
	}
	return cr >= rr
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

	// SaaS Plugin daily write-quota — only meaningful for SaaS Plugin
	// tiers (Free/Pro/Premium per ADR-050 §1). The community build never
	// resolves to a SaaS Plugin tier, so any read here is a no-op; the
	// field exists so the struct shape stays identical across builds.
	DailyEventQuota int `json:"daily_event_quota"`

	// V1 Plugin Pro graduated-freemium fields (umbrella #1958). Free
	// tier exposes a "taste" of these capabilities — Pro tier removes
	// the caps. -1 = unlimited (Pro / Premium / self-hosted higher
	// tiers). Same semantics as DailyEventQuota: -1 means n/a / not a
	// SaaS Plugin tier. The community build never resolves to a SaaS
	// Plugin tier; field carried so cross-build struct shape is
	// identical.
	MaxActiveCustomPolicies int `json:"max_active_custom_policies"`
	MaxHITLApprovalsPerWeek int `json:"max_hitl_approvals_per_week"`

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
		DailyEventQuota:        -1,    // not a SaaS Plugin tier; daily quota n/a
		// V1 Plugin Pro fields: -1 = n/a (community build never resolves
		// to a SaaS Plugin tier; cross-build struct-shape parity only).
		MaxActiveCustomPolicies: -1,
		MaxHITLApprovalsPerWeek: -1,
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
		DailyEventQuota:        -1, // not a SaaS Plugin tier; daily quota n/a
		// V1 Plugin Pro fields: -1 = n/a (Evaluation is self-hosted, not SaaS Plugin)
		MaxActiveCustomPolicies: -1,
		MaxHITLApprovalsPerWeek: -1,
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
// Rotated on 2026-04-09 (issue #1541). Must match ee/platform/agent/license/validation.go.
var enterprisePublicKey = ed25519.PublicKey{
	0x48, 0xac, 0xd8, 0xd1, 0x32, 0xaf, 0x9d, 0x4f,
	0xef, 0x3e, 0x6a, 0x92, 0x49, 0xb6, 0xdb, 0x2f,
	0xe8, 0x07, 0x21, 0x45, 0xd2, 0xaf, 0x2c, 0xfb,
	0x42, 0xb8, 0xc7, 0x22, 0x1e, 0x04, 0xa4, 0xb6,
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
//
// Plugin-claim claims (TenantID, Aud, JTI, KID, Origin) are all `omitempty` so
// they only appear in plugin-claim tokens. Self-hosted tokens continue to
// serialize without these fields, preserving backward compatibility — existing
// validators don't read fields they don't know about. Carried in both
// community and enterprise builds so HasScope() / HostingMode() (defined in
// scope.go, no build tag) compile against a uniform shape.
type ServiceLicensePayload struct {
	LicenseID   string      `json:"id,omitempty"`
	Tier        string      `json:"tier"`
	OrgID       string      `json:"org_id"`
	ServiceName string      `json:"service_name,omitempty"`
	ServiceType string      `json:"service_type,omitempty"`
	Permissions []string    `json:"permissions,omitempty"`
	IssuedAt    string      `json:"issued_at,omitempty"` // Format: YYYYMMDD
	ExpiresAt   string      `json:"expires_at"`          // Format: YYYYMMDD
	Email       string      `json:"email,omitempty"`
	Email2      string      `json:"email2,omitempty"`
	Limits      *TierLimits `json:"limits,omitempty"`

	// Plugin-claim / SaaS-quadrant claims. Only present in tokens issued for
	// the SaaS Plugin path; self-hosted tokens leave them empty.
	TenantID string `json:"tenant_id,omitempty"`
	Aud      string `json:"aud,omitempty"` // see ADR-050 §1 for the canonical six values
	JTI      string `json:"jti,omitempty"`
	KID      string `json:"kid,omitempty"`
	Origin   string `json:"origin,omitempty"`
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
