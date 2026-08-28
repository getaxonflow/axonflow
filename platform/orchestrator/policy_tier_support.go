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

package orchestrator

import (
	"context"
	"fmt"

	"axonflow/platform/agent/license"
)

// LicenseChecker provides license validation for tier enforcement.
type LicenseChecker interface {
	// IsEnterprise returns true if the current deployment is Enterprise edition.
	IsEnterprise() bool

	// Tier returns the current license tier.
	Tier() license.Tier

	// PolicyLimit returns the maximum number of tenant policies allowed.
	// Returns -1 for unlimited (Enterprise).
	PolicyLimit() int

	// OrgPolicyLimit returns the maximum number of organization policies allowed.
	// Returns -1 for unlimited (Enterprise).
	OrgPolicyLimit() int

	// CustomPolicyConnectorLimit returns the maximum number of connectors with custom policies.
	// Returns -1 for unlimited (Enterprise).
	CustomPolicyConnectorLimit() int

	// AuditRetentionDays returns the number of days audit logs are retained.
	AuditRetentionDays() int

	// MaxLLMProviders returns the maximum number of LLM providers allowed.
	// Returns -1 for unlimited (Enterprise).
	MaxLLMProviders() int

	// MaxExecutionHistory returns the maximum number of execution history records.
	// Returns -1 for unlimited (Enterprise).
	MaxExecutionHistory() int

	// MaxConcurrentExecutions returns the maximum number of concurrent executions.
	// Returns -1 for unlimited (Enterprise).
	MaxConcurrentExecutions() int

	// MaxPlans returns the maximum number of stored plans with versioning.
	// Returns -1 for unlimited (Enterprise).
	MaxPlans() int

	// MaxVersionsPerPlan returns the maximum number of versions per plan.
	// Returns -1 for unlimited (Enterprise).
	MaxVersionsPerPlan() int

	// MaxSSEConnections returns the maximum concurrent SSE connections per tenant.
	// Returns -1 for unlimited (Enterprise).
	MaxSSEConnections() int

	// MaxCostEstimatesPerDay returns the maximum number of cost estimates per day.
	// Returns -1 for unlimited (Enterprise).
	MaxCostEstimatesPerDay() int

	// MaxPendingApprovals returns the maximum number of concurrent pending approvals per tenant.
	// Returns -1 for unlimited (Enterprise).
	MaxPendingApprovals() int

	// MediaGovernanceEnabled returns true if media governance is enabled for the current tier.
	// Community: false by default (opt-in via env var), Evaluation/Enterprise: true.
	MediaGovernanceEnabled() bool

	// IsHITLApprovalEnabled returns true if HITL approval gates are enabled.
	IsHITLApprovalEnabled() bool

	// HITLExpiryHours returns the approval expiry time in hours (0 = no expiry).
	HITLExpiryHours() int

	// IsPolicySimulationEnabled returns true if policy simulation is enabled.
	IsPolicySimulationEnabled() bool

	// MaxSimulationsPerDay returns the maximum policy simulations per day.
	// Returns -1 for unlimited (Enterprise).
	MaxSimulationsPerDay() int

	// MaxImpactReportInputs returns the maximum inputs per impact report run.
	MaxImpactReportInputs() int

	// IsEvidenceExportEnabled returns true if evidence export is enabled.
	IsEvidenceExportEnabled() bool

	// MaxEvidenceExportRecords returns the maximum records per evidence export.
	// Returns -1 for unlimited (Enterprise).
	MaxEvidenceExportRecords() int

	// MaxEvidenceWindowDays returns the maximum lookback window in days for evidence export.
	// Returns -1 for unlimited (Enterprise).
	MaxEvidenceWindowDays() int

	// MaxEvidenceExportsPerDay returns the maximum evidence exports per day.
	// Returns -1 for unlimited (Enterprise).
	MaxEvidenceExportsPerDay() int
}

// DefaultLicenseChecker is a default implementation that returns Community mode.
type DefaultLicenseChecker struct{}

// IsEnterprise returns false for the default (Community) license checker.
func (d *DefaultLicenseChecker) IsEnterprise() bool {
	return false
}

// Tier returns Community tier for the default license checker.
func (d *DefaultLicenseChecker) Tier() license.Tier {
	return license.TierCommunity
}

// PolicyLimit returns the Community policy limit.
func (d *DefaultLicenseChecker) PolicyLimit() int {
	return license.CommunityLimits.TenantPolicies
}

// OrgPolicyLimit returns 0 for Community (org policies not allowed).
func (d *DefaultLicenseChecker) OrgPolicyLimit() int {
	return 0
}

// CustomPolicyConnectorLimit returns the Community custom policy connector limit.
func (d *DefaultLicenseChecker) CustomPolicyConnectorLimit() int {
	return license.CommunityLimits.CustomPolicyConnectors
}

// AuditRetentionDays returns 3 days for Community.
func (d *DefaultLicenseChecker) AuditRetentionDays() int {
	return 3
}

// MaxLLMProviders returns 2 for Community.
func (d *DefaultLicenseChecker) MaxLLMProviders() int {
	return 2
}

// MaxExecutionHistory returns 50 for Community.
func (d *DefaultLicenseChecker) MaxExecutionHistory() int {
	return 50
}

// MaxConcurrentExecutions returns 5 for Community.
func (d *DefaultLicenseChecker) MaxConcurrentExecutions() int {
	return 5
}

// MaxPlans returns 25 for Community.
func (d *DefaultLicenseChecker) MaxPlans() int {
	return 25
}

// MaxVersionsPerPlan returns 10 for Community.
func (d *DefaultLicenseChecker) MaxVersionsPerPlan() int {
	return 10
}

// MaxSSEConnections returns 5 for Community.
func (d *DefaultLicenseChecker) MaxSSEConnections() int {
	return license.CommunityLimits.MaxSSEConnections
}

// MaxCostEstimatesPerDay returns 10 for Community.
func (d *DefaultLicenseChecker) MaxCostEstimatesPerDay() int {
	return license.CommunityLimits.MaxCostEstimatesPerDay
}

// MaxPendingApprovals returns 5 for Community.
func (d *DefaultLicenseChecker) MaxPendingApprovals() int {
	return license.CommunityLimits.MaxPendingApprovals
}

// MediaGovernanceEnabled returns false for Community (opt-in via env var).
func (d *DefaultLicenseChecker) MediaGovernanceEnabled() bool {
	return license.CommunityLimits.MediaGovernanceEnabled
}

// IsHITLApprovalEnabled returns false for Community.
func (d *DefaultLicenseChecker) IsHITLApprovalEnabled() bool {
	return license.CommunityLimits.HITLApprovalEnabled
}

// HITLExpiryHours returns 0 for Community.
func (d *DefaultLicenseChecker) HITLExpiryHours() int {
	return license.CommunityLimits.HITLExpiryHours
}

// IsPolicySimulationEnabled returns false for Community.
func (d *DefaultLicenseChecker) IsPolicySimulationEnabled() bool {
	return license.CommunityLimits.PolicySimulationEnabled
}

// MaxSimulationsPerDay returns 0 for Community.
func (d *DefaultLicenseChecker) MaxSimulationsPerDay() int {
	return license.CommunityLimits.MaxSimulationsPerDay
}

// MaxImpactReportInputs returns 0 for Community.
func (d *DefaultLicenseChecker) MaxImpactReportInputs() int {
	return license.CommunityLimits.MaxImpactReportInputs
}

// IsEvidenceExportEnabled returns false for Community.
func (d *DefaultLicenseChecker) IsEvidenceExportEnabled() bool {
	return license.CommunityLimits.EvidenceExportEnabled
}

// MaxEvidenceExportRecords returns 0 for Community.
func (d *DefaultLicenseChecker) MaxEvidenceExportRecords() int {
	return license.CommunityLimits.MaxEvidenceExportRecords
}

// MaxEvidenceWindowDays returns 0 for Community.
func (d *DefaultLicenseChecker) MaxEvidenceWindowDays() int {
	return license.CommunityLimits.MaxEvidenceWindowDays
}

// MaxEvidenceExportsPerDay returns 0 for Community.
func (d *DefaultLicenseChecker) MaxEvidenceExportsPerDay() int {
	return license.CommunityLimits.MaxEvidenceExportsPerDay
}

// EnvLicenseChecker validates the license via AXONFLOW_LICENSE_KEY environment variable.
// Each method re-reads the license to support hot-reload scenarios.
type EnvLicenseChecker struct{}

// NewEnvLicenseChecker creates a license checker that validates via AXONFLOW_LICENSE_KEY.
func NewEnvLicenseChecker() *EnvLicenseChecker {
	return &EnvLicenseChecker{}
}

// IsEnterprise returns true if AXONFLOW_LICENSE_KEY contains a valid paid license
// (Professional, Enterprise, or Plus).
func (e *EnvLicenseChecker) IsEnterprise() bool {
	return license.IsPaidTier(e.Tier())
}

// Tier returns the current license tier.
func (e *EnvLicenseChecker) Tier() license.Tier {
	return license.GetCurrentTier(context.Background())
}

// PolicyLimit returns the maximum number of tenant policies allowed.
func (e *EnvLicenseChecker) PolicyLimit() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.TenantPolicies
}

// OrgPolicyLimit returns the maximum number of organization policies allowed.
func (e *EnvLicenseChecker) OrgPolicyLimit() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.OrgPolicies
}

// CustomPolicyConnectorLimit returns the maximum number of connectors with custom policies.
func (e *EnvLicenseChecker) CustomPolicyConnectorLimit() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.CustomPolicyConnectors
}

// AuditRetentionDays returns the number of days audit logs are retained.
func (e *EnvLicenseChecker) AuditRetentionDays() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.AuditRetentionDays
}

// MaxLLMProviders returns the maximum number of LLM providers allowed.
func (e *EnvLicenseChecker) MaxLLMProviders() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MaxLLMProviders
}

// MaxExecutionHistory returns the maximum number of execution history records.
func (e *EnvLicenseChecker) MaxExecutionHistory() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MaxExecutionHistory
}

// MaxConcurrentExecutions returns the maximum number of concurrent executions.
func (e *EnvLicenseChecker) MaxConcurrentExecutions() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MaxConcurrentExec
}

// MaxPlans returns the maximum number of stored plans with versioning.
func (e *EnvLicenseChecker) MaxPlans() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MaxPlans
}

// MaxVersionsPerPlan returns the maximum number of versions per plan.
func (e *EnvLicenseChecker) MaxVersionsPerPlan() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MaxVersionsPerPlan
}

// MaxSSEConnections returns the maximum concurrent SSE connections per tenant.
func (e *EnvLicenseChecker) MaxSSEConnections() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MaxSSEConnections
}

// MaxCostEstimatesPerDay returns the maximum number of cost estimates per day.
func (e *EnvLicenseChecker) MaxCostEstimatesPerDay() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MaxCostEstimatesPerDay
}

// MaxPendingApprovals returns the maximum number of concurrent pending approvals per tenant.
func (e *EnvLicenseChecker) MaxPendingApprovals() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MaxPendingApprovals
}

// MediaGovernanceEnabled returns true if the current tier has media governance enabled.
func (e *EnvLicenseChecker) MediaGovernanceEnabled() bool {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MediaGovernanceEnabled
}

// IsHITLApprovalEnabled returns true if HITL approval gates are enabled for the current tier.
func (e *EnvLicenseChecker) IsHITLApprovalEnabled() bool {
	limits := license.GetCurrentLimits(context.Background())
	return limits.HITLApprovalEnabled
}

// HITLExpiryHours returns the approval expiry time in hours.
func (e *EnvLicenseChecker) HITLExpiryHours() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.HITLExpiryHours
}

// IsPolicySimulationEnabled returns true if policy simulation is enabled for the current tier.
func (e *EnvLicenseChecker) IsPolicySimulationEnabled() bool {
	limits := license.GetCurrentLimits(context.Background())
	return limits.PolicySimulationEnabled
}

// MaxSimulationsPerDay returns the maximum policy simulations per day.
func (e *EnvLicenseChecker) MaxSimulationsPerDay() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MaxSimulationsPerDay
}

// MaxImpactReportInputs returns the maximum inputs per impact report run.
func (e *EnvLicenseChecker) MaxImpactReportInputs() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MaxImpactReportInputs
}

// IsEvidenceExportEnabled returns true if evidence export is enabled for the current tier.
func (e *EnvLicenseChecker) IsEvidenceExportEnabled() bool {
	limits := license.GetCurrentLimits(context.Background())
	return limits.EvidenceExportEnabled
}

// MaxEvidenceExportRecords returns the maximum records per evidence export.
func (e *EnvLicenseChecker) MaxEvidenceExportRecords() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MaxEvidenceExportRecords
}

// MaxEvidenceWindowDays returns the maximum lookback window in days.
func (e *EnvLicenseChecker) MaxEvidenceWindowDays() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MaxEvidenceWindowDays
}

// MaxEvidenceExportsPerDay returns the maximum evidence exports per day.
func (e *EnvLicenseChecker) MaxEvidenceExportsPerDay() int {
	limits := license.GetCurrentLimits(context.Background())
	return limits.MaxEvidenceExportsPerDay
}

// TierValidationError represents a tier-related validation failure.
type TierValidationError struct {
	Message string
	Code    string
}

// Error implements the error interface.
func (e *TierValidationError) Error() string {
	return fmt.Sprintf("%s (%s)", e.Message, e.Code)
}

// IsTierValidationError checks if an error is a TierValidationError.
func IsTierValidationError(err error) bool {
	_, ok := err.(*TierValidationError)
	return ok
}

// NewTierValidationError creates a new TierValidationError.
func NewTierValidationError(message, code string) *TierValidationError {
	return &TierValidationError{
		Message: message,
		Code:    code,
	}
}

// Tier error codes
const (
	ErrCodeSystemTierImmutable          = "SYSTEM_TIER_IMMUTABLE"
	ErrCodeOrgTierEnterprise            = "ORG_TIER_REQUIRES_ENTERPRISE"
	ErrCodeOrgTierEvaluationOrHigher    = "ORG_TIER_REQUIRES_EVALUATION_OR_HIGHER"
	ErrCodePolicyLimitExceeded          = "POLICY_LIMIT_EXCEEDED"
	ErrCodeOrgPolicyLimitExceeded       = "ORG_POLICY_LIMIT_EXCEEDED"
	ErrCodeConnectorLimitExceeded       = "CONNECTOR_LIMIT_EXCEEDED"
	ErrCodeLicenseExpired               = "LICENSE_EXPIRED"
	ErrCodeCostEstimateLimitExceeded    = "COST_ESTIMATE_LIMIT_EXCEEDED"
	ErrCodePendingApprovalLimitExceeded = "PENDING_APPROVAL_LIMIT_EXCEEDED"
	ErrCodeSimulationLimitExceeded      = "SIMULATION_LIMIT_EXCEEDED"
	ErrCodeEvidenceExportLimitExceeded  = "EVIDENCE_EXPORT_LIMIT_EXCEEDED"
	ErrCodeFeatureRequiresEvaluation    = "FEATURE_REQUIRES_EVALUATION_LICENSE"
)

// hitlResolveAllowed reports whether a caller may RESOLVE existing HITL
// approvals - approve, reject, or list what is pending - as distinct from
// CREATING new ones.
//
// THE TWO QUESTIONS ARE DIFFERENT AND MUST NOT SHARE A PREDICATE.
//
// The 2026-08-26 operator decision made HITL approvals Enterprise-only. That
// is a decision about who may CREATE approval entries; it is enforced at the
// chokepoint in platform/agent/hitl/queue, per call, where a licence renewed
// at runtime takes effect at the next gate.
//
// Applying the same predicate to resolution strands rows. A deployment that
// holds pending approvals at upgrade time - every Evaluation deployment that
// used WCP step gates, and any deployment whose rows were written by the
// unlicensed direct INSERT this change removes - would lose approve, reject
// AND the pending list in the same release, leaving entries that can never be
// cleared and workflows that can never proceed. That is verbatim the
// phantom-row defect #3408 exists to close, reintroduced by the entitlement
// change itself.
//
// R3 round 2: this predicate exists because the two planes had already drifted
// once. Round 1 fixed the WCP registration (run.go) and left the three MAP
// handlers on IsHITLApprovalEnabled, so on DEPLOYMENT_MODE=community with an
// Evaluation licence WCP drained and MAP returned 403 - and the MAP comments
// still claimed "both planes accept Evaluation+". One predicate, one place to
// change, and a test that asserts the planes agree.
//
// WHAT THIS DELIBERATELY DOES NOT COVER, measured rather than assumed.
//
// The drain set is Evaluation and above, so Community, Free, Pro and Premium
// are still refused here. That matters for one narrow deployment class: the
// PRE-FIX enterprise binary consulted no licence at all (see
// hitl_wcp_enterprise.go's doc comment), so a Community/Free/Pro/Premium-tier
// deployment running the enterprise image genuinely accumulated wcp_step_gate
// rows on main. Such a deployment running with DEPLOYMENT_MODE=community
// cannot manually approve them, because this predicate refuses it.
//
// Those rows are NOT permanently stranded, which is the part worth having
// checked rather than assumed: the agent's cross-tenant expire ticker
// (platform/agent/run.go, ExpireStaleAcrossTenants -> ExpireStaleReturning)
// predicates on `status = 'pending' AND expires_at < CURRENT_TIMESTAMP` with
// NO request_type filter, so it expires these rows like any other. The
// deployment loses the ability to APPROVE before expiry, not the ability to
// clear the queue. In DEPLOYMENT_MODE=enterprise the routes are registered
// unconditionally and even that does not apply.
//
// Widening this predicate to those four tiers would hand Community an approval
// API it has never had. That is a tier-entitlement decision of exactly the
// kind the 2026-08-26 operator decision settled for Evaluation, and it is not
// a worker's call to make unilaterally - so it is escalated on #3517 rather
// than taken here. Note also that RegisterEvaluationRoutes bundles CHECKPOINT
// RESUME with the three approval routes, so widening this without splitting
// that bundle would grant a second, unrelated capability by accident.
//
// A nil checker is refused: no tier resolved is not a licence to act.
//
// The parameter is the NARROWEST interface this predicate reads, not
// LicenseChecker. Tier() is the only method involved, and a wider parameter
// would force every future test double to implement a dozen unrelated methods
// just to assert a tier - friction that is how gates end up with bespoke,
// drifting checks instead of a shared one. Any LicenseChecker satisfies it.
type hitlTierSource interface {
	Tier() license.Tier
}

func hitlResolveAllowed(c hitlTierSource) bool {
	if c == nil {
		return false
	}
	return license.IsEvaluationOrHigher(c.Tier())
}
