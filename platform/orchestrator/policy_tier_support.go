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
	ErrCodeSystemTierImmutable   = "SYSTEM_TIER_IMMUTABLE"
	ErrCodeOrgTierEnterprise     = "ORG_TIER_REQUIRES_ENTERPRISE"
	ErrCodeOrgTierEvaluationOrHigher = "ORG_TIER_REQUIRES_EVALUATION_OR_HIGHER"
	ErrCodePolicyLimitExceeded       = "POLICY_LIMIT_EXCEEDED"
	ErrCodeOrgPolicyLimitExceeded = "ORG_POLICY_LIMIT_EXCEEDED"
	ErrCodeConnectorLimitExceeded = "CONNECTOR_LIMIT_EXCEEDED"
	ErrCodeLicenseExpired        = "LICENSE_EXPIRED"
)
