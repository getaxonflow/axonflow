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

// CommunityPolicyLimit is the maximum number of tenant policies allowed in Community edition.
const CommunityPolicyLimit = 30

// LicenseChecker provides license validation for tier enforcement.
type LicenseChecker interface {
	// IsEnterprise returns true if the current deployment is Enterprise edition.
	IsEnterprise() bool
}

// DefaultLicenseChecker is a default implementation that returns Community mode.
type DefaultLicenseChecker struct{}

// IsEnterprise returns false for the default (Community) license checker.
func (d *DefaultLicenseChecker) IsEnterprise() bool {
	return false
}

// EnvLicenseChecker validates the license via AXONFLOW_LICENSE_KEY environment variable.
type EnvLicenseChecker struct{}

// NewEnvLicenseChecker creates a license checker that validates via AXONFLOW_LICENSE_KEY.
func NewEnvLicenseChecker() *EnvLicenseChecker {
	return &EnvLicenseChecker{}
}

// IsEnterprise returns true if AXONFLOW_LICENSE_KEY contains a valid Enterprise license.
func (e *EnvLicenseChecker) IsEnterprise() bool {
	return license.IsEnterpriseTier(context.Background())
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
	ErrCodeSystemTierImmutable = "SYSTEM_TIER_IMMUTABLE"
	ErrCodeOrgTierEnterprise   = "ORG_TIER_REQUIRES_ENTERPRISE"
	ErrCodePolicyLimitExceeded = "POLICY_LIMIT_EXCEEDED"
)
