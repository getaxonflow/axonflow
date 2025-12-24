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
	"fmt"
	"os"
	"strings"
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

// EnvLicenseChecker checks the DEPLOYMENT_MODE environment variable to determine
// if the current deployment is Enterprise edition.
type EnvLicenseChecker struct {
	mode string
}

// NewEnvLicenseChecker creates a license checker that reads DEPLOYMENT_MODE from environment.
func NewEnvLicenseChecker() *EnvLicenseChecker {
	return &EnvLicenseChecker{
		mode: strings.ToLower(os.Getenv("DEPLOYMENT_MODE")),
	}
}

// IsEnterprise returns true if DEPLOYMENT_MODE is not "community" (or empty).
// Enterprise modes include: saas, enterprise, banking, travel, healthcare, etc.
func (e *EnvLicenseChecker) IsEnterprise() bool {
	// Empty or "community" means Community edition
	if e.mode == "" || e.mode == "community" {
		return false
	}
	return true
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
