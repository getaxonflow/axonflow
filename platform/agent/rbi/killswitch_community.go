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

package rbi

import (
	"context"
	"database/sql"
)

// KillSwitchChecker is the Community stub for kill switch checking.
// In Community mode, kill switches are not enforced.
type KillSwitchChecker struct{}

// NewKillSwitchChecker creates a new kill switch checker.
// In Community mode, this returns a no-op implementation.
func NewKillSwitchChecker(_ *sql.DB) *KillSwitchChecker {
	return &KillSwitchChecker{}
}

// KillSwitchCheckResult represents the result of a kill switch check.
type KillSwitchCheckResult struct {
	// IsBlocked indicates if the request should be blocked
	IsBlocked bool `json:"is_blocked"`

	// Reason provides the blocking reason if blocked
	Reason string `json:"reason,omitempty"`

	// KillSwitchID is the ID of the active kill switch if any
	KillSwitchID string `json:"kill_switch_id,omitempty"`

	// Scope indicates the kill switch scope
	Scope string `json:"scope,omitempty"`

	// FallbackBehavior indicates what to do when blocked
	FallbackBehavior string `json:"fallback_behavior,omitempty"`
}

// CheckKillSwitch checks if any active kill switch applies to the request.
// In Community mode, this always returns not blocked.
func (k *KillSwitchChecker) CheckKillSwitch(_ context.Context, _, _ string) *KillSwitchCheckResult {
	return &KillSwitchCheckResult{
		IsBlocked: false,
		Reason:    "",
	}
}

// KillSwitchEnabled returns whether kill switch enforcement is enabled.
// In Community mode, this returns false.
func KillSwitchEnabled() bool {
	return false
}

// ListActiveKillSwitches returns all active kill switches for an org.
// In Community mode, this returns an empty slice.
func (k *KillSwitchChecker) ListActiveKillSwitches(_ context.Context, _ string) ([]*ActiveKillSwitch, error) {
	return nil, nil
}

// ActiveKillSwitch represents a simplified view of an active kill switch.
type ActiveKillSwitch struct {
	ID               string `json:"id"`
	Scope            string `json:"scope"`
	SystemID         string `json:"system_id,omitempty"`
	TargetIdentifier string `json:"target_identifier,omitempty"`
	ActivatedBy      string `json:"activated_by"`
	ActivationReason string `json:"activation_reason"`
	FallbackBehavior string `json:"fallback_behavior"`
}
