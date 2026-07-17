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

package agent

import (
	"fmt"

	sharedpolicy "axonflow/platform/shared/policy"
)

// convertSharedResultToStatic converts a shared policy engine RequestResult
// to a StaticPolicyResult for backward compatibility with existing handler code.
// This bridges the shared engine result to the StaticPolicyResult type used by handlers.
func convertSharedResultToStatic(result *sharedpolicy.RequestResult) *StaticPolicyResult {
	if result == nil {
		return &StaticPolicyResult{
			Blocked:           false,
			TriggeredPolicies: []string{},
			ChecksPerformed:   []string{"shared_policy_engine"},
		}
	}

	staticResult := &StaticPolicyResult{
		Blocked:          result.Blocked,
		Reason:           result.BlockReason,
		ProcessingTimeMs: result.ProcessingTimeMs,
		ChecksPerformed:  []string{"shared_policy_engine"},
		EvaluationError:  result.EvaluationError, // #2862: propagate fail-closed availability failure
	}

	// Convert matched policies to triggered policy IDs
	for _, match := range result.MatchedPolicies {
		staticResult.TriggeredPolicies = append(staticResult.TriggeredPolicies, match.PolicyID)
		// Capture severity from the blocking policy
		if result.Blocked && result.BlockedBy != nil && match.PolicyID == result.BlockedBy.PolicyID {
			staticResult.Severity = string(result.BlockedBy.Severity)
		}
	}

	// Translate each non-blocking PII policy match into the governance signal
	// its RESOLVED action implies. The action carried on the match already has
	// the per-category PII_ACTION override applied (engine.go sets
	// match.Action = override), so keying on it here is edition- and
	// posture-accurate:
	//
	//   redact          → a redaction obligation (RequiresRedaction)
	//   anything else   → a truthful advisory reason, no obligation
	//   block           → cannot occur here (result.Blocked short-circuits above)
	//
	// The default arm is deliberately the CATCH-ALL, not just warn/log: a matched
	// PII policy must NEVER be a silent bare allow, so any non-blocking,
	// non-redacting resolved action (warn/log, and also require_approval or a
	// future action) emits an advisory reason. This closes the require_approval
	// fall-through — require_approval ALSO sets RequiresApproval below, which
	// becomes needs_approval in enterprise (the advisory then rides the early
	// return unused), but in community mode HITL is dropped, so without the
	// advisory a require_approval PII match would be a bare allow (#2965 R3).
	//
	// #2965: category membership is decided by the SHARED, prefix-based
	// sharedpolicy.IsPIIPolicyCategory — NOT a duplicate agent-local switch.
	// The old switch omitted pii-indonesia, so a matched-but-redacting KTP
	// policy set no obligation and fell through to a bare allow while the
	// policy still appeared in evaluated_policies. Deriving the redaction
	// obligation from resolved ACTION (not merely "is this PII?") also fixes
	// the sibling bug where warn/log postures silently emitted redact_pii
	// because the previous loop ignored match.Action entirely.
	for _, match := range result.MatchedPolicies {
		if result.Blocked || !sharedpolicy.IsPIIPolicyCategory(match.Category) {
			continue
		}
		switch match.Action {
		case sharedpolicy.ActionRedact:
			staticResult.RequiresRedaction = true
		default:
			staticResult.AdvisoryReasons = append(staticResult.AdvisoryReasons, advisoryPIIReason(match))
		}
	}

	// Issue #1081: Check for require_approval action in matched policies
	// This enables HITL enforcement for EU AI Act Article 14 and other compliance frameworks
	for _, match := range result.MatchedPolicies {
		if match.Action == sharedpolicy.ActionRequireApproval {
			staticResult.RequiresApproval = true
			break
		}
	}

	return staticResult
}

// advisoryPIIReason builds the governance reason surfaced when a PII policy
// MATCHED but its resolved action (warn/log) carries no redaction obligation.
// It exists so a matched policy is never a silent bare allow (#2965): the reason
// records which policy fired, its category, and that no redaction was applied.
func advisoryPIIReason(match sharedpolicy.PolicyMatch) string {
	return fmt.Sprintf("%s detected by policy %s (action=%s); no redaction applied",
		match.Category, match.PolicyID, match.Action)
}
