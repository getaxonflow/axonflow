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

	// Set RequiresRedaction based on matched PII policies that aren't blocking
	// (e.g., when action is "redact" instead of "block")
	for _, match := range result.MatchedPolicies {
		if !result.Blocked && isPIICategory(match.Category) {
			staticResult.RequiresRedaction = true
			break
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

// isPIICategory returns true if the category is a PII-related category.
func isPIICategory(category sharedpolicy.PolicyCategory) bool {
	switch category {
	case sharedpolicy.CategoryPIIGlobal,
		sharedpolicy.CategoryPIIUS,
		sharedpolicy.CategoryPIIIndia,
		sharedpolicy.CategoryPIIEU,
		sharedpolicy.CategoryPIISingapore:
		return true
	default:
		return false
	}
}
