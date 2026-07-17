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

import "regexp"

// PolicyPattern represents a static policy rule
type PolicyPattern struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	PatternStr  string
	Severity    string // "low", "medium", "high", "critical"
	Description string
	Enabled     bool
}

// StaticPolicyResult contains the result of static policy evaluation.
// Used by both the unified shared engine (via convertSharedResultToStatic)
// and handler response types.
type StaticPolicyResult struct {
	Blocked           bool
	Reason            string
	TriggeredPolicies []string
	ChecksPerformed   []string
	ProcessingTimeMs  int64
	Severity          string
	RequiresRedaction bool // True if PII detected and should be redacted (Issue #891)
	RequiresApproval  bool // True if HITL approval is required (Issue #1081 - EU AI Act Article 14)
	EvaluationError   bool // True when Blocked is a fail-closed availability failure (could-not-scan), not a policy verdict (#2862)
	// AdvisoryReasons carries governance reasons for PII policies that MATCHED
	// but resolved to a non-blocking, non-redacting action (warn/log). They emit
	// no obligation, but a matched policy must never be a silent bare allow
	// (#2965) — these surface as verdict reasons so the match is self-documenting.
	AdvisoryReasons []string
}
