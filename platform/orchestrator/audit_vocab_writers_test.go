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

// Red-on-revert guards for the orchestrator-plane audit writers (#2638 S-WRITERS).
//
// Pins every orchestrator-plane audit_logs.policy_decision value to the shared
// canonical vocabulary (platform/shared/audit) so a revert to a divergent
// spelling — in particular the historical off-set "pending_approval" the
// workflow gate emitted, which the migration-123 CHECK rejects — fails here in
// the standard orchestrator unit job, before it can drop an audit row at the DB.

import (
	"testing"

	sharedaudit "axonflow/platform/shared/audit"
)

// TestWorkflowAuditDecision is THE guard for the locked pending_approval fix:
// require_approval MUST map to the canonical needs_approval, never the off-set
// "pending_approval" (which is not canonical and would fail the migration-123
// CHECK, silently losing the step_gate audit row).
func TestWorkflowAuditDecision(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"block", sharedaudit.DecisionBlocked},
		{"require_approval", sharedaudit.DecisionNeedsApproval},
		{"allow", sharedaudit.DecisionAllowed}, // common case → default
		{"", sharedaudit.DecisionAllowed},      // empty/unknown → default allowed (pre-existing)
		{"something_else", sharedaudit.DecisionAllowed},
	}
	for _, c := range cases {
		got := workflowAuditDecision(c.in)
		if got != c.want {
			t.Errorf("workflowAuditDecision(%q) = %q, want %q", c.in, got, c.want)
		}
		if !sharedaudit.IsCanonical(got) {
			t.Errorf("workflowAuditDecision(%q) = %q is NOT canonical (would be rejected by the migration-123 CHECK)", c.in, got)
		}
	}
	// Explicit regression assertion for the exact bug this session fixes.
	if got := workflowAuditDecision("require_approval"); got == "pending_approval" {
		t.Fatal("workflowAuditDecision regressed to the off-set 'pending_approval' (rejected by the migration-123 CHECK)")
	}
}

// TestResponseVerdictConsts_AreCanonical pins the response-plane verdicts
// (response_processor.go responseVerdict*) onto the shared vocabulary.
func TestResponseVerdictConsts_AreCanonical(t *testing.T) {
	cases := []struct {
		name, got, want string
	}{
		{"responseVerdictAllowed", responseVerdictAllowed, sharedaudit.DecisionAllowed},
		{"responseVerdictRedacted", responseVerdictRedacted, sharedaudit.DecisionRedacted},
		{"responseVerdictBlocked", responseVerdictBlocked, sharedaudit.DecisionBlocked},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want canonical %q", c.name, c.got, c.want)
		}
		if !sharedaudit.IsCanonical(c.got) {
			t.Errorf("%s = %q is not in the canonical set", c.name, c.got)
		}
	}
}

// TestOverrideAuditMarkerIsRecognized asserts the override lifecycle writer uses
// the recognized non-verdict marker, which must be in the migration-123 CHECK
// set (it is NOT a canonical verdict, so IsCanonical is intentionally false, but
// Normalize must pass it through unchanged rather than fail-safe it to error).
func TestOverrideAuditMarkerIsRecognized(t *testing.T) {
	if sharedaudit.DecisionOverrideLifecycle != "override_lifecycle" {
		t.Errorf("DecisionOverrideLifecycle = %q, want \"override_lifecycle\"", sharedaudit.DecisionOverrideLifecycle)
	}
	if sharedaudit.IsCanonical(sharedaudit.DecisionOverrideLifecycle) {
		t.Error("override_lifecycle must NOT be a canonical verdict (it is a non-verdict marker)")
	}
	if got := sharedaudit.Normalize(sharedaudit.DecisionOverrideLifecycle); got != sharedaudit.DecisionOverrideLifecycle {
		t.Errorf("Normalize(override_lifecycle) = %q, want passthrough %q", got, sharedaudit.DecisionOverrideLifecycle)
	}
	if !sharedaudit.IsKnown(sharedaudit.DecisionOverrideLifecycle) {
		t.Error("override_lifecycle must be a KNOWN value so it is not treated as an unrecognized writer spelling")
	}
}
