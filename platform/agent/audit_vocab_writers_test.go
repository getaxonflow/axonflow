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

// Convergence guards for the agent-plane audit writers (#2638 S-WRITERS).
//
// The per-plane verdict mappings themselves are already covered
// (TestCanonicalAuditVerdict, TestGatewayPreCheckAuditVerdict, the
// recordGatewayPreCheckAudit writer test). What #2638 ADDS, and what these tests
// pin, is that every agent-plane verdict CONSTANT now flows from the single
// shared vocabulary (platform/shared/audit) and is a member of the canonical set
// the migration-123 CHECK enforces — so a revert of a const swap to a divergent
// value (e.g. the legacy wire "allow"/"deny", which the CHECK rejects) fails
// here, BEFORE it can drop an audit row at the DB or mislabel the portal feed.
//
// Pure-function assertions — no Postgres — so they run in the standard agent
// unit job, complementing the real-Postgres migration + runtime-e2e tests.

import (
	"testing"

	sharedaudit "axonflow/platform/shared/audit"
)

// TestAgentAuditConsts_AreCanonical asserts every agent-plane audit verdict
// constant equals its shared-package source AND is a member of the canonical set
// the migration-123 CHECK enforces. If a const is reverted to a divergent value
// (e.g. mcpVerdictBlocked = "deny"), both the value mismatch and the
// non-canonical membership are reported.
func TestAgentAuditConsts_AreCanonical(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		// Decision plane (decision_handler.go AuditVerdict*).
		{"AuditVerdictAllowed", AuditVerdictAllowed, sharedaudit.DecisionAllowed},
		{"AuditVerdictBlocked", AuditVerdictBlocked, sharedaudit.DecisionBlocked},
		{"AuditVerdictRedacted", AuditVerdictRedacted, sharedaudit.DecisionRedacted},
		{"AuditVerdictError", AuditVerdictError, sharedaudit.DecisionError},
		// MCP plane (mcp_richer_context.go mcpVerdict*).
		{"mcpVerdictAllowed", mcpVerdictAllowed, sharedaudit.DecisionAllowed},
		{"mcpVerdictBlocked", mcpVerdictBlocked, sharedaudit.DecisionBlocked},
		{"mcpVerdictRedacted", mcpVerdictRedacted, sharedaudit.DecisionRedacted},
		{"mcpVerdictError", mcpVerdictError, sharedaudit.DecisionError},
		// Gateway plane (gateway_handlers.go gatewayAudit*).
		{"gatewayAuditAllowed", gatewayAuditAllowed, sharedaudit.DecisionAllowed},
		{"gatewayAuditBlocked", gatewayAuditBlocked, sharedaudit.DecisionBlocked},
		{"gatewayAuditRedacted", gatewayAuditRedacted, sharedaudit.DecisionRedacted},
		{"gatewayAuditNeedsApproval", gatewayAuditNeedsApproval, sharedaudit.DecisionNeedsApproval},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want canonical %q", c.name, c.got, c.want)
		}
		if !sharedaudit.IsCanonical(c.got) {
			t.Errorf("%s = %q is NOT in the canonical set (would be rejected by the migration-123 CHECK)", c.name, c.got)
		}
	}
}

// TestDecisionWireConstsUnchanged guards the WIRE verdict contract the SDK/PEP
// depend on (decision_handler.go:63-75). #2638 must NOT collapse these into the
// audit vocabulary: "allow"/"deny" are the OpenAPI enum the PEP enforces, value-
// distinct from the canonical audit "allowed"/"blocked". A revert that aliased a
// wire const onto an audit const would silently break every PEP in the field.
func TestDecisionWireConstsUnchanged(t *testing.T) {
	if VerdictAllow != "allow" {
		t.Errorf("VerdictAllow = %q, want \"allow\" (wire contract)", VerdictAllow)
	}
	if VerdictDeny != "deny" {
		t.Errorf("VerdictDeny = %q, want \"deny\" (wire contract)", VerdictDeny)
	}
	// The wire tokens must NOT be canonical audit values: a refactor that aliased
	// a wire const onto an audit const (e.g. VerdictAllow = DecisionAllowed) would
	// make it canonical here AND silently break every field PEP/SDK.
	if sharedaudit.IsCanonical(VerdictAllow) || sharedaudit.IsCanonical(VerdictDeny) {
		t.Fatalf("WIRE verdict collapsed onto the canonical AUDIT vocabulary (allow=%q deny=%q) — breaks the PEP/SDK contract", VerdictAllow, VerdictDeny)
	}
}
