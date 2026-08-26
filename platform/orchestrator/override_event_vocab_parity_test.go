// Copyright 2026 AxonFlow
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
	"strings"
	"testing"

	sharedaudit "axonflow/platform/shared/audit"
)

// The override-event request_type vocabulary exists TWICE by necessity:
// IsOverrideEventType here, and audit.OverrideEventRequestTypes in
// platform/shared, which is a leaf package and cannot import this one. This
// test is what keeps them one vocabulary.
//
// It is not decorative. audit.OverrideEventExclusionSQL is what keeps override
// rows off "Top Triggered Policies" on BOTH planes (#3426 / #3438 R3): an
// override_used row names the policy the override BYPASSED, so a missing entry
// here promotes the one policy that was not enforced to the top of a
// regulator-facing table. A fifth lifecycle event added to IsOverrideEventType
// and not to the shared list would reintroduce exactly that, silently.
func TestOverrideEventRequestTypesMatchOrchestrator(t *testing.T) {
	// Anti-vacuity: an empty shared list would make every loop below pass.
	if len(sharedaudit.OverrideEventRequestTypes) == 0 {
		t.Fatal("audit.OverrideEventRequestTypes is empty; every assertion below would be vacuous")
	}

	// Every shared entry must be an override event by the orchestrator's own
	// predicate.
	for _, rt := range sharedaudit.OverrideEventRequestTypes {
		if !IsOverrideEventType(rt) {
			t.Errorf("audit.OverrideEventRequestTypes has %q, which IsOverrideEventType rejects", rt)
		}
		if !sharedaudit.IsOverrideEventRequestType(rt) {
			t.Errorf("audit.IsOverrideEventRequestType rejects its own vocabulary entry %q", rt)
		}
	}

	// And the other direction: every constant the orchestrator writes must be in
	// the shared list. This is the direction that actually breaks the aggregate.
	for _, rt := range []string{
		AuditEventOverrideCreated,
		AuditEventOverrideUsed,
		AuditEventOverrideExpired,
		AuditEventOverrideRevoked,
	} {
		if !sharedaudit.IsOverrideEventRequestType(rt) {
			t.Errorf("orchestrator writes request_type %q, which audit.OverrideEventRequestTypes omits; "+
				"override rows on that event would be counted as triggered policies", rt)
		}
	}

	// The MCP plane's writer (platform/agent writeOverrideUsedEvent) stamps this
	// literal directly rather than importing either constant, and it is the row
	// the policy_decision-keyed exclusion used to miss entirely. Pin the string.
	if !sharedaudit.IsOverrideEventRequestType("override_used") {
		t.Error(`"override_used" (the literal platform/agent/mcp_richer_context.go stamps) is not an override event type`)
	}

	// The generated SQL must actually mention every event type; a builder that
	// silently emitted a shorter list would pass everything above.
	sql := sharedaudit.OverrideEventExclusionSQL("request_type")
	for _, rt := range sharedaudit.OverrideEventRequestTypes {
		if !strings.Contains(sql, "'"+rt+"'") {
			t.Errorf("OverrideEventExclusionSQL does not exclude %q: %s", rt, sql)
		}
	}
	if !strings.HasPrefix(sql, "request_type <> ALL (") {
		t.Errorf("OverrideEventExclusionSQL keyed on the wrong column or operator: %s", sql)
	}

	// And the aggregation must consume it. The whole point of the shared list is
	// that TopPoliciesQuery excludes on request_type, not on policy_decision
	// alone; that was the half-applied fix.
	q := sharedaudit.TopPoliciesQuery("tenant_id = $1", "$2")
	if !strings.Contains(q, sql) {
		t.Errorf("TopPoliciesQuery does not carry the request_type override exclusion:\n%s", q)
	}
	if !strings.Contains(q, "policy_decision <> '"+sharedaudit.DecisionOverrideLifecycle+"'") {
		t.Errorf("TopPoliciesQuery dropped the policy_decision exclusion its siblings share:\n%s", q)
	}
}
