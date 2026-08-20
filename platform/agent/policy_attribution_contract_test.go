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

package agent

// Cross-plane writer/reader policy-attribution contract (#3243, v9.16.1).
//
// The 9.16.0 defect class: each audit writer records "which policy fired"
// under its own policy_details key (policy_ids / policy_names +
// policy_matches / singular policy_id), while the compliance exporters read
// ONE key -- so a whole plane's rows render a blank Policy cell on a
// regulator artifact, and nothing fails.
//
// These tests close the loop structurally: for each writer's details-map
// builder, the marshaled JSON is fed through
// sharedaudit.ExtractPolicyIdentity -- the Go mirror of the exporters' SQL
// fallback chain (the mirror itself is pinned to the SQL by
// TestPolicyIdentitySQLExpr_ReadsEveryKeyTheGoExtractorReads in
// platform/shared/audit). A writer that moves its identity under a key the
// exporters cannot resolve fails HERE, in CI, instead of shipping another
// blank column.
//
// The cowork writer's case lives in policy_attribution_contract_enterprise_test.go
// (its builder is enterprise-tagged); the HITL writer's case lives in
// ee/platform/agent/hitl (its builder is in the ee module).

import (
	"encoding/json"
	"testing"

	sharedaudit "axonflow/platform/shared/audit"
)

func mustExtract(t *testing.T, details map[string]interface{}) (string, string) {
	t.Helper()
	b, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("marshal details: %v", err)
	}
	return sharedaudit.ExtractPolicyIdentity(b)
}

// Decision plane (/api/v1/decide, also the plane every gateway adapter
// evaluates through): identity travels as policy_ids.
func TestPolicyAttributionContract_DecisionWriter(t *testing.T) {
	details := buildDecisionAuditDetails(
		"dec-1", "llm",
		[]string{"indonesia_pii_protection"},
		[]string{"Critical Indonesia PII detected"},
		nil, false, decisionAuditInput{},
	)
	id, _ := mustExtract(t, details)
	if id != "indonesia_pii_protection" {
		t.Fatalf("decision-plane identity unreadable by the exporters: got %q", id)
	}
}

// MCP decision plane (check-input dynamic blocks, check-output, tool errors):
// identity travels as policy_ids.
func TestPolicyAttributionContract_MCPDecisionWriter(t *testing.T) {
	details := buildMCPDecisionAuditDetails(
		"dec-2",
		[]string{"prompt-injection-block"},
		[]string{"blocked by policy"},
		nil, "", nil, "srv", "tool",
	)
	id, _ := mustExtract(t, details)
	if id != "prompt-injection-block" {
		t.Fatalf("MCP-decision-plane identity unreadable by the exporters: got %q", id)
	}
}

// MCP check-input static-block plane (writeExplainableAuditLog) -- the writer
// behind the design partner's blank-Policy report. Two shapes:
//   - the CURRENT (>= 9.16.1) shape, which now also writes policy_ids;
//   - the PRE-9.16.1 shape (no policy_ids), which must STILL resolve id AND
//     version through policy_matches -- that resolution is what heals the
//     partner's historical rows on re-export, with no data migration.
func TestPolicyAttributionContract_ExplainableWriter(t *testing.T) {
	matches := []RicherPolicyMatch{{
		PolicyID:   "sql-injection-block",
		PolicyName: "SQL Injection Block",
		RiskLevel:  "high",
		Version:    3,
	}}

	details := buildExplainableAuditDetails("dec-3", "blocked: sql injection", "high", matches, "")
	id, ver := mustExtract(t, details)
	if id != "sql-injection-block" || ver != "3" {
		t.Fatalf("check-input identity unreadable: got id=%q ver=%q", id, ver)
	}
	if _, ok := details["policy_ids"]; !ok {
		t.Fatalf("9.16.1 forward fix missing: writeExplainableAuditLog details carry no policy_ids")
	}

	// The pre-9.16.1 shape: identical minus policy_ids.
	delete(details, "policy_ids")
	id, ver = mustExtract(t, details)
	if id != "sql-injection-block" || ver != "3" {
		t.Fatalf("PRE-9.16.1 check-input rows would NOT heal on re-export: got id=%q ver=%q", id, ver)
	}
}

// A match with no PolicyID (dynamic-only match) must not produce an empty
// policy_ids entry, and the name must still resolve via policy_names.
func TestPolicyAttributionContract_ExplainableWriter_NameOnlyMatch(t *testing.T) {
	matches := []RicherPolicyMatch{{PolicyName: "Dynamic Rule"}}
	details := buildExplainableAuditDetails("dec-4", "blocked", "medium", matches, "")
	if _, ok := details["policy_ids"]; ok {
		t.Fatalf("policy_ids must be omitted when no match carries an id")
	}
	id, _ := mustExtract(t, details)
	if id != "Dynamic Rule" {
		t.Fatalf("name-only match unreadable: got %q", id)
	}
}

// Negative control: a details map that records NO identity (the pre-9.16.1
// cowork shape) must extract empty -- the exporters render the placeholder for
// it, and any non-empty extraction here would mean the chain fabricates
// attribution from a non-identity key.
func TestPolicyAttributionContract_NoIdentityExtractsEmpty(t *testing.T) {
	details := map[string]interface{}{
		"decision_id":     "dec-5",
		"source":          "cowork_otel",
		"plane":           "cowork",
		"event_name":      "user_prompt",
		"redacted_fields": []string{"statement"},
	}
	id, ver := mustExtract(t, details)
	if id != "" || ver != "" {
		t.Fatalf("fabricated attribution from a non-identity key: id=%q ver=%q", id, ver)
	}
}

// ---------------------------------------------------------------------------
// #3365: writer-side display-name stamping. Every canonical writer that
// stamps policy_ids must ALSO stamp policy_names when a name is resolvable
// (evaluation-time match map, or the builtin guard table for code-backed ids),
// so the shared reader / portal resolver stops rendering the
// "(name not recorded)" marker on freshly-written acted rows.
// ---------------------------------------------------------------------------

func TestPolicyAttributionContract_DecisionWriterStampsNames(t *testing.T) {
	details := buildDecisionAuditDetails(
		"dec-3", "llm",
		[]string{"sys_pii_indonesia_ktp", "circuit_breaker"},
		[]string{"matched"},
		nil, false,
		decisionAuditInput{policyNames: map[string]string{
			"sys_pii_indonesia_ktp": "Indonesian KTP Detection",
		}},
	)
	names, ok := details["policy_names"].([]string)
	if !ok || len(names) != 2 {
		t.Fatalf("decision writer must stamp policy_names for resolvable ids, got %v", details["policy_names"])
	}
	if names[0] != "Indonesian KTP Detection" || names[1] != "Circuit breaker guard" {
		t.Fatalf("threaded name + builtin guard name in policy_ids order, got %v", names)
	}
	// The identity contract is unchanged: exporters still resolve the id.
	id, _ := mustExtract(t, details)
	if id != "sys_pii_indonesia_ktp" {
		t.Fatalf("identity regressed: got %q", id)
	}
}

func TestPolicyAttributionContract_DecisionWriterNoNames_NoKey(t *testing.T) {
	// An id with no threaded name and no builtin entry stays honest: NO
	// policy_names key, so the reader renders ids + its explicit marker
	// rather than a fabricated name.
	details := buildDecisionAuditDetails(
		"dec-4", "llm",
		[]string{"tenant_custom_rule_without_threaded_name"},
		nil, nil, false, decisionAuditInput{},
	)
	if _, present := details["policy_names"]; present {
		t.Fatalf("writer must not fabricate a name for an unthreaded id: %v", details["policy_names"])
	}
}

func TestPolicyAttributionContract_MCPDecisionWriterStampsNames(t *testing.T) {
	details := buildMCPDecisionAuditDetails(
		"dec-5",
		[]string{"sys_pii_iban", "sqli_response_scan"},
		[]string{"blocked"},
		nil, "",
		map[string]string{"sys_pii_iban": "IBAN Detection"},
		"srv", "tool",
	)
	names, ok := details["policy_names"].([]string)
	if !ok || len(names) != 2 || names[0] != "IBAN Detection" || names[1] != "SQL injection response scan" {
		t.Fatalf("MCP decision writer must stamp names (threaded + builtin), got %v", details["policy_names"])
	}
	id, _ := mustExtract(t, details)
	if id != "sys_pii_iban" {
		t.Fatalf("identity regressed: got %q", id)
	}
}
