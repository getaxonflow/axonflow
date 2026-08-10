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

package audit

import (
	"strings"
	"testing"
)

// policyIdentityParityVectors is the SINGLE vector table for the extraction
// chain, consumed by two tests: TestExtractPolicyIdentity_FallbackChain runs
// every vector through the Go mirror, and the real-Postgres parity test
// (policy_identity_realpg_test.go) runs the SAME vectors through the actual
// SQL expressions on a throwaway postgres:16 and asserts both surfaces agree.
// Adding a shape here pins it on both sides at once.
type policyIdentityVector struct {
	name         string
	details      string
	wantIdentity string
	wantVersion  string
}

var policyIdentityParityVectors = []policyIdentityVector{
	{
		name:         "policy_ids array wins",
		details:      `{"policy_ids":["indonesia_pii_protection","other"],"policy_id":"loser","policy_names":["Loser Name"]}`,
		wantIdentity: "indonesia_pii_protection",
	},
	{
		name:         "EMPTY policy_ids array falls through to policy_id",
		details:      `{"policy_ids":[],"policy_id":"hitl-policy-7"}`,
		wantIdentity: "hitl-policy-7",
	},
	{
		name:         "null policy_ids falls through",
		details:      `{"policy_ids":null,"policy_id":"hitl-policy-7"}`,
		wantIdentity: "hitl-policy-7",
	},
	{
		name:         "absent policy_ids falls through to singular policy_id",
		details:      `{"policy_id":"hitl-policy-7","policy_name":"HITL Gate"}`,
		wantIdentity: "hitl-policy-7",
	},
	{
		name:         "policy_name alone (singular) resolves last",
		details:      `{"policy_name":"HITL Gate"}`,
		wantIdentity: "HITL Gate",
	},
	{
		// The partner-reported class: writeExplainableAuditLog pre-9.16.1
		// wrote policy_matches + policy_names + policy_versions but never
		// policy_ids. These rows must heal on re-export, id + version.
		name:         "pre-9.16.1 check-input shape resolves policy_matches id and version",
		details:      `{"decision_id":"d1","reason":"blocked","policy_names":["SQL Injection Block"],"policy_matches":[{"policy_id":"sql-injection-block","policy_name":"SQL Injection Block","policy_version":3,"allow_override":false}],"policy_versions":{"sql-injection-block":3}}`,
		wantIdentity: "sql-injection-block",
		wantVersion:  "3",
	},
	{
		name:         "policy_names as JSON array",
		details:      `{"policy_names":["PII Basic","Second"]}`,
		wantIdentity: "PII Basic",
	},
	{
		// The legacy CSV-string shape the portal reader at
		// orchestrator/audit_logger.go matches with LIKE. Reading this as
		// a JSON array yields NULL/blank, which is failure mode (ii) in
		// the workstream brief.
		name:         "policy_names as legacy CSV STRING takes the first element",
		details:      `{"policy_names":"PII Basic, Prompt Injection"}`,
		wantIdentity: "PII Basic",
	},
	{
		name:         "cowork 9.16.1 capture shape resolves id and ruleset version",
		details:      `{"source":"cowork_otel","policy_ids":["sys_pii_email"],"policy_categories":["pii-global"],"ruleset_version":"9.16.1","reason":"PII redaction: email"}`,
		wantIdentity: "sys_pii_email",
		wantVersion:  "9.16.1",
	},
	{
		name:         "no identity under any key resolves empty",
		details:      `{"decision_id":"x","source":"cowork_otel","redacted_fields":["statement"]}`,
		wantIdentity: "",
	},
	{
		name:         "empty strings under every key resolve empty",
		details:      `{"policy_ids":[""],"policy_id":"","policy_names":"","policy_name":""}`,
		wantIdentity: "",
	},
	{
		name:         "malformed json resolves empty, never panics",
		details:      `{"policy_ids":`,
		wantIdentity: "",
	},
	// Semantic-parity vectors (R3 finding 2): shapes where unguarded
	// Postgres operators and a naive Go reading disagree. Both sides are
	// now type-guarded to resolve these identically.
	{
		name:         "policy_ids as a bare scalar string does NOT resolve (array-guarded on both sides)",
		details:      `{"policy_ids":"abc","policy_id":"real"}`,
		wantIdentity: "real",
	},
	{
		// R3 round 2 MEDIUM 1, confirmed on PG16 pre-fix: the scalar
		// policy_ids fails the guarded identity arm (identity comes from
		// policy_id), but an unguarded version key-derivation read the
		// scalar through the jsonb scalar-as-array quirk and paired
		// ANOTHER policy's version with the resolved identity, rendering
		// "real (v9)". The version must be keyed by the RESOLVED id.
		name:         "scalar policy_ids must not key another policy's version onto the resolved identity",
		details:      `{"policy_ids":"p2","policy_id":"real","policy_versions":{"p2":"9"}}`,
		wantIdentity: "real",
		wantVersion:  "",
	},
	{
		// R3 round 2 MEDIUM 2, confirmed on PG16 pre-fix: container-level
		// guards alone let an OBJECT element render as raw JSON text
		// ('{"a": 1}') in a regulator Policy cell. Elements are
		// string-guarded on both surfaces; malformed rows resolve nothing
		// and take the placeholder path.
		name:         "object element under policy_ids never renders raw JSON as a policy",
		details:      `{"policy_ids":[{"a":1}]}`,
		wantIdentity: "",
	},
	{
		name:         "array element under policy_ids never renders raw JSON as a policy",
		details:      `{"policy_ids":[[1,2]]}`,
		wantIdentity: "",
	},
	{
		name:         "object element under policy_names never renders raw JSON as a policy",
		details:      `{"policy_names":[{"a":1}]}`,
		wantIdentity: "",
	},
	{
		name:         "object-valued policy_matches[0].policy_id never renders raw JSON as a policy",
		details:      `{"policy_matches":[{"policy_id":{"x":1},"policy_version":3}]}`,
		wantIdentity: "",
	},
	{
		name:         "non-string elements do not resolve (identity arms are string-only on both sides)",
		details:      `{"policy_ids":[42]}`,
		wantIdentity: "",
	},
	{
		name:         "numeric singular policy_id does not resolve (string-only, no per-surface numeric rendering)",
		details:      `{"policy_id":7}`,
		wantIdentity: "",
	},
	{
		name:         "policy_names as a JSON object never becomes raw JSON text on the artifact",
		details:      `{"policy_names":{"a":1}}`,
		wantIdentity: "",
	},
	{
		name:         "version pairs with the RESOLVED id via the policy_versions map, not blindly with matches[0]",
		details:      `{"policy_ids":["p2"],"policy_matches":[{"policy_name":"Dyn","policy_version":3},{"policy_id":"p2","policy_version":7}],"policy_versions":{"p2":7}}`,
		wantIdentity: "p2",
		wantVersion:  "7",
	},
	{
		name:         "a match version of 0 is the writer's omitempty zero, not a version",
		details:      `{"policy_matches":[{"policy_id":"p1","policy_version":0}]}`,
		wantIdentity: "p1",
	},
	{
		name:         "a version with no identity anywhere resolves NO version (never beside a placeholder)",
		details:      `{"policy_matches":[{"policy_version":3}]}`,
		wantIdentity: "",
	},
	{
		name:         "an affirmative no-policy marker is NOT an identity",
		details:      `{"policy_attribution":"user_decision","reason":"cowork tool_decision: Bash rejected"}`,
		wantIdentity: "",
	},
	{
		// The inline match version pairs only with ITS OWN match: identity
		// resolved from the singular policy_id must not adopt an id-less
		// match's version.
		name:         "an id-less match's inline version never pairs with a singular-scalar identity",
		details:      `{"policy_id":"real","policy_matches":[{"policy_name":"Dyn","policy_version":3}]}`,
		wantIdentity: "real",
		wantVersion:  "",
	},
	{
		// ruleset_version pairs only with a policy_ids-resolved identity
		// (the key the cowork writer stamps it alongside).
		name:         "ruleset_version never pairs with an identity that did not come from policy_ids",
		details:      `{"policy_id":"real","ruleset_version":"9.16.1"}`,
		wantIdentity: "real",
		wantVersion:  "",
	},
}

func TestExtractPolicyIdentity_FallbackChain(t *testing.T) {
	for _, tc := range policyIdentityParityVectors {
		t.Run(tc.name, func(t *testing.T) {
			id, ver := ExtractPolicyIdentity([]byte(tc.details))
			if id != tc.wantIdentity {
				t.Errorf("identity = %q, want %q", id, tc.wantIdentity)
			}
			if ver != tc.wantVersion {
				t.Errorf("version = %q, want %q", ver, tc.wantVersion)
			}
		})
	}
}

// TestPolicyIdentitySQLExpr_ReadsEveryKeyTheGoExtractorReads pins the SQL
// expression to the same key set the Go extractor resolves, via the shared
// constants. The Go extractor is what the cross-plane contract tests execute;
// this test is what makes those contract tests speak for the exporters' SQL. A
// key added to one side without the other fails here.
func TestPolicyIdentitySQLExpr_ReadsEveryKeyTheGoExtractorReads(t *testing.T) {
	expr := PolicyIdentitySQLExpr("policy_details")
	for _, key := range []string{
		policyDetailKeyIDs, policyDetailKeyMatches, policyDetailKeyNames,
		policyDetailKeyID, policyDetailKeyName,
	} {
		if !strings.Contains(expr, "'"+key+"'") {
			t.Errorf("PolicyIdentitySQLExpr does not read %q:\n%s", key, expr)
		}
	}
	// The legacy CSV-string shape must be handled by type, not assumed away.
	if !strings.Contains(expr, "jsonb_typeof") || !strings.Contains(expr, "split_part") {
		t.Errorf("PolicyIdentitySQLExpr must branch on jsonb_typeof and split the legacy CSV string:\n%s", expr)
	}
	// The exporters embed this inside COALESCE(...) AS <alias> selects; a NULL
	// (rather than '') would change their scan behavior.
	if !strings.HasPrefix(strings.TrimSpace(expr), "COALESCE(") || !strings.Contains(expr, "'')") {
		t.Errorf("PolicyIdentitySQLExpr must resolve to '' when nothing matches:\n%s", expr)
	}

	vexpr := PolicyVersionSQLExpr("policy_details")
	if !strings.Contains(vexpr, "'"+policyDetailKeyMatches+"'") || !strings.Contains(vexpr, "'"+policyMatchKeyVersion+"'") {
		t.Errorf("PolicyVersionSQLExpr must read %s[0].%s:\n%s", policyDetailKeyMatches, policyMatchKeyVersion, vexpr)
	}
	if !strings.Contains(vexpr, "ruleset_version") {
		t.Errorf("PolicyVersionSQLExpr must read ruleset_version:\n%s", vexpr)
	}
}

func TestPolicyOrPlaceholder(t *testing.T) {
	cases := []struct {
		identity, verdict, attribution, want string
	}{
		{"sys_pii_email", "redacted", "", "sys_pii_email"},
		{"", "blocked", "", PolicyNotRecordedPlaceholder},
		{"", "redacted", "", PolicyNotRecordedPlaceholder},
		{"", "needs_approval", "", PolicyNotRecordedPlaceholder},
		// Legacy verdict spellings normalize before the acted-set check.
		{"", "deny", "", PolicyNotRecordedPlaceholder},
		// A row that did not act must NOT claim "not recorded": nothing fired.
		{"", "allowed", "", ""},
		{"", "error", "", ""},
		{"", "", "", ""},
		// A writer's AFFIRMATIVE no-policy statement beats the placeholder: a
		// post-9.16.1 user rejection / unnamed gate must never render a false
		// "(pre-9.16.1)" era claim or imply a policy fired (R3 finding 1).
		{"", "blocked", PolicyAttributionUserDecision, PolicyLabelUserDecision},
		{"", "blocked", PolicyAttributionUnnamedGate, PolicyLabelUnnamedGate},
		// A recorded identity always beats the marker.
		{"p1", "blocked", PolicyAttributionUserDecision, "p1"},
		// An unrecognized marker is not an affirmative statement this reader
		// understands: fall through to the placeholder on an acted row.
		{"", "blocked", "mystery_marker", PolicyNotRecordedPlaceholder},
		// The marker is an affirmative statement independent of the verdict:
		// "no policy fired" is as true on an allowed row as on a blocked one.
		{"", "allowed", PolicyAttributionUserDecision, PolicyLabelUserDecision},
	}
	for _, tc := range cases {
		if got := PolicyOrPlaceholder(tc.identity, tc.verdict, tc.attribution); got != tc.want {
			t.Errorf("PolicyOrPlaceholder(%q,%q,%q) = %q, want %q", tc.identity, tc.verdict, tc.attribution, got, tc.want)
		}
	}
}

func TestFormatPolicyWithVersion(t *testing.T) {
	if got := FormatPolicyWithVersion("p1", "3"); got != "p1 (v3)" {
		t.Errorf("got %q", got)
	}
	if got := FormatPolicyWithVersion("p1", ""); got != "p1" {
		t.Errorf("got %q", got)
	}
	if got := FormatPolicyWithVersion("", "3"); got != "" {
		t.Errorf("got %q", got)
	}
	if got := FormatPolicyWithVersion(PolicyNotRecordedPlaceholder, "3"); got != PolicyNotRecordedPlaceholder {
		t.Errorf("placeholder must never carry a version, got %q", got)
	}
	if got := FormatPolicyWithVersion(PolicyLabelUserDecision, "3"); got != PolicyLabelUserDecision {
		t.Errorf("a no-policy label must never carry a version, got %q", got)
	}
	if got := FormatPolicyWithVersion(PolicyLabelUnnamedGate, "3"); got != PolicyLabelUnnamedGate {
		t.Errorf("a no-policy label must never carry a version, got %q", got)
	}
}
