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
	// wantIdentities is the FULL set PolicyIdentitySetSQLExpr /
	// ExtractPolicyIdentities must resolve (#3426). Leave it nil for a vector
	// whose set is just its scalar identity: wantSet() then derives
	// [wantIdentity], or the empty set when no identity resolves. Spelling it
	// out is therefore only required where the widened reader sees MORE than
	// the scalar one, which is exactly the property #3426 turns on.
	wantIdentities []string
}

// wantSet is the expected full identity set for a vector.
func (v policyIdentityVector) wantSet() []string {
	if v.wantIdentities != nil {
		return v.wantIdentities
	}
	if v.wantIdentity == "" {
		return nil
	}
	return []string{v.wantIdentity}
}

var policyIdentityParityVectors = []policyIdentityVector{
	{
		name:         "policy_ids array wins",
		details:      `{"policy_ids":["indonesia_pii_protection","other"],"policy_id":"loser","policy_names":["Loser Name"]}`,
		wantIdentity: "indonesia_pii_protection",
		// The whole ids array, and NOT the names beside it: one arm supplies
		// the whole set, so a row cannot be counted once per id AND once per
		// name.
		wantIdentities: []string{"indonesia_pii_protection", "other"},
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
		// policy_matches wins over the policy_names beside it, so the set is
		// the match ids, not the display names.
		wantIdentities: []string{"sql-injection-block"},
	},
	{
		name:           "policy_names as JSON array",
		details:        `{"policy_names":["PII Basic","Second"]}`,
		wantIdentity:   "PII Basic",
		wantIdentities: []string{"PII Basic", "Second"},
	},
	{
		// The legacy CSV-string shape the portal reader at
		// orchestrator/audit_logger.go matches with LIKE. Reading this as
		// a JSON array yields NULL/blank, which is failure mode (ii) in
		// the workstream brief.
		name:         "policy_names as legacy CSV STRING takes the first element",
		details:      `{"policy_names":"PII Basic, Prompt Injection"}`,
		wantIdentity: "PII Basic",
		// The CSV arm expands to EVERY element, space-trimmed the way btrim
		// trims, not just the split_part(...,1) the scalar chain takes.
		wantIdentities: []string{"PII Basic", "Prompt Injection"},
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
		// policy_ids is the winning arm; the match ids are NOT appended.
		wantIdentities: []string{"p2"},
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

	// ---------------------------------------------------------------------
	// #3426 set-resolution vectors. The scalar chain answers "which policy do
	// I print in this cell"; the set answers "which policies fired", which is
	// what the top-policies aggregation groups on. Every vector below pins
	// BOTH, so the set can never select a different ARM than the scalar and
	// can never disagree with it on the first element.
	// ---------------------------------------------------------------------
	{
		// THE DEFECT SHAPE. A decide-plane row through the FinCrime seam:
		// several controls fire, their ids are appended to policy_ids and
		// their display names to policy_names. The pre-#3426 aggregation read
		// the SINGULAR policy_name, which is absent here, so the whole row was
		// excluded before grouping. Resolving only policy_ids[0] would count
		// one of the three and under-report the other two by the same
		// mechanism, so the set is all three.
		name:           "fincrime seam row: every appended control id is in the set",
		details:        `{"policy_ids":["fincrime_structuring","fincrime_high_risk_geo","fincrime_ml_risk_score"],"policy_names":["Structuring / Smurfing","High-Risk Jurisdiction","FinCrime ML Fraud Score"],"policy_versions":{"fincrime_structuring":1},"risk_score":0.91}`,
		wantIdentity:   "fincrime_structuring",
		wantVersion:    "1",
		wantIdentities: []string{"fincrime_structuring", "fincrime_high_risk_geo", "fincrime_ml_risk_score"},
	},
	{
		// The HITL exception the aggregation used to mistake for the universal
		// convention. It must keep resolving: the fix widens the reader, it
		// does not swap one exclusion for another.
		name:           "HITL singular-scalar row stays counted",
		details:        `{"workflow_id":"wf-1","step_id":"s2","action":"approved","policy_id":"hv-wire-oversight","policy_name":"High-Value Wire Transfer Oversight"}`,
		wantIdentity:   "hv-wire-oversight",
		wantIdentities: []string{"hv-wire-oversight"},
	},
	{
		// A row listing the same policy twice triggered it once. Without the
		// first-occurrence collapse a LATERAL unnest would multiply the row
		// into the aggregate.
		name:           "repeats within an arm collapse on first occurrence",
		details:        `{"policy_ids":["dup","other","dup"]}`,
		wantIdentity:   "dup",
		wantIdentities: []string{"dup", "other"},
	},
	{
		name:           "legacy CSV names collapse repeats too",
		details:        `{"policy_names":"A, B, A"}`,
		wantIdentity:   "A",
		wantIdentities: []string{"A", "B"},
	},
	{
		// The arm ACTIVATES (element 0 is a string) and then filters the
		// non-string elements out, exactly like the scalar chain's element
		// guard would if it looked past index 0.
		name:           "non-string elements after a valid first are dropped, not resolved",
		details:        `{"policy_ids":["ok",42,{"a":1},"two"]}`,
		wantIdentity:   "ok",
		wantIdentities: []string{"ok", "two"},
	},
	{
		// ARM SELECTION PARITY. Element 0 is not a string, so the scalar chain
		// skips the policy_ids arm entirely and resolves the singular scalar.
		// The set must skip the SAME arm: expanding policy_ids here would
		// resolve "later", a policy the printed cell beside it never names.
		name:           "an unresolvable first element skips the WHOLE arm on both surfaces",
		details:        `{"policy_ids":[42,"later"],"policy_id":"real"}`,
		wantIdentity:   "real",
		wantIdentities: []string{"real"},
	},
	{
		name:           "an EMPTY first element skips the whole arm on both surfaces",
		details:        `{"policy_ids":["","b"],"policy_id":"real"}`,
		wantIdentity:   "real",
		wantIdentities: []string{"real"},
	},
	{
		// The CSV twin of the above: split_part(...,1) is empty, so the scalar
		// chain falls through and the set must fall through with it.
		name:           "a leading empty CSV element skips the names arm on both surfaces",
		details:        `{"policy_names":", B","policy_id":"real"}`,
		wantIdentity:   "real",
		wantIdentities: []string{"real"},
	},
	{
		name:           "every policy_matches entry that carries an id is in the set",
		details:        `{"policy_matches":[{"policy_id":"a","policy_version":2},{"policy_id":"b"},{"policy_name":"id-less"},{"policy_id":""}]}`,
		wantIdentity:   "a",
		wantVersion:    "2",
		wantIdentities: []string{"a", "b"},
	},
	{
		name:           "a bare scalar policy_ids resolves NO set (array-guarded, matching the scalar chain)",
		details:        `{"policy_ids":"abc"}`,
		wantIdentity:   "",
		wantIdentities: nil,
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

// TestExtractPolicyIdentities_SetResolution runs every parity vector through
// the widened Go mirror (#3426) and additionally pins the two invariants that
// let the scalar and the set chains coexist without drifting:
//
//	SAME ARM        the set never contains a value the scalar chain could not
//	                have selected, because both pick the same arm;
//	SAME FIRST      set[0] IS the scalar identity whenever the set is non-empty.
//
// The second invariant is asserted, never assumed: it is what makes the
// aggregation's chips reconcile with the Policy column rendered beside them.
func TestExtractPolicyIdentities_SetResolution(t *testing.T) {
	for _, tc := range policyIdentityParityVectors {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractPolicyIdentities([]byte(tc.details))
			want := tc.wantSet()
			if len(got) != len(want) {
				t.Fatalf("identities = %q, want %q", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("identities = %q, want %q", got, want)
				}
			}
			scalar, _ := ExtractPolicyIdentity([]byte(tc.details))
			if len(got) == 0 {
				if scalar != "" {
					t.Errorf("empty identity set but scalar chain resolved %q", scalar)
				}
				return
			}
			if got[0] != scalar {
				t.Errorf("set[0] = %q but the scalar chain resolves %q; the aggregation would name a policy the Policy column never shows", got[0], scalar)
			}
			// No duplicates: a policy listed twice on one row triggered once.
			seen := map[string]bool{}
			for _, s := range got {
				if seen[s] {
					t.Errorf("duplicate %q in identity set %q", s, got)
				}
				seen[s] = true
			}
		})
	}
}

// TestPolicyIdentitySetSQLExpr_MirrorsTheScalarArms pins the structural
// properties that the real-Postgres parity test then confirms behaviourally.
func TestPolicyIdentitySetSQLExpr_MirrorsTheScalarArms(t *testing.T) {
	expr := PolicyIdentitySetSQLExpr("policy_details")
	for _, key := range []string{
		policyDetailKeyIDs, policyDetailKeyMatches, policyDetailKeyNames,
		policyDetailKeyID, policyDetailKeyName,
	} {
		if !strings.Contains(expr, "'"+key+"'") {
			t.Errorf("PolicyIdentitySetSQLExpr does not read %q:\n%s", key, expr)
		}
	}
	// EVERY arm of the scalar chain must appear verbatim as the set's
	// activation guard. This is the anti-drift mechanism: a new arm, or an
	// edited guard, cannot land on one surface only.
	for i, arm := range policyIdentityArmsSQL("policy_details") {
		if !strings.Contains(expr, arm) {
			t.Errorf("set arm %d is not gated on the scalar chain's arm; the two can select different keys:\n%s", i, arm)
		}
	}
	// Empty array, never NULL: unnest(NULL) yields no rows either, but a NULL
	// would silently swallow a COALESCE bug instead of failing loudly.
	if !strings.Contains(expr, "ARRAY[]::text[]") {
		t.Errorf("PolicyIdentitySetSQLExpr must fall back to an empty text[]:\n%s", expr)
	}
	// jsonb_array_elements RAISES on a non-array; every call must be container
	// guarded or one malformed historical row fails the whole aggregation.
	for _, chunk := range strings.Split(expr, "jsonb_array_elements(")[1:] {
		if !strings.HasPrefix(chunk, "CASE WHEN jsonb_typeof(") {
			t.Errorf("unguarded jsonb_array_elements call would RAISE on a non-array row:\n%.120s", chunk)
		}
	}
}

// TestTopPoliciesQuery_UsesTheSharedChain pins the aggregation both the portal
// tile and the Compliance Report export render (#3426).
func TestTopPoliciesQuery_UsesTheSharedChain(t *testing.T) {
	q := TopPoliciesQuery("tenant_id = $1", "$2")

	// THE REGRESSION. Grouping or filtering on the singular scalar is what
	// excluded every array-stamping plane; the singular key may only be
	// reachable THROUGH the shared chain's last arm.
	if strings.Contains(q, "GROUP BY policy_details") || strings.Contains(q, "policy_details->>'policy_name' IS NOT NULL") {
		t.Errorf("top-policies query reads the singular policy_name directly again (#3426):\n%s", q)
	}
	if !strings.Contains(q, PolicyIdentitySetSQLExpr("policy_details")) {
		t.Errorf("top-policies query does not resolve identity through the shared chain:\n%s", q)
	}
	if !strings.Contains(q, "CROSS JOIN LATERAL unnest(") {
		t.Errorf("top-policies query must expand EVERY identity on the row, not just the first:\n%s", q)
	}
	// The caller's predicate and its blocked-spellings placeholder must both
	// land, and the predicate must be PARENTHESISED: appending " AND ..." to a
	// bare predicate binds tighter than a top-level OR in it, which would widen
	// the aggregation past the rows the caller scoped it to.
	if !strings.Contains(q, "WHERE (tenant_id = $1") || !strings.Contains(q, "ANY($2)") {
		t.Errorf("top-policies query lost or failed to parenthesise the caller's predicate:\n%s", q)
	}
	if or := TopPoliciesQuery("a = 1 OR b = 2", "$2"); !strings.Contains(or, "WHERE (a = 1 OR b = 2)") {
		t.Errorf("a predicate with a top-level OR is not parenthesised:\n%s", or)
	}
	// Ties must not depend on the plan.
	if !strings.Contains(q, "ORDER BY trigger_count DESC, "+topPoliciesAlias+".policy ASC") {
		t.Errorf("top-policies query has no deterministic tiebreak:\n%s", q)
	}
	if !strings.Contains(q, "LIMIT 10") {
		t.Errorf("top-policies query limit drifted from TopPoliciesLimit:\n%s", q)
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

// TestExtractPolicyIdentityIsName_ArmClassification pins the Go mirror of
// PolicyIdentityIsNameSQLExpr WITHOUT a database (#3426 R3 round 2).
//
// The SQL/Go parity gate for this flag lives in the real-Postgres file and is
// skipped unless TEST_PG_INTEGRATION=1, so on a plain `go test ./...` the
// mirror had no coverage at all. It decides whether the portal renders
// POLICY_NAME_NOT_RECORDED_MARKER beside a top-policies entry, so an arm
// classified wrong here shows a raw id dressed as a stamped display name on a
// regulator-facing report.
func TestExtractPolicyIdentityIsName_ArmClassification(t *testing.T) {
	cases := []struct {
		name         string
		details      string
		wantRecorded bool
		wantResolved bool
	}{
		// The id-yielding arms. policy_ids is the decide plane and the
		// FinCrime seam; policy_matches[*].policy_id is MCP check-input.
		{"policy_ids wins even when names are stamped beside it",
			`{"policy_ids":["sys_pii_iban"],"policy_names":["PII: IBAN"]}`, false, true},
		{"policy_matches id wins over the names beside it",
			`{"policy_matches":[{"policy_id":"sql-injection-block"}],"policy_names":["SQL Injection Block"]}`, false, true},
		{"singular policy_id beats the policy_name on the same HITL row",
			`{"policy_id":"hv-wire","policy_name":"High-Value Wire"}`, false, true},
		// The name-yielding arms.
		{"policy_names array with no id anywhere is a stamped NAME",
			`{"policy_names":["Structuring"]}`, true, true},
		{"legacy CSV policy_names is a stamped NAME",
			`{"policy_names":"Structuring, Geo Block"}`, true, true},
		{"singular policy_name alone is a stamped NAME",
			`{"policy_name":"High-Value Wire"}`, true, true},
		// Nothing resolves: the flag must report NOT RESOLVED rather than a
		// default false, which the SQL expresses as NULL. A false-when-absent
		// mirror would claim "this is an id" about a policy that is not there.
		{"no identity at all", `{"decision_id":"d9"}`, false, false},
		{"empty first element gates the whole arm off (see PolicyIdentitySetSQLExpr)",
			`{"policy_ids":["","b"]}`, false, false},
		{"non-string element gates the arm off", `{"policy_ids":[7,"b"]}`, false, false},
		{"malformed json never panics", `{not json`, false, false},
		// The gate falls THROUGH to a later arm rather than resolving nothing,
		// and the later arm's classification is what must be reported.
		{"blank policy_ids falls through to the singular name",
			`{"policy_ids":["","b"],"policy_name":"N"}`, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotRecorded, gotResolved := ExtractPolicyIdentityIsName([]byte(tc.details))
			if gotResolved != tc.wantResolved || gotRecorded != tc.wantRecorded {
				t.Errorf("ExtractPolicyIdentityIsName(%s) = (recorded %v, resolved %v), want (%v, %v)",
					tc.details, gotRecorded, gotResolved, tc.wantRecorded, tc.wantResolved)
			}
			// The flag and the identity are one event: a resolved flag with no
			// identity (or the reverse) would put a marker decision on a policy
			// that does not exist, or leave one unlabelled.
			identity, _ := ExtractPolicyIdentity([]byte(tc.details))
			if (identity != "") != gotResolved {
				t.Errorf("identity=%q but resolved=%v on %s; the flag and the identity took different arms",
					identity, gotResolved, tc.details)
			}
		})
	}
}
