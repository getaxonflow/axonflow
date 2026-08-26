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
	"encoding/json"
	"fmt"
	"strings"
)

// This file is the single definition of HOW a policy identity is read out of an
// audit_logs.policy_details JSONB payload (#3243 follow-up, v9.16.1).
//
// History: the audit planes never converged on ONE key for "which policy
// fired". The census (2026-08, design-partner report of a blank Policy column
// on the OJK export):
//
//	decision plane   writeDecisionAuditLog     "policy_ids"  (JSON array)
//	MCP decision     writeMCPDecisionAudit     "policy_ids"  (JSON array)
//	MCP check-input  writeExplainableAuditLog  "policy_names" (JSON array) +
//	                                           "policy_matches" ([{policy_id,
//	                                           policy_name, policy_version}]) +
//	                                           "policy_versions" ({id: version})
//	                                           -- NO "policy_ids" before 9.16.1
//	HITL             hitl repository           "policy_id" / "policy_name"
//	                                           (singular scalars)
//	cowork OTEL      writeCoworkAuditLog       nothing at all before 9.16.1
//	legacy rows      assorted                  "policy_names" as a CSV-ish
//	                                           STRING (see the portal reader at
//	                                           orchestrator/audit_logger.go)
//
// while every compliance exporter read ONLY policy_details->'policy_ids'->>0.
// Rows written by any other plane rendered a blank Policy cell on a regulator
// artifact. The fallback chain below reads every shape the writers have ever
// produced, in one place, in both SQL (for the exporters) and Go (for the
// cross-plane writer/reader contract tests that keep new writer keys readable).

// Policy-identity keys the audit writers use inside policy_details. The SQL
// expression and the Go extractor below are BOTH built from these constants so
// the two cannot silently diverge on a key name.
const (
	policyDetailKeyIDs      = "policy_ids"      // JSON array of ids (decision + MCP planes)
	policyDetailKeyMatches  = "policy_matches"  // array of {policy_id, policy_name, policy_version}
	policyDetailKeyNames    = "policy_names"    // JSON array OR legacy CSV string of names
	policyDetailKeyID       = "policy_id"       // singular scalar (HITL)
	policyDetailKeyName     = "policy_name"     // singular scalar (HITL)
	policyMatchKeyID        = "policy_id"       // inside a policy_matches entry
	policyMatchKeyVersion   = "policy_version"  // inside a policy_matches entry
	policyDetailKeyVersions = "policy_versions" // {policy_id: version} map
)

// PolicyDetailKeyRulesetVersion is the cowork capture's version key (#3243
// v9.16.1): the platform version whose redaction ruleset produced the match.
// Shared between the writer (buildCoworkAuditDetails) and PolicyVersionSQLExpr
// so the two cannot silently diverge on the key name.
const PolicyDetailKeyRulesetVersion = "ruleset_version"

// PolicyDetailKeyAttribution is the AFFIRMATIVE no-policy marker (#3243
// v9.16.1 R3 finding). Some rows act without any platform policy firing -- a
// cowork/Claude Code user rejecting a tool call, a HITL gate configured with
// no policy identity. Before this key existed those rows were
// indistinguishable from pre-9.16.1 rows whose writer failed to record what
// fired, so the exporters rendered the "(pre-9.16.1)" placeholder on
// freshly-written rows: a false era claim AND an implied policy. A writer that
// KNOWS no policy fired states it here; PolicyOrPlaceholder renders the
// matching honest label instead of the placeholder.
const PolicyDetailKeyAttribution = "policy_attribution"

// Recognized PolicyDetailKeyAttribution values and their export labels. The
// labels are display text, deliberately NOT id-shaped, so they can never be
// mistaken for a policy identifier on a regulator artifact.
const (
	// PolicyAttributionUserDecision - a human/client rejected the action
	// (cowork tool_decision reject). No platform policy fired.
	PolicyAttributionUserDecision = "user_decision"
	// PolicyAttributionUnnamedGate - a HITL workflow step gate fired but the
	// gate carries no configured policy id/name.
	PolicyAttributionUnnamedGate = "workflow_step_gate"

	PolicyLabelUserDecision = "None (user decision)"
	PolicyLabelUnnamedGate  = "Workflow step gate (policy not named)"
)

// AttributionLabel maps a recorded policy_attribution marker to its export
// label, or "" for unrecognized/absent markers (which then fall through to the
// acted-row placeholder -- an unrecognized marker is not an affirmative
// statement this reader understands).
func AttributionLabel(marker string) string {
	switch marker {
	case PolicyAttributionUserDecision:
		return PolicyLabelUserDecision
	case PolicyAttributionUnnamedGate:
		return PolicyLabelUnnamedGate
	}
	return ""
}

// PolicyNotRecordedPlaceholder is the single string every regulator exporter
// renders in a Policy cell when a row that ACTED (blocked / redacted /
// needs_approval) carries no policy identity under ANY of the keys above.
// Those are pre-9.16.1 rows whose writer never recorded what fired; the
// placeholder states that honestly instead of leaving the cell blank, and no
// attribution is ever inferred or backfilled for them.
const PolicyNotRecordedPlaceholder = "Not recorded (pre-9.16.1)"

// PolicyIdentitySQLExpr returns the SQL expression resolving the first policy
// identity recorded on a row, given the SQL reference to the policy_details
// JSONB column (normally just `policy_details`). It returns an empty string (never
// NULL) when no shape resolves, matching the exporters' existing
// COALESCE(..., empty-string) convention.
//
// Order: ids are preferred over display names (a fabricated-looking name on a
// regulator artifact is worse than a raw identifier), and array shapes over
// singular scalars only because no writer emits both:
//
//	policy_ids[0] -> policy_matches[0].policy_id -> policy_names (array first
//	element, else first element of the legacy CSV string) -> policy_id ->
//	policy_name
//
// The policy_names branch must NOT assume a JSON array: legacy writers stored
// it as a CSV-ish STRING (see orchestrator/audit_logger.go's LIKE-based
// reader), and `->'policy_names'->>0` on a JSONB string is NULL, which is
// exactly the silently-blank-cell class this helper removes.
//
// Every arm is TYPE-GUARDED at BOTH the container AND the element level to
// resolve a STRING and nothing else. Postgres is otherwise permissive in
// surprising ways -- `->>0` treats a jsonb scalar as a one-element array,
// `->>` on an object-valued key renders raw JSON text -- and an unguarded arm
// would surface raw JSON like `{"a": 1}` as a "policy" on a regulator
// artifact while the Go mirror below (and the contract tests built on it)
// resolved nothing. Container guards alone are NOT enough: `->0` inherits the
// scalar-as-array quirk, and `policy_ids: [{"a":1}]` passes a container-only
// guard while its ELEMENT renders raw JSON (both empirically confirmed on
// PG16 in this PR's second R3 round). This chain reads arbitrary historical
// JSONB, so malformed/foreign shapes must resolve NOTHING on both surfaces
// and take the placeholder path.
func PolicyIdentitySQLExpr(detailsCol string) string {
	return "COALESCE(\n\t\t" + strings.Join(policyIdentityArmsSQL(detailsCol), ",\n\t\t") + ",\n\t\t'')"
}

// policyIdentityArmsSQL returns the resolution chain's five arms, in
// precedence order, each a SQL expression yielding a non-empty string or NULL.
//
// It exists so that every consumer of the chain is built from ONE definition of
// each arm. PolicyIdentitySQLExpr COALESCEs them; PolicyVersionSQLExpr keys its
// map lookups off arms 0 and 1 (it used to re-spell both inline, and a
// second-R3-round divergence there is what paired another policy's version with
// the resolved identity); PolicyIdentitySetSQLExpr uses each arm as the
// ACTIVATION GUARD for the matching expansion in policyIdentityArmSetsSQL, so
// the set expression can never select a different arm than the scalar one does.
func policyIdentityArmsSQL(detailsCol string) []string {
	return []string{
		fmt.Sprintf(`CASE WHEN jsonb_typeof(%[1]s->'%[2]s') = 'array'
		      AND jsonb_typeof(%[1]s->'%[2]s'->0) = 'string'
		     THEN NULLIF(%[1]s->'%[2]s'->>0, '') END`,
			detailsCol, policyDetailKeyIDs),
		fmt.Sprintf(`CASE WHEN jsonb_typeof(%[1]s->'%[2]s') = 'array'
		      AND jsonb_typeof(%[1]s->'%[2]s'->0->'%[3]s') = 'string'
		     THEN NULLIF(%[1]s->'%[2]s'->0->>'%[3]s', '') END`,
			detailsCol, policyDetailKeyMatches, policyMatchKeyID),
		// btrim with no second argument strips SPACES only, not tabs or
		// newlines. That is deliberate and is mirrored exactly by the Go
		// twin's strings.Trim(v, " ") (NOT strings.TrimSpace): a legacy CSV
		// value written as "a,\tb" must resolve the same string on both
		// surfaces, and widening either side alone would reintroduce the
		// SQL/Go divergence this file exists to prevent. Widen BOTH or
		// neither.
		fmt.Sprintf(`CASE WHEN jsonb_typeof(%[1]s->'%[2]s') = 'array'
		      AND jsonb_typeof(%[1]s->'%[2]s'->0) = 'string'
		     THEN NULLIF(%[1]s->'%[2]s'->>0, '')
		     WHEN jsonb_typeof(%[1]s->'%[2]s') = 'string'
		     THEN NULLIF(btrim(split_part(%[1]s->>'%[2]s', ',', 1)), '')
		     END`,
			detailsCol, policyDetailKeyNames),
		fmt.Sprintf(`CASE WHEN jsonb_typeof(%[1]s->'%[2]s') = 'string'
		     THEN NULLIF(%[1]s->>'%[2]s', '') END`,
			detailsCol, policyDetailKeyID),
		fmt.Sprintf(`CASE WHEN jsonb_typeof(%[1]s->'%[2]s') = 'string'
		     THEN NULLIF(%[1]s->>'%[2]s', '') END`,
			detailsCol, policyDetailKeyName),
	}
}

// PolicyVersionSQLExpr returns the SQL expression resolving the recorded
// VERSION of the policy PolicyIdentitySQLExpr resolves, or an empty string
// when the writer recorded none.
//
// The version is keyed by the RESOLVED IDENTITY -- every arm derives its key
// from the SAME guarded expression PolicyIdentitySQLExpr produces, one source
// of truth (second R3 round: keying the map lookup off a raw
// `policy_ids->>0` read let the jsonb scalar-as-array quirk pair ANOTHER
// policy's version with the resolved identity -- `{"policy_ids":"p2",
// "policy_id":"real","policy_versions":{"p2":"9"}}` rendered `real (v9)`,
// confirmed on PG16):
//
//  1. policy_versions keyed by the resolved identity -- the {id: version} map
//     the check-input writer records;
//  2. policy_matches[0].policy_version, ONLY when policy_matches[0].policy_id
//     IS the resolved identity (same match, so the pairing is exact). "0" is
//     excluded (the writer's omitempty zero, not a version);
//  3. ruleset_version (the cowork capture, = platform version), ONLY when the
//     identity was resolved from policy_ids -- the key the cowork writer
//     stamps it alongside.
//
// An empty identity therefore resolves an empty version by construction; the
// exporters additionally blank the version whenever the identity is blank.
// Version VALUES render via ->>: integral JSON numbers (the only shape the
// writers emit) render identically on both surfaces; exotic non-integral
// numeric or non-scalar version VALUES could render differently per surface
// and are knowingly out of scope (the identity, the regulator-facing field,
// is string-guarded end to end).
func PolicyVersionSQLExpr(detailsCol string) string {
	identity := PolicyIdentitySQLExpr(detailsCol)
	arms := policyIdentityArmsSQL(detailsCol)
	firstIDArm := arms[policyArmIdxIDs]
	matchIDArm := arms[policyArmIdxMatches]
	return fmt.Sprintf(`COALESCE(
		NULLIF(%[1]s->'%[2]s'->>(%[3]s), ''),
		CASE WHEN (%[4]s) = (%[3]s)
		     THEN NULLIF(NULLIF(%[1]s->'%[5]s'->0->>'%[6]s', '0'), '') END,
		CASE WHEN (%[7]s) = (%[3]s)
		     THEN NULLIF(%[1]s->>'%[8]s', '') END,
		'')`,
		detailsCol,
		policyDetailKeyVersions,
		identity,
		matchIDArm,
		policyDetailKeyMatches,
		policyMatchKeyVersion,
		firstIDArm,
		PolicyDetailKeyRulesetVersion)
}

// Indices into policyIdentityArmsSQL / policyIdentityArmSetsSQL. Named so the
// two slices are demonstrably index-parallel at every use site.
const (
	policyArmIdxIDs = iota
	policyArmIdxMatches
	policyArmIdxNames
	policyArmIdxID
	policyArmIdxName
)

// PolicyIdentitySetSQLExpr returns the SQL expression resolving EVERY policy
// identity recorded on a row as a `text[]`, given the SQL reference to the
// policy_details JSONB column. It returns an empty array (never NULL) when no
// shape resolves, so `unnest(...)` over it contributes zero rows for a row that
// records no policy.
//
// This is PolicyIdentitySQLExpr widened from "the first identity" to "all of
// them", for the aggregations that ask WHICH POLICIES FIRED rather than which
// one to print in a single cell (#3426: the top-policies aggregation behind the
// portal tile and the Compliance Report export). Two invariants make it safe to
// have both:
//
//  1. SAME ARM. Each expansion is gated on the matching arm of
//     policyIdentityArmsSQL, so the set and the scalar always resolve out of
//     the SAME key. A row stamping both policy_ids and policy_names (every
//     decide-plane and FinCrime-seam row) yields the ids, not ids AND names
//     double counted.
//  2. SAME FIRST ELEMENT. Within an arm the expansion preserves document order
//     and applies the arm's own element guard, so element 1 of the set is
//     exactly what PolicyIdentitySQLExpr resolves. The real-Postgres parity
//     test asserts that over the whole vector corpus rather than trusting it.
//
// Duplicates within an arm are collapsed on FIRST OCCURRENCE (a row listing a
// policy twice triggered it once), which also keeps a LATERAL unnest from
// multiplying the row into the aggregate.
//
// INHERITED FIRST-ELEMENT ACTIVATION GATE, and what it costs. The gate below is
// the SCALAR arm, which resolves element 0 and nothing else. So an arm is only
// activated when its FIRST element is a non-empty string, and the expansion of
// a later-but-valid element is dropped with it. Empirically on PG16:
//
//	{"policy_ids": ["", "b"]}          -> resolves NOTHING (not {"b"})
//	{"policy_ids": [7, "b"]}           -> resolves NOTHING
//	{"policy_ids": ["", "b"], "policy_name": "N"} -> falls through to "N"
//
// This is intentional and is the SAME-ARM invariant's price: gating each
// expansion on its own set being non-empty would let the set select an arm the
// scalar does not, which is the exact singular-versus-plural drift #3243
// removed, and it would make set[1] stop being what the Policy column renders.
// A row whose first identity slot is blank or non-string is a malformed write,
// and resolving nothing (then taking the placeholder path) is the fail-closed
// answer both surfaces already give it. Widening this means widening
// PolicyIdentitySQLExpr and every exporter built on it, not this function alone.
func PolicyIdentitySetSQLExpr(detailsCol string) string {
	arms := policyIdentityArmsSQL(detailsCol)
	sets := policyIdentityArmSetsSQL(detailsCol)
	parts := make([]string, 0, len(arms)+1)
	for i := range arms {
		parts = append(parts, fmt.Sprintf("CASE WHEN (%s) IS NOT NULL THEN %s END", arms[i], sets[i]))
	}
	parts = append(parts, "ARRAY[]::text[]")
	return "COALESCE(\n\t\t" + strings.Join(parts, ",\n\t\t") + ")"
}

// policyIdentityArmYieldsName reports, per arm of policyIdentityArmsSQL and
// index-parallel with it, whether that arm resolves a writer-stamped DISPLAY
// NAME rather than a policy IDENTIFIER.
//
// The chain prefers ids over names (see PolicyIdentitySQLExpr), so most arms
// yield an id. Only the policy_names arm (array or legacy CSV) and the singular
// policy_name scalar carry a name a writer actually recorded.
var policyIdentityArmYieldsName = [...]bool{
	policyArmIdxIDs:     false, // policy_ids[*]
	policyArmIdxMatches: false, // policy_matches[*].policy_id
	policyArmIdxNames:   true,  // policy_names (array or legacy CSV)
	policyArmIdxID:      false, // policy_id scalar (HITL)
	policyArmIdxName:    true,  // policy_name scalar (HITL)
}

// PolicyIdentityIsNameSQLExpr returns the SQL boolean answering exactly one
// question: "is the STRING that PolicyIdentitySQLExpr / PolicyIdentitySetSQLExpr
// resolved a display NAME, or a raw identifier?". NULL when no arm resolves.
//
// It exists because a resolved identity is NOT self-describing. The chain is
// id-first, so on a decide-plane row it yields `sys_pii_iban` while the row also
// carries the readable "PII: IBAN" under policy_names, and on a HITL row it
// yields the stamped name. Any surface that renders a resolved identity to a
// human therefore has to say WHICH it is showing, or an id silently
// masquerades as a name.
//
// IT IS NOT A STATEMENT ABOUT THE WRITER, and reading it as one is a defect
// this expression has already caused once (#3438 R3). The writer-side contract
// is stampPolicyIdentityNames (platform/agent/policy_identity_stamp.go): since
// #3365 every canonical writer stamps policy_names BESIDE policy_ids, and the
// key "is omitted entirely when no id resolves a name". So on the common
// decide-plane row a name IS recorded and this expression still returns FALSE,
// because the id-first chain selected the ids arm. A renderer that turns a
// false here into the row-level POLICY_NAME_NOT_RECORDED_MARKER
// ("(name not recorded)") therefore prints a claim the row disproves, next to
// a Policy column on the same panel rendering that very name.
//
// The row-level portal resolver (resolvePolicyIdentityDisplay in
// customer-portal-ui/lib/api.ts) is NAME-first, so ITS `nameRecorded` really
// does mean "no writer recorded a name" and the marker there is honest. These
// two flags answer different questions and are deliberately not named alike.
// A consumer of this one owes its reader a neutral identifier affordance
// (POLICY_IDENTIFIER_MARKER), never a writer claim.
//
// Answering "did this row record a name under ANY key" instead would need a
// SECOND per-row JSONB traversal of policy_names / policy_name over every
// in-scope row, on a query already measured at ~2.9us per in-scope row, and it
// would still not let the aggregate PRINT that name: policy_names is not
// index-parallel to policy_ids (#3347 / #3359), so no name can be paired to a
// resolved id at read time. Naming the arm honestly is the cheaper and truer
// answer.
func PolicyIdentityIsNameSQLExpr(detailsCol string) string {
	arms := policyIdentityArmsSQL(detailsCol)
	parts := make([]string, 0, len(arms))
	for i := range arms {
		parts = append(parts, fmt.Sprintf("WHEN (%s) IS NOT NULL THEN %t", arms[i], policyIdentityArmYieldsName[i]))
	}
	return "CASE\n\t\t" + strings.Join(parts, "\n\t\t") + "\n\t\tEND"
}

// policyIdentityArmSetsSQL returns the full expansion for each arm of
// policyIdentityArmsSQL, index-parallel with it. Each yields a text[] of the
// arm's non-empty string values in document order, first occurrence wins.
//
// Every jsonb_array_elements call is wrapped in a container type guard: the
// function RAISES on a non-array input, and these expressions read arbitrary
// historical JSONB where any key can hold any shape. The guard makes a foreign
// shape resolve an empty array instead of failing the whole aggregation query,
// which is the fail-closed behaviour the scalar chain already has.
func policyIdentityArmSetsSQL(detailsCol string) []string {
	// jsonbArrayText: the distinct non-empty STRING elements of a jsonb array
	// key, in document order. `e #>> '{}'` is the text of a jsonb scalar
	// (`->>` has no array-element form here); the jsonb_typeof guard keeps
	// numbers, objects and arrays out, matching the scalar chain's element
	// guard.
	jsonbArrayText := func(key string) string {
		return fmt.Sprintf(`ARRAY(SELECT q.v FROM (
		       SELECT e #>> '{}' AS v, MIN(o) AS ord
		         FROM jsonb_array_elements(CASE WHEN jsonb_typeof(%[1]s->'%[2]s') = 'array'
		                                        THEN %[1]s->'%[2]s' ELSE '[]'::jsonb END)
		              WITH ORDINALITY AS t(e, o)
		        WHERE jsonb_typeof(e) = 'string' AND e #>> '{}' <> ''
		        GROUP BY 1) q ORDER BY q.ord)`, detailsCol, key)
	}
	matchIDs := fmt.Sprintf(`ARRAY(SELECT q.v FROM (
		       SELECT e->>'%[3]s' AS v, MIN(o) AS ord
		         FROM jsonb_array_elements(CASE WHEN jsonb_typeof(%[1]s->'%[2]s') = 'array'
		                                        THEN %[1]s->'%[2]s' ELSE '[]'::jsonb END)
		              WITH ORDINALITY AS t(e, o)
		        WHERE jsonb_typeof(e->'%[3]s') = 'string' AND e->>'%[3]s' <> ''
		        GROUP BY 1) q ORDER BY q.ord)`,
		detailsCol, policyDetailKeyMatches, policyMatchKeyID)
	// The legacy CSV form of policy_names, split on the same separator the
	// scalar chain's split_part uses and space-trimmed with the same btrim.
	namesCSV := fmt.Sprintf(`ARRAY(SELECT q.v FROM (
		       SELECT btrim(p) AS v, MIN(o) AS ord
		         FROM unnest(string_to_array(CASE WHEN jsonb_typeof(%[1]s->'%[2]s') = 'string'
		                                          THEN %[1]s->>'%[2]s' ELSE '' END, ','))
		              WITH ORDINALITY AS t(p, o)
		        WHERE btrim(p) <> ''
		        GROUP BY 1) q ORDER BY q.ord)`, detailsCol, policyDetailKeyNames)
	return []string{
		jsonbArrayText(policyDetailKeyIDs),
		matchIDs,
		// Exactly one of the two shapes can be present (jsonb_typeof is
		// single-valued), so the concatenation is the array branch OR the CSV
		// branch, never a mixture.
		jsonbArrayText(policyDetailKeyNames) + " || " + namesCSV,
		fmt.Sprintf(`ARRAY[%s->>'%s']`, detailsCol, policyDetailKeyID),
		fmt.Sprintf(`ARRAY[%s->>'%s']`, detailsCol, policyDetailKeyName),
	}
}

// ExtractPolicyIdentity is the Go mirror of PolicyIdentitySQLExpr +
// PolicyVersionSQLExpr, over the marshaled policy_details JSON. It exists for
// the cross-plane writer/reader contract tests: each audit writer's
// details-map builder is fed through this extractor, so a writer that starts
// recording identity under a key the exporters' SQL does not read fails in CI
// instead of shipping another blank Policy column.
//
// It must be fed the JSON BYTES (marshal the writer's map first), not the Go
// map, so typed values (e.g. a []RicherPolicyMatch) are seen through their
// real JSON keys exactly as Postgres sees them.
func ExtractPolicyIdentity(detailsJSON []byte) (identity, version string) {
	var details map[string]interface{}
	if err := json.Unmarshal(detailsJSON, &details); err != nil {
		return "", ""
	}

	identity = firstNonEmptyIdentity(details)
	if identity == "" {
		return "", ""
	}
	version = extractVersion(details, identity)
	return identity, version
}

// firstNonEmptyIdentity mirrors PolicyIdentitySQLExpr: every arm resolves a
// non-empty STRING and nothing else (element-level guard, matching the SQL's
// jsonb_typeof checks -- a raw object/array/number under any of these keys is
// a malformed/foreign row and must resolve nothing on both surfaces).
func firstNonEmptyIdentity(details map[string]interface{}) string {
	// 1. policy_ids[0] (array container + string element, matching the SQL).
	if s := firstStringElem(details[policyDetailKeyIDs]); s != "" {
		return s
	}
	// 2. policy_matches[0].policy_id
	if m := firstMatch(details); m != nil {
		if s := stringOnly(m[policyMatchKeyID]); s != "" {
			return s
		}
	}
	// 3. policy_names: JSON array or the legacy CSV string. Space-trim only
	// (not TrimSpace), matching Postgres btrim's default character set.
	switch names := details[policyDetailKeyNames].(type) {
	case []interface{}:
		if len(names) > 0 {
			if s := stringOnly(names[0]); s != "" {
				return s
			}
		}
	case string:
		if first := strings.Trim(strings.SplitN(names, ",", 2)[0], " "); first != "" {
			return first
		}
	}
	// 4./5. singular scalars (HITL), string-typed only.
	if s := stringOnly(details[policyDetailKeyID]); s != "" {
		return s
	}
	if s := stringOnly(details[policyDetailKeyName]); s != "" {
		return s
	}
	return ""
}

// ExtractPolicyIdentities is the Go mirror of PolicyIdentitySQLExpr's widened
// sibling PolicyIdentitySetSQLExpr: EVERY policy identity recorded on the row,
// out of the single highest-precedence key that resolves one, in document
// order, first occurrence wins. Returns nil when nothing resolves.
//
// By construction result[0] == ExtractPolicyIdentity's identity whenever the
// result is non-empty; the unit tests and the real-Postgres parity test both
// assert that rather than assuming it.
func ExtractPolicyIdentities(detailsJSON []byte) []string {
	var details map[string]interface{}
	if err := json.Unmarshal(detailsJSON, &details); err != nil {
		return nil
	}
	return allIdentities(details)
}

// allIdentities mirrors policyIdentityArmsSQL + policyIdentityArmSetsSQL: the
// FIRST arm whose scalar guard resolves supplies every value, so a row
// stamping both policy_ids and policy_names contributes its ids only.
func allIdentities(details map[string]interface{}) []string {
	// 1. policy_ids, gated on element 0 being a non-empty string.
	if firstStringElem(details[policyDetailKeyIDs]) != "" {
		return dedupeOrdered(stringElems(details[policyDetailKeyIDs]))
	}
	// 2. policy_matches[*].policy_id, gated on match 0 carrying one.
	if m := firstMatch(details); m != nil && stringOnly(m[policyMatchKeyID]) != "" {
		arr, _ := details[policyDetailKeyMatches].([]interface{})
		out := make([]string, 0, len(arr))
		for _, e := range arr {
			if obj, ok := e.(map[string]interface{}); ok {
				if s := stringOnly(obj[policyMatchKeyID]); s != "" {
					out = append(out, s)
				}
			}
		}
		return dedupeOrdered(out)
	}
	// 3. policy_names: JSON array or the legacy CSV string. Space-trim only
	// (not TrimSpace), matching Postgres btrim's default character set.
	switch names := details[policyDetailKeyNames].(type) {
	case []interface{}:
		if len(names) > 0 && stringOnly(names[0]) != "" {
			return dedupeOrdered(stringElems(names))
		}
	case string:
		if strings.Trim(strings.SplitN(names, ",", 2)[0], " ") != "" {
			parts := strings.Split(names, ",")
			out := make([]string, 0, len(parts))
			for _, p := range parts {
				if v := strings.Trim(p, " "); v != "" {
					out = append(out, v)
				}
			}
			return dedupeOrdered(out)
		}
	}
	// 4./5. singular scalars (HITL), string-typed only.
	if s := stringOnly(details[policyDetailKeyID]); s != "" {
		return []string{s}
	}
	if s := stringOnly(details[policyDetailKeyName]); s != "" {
		return []string{s}
	}
	return nil
}

// ExtractPolicyIdentityIsName is the Go mirror of PolicyIdentityIsNameSQLExpr:
// reports whether the arm that resolved this row's identity yields a display
// NAME (true) or a raw IDENTIFIER (false), and whether any arm resolved at all.
//
// Same caveat as the SQL half: this is a property of the RESOLVED STRING, not
// of the writer. A row stamping both policy_ids and policy_names resolves the
// ids arm and returns false while a name is plainly recorded on it.
//
// It exists for the same reason the other mirrors do: the real-Postgres parity
// test runs both halves over the whole adversarial vector corpus, so an arm
// added or reordered in one surface and not the other fails in CI rather than
// shipping a chip labelled as a name that is an id.
func ExtractPolicyIdentityIsName(detailsJSON []byte) (isName, resolved bool) {
	var details map[string]interface{}
	if err := json.Unmarshal(detailsJSON, &details); err != nil {
		return false, false
	}
	// Arm order and activation gates are firstNonEmptyIdentity's, unchanged.
	if firstStringElem(details[policyDetailKeyIDs]) != "" {
		return policyIdentityArmYieldsName[policyArmIdxIDs], true
	}
	if m := firstMatch(details); m != nil && stringOnly(m[policyMatchKeyID]) != "" {
		return policyIdentityArmYieldsName[policyArmIdxMatches], true
	}
	switch names := details[policyDetailKeyNames].(type) {
	case []interface{}:
		if len(names) > 0 && stringOnly(names[0]) != "" {
			return policyIdentityArmYieldsName[policyArmIdxNames], true
		}
	case string:
		if strings.Trim(strings.SplitN(names, ",", 2)[0], " ") != "" {
			return policyIdentityArmYieldsName[policyArmIdxNames], true
		}
	}
	if stringOnly(details[policyDetailKeyID]) != "" {
		return policyIdentityArmYieldsName[policyArmIdxID], true
	}
	if stringOnly(details[policyDetailKeyName]) != "" {
		return policyIdentityArmYieldsName[policyArmIdxName], true
	}
	return false, false
}

// stringElems returns the non-empty string elements of a JSON array, in order.
func stringElems(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s := stringOnly(e); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// dedupeOrdered collapses repeats keeping the FIRST occurrence's position, the
// Go twin of the SQL expansions' `GROUP BY value ORDER BY MIN(ordinality)`.
// Returns nil for an empty input so an absent identity is nil on both surfaces.
func dedupeOrdered(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// extractVersion mirrors PolicyVersionSQLExpr: every arm is keyed by the
// RESOLVED identity (see the SQL's doc comment for the pairing rationale).
// The identity!=""-only gate lives in ExtractPolicyIdentity, which matches
// how the exporters consume the SQL pair: they blank the version whenever the
// identity is blank, so a version can never render beside the placeholder or
// an empty cell.
func extractVersion(details map[string]interface{}, identity string) string {
	// 1. policy_versions[resolved identity].
	if versions, ok := details[policyDetailKeyVersions].(map[string]interface{}); ok {
		if s := jsonScalarString(versions[identity]); s != "" {
			return s
		}
	}
	// 2. policy_matches[0].policy_version, only when [0] IS the resolved
	// policy ("0" = the writer's omitempty zero, not a version).
	if m := firstMatch(details); m != nil && stringOnly(m[policyMatchKeyID]) == identity && identity != "" {
		if s := jsonScalarString(m[policyMatchKeyVersion]); s != "" && s != "0" {
			return s
		}
	}
	// 3. ruleset_version, only when the identity came from policy_ids (the
	// key the cowork writer stamps it alongside).
	if firstStringElem(details[policyDetailKeyIDs]) == identity && identity != "" {
		if s := jsonScalarString(details[PolicyDetailKeyRulesetVersion]); s != "" {
			return s
		}
	}
	return ""
}

// firstStringElem returns v[0] when v is a JSON array whose first element is a
// non-empty string, else "".
func firstStringElem(v interface{}) string {
	if arr, ok := v.([]interface{}); ok && len(arr) > 0 {
		return stringOnly(arr[0])
	}
	return ""
}

// stringOnly returns v when it is a string, else "" (the Go twin of the SQL's
// jsonb_typeof(...) = 'string' element guards).
func stringOnly(v interface{}) string {
	s, _ := v.(string)
	return s
}

// firstMatch returns policy_matches[0] when it is an object in an array.
func firstMatch(details map[string]interface{}) map[string]interface{} {
	if arr, ok := details[policyDetailKeyMatches].([]interface{}); ok && len(arr) > 0 {
		if m, ok := arr[0].(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

// jsonScalarString renders a JSON scalar (string / number / boolean) the way
// Postgres ->> renders it: numbers without a trailing ".0" for integral
// values, booleans as true/false. Non-scalars (objects, arrays, null, absent)
// render "", which is where the SQL's jsonb_typeof guards land too.
func jsonScalarString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	default:
		return ""
	}
}

// PolicyOrPlaceholder resolves what a regulator export's Policy cell shows for
// a row:
//
//  1. the recorded identity, when there is one;
//  2. the honest no-policy label, when the writer AFFIRMATIVELY recorded that
//     no platform policy fired (policy_attribution -- a cowork user rejection,
//     an unnamed HITL gate). Rendering the placeholder here would make a
//     false era claim AND imply a policy fired on a freshly-written row;
//  3. the single PolicyNotRecordedPlaceholder, when the row ACTED (its
//     normalized verdict is blocked / redacted / needs_approval) but recorded
//     neither an identity nor an affirmative no-policy statement -- the
//     pre-9.16.1 writer classes;
//  4. "" for every other row. A row that did not act gets NO placeholder:
//     claiming "not recorded" on a pure observation row would imply a policy
//     fired when none did.
func PolicyOrPlaceholder(identity, rawVerdict, attribution string) string {
	if identity != "" {
		return identity
	}
	if label := AttributionLabel(attribution); label != "" {
		return label
	}
	switch Normalize(rawVerdict) {
	case DecisionBlocked, DecisionRedacted, DecisionNeedsApproval:
		return PolicyNotRecordedPlaceholder
	}
	return ""
}

// PolicyAttributionSQLExpr resolves the affirmative no-policy marker a writer
// may have recorded (empty string when absent). Selected alongside
// PolicyIdentitySQLExpr/PolicyVersionSQLExpr and fed to PolicyOrPlaceholder.
func PolicyAttributionSQLExpr(detailsCol string) string {
	return fmt.Sprintf(`COALESCE(%s->>'%s', '')`, detailsCol, PolicyDetailKeyAttribution)
}

// FormatPolicyWithVersion renders "identity (vN)" for table cells when a
// version was recorded, and the bare identity otherwise. Never applied to the
// placeholder or to an affirmative no-policy label (neither has a version by
// construction, and a version suffix would dress them up as identifiers).
func FormatPolicyWithVersion(identity, version string) string {
	switch identity {
	case "", PolicyNotRecordedPlaceholder, PolicyLabelUserDecision, PolicyLabelUnnamedGate:
		return identity
	}
	if version == "" {
		return identity
	}
	return identity + " (v" + version + ")"
}
