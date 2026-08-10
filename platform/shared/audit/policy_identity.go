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
	return fmt.Sprintf(`COALESCE(
		CASE WHEN jsonb_typeof(%[1]s->'%[2]s') = 'array'
		      AND jsonb_typeof(%[1]s->'%[2]s'->0) = 'string'
		     THEN NULLIF(%[1]s->'%[2]s'->>0, '') END,
		CASE WHEN jsonb_typeof(%[1]s->'%[3]s') = 'array'
		      AND jsonb_typeof(%[1]s->'%[3]s'->0->'%[4]s') = 'string'
		     THEN NULLIF(%[1]s->'%[3]s'->0->>'%[4]s', '') END,
		CASE WHEN jsonb_typeof(%[1]s->'%[5]s') = 'array'
		      AND jsonb_typeof(%[1]s->'%[5]s'->0) = 'string'
		     THEN NULLIF(%[1]s->'%[5]s'->>0, '')
		     WHEN jsonb_typeof(%[1]s->'%[5]s') = 'string'
		     THEN NULLIF(btrim(split_part(%[1]s->>'%[5]s', ',', 1)), '')
		     END,
		CASE WHEN jsonb_typeof(%[1]s->'%[6]s') = 'string'
		     THEN NULLIF(%[1]s->>'%[6]s', '') END,
		CASE WHEN jsonb_typeof(%[1]s->'%[7]s') = 'string'
		     THEN NULLIF(%[1]s->>'%[7]s', '') END,
		'')`,
		detailsCol,
		policyDetailKeyIDs,
		policyDetailKeyMatches, policyMatchKeyID,
		policyDetailKeyNames,
		policyDetailKeyID,
		policyDetailKeyName)
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
	firstIDArm := fmt.Sprintf(`CASE WHEN jsonb_typeof(%[1]s->'%[2]s') = 'array'
		      AND jsonb_typeof(%[1]s->'%[2]s'->0) = 'string'
		     THEN NULLIF(%[1]s->'%[2]s'->>0, '') END`,
		detailsCol, policyDetailKeyIDs)
	matchIDArm := fmt.Sprintf(`CASE WHEN jsonb_typeof(%[1]s->'%[2]s') = 'array'
		      AND jsonb_typeof(%[1]s->'%[2]s'->0->'%[3]s') = 'string'
		     THEN NULLIF(%[1]s->'%[2]s'->0->>'%[3]s', '') END`,
		detailsCol, policyDetailKeyMatches, policyMatchKeyID)
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
