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

package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ConditionEvaluator is the ONE dynamic-policy matcher named by the target
// architecture (#3293 Slice 2 / #3296): field-op-value -> bool. It replaced
// five independently-maintained implementations that had drifted onto
// divergent operator sets and divergent semantics for the operators they
// shared:
//
//  1. platform/orchestrator/dynamic_policy_engine.go:619
//     DynamicPolicyEngine.evaluateCondition ("1a") — file deleted by #3319;
//     DynamicPolicyEngine no longer exists, cited here for provenance only
//  2. platform/orchestrator/db_dynamic_policies.go:1113 DatabaseDynamicPolicyEngine.evaluateCondition ("1b")
//  3. platform/orchestrator/mcp_dynamic_policy_handler.go:509 MCPDynamicPolicyHandler.evaluateCondition ("1c")
//  4. platform/orchestrator/policy_api_service.go:609 PolicyService.evaluateCondition ("1d", wrapper)
//  5. platform/orchestrator/policy_api_service.go:645 PolicyService.evaluateOperator ("1e")
//
// A first pass onto this type (#3296 Slice 1) kept the refactor
// behavior-neutral: every divergence between the five was preserved exactly,
// as a caller-supplied option. That was the safe intermediate state, not the
// destination — preserving five-way drift just makes the drift official.
// This is the second pass: each divergence is resolved for real, the option
// that carried it is deleted, and every caller now runs identical operator
// semantics. What follows is the convergence record — read it before
// changing an operator's behavior here, and read it when a policy matches
// differently than it did before this change landed.
//
// # Convergence record — five deliberate, customer-visible behavior changes
//
// A sixth convergence — "zero conditions never match" — shipped briefly in
// this same effort and has been WITHDRAWN. It is recorded, and its
// withdrawal explained, in its own section below rather than renumbered
// away: the reasoning for why it looked necessary, and why it turned out not
// to be, is worth keeping visible for the next person who reaches for the
// same fix.
//
//  1. contains / not_contains case sensitivity. 1a, 1b and 1e all lowercased
//     both sides before the substring test; 1c
//     (mcp_dynamic_policy_handler.go:551-552) did not — no strings.ToLower,
//     so it required an exact-case match. Converged to case-insensitive
//     everywhere. Caller changed: 1c (the MCP plane) only. Direction: MORE
//     matching on 1c — a `contains`/`not_contains` condition there now
//     matches regardless of case, where it previously required exact case.
//     MORE restrictive for a blocking policy; more permissive for an
//     allow-gate. The per-caller case-sensitivity option is gone.
//
//  2. contains_any non-string list items. 1b
//     (db_dynamic_policies.go:1159-1165) silently skipped a Value-list item
//     that was not a Go string; 1e (policy_api_service.go:658-666)
//     stringified every item with %v and matched it. Converged to
//     stringify-every-item (1e's behavior): silently dropping an element the
//     policy author explicitly listed makes the policy under-match with no
//     signal, which is the wrong default for a governance control. Caller
//     changed: 1b (the database-backed engine — LLM/MAP/WCP planes) only. A
//     contains_any Value list mixing a JSON number/bool/null with strings now
//     also matches on the non-string item, where it previously ignored it.
//     Direction: MORE matching on 1b. MORE restrictive for a blocking policy.
//     The per-caller stringify-vs-skip option is gone.
//
//  3. greater_than / less_than numeric coercion. Neither legacy behavior
//     survives — both were wrong, in opposite directions. 1a
//     (dynamic_policy_engine.go:1424-1459) compared only
//     float64/float32/int/int64 operands: a numeric string (which JSON
//     produces constantly) never compared, always false. 1b
//     (db_dynamic_policies.go:1358-1374) parsed a string with
//     strconv.ParseFloat and silently coerced ANY unparseable value — a
//     non-numeric string, or any other type — to 0.0, with no failure signal
//     at all. That is a live false-positive: a non-numeric string field value
//     under `less_than 100` evaluated `0 < 100` = true, a spurious match on a
//     blocking rule. Converged semantics: a numeric string parses via
//     strconv.ParseFloat; an operand that is neither a numeric type nor a
//     parseable numeric string is NOT COMPARABLE, and the condition is false.
//     An unparseable value is never coerced to 0.0. Callers changed: BOTH 1a
//     and 1b.
//     - 1a: MORE matching — a numeric-looking string field value or
//     threshold now compares, where it never did before. MORE
//     restrictive for a blocking policy.
//     - 1b: matches on the numeric-string path exactly as before (ParseFloat
//     succeeded then and still does), but LESS matching on the
//     false-positive path — a non-numeric string, bool, nil, slice, or
//     map operand no longer coerces to 0.0 and silently satisfies
//     `less_than <positive threshold>`. LESS restrictive for a blocking
//     policy on exactly that input, which is the point: that match was
//     never supposed to fire.
//     The per-caller numeric-coercion option is gone.
//
//  4. regex pattern type. 1a (dynamic_policy_engine.go:634) accepted any
//     condition Value, stringifying it with %v before compiling — so
//     `value: 1.5` became the pattern "1.5", where `.` is a wildcard, not a
//     literal dot. 1b, 1c and 1e all required a Go string and refused to
//     compile (false, no attempt) otherwise. Converged to string-required.
//     Caller changed: 1a only — a stored policy with a non-string regex Value
//     stops matching. Direction: LESS matching on 1a. This is a NARROWING,
//     and the one convergence in this list that makes a blocking policy fire
//     LESS than it did before. It is paired with an authoring-side fix
//     (PolicyService.validateCondition, policy_api_service.go) that rejects a
//     non-string regex value at write time, so this shape cannot be created
//     going forward — see that function's own comment. The per-caller
//     stringify-and-compile fallback option is gone.
//
//  5. operator coverage per call site. 1a implemented 7 of the 10 operators,
//     1c implemented 4, 1e implemented 8; 1b was already the 10-operator
//     union. ValidPolicyOperators (policy_api_types.go) and the portal's
//     POLICY_OPERATORS (lib/api.ts) have always offered all 10, so a policy
//     author could pick an operator the enforcing call site silently never
//     evaluated — an inert, undetectable no-op from the author's chair. This
//     was a standing violation of the getPoliciesForMCP invariant (#3061,
//     mcp_dynamic_policy_handler.go): "a policy is evaluated here if and only
//     if it would be enforced for this tenant on the LLM/MAP/WCP planes." 1c's
//     4-operator subset broke that invariant for 6 of the 10 operators.
//     Converged to the full 10-operator union at every call site. Callers
//     changed:
//     - 1a gains not_contains, contains_any, not_in.
//     - 1c gains not_contains, contains_any, greater_than, less_than, in,
//     not_in (the 6-operator MCP-plane parity gap above).
//     - 1e gains greater_than, less_than.
//     Direction: MORE matching everywhere this applies — a
//     previously-inert operator starts enforcing for real. MORE restrictive
//     for a blocking policy that used one of these operators and, until now,
//     silently never fired. The per-caller operator-subset restriction is
//     gone, and with it the four near-duplicate constructors that existed
//     only to bake in a different restriction/knob combination per caller —
//     with those knobs gone, every call site now constructs a
//     ConditionEvaluator literal directly.
//
// # Withdrawn: "zero conditions never match" (formerly convergence 6)
//
// 1a, 1b and 1e treated a zero-condition policy as an unconditional match
// (their AND-loop simply never runs, which is vacuous truth — AND over an
// empty set is true by definition, the same reason an empty `WHERE` matches
// every row). 1c (mcp_dynamic_policy_handler.go) was the sole exception — an
// explicit fail-safe returning no-match, added (#3061) because a
// condition-less policy carrying a block action would otherwise deny every
// governed tool call for a tenant on that plane.
//
// A later pass converged every caller onto 1c's no-match semantics, reasoning
// that the blast-radius asymmetry (a bad row silently going from "inert" to
// "denies everyone") was worth narrowing away entirely. That converged state
// shipped briefly and is now WITHDRAWN — restored to vacuous-truth-matches,
// which is what "no conditions" honestly means. Two things changed the
// analysis:
//
//   - The asymmetry was being fixed at the wrong layer. Matching
//     unconditionally is not a defect in the evaluator — it is what "no
//     conditions" means, the same way a filter with no clauses passes
//     everything through. Making that construct inert instead of fixing the
//     one path that could actually place a dangerous row into production is
//     treating the symptom.
//   - The real gap was two paths that could produce a zero-condition row
//     nobody meant to write: validateUpdateRequest accepted an
//     explicitly-empty `[]` (fixed — see its own comment, and it stays
//     fixed), and a stored conditions blob that failed to unmarshal used to
//     be cached as indistinguishable from a genuinely empty list (fixed —
//     see cachedPolicyToDynamicPolicy in db_dynamic_policies.go, which now
//     refuses to cache such a row at all rather than passing it through with
//     Conditions silently nil'd out). With both closed, and creation already
//     rejecting zero conditions outright, the only way a condition-less
//     policy can exist at all is a platform-seeded row that means exactly
//     that: "applies to everything." There is no longer a corruption path
//     that produces one by accident.
//
// The safety this convergence was buying now comes from controlling what can
// exist (validated authoring, corruption refused at load) rather than from
// making a legitimate construct — zero conditions, meaning "applies to
// everything" — permanently unusable, including for the platform's own
// unconditionally-applicable seed/fallback policies, which is what forced
// those to grow a synthetic always-true condition as a workaround. That
// workaround is gone along with this convergence. MatchAll's zero-length
// case is vacuous truth again, like every other AND-loop in this file; no
// caller has a special case for it anymore.
//
// # Unevaluable conditions (#3296 Slice 2 / epic #3293)
//
// The per-caller unknown-operator logging hook this evaluator used to carry
// is gone. It reproduced each caller's own "operator I don't
// recognize" log line, but the evaluator runs per request x per policy x per
// condition: a single corrupt stored row could spam that log unboundedly,
// which is the wrong shape for something that needs to be counted, not
// narrated. Every place a condition cannot be evaluated — an unrecognized
// operator, an operand that won't coerce, a non-string regex pattern, or
// (one layer up, at the caller) corrupt conditions JSON or an unresolved
// field — now reports through the UnevaluableRecorder passed into Match and
// MatchAll instead. A nil recorder is always a safe no-op; see
// unevaluable_recorder.go for the interface and the closed Reason* constant
// set. ConditionEvaluator itself carries no configuration fields as a
// result — every call site now constructs a bare ConditionEvaluator{}.
//
// # Field resolution is NOT part of this evaluator
//
// getFieldValue (the "field" half of "field op value") stays with each
// caller — 1a, 1b, and 1c each resolve a different request shape into a
// field value, and none of that logic is duplicated here. A FieldResolver
// is supplied by the caller per evaluation; ok=false (field not present)
// is treated identically to every legacy impl's own "unrecognized field"
// path — as a nil value, never as a distinct third outcome. The MCP handler
// and the policy-test evaluator additionally short-circuit to false BEFORE
// calling Match when a field cannot be resolved at all (mcpFieldValue,
// policyTestFieldValue in platform/orchestrator) — that short-circuit is
// caller-side, predates this evaluator, and is unrelated to the six
// convergences above; it must not move inside Match.
type ConditionEvaluator struct{}

// FieldResolver resolves a MatchCondition's Field to a value from a
// caller-specific request shape. ok=false means "field not present /
// unrecognized" — Match treats that identically to every legacy impl's own
// getFieldValue returning nil for an unrecognized field: as a nil value, not
// as a distinct outcome.
type FieldResolver func(field string) (value any, ok bool)

// MatchCondition is the substrate's field-op-value triple — the parsed,
// typed shape every legacy PolicyCondition (1a/1c/1d) and every JSON-sourced
// map (1b, via MapCondition) reduces to before evaluation.
type MatchCondition struct {
	Field    string
	Operator string
	Value    any
}

// unknownOperator records ReasonUnknownOperator (if recorder is non-nil) and
// returns false — the unconditional outcome every legacy impl returns for an
// operator it does not evaluate, whether because the switch's default case
// caught it (1a, 1b) or because a narrower legacy switch excluded it
// entirely (1c, 1e). Since #3296's convergence pass this only fires for an
// operator string truly outside the ten implemented below — every call site
// now evaluates the full union for real.
func unknownOperator(recorder UnevaluableRecorder) bool {
	recordUnevaluable(recorder, ReasonUnknownOperator)
	return false
}

// Match evaluates one MatchCondition against a field value resolved by
// resolve. A nil resolve is treated as "no field ever resolves" (every field
// is absent), which is a safe caller error rather than a panic.
//
// recorder is notified (via UnevaluableRecorder.RecordUnevaluable) whenever
// the condition could not be genuinely evaluated — as opposed to being
// genuinely evaluated and simply not matching. A nil recorder is always a
// safe no-op; see unevaluable_recorder.go.
func (e ConditionEvaluator) Match(cond MatchCondition, resolve FieldResolver, recorder UnevaluableRecorder) bool {
	var fieldValue any
	if resolve != nil {
		if v, ok := resolve(cond.Field); ok {
			fieldValue = v
		}
	}

	switch cond.Operator {
	case "equals":
		return sprintValue(fieldValue) == sprintValue(cond.Value)
	case "not_equals":
		return sprintValue(fieldValue) != sprintValue(cond.Value)
	case "contains":
		return matchContains(fieldValue, cond.Value)
	case "not_contains":
		return !matchContains(fieldValue, cond.Value)
	case "contains_any":
		return matchContainsAny(fieldValue, cond.Value)
	case "greater_than":
		fv, fok := toFloat64(fieldValue)
		cv, cok := toFloat64(cond.Value)
		if !fok || !cok {
			recordUnevaluable(recorder, ReasonNonNumericOperand)
			return false
		}
		return fv > cv
	case "less_than":
		fv, fok := toFloat64(fieldValue)
		cv, cok := toFloat64(cond.Value)
		if !fok || !cok {
			recordUnevaluable(recorder, ReasonNonNumericOperand)
			return false
		}
		return fv < cv
	case "regex":
		return matchRegexCondition(fieldValue, cond.Value, recorder)
	case "in":
		return matchInList(fieldValue, cond.Value)
	case "not_in":
		return !matchInList(fieldValue, cond.Value)
	default:
		return unknownOperator(recorder)
	}
}

// MatchAll evaluates every condition with AND semantics: the first
// non-match short-circuits to false. A zero-length list is vacuously true —
// AND over an empty set — restored after a brief withdrawal (see the package
// doc's "Withdrawn" section); "no conditions" means the policy applies to
// everything, not that it matches nothing. No production caller currently
// reaches MatchAll (each loops over its own conditions by hand — see
// evaluatePolicy, EvaluateDynamicPolicies, evaluateConditions in
// platform/orchestrator), but this is the correct substrate default for any
// future one.
func (e ConditionEvaluator) MatchAll(conds []MatchCondition, resolve FieldResolver, recorder UnevaluableRecorder) bool {
	for _, c := range conds {
		if !e.Match(c, resolve, recorder) {
			return false
		}
	}
	return true
}

// MapCondition adapts 1b's untyped JSON condition shape
// (map[string]interface{}, as parsed straight out of dynamic_policies.conditions
// by DatabaseDynamicPolicyEngine.EvaluateDynamicPolicies) into a
// MatchCondition. Key lookup replicates db_dynamic_policies.go:1114-1116
// exactly:
//
//	field, _ := cond["field"].(string)
//	operator, _ := cond["operator"].(string)
//	value := cond["value"]
//
// ok is always true. 1b never bails out of evaluateCondition when a key is
// absent or the wrong type — a missing "field"/"operator" silently becomes
// "", which then falls through Match's switch to the unknown-operator path
// exactly as it does in 1b today. There is no failure state to surface here
// that 1b itself distinguishes.
func MapCondition(m map[string]any) (MatchCondition, bool) {
	field, _ := m["field"].(string)
	operator, _ := m["operator"].(string)
	value := m["value"]
	return MatchCondition{Field: field, Operator: operator, Value: value}, true
}

// sprintValue is the %v string form used by every legacy impl's equals /
// not_equals / in / not_in comparisons (fmt.Sprint and fmt.Sprintf("%v", ...)
// are identical for these purposes). fmt.Sprintf("%v", nil) == "<nil>",
// matching fmt.Sprint(nil) exactly.
func sprintValue(v any) string {
	return fmt.Sprintf("%v", v)
}

// stringOrSprint returns v unchanged if it is already a string (avoiding a
// redundant round-trip through Sprintf), else its %v form. This is the field
// value handling shared by contains / not_contains / contains_any / regex
// across all four callers — a string fieldValue formats identically either
// way, so this is not a behavior choice, just how the legacy impls already
// spelled it (1b, 1c: type-assert-then-fallback; 1a, 1e: Sprint/Sprintf
// unconditionally).
func stringOrSprint(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// matchContains implements `contains` (and, negated, `not_contains`).
// Case-insensitive at every call site (#3296 convergence 1) — both sides are
// lowercased before strings.Contains. 1c (mcp_dynamic_policy_handler.go) was
// the sole case-sensitive legacy impl; see the package doc's convergence
// record for the direction of that change.
func matchContains(fieldValue, condValue any) bool {
	fieldStr := strings.ToLower(stringOrSprint(fieldValue))
	condStr := strings.ToLower(stringOrSprint(condValue))
	return strings.Contains(fieldStr, condStr)
}

// toStringSlice normalizes a condition Value into a list of strings for `in`
// / `not_in`. Every item is stringified with %v unconditionally — 1a/1b/1e's
// shared, non-divergent behavior for these two operators (unlike
// contains_any, see containsAnyItems). Both []any and []string are accepted,
// a superset of 1e's []interface{}-only support; see condition_evaluator_test.go
// for why that widening is documented as verified-unreachable for 1e rather
// than a real behavior change.
func toStringSlice(v any) ([]string, bool) {
	switch vv := v.(type) {
	case []any:
		out := make([]string, len(vv))
		for i, item := range vv {
			out[i] = sprintValue(item)
		}
		return out, true
	case []string:
		return vv, true
	default:
		return nil, false
	}
}

// containsAnyItems normalizes a contains_any Value list. Every non-string
// item is stringified with %v and matched like any other (#3296 convergence
// 2) — 1b's legacy silent-skip of a non-string item is gone; see the package
// doc's convergence record for why silently dropping an element the author
// listed was the wrong default. A Go []string list has no non-string items
// by construction, so this only changes behavior on a []any list.
//
// Accepting []string here at all is a superset of 1e's own legacy
// contains_any arm, which only type-asserted []interface{}
// (policy_api_service.go:659) — a verified-unreachable widening for 1e, not
// merely an assumed one: PolicyService.TestPolicy always sources conditions
// through PolicyRepository.GetByID's JSON round trip, which never produces a
// Go []string.
func containsAnyItems(v any) ([]string, bool) {
	switch vv := v.(type) {
	case []any:
		out := make([]string, 0, len(vv))
		for _, item := range vv {
			if s, ok := item.(string); ok {
				out = append(out, s)
				continue
			}
			out = append(out, sprintValue(item))
		}
		return out, true
	case []string:
		return vv, true
	default:
		return nil, false
	}
}

// matchContainsAny implements `contains_any`: true if the (lowercased) field
// value contains any (lowercased) item of the Value list. Live at every call
// site as of #3296 convergence 5 (1a and 1c previously excluded it).
func matchContainsAny(fieldValue, condValue any) bool {
	fieldLower := strings.ToLower(stringOrSprint(fieldValue))
	items, ok := containsAnyItems(condValue)
	if !ok {
		return false
	}
	for _, item := range items {
		if strings.Contains(fieldLower, strings.ToLower(item)) {
			return true
		}
	}
	return false
}

// matchInList implements `in` (and, negated, `not_in`): true if
// sprintValue(fieldValue) equals the %v form of any item in the Value list.
// A Value that is neither []any nor []string matches nothing, which makes
// `in` false and `not_in` (its negation) true — reproducing 1b's not_in
// falling through its switch to `return true` for an unrecognized list shape
// (db_dynamic_policies.go:1219-1235).
func matchInList(fieldValue, listValue any) bool {
	fieldStr := sprintValue(fieldValue)
	items, ok := toStringSlice(listValue)
	if !ok {
		return false
	}
	for _, item := range items {
		if item == fieldStr {
			return true
		}
	}
	return false
}

// matchRegexCondition implements `regex`. The pattern MUST be a Go string
// (#3296 convergence 4) — a non-string condition Value is an immediate
// non-match, never a compile attempt. 1a's legacy fmt.Sprint-and-compile
// fallback for a non-string Value is gone; see the package doc's convergence
// record and PolicyService.validateCondition (policy_api_service.go) for the
// paired authoring-side rejection. The field value is stringified with
// stringOrSprint either way. A pattern that fails to compile is a non-match,
// never a panic — regexp.MatchString reports the compile error rather than
// panicking, and this function discards it exactly as every legacy impl
// does (each one only differed in whether it logged the error, which is
// outside this pure-function evaluator's job — each caller's own
// evaluateCondition performs an equivalent pre-check purely for its own
// diagnostic log line).
func matchRegexCondition(fieldValue, patternValue any, recorder UnevaluableRecorder) bool {
	pattern, ok := patternValue.(string)
	if !ok {
		recordUnevaluable(recorder, ReasonNonStringPattern)
		return false
	}
	fieldStr := stringOrSprint(fieldValue)
	matched, err := regexp.MatchString(pattern, fieldStr)
	if err != nil {
		return false
	}
	return matched
}

// toFloat64 converts v to a float64 for greater_than / less_than, per
// #3296 convergence 3. float64/float32/int/int64 convert directly. A string
// is parsed with strconv.ParseFloat; a parse failure means NOT COMPARABLE
// (0, false), never a silent 0.0 — that silent coercion was 1b's live
// false-positive bug (see the package doc's convergence record) and is not
// reproduced here. Every other type (bool, nil, slice, map, ...) is also NOT
// COMPARABLE. Both operands must resolve to a number via this function or
// Match's greater_than/less_than arms return false unconditionally.
func toFloat64(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case string:
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}
