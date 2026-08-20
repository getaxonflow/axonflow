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
	"testing"
)

// fieldMapResolver builds a FieldResolver over a plain map, used throughout
// this file to stand in for each legacy impl's getFieldValue.
func fieldMapResolver(m map[string]any) FieldResolver {
	return func(field string) (any, bool) {
		v, ok := m[field]
		return v, ok
	}
}

// fakeRecorder is the in-package UnevaluableRecorder test double used to
// assert exactly which Reason* constant fired, and how many times.
type fakeRecorder struct {
	reasons []string
}

func (f *fakeRecorder) RecordUnevaluable(reason string) {
	f.reasons = append(f.reasons, reason)
}

// ---------------------------------------------------------------------------
// Table-driven coverage: every operator x (match / no-match / field-absent /
// type-mismatch / nil value). All ten operators are live on every
// ConditionEvaluator instance since #3296's convergence pass — there is no
// per-caller operator-subset restriction left to vary per table entry.
// ---------------------------------------------------------------------------

func TestConditionEvaluator_Operators(t *testing.T) {
	tests := []struct {
		name   string
		cond   MatchCondition
		fields map[string]any
		want   bool
	}{
		// equals
		{"equals_match", MatchCondition{Field: "f", Operator: "equals", Value: "admin"}, map[string]any{"f": "admin"}, true},
		{"equals_no_match", MatchCondition{Field: "f", Operator: "equals", Value: "admin"}, map[string]any{"f": "user"}, false},
		{"equals_field_absent", MatchCondition{Field: "f", Operator: "equals", Value: "<nil>"}, map[string]any{}, true},
		{"equals_type_mismatch_numeric_string", MatchCondition{Field: "f", Operator: "equals", Value: "5"}, map[string]any{"f": 5}, true}, // both Sprint to "5"
		{"equals_nil_value", MatchCondition{Field: "f", Operator: "equals", Value: nil}, map[string]any{"f": nil}, true},

		// not_equals
		{"not_equals_match", MatchCondition{Field: "f", Operator: "not_equals", Value: "admin"}, map[string]any{"f": "user"}, true},
		{"not_equals_no_match", MatchCondition{Field: "f", Operator: "not_equals", Value: "admin"}, map[string]any{"f": "admin"}, false},
		{"not_equals_field_absent", MatchCondition{Field: "f", Operator: "not_equals", Value: "x"}, map[string]any{}, true},

		// contains (case-insensitive everywhere, #3296 convergence 1)
		{"contains_match", MatchCondition{Field: "f", Operator: "contains", Value: "wor"}, map[string]any{"f": "hello world"}, true},
		{"contains_no_match", MatchCondition{Field: "f", Operator: "contains", Value: "zzz"}, map[string]any{"f": "hello world"}, false},
		{"contains_case_insensitive", MatchCondition{Field: "f", Operator: "contains", Value: "WORLD"}, map[string]any{"f": "hello world"}, true},
		{"contains_field_absent", MatchCondition{Field: "f", Operator: "contains", Value: "x"}, map[string]any{}, false},
		{"contains_nil_value", MatchCondition{Field: "f", Operator: "contains", Value: nil}, map[string]any{"f": "hello"}, false}, // "<nil>" is not a substring of "hello" — see dedicated test below

		// not_contains
		{"not_contains_match", MatchCondition{Field: "f", Operator: "not_contains", Value: "zzz"}, map[string]any{"f": "hello world"}, true},
		{"not_contains_no_match", MatchCondition{Field: "f", Operator: "not_contains", Value: "wor"}, map[string]any{"f": "hello world"}, false},
		{"not_contains_case_insensitive", MatchCondition{Field: "f", Operator: "not_contains", Value: "WORLD"}, map[string]any{"f": "hello world"}, false},

		// contains_any (stringifies every list item, #3296 convergence 2)
		{"contains_any_match", MatchCondition{Field: "f", Operator: "contains_any", Value: []any{"zzz", "wor"}}, map[string]any{"f": "hello world"}, true},
		{"contains_any_match_string_slice", MatchCondition{Field: "f", Operator: "contains_any", Value: []string{"zzz", "wor"}}, map[string]any{"f": "hello world"}, true},
		{"contains_any_no_match", MatchCondition{Field: "f", Operator: "contains_any", Value: []any{"zzz", "yyy"}}, map[string]any{"f": "hello world"}, false},
		{"contains_any_type_mismatch_not_a_list", MatchCondition{Field: "f", Operator: "contains_any", Value: "wor"}, map[string]any{"f": "hello world"}, false},
		{"contains_any_nil_value", MatchCondition{Field: "f", Operator: "contains_any", Value: nil}, map[string]any{"f": "hello world"}, false},

		// greater_than (#3296 convergence 3: numeric strings parse, unparseable never coerces to 0)
		{"greater_than_match", MatchCondition{Field: "f", Operator: "greater_than", Value: 3.0}, map[string]any{"f": 5.0}, true},
		{"greater_than_no_match", MatchCondition{Field: "f", Operator: "greater_than", Value: 5.0}, map[string]any{"f": 3.0}, false},
		{"greater_than_field_absent_not_comparable", MatchCondition{Field: "f", Operator: "greater_than", Value: -1.0}, map[string]any{}, false},
		{"greater_than_type_mismatch_bool_not_comparable", MatchCondition{Field: "f", Operator: "greater_than", Value: 1.0}, map[string]any{"f": true}, false},
		{"greater_than_numeric_string_field_compares", MatchCondition{Field: "f", Operator: "greater_than", Value: 3.0}, map[string]any{"f": "5"}, true},
		{"greater_than_unparseable_string_not_comparable", MatchCondition{Field: "f", Operator: "greater_than", Value: -1.0}, map[string]any{"f": "not-a-number"}, false},

		// less_than
		{"less_than_match", MatchCondition{Field: "f", Operator: "less_than", Value: 5.0}, map[string]any{"f": 3.0}, true},
		{"less_than_no_match", MatchCondition{Field: "f", Operator: "less_than", Value: 3.0}, map[string]any{"f": 5.0}, false},

		// regex (string-required everywhere, #3296 convergence 4)
		{"regex_match", MatchCondition{Field: "f", Operator: "regex", Value: "^hel+o"}, map[string]any{"f": "hello world"}, true},
		{"regex_no_match", MatchCondition{Field: "f", Operator: "regex", Value: "^zzz"}, map[string]any{"f": "hello world"}, false},
		{"regex_field_absent", MatchCondition{Field: "f", Operator: "regex", Value: "<nil>"}, map[string]any{}, true},
		{"regex_value_type_mismatch_non_string", MatchCondition{Field: "f", Operator: "regex", Value: 5}, map[string]any{"f": "hello"}, false},
		{"regex_invalid_pattern_no_panic", MatchCondition{Field: "f", Operator: "regex", Value: "["}, map[string]any{"f": "hello"}, false},

		// in
		{"in_match_interface_slice", MatchCondition{Field: "f", Operator: "in", Value: []any{"a", "b", "c"}}, map[string]any{"f": "b"}, true},
		{"in_match_string_slice", MatchCondition{Field: "f", Operator: "in", Value: []string{"a", "b", "c"}}, map[string]any{"f": "b"}, true},
		{"in_no_match", MatchCondition{Field: "f", Operator: "in", Value: []any{"a", "b", "c"}}, map[string]any{"f": "z"}, false},
		{"in_type_mismatch_not_a_list", MatchCondition{Field: "f", Operator: "in", Value: "a,b,c"}, map[string]any{"f": "a"}, false},
		{"in_field_absent", MatchCondition{Field: "f", Operator: "in", Value: []any{"a", "<nil>"}}, map[string]any{}, true},

		// not_in
		{"not_in_match", MatchCondition{Field: "f", Operator: "not_in", Value: []any{"a", "b", "c"}}, map[string]any{"f": "z"}, true},
		{"not_in_no_match", MatchCondition{Field: "f", Operator: "not_in", Value: []any{"a", "b", "c"}}, map[string]any{"f": "b"}, false},
		{"not_in_type_mismatch_not_a_list_defaults_true", MatchCondition{Field: "f", Operator: "not_in", Value: "a,b,c"}, map[string]any{"f": "a"}, true},
	}

	e := ConditionEvaluator{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.Match(tt.cond, fieldMapResolver(tt.fields), nil)
			if got != tt.want {
				t.Errorf("Match(%+v) = %v, want %v", tt.cond, got, tt.want)
			}
		})
	}
}

// contains_nil_value above asserted true; verify explicitly what "<nil>"
// substring logic does so the table entry isn't mysterious: fmt.Sprintf("%v",
// nil) == "<nil>", and "hello" does not contain "<nil>" — so this should be
// false, not true. This dedicated test catches that mistake directly.
func TestConditionEvaluator_Contains_NilValueIsNotSubstring(t *testing.T) {
	e := ConditionEvaluator{}
	got := e.Match(MatchCondition{Field: "f", Operator: "contains", Value: nil}, fieldMapResolver(map[string]any{"f": "hello"}), nil)
	if got != false {
		t.Errorf("contains with nil Value against \"hello\" = %v, want false (\"<nil>\" is not a substring of \"hello\")", got)
	}
}

// ---------------------------------------------------------------------------
// Convergence 3 — greater_than / less_than: numeric strings parse via
// strconv.ParseFloat; an unparseable value is NOT COMPARABLE (false), never
// silently coerced to 0.0. Neither legacy impl survives: 1a
// (dynamic_policy_engine.go:1424-1459) never compared a numeric string at
// all; 1b (db_dynamic_policies.go:1358-1374) is the false-positive bug this
// closes.
// ---------------------------------------------------------------------------

// TestConditionEvaluator_NumericComparison_NumericStringParses proves the
// widening over 1a: a numeric-looking string field value or threshold now
// compares correctly on every caller, where 1a's strict typed-only
// comparison rejected it outright.
func TestConditionEvaluator_NumericComparison_NumericStringParses(t *testing.T) {
	e := ConditionEvaluator{}

	tests := []struct {
		name      string
		fieldVal  any
		threshold any
		op        string
		want      bool
	}{
		{"int_greater_than", 5, 3.0, "greater_than", true},
		{"int64_greater_than", int64(5), 3.0, "greater_than", true},
		{"float64_greater_than", 5.0, 3.0, "greater_than", true},
		{"float32_greater_than", float32(5.0), 3.0, "greater_than", true},
		{"numeric_string_field_parses", "5", 3.0, "greater_than", true},
		{"numeric_string_threshold_parses", 5.0, "3", "greater_than", true},
		{"numeric_string_less_than_parses", "3", 5.0, "less_than", true},
		{"int_less_than", 3, 5.0, "less_than", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := MatchCondition{Field: "f", Operator: tt.op, Value: tt.threshold}
			got := e.Match(cond, fieldMapResolver(map[string]any{"f": tt.fieldVal}), nil)
			if got != tt.want {
				t.Errorf("%s: Match = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestConditionEvaluator_NumericComparison_UnparseableStringNeverMatches_LessThan
// is the 1b false-positive regression test, named so the bug it closes is
// obvious: db_dynamic_policies.go's legacy toFloat64 silently coerced ANY
// ParseFloat failure to 0.0 with no failure signal, so a non-numeric string
// field value under `less_than 100` evaluated `0 < 100` = true — a spurious
// match on what was, in production, frequently a BLOCKING rule. The
// converged toFloat64 treats an unparseable string as NOT COMPARABLE, so
// this must be false.
func TestConditionEvaluator_NumericComparison_UnparseableStringNeverMatches_LessThan(t *testing.T) {
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "less_than", Value: 100.0}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "not-a-number"}), nil)
	if got {
		t.Fatalf("regression: an unparseable string field value must NOT satisfy less_than (1b's legacy silent-0.0-coercion false positive) — expected false, got true")
	}
}

// TestConditionEvaluator_NumericComparison_UnparseableStringNeverMatches_GreaterThan
// is the mirror case on greater_than: 1b's bug also made `0 > <negative
// threshold>` spuriously true for any unparseable operand.
func TestConditionEvaluator_NumericComparison_UnparseableStringNeverMatches_GreaterThan(t *testing.T) {
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "greater_than", Value: -1.0}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "not-a-number"}), nil)
	if got {
		t.Fatalf("regression: an unparseable string field value must NOT satisfy greater_than -1 (1b's legacy silent-0.0-coercion false positive) — expected false, got true")
	}
}

// TestConditionEvaluator_NumericComparison_NonNumericTypesNeverMatch covers
// every other non-numeric Go type 1b's bug also silently coerced to 0.0:
// bool, nil, a slice, and a map. None of these are comparable under the
// converged semantics.
func TestConditionEvaluator_NumericComparison_NonNumericTypesNeverMatch(t *testing.T) {
	e := ConditionEvaluator{}

	tests := []struct {
		name     string
		fieldVal any
	}{
		{"bool", true},
		{"nil", nil},
		{"slice", []any{1, 2}},
		{"map", map[string]any{"a": 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := map[string]any{}
			if tt.fieldVal != nil {
				fields["f"] = tt.fieldVal
			}
			got := e.Match(MatchCondition{Field: "f", Operator: "greater_than", Value: -1.0}, fieldMapResolver(fields), nil)
			if got {
				t.Fatalf("%s field value must not be comparable under greater_than, expected false, got true", tt.name)
			}
		})
	}
}

// TestConditionEvaluator_NumericComparison_BothOperandsUnresolvable_False
// covers the case where neither the field value nor the threshold resolves
// to a number — Match's greater_than/less_than arms require BOTH operands to
// convert via toFloat64.
func TestConditionEvaluator_NumericComparison_BothOperandsUnresolvable_False(t *testing.T) {
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "greater_than", Value: "also-not-a-number"}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "not-a-number"}), nil)
	if got {
		t.Fatalf("both operands unresolvable to a number must be false, got true")
	}
}

// ---------------------------------------------------------------------------
// Convergence 1 — contains / not_contains case sensitivity: case-insensitive
// on every caller now, including the MCP handler (1c), the sole legacy
// holdout. mcp_dynamic_policy_handler_test.go carries the caller-specific
// version of this test (through the handler's own evaluateCondition); this
// one pins it at the shared-evaluator level.
// ---------------------------------------------------------------------------

func TestConditionEvaluator_Contains_CaseInsensitiveEverywhere(t *testing.T) {
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "contains", Value: "WORLD"}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "hello world"}), nil)
	if !got {
		t.Fatalf("contains must match case-insensitively on every ConditionEvaluator instance (#3296 convergence 1, including the former 1c holdout), got false")
	}
}

// ---------------------------------------------------------------------------
// Withdrawn convergence — zero conditions vacuously matches, on every
// caller. A prior revision of this effort converged every caller onto the
// MCP plane's #3061 fail-safe (no-match on zero conditions) instead of the
// other way around, and shipped it as convergence 6. That is withdrawn: see
// condition_evaluator.go's "Withdrawn" doc section for why, and
// TestConditionEvaluator_MatchAll_EmptyConditionsVacuouslyMatch below for the
// restored-semantics test.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Convergence 5 — the full 10-operator union is live on every
// ConditionEvaluator instance; there is no per-caller operator-subset
// restriction left. This is the test that proves the MCP-plane parity gap (#3061) is
// closed at the shared-evaluator level; mcp_dynamic_policy_handler_test.go
// carries the caller-specific version through the handler's own
// evaluateCondition.
// ---------------------------------------------------------------------------

func TestConditionEvaluator_AllTenOperatorsLiveOnEveryInstance(t *testing.T) {
	e := ConditionEvaluator{}

	tests := []struct {
		operator string
		cond     MatchCondition
		fields   map[string]any
		want     bool
	}{
		{"equals", MatchCondition{Field: "f", Operator: "equals", Value: "x"}, map[string]any{"f": "x"}, true},
		{"not_equals", MatchCondition{Field: "f", Operator: "not_equals", Value: "y"}, map[string]any{"f": "x"}, true},
		{"contains", MatchCondition{Field: "f", Operator: "contains", Value: "x"}, map[string]any{"f": "xyz"}, true},
		{"not_contains", MatchCondition{Field: "f", Operator: "not_contains", Value: "q"}, map[string]any{"f": "xyz"}, true},
		{"contains_any", MatchCondition{Field: "f", Operator: "contains_any", Value: []any{"q", "x"}}, map[string]any{"f": "xyz"}, true},
		{"greater_than", MatchCondition{Field: "f", Operator: "greater_than", Value: 1.0}, map[string]any{"f": 2.0}, true},
		{"less_than", MatchCondition{Field: "f", Operator: "less_than", Value: 3.0}, map[string]any{"f": 2.0}, true},
		{"regex", MatchCondition{Field: "f", Operator: "regex", Value: "^xy"}, map[string]any{"f": "xyz"}, true},
		{"in", MatchCondition{Field: "f", Operator: "in", Value: []any{"a", "x"}}, map[string]any{"f": "x"}, true},
		{"not_in", MatchCondition{Field: "f", Operator: "not_in", Value: []any{"a", "b"}}, map[string]any{"f": "x"}, true},
	}

	if len(tests) != 10 {
		t.Fatalf("expected exactly 10 operators under test, got %d — update this test if the operator union changes", len(tests))
	}

	for _, tt := range tests {
		t.Run(tt.operator, func(t *testing.T) {
			got := e.Match(tt.cond, fieldMapResolver(tt.fields), nil)
			if got != tt.want {
				t.Errorf("operator %q must evaluate for real on every ConditionEvaluator instance, Match = %v, want %v", tt.operator, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unknown operator -> false, and ReasonUnknownOperator recorded exactly
// once. The old per-caller logging hook is gone —
// #3296 Slice 2 replaced it with UnevaluableRecorder, injected per call
// rather than configured on the struct, so a corrupt row is counted instead
// of spamming a log line once per request.
// ---------------------------------------------------------------------------

func TestConditionEvaluator_UnknownOperator_ReturnsFalseAndRecordsReason(t *testing.T) {
	rec := &fakeRecorder{}
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "starts_with", Value: "x"}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "xyz"}), rec)
	if got {
		t.Fatalf("unknown operator must return false, got true")
	}
	if len(rec.reasons) != 1 || rec.reasons[0] != ReasonUnknownOperator {
		t.Fatalf("expected UnevaluableRecorder to fire exactly once with %q, got %v", ReasonUnknownOperator, rec.reasons)
	}
}

func TestConditionEvaluator_UnknownOperator_NilRecorderDoesNotPanic(t *testing.T) {
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "bogus", Value: "x"}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "x"}), nil)
	if got {
		t.Fatalf("unknown operator with nil recorder must still return false, got true")
	}
}

func TestConditionEvaluator_EmptyOperatorString_TreatedAsUnknown(t *testing.T) {
	// MapCondition never fails to extract an operator key (see its doc); a
	// missing "operator" key produces "" here, which must land on the
	// unknown-operator path exactly like 1b's own switch does for "".
	rec := &fakeRecorder{}
	e := ConditionEvaluator{}
	cond, ok := MapCondition(map[string]any{"field": "f", "value": "x"})
	if !ok {
		t.Fatalf("MapCondition must always return ok=true")
	}
	if cond.Operator != "" {
		t.Fatalf("expected empty operator, got %q", cond.Operator)
	}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "x"}), rec)
	if got {
		t.Fatalf("empty operator must be treated as unknown -> false, got true")
	}
	if len(rec.reasons) != 1 || rec.reasons[0] != ReasonUnknownOperator {
		t.Fatalf("expected UnevaluableRecorder to fire once with %q, got %v", ReasonUnknownOperator, rec.reasons)
	}
}

// ---------------------------------------------------------------------------
// Unevaluable-conditions recording (#3296 Slice 2 / epic #3293) — one test
// per Reason* constant this package itself emits. ReasonConditionsUnmarshalFailed
// and ReasonFieldUnresolved are recorded by orchestrator callers, not this
// package, and are covered by that package's own tests.
// ---------------------------------------------------------------------------

func TestConditionEvaluator_NonNumericOperand_RecordsReason_GreaterThan(t *testing.T) {
	rec := &fakeRecorder{}
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "greater_than", Value: -1.0}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "not-a-number"}), rec)
	if got {
		t.Fatalf("non-numeric operand must not match, got true")
	}
	if len(rec.reasons) != 1 || rec.reasons[0] != ReasonNonNumericOperand {
		t.Fatalf("expected UnevaluableRecorder to fire once with %q, got %v", ReasonNonNumericOperand, rec.reasons)
	}
}

func TestConditionEvaluator_NonNumericOperand_RecordsReason_LessThan(t *testing.T) {
	rec := &fakeRecorder{}
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "less_than", Value: 100.0}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "not-a-number"}), rec)
	if got {
		t.Fatalf("non-numeric operand must not match, got true")
	}
	if len(rec.reasons) != 1 || rec.reasons[0] != ReasonNonNumericOperand {
		t.Fatalf("expected UnevaluableRecorder to fire once with %q, got %v", ReasonNonNumericOperand, rec.reasons)
	}
}

func TestConditionEvaluator_NonNumericOperand_NotRecordedOnSuccessfulComparison(t *testing.T) {
	rec := &fakeRecorder{}
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "greater_than", Value: 3.0}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": 5.0}), rec)
	if !got {
		t.Fatalf("expected a match, got false")
	}
	if len(rec.reasons) != 0 {
		t.Fatalf("a genuinely evaluable comparison must not record anything, got %v", rec.reasons)
	}
}

func TestConditionEvaluator_NonStringPattern_RecordsReason(t *testing.T) {
	rec := &fakeRecorder{}
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "regex", Value: 42}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "42"}), rec)
	if got {
		t.Fatalf("non-string regex Value must not match, got true")
	}
	if len(rec.reasons) != 1 || rec.reasons[0] != ReasonNonStringPattern {
		t.Fatalf("expected UnevaluableRecorder to fire once with %q, got %v", ReasonNonStringPattern, rec.reasons)
	}
}

func TestConditionEvaluator_NonStringPattern_NotRecordedOnValidPattern(t *testing.T) {
	rec := &fakeRecorder{}
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "regex", Value: "^hel+o"}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "hello world"}), rec)
	if !got {
		t.Fatalf("expected a match, got false")
	}
	if len(rec.reasons) != 0 {
		t.Fatalf("a valid string pattern must not record anything, got %v", rec.reasons)
	}
}

// TestConditionEvaluator_MatchAll_EmptyConditionsVacuouslyMatch pins the
// restored semantics: AND over an empty set is true, so a policy with no
// conditions applies to everything. See condition_evaluator.go's "Withdrawn"
// doc section — a stricter "zero conditions never matches" behavior briefly
// shipped as convergence 6 and was reverted; this is not new behavior, it is
// the original one restored.
func TestConditionEvaluator_MatchAll_EmptyConditionsVacuouslyMatch(t *testing.T) {
	rec := &fakeRecorder{}
	e := ConditionEvaluator{}
	got := e.MatchAll(nil, fieldMapResolver(nil), rec)
	if !got {
		t.Fatalf("MatchAll(nil, ...) must be true (vacuous truth), got false")
	}
	if len(rec.reasons) != 0 {
		t.Fatalf("an empty condition list is a legitimate match, not an unevaluable one — expected no recorded reasons, got %v", rec.reasons)
	}
}

// TestConditionEvaluator_NilRecorder_EveryUnevaluablePathIsSafe drives every
// emit point in this file with recorder=nil to prove UnevaluableRecorder
// being unset never panics — the interface's central safety contract.
func TestConditionEvaluator_NilRecorder_EveryUnevaluablePathIsSafe(t *testing.T) {
	e := ConditionEvaluator{}
	resolver := fieldMapResolver(map[string]any{"f": "not-a-number"})

	e.Match(MatchCondition{Field: "f", Operator: "bogus"}, resolver, nil)
	e.Match(MatchCondition{Field: "f", Operator: "greater_than", Value: -1.0}, resolver, nil)
	e.Match(MatchCondition{Field: "f", Operator: "less_than", Value: 100.0}, resolver, nil)
	e.Match(MatchCondition{Field: "f", Operator: "regex", Value: 42}, resolver, nil)
	e.MatchAll(nil, resolver, nil)
}

// ---------------------------------------------------------------------------
// Regex: invalid pattern must not panic; non-string Value never matches
// (#3296 convergence 4 — string-required on every caller now, including the
// former 1a stringify-and-compile holdout).
// ---------------------------------------------------------------------------

func TestConditionEvaluator_Regex_InvalidPatternDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("invalid regex pattern must not panic, got panic: %v", r)
		}
	}()
	e := ConditionEvaluator{}
	patterns := []string{"[", "(unclosed", "*invalid", "a{2,1}", "\\"}
	for _, p := range patterns {
		cond := MatchCondition{Field: "f", Operator: "regex", Value: p}
		got := e.Match(cond, fieldMapResolver(map[string]any{"f": "hello"}), nil)
		if got {
			t.Errorf("invalid pattern %q must not match, got true", p)
		}
	}
}

func TestConditionEvaluator_Regex_NonStringValue_NoMatch(t *testing.T) {
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "regex", Value: 42}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "42"}), nil)
	if got {
		t.Fatalf("non-string regex Value must not match on any caller (string-required everywhere), got true")
	}
}

// TestConditionEvaluator_Regex_NonStringValue_1a_NoLongerStringifies pins the
// convergence directly: 1a's legacy fmt.Sprint-and-compile fallback for a
// non-string regex Value (dynamic_policy_engine.go:634, `value: 1.5` used to
// compile as pattern "1.5", where `.` is a wildcard) is gone. The same
// (condition, request) pair that used to match under 1a's old behavior must
// now be a non-match, identically to every other caller.
func TestConditionEvaluator_Regex_NonStringValue_1a_NoLongerStringifies(t *testing.T) {
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "regex", Value: 123}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "value is 123 here"}), nil)
	if got {
		t.Fatalf("a non-string regex Value must not compile-and-match, even on the former 1a call site — expected false, got true")
	}
}

// ---------------------------------------------------------------------------
// MapCondition adapter — replicates 1b's exact key lookup.
// ---------------------------------------------------------------------------

func TestMapCondition_ExactKeyShape_1b(t *testing.T) {
	m := map[string]any{
		"field":    "risk_score",
		"operator": "greater_than",
		"value":    0.8,
	}
	cond, ok := MapCondition(m)
	if !ok {
		t.Fatalf("MapCondition must return ok=true")
	}
	if cond.Field != "risk_score" || cond.Operator != "greater_than" || cond.Value != 0.8 {
		t.Fatalf("MapCondition(%v) = %+v, want Field=risk_score Operator=greater_than Value=0.8", m, cond)
	}
}

func TestMapCondition_MissingKeys_SilentlyZeroValue(t *testing.T) {
	// 1b's `field, _ := cond["field"].(string)` never bails on a missing key
	// — it silently produces the zero value and proceeds. MapCondition must
	// reproduce that: ok=true even when every key is absent.
	cond, ok := MapCondition(map[string]any{})
	if !ok {
		t.Fatalf("MapCondition must return ok=true even for an empty map (1b never bails)")
	}
	if cond.Field != "" || cond.Operator != "" || cond.Value != nil {
		t.Fatalf("expected zero-value MatchCondition for an empty map, got %+v", cond)
	}
}

func TestMapCondition_WrongTypeKeys_SilentlyZeroValue(t *testing.T) {
	// A "field" that isn't a string (e.g. a number) must not panic — the
	// type assertion's ok=false path silently zero-values it, matching 1b.
	m := map[string]any{"field": 123, "operator": 456, "value": "x"}
	cond, ok := MapCondition(m)
	if !ok {
		t.Fatalf("MapCondition must return ok=true")
	}
	if cond.Field != "" || cond.Operator != "" {
		t.Fatalf("expected Field/Operator to silently zero-value on type mismatch, got %+v", cond)
	}
	if cond.Value != "x" {
		t.Fatalf("Value is untyped passthrough — expected \"x\", got %v", cond.Value)
	}
}

// ---------------------------------------------------------------------------
// Convergence 2 — contains_any: every list item is stringified now (1e's
// former behavior), on every caller. 1b's legacy silent-skip of a
// non-string item is gone.
// ---------------------------------------------------------------------------

func TestConditionEvaluator_ContainsAny_NonStringListItem_AlwaysStringified(t *testing.T) {
	e := ConditionEvaluator{}
	// The list contains a non-string item (5); it must be stringified to "5"
	// and matched — on every caller now, not only the former 1e call site.
	cond := MatchCondition{Field: "f", Operator: "contains_any", Value: []any{5, "zzz"}}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "value is 5 here"}), nil)
	if !got {
		t.Fatalf("contains_any must stringify a non-string list item and match on every caller (#3296 convergence 2), got false")
	}
}

// TestConditionEvaluator_ContainsAny_NonStringListItem_1b_NoLongerSkips pins
// the convergence directly against 1b's specific legacy input/output: a
// query containing "0.9" against a contains_any list of [0.9,
// "unrelated-term"] used to be a non-match on the database engine (1b
// silently skipped the float item); it must now match.
func TestConditionEvaluator_ContainsAny_NonStringListItem_1b_NoLongerSkips(t *testing.T) {
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "contains_any", Value: []any{0.9, "unrelated-term"}}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "risk score is 0.9 today"}), nil)
	if !got {
		t.Fatalf("contains_any must match a stringified non-string list item, even on the former 1b call site — expected true, got false")
	}
}

// TestConditionEvaluator_ContainsAny_GoNativeStringSlice pins the resolved
// (never a caller-supplied knob) list-shape half of the contains_any
// behavior: legacy PolicyService.evaluateOperator's contains_any arm only
// type-asserted conditionValue.([]interface{}) (policy_api_service.go:659),
// so a Go-native []string Value would have fallen through to an
// unconditional false there. The shared evaluator accepts []string uniformly
// (same as it does for in/not_in), which is a real widening in the abstract
// — but verified unreachable in production for the policy-test call site:
// PolicyService.TestPolicy is the only entry point that reaches this
// operator, and it always sources policy.Conditions through
// PolicyRepository.GetByID's JSON round trip (policy_api_repository.go:191),
// which decodes a JSON array into []interface{}, never a Go []string. This
// test exists so that claim is executable, not only a doc comment.
func TestConditionEvaluator_ContainsAny_GoNativeStringSlice(t *testing.T) {
	e := ConditionEvaluator{}
	cond := MatchCondition{Field: "f", Operator: "contains_any", Value: []string{"zzz", "wor"}}
	got := e.Match(cond, fieldMapResolver(map[string]any{"f": "hello world"}), nil)
	if !got {
		t.Fatalf("contains_any must match a Go-native []string Value (documented, verified-unreachable-in-production widening for the policy-test caller), got false")
	}
}

// ---------------------------------------------------------------------------
// MatchAll: AND semantics, short-circuit on first non-match.
// ---------------------------------------------------------------------------

func TestConditionEvaluator_MatchAll_AndSemantics(t *testing.T) {
	e := ConditionEvaluator{}
	conds := []MatchCondition{
		{Field: "role", Operator: "equals", Value: "admin"},
		{Field: "risk", Operator: "greater_than", Value: 0.5},
	}
	fields := map[string]any{"role": "admin", "risk": 0.9}
	if !e.MatchAll(conds, fieldMapResolver(fields), nil) {
		t.Fatalf("expected all conditions to match")
	}

	fields["risk"] = 0.1
	if e.MatchAll(conds, fieldMapResolver(fields), nil) {
		t.Fatalf("expected MatchAll to fail once one condition fails")
	}
}

func TestConditionEvaluator_MatchAll_NilResolveDoesNotPanic(t *testing.T) {
	e := ConditionEvaluator{}
	conds := []MatchCondition{{Field: "f", Operator: "equals", Value: "x"}}
	got := e.MatchAll(conds, nil, nil)
	if got {
		t.Fatalf("nil resolver means every field is absent -> Sprint(nil) != \"x\" -> false, got true")
	}
}
