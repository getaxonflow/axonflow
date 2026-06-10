// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// The per-string masking replaces a matched span in place. When the string value
// is itself serialized JSON (the Claude Desktop proxy submits a whole tool result
// as one string), masking a value in a NON-string position (a bare number) yields
// invalid JSON and a downstream JSON consumer rejects the whole benign response.
// These tests pin that the redactor never emits invalid JSON, while keeping the
// common cases byte-identical.

// a 6-digit "code" pattern stands in for any broad numeric detector that can land
// on a bare JSON number.
func sixDigitPlan(strategy RedactionStrategy) []RedactionPlan {
	return []RedactionPlan{{
		Match:    PolicyMatch{PolicyID: "test_sixdigit"},
		Policy:   CompiledPolicy{PolicyID: "test_sixdigit", PatternStr: `\b\d{6}\b`, Category: CategoryPIIGlobal, Severity: SeverityMedium},
		Strategy: strategy,
	}}
}

func TestRedactor_JSONSafe_BareNumberStaysValidJSON(t *testing.T) {
	r := NewFieldRedactor()
	// The exact shape the Desktop proxy submits: a "statement" field whose value is
	// a serialized JSON object with the PII as a bare number.
	rows := []map[string]interface{}{
		{"statement": `{"period":"2026-Q2","avg_order_idr":369318,"orders":1320}`},
	}
	out, fields := r.applyToRows(rows, sixDigitPlan(StrategyMask))
	got := out.([]map[string]interface{})[0]["statement"].(string)

	if !json.Valid([]byte(got)) {
		t.Fatalf("redacted statement is NOT valid JSON: %s", got)
	}
	if len(fields) == 0 {
		t.Fatalf("expected the 6-digit value to be redacted, got none: %s", got)
	}
	if strings.Contains(got, "369318") {
		t.Errorf("the bare number was not redacted: %s", got)
	}
	// The masked number coerces to a quoted string; the rest of the document survives.
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(got), &obj); err != nil {
		t.Fatalf("unmarshal failed: %v (%s)", err, got)
	}
	if obj["period"] != "2026-Q2" || obj["orders"].(float64) != 1320 {
		t.Errorf("non-PII fields were corrupted: %s", got)
	}
}

func TestRedactor_JSONSafe_StringValueMaskedStaysValid(t *testing.T) {
	// A value that is ITSELF a JSON document is walked + re-serialized (so escaped-PII
	// in leaves is caught), which may normalize key order / whitespace — that is
	// acceptable for a value being redacted. The contract is: masked, valid JSON,
	// secret gone, other fields preserved. (Plain non-JSON string values are NOT
	// reparsed — see TestRedactor_JSONSafe_NonJSONUnchangedBehavior.)
	r := NewFieldRedactor()
	in := `{"ref":"order 123456 done","n":42}`
	rows := []map[string]interface{}{{"statement": in}}
	out, _ := r.applyToRows(rows, sixDigitPlan(StrategyMask))
	got := out.([]map[string]interface{})[0]["statement"].(string)

	if !json.Valid([]byte(got)) {
		t.Fatalf("not valid JSON: %s", got)
	}
	if strings.Contains(got, "123456") {
		t.Errorf("string-embedded number not masked: %s", got)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(got), &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["n"].(float64) != 42 || !strings.HasPrefix(obj["ref"].(string), "order 1") {
		t.Errorf("non-PII fields not preserved: %s", got)
	}
}

func TestRedactor_JSONSafe_NonJSONUnchangedBehavior(t *testing.T) {
	// A plain (non-JSON) string must keep the exact flat masking behavior.
	r := NewFieldRedactor()
	rows := []map[string]interface{}{{"note": "ticket 123456 escalated"}}
	out, _ := r.applyToRows(rows, sixDigitPlan(StrategyMask))
	got := out.([]map[string]interface{})[0]["note"].(string)
	if got != "ticket 1****6 escalated" {
		t.Errorf("non-JSON flat masking changed: %q", got)
	}
}

func TestRedactor_JSONSafe_NestedAndArray(t *testing.T) {
	r := NewFieldRedactor()
	in := `{"a":{"code":654321},"list":[111111,{"x":"v 222222"}]}`
	rows := []map[string]interface{}{{"statement": in}}
	out, _ := r.applyToRows(rows, sixDigitPlan(StrategyMask))
	got := out.([]map[string]interface{})[0]["statement"].(string)
	if !json.Valid([]byte(got)) {
		t.Fatalf("nested redaction produced invalid JSON: %s", got)
	}
	for _, n := range []string{"654321", "111111", "222222"} {
		if strings.Contains(got, n) {
			t.Errorf("number %s not redacted in nested/array doc: %s", n, got)
		}
	}
}

// applyToString path (plain string content) gets the same guard.
func TestRedactor_JSONSafe_ApplyToStringPath(t *testing.T) {
	r := NewFieldRedactor()
	in := `{"v":369318}`
	out, _ := r.applyToString(in, sixDigitPlan(StrategyMask))
	got := out.(string)
	if !json.Valid([]byte(got)) || strings.Contains(got, "369318") {
		t.Errorf("applyToString did not keep JSON valid + redacted: %s", got)
	}
}

// Escaped-digit evasion (R3 round 3): PII hidden behind \uXXXX escapes in a string
// leaf evades the raw-byte flat scan (so flatMasked==original), but a JSON consumer
// decodes it. jsonSafeRemask must still decode + redact it.
func TestRedactor_JSONSafe_EscapedDigitsCaught(t *testing.T) {
	r := NewFieldRedactor()
	// `\\u0033` is the literal 6 bytes backslash-u-0-0-3-3, so the raw JSON is
	// {"x":"123456"} — the raw-byte flat scan sees no 6-digit run, but the value
	// DECODES to "123456". The walk must decode + redact it.
	in := "{\"x\":\"12\\u0033456\"}"
	if json.Valid([]byte(in)) == false {
		t.Fatalf("test input not valid JSON: %s", in)
	}
	rows := []map[string]interface{}{{"statement": in}}
	out, _ := r.applyToRows(rows, sixDigitPlan(StrategyMask))
	got := out.([]map[string]interface{})[0]["statement"].(string)
	if !json.Valid([]byte(got)) {
		t.Fatalf("not valid JSON: %s", got)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(got), &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, _ := obj["x"].(string); v == "123456" || strings.Contains(v, "123456") {
		t.Errorf("FAIL-OPEN: escaped PII leaked once decoded: x=%q (out=%s)", v, got)
	}
}

func TestRedactJSONAware_RejectsNonJSON(t *testing.T) {
	r := NewFieldRedactor()
	if _, _, ok := r.redactJSONAware("not json 369318", map[string][]RedactionPlan{}); ok {
		t.Error("redactJSONAware should return ok=false for non-JSON input")
	}
	if _, _, ok := r.redactJSONAware(`{"a":1} trailing`, map[string][]RedactionPlan{}); ok {
		t.Error("redactJSONAware should reject trailing garbage")
	}
}

// Fail-closed invariant (R3): a pattern that matches ACROSS a JSON leaf boundary is
// masked by the flat path (breaking JSON) but found by NO single leaf. jsonSafeRemask
// must keep the redacted-but-invalid flat result, never return the clean original
// (which would be a fail-OPEN leak). No current sys_pii_* pattern matches across
// leaves, but the contract must hold.
func TestRedactor_JSONSafe_CrossLeafFailsClosed(t *testing.T) {
	r := NewFieldRedactor()
	crossLeafPlan := []RedactionPlan{{
		Match:    PolicyMatch{PolicyID: "test_pair"},
		Policy:   CompiledPolicy{PolicyID: "test_pair", PatternStr: `\d{6},\d{6}`, Category: CategoryPIIGlobal, Severity: SeverityMedium},
		Strategy: StrategyMask,
	}}
	in := `{"vals":[123456,789012]}`
	rows := []map[string]interface{}{{"statement": in}}
	out, _ := r.applyToRows(rows, crossLeafPlan)
	got := out.([]map[string]interface{})[0]["statement"].(string)
	if got == in {
		t.Fatalf("FAIL-OPEN: cross-leaf match returned the clean original (PII leaked): %s", got)
	}
	if strings.Contains(got, "123456,789012") {
		t.Errorf("the cross-leaf secret survived intact: %s", got)
	}
}

// Symmetric fail-closed (R3 round 2): when the per-leaf walk masks a DIFFERENT leaf
// AND a cross-leaf span also matched, the JSON-aware result must NOT be returned with
// the cross-leaf span intact — re-scan must catch the residue and fall back.
func TestRedactor_JSONSafe_CrossLeafWithOtherLeafFailsClosed(t *testing.T) {
	r := NewFieldRedactor()
	plans := []RedactionPlan{
		{Match: PolicyMatch{PolicyID: "p_single"}, Policy: CompiledPolicy{PolicyID: "p_single", PatternStr: `\b999999\b`, Category: CategoryPIIGlobal, Severity: SeverityMedium}, Strategy: StrategyMask},
		{Match: PolicyMatch{PolicyID: "p_pair"}, Policy: CompiledPolicy{PolicyID: "p_pair", PatternStr: `\d{6},\d{6}`, Category: CategoryPIIGlobal, Severity: SeverityMedium}, Strategy: StrategyMask},
	}
	in := `{"single":999999,"vals":[123456,789012]}`
	rows := []map[string]interface{}{{"statement": in}}
	out, _ := r.applyToRows(rows, plans)
	got := out.([]map[string]interface{})[0]["statement"].(string)
	if strings.Contains(got, "123456,789012") {
		t.Errorf("FAIL-OPEN: cross-leaf pair leaked while another leaf was masked: %s", got)
	}
}

// HTML characters in a redacted JSON value must not be gratuitously \u-escaped on the
// repair path (R3 low).
func TestRedactor_JSONSafe_NoHTMLEscapeOnRepair(t *testing.T) {
	r := NewFieldRedactor()
	in := `{"n":369318,"html":"a<b>c&d"}`
	rows := []map[string]interface{}{{"statement": in}}
	out, _ := r.applyToRows(rows, sixDigitPlan(StrategyMask))
	got := out.([]map[string]interface{})[0]["statement"].(string)
	if !json.Valid([]byte(got)) {
		t.Fatalf("not valid JSON: %s", got)
	}
	if strings.Contains(got, "\\u003c") || strings.Contains(got, "\\u0026") {
		t.Errorf("HTML was gratuitously \\u-escaped on repair: %s", got)
	}
	if !strings.Contains(got, "a<b>c&d") { // literal angle/amp preserved (not escaped)
		t.Errorf("unmatched HTML string was altered: %s", got)
	}
}
