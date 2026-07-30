// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"
	"time"
)

// mustTime parses an RFC3339 timestamp or fails the test.
func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("bad test timestamp %q: %v", s, err)
	}
	return ts
}

// --- Off-hours (timezone-anchored business-hours window) -------------------

func TestEvaluateTimeAccess_OffHoursWIB(t *testing.T) {
	handler := NewMCPDynamicPolicyHandler(nil)

	// Off-hours alert: outside 07:00–22:00 Asia/Jakarta (WIB, UTC+7).
	policy := DynamicPolicy{
		ID:   "acme_off_hours",
		Name: "Off-Hours Access Alert",
		Type: "time-access",
		Conditions: []PolicyCondition{
			{Field: "timezone", Operator: "equals", Value: "Asia/Jakarta"},
			{Field: "business_hours_start", Operator: "equals", Value: float64(7)},
			{Field: "business_hours_end", Operator: "equals", Value: float64(22)},
		},
		Actions: []PolicyAction{{Type: "alert", Config: map[string]interface{}{"reason": "Off-hours merchant data access"}}},
	}

	tests := []struct {
		name        string
		utc         string // request instant in UTC
		wantMatch   bool
		wantAllowed bool // alert disposition keeps the request allowed
	}{
		// 02:00 WIB == 19:00 UTC prior day → off-hours.
		{"2am WIB off-hours", "2026-06-04T19:00:00Z", true, true},
		// 09:00 WIB == 02:00 UTC → in business hours.
		{"9am WIB in-hours", "2026-06-05T02:00:00Z", false, true},
		// 21:59 WIB == 14:59 UTC → in business hours (end is exclusive at 22).
		{"9:59pm WIB in-hours", "2026-06-05T14:59:00Z", false, true},
		// 22:00 WIB == 15:00 UTC → off-hours (end exclusive).
		{"10pm WIB off-hours", "2026-06-05T15:00:00Z", true, true},
		// 06:59 WIB == 23:59 UTC prior day → off-hours (before start).
		{"6:59am WIB off-hours", "2026-06-04T23:59:00Z", true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := MCPPolicyEvaluationRequest{
				TenantID:      "acme-ops",
				ConnectorName: "acme-crm",
				UserID:        "leader-1",
				RequestTime:   mustTime(t, tc.utc),
			}
			matched, allowed, reason := handler.evaluateTimeAccess(policy, req)
			if matched != tc.wantMatch {
				t.Errorf("matched=%v, want %v (reason=%q)", matched, tc.wantMatch, reason)
			}
			if allowed != tc.wantAllowed {
				t.Errorf("allowed=%v, want %v", allowed, tc.wantAllowed)
			}
			if matched && reason == "" {
				t.Error("expected a non-empty reason on match")
			}
		})
	}
}

func TestEvaluateTimeAccess_OffHoursRequireApprovalDenies(t *testing.T) {
	handler := NewMCPDynamicPolicyHandler(nil)
	policy := DynamicPolicy{
		Type: "time-access",
		Conditions: []PolicyCondition{
			{Field: "timezone", Operator: "equals", Value: "Asia/Jakarta"},
			{Field: "business_hours_start", Operator: "equals", Value: float64(7)},
			{Field: "business_hours_end", Operator: "equals", Value: float64(22)},
		},
		Actions: []PolicyAction{{Type: "require_approval"}},
	}
	// 03:00 WIB == 20:00 UTC prior day → off-hours; require_approval should hold.
	req := MCPPolicyEvaluationRequest{TenantID: "t", ConnectorName: "c", RequestTime: mustTime(t, "2026-06-04T20:00:00Z")}
	matched, allowed, _ := handler.evaluateTimeAccess(policy, req)
	if !matched || allowed {
		t.Errorf("require_approval off-hours should match and hold: matched=%v allowed=%v", matched, allowed)
	}
}

func TestEvaluateTimeAccess_LegacyHourPathPreserved(t *testing.T) {
	handler := NewMCPDynamicPolicyHandler(nil)
	// No timezone/business_hours declared → legacy UTC hour comparison path.
	policy := DynamicPolicy{
		Type: "time-access",
		Conditions: []PolicyCondition{
			{Field: "hour", Operator: "greater_than", Value: float64(8)},
		},
	}
	// This exercises the legacy branch without asserting wall-clock-dependent
	// behavior: it must not panic and must return a boolean triple.
	req := MCPPolicyEvaluationRequest{TenantID: "t", ConnectorName: "c"}
	_, _, _ = handler.evaluateTimeAccess(policy, req)
}

func TestParseBusinessHoursWindow_NotDeclared(t *testing.T) {
	policy := DynamicPolicy{
		Type:       "time-access",
		Conditions: []PolicyCondition{{Field: "hour", Operator: "greater_than", Value: float64(8)}},
	}
	if _, ok := parseBusinessHoursWindow(policy); ok {
		t.Error("expected no business-hours window for a legacy hour policy")
	}
}

func TestOutsideBusinessHours_InvalidTimezoneFallsBack(t *testing.T) {
	w := businessHoursWindow{timezone: "Not/AZone", start: 7, end: 22, hasStart: true, hasEnd: true}
	// 03:00 UTC is in [7,22)? No → outside. Falls back to the instant's own
	// location (UTC here) rather than treating it as in-hours.
	at := mustTime(t, "2026-06-05T03:00:00Z")
	if !outsideBusinessHours(w, at) {
		t.Error("expected 03:00 UTC to be outside business hours under fallback")
	}
}

// --- Bulk retrieval ---------------------------------------------------------

func TestEvaluateAnomaly_BulkRetrieval(t *testing.T) {
	handler := NewMCPDynamicPolicyHandler(nil)
	policy := DynamicPolicy{
		ID:   "acme_bulk",
		Name: "Bulk Retrieval Guard",
		Type: "anomaly",
		Conditions: []PolicyCondition{
			{Field: "session_record_count", Operator: "greater_than", Value: float64(500)},
		},
		Actions: []PolicyAction{{Type: "require_approval", Config: map[string]interface{}{"reason": "Bulk merchant retrieval requires approval"}}},
	}

	tests := []struct {
		name      string
		count     interface{}
		inMeta    bool
		wantMatch bool
	}{
		{"under threshold", float64(499), true, false},
		{"at threshold (exclusive)", float64(500), true, false},
		{"over threshold", float64(501), true, true},
		{"well over", float64(5000), true, true},
		{"string numeric over", "750", true, true},
		{"signal absent", nil, false, false},
		{"from parameters", float64(900), false, true}, // provided via Parameters instead
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := MCPPolicyEvaluationRequest{TenantID: "acme-fintech", ConnectorName: "acme-crm", UserID: "leader-2"}
			if tc.count != nil {
				if tc.inMeta {
					req.Metadata = map[string]interface{}{"session_record_count": tc.count}
				} else {
					req.Parameters = map[string]interface{}{"session_record_count": tc.count}
				}
			}
			matched, allowed, reason := handler.evaluateAnomaly(policy, req)
			if matched != tc.wantMatch {
				t.Errorf("matched=%v, want %v (reason=%q)", matched, tc.wantMatch, reason)
			}
			if tc.wantMatch {
				if allowed {
					t.Error("require_approval bulk match should hold the request (allowed=false)")
				}
				if reason == "" {
					t.Error("expected a reason on bulk match")
				}
			}
		})
	}
}

// --- Volume anomaly (3x baseline) ------------------------------------------

func TestEvaluateAnomaly_VolumeMultiplier(t *testing.T) {
	handler := NewMCPDynamicPolicyHandler(nil)
	policy := DynamicPolicy{
		ID:   "acme_volume",
		Name: "3x Volume Anomaly",
		Type: "anomaly",
		Conditions: []PolicyCondition{
			{Field: "volume_ratio", Operator: "greater_or_equal", Value: float64(3)},
		},
		Actions: []PolicyAction{{Type: "alert"}},
	}

	tests := []struct {
		name      string
		session   interface{}
		baseline  interface{}
		wantMatch bool
	}{
		{"2x below threshold", float64(200), float64(100), false},
		{"exactly 3x", float64(300), float64(100), true},
		{"5x", float64(500), float64(100), true},
		{"zero baseline (cold start)", float64(500), float64(0), false},
		{"missing baseline", float64(500), nil, false},
		{"missing session", nil, float64(100), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			meta := map[string]interface{}{}
			if tc.session != nil {
				meta["session_volume"] = tc.session
			}
			if tc.baseline != nil {
				meta["baseline_volume"] = tc.baseline
			}
			req := MCPPolicyEvaluationRequest{TenantID: "acme-ops", ConnectorName: "bigquery", UserID: "leader-3", Metadata: meta}
			matched, allowed, _ := handler.evaluateAnomaly(policy, req)
			if matched != tc.wantMatch {
				t.Errorf("matched=%v, want %v", matched, tc.wantMatch)
			}
			if tc.wantMatch && !allowed {
				t.Error("alert disposition should keep the request allowed")
			}
		})
	}
}

func TestEvaluateAnomaly_NoConditionsDoesNotMatch(t *testing.T) {
	handler := NewMCPDynamicPolicyHandler(nil)
	policy := DynamicPolicy{Type: "anomaly"}
	req := MCPPolicyEvaluationRequest{TenantID: "t", ConnectorName: "c"}
	if matched, allowed, _ := handler.evaluateAnomaly(policy, req); matched || !allowed {
		t.Errorf("empty anomaly policy must not match: matched=%v allowed=%v", matched, allowed)
	}
}

func TestEvaluateAnomaly_CombinedConditionsAND(t *testing.T) {
	handler := NewMCPDynamicPolicyHandler(nil)
	// Both bulk AND volume must hold.
	policy := DynamicPolicy{
		Type: "anomaly",
		Conditions: []PolicyCondition{
			{Field: "session_record_count", Operator: "greater_than", Value: float64(500)},
			{Field: "volume_ratio", Operator: "greater_or_equal", Value: float64(3)},
		},
		Actions: []PolicyAction{{Type: "block"}},
	}

	// Only bulk satisfied, volume normal → no match (AND).
	req := MCPPolicyEvaluationRequest{
		TenantID: "t", ConnectorName: "c",
		Metadata: map[string]interface{}{
			"session_record_count": float64(900),
			"session_volume":       float64(100),
			"baseline_volume":      float64(100),
		},
	}
	if matched, _, _ := handler.evaluateAnomaly(policy, req); matched {
		t.Error("AND semantics: should not match when only bulk satisfied")
	}

	// Both satisfied → match and block.
	req.Metadata["session_volume"] = float64(400)
	matched, allowed, _ := handler.evaluateAnomaly(policy, req)
	if !matched || allowed {
		t.Errorf("both satisfied → block: matched=%v allowed=%v", matched, allowed)
	}
}

// --- Dispatch + filter integration -----------------------------------------

func TestEvaluatePolicy_DispatchesAnomaly(t *testing.T) {
	handler := NewMCPDynamicPolicyHandler(nil)
	policy := DynamicPolicy{
		Type:       "anomaly",
		Conditions: []PolicyCondition{{Field: "session_record_count", Operator: "greater_than", Value: float64(500)}},
		Actions:    []PolicyAction{{Type: "require_approval"}},
	}
	req := MCPPolicyEvaluationRequest{
		TenantID: "t", ConnectorName: "c",
		Metadata: map[string]interface{}{"session_record_count": float64(600)},
	}
	matched, allowed, _ := handler.evaluatePolicy(policy, req)
	if !matched || allowed {
		t.Errorf("evaluatePolicy should dispatch anomaly type: matched=%v allowed=%v", matched, allowed)
	}
}

func TestGetPoliciesForMCP_IncludesAnomalyAndTimeAccess(t *testing.T) {
	policies := []DynamicPolicy{
		{ID: "a", Type: "anomaly", Enabled: true, TenantID: "acme-ops"},
		{ID: "t", Type: "time-access", Enabled: true, TenantID: "acme-ops"},
		{ID: "x", Type: "content", Enabled: true, TenantID: "acme-ops"}, // #3061: now MCP-related
		{ID: "other", Type: "anomaly", Enabled: true, TenantID: "different-tenant"},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	got, err := handler.getPoliciesForMCP(MCPPolicyEvaluationRequest{TenantID: "acme-ops", ConnectorName: "acme-crm"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ids := map[string]bool{}
	for _, p := range got {
		ids[p.ID] = true
	}
	if !ids["a"] || !ids["t"] {
		t.Errorf("expected anomaly + time-access policies included, got %v", ids)
	}
	// #3061 CONTRACT CHANGE (deliberate): this assertion was inverted. It
	// pinned the defect — "content" is the type axonflow_create_tenant_policy
	// writes and the type POST /api/v1/policies defaults to, so excluding it
	// meant every user-authored tenant policy was dropped before evaluation
	// and could never enforce on the MCP tool-governance plane, while the tool
	// promised "It will apply to subsequent governed calls."
	if !ids["x"] {
		t.Error("content policy must be included on the MCP path (#3061)")
	}
	// The TENANT filter is untouched by that change and must still isolate.
	if ids["other"] {
		t.Error("policy for a different tenant should be excluded")
	}
}

// --- Numeric helper edge cases ---------------------------------------------

func TestNumericCompare_Operators(t *testing.T) {
	cases := []struct {
		a, b float64
		op   string
		want bool
	}{
		{5, 3, "greater_than", true},
		{3, 3, "greater_than", false},
		{3, 3, "greater_or_equal", true},
		{2, 3, "less_than", true},
		{3, 3, "less_or_equal", true},
		{3, 3, "equals", true},
		{3, 3, "unknown_op", false},
	}
	for _, c := range cases {
		if got := numericCompare(c.a, c.b, c.op); got != c.want {
			t.Errorf("numericCompare(%v,%v,%q)=%v want %v", c.a, c.b, c.op, got, c.want)
		}
	}
}

func TestToFloat_Coercions(t *testing.T) {
	cases := []struct {
		in   interface{}
		want float64
		ok   bool
	}{
		{float64(3.5), 3.5, true},
		{int(7), 7, true},
		{int64(9), 9, true},
		{"12.5", 12.5, true},
		{"notnum", 0, false},
		{true, 0, false},
		{nil, 0, false},
	}
	for _, c := range cases {
		got, ok := toFloat(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("toFloat(%v)=(%v,%v) want (%v,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestActionDenies(t *testing.T) {
	for _, a := range []string{"block", "require_approval"} {
		if !actionDenies(a) {
			t.Errorf("action %q should deny", a)
		}
	}
	for _, a := range []string{"alert", "warn", "log", ""} {
		if actionDenies(a) {
			t.Errorf("action %q should not deny", a)
		}
	}
}
