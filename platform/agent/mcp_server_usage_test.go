// Copyright 2025-2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package agent

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRecordMCPToolCallUsage_Guards verifies the metering call is a safe no-op
// (no panic, no goroutine touching a nil DB) when identity or the usage DB is
// missing — an unauthenticated or misconfigured call must never crash the
// handler or write a NULL-org row.
func TestRecordMCPToolCallUsage_Guards(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/mcp-server", nil)
	result := map[string]interface{}{"allowed": true, "policies_evaluated": 1}

	// Ensure usageDB is nil for this test regardless of ambient state.
	prev := usageDB
	usageDB = nil
	t.Cleanup(func() { usageDB = prev })

	// nil session — must return without spawning a recorder.
	recordMCPToolCallUsage(req, nil, "check_policy", result, nil, time.Now())

	// empty org — RLS-scoped write is impossible; must no-op.
	recordMCPToolCallUsage(req, &mcpSession{orgID: ""}, "check_policy", result, nil, time.Now())

	// nil usageDB with a valid session — still a no-op (no goroutine, no panic).
	recordMCPToolCallUsage(req, &mcpSession{orgID: "org-x", clientID: "c"}, "check_policy", result, nil, time.Now())
}

// TestMCPUsageMetrics verifies extraction of governance metrics from a
// check_policy / check_output tool result map (#2758). These feed the
// policies_evaluated / policy_violations columns of the usage_events row.
func TestMCPUsageMetrics(t *testing.T) {
	tests := []struct {
		name           string
		result         interface{}
		wantEvaluated  int
		wantViolations int
	}{
		{"nil result", nil, 0, 0},
		{"non-map result", "not a map", 0, 0},
		{
			name:           "allow with policies evaluated",
			result:         map[string]interface{}{"allowed": true, "policies_evaluated": 3},
			wantEvaluated:  3,
			wantViolations: 0,
		},
		{
			name:           "block counts one violation",
			result:         map[string]interface{}{"allowed": false, "policies_evaluated": 2},
			wantEvaluated:  2,
			wantViolations: 1,
		},
		{
			name:           "block without policies_evaluated key",
			result:         map[string]interface{}{"allowed": false},
			wantEvaluated:  0,
			wantViolations: 1,
		},
		{
			name:           "non-governance tool (no keys)",
			result:         map[string]interface{}{"policies": []string{"a", "b"}},
			wantEvaluated:  0,
			wantViolations: 0,
		},
		{
			// Defensive: a non-int policies_evaluated (e.g. deserialized as
			// float64) must not panic and must not be counted.
			name:           "wrong-typed policies_evaluated ignored",
			result:         map[string]interface{}{"allowed": true, "policies_evaluated": float64(5)},
			wantEvaluated:  0,
			wantViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEval, gotViol := mcpUsageMetrics(tt.result)
			if gotEval != tt.wantEvaluated {
				t.Errorf("policiesEvaluated = %d, want %d", gotEval, tt.wantEvaluated)
			}
			if gotViol != tt.wantViolations {
				t.Errorf("policyViolations = %d, want %d", gotViol, tt.wantViolations)
			}
		})
	}
}

// TestBuildMCPToolCallUsageEvent verifies the api_call usage_events row built
// for a served MCP-server tools/call carries the session's license org/client
// (the RLS scope key the portal Usage page also filters on), the request
// primitives, and the correct status derivation (#2758).
func TestBuildMCPToolCallUsageEvent(t *testing.T) {
	session := &mcpSession{
		orgID:    "design-partner-eval",
		tenantID: "design-partner-eval",
		clientID: "cs_plugin_key",
	}

	t.Run("clean allow → 200, no violation, org scoped", func(t *testing.T) {
		result := map[string]interface{}{"allowed": true, "policies_evaluated": 4}
		ev := buildMCPToolCallUsageEvent(session, result, nil,
			"POST", "/api/v1/mcp-server", "agent-abc", 12)

		if ev.OrgID != "design-partner-eval" {
			t.Errorf("OrgID = %q, want design-partner-eval (RLS scope must match portal session)", ev.OrgID)
		}
		if ev.ClientID != "cs_plugin_key" {
			t.Errorf("ClientID = %q, want cs_plugin_key", ev.ClientID)
		}
		if ev.InstanceType != "agent" {
			t.Errorf("InstanceType = %q, want agent", ev.InstanceType)
		}
		if ev.InstanceID != "agent-abc" {
			t.Errorf("InstanceID = %q, want agent-abc", ev.InstanceID)
		}
		if ev.HTTPMethod != "POST" || ev.HTTPPath != "/api/v1/mcp-server" {
			t.Errorf("HTTP = %s %s, want POST /api/v1/mcp-server", ev.HTTPMethod, ev.HTTPPath)
		}
		if ev.HTTPStatusCode != http.StatusOK {
			t.Errorf("HTTPStatusCode = %d, want 200", ev.HTTPStatusCode)
		}
		if ev.LatencyMs != 12 {
			t.Errorf("LatencyMs = %d, want 12", ev.LatencyMs)
		}
		if ev.PoliciesEvaluated != 4 || ev.PolicyViolations != 0 {
			t.Errorf("metrics = (%d,%d), want (4,0)", ev.PoliciesEvaluated, ev.PolicyViolations)
		}
	})

	t.Run("block decision → 200 (successful decision), one violation", func(t *testing.T) {
		result := map[string]interface{}{"allowed": false, "policies_evaluated": 2}
		ev := buildMCPToolCallUsageEvent(session, result, nil,
			"POST", "/api/v1/mcp-server", "agent-abc", 5)
		if ev.HTTPStatusCode != http.StatusOK {
			t.Errorf("a block is a successful decision: HTTPStatusCode = %d, want 200", ev.HTTPStatusCode)
		}
		if ev.PolicyViolations != 1 {
			t.Errorf("PolicyViolations = %d, want 1", ev.PolicyViolations)
		}
	})

	t.Run("governance tool error → 500 (fail-closed deny)", func(t *testing.T) {
		ev := buildMCPToolCallUsageEvent(session, nil, errors.New("policy evaluation temporarily unavailable"),
			"POST", "/api/v1/mcp-server", "agent-abc", 30)
		if ev.HTTPStatusCode != http.StatusInternalServerError {
			t.Errorf("HTTPStatusCode = %d, want 500 for fail-closed tool error", ev.HTTPStatusCode)
		}
	})
}
