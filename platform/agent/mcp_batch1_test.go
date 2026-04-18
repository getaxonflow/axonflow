// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"strings"
	"testing"
)

// TestMCPToolExplainDecision_RejectsMissingArg verifies input validation
// runs before the proxy call — a missing decision_id returns a clean
// error rather than a proxy failure.
func TestMCPToolExplainDecision_RejectsMissingArg(t *testing.T) {
	session := &mcpSession{tenantID: "t-1", userID: "u-1"}
	_, err := mcpToolExplainDecision(session, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing decision_id")
	}
	if !strings.Contains(err.Error(), "decision_id") {
		t.Errorf("error = %v, want substring 'decision_id'", err)
	}
}

func TestMCPToolExplainDecision_RejectsEmptyString(t *testing.T) {
	session := &mcpSession{tenantID: "t-1"}
	_, err := mcpToolExplainDecision(session, map[string]interface{}{"decision_id": ""})
	if err == nil {
		t.Fatal("expected error for empty decision_id")
	}
}

func TestMCPToolCreateOverride_RejectsMissingRequired(t *testing.T) {
	session := &mcpSession{tenantID: "t-1", userID: "u-1"}

	cases := []struct {
		name string
		args map[string]interface{}
	}{
		{"no policy_id", map[string]interface{}{"policy_type": "static", "override_reason": "x"}},
		{"no policy_type", map[string]interface{}{"policy_id": "p-1", "override_reason": "x"}},
		{"no override_reason", map[string]interface{}{"policy_id": "p-1", "policy_type": "static"}},
		{"all empty strings", map[string]interface{}{"policy_id": "", "policy_type": "", "override_reason": ""}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mcpToolCreateOverride(session, tc.args)
			if err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

func TestMCPToolDeleteOverride_RejectsMissingArg(t *testing.T) {
	session := &mcpSession{tenantID: "t-1"}
	_, err := mcpToolDeleteOverride(session, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing override_id")
	}
}

// TestMCPToolListOverrides_PassesThroughEmptyArgs verifies the handler
// handles zero-arg invocation (list all) without erroring before the
// proxy call — the proxy call itself will fail because orchestrator is
// not configured in unit-test mode, which is fine.
func TestMCPToolListOverrides_DoesNotErrorOnEmpty(t *testing.T) {
	session := &mcpSession{tenantID: "t-1", userID: "u-1"}
	// Will error because orchestratorURL is unset in tests — we just
	// want to confirm it doesn't error in our own validation path.
	_, err := mcpToolListOverrides(session, map[string]interface{}{})
	if err == nil {
		t.Skip("orchestrator reachable in this env; validation path passes")
	}
	if !strings.Contains(err.Error(), "orchestrator") && !strings.Contains(err.Error(), "list") {
		t.Errorf("expected proxy error, got validation error: %v", err)
	}
}
