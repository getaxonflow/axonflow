// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"strings"
	"testing"

	"axonflow/platform/shared/legacyfreeze"
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

// TestMCPToolCreateOverride_AnswersTheFreezeWhateverTheArgs: from v11 the tool
// writes nothing (#4252), so its arguments decide nothing: a session with a real
// identity is answered the freeze for every argument shape, including the ones
// that used to fail validation.
func TestMCPToolCreateOverride_AnswersTheFreezeWhateverTheArgs(t *testing.T) {
	session := &mcpSession{tenantID: "t-1", userID: "u-1", userEmail: "dev@corp.example"}
	for _, args := range []map[string]interface{}{
		{"policy_type": "static", "override_reason": "x"},
		{"policy_id": "p-1", "override_reason": "x"},
		{"policy_id": "p-1", "policy_type": "static"},
		{"policy_id": "", "policy_type": "", "override_reason": ""},
	} {
		_, err := mcpToolCreateOverride(session, args)
		if err == nil || !strings.HasPrefix(err.Error(), legacyfreeze.ErrCode+": ") {
			t.Errorf("args %v: err = %v, want the freeze", args, err)
		}
	}
}

// TestMCPToolDeleteOverride_AnswersTheFreezeWithoutAnID: delete answers the
// freeze for every caller and argument set, including a missing override_id.
func TestMCPToolDeleteOverride_AnswersTheFreezeWithoutAnID(t *testing.T) {
	_, err := mcpToolDeleteOverride(&mcpSession{tenantID: "t-1"}, map[string]interface{}{})
	if err == nil || !strings.HasPrefix(err.Error(), legacyfreeze.ErrCode+": ") {
		t.Fatalf("err = %v, want the freeze", err)
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
