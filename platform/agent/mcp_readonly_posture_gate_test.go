// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"

	"github.com/DATA-DOG/go-sqlmock"
)

// nilGlobalPolicyEngines disables both the dynamic and static engines for the
// duration of a test so evaluateInputPolicies is a no-op (returns an empty
// outcome → allowed). This lets the gate tests prove the read-only posture
// decision happens BEFORE, and independently of, normal policy evaluation.
func nilGlobalPolicyEngines(t *testing.T) {
	t.Helper()
	origEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	origEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	sharedpolicy.SetGlobalEngine(nil)
	t.Cleanup(func() {
		sharedpolicy.SetGlobalDynamicPolicyEvaluator(origEval)
		sharedpolicy.SetGlobalEngine(origEngine)
	})
}

func testMCPSession() *mcpSession {
	return &mcpSession{
		tenantID: "tenant-1", orgID: "org-1", clientID: "client-1",
		userID: "u1", userRole: "admin", userEmail: "u@e.com",
	}
}

// TestReadOnlyPosture_WriteBlockedAtGate is the red-on-revert guard for the core
// behaviour: with MCP_READ_ONLY on, a write-path tool call is blocked at the
// gate (before any policy engine runs) and a canonical "blocked" audit row is
// emitted. Removing the gate wiring leaves the INSERT expectation unmet.
func TestReadOnlyPosture_WriteBlockedAtGate(t *testing.T) {
	t.Setenv(EnvMCPReadOnly, "true")
	nilGlobalPolicyEngines(t) // prove the block does not depend on policy eval

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), "client-1", "tenant-1", "org-1",
			"mcp_check_policy", sqlmock.AnyArg(), sqlmock.AnyArg(),
			mcpVerdictBlocked, // canonical 'blocked'
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			PlaneMCP,
			nil, // correlation_id
			nil, // redacted_fields NULL on a block
			nil, // session_id NULL (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	resp, err := mcpToolCheckPolicy(context.Background(), testMCPSession(), map[string]interface{}{
		"connector_type": "claude_code.Bash",
		"statement":      "rm -rf /tmp/x",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, _ := resp.(map[string]interface{})
	if m["allowed"] != false {
		t.Errorf("expected allowed=false on write-path block, got %v", resp)
	}
	if m["read_only_posture"] != true {
		t.Errorf("expected read_only_posture=true marker, got %v", m["read_only_posture"])
	}
	if m["blocked_by"] != readOnlyPosturePolicyID {
		t.Errorf("expected blocked_by=%q, got %v", readOnlyPosturePolicyID, m["blocked_by"])
	}
	if _, ok := m["decision_id"].(string); !ok || m["decision_id"] == "" {
		t.Errorf("expected a non-empty decision_id, got %v", m["decision_id"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("write-path block did not emit a canonical audit row: %v", err)
	}
}

// TestReadOnlyPosture_ReadAllowedAtGate verifies a read-path call is NOT blocked
// by the posture and falls through to normal evaluation (which, with engines
// nil, allows it). No posture audit row is written for an allowed read.
func TestReadOnlyPosture_ReadAllowedAtGate(t *testing.T) {
	t.Setenv(EnvMCPReadOnly, "true")
	nilGlobalPolicyEngines(t)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()
	// No ExpectExec: an allowed read must not write any audit row here. An
	// unexpected INSERT makes sqlmock fail the test.

	resp, err := mcpToolCheckPolicy(context.Background(), testMCPSession(), map[string]interface{}{
		"connector_type": "claude_code.Read",
		"statement":      "/etc/hosts",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, _ := resp.(map[string]interface{})
	if m["allowed"] != true {
		t.Errorf("expected allowed=true on read-path under read-only posture, got %v", resp)
	}
	if _, present := m["read_only_posture"]; present {
		t.Errorf("read path must not carry the read_only_posture marker, got %v", m)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected audit write on allowed read: %v", err)
	}
}

// TestReadOnlyPosture_ToggleOffNoBlock verifies that with the posture OFF, a
// write-path call is NOT blocked by the posture (it falls through to normal
// evaluation, which allows it here). This is the default for every deployment
// that does not opt in.
func TestReadOnlyPosture_ToggleOffNoBlock(t *testing.T) {
	t.Setenv(EnvMCPReadOnly, "false")
	nilGlobalPolicyEngines(t)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()
	// No ExpectExec: posture off + engines nil → allowed, no audit row.

	resp, err := mcpToolCheckPolicy(context.Background(), testMCPSession(), map[string]interface{}{
		"connector_type": "claude_code.Bash",
		"statement":      "rm -rf /tmp/x",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, _ := resp.(map[string]interface{})
	if m["allowed"] != true {
		t.Errorf("expected allowed=true with posture off, got %v", resp)
	}
	if _, present := m["read_only_posture"]; present {
		t.Errorf("posture-off path must not carry the read_only_posture marker, got %v", m)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected audit write with posture off: %v", err)
	}
}
