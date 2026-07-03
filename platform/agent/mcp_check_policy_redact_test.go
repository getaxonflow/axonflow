// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Unit tests for issue #2746: check_policy must call redactInputStatement on
// the allow path so a PII-bearing Write call is denied before execution and
// Claude retries with the masked content.

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	sharedpolicy "axonflow/platform/shared/policy"
)

// validNIKStatement is a statement that contains a checksum-valid Indonesian
// NIK (same identifier as validNIKResponse in indonesia_response_pii_test.go,
// adapted for the request plane). The Indonesia detector is purely algorithmic —
// no DB-backed policy required — so this test exercises the redaction path
// without a policy-seeded stack.
const validNIKStatement = "write NIK 3174042506780001 to customer record"

// TestMCPToolCheckPolicy_PIIRedact_RequiresRedactionField verifies that when a
// statement contains PII under a redact-action policy, check_policy returns
// allowed:true with requires_redaction:true and a non-empty redacted_statement
// (issue #2746).
func TestMCPToolCheckPolicy_PIIRedact_RequiresRedactionField(t *testing.T) {
	// Set MCP detection config to redact mode. withMCPPIIAction also nil's the
	// global engine — we override that below with a non-nil stub engine so
	// redactInputStatement passes its nil-guard and reaches the Indonesia detector.
	withMCPPIIAction(t, DetectionActionRedact)

	// Provide a non-nil engine backed by a mock DB that LOADS SUCCESSFULLY with
	// an empty policy set (no rows). EnabledPIICategories returns nil (no PII
	// categories → static PII pass skipped); only the checksum-validated
	// Indonesia detector runs, which masks the NIK without any DB-seeded policy.
	//
	// #2820: the mock MUST return empty rows (a successful empty load), NOT run
	// out of expectations (a load ERROR). redactInputStatement now fails CLOSED
	// on a load error (returns evaluated=false so the PEP withholds) — an
	// expectation-less mock would trip that path and mask nothing. A successful
	// empty load is the honest "engine present, no PII policies" state this test
	// intends.
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	mock.MatchExpectationsInOrder(false)
	emptyCols := []string{"id", "policy_id", "name", "category", "tier", "pattern", "severity",
		"description", "phase", "action_request", "action_response",
		"enabled", "priority", "tenant_id", "organization_id", "metadata"}
	for i := 0; i < 6; i++ {
		mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows(emptyCols))
	}
	// withMCPPIIAction set the engine to nil; replace it with the stub.
	// The t.Cleanup registered by withMCPPIIAction restores the original engine.
	sharedpolicy.SetGlobalEngine(sharedpolicy.NewUnifiedPolicyEngine(db, sharedpolicy.EngineConfig{GracefulDegradation: true}, nil))

	resp, err := mcpToolCheckPolicy(context.Background(), &mcpSession{
		tenantID: "t1", orgID: "o1", clientID: "c1",
		userID: "u1", userRole: "admin", userEmail: "u@e.com",
	}, map[string]interface{}{
		"connector_type": "claude_code.Write",
		"statement":      validNIKStatement,
		"operation":      "execute",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, _ := resp.(map[string]interface{})
	// A redact policy allows the call but requires the PEP to swap the content.
	if m["allowed"] != true {
		t.Fatalf("expected allowed=true (redact policy allows, just masks), got %v", m)
	}
	if m["requires_redaction"] != true {
		t.Errorf("expected requires_redaction=true for PII-bearing statement under redact policy, got resp=%v", m)
	}
	if rs, _ := m["redacted_statement"].(string); rs == "" {
		t.Error("expected non-empty redacted_statement")
	}
}

// TestMCPToolCheckPolicy_BlockedPath_NoRequiresRedaction verifies that a
// blocked check_policy response never includes requires_redaction — the
// redaction code only runs on the allow path (issue #2746).
func TestMCPToolCheckPolicy_BlockedPath_NoRequiresRedaction(t *testing.T) {
	// Use the read-only posture to produce a guaranteed block without needing
	// a DB-seeded blocking PII policy. The assertion is purely structural:
	// a blocked response must never carry requires_redaction.
	t.Setenv("MCP_READ_ONLY", "true")

	resp, err := mcpToolCheckPolicy(context.Background(), &mcpSession{
		tenantID: "t1", orgID: "o1", clientID: "c1",
		userID: "u1", userRole: "admin", userEmail: "u@e.com",
	}, map[string]interface{}{
		"connector_type": "claude_code.Write",
		"statement":      validNIKStatement,
		"operation":      "execute",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, _ := resp.(map[string]interface{})
	if m["allowed"] != false {
		t.Fatalf("expected allowed=false under read-only posture, got %v", m)
	}
	if _, present := m["requires_redaction"]; present {
		t.Error("blocked response must not contain requires_redaction field")
	}
}
