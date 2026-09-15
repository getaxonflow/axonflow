// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// =============================================================================
// #2627 (AUDIT-FIX-B): MCP check-input → canonical audit_logs decision row
//
// The customer portal's decisions feed (orchestrator GET /api/v1/decisions)
// reads audit_logs WHERE policy_details->>'decision_id' IS NOT NULL. A clean
// allow on check-input goes through the SAME writer /decide uses
// (recordDecideDecision → writeDecisionAuditLog), keyed by the same decision_id
// as the mcp_query_audits satellite, mirroring the response plane (#2586). A
// refusal dual-writes its own richer row (writeExplainableAuditLog) and a
// redaction its own verdict (writeMCPDecisionAudit), so neither is routed
// through that emit. These tests pin the permit→verdict mapping and the fact
// that the handler actually emits the row (red-on-revert).
// =============================================================================

// TestMCPInputDecisionVerdict pins the pure mapping from the request pass's
// permit to the (verdict, policy_ids, reasons) the canonical row carries. A
// refusal is intentionally absent: it dual-writes a richer audit_logs row via
// writeExplainableAuditLog and must not be routed here.
func TestMCPInputDecisionVerdict(t *testing.T) {
	tests := []struct {
		name        string
		enforced    requestPassEnforcement
		didRedact   bool
		wantVerdict string
		wantPolicy  []string
		wantReasons []string
	}{
		{
			name:        "clean permit → allowed, no policy ids, no reasons",
			enforced:    requestPassEnforcement{verdict: VerdictAllow},
			wantVerdict: mcpVerdictAllowed,
		},
		{
			name:        "permit determined by controls → allowed, their ids surfaced",
			enforced:    requestPassEnforcement{verdict: VerdictAllow, evaluatedPolicies: []string{"corpus:pii-us-ssn"}},
			wantVerdict: mcpVerdictAllowed,
			wantPolicy:  []string{"corpus:pii-us-ssn"},
		},
		{
			name:        "permit whose redaction was discharged → redacted, ids and the redact reason surfaced",
			enforced:    requestPassEnforcement{verdict: VerdictAllow, evaluatedPolicies: []string{"corpus:pii-us-ssn"}},
			didRedact:   true,
			wantVerdict: mcpVerdictRedacted,
			wantPolicy:  []string{"corpus:pii-us-ssn"},
			wantReasons: []string{"request PII redacted"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotVerdict, gotPolicy, gotReasons, _ := mcpInputDecisionVerdict(tc.enforced, tc.didRedact)
			if gotVerdict != tc.wantVerdict {
				t.Errorf("verdict: got %q, want %q", gotVerdict, tc.wantVerdict)
			}
			if !reflect.DeepEqual(gotPolicy, tc.wantPolicy) {
				t.Errorf("policy_ids: got %v, want %v", gotPolicy, tc.wantPolicy)
			}
			if !reflect.DeepEqual(gotReasons, tc.wantReasons) {
				t.Errorf("reasons: got %v, want %v", gotReasons, tc.wantReasons)
			}
		})
	}
}

// TestMCPCheckInputHandler_AllowEmitsAuditLogsDecisionRow proves the terminal
// allow path converges onto audit_logs (policy_decision='allowed'), so a clean
// request is portal-visible, not just refusals. The statement matches nothing
// the default test engine's detectors look for, so the anchored engine permits
// it.
func TestMCPCheckInputHandler_AllowEmitsAuditLogsDecisionRow(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), // id
			sqlmock.AnyArg(), // request_id
			sqlmock.AnyArg(), // timestamp
			sqlmock.AnyArg(), // user_id
			sqlmock.AnyArg(), // user_email
			sqlmock.AnyArg(), // user_role
			sqlmock.AnyArg(), // client_id
			sqlmock.AnyArg(), // tenant_id
			sqlmock.AnyArg(), // org_id
			"decision_tool",  // request_type
			sqlmock.AnyArg(), // query
			sqlmock.AnyArg(), // query_hash
			"allowed",        // policy_decision
			sqlmock.AnyArg(), // policy_details
			sqlmock.AnyArg(), // decision_id (first-class column; #2592)
			PlaneMCP,         // plane — MCP request surface (#2627)
			nil,              // obligations (none on a clean allow)
			nil,              // correlation_id (#2598): no traceparent → NULL → singleton
			nil,              // redacted_fields (#2643): clean allow → NULL
			nil,              // session_id (#2896): no trusted client session id → NULL
			sqlmock.AnyArg(), // response_time_ms (#3424): handler elapsed time
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (allow), got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got false (block_reason=%q)", resp.BlockReason)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("audit_logs decision row was not emitted by the allow path: %v", err)
	}
}
