// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent/sqli"
	sharedpolicy "axonflow/platform/shared/policy"
)

// =============================================================================
// #2641 (AUDIT-C): MCP-plane audit completeness.
//
// Every terminal MCP verdict + pre-policy early-return deny must write a
// canonical audit_logs row (plane=mcp, canonical past-tense policy_decision,
// redacted_fields populated on a redaction) — closing the StaticResult-gated
// holes where dynamic/SQLi/redact verdicts wrote ZERO rows and surfaced as
// "Logged" (or nothing) in the portal decisions feed.
//
// These tests are red-on-revert: each pins the INSERT that the fix adds, so
// removing the fix leaves an unmet sqlmock expectation (test fails). The
// precondition-absent cases (dynamic-ONLY block, SQLi-ONLY block,
// clean-then-redact) are exercised explicitly per
// feedback_tests_must_exercise_precondition_absent_case.
// =============================================================================

// captureArg records the JSONB/[]byte value passed at a given INSERT position so
// the test can decode and assert on it (e.g. redacted_fields). Always matches.
type captureArg struct{ dst *[]byte }

func (c captureArg) Match(value driver.Value) bool {
	switch v := value.(type) {
	case []byte:
		*c.dst = append([]byte(nil), v...)
	case string:
		*c.dst = []byte(v)
	default:
		*c.dst = nil
	}
	return true
}

// --- writeMCPDecisionAudit: the canonical writer used by every AUDIT-C hole ---

// TestWriteMCPDecisionAudit_RedactedPopulatesRedactedFields pins the core DoD
// guarantee: a redaction writes policy_decision='redacted' AND populates the
// redacted_fields JSONB column (NOT empty) — the column writeDecisionAuditLog
// structurally omits, which is the whole reason this writer exists.
func TestWriteMCPDecisionAudit_RedactedPopulatesRedactedFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	var redactedFieldsJSON []byte
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(),                     // id (audit_mcp_<decision_id>)
			"req-1",                              // request_id
			sqlmock.AnyArg(),                     // timestamp
			0,                                    // user_id
			"u@e.com",                            // user_email
			"service",                            // user_role
			"client-1",                           // client_id
			"tenant-1",                           // tenant_id
			"org-1",                              // org_id
			"mcp_check_output",                   // request_type
			"mcp check-output: postgres",         // query (non-PII descriptor)
			sqlmock.AnyArg(),                     // query_hash
			mcpVerdictRedacted,                   // policy_decision — canonical
			sqlmock.AnyArg(),                     // policy_details JSONB
			"dec-1",                              // decision_id (first-class)
			PlaneMCP,                             // plane=mcp
			"corr-1",                             // correlation_id
			captureArg{dst: &redactedFieldsJSON}, // redacted_fields JSONB (#2641)
			nil,                                  // session_id NULL — no X-Session-Id on ctx (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeMCPDecisionAudit(context.Background(), db,
		"dec-1", "req-1",
		"tenant-1", "org-1", "client-1", "u@e.com",
		"0", "service",
		"mcp_check_output", "mcp check-output: postgres", "",
		mcpVerdictRedacted,
		[]string{"pii-us-ssn"},
		[]string{"response PII redacted: nik"},
		[]string{"nik", "npwp"},
		"corr-1")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redacted MCP decision row not written as expected: %v", err)
	}
	var got []string
	if err := json.Unmarshal(redactedFieldsJSON, &got); err != nil {
		t.Fatalf("redacted_fields not valid JSON array: %v (raw=%s)", err, redactedFieldsJSON)
	}
	if len(got) != 2 || got[0] != "nik" || got[1] != "npwp" {
		t.Errorf("redacted_fields = %v, want [nik npwp]", got)
	}
}

// TestWriteMCPDecisionAudit_NoRedactionNullColumn proves a non-redaction verdict
// (a block) passes SQL NULL for redacted_fields — never the JSON literal "null"
// or "[]" — so the compliance exporters that COALESCE on the column see NULL.
func TestWriteMCPDecisionAudit_NoRedactionNullColumn(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), 0,
			"unknown@axonflow.local", // user_email fallback
			"service",                // user_role fallback
			"unknown",                // client_id fallback
			"unknown",                // tenant_id fallback
			"",                       // org_id (passed empty → stays empty/NULL-able)
			"mcp_check_policy",
			"mcp check_policy: postgres",
			sqlmock.AnyArg(), // query_hash
			mcpVerdictBlocked,
			sqlmock.AnyArg(), // policy_details
			"dec-2",
			PlaneMCP,
			nil, // correlation_id NULL (none supplied)
			nil, // redacted_fields NULL — NOT [] or "null" (#2641)
			nil, // session_id NULL — no X-Session-Id on ctx (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeMCPDecisionAudit(context.Background(), db,
		"dec-2", "",
		"", "", "", "", // empty identity → NOT-NULL fallbacks
		"", "",
		"mcp_check_policy", "mcp check_policy: postgres", "",
		mcpVerdictBlocked,
		[]string{"dynamic_policy"},
		[]string{"blocked"},
		nil, // no redaction
		"")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("blocked MCP decision row not written as expected: %v", err)
	}
}

// TestWriteMCPDecisionAudit_NoopGuards confirms the best-effort no-ops: a nil db
// or an empty decision_id never panics and never attempts a write.
func TestWriteMCPDecisionAudit_NoopGuards(t *testing.T) {
	// nil db → no panic, no write.
	writeMCPDecisionAudit(context.Background(), nil,
		"dec", "req", "t", "o", "c", "e", "0", "r",
		"rt", "q", "h", mcpVerdictBlocked, nil, nil, nil, "")

	// empty decision_id → no write (would fail the strict mock if it tried).
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	writeMCPDecisionAudit(context.Background(), db,
		"", "req", "t", "o", "c", "e", "0", "r",
		"rt", "q", "h", mcpVerdictBlocked, nil, nil, nil, "")
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("empty decision_id must not write: %v", err)
	}
}

// --- mcp_server_handler.go JSON-RPC tools: the StaticResult-gated holes ---

// TestMcpToolCheckPolicy_DynamicBlock_EmitsCanonicalAudit is the red-on-revert
// guard for MCPSRV-CHECKPOLICY-DYNAMIC-ONLY-BLOCK. A dynamic-ONLY block carries
// NO StaticResult, so the writeExplainableAuditLog call (gated on
// StaticResult.Blocked) never fires — the block was portal-invisible. The fix
// emits a canonical 'blocked' row. Precondition-absent: there is no static match.
func TestMcpToolCheckPolicy_DynamicBlock_EmitsCanonicalAudit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()

	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil) // no static engine → dynamic-ONLY
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	server := mockOrchestratorServer(t, sharedpolicy.DynamicPolicyResponse{
		Allowed:           false,
		BlockReason:       "Budget exhausted",
		PoliciesEvaluated: 1,
		MatchedPolicies: []sharedpolicy.DynamicPolicyMatch{
			{PolicyID: "budget-1", PolicyType: "budget", Action: "block"},
		},
	})
	defer server.Close()
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"postgres"},
	})

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), "client-1", "tenant-1", "org-1",
			"mcp_check_policy", sqlmock.AnyArg(), sqlmock.AnyArg(),
			mcpVerdictBlocked, // canonical 'blocked' — NOT legacy 'deny'
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			PlaneMCP,
			nil, // correlation_id (no traceparent on the MCP-server session)
			nil, // redacted_fields NULL on a block
			nil, // session_id NULL — session carries no clientSessionID (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	resp, err := mcpToolCheckPolicy(context.Background(), &mcpSession{
		tenantID: "tenant-1", orgID: "org-1", clientID: "client-1",
		userID: "u1", userRole: "admin", userEmail: "u@e.com",
	}, map[string]interface{}{
		"connector_type": "postgres", // not an integration prefix → AutoDetect no-ops
		"statement":      "SELECT 1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m, _ := resp.(map[string]interface{}); m["allowed"] != false {
		t.Errorf("expected allowed=false on dynamic block, got %v", resp)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("dynamic-only block did not emit a canonical audit row: %v", err)
	}
}

// TestMcpToolCheckOutput_SQLiBlock_EmitsCanonicalAudit is the red-on-revert guard
// for MCPSRV-CHECKOUTPUT-SQLI-NO-AUDIT. A SQLi-ONLY block has no StaticResult, so
// it wrote ZERO rows. Precondition-absent: no static policy match.
func TestMcpToolCheckOutput_SQLiBlock_EmitsCanonicalAudit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()

	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalSQLi := sqli.GetGlobalMiddleware()
	defer sqli.SetGlobalMiddleware(originalSQLi)
	cfg := sqli.DefaultConfig().WithBlockOnDetection(true)
	mw, err := sqli.NewScanningMiddleware(sqli.WithMiddlewareConfig(cfg))
	if err != nil {
		t.Fatalf("new middleware: %v", err)
	}
	sqli.SetGlobalMiddleware(mw)

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), "client-1", "tenant-1", "org-1",
			"mcp_check_output", sqlmock.AnyArg(), sqlmock.AnyArg(),
			mcpVerdictBlocked,
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			PlaneMCP,
			nil,
			nil, // redacted_fields NULL
			nil, // session_id NULL (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	resp, err := mcpToolCheckOutput(context.Background(), &mcpSession{
		tenantID: "tenant-1", orgID: "org-1", clientID: "client-1",
		userID: "u1", userRole: "admin", userEmail: "u@e.com",
	}, map[string]interface{}{
		"connector_type": "postgres",
		"response_data": []interface{}{
			map[string]interface{}{"id": 1, "data": "admin' UNION SELECT password FROM users--"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m, _ := resp.(map[string]interface{}); m["allowed"] != false {
		t.Errorf("expected allowed=false on SQLi block, got %v", resp)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("SQLi-only block did not emit a canonical audit row: %v", err)
	}
}

// TestMcpToolCheckOutput_RedactAndAllow_EmitsRedactedAudit is the red-on-revert
// guard for MCPSRV-CHECKOUTPUT-REDACT-NO-AUDIT — the WORST writer: an OJK
// NIK/NPWP response mask is allowed (blocked=false) and previously early-returned
// writing ZERO rows. Precondition-absent / clean-then-redact: the response is
// ALLOWED yet a 'redacted' row with redacted_fields must still be written.
func TestMcpToolCheckOutput_RedactAndAllow_EmitsRedactedAudit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()

	// PII_ACTION=redact + the Indonesia response detector masks the NIK; the
	// static engine is nil'd so only the Indonesia step runs (an allow, not a block).
	withMCPPIIAction(t, DetectionActionRedact)

	var redactedFieldsJSON []byte
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), "client-1", "tenant-1", "org-1",
			"mcp_check_output", sqlmock.AnyArg(), sqlmock.AnyArg(),
			mcpVerdictRedacted, // 'redacted' — NOT 'allowed' (the #2641 bug)
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			PlaneMCP,
			nil,
			captureArg{dst: &redactedFieldsJSON}, // redacted_fields populated
			nil,                                  // session_id NULL (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	resp, err := mcpToolCheckOutput(context.Background(), &mcpSession{
		tenantID: "tenant-1", orgID: "org-1", clientID: "client-1",
		userID: "u1", userRole: "admin", userEmail: "u@e.com",
	}, map[string]interface{}{
		"connector_type": "postgres",
		"message":        validNIKResponse, // contains a valid NIK
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The decision is ALLOWED (a redact-and-allow) yet must still be audited.
	if m, _ := resp.(map[string]interface{}); m["allowed"] != true {
		t.Errorf("expected allowed=true on redact-and-allow, got %v", resp)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redact-and-allow did not emit a 'redacted' audit row: %v", err)
	}
	var fields []string
	if err := json.Unmarshal(redactedFieldsJSON, &fields); err != nil {
		t.Fatalf("redacted_fields not a JSON array: %v (raw=%s)", err, redactedFieldsJSON)
	}
	if len(fields) == 0 {
		t.Error("redact-and-allow must populate redacted_fields, got empty")
	}
}

// TestMcpToolCheckOutput_CleanAllow_NoAuditRow proves we do NOT over-audit: a
// clean allow on the JSON-RPC plane writes no audit_logs row (the DoD lists only
// terminal block/redact + denies, not plain allows — consistent with prior
// behavior and bounded audit volume on the hot pre/post-tool hook path).
func TestMcpToolCheckOutput_CleanAllow_NoAuditRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()

	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	// No ExpectExec registered → any INSERT would be an unexpected-query failure.
	resp, err := mcpToolCheckOutput(context.Background(), &mcpSession{
		tenantID: "tenant-1", orgID: "org-1", clientID: "client-1",
	}, map[string]interface{}{
		"connector_type": "postgres",
		"message":        "1 row affected",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m, _ := resp.(map[string]interface{}); m["allowed"] != true {
		t.Errorf("expected allowed=true on clean output, got %v", resp)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("clean allow must NOT write an audit row: %v", err)
	}
}

// --- mcp_server_handler.go dispatch denials (auditMCPServerDeny shared writer) ---

// TestAuditMCPServerDeny pins the shared dispatch-deny writer used by
// MCPSRV-DAILYCAP-DENY / TIERGATE-DENY / TOOLERR-FAILCLOSED / SESSIONDELETE-AUTHZ:
// it writes a canonical row from the authenticated session identity, and no-ops
// on a nil session.
func TestAuditMCPServerDeny(t *testing.T) {
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
			"u@e.com", "admin", "client-9", "tenant-9", "org-9",
			"mcp_tools_call", "mcp tools/call: check_policy", sqlmock.AnyArg(),
			mcpVerdictError, // tool-error → canonical 'error'
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			PlaneMCP,
			nil, nil, // correlation_id, redacted_fields
			nil, // session_id NULL (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	auditMCPServerDeny(context.Background(), &mcpSession{
		tenantID: "tenant-9", orgID: "org-9", clientID: "client-9",
		userID: "u9", userRole: "admin", userEmail: "u@e.com",
	}, "mcp_tools_call", "check_policy", mcpVerdictError, "governance tool error", []string{"tool_error"})
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("auditMCPServerDeny did not write the canonical row: %v", err)
	}

	// nil session → no-op (no panic, no write).
	auditMCPServerDeny(context.Background(), nil, "mcp_tools_call", "x", mcpVerdictBlocked, "y", nil)
}

// TestHandleMCPToolsCall_Unauthenticated_EmitsBlockedAudit is the red-on-revert
// guard for MCPSRV-UNAUTH-JSONRPC: an unauthenticated tools/call (enterprise
// mode, no creds) records a 'blocked' row under the unauthenticated tenant
// sentinel — never a caller-claimed tenant (no spoofing).
func TestHandleMCPToolsCall_Unauthenticated_EmitsBlockedAudit(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise") // require real auth → resolveMCPSession fails

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
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), 0,
			sqlmock.AnyArg(), "service", sqlmock.AnyArg(),
			mcpUnauthenticatedTenant, // tenant_id sentinel — NOT caller-claimed
			"",                       // org_id empty → out of every real tenant feed
			"mcp_tools_call", sqlmock.AnyArg(), sqlmock.AnyArg(),
			mcpVerdictBlocked,
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			PlaneMCP,
			nil, nil, // correlation_id, redacted_fields
			nil, // session_id NULL (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	params, _ := json.Marshal(map[string]interface{}{
		"name":      "check_policy",
		"arguments": map[string]interface{}{"connector_type": "postgres", "statement": "x"},
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp-server", bytes.NewReader(nil))
	w := httptest.NewRecorder()
	handleMCPToolsCall(w, req, &jsonRPCRequest{JSONRPC: "2.0", ID: "c1", Method: "tools/call", Params: params})

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauthenticated tools/call, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unauthenticated tools/call did not emit a security audit row: %v", err)
	}
}

// --- mcp_handler.go check-input: vocab + redaction + early returns ---

// TestMCPCheckInputHandler_UnsupportedContentType_EmitsBlockedAudit is the
// red-on-revert guard for MCPIN-PREPOLICY-EARLYRETURNS (415 arm): a fail-closed
// content_type refusal writes a 'blocked' row against the authenticated tenant.
func TestMCPCheckInputHandler_UnsupportedContentType_EmitsBlockedAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

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
			sqlmock.AnyArg(), "service", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			"mcp_check_input", sqlmock.AnyArg(), sqlmock.AnyArg(),
			mcpVerdictBlocked,
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			PlaneMCP,
			sqlmock.AnyArg(), // correlation_id (may be NULL)
			nil,              // redacted_fields NULL
			nil,              // session_id NULL (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
		TenantID:      "default",
		ContentType:   "image/tiff", // no registered detector → fail-closed 415
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("415 early return did not emit a 'blocked' audit row: %v", err)
	}
}

// TestMCPCheckInputHandler_EvalUnavailable_EmitsErrorAudit is the red-on-revert
// guard for the fail-closed dynamic-evaluator-unavailable early return: a 503
// records a canonical 'error' row keyed by the decision_id.
func TestMCPCheckInputHandler_EvalUnavailable_EmitsErrorAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()

	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	// An unreachable orchestrator with GracefulDegradation=false → EvalUnavailable.
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: "http://127.0.0.1:0", // unroutable
		Timeout:              200 * time.Millisecond,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"postgres"},
	})

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			"mcp_check_input", sqlmock.AnyArg(), sqlmock.AnyArg(),
			mcpVerdictError, // fail-closed → canonical 'error'
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			PlaneMCP,
			sqlmock.AnyArg(),
			nil,
			nil, // session_id NULL (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("EvalUnavailable did not emit an 'error' audit row: %v", err)
	}
}

// TestMCPCheckOutputHandler_Redaction_EmitsRedactedWithFields drives the HTTP
// check-output handler through the Indonesia redact path and proves the canonical
// row is policy_decision='redacted' (not 'allowed') WITH redacted_fields — the
// response-plane mirror of the JSON-RPC redact fix. Clean-then-redact: 200 OK +
// a redacted audit row.
func TestMCPCheckOutputHandler_Redaction_EmitsRedactedWithFields(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()

	withMCPPIIAction(t, DetectionActionRedact)

	var redactedFieldsJSON []byte
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			"mcp_check_output", sqlmock.AnyArg(), sqlmock.AnyArg(),
			mcpVerdictRedacted,
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			PlaneMCP,
			sqlmock.AnyArg(),
			captureArg{dst: &redactedFieldsJSON},
			nil, // session_id NULL (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Message:       validNIKResponse,
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (redact-and-allow), got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckOutputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Allowed {
		t.Error("redact-and-allow must report allowed=true")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("check-output redaction did not emit a 'redacted' row: %v", err)
	}
	var fields []string
	if err := json.Unmarshal(redactedFieldsJSON, &fields); err != nil || len(fields) == 0 {
		t.Errorf("redacted_fields must be a non-empty JSON array, got %s (err=%v)", redactedFieldsJSON, err)
	}
}
