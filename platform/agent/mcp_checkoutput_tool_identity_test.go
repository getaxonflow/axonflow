// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Response-plane capability scoping (#2955, sub-issue of epic #2905): the
// check-output plane must key capability scoping off the caller-sent (server,
// tool) split — MCPCheckOutputRequest.ConnectorType is the SERVER axis and the
// new MCPCheckOutputRequest.Tool is the sub-tool — exactly as check-input does
// since #2916. Before #2955 the handler duplicated ConnectorType into
// evaluateOutputPolicies' toolIdentity param, so a text-document tool's output
// was scored against the bare server name (never a text-document tool) and the
// execution-class response scanners ran again on documentation — reintroducing
// the #2802 documentation-FP class for the langgraph de-concat SDKs.
//
// Since v11 the execution-class response scan decides nothing: the response
// pass's verdict is the anchored engine's. What tool identity changes is
// whether that scan RUNS, which these tests read off the middleware's own scan
// counter. They prove, deterministically:
//   1. Tool present + text-document → the execution-class response SQLi scan is
//      scoped OUT (capability relaxation keys off req.Tool).
//   2. Tool absent → FULL (fail-closed) evaluation; the scan runs. No silent
//      widen, no fallback from ConnectorType.
//   3. The SERVER axis must never relax scoping: a text-document-looking
//      connector_type with an empty tool still gets full evaluation. This case
//      is the direct regression guard against the pre-#2955 duplication bug —
//      it PASSES only when the handler passes req.Tool (not req.ConnectorType).
//   4. Both identity axes land on the canonical audit row as
//      policy_details.tool_server / policy_details.tool_name.
//   5. The scan's block decides nothing, even from a middleware configured to
//      block.

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent/sqli"
)

// installSQLiResponseMiddleware swaps the global SQLi middleware for a fresh
// one in response=basic mode, blocking or not as asked, and restores the prior
// instance after the test. It returns the instance so a test can read whether
// the execution-class response scan RAN. No production path builds a blocking
// one (the global middleware is lazily DefaultConfig, BlockOnDetection=false);
// block=true exists to prove that even such a middleware decides nothing.
func installSQLiResponseMiddleware(t *testing.T, block bool) *sqli.ScanningMiddleware {
	t.Helper()
	old := sqli.GetGlobalMiddleware()
	mw, err := sqli.NewScanningMiddleware(sqli.WithMiddlewareConfig(sqli.DefaultConfig().WithBlockOnDetection(block)))
	if err != nil {
		t.Fatalf("new SQLi middleware: %v", err)
	}
	sqli.SetGlobalMiddleware(mw)
	t.Cleanup(func() { sqli.SetGlobalMiddleware(old) })
	return mw
}

// scanRan reports whether call made mw run a response scan.
func scanRan(mw *sqli.ScanningMiddleware, call func()) bool {
	before := mw.GetMetrics().ScansTotal
	call()
	return mw.GetMetrics().ScansTotal > before
}

// sqliResponseMessage is a response the SQLi response scanner detects
// (sqli/middleware_test.go).
const sqliResponseMessage = "Error: syntax near ' UNION SELECT * FROM admin_passwords--"

// checkOutputScan drives POST /api/v1/mcp/check-output with the given
// (connector_type, tool) and a message the SQLi response scanner detects,
// returning the HTTP status.
func checkOutputScan(t *testing.T, connectorType, tool string) int {
	t.Helper()
	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: connectorType,
		Tool:          tool,
		Message:       sqliResponseMessage,
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckOutputHandler(w, req)
	return w.Code
}

func TestCheckOutput_ToolIdentity_ScopesExecutionClassResponseScan(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mw := installSQLiResponseMiddleware(t, false)
	installUsageDBMock(t) // best-effort audit writes; unmatched inserts are logged + ignored

	ran := func(connectorType, tool string) bool {
		t.Helper()
		return scanRan(mw, func() {
			if code := checkOutputScan(t, connectorType, tool); code != http.StatusOK {
				t.Fatalf("check-output (%q, %q) answered %d; the scan decides nothing, so the response is released", connectorType, tool, code)
			}
		})
	}

	// connector_type is a SERVER name that is NOT a text-document tool.
	const server = "atlassian_remote"

	// 1. Tool present + text-document: the execution-class scan is scoped out.
	//    Under the pre-#2955 bug (connector_type duplicated into toolIdentity)
	//    IsTextDocumentTool("atlassian_remote") is false and the scan would run.
	if ran(server, "getConfluencePage") {
		t.Error("text-document tool: the execution-class scan ran; scoping is not keying off req.Tool")
	}

	// 2. Tool absent: FULL (fail-closed) evaluation; the scan runs.
	if !ran(server, "") {
		t.Error("absent tool: the execution-class scan did not run; a missing tool must NOT silently widen")
	}

	// 3. SERVER axis must not relax scoping: a text-document-looking
	//    connector_type with an empty tool still gets full evaluation. This is
	//    the regression guard: the scan is skipped (wrongly) only if the handler
	//    feeds req.ConnectorType into toolIdentity (the pre-#2955 duplication).
	if !ran("getConfluencePage", "") {
		t.Error("server axis relaxed scoping: the scan did not run with a text-document-looking connector_type and an empty tool; the server name must never classify a tool")
	}
}

// toolIdentityDetails is a sqlmock argument matcher over the writeDecisionAuditLog
// policy_details JSON column, asserting it carries the split (tool_server,
// tool_name) identity for the check-output decision row.
type toolIdentityDetails struct {
	wantServer string
	wantTool   string
}

func (m toolIdentityDetails) Match(v driver.Value) bool {
	var raw []byte
	switch t := v.(type) {
	case []byte:
		raw = t
	case string:
		raw = []byte(t)
	default:
		return false
	}
	var details map[string]interface{}
	if err := json.Unmarshal(raw, &details); err != nil {
		return false
	}
	return details["tool_server"] == m.wantServer && details["tool_name"] == m.wantTool
}

func TestCheckOutput_ToolIdentity_PersistedOnAuditRow(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	disableOutputCheckers(t)
	mock := installUsageDBMock(t)

	// The canonical allow row goes through recordDecideDecision ->
	// writeDecisionAuditLog. Pin policy_details (14th arg, per
	// expectDecideWriterRow's column layout) to the split identity; every other
	// column is free.
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
			sqlmock.AnyArg(), // request_type
			sqlmock.AnyArg(), // query
			sqlmock.AnyArg(), // query_hash
			sqlmock.AnyArg(), // policy_decision
			toolIdentityDetails{wantServer: "postgres", wantTool: "query"}, // policy_details
			sqlmock.AnyArg(), // decision_id
			sqlmock.AnyArg(), // plane
			sqlmock.AnyArg(), // obligations
			sqlmock.AnyArg(), // correlation_id
			sqlmock.AnyArg(), // redacted_fields
			sqlmock.AnyArg(), // session_id
			sqlmock.AnyArg(), // response_time_ms (#3424): handler elapsed time
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Tool:          "query",
		Message:       "1 row affected",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (allow), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("check-output allow row did not persist policy_details.tool_server/tool_name: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Sibling plane: the MCP-server stdio `check_output` JSON-RPC tool
// (mcpToolCheckOutput). #2916 fixed BOTH the REST check-input handler AND the
// stdio check_policy tool; #2955 must mirror it on BOTH the REST check-output
// handler (above) AND this stdio check_output tool — otherwise the exact
// connector_type→toolIdentity duplication survives on the plane the Claude Code
// plugin's PostToolUse hook actually calls over the wire.
// ---------------------------------------------------------------------------

// toolSession is the stdio session the sibling-plane tests call as.
func toolSession() *mcpSession {
	return &mcpSession{tenantID: "t-1", orgID: "o-1", clientID: "c-1", userID: "u-1", userRole: "admin", userEmail: "u@e.com"}
}

// checkOutputTool drives the stdio check_output tool and returns its response
// map, failing the test on a transport error.
func checkOutputTool(t *testing.T, args map[string]interface{}) map[string]interface{} {
	t.Helper()
	session := toolSession()
	resp, err := mcpToolCheckOutput(authenticatedToolContext(session), session, args, pepHandshakeResolution{})
	if err != nil {
		t.Fatalf("mcpToolCheckOutput(%v): %v", args, err)
	}
	m, _ := resp.(map[string]interface{})
	return m
}

func TestMcpToolCheckOutput_ToolIdentity_ScopesExecutionClassResponseScan(t *testing.T) {
	// Same discriminator as the REST scoping test: whether the scan ran.
	mw := installSQLiResponseMiddleware(t, false)
	installUsageDBMock(t) // best-effort audit writes; unmatched inserts logged + ignored

	ran := func(connectorType, tool string) bool {
		t.Helper()
		return scanRan(mw, func() {
			m := checkOutputTool(t, map[string]interface{}{
				"connector_type": connectorType,
				"tool":           tool,
				"message":        sqliResponseMessage,
			})
			if m["allowed"] != true {
				t.Fatalf("check_output (%q, %q) = %v; the scan decides nothing, so the response is released", connectorType, tool, m)
			}
		})
	}

	const server = "atlassian_remote" // a server name that is NOT a text-document tool

	// Text-document tool → execution-class scan scoped out. Under the pre-#2955
	// bug (connector_type duplicated into toolIdentity) the scan would run.
	if ran(server, "getConfluencePage") {
		t.Error("text-document tool: the execution-class scan ran; stdio scoping is not keying off args[\"tool\"]")
	}
	// Absent tool → full (fail-closed) evaluation → the scan runs.
	if !ran(server, "") {
		t.Error("absent tool: the execution-class scan did not run; a missing tool must NOT silently widen on the stdio plane")
	}
	// Server axis must not relax scoping: a text-document-looking connector_type
	// with an empty tool still gets full evaluation (regression guard for the
	// pre-#2955 duplication).
	if !ran("getConfluencePage", "") {
		t.Error("server axis relaxed scoping: the scan did not run with a text-document-looking connector_type but empty tool")
	}
}

func TestMcpToolCheckOutput_ToolIdentity_PersistedOnAuditRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()

	// A redaction on the stdio plane writes the canonical "redacted" row through
	// writeMCPDecisionAudit, which carries the split identity. policy_details is
	// the 14th arg of that INSERT (mcp_richer_context.go). Pin it to the split
	// identity; every other column is free.
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), // id, request_id, timestamp, user_id
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), // user_email, user_role, client_id, tenant_id, org_id
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), // request_type, query, query_hash
			sqlmock.AnyArg(), // policy_decision
			toolIdentityDetails{wantServer: "claude_code", wantTool: "Bash"}, // policy_details (14th)
			sqlmock.AnyArg(), sqlmock.AnyArg(), // decision_id, plane
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), // correlation_id, redacted_fields, session_id
			sqlmock.AnyArg(), // response_time_ms (#3424): mcpToolCheckOutput's own elapsed time
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// An organization that recorded pii=redact: the NIK is masked and the
	// response released, which writes the redacted row.
	withMCPPIIAction(t, DetectionActionRedact)
	m := checkOutputTool(t, map[string]interface{}{
		"connector_type": "claude_code",
		"tool":           "Bash",
		"message":        validNIKResponse,
	})
	if m["allowed"] != true || m["redacted_message"] == nil {
		t.Fatalf("expected the NIK redacted and the response released, got %v", m)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("stdio check_output redaction row did not persist policy_details.tool_server/tool_name: %v", err)
	}
}

// TestMCPCheckOutput_TheSQLiResponseScanDecidesNothing: the response pass's
// verdict is the anchored engine's. The execution-class SQLi scan still runs,
// and the middleware logs and audits what it finds, but nothing honours its
// block - even from a middleware configured to block, which no production path
// builds. A branch that honoured it again turns this red.
func TestMCPCheckOutput_TheSQLiResponseScanDecidesNothing(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mw := installSQLiResponseMiddleware(t, true)
	installUsageDBMock(t)

	released := func(t *testing.T, call func() bool) {
		t.Helper()
		var ok bool
		if !scanRan(mw, func() { ok = call() }) {
			t.Fatal("the SQLi response scan did not run, so this proves nothing about its block")
		}
		if !ok {
			t.Fatal("a response the blocking middleware detects was refused; the scan decides nothing")
		}
	}
	t.Run("stdio, rows", func(t *testing.T) {
		released(t, func() bool {
			return checkOutputTool(t, map[string]interface{}{
				"connector_type": "postgres",
				"response_data":  []interface{}{map[string]interface{}{"id": 1, "data": "admin' UNION SELECT password FROM users--"}},
			})["allowed"] == true
		})
	})
	t.Run("stdio, message", func(t *testing.T) {
		released(t, func() bool {
			return checkOutputTool(t, map[string]interface{}{"connector_type": "postgres", "message": sqliResponseMessage})["allowed"] == true
		})
	})
	t.Run("REST check-output", func(t *testing.T) {
		released(t, func() bool { return checkOutputScan(t, "postgres", "") == http.StatusOK })
	})
}
