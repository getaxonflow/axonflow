// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent/sqli"
	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
	sharedpolicy "axonflow/platform/shared/policy"
)

// =============================================================================
// #2679 (FIX-HOLE1 / AUDIT-C #2641): MCP connector-exec plane canonical audit.
//
// mcpQueryHandler (POST /mcp/resources/query) and mcpExecuteHandler
// (POST /mcp/tools/execute) are a full PEP, but every terminal verdict
// previously wrote ONLY the reader-less mcp_query_audits satellite — so blocks
// and redactions on these routes were invisible in the portal /decisions feed
// and the SEBI/EU-AI-Act exports (the THIRD MCP plane #2641 missed). Each handler
// now additively emits a canonical audit_logs row via writeMCPDecisionAudit on
// every terminal verdict, keyed by the SAME decision_id as the satellite.
//
// These tests are red-on-revert: each pins the canonical INSERT the fix adds, so
// removing an emit leaves an unmet sqlmock expectation. The precondition-absent
// cases the brief mandates are exercised explicitly — redact-and-allow (the
// response is ALLOWED yet a 'redacted' row with redacted_fields must still be
// written) and dynamic-ONLY block (no StaticResult present). Clean-allow,
// tool-error fail-closed, eval-unavailable fail-closed, and a response-phase
// block (exfil for query, SQLi for execute) cover the remaining emit call sites.
//
// NOTE on the request-phase static-block branch: like the rest of this package
// (see TestMCPCheckInputHandler_WithEngineNoPolicies_Allowed — "Static policy
// blocking with live policies is exercised by shared/policy engine_test.go"),
// a request static block requires a DB-backed live policy cache, so it is covered
// at the engine layer + the runtime-e2e harness (runtime-e2e/2679_*) rather than
// reconstructed here. Its emit call site is structurally identical to the
// dynamic-block emit (same writer, same canonical 'blocked' verdict) pinned below.
// =============================================================================

// writeMCPDecisionAudit's 18-column INSERT (mcp_richer_context.go). The helpers
// pin the load-bearing columns this feature guarantees — request_type (the route
// descriptor), policy_decision (canonical past-tense vocab), plane=mcp, and
// redacted_fields — while leaving the community-mode identity columns to AnyArg.

// expectCanonicalDecisionRow registers the canonical audit_logs INSERT for a
// block/error/clean-allow verdict (redacted_fields = SQL NULL). correlation_id is
// NULL because these tests send no traceparent header.
func expectCanonicalDecisionRow(mock sqlmock.Sqlmock, requestType, verdict string) {
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), // id (audit_mcp_<decision_id>)
			sqlmock.AnyArg(), // request_id
			sqlmock.AnyArg(), // timestamp
			sqlmock.AnyArg(), // user_id
			sqlmock.AnyArg(), // user_email
			sqlmock.AnyArg(), // user_role
			sqlmock.AnyArg(), // client_id
			sqlmock.AnyArg(), // tenant_id
			sqlmock.AnyArg(), // org_id
			requestType,      // request_type — the connector-exec route
			sqlmock.AnyArg(), // query (non-PII descriptor)
			sqlmock.AnyArg(), // query_hash
			verdict,          // policy_decision — canonical past-tense vocab
			sqlmock.AnyArg(), // policy_details JSONB
			sqlmock.AnyArg(), // decision_id (first-class)
			PlaneMCP,         // plane=mcp
			nil,              // correlation_id (no traceparent → NULL → singleton)
			nil,              // redacted_fields NULL — block/error/clean allow
			nil,              // session_id NULL — no X-Session-Id on ctx (#2753)
			sqlmock.AnyArg(), // response_time_ms (#3424)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
}

// expectRedactedDecisionRow registers the canonical INSERT for a redact-and-allow
// verdict, capturing the redacted_fields JSONB so the test can assert it is
// populated (the column writeDecisionAuditLog structurally omits).
func expectRedactedDecisionRow(mock sqlmock.Sqlmock, requestType string, dst *[]byte) {
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(),     // id
			sqlmock.AnyArg(),     // request_id
			sqlmock.AnyArg(),     // timestamp
			sqlmock.AnyArg(),     // user_id
			sqlmock.AnyArg(),     // user_email
			sqlmock.AnyArg(),     // user_role
			sqlmock.AnyArg(),     // client_id
			sqlmock.AnyArg(),     // tenant_id
			sqlmock.AnyArg(),     // org_id
			requestType,          // request_type
			sqlmock.AnyArg(),     // query
			sqlmock.AnyArg(),     // query_hash
			mcpVerdictRedacted,   // policy_decision = 'redacted' — NOT 'allowed'
			sqlmock.AnyArg(),     // policy_details
			sqlmock.AnyArg(),     // decision_id
			PlaneMCP,             // plane=mcp
			nil,                  // correlation_id NULL
			captureArg{dst: dst}, // redacted_fields populated (#2641 DoD)
			nil,                  // session_id NULL — no X-Session-Id on ctx (#2753)
			sqlmock.AnyArg(),     // response_time_ms (#3424)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
}

// setUsageDBMock swaps the package usageDB for a strict sqlmock and restores it.
func setUsageDBMock(t *testing.T) (sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	origDB := usageDB
	usageDB = db
	return mock, func() {
		usageDB = origDB
		_ = db.Close()
	}
}

// registerExecConnector resets the MCP registry to a single mock connector named
// "test-db" (wildcard tenant, so community-mode access checks pass).
func registerExecConnector(t *testing.T, conn *mockConnector) {
	t.Helper()
	mcpRegistry = registry.NewRegistry()
	if err := mcpRegistry.Register("test-db", conn, &base.ConnectorConfig{Name: "test-db", TenantID: "*"}); err != nil {
		t.Fatalf("register connector: %v", err)
	}
}

// quietPolicyEngines nils the static + dynamic engines and resets the exfil
// checker so a handler reaches a clean terminal verdict deterministically.
func quietPolicyEngines(t *testing.T) {
	t.Helper()
	origEngine := sharedpolicy.GetGlobalEngine()
	origEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	origExfil := sharedpolicy.GetGlobalExfiltrationChecker()
	sharedpolicy.SetGlobalEngine(nil)
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	sharedpolicy.ResetGlobalExfiltrationChecker()
	t.Cleanup(func() {
		sharedpolicy.SetGlobalEngine(origEngine)
		sharedpolicy.SetGlobalDynamicPolicyEvaluator(origEval)
		sharedpolicy.SetGlobalExfiltrationChecker(origExfil)
	})
}

// denyingDynamicEvaluator points the global dynamic evaluator at a mock
// orchestrator that blocks "test-db", and nils the static engine (dynamic-ONLY).
func denyingDynamicEvaluator(t *testing.T) {
	t.Helper()
	origEngine := sharedpolicy.GetGlobalEngine()
	origEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalEngine(nil) // no static match → dynamic-ONLY block
	server := mockOrchestratorServer(t, sharedpolicy.DynamicPolicyResponse{
		Allowed:           false,
		BlockReason:       "Budget exhausted",
		PoliciesEvaluated: 1,
		MatchedPolicies: []sharedpolicy.DynamicPolicyMatch{
			{PolicyID: "budget-1", PolicyType: "budget", Action: "block"},
		},
	})
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"test-db"},
	})
	t.Cleanup(func() {
		server.Close()
		sharedpolicy.SetGlobalEngine(origEngine)
		sharedpolicy.SetGlobalDynamicPolicyEvaluator(origEval)
	})
}

// unreachableDynamicEvaluator forces EvalUnavailable (fail-closed) by pointing the
// evaluator at an unroutable endpoint with GracefulDegradation=false.
func unreachableDynamicEvaluator(t *testing.T) {
	t.Helper()
	origEngine := sharedpolicy.GetGlobalEngine()
	origEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalEngine(nil)
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: "http://127.0.0.1:0", // unroutable
		Timeout:              200 * time.Millisecond,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"test-db"},
	})
	t.Cleanup(func() {
		sharedpolicy.SetGlobalEngine(origEngine)
		sharedpolicy.SetGlobalDynamicPolicyEvaluator(origEval)
	})
}

func postQuery(req MCPQueryRequest) *httptest.ResponseRecorder {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpQueryHandler(w, r)
	return w
}

func postExecute(req MCPExecuteRequest) *httptest.ResponseRecorder {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/mcp/tools/execute", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpExecuteHandler(w, r)
	return w
}

// --- resources/query ---------------------------------------------------------

// TestMCPQueryHandler_DynamicBlock_EmitsBlockedAudit: a dynamic-ONLY request block
// (no StaticResult present) must write a canonical 'blocked' row — previously it
// wrote only the reader-less satellite and showed as "Logged".
func TestMCPQueryHandler_DynamicBlock_EmitsBlockedAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mock, restore := setUsageDBMock(t)
	defer restore()
	registerExecConnector(t, &mockConnector{})
	denyingDynamicEvaluator(t)

	expectCanonicalDecisionRow(mock, "mcp_resources_query", mcpVerdictBlocked)

	w := postQuery(MCPQueryRequest{Connector: "test-db", Statement: "SELECT * FROM users"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (dynamic block), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("dynamic block did not emit a canonical 'blocked' audit row: %v", err)
	}
}

// TestMCPQueryHandler_ResponseRedaction_EmitsRedactedAudit: a NIK in the response
// rows is masked under PII_ACTION=redact. The decision is ALLOWED (200) yet a
// 'redacted' row carrying redacted_fields must still be written — the worst hole
// (a leak-mask that wrote nothing). Precondition-absent: no static engine, no block.
func TestMCPQueryHandler_ResponseRedaction_EmitsRedactedAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mock, restore := setUsageDBMock(t)
	defer restore()
	registerExecConnector(t, &mockConnector{queryResult: &base.QueryResult{
		Rows:     []map[string]interface{}{{"info": "Pelanggan NIK 3174042506780001 terdaftar"}},
		RowCount: 1,
		Duration: time.Millisecond,
	}})
	// PII_ACTION=redact + Indonesia response detector (also nils the static engine).
	withMCPPIIAction(t, DetectionActionRedact)
	origEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalDynamicPolicyEvaluator(origEval) })

	var redactedFieldsJSON []byte
	expectRedactedDecisionRow(mock, "mcp_resources_query", &redactedFieldsJSON)

	w := postQuery(MCPQueryRequest{Connector: "test-db", Statement: "SELECT * FROM customers"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (redact-and-allow), got %d: %s", w.Code, w.Body.String())
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

// TestMCPQueryHandler_CleanAllow_EmitsAllowedAudit: a clean allow is portal-visible
// too (the connector-exec PEP audits allows, mirroring check-input #2627).
func TestMCPQueryHandler_CleanAllow_EmitsAllowedAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mock, restore := setUsageDBMock(t)
	defer restore()
	registerExecConnector(t, &mockConnector{})
	quietPolicyEngines(t)

	expectCanonicalDecisionRow(mock, "mcp_resources_query", mcpVerdictAllowed)

	w := postQuery(MCPQueryRequest{Connector: "test-db", Statement: "SELECT 1"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (clean allow), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("clean allow did not emit an 'allowed' audit row: %v", err)
	}
}

// TestMCPQueryHandler_ExfilBlock_EmitsBlockedAudit: a response-phase exfiltration
// block must write a canonical 'blocked' row (covers the response-phase emit).
func TestMCPQueryHandler_ExfilBlock_EmitsBlockedAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mock, restore := setUsageDBMock(t)
	defer restore()

	origEngine := sharedpolicy.GetGlobalEngine()
	origEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	origExfil := sharedpolicy.GetGlobalExfiltrationChecker()
	sharedpolicy.SetGlobalEngine(nil)
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	sharedpolicy.InitGlobalExfiltrationCheckerWithLimits(sharedpolicy.ExfiltrationLimits{
		MaxRowsPerQuery:  2,
		MaxBytesPerQuery: 10 * 1024 * 1024,
		Enabled:          true,
	})
	t.Cleanup(func() {
		sharedpolicy.SetGlobalEngine(origEngine)
		sharedpolicy.SetGlobalDynamicPolicyEvaluator(origEval)
		sharedpolicy.SetGlobalExfiltrationChecker(origExfil)
	})

	registerExecConnector(t, &mockConnector{queryResult: &base.QueryResult{
		Rows:     []map[string]interface{}{{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}},
		RowCount: 4, // > 2 limit
		Duration: time.Millisecond,
	}})

	expectCanonicalDecisionRow(mock, "mcp_resources_query", mcpVerdictBlocked)

	w := postQuery(MCPQueryRequest{Connector: "test-db", Statement: "SELECT * FROM users"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (exfil block), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("exfil block did not emit a canonical 'blocked' audit row: %v", err)
	}
}

// TestMCPQueryHandler_ToolError_EmitsErrorAudit: a connector execution failure is a
// tool-error fail-closed → canonical 'error' row (never the raw error string).
func TestMCPQueryHandler_ToolError_EmitsErrorAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mock, restore := setUsageDBMock(t)
	defer restore()
	registerExecConnector(t, &mockConnector{queryError: errors.New("connection refused to 10.0.0.5")})
	quietPolicyEngines(t)

	expectCanonicalDecisionRow(mock, "mcp_resources_query", mcpVerdictError)

	w := postQuery(MCPQueryRequest{Connector: "test-db", Statement: "SELECT 1"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 (tool error), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("tool error did not emit a canonical 'error' audit row: %v", err)
	}
}

// TestMCPQueryHandler_EvalUnavailable_EmitsErrorAudit: an unreachable dynamic
// evaluator fails closed (503) and must record the unevaluated attempt as 'error'.
func TestMCPQueryHandler_EvalUnavailable_EmitsErrorAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mock, restore := setUsageDBMock(t)
	defer restore()
	registerExecConnector(t, &mockConnector{})
	unreachableDynamicEvaluator(t)

	expectCanonicalDecisionRow(mock, "mcp_resources_query", mcpVerdictError)

	w := postQuery(MCPQueryRequest{Connector: "test-db", Statement: "SELECT 1"})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (eval unavailable), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("eval-unavailable did not emit a canonical 'error' audit row: %v", err)
	}
}

// --- tools/execute -----------------------------------------------------------

// TestMCPExecuteHandler_DynamicBlock_EmitsBlockedAudit: dynamic-ONLY block on the
// execute route → canonical 'blocked' row.
func TestMCPExecuteHandler_DynamicBlock_EmitsBlockedAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mock, restore := setUsageDBMock(t)
	defer restore()
	registerExecConnector(t, &mockConnector{})
	denyingDynamicEvaluator(t)

	expectCanonicalDecisionRow(mock, "mcp_tools_execute", mcpVerdictBlocked)

	w := postExecute(MCPExecuteRequest{Connector: "test-db", Action: "INSERT", Statement: "INSERT INTO t VALUES (1)"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (dynamic block), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("dynamic block did not emit a canonical 'blocked' audit row: %v", err)
	}
}

// TestMCPExecuteHandler_ResponseRedaction_EmitsRedactedAudit: a NIK in the execute
// result message is masked under PII_ACTION=redact → 'redacted' row + redacted_fields.
func TestMCPExecuteHandler_ResponseRedaction_EmitsRedactedAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mock, restore := setUsageDBMock(t)
	defer restore()
	registerExecConnector(t, &mockConnector{executeResult: &base.CommandResult{
		RowsAffected: 1,
		Duration:     time.Millisecond,
		Message:      validNIKResponse, // contains a valid NIK
	}})
	withMCPPIIAction(t, DetectionActionRedact)
	origEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalDynamicPolicyEvaluator(origEval) })

	var redactedFieldsJSON []byte
	expectRedactedDecisionRow(mock, "mcp_tools_execute", &redactedFieldsJSON)

	w := postExecute(MCPExecuteRequest{Connector: "test-db", Action: "UPDATE", Statement: "UPDATE customers SET x=1"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (redact-and-allow), got %d: %s", w.Code, w.Body.String())
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

// TestMCPExecuteHandler_CleanAllow_EmitsAllowedAudit: clean allow → 'allowed' row.
func TestMCPExecuteHandler_CleanAllow_EmitsAllowedAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mock, restore := setUsageDBMock(t)
	defer restore()
	registerExecConnector(t, &mockConnector{})
	quietPolicyEngines(t)

	expectCanonicalDecisionRow(mock, "mcp_tools_execute", mcpVerdictAllowed)

	w := postExecute(MCPExecuteRequest{Connector: "test-db", Action: "INSERT", Statement: "INSERT INTO t VALUES (1)"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (clean allow), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("clean allow did not emit an 'allowed' audit row: %v", err)
	}
}

// TestMCPExecuteHandler_SQLiResponseBlock_EmitsBlockedAudit: a SQLi pattern in the
// execute result message triggers a response-phase block → canonical 'blocked' row
// (covers the execute route's response-phase emit call site).
func TestMCPExecuteHandler_SQLiResponseBlock_EmitsBlockedAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mock, restore := setUsageDBMock(t)
	defer restore()

	origEngine := sharedpolicy.GetGlobalEngine()
	origEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	origSQLi := sqli.GetGlobalMiddleware()
	sharedpolicy.SetGlobalEngine(nil)
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	mw, err := sqli.NewScanningMiddleware(sqli.WithMiddlewareConfig(sqli.DefaultConfig().WithBlockOnDetection(true)))
	if err != nil {
		t.Fatalf("new sqli middleware: %v", err)
	}
	sqli.SetGlobalMiddleware(mw)
	t.Cleanup(func() {
		sharedpolicy.SetGlobalEngine(origEngine)
		sharedpolicy.SetGlobalDynamicPolicyEvaluator(origEval)
		sqli.SetGlobalMiddleware(origSQLi)
	})

	registerExecConnector(t, &mockConnector{executeResult: &base.CommandResult{
		RowsAffected: 1,
		Duration:     time.Millisecond,
		Message:      "admin' UNION SELECT password FROM users WHERE 1=1 OR 1=1 --",
	}})

	expectCanonicalDecisionRow(mock, "mcp_tools_execute", mcpVerdictBlocked)

	w := postExecute(MCPExecuteRequest{Connector: "test-db", Action: "UPDATE", Statement: "UPDATE t SET x=1"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (SQLi response block), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("SQLi response block did not emit a canonical 'blocked' audit row: %v", err)
	}
}

// TestMCPExecuteHandler_ToolError_EmitsErrorAudit: execute failure → 'error' row.
func TestMCPExecuteHandler_ToolError_EmitsErrorAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mock, restore := setUsageDBMock(t)
	defer restore()
	registerExecConnector(t, &mockConnector{executeError: errors.New("deadlock detected on table accounts")})
	quietPolicyEngines(t)

	expectCanonicalDecisionRow(mock, "mcp_tools_execute", mcpVerdictError)

	w := postExecute(MCPExecuteRequest{Connector: "test-db", Action: "INSERT", Statement: "INSERT INTO t VALUES (1)"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 (tool error), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("tool error did not emit a canonical 'error' audit row: %v", err)
	}
}

// TestMCPExecuteHandler_EvalUnavailable_EmitsErrorAudit: fail-closed 503 → 'error' row.
func TestMCPExecuteHandler_EvalUnavailable_EmitsErrorAudit(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mock, restore := setUsageDBMock(t)
	defer restore()
	registerExecConnector(t, &mockConnector{})
	unreachableDynamicEvaluator(t)

	expectCanonicalDecisionRow(mock, "mcp_tools_execute", mcpVerdictError)

	w := postExecute(MCPExecuteRequest{Connector: "test-db", Action: "INSERT", Statement: "INSERT INTO t VALUES (1)"})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (eval unavailable), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("eval-unavailable did not emit a canonical 'error' audit row: %v", err)
	}
}
