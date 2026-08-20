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
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	sharedpolicy "axonflow/platform/shared/policy"
)

// =============================================================================
// #2563 (AUDIT-A1): MCP check-output → canonical audit_logs decision row
//
// The customer portal's decisions feed (orchestrator GET /api/v1/decisions)
// reads audit_logs WHERE policy_details->>'decision_id' IS NOT NULL. The MCP
// response plane previously persisted blocks only to mcp_query_audits, which
// the portal never reads — so a NIK/NPWP response block showed as "Logged",
// not "Blocked". mcpCheckOutputHandler now reuses the SAME writer /decide uses
// (recordDecideDecision → writeDecisionAuditLog) so the decision lands in the
// portal feed. These tests pin both the branch→verdict mapping and the fact
// that the handler actually emits the row (red-on-revert).
// =============================================================================

// TestMCPOutputDecisionVerdict pins the pure branch→(verdict, policy_ids,
// reasons) mapping for every terminal outcome of mcpCheckOutputHandler. The
// switch order here MUST mirror the handler's branch order (SQLi → static block
// → exfil → allow) so the recorded verdict always matches the HTTP branch that
// fires.
func TestMCPOutputDecisionVerdict(t *testing.T) {
	tests := []struct {
		name        string
		outcome     OutputPolicyOutcome
		wantVerdict string
		wantPolicy  []string
		wantReasons []string
	}{
		{
			name: "sqli block → deny",
			outcome: OutputPolicyOutcome{
				SQLiBlocked: true,
				SQLiPattern: "UNION SELECT",
			},
			wantVerdict: mcpVerdictBlocked,
			wantPolicy:  []string{"sqli_response_scan"},
			wantReasons: []string{"SQL injection detected in response: UNION SELECT"},
		},
		{
			name: "static block (e.g. Indonesia NIK hard-deny) → deny with matched policy ids",
			outcome: OutputPolicyOutcome{
				StaticResult: &sharedpolicy.ResponseResult{
					Blocked:     true,
					BlockReason: "Indonesia NIK detected in response",
					MatchedPolicies: []sharedpolicy.PolicyMatch{
						{PolicyID: "pii-indonesia-nik"},
					},
				},
			},
			wantVerdict: mcpVerdictBlocked,
			wantPolicy:  []string{"pii-indonesia-nik"},
			wantReasons: []string{"Indonesia NIK detected in response"},
		},
		{
			name: "Indonesia NIK hard-deny (BlockedBy only, no MatchedPolicies) → deny attributes BlockedBy",
			outcome: OutputPolicyOutcome{
				StaticResult: &sharedpolicy.ResponseResult{
					Blocked:     true,
					BlockReason: "Critical Indonesia PII detected (NIK or NPWP)",
					BlockedBy:   &sharedpolicy.CompiledPolicy{PolicyID: "sys_pii_indonesia_ktp"},
				},
			},
			wantVerdict: mcpVerdictBlocked,
			wantPolicy:  []string{"sys_pii_indonesia_ktp"},
			wantReasons: []string{"Critical Indonesia PII detected (NIK or NPWP)"},
		},
		{
			name: "exfiltration exceeded → deny",
			outcome: OutputPolicyOutcome{
				ExfilResult: &sharedpolicy.ExfiltrationResult{
					Exceeded:    true,
					LimitType:   "rows",
					BlockReason: "row limit exceeded (5 > 2)",
				},
			},
			wantVerdict: mcpVerdictBlocked,
			wantPolicy:  []string{"exfiltration_limit"},
			wantReasons: []string{"row limit exceeded (5 > 2)"},
		},
		{
			name: "static redaction → allow, redact is portal-visible (HARD RULE 1)",
			outcome: OutputPolicyOutcome{
				StaticResult: &sharedpolicy.ResponseResult{
					Redacted: true,
					RedactedFields: []sharedpolicy.RedactedField{
						{Path: "rows[0].ssn", PolicyID: "pii-us-ssn", PIIType: "ssn"},
					},
					MatchedPolicies: []sharedpolicy.PolicyMatch{
						{PolicyID: "pii-us-ssn"},
					},
				},
			},
			wantVerdict: mcpVerdictRedacted,
			wantPolicy:  []string{"pii-us-ssn"},
			wantReasons: []string{"response PII redacted: rows[0].ssn"},
		},
		{
			name: "Indonesia-only redaction (StaticResult nil) → allow, reason from Indonesia types",
			outcome: OutputPolicyOutcome{
				RedactedMessage:        "NIK 31**********0001",
				IndonesiaRedactedTypes: []string{"nik"},
			},
			wantVerdict: mcpVerdictRedacted,
			wantPolicy:  nil,
			wantReasons: []string{"response PII redacted: nik"},
		},
		{
			name:        "clean allow → allowed, no policy ids, no reasons",
			outcome:     OutputPolicyOutcome{},
			wantVerdict: mcpVerdictAllowed,
			wantPolicy:  nil,
			wantReasons: nil,
		},
		{
			name: "deny precedence: SQLi wins over a present static result",
			outcome: OutputPolicyOutcome{
				SQLiBlocked: true,
				SQLiPattern: "; DROP TABLE",
				StaticResult: &sharedpolicy.ResponseResult{
					Blocked:     true,
					BlockReason: "should not be used",
				},
			},
			wantVerdict: mcpVerdictBlocked,
			wantPolicy:  []string{"sqli_response_scan"},
			wantReasons: []string{"SQL injection detected in response: ; DROP TABLE"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotVerdict, gotPolicy, gotReasons, _ := mcpOutputDecisionVerdict(tc.outcome)
			if gotVerdict != tc.wantVerdict {
				t.Errorf("verdict: got %q, want %q", gotVerdict, tc.wantVerdict)
			}
			if !reflect.DeepEqual(gotPolicy, tc.wantPolicy) {
				t.Errorf("policy_ids: got %v, want %v", gotPolicy, tc.wantPolicy)
			}
			if !reflect.DeepEqual(gotReasons, tc.wantReasons) {
				t.Errorf("reasons: got %v, want %v", gotReasons, tc.wantReasons)
			}
			// #2641: the response plane emits the canonical past-tense vocab the
			// portal decisions feed keys on — blocked | redacted | allowed (never the
			// legacy allow/deny). needs_approval is not a response-plane outcome.
			switch tc.wantVerdict {
			case mcpVerdictBlocked, mcpVerdictRedacted, mcpVerdictAllowed:
				// canonical
			default:
				t.Fatalf("unexpected verdict in fixture: %q", tc.wantVerdict)
			}
		})
	}
}

// TestMCPCheckOutputHandler_BlockEmitsAuditLogsDecisionRow is the red-on-revert
// guard: a blocked MCP response (exfiltration exceeded here — a deterministic
// block that needs no live policy engine) MUST write a canonical audit_logs
// decision row with policy_decision='deny' and request_type='decision_tool',
// via the same recordDecideDecision writer /decide uses. If the emit is removed
// from mcpCheckOutputHandler, the expected INSERT never fires and
// ExpectationsWereMet() fails — turning this test red.
func TestMCPCheckOutputHandler_BlockEmitsAuditLogsDecisionRow(t *testing.T) {
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

	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)
	sharedpolicy.InitGlobalExfiltrationCheckerWithLimits(sharedpolicy.ExfiltrationLimits{
		MaxRowsPerQuery:  2,
		MaxBytesPerQuery: 10 * 1024 * 1024,
		Enabled:          true,
	})

	// The canonical audit_logs decision row. id and most identity columns vary
	// per request (decision_id is a fresh uuid) → AnyArg; the columns this
	// feature exists to guarantee are pinned: request_type='decision_tool'
	// (DecisionStageTool) and policy_decision='deny'.
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), // id (decide_<decision_id>)
			sqlmock.AnyArg(), // request_id
			sqlmock.AnyArg(), // timestamp
			sqlmock.AnyArg(), // user_id
			sqlmock.AnyArg(), // user_email
			sqlmock.AnyArg(), // user_role
			sqlmock.AnyArg(), // client_id
			sqlmock.AnyArg(), // tenant_id
			sqlmock.AnyArg(), // org_id
			"decision_tool",  // request_type
			sqlmock.AnyArg(), // query (non-PII descriptor)
			sqlmock.AnyArg(), // query_hash
			"blocked",        // policy_decision
			sqlmock.AnyArg(), // policy_details (JSONB)
			sqlmock.AnyArg(), // decision_id (first-class column; #2592)
			PlaneMCP,         // plane — MCP response surface (#2592)
			nil,              // obligations (none on a block)
			// correlation_id (#2598): the MCP response plane stamps the inbound
			// traceparent's W3C trace-id so this block groups with the other stages
			// of the SAME logical tool call. Pinned to prove the threading.
			"0af7651916cd43dd8448eb211c80319c",
			nil, // redacted_fields (#2643): MCP block has none → NULL
			nil, // session_id (#2896): no trusted client session id → NULL
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	rows := []map[string]interface{}{
		{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5},
	}
	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		ResponseData:  rows,
		RowCount:      5,
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	// Propagate a W3C traceparent so the response-plane decision carries a
	// correlation_id (#2598). trace-id 0af7651916cd43dd8448eb211c80319c.
	req.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (block), got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckOutputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Allowed {
		t.Error("expected allowed=false on the block path")
	}
	if resp.DecisionID == "" {
		t.Error("block path must surface decision_id (same id as the audit_logs row)")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("audit_logs decision row was not emitted by the block path: %v", err)
	}
}

// TestMCPCheckOutputHandler_AllowEmitsAuditLogsDecisionRow proves the allow path
// also converges onto audit_logs (policy_decision='allow'), so a clean or
// redacted response is portal-visible — not just blocks. Mirrors the block test
// with a no-exfiltration message-style response.
func TestMCPCheckOutputHandler_AllowEmitsAuditLogsDecisionRow(t *testing.T) {
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

	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	sharedpolicy.SetGlobalExfiltrationChecker(nil)
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

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
			PlaneMCP,         // plane — MCP response surface (#2592)
			nil,              // obligations (none on a clean allow)
			nil,              // correlation_id (#2598): no traceparent → NULL → singleton
			nil,              // redacted_fields (#2643): clean allow → NULL
			nil,              // session_id (#2896): no trusted client session id → NULL
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
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
		t.Errorf("audit_logs decision row was not emitted by the allow path: %v", err)
	}
}
