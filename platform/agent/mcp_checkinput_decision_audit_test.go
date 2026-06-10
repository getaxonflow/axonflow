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
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	sharedpolicy "axonflow/platform/shared/policy"
)

// =============================================================================
// #2627 (AUDIT-FIX-B): MCP check-input → canonical audit_logs decision row
//
// The customer portal's decisions feed (orchestrator GET /api/v1/decisions)
// reads audit_logs WHERE policy_details->>'decision_id' IS NOT NULL. The MCP
// request plane previously persisted dynamic-block + allow (+redact) terminal
// verdicts ONLY to the mcp_query_audits satellite, which the portal never reads
// — so a dynamic-policy block showed as "Logged", not "Blocked", and an allow
// never appeared at all. mcpCheckInputHandler now reuses the SAME writer /decide
// uses (recordDecideDecision → writeDecisionAuditLog) so those decisions land in
// the portal feed, keyed by the same decision_id as the satellite — mirroring
// the response plane (#2586). The static-block deny + override-flip allow already
// dual-write canonical rows (writeExplainableAuditLog / writeOverrideUsedEvent)
// and are deliberately NOT routed through the new emit. These tests pin both the
// branch→verdict mapping and the fact that the handler actually emits the row
// (red-on-revert).
// =============================================================================

// TestMCPInputDecisionVerdict pins the pure branch→(verdict, policy_ids, reasons)
// mapping for the two terminal outcomes mcpInputDecisionVerdict covers
// (dynamic-block deny → allow). The static-block deny is intentionally absent: it
// dual-writes a richer audit_logs row via writeExplainableAuditLog and must not be
// routed here.
func TestMCPInputDecisionVerdict(t *testing.T) {
	tests := []struct {
		name        string
		outcome     InputPolicyOutcome
		didRedact   bool
		wantVerdict string
		wantPolicy  []string
		wantReasons []string
	}{
		{
			name: "dynamic block with matched policy ids → deny",
			outcome: InputPolicyOutcome{
				DynamicBlocked:     true,
				DynamicBlockReason: "Rate limit exceeded",
				DynamicInfo: &sharedpolicy.DynamicPolicyInfo{
					MatchedPolicies: []sharedpolicy.DynamicPolicyMatch{
						{PolicyID: "rate-limit-1", Action: "block"},
					},
				},
			},
			wantVerdict: VerdictDeny,
			wantPolicy:  []string{"rate-limit-1"},
			wantReasons: []string{"Rate limit exceeded"},
		},
		{
			name: "dynamic block, no per-policy match → deny attributes the dynamic_policy sentinel",
			outcome: InputPolicyOutcome{
				DynamicBlocked:     true,
				DynamicBlockReason: "Budget exhausted",
				DynamicInfo:        &sharedpolicy.DynamicPolicyInfo{},
			},
			wantVerdict: VerdictDeny,
			wantPolicy:  []string{"dynamic_policy"},
			wantReasons: []string{"Budget exhausted"},
		},
		{
			name: "dynamic block, nil DynamicInfo → deny attributes the dynamic_policy sentinel",
			outcome: InputPolicyOutcome{
				DynamicBlocked:     true,
				DynamicBlockReason: "blocked",
			},
			wantVerdict: VerdictDeny,
			wantPolicy:  []string{"dynamic_policy"},
			wantReasons: []string{"blocked"},
		},
		{
			name:        "clean allow → allow, no policy ids, no reasons",
			outcome:     InputPolicyOutcome{},
			wantVerdict: VerdictAllow,
			wantPolicy:  nil,
			wantReasons: nil,
		},
		{
			name: "allow with a matched (non-blocking redact) static policy → allow, policy ids surfaced",
			outcome: InputPolicyOutcome{
				StaticResult: &sharedpolicy.RequestResult{
					MatchedPolicies: []sharedpolicy.PolicyMatch{
						{PolicyID: "pii-us-ssn"},
					},
				},
			},
			didRedact:   true,
			wantVerdict: VerdictAllow,
			wantPolicy:  []string{"pii-us-ssn"},
			wantReasons: []string{"request PII redacted"},
		},
		{
			name:        "redact with no static result (engine-only redactor) → allow, redact reason still surfaced",
			outcome:     InputPolicyOutcome{},
			didRedact:   true,
			wantVerdict: VerdictAllow,
			wantPolicy:  nil,
			wantReasons: []string{"request PII redacted"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotVerdict, gotPolicy, gotReasons := mcpInputDecisionVerdict(tc.outcome, tc.didRedact)
			if gotVerdict != tc.wantVerdict {
				t.Errorf("verdict: got %q, want %q", gotVerdict, tc.wantVerdict)
			}
			if !reflect.DeepEqual(gotPolicy, tc.wantPolicy) {
				t.Errorf("policy_ids: got %v, want %v", gotPolicy, tc.wantPolicy)
			}
			if !reflect.DeepEqual(gotReasons, tc.wantReasons) {
				t.Errorf("reasons: got %v, want %v", gotReasons, tc.wantReasons)
			}
			// allow/deny are the only verdicts the request plane can emit
			// (needs_approval is not a check-input outcome).
			if tc.wantVerdict != VerdictAllow && tc.wantVerdict != VerdictDeny {
				t.Fatalf("unexpected verdict in fixture: %q", tc.wantVerdict)
			}
		})
	}
}

// TestMCPCheckInputHandler_DynamicBlockEmitsAuditLogsDecisionRow is the
// red-on-revert guard for the dynamic-block branch: a request blocked by the
// dynamic policy engine MUST write a canonical audit_logs decision row with
// policy_decision='deny' and request_type='decision_tool', via the same
// recordDecideDecision writer /decide uses. If the emit is removed, the expected
// INSERT never fires and ExpectationsWereMet() fails — turning this test red.
func TestMCPCheckInputHandler_DynamicBlockEmitsAuditLogsDecisionRow(t *testing.T) {
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

	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)

	// Orchestrator denies the request → dynamic block.
	server := mockOrchestratorServer(t, sharedpolicy.DynamicPolicyResponse{
		Allowed:           false,
		BlockReason:       "Rate limit exceeded",
		PoliciesEvaluated: 1,
		MatchedPolicies: []sharedpolicy.DynamicPolicyMatch{
			{PolicyID: "rate-limit-1", PolicyType: "rate-limit", Action: "block"},
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

	// The canonical audit_logs decision row. decision_id is a fresh uuid → AnyArg;
	// the columns this feature exists to guarantee are pinned: request_type=
	// 'decision_tool' (DecisionStageTool) and policy_decision='deny'.
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
			"deny",           // policy_decision
			sqlmock.AnyArg(), // policy_details (JSONB)
			sqlmock.AnyArg(), // decision_id (first-class column; #2592)
			PlaneMCP,         // plane — MCP request surface (#2627)
			nil,              // obligations (none on a block)
			// correlation_id (#2598): the inbound traceparent's W3C trace-id, pinned
			// to prove the request plane threads it just like the response plane.
			"0af7651916cd43dd8448eb211c80319c",
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT * FROM users",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (block), got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Allowed {
		t.Error("expected allowed=false on the dynamic-block path")
	}
	if resp.DecisionID == "" {
		t.Error("block path must surface decision_id (same id as the audit_logs row)")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("audit_logs decision row was not emitted by the dynamic-block path: %v", err)
	}
}

// TestMCPCheckInputHandler_AllowEmitsAuditLogsDecisionRow proves the terminal
// allow path also converges onto audit_logs (policy_decision='allow'), so a clean
// (or redacted) request is portal-visible — not just blocks. Mirrors the
// dynamic-block test with no policy engines configured (clean allow).
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

	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)

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
			"allow",          // policy_decision
			sqlmock.AnyArg(), // policy_details
			sqlmock.AnyArg(), // decision_id (first-class column; #2592)
			PlaneMCP,         // plane — MCP request surface (#2627)
			nil,              // obligations (none on a clean allow)
			nil,              // correlation_id (#2598): no traceparent → NULL → singleton
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
