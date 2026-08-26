// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestAuditSummaryHandler_HandleSummary_ValidRequest(t *testing.T) {
	// #3096: auditSummaryRequestHandler resolves its read scope via
	// resolveCallerReadScope. This test covers the summary payload, not read
	// authority, and reached the tenant-wide path via an unset
	// DEPLOYMENT_MODE; unset is now the enterprise posture, so name the mode.
	t.Setenv("DEPLOYMENT_MODE", "community")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	handler := NewAuditSummaryHandler(db)

	// Mock action query
	actionRows := sqlmock.NewRows([]string{"request_type", "policy_decision", "cnt"}).
		AddRow("llm_call", "allowed", 80).
		AddRow("llm_call", "blocked", 10).
		AddRow("tool_call", "allowed", 5).
		AddRow("tool_call", "redacted", 5)
	mock.ExpectQuery("SELECT request_type, policy_decision, COUNT").
		WithArgs("travel-us", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(actionRows)

	// Mock latency query (v7.4.1+: powers the Avg Latency card)
	latencyRows := sqlmock.NewRows([]string{"avg", "samples"}).AddRow(150.5, 12)
	mock.ExpectQuery("SELECT AVG\\(response_time_ms\\), COUNT").
		WithArgs("travel-us", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(latencyRows)

	// Mock policy query. The matcher is the LATERAL expansion, not a bare
	// "SELECT" (#3426): a matcher that loose accepted the defective query that
	// grouped on the singular policy_details->>'policy_name', AND it accepted
	// the shared-chain query, so it could not tell them apart. Worse, this
	// handler treats a failed policy query as non-fatal, so a mismatch here
	// produced an empty tile and a green test.
	policyRows := sqlmock.NewRows([]string{"policy_name", "identity_is_name", "trigger_count", "block_count", "total_policies"}).
		// The real server shape (#3426): identity-first policy_name, the
		// identity_is_name flag saying whether that string is a stamped NAME or a
		// raw id, and the pre-LIMIT distinct total. A mock that omits either
		// certifies a renderer reading fields the server never sent.
		AddRow("demo-block-bulk-email", true, 8, 8, 2).
		AddRow("pii-detection", false, 5, 2, 2)
	mock.ExpectQuery("CROSS JOIN LATERAL unnest").
		WithArgs("travel-us", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(policyRows)

	body := `{"start_time":"2026-01-01T00:00:00Z","end_time":"2026-04-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var summary ComplianceSummary
	if err := json.NewDecoder(rr.Body).Decode(&summary); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if summary.TotalEvents != 100 {
		t.Errorf("expected 100 total events, got %d", summary.TotalEvents)
	}
	if summary.ByAction["llm_call"] != 90 {
		t.Errorf("expected 90 llm_call events, got %d", summary.ByAction["llm_call"])
	}
	if summary.ByAction["tool_call"] != 10 {
		t.Errorf("expected 10 tool_call events, got %d", summary.ByAction["tool_call"])
	}
	if summary.ComplianceScore != 90.0 {
		t.Errorf("expected compliance score 90.0, got %f", summary.ComplianceScore)
	}
	if len(summary.TopPolicies) != 2 {
		t.Errorf("expected 2 top policies, got %d", len(summary.TopPolicies))
	}
	if summary.TopPolicies[0].PolicyName != "demo-block-bulk-email" {
		t.Errorf("expected first policy 'demo-block-bulk-email', got '%s'", summary.TopPolicies[0].PolicyName)
	}
	if summary.BySeverity["critical"] != 10 {
		t.Errorf("expected 10 critical (blocked) events, got %d", summary.BySeverity["critical"])
	}
	if summary.BySeverity["warning"] != 5 {
		t.Errorf("expected 5 warning (redacted) events, got %d", summary.BySeverity["warning"])
	}

	// v7.4.1+ card-view aggregates (Bug 2): portal UI reads these directly.
	// total=100 (80+10+5+5), allowed=85 (80+5), blocked=10, modified=5,
	// block_rate=10%, avg_latency=150.5ms.
	if summary.TotalRequests != 100 {
		t.Errorf("expected total_requests=100, got %d", summary.TotalRequests)
	}
	if summary.AllowedRequests != 85 {
		t.Errorf("expected allowed_requests=85, got %d", summary.AllowedRequests)
	}
	if summary.BlockedRequests != 10 {
		t.Errorf("expected blocked_requests=10, got %d", summary.BlockedRequests)
	}
	if summary.ModifiedRequests != 5 {
		t.Errorf("expected modified_requests=5, got %d", summary.ModifiedRequests)
	}
	if summary.BlockRatePercent != 10.0 {
		t.Errorf("expected block_rate_percent=10.0, got %f", summary.BlockRatePercent)
	}
	if summary.AvgLatencyMs == nil {
		t.Fatalf("expected avg_latency_ms=150.5, got null (12 samples were reported)")
	}
	if *summary.AvgLatencyMs != 150.5 {
		t.Errorf("expected avg_latency_ms=150.5, got %f", *summary.AvgLatencyMs)
	}
	if summary.LatencySampleCount != 12 {
		t.Errorf("expected latency_sample_count=12, got %d", summary.LatencySampleCount)
	}
}

// Regression: the agent's check_policy path (the one the Claude Code / Cursor
// / Codex plugin PreToolUse hooks call) records a denied tool call with
// policy_decision="deny", NOT "blocked". The summary must count "deny" as
// blocked — otherwise a real block (e.g. an SSN caught by sys_pii_ssn) shows
// as 0 blocked / 100% compliance, masking a real block during evaluation.
func TestAuditSummaryHandler_HandleSummary_CountsDenyAsBlocked(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	handler := NewAuditSummaryHandler(db)

	// 3 allowed + 1 "deny" (plugin-hook vocabulary) + 1 "denied" variant.
	actionRows := sqlmock.NewRows([]string{"request_type", "policy_decision", "cnt"}).
		AddRow("mcp_check_policy", "allowed", 3).
		AddRow("mcp_check_policy", "deny", 1).
		AddRow("tool_call", "denied", 1)
	mock.ExpectQuery("SELECT request_type, policy_decision, COUNT").
		WithArgs("tenant-1", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(actionRows)

	latencyRows := sqlmock.NewRows([]string{"avg", "samples"}).AddRow(nil, 0)
	mock.ExpectQuery("SELECT AVG\\(response_time_ms\\), COUNT").
		WithArgs("tenant-1", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(latencyRows)

	policyRows := sqlmock.NewRows([]string{"policy_name", "identity_is_name", "trigger_count", "block_count", "total_policies"}).
		AddRow("SSN Detection", true, 1, 1, 1)
	mock.ExpectQuery("SELECT").
		WithArgs("tenant-1", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(policyRows)

	body := `{"start_time":"2026-01-01T00:00:00Z","end_time":"2026-04-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-1")
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var summary ComplianceSummary
	if err := json.NewDecoder(rr.Body).Decode(&summary); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// 2 of 5 are denials → blocked must be 2, allowed 3, severity critical 2.
	if summary.BlockedRequests != 2 {
		t.Errorf("expected blocked_requests=2 (deny+denied counted as blocked), got %d", summary.BlockedRequests)
	}
	if summary.AllowedRequests != 3 {
		t.Errorf("expected allowed_requests=3, got %d", summary.AllowedRequests)
	}
	if summary.BySeverity["critical"] != 2 {
		t.Errorf("expected 2 critical events, got %d", summary.BySeverity["critical"])
	}
	if summary.BlockRatePercent != 40.0 {
		t.Errorf("expected block_rate_percent=40.0, got %f", summary.BlockRatePercent)
	}
	// A block happened — compliance must NOT read as a perfect 100%.
	if summary.ComplianceScore == 100.0 {
		t.Errorf("compliance score should not be 100%% when 2/5 requests were blocked, got %f", summary.ComplianceScore)
	}
}

func TestAuditSummaryHandler_HandleSummary_InvalidBody(t *testing.T) {
	handler := NewAuditSummaryHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader("not json"))
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAuditSummaryHandler_HandleSummary_InvalidStartTime(t *testing.T) {
	handler := NewAuditSummaryHandler(nil)

	body := `{"start_time":"not-a-date","end_time":"2026-04-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAuditSummaryHandler_HandleSummary_InvalidEndTime(t *testing.T) {
	handler := NewAuditSummaryHandler(nil)

	body := `{"start_time":"2026-01-01T00:00:00Z","end_time":"not-a-date"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAuditSummaryHandler_HandleSummary_EndBeforeStart(t *testing.T) {
	handler := NewAuditSummaryHandler(nil)

	body := `{"start_time":"2026-04-01T00:00:00Z","end_time":"2026-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAuditSummaryHandler_HandleSummary_RangeExceedsOneYear(t *testing.T) {
	handler := NewAuditSummaryHandler(nil)

	body := `{"start_time":"2024-01-01T00:00:00Z","end_time":"2026-04-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAuditSummaryHandler_HandleSummary_MissingTenantID(t *testing.T) {
	handler := NewAuditSummaryHandler(nil)

	body := `{"start_time":"2026-01-01T00:00:00Z","end_time":"2026-04-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	// No X-Tenant-ID or X-Org-ID headers
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing tenant ID, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAuditSummaryHandler_HandleSummary_NilDB(t *testing.T) {
	handler := NewAuditSummaryHandler(nil)

	body := `{"start_time":"2026-01-01T00:00:00Z","end_time":"2026-04-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for nil db, got %d: %s", rr.Code, rr.Body.String())
	}

	var summary ComplianceSummary
	if err := json.NewDecoder(rr.Body).Decode(&summary); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if summary.TotalEvents != 0 {
		t.Errorf("expected 0 events for nil db, got %d", summary.TotalEvents)
	}
	if summary.ComplianceScore != 100 {
		t.Errorf("expected 100 compliance score for empty, got %f", summary.ComplianceScore)
	}
}

func TestAuditSummaryHandler_HandleSummary_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	handler := NewAuditSummaryHandler(db)

	mock.ExpectQuery("SELECT request_type").
		WillReturnError(sqlmock.ErrCancelled)

	body := `{"start_time":"2026-01-01T00:00:00Z","end_time":"2026-04-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestAuditSummaryHandler_HandleSummary_CORS(t *testing.T) {
	handler := NewAuditSummaryHandler(nil)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/audit/summary", nil)
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for OPTIONS, got %d", rr.Code)
	}
}

// v6.2.0: The X-Org-ID fallback was removed from audit summary because it
// was a permissive safety net that obscured auth middleware misconfig.
// X-Tenant-ID is always set by the agent's auth middleware from the
// authenticated session; its absence means the request bypassed auth
// and must be rejected.
func TestAuditSummaryHandler_HandleSummary_MissingTenantHeaderRejected(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	handler := NewAuditSummaryHandler(db)

	body := `{"start_time":"2026-01-01T00:00:00Z","end_time":"2026-04-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	// Only X-Org-ID set, no X-Tenant-ID. Must be rejected.
	req.Header.Set("X-Org-ID", "banking-india")
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAuditSummaryHandler_HandleSummary_ZeroBlockedEvents(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	handler := NewAuditSummaryHandler(db)

	actionRows := sqlmock.NewRows([]string{"request_type", "policy_decision", "cnt"}).
		AddRow("llm_call", "allowed", 50)
	mock.ExpectQuery("SELECT request_type").
		WillReturnRows(actionRows)

	policyRows := sqlmock.NewRows([]string{"policy_name", "identity_is_name", "trigger_count", "block_count", "total_policies"})
	mock.ExpectQuery("SELECT").
		WillReturnRows(policyRows)

	body := `{"start_time":"2026-01-01T00:00:00Z","end_time":"2026-04-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var summary ComplianceSummary
	json.NewDecoder(rr.Body).Decode(&summary)

	if summary.ComplianceScore != 100 {
		t.Errorf("expected 100%% compliance with no blocks, got %f", summary.ComplianceScore)
	}
}

func TestAuditSummaryHandler_HandleSummary_AllBlocked(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	handler := NewAuditSummaryHandler(db)

	actionRows := sqlmock.NewRows([]string{"request_type", "policy_decision", "cnt"}).
		AddRow("llm_call", "blocked", 10)
	mock.ExpectQuery("SELECT request_type").
		WillReturnRows(actionRows)

	policyRows := sqlmock.NewRows([]string{"policy_name", "identity_is_name", "trigger_count", "block_count", "total_policies"})
	mock.ExpectQuery("SELECT").
		WillReturnRows(policyRows)

	body := `{"start_time":"2026-01-01T00:00:00Z","end_time":"2026-04-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var summary ComplianceSummary
	json.NewDecoder(rr.Body).Decode(&summary)

	if summary.ComplianceScore != 0 {
		t.Errorf("expected 0%% compliance with all blocked, got %f", summary.ComplianceScore)
	}
}

func TestNewAuditSummaryHandler(t *testing.T) {
	handler := NewAuditSummaryHandler(nil)
	if handler == nil {
		t.Error("expected non-nil handler")
	}
	if handler.db != nil {
		t.Error("expected nil db")
	}
}

// TestAuditSummaryHandler_CardAggregates_EmptyTenant exercises the
// zero-traffic case: total_requests should be 0 and block_rate should NOT
// explode into NaN. The bug we shipped in v7.4.0 was the *opposite*
// (dashboard card showed zeros even when there WAS data). This test pins the
// no-data path so we don't regress either way.
//
// #3424 INVERTED THE LATENCY ASSERTION HERE. This test used to require
// avg_latency_ms == 0 on a tenant with no measured rows, which is precisely
// the behaviour that put a confident "Avg Latency: 0ms" on the portal for
// stacks serving real governed traffic: it made a count-like zero the
// contract for a measurement that did not exist. The count aggregates above
// genuinely are 0 when there is no traffic; an average over no samples is not
// 0, it is unknown, and the contract is now null + a sample count of 0. A
// test asserting the old value would keep re-certifying the defect.
func TestAuditSummaryHandler_CardAggregates_EmptyTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	handler := NewAuditSummaryHandler(db)

	mock.ExpectQuery("SELECT request_type, policy_decision, COUNT").
		WithArgs("empty-tenant", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"request_type", "policy_decision", "cnt"}))
	mock.ExpectQuery("SELECT AVG\\(response_time_ms\\), COUNT").
		WithArgs("empty-tenant", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"avg", "samples"}).AddRow(nil, 0))
	mock.ExpectQuery("SELECT").
		WithArgs("empty-tenant", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"policy_name", "identity_is_name", "trigger_count", "block_count", "total_policies"}))

	body := `{"start_time":"2026-04-22T00:00:00Z","end_time":"2026-04-23T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "empty-tenant")
	rr := httptest.NewRecorder()

	handler.HandleSummary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Snapshot the wire bytes BEFORE decoding: the decoder drains rr.Body, so
	// reading it afterwards yields "" and any assertion on it is vacuous.
	wire := rr.Body.String()

	var summary ComplianceSummary
	if err := json.NewDecoder(strings.NewReader(wire)).Decode(&summary); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if summary.TotalRequests != 0 {
		t.Errorf("total_requests = %d, want 0", summary.TotalRequests)
	}
	if summary.BlockRatePercent != 0.0 {
		t.Errorf("block_rate_percent = %f, want 0 (no NaN on empty set)", summary.BlockRatePercent)
	}
	if summary.AvgLatencyMs != nil {
		t.Errorf("avg_latency_ms = %f, want null (no measured samples must not render as a measured zero)", *summary.AvgLatencyMs)
	}
	if summary.LatencySampleCount != 0 {
		t.Errorf("latency_sample_count = %d, want 0", summary.LatencySampleCount)
	}
	// The serialized form is what the portal actually reads, so pin it: the key
	// must be present and null, not absent (an absent key and a null both read
	// as undefined/null in the client, but a `omitempty` slip would silently
	// change the wire contract for other consumers).
	if !strings.Contains(wire, `"avg_latency_ms":null`) {
		t.Errorf("wire form should carry avg_latency_ms:null, got %s", wire)
	}
	if summary.ComplianceScore != 100.0 {
		t.Errorf("compliance_score = %f, want 100 (no events = fully compliant)", summary.ComplianceScore)
	}
}

// TestAuditSummaryHandler_CardAggregates_NeedsApprovalAndErrorBucketed
// pins the corrected card-view triage (#2636/#2653): pending_approval and
// error are NO LONGER swept into allowed by a default arm — pending_approval
// normalizes to needs_approval and lands in needs_approval_requests, error
// lands in error_requests, and the arithmetic invariant
// total_requests == allowed + blocked + modified + needs_approval + error
// still closes. The old behavior (everything-not-blocked-or-redacted →
// allowed) corrupted block-rate/compliance metrics by inflating "allowed"
// with deferred-to-human and failed requests.
func TestAuditSummaryHandler_CardAggregates_NeedsApprovalAndErrorBucketed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	handler := NewAuditSummaryHandler(db)

	mock.ExpectQuery("SELECT request_type, policy_decision, COUNT").
		WithArgs("banking-demo", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"request_type", "policy_decision", "cnt"}).
			AddRow("llm_call", "allowed", 369).
			AddRow("workflow_step_gate", "pending_approval", 12).
			AddRow("llm_call", "error", 4))
	mock.ExpectQuery("SELECT AVG\\(response_time_ms\\), COUNT").
		WithArgs("banking-demo", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"avg", "samples"}).AddRow(nil, 0))
	mock.ExpectQuery("SELECT").
		WithArgs("banking-demo", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"policy_name", "identity_is_name", "trigger_count", "block_count", "total_policies"}))

	body := `{"start_time":"2026-04-22T00:00:00Z","end_time":"2026-04-23T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "banking-demo")
	rr := httptest.NewRecorder()
	handler.HandleSummary(rr, req)

	var summary ComplianceSummary
	_ = json.NewDecoder(rr.Body).Decode(&summary)

	if summary.TotalRequests != 385 {
		t.Errorf("total_requests = %d, want 385", summary.TotalRequests)
	}
	if summary.AllowedRequests != 369 {
		t.Errorf("allowed_requests = %d, want 369 (pending_approval + error NO LONGER counted as allowed)", summary.AllowedRequests)
	}
	if summary.NeedsApprovalRequests != 12 {
		t.Errorf("needs_approval_requests = %d, want 12 (pending_approval normalized to needs_approval)", summary.NeedsApprovalRequests)
	}
	if summary.ErrorRequests != 4 {
		t.Errorf("error_requests = %d, want 4", summary.ErrorRequests)
	}
	if summary.BlockedRequests != 0 {
		t.Errorf("blocked_requests = %d, want 0", summary.BlockedRequests)
	}
	if summary.ModifiedRequests != 0 {
		t.Errorf("modified_requests = %d, want 0", summary.ModifiedRequests)
	}
	// Core invariant: math always closes across all five verdict buckets.
	sum := summary.AllowedRequests + summary.BlockedRequests + summary.ModifiedRequests +
		summary.NeedsApprovalRequests + summary.ErrorRequests
	if sum != summary.TotalRequests {
		t.Errorf("allowed(%d)+blocked(%d)+modified(%d)+needs_approval(%d)+error(%d)=%d != total(%d)",
			summary.AllowedRequests, summary.BlockedRequests, summary.ModifiedRequests,
			summary.NeedsApprovalRequests, summary.ErrorRequests, sum, summary.TotalRequests)
	}
}

// TestAuditSummaryHandler_CardAggregates_AllBlocked pins the edge of the
// block_rate computation: 100% blocked should produce 100.0, not overflow
// or divide-by-zero.
func TestAuditSummaryHandler_CardAggregates_AllBlocked(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	handler := NewAuditSummaryHandler(db)

	mock.ExpectQuery("SELECT request_type, policy_decision, COUNT").
		WithArgs("blocked-tenant", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"request_type", "policy_decision", "cnt"}).
			AddRow("workflow_step_gate", "blocked", 7))
	mock.ExpectQuery("SELECT AVG\\(response_time_ms\\), COUNT").
		WithArgs("blocked-tenant", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"avg", "samples"}).AddRow(nil, 0))
	mock.ExpectQuery("SELECT").
		WithArgs("blocked-tenant", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"policy_name", "identity_is_name", "trigger_count", "block_count", "total_policies"}))

	body := `{"start_time":"2026-04-22T00:00:00Z","end_time":"2026-04-23T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "blocked-tenant")
	rr := httptest.NewRecorder()
	handler.HandleSummary(rr, req)

	var summary ComplianceSummary
	_ = json.NewDecoder(rr.Body).Decode(&summary)

	if summary.BlockedRequests != 7 {
		t.Errorf("blocked_requests = %d, want 7", summary.BlockedRequests)
	}
	if summary.BlockRatePercent != 100.0 {
		t.Errorf("block_rate_percent = %f, want 100", summary.BlockRatePercent)
	}
	if summary.ComplianceScore != 0.0 {
		t.Errorf("compliance_score = %f, want 0 (everything blocked)", summary.ComplianceScore)
	}
}

// The portal's Compliance Summary renders one tile per verdict bucket and
// tells the reader that the buckets sum to Total. That claim is only as strong
// as the weakest end of it, and the portal end is the weak one: its jest suite
// asserts the sum over a HAND-WRITTEN fixture, so a sixth bucket added here
// would ship with the tiles silently no longer closing and that suite still
// green. A fixture cannot notice a field it was never told about.
//
// This is the binding the portal cannot do for itself, in the package that
// owns the struct: the set of verdict buckets is pinned by name, so ADDING one
// (or renaming one) is a build-level conversation rather than a display defect
// discovered in production.
func TestComplianceSummaryVerdictBucketsAreThePortalTileSet(t *testing.T) {
	// Exactly the buckets TotalRequests is documented to be the sum of, and
	// exactly the tiles ee/platform/customer-portal-ui/app/audit/page.tsx
	// renders beside it.
	want := map[string]bool{
		"allowed_requests":        true,
		"blocked_requests":        true,
		"modified_requests":       true,
		"needs_approval_requests": true,
		"error_requests":          true,
	}

	// A verdict bucket is an int field whose json tag ends in "_requests" and
	// which is not the total itself. Derived from the struct rather than from a
	// literal list, so a NEW bucket is caught by construction.
	got := map[string]bool{}
	rt := reflect.TypeOf(ComplianceSummary{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "" || tag == "total_requests" || !strings.HasSuffix(tag, "_requests") {
			continue
		}
		if f.Type.Kind() != reflect.Int {
			continue
		}
		got[tag] = true
	}

	// Anti-vacuity: if the discovery rule stops matching anything, the
	// comparison below would pass against an empty set on both sides.
	if len(got) == 0 {
		t.Fatal("discovered no verdict buckets; the field-matching rule no longer matches the struct, " +
			"so this test would pass vacuously")
	}

	for tag := range got {
		if !want[tag] {
			t.Errorf("ComplianceSummary gained verdict bucket %q, which the portal's Compliance Summary "+
				"does not render. total_requests is documented as the sum of the verdict buckets, so the "+
				"portal tiles no longer close against Total. Add the tile in "+
				"ee/platform/customer-portal-ui/app/audit/page.tsx (and its assertion in "+
				"__tests__/app/audit/verdict-tiles.test.tsx), then add %q here.", tag, tag)
		}
	}
	for tag := range want {
		if !got[tag] {
			t.Errorf("verdict bucket %q is gone from ComplianceSummary but the portal still renders a tile "+
				"for it; remove the tile before removing the field", tag)
		}
	}
}
