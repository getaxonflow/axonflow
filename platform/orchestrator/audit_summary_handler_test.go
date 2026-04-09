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
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestAuditSummaryHandler_HandleSummary_ValidRequest(t *testing.T) {
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

	// Mock policy query
	policyRows := sqlmock.NewRows([]string{"policy_name", "trigger_count", "block_count"}).
		AddRow("demo-block-bulk-email", 8, 8).
		AddRow("pii-detection", 5, 2)
	mock.ExpectQuery("SELECT").
		WithArgs("travel-us", sqlmock.AnyArg(), sqlmock.AnyArg()).
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

	policyRows := sqlmock.NewRows([]string{"policy_name", "trigger_count", "block_count"})
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

	policyRows := sqlmock.NewRows([]string{"policy_name", "trigger_count", "block_count"})
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
