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

package orchestrator

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axonflow/platform/agent/license"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
)

// newTestAuditHandlerWithMockDB creates a MediaGovernanceAuditHandler backed by sqlmock.
func newTestAuditHandlerWithMockDB(t *testing.T, tier license.Tier) (*MediaGovernanceAuditHandler, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	lc := newMockLicenseChecker(tier)
	handler := NewMediaGovernanceAuditHandler(db, lc)
	return handler, mock, func() { db.Close() }
}

// ---------- NewMediaGovernanceAuditHandler ----------

func TestNewMediaGovernanceAuditHandler(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceAuditHandler(db, lc)

	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	if handler.db != db {
		t.Error("expected handler.db to match provided db")
	}
	if handler.licenseChecker != lc {
		t.Error("expected handler.licenseChecker to match provided checker")
	}
}

// ---------- RegisterRoutes ----------

func TestAuditHandler_RegisterRoutes(t *testing.T) {
	handler, _, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	// Verify the route is registered by making a request
	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// Should not be 404 (route exists)
	if rr.Code == http.StatusNotFound {
		t.Error("expected route to be registered, got 404")
	}
}

// ---------- CORS handling ----------

func TestAuditHandler_CORS_AllowedOrigin(t *testing.T) {
	handler, _, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/media-governance/audit/export", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 for OPTIONS, got %d", rr.Code)
	}

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("expected Access-Control-Allow-Origin=http://localhost:3000, got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got != "GET, OPTIONS" {
		t.Errorf("expected Access-Control-Allow-Methods='GET, OPTIONS', got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("expected Access-Control-Allow-Headers to be set")
	}
	if got := rr.Header().Get("Access-Control-Max-Age"); got != "86400" {
		t.Errorf("expected Access-Control-Max-Age=86400, got %q", got)
	}
}

func TestAuditHandler_CORS_DisallowedOrigin(t *testing.T) {
	handler, _, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/media-governance/audit/export", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 for OPTIONS, got %d", rr.Code)
	}

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected empty Access-Control-Allow-Origin for disallowed origin, got %q", got)
	}
}

func TestAuditHandler_CORS_NoOriginHeader(t *testing.T) {
	handler, _, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/media-governance/audit/export", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 for OPTIONS, got %d", rr.Code)
	}

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected empty Access-Control-Allow-Origin when no Origin header, got %q", got)
	}
	// Other headers should still be set
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got != "GET, OPTIONS" {
		t.Errorf("expected Access-Control-Allow-Methods='GET, OPTIONS', got %q", got)
	}
}

// ---------- Non-Enterprise tier returns 403 ----------

func TestAuditHandler_CommunityTier_Returns403(t *testing.T) {
	handler, _, cleanup := newTestAuditHandlerWithMockDB(t, license.TierCommunity)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 for community tier, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'error' object in response")
	}
	if errObj["code"] != "ENTERPRISE_REQUIRED" {
		t.Errorf("expected error code ENTERPRISE_REQUIRED, got %v", errObj["code"])
	}
}

func TestAuditHandler_EvaluationTier_Returns403(t *testing.T) {
	handler, _, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEvaluation)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 for evaluation tier, got %d", rr.Code)
	}
}

// ---------- Missing X-Tenant-ID returns 400 ----------

func TestAuditHandler_MissingTenantID_Returns400(t *testing.T) {
	handler, _, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export", nil)
	// No X-Tenant-ID header
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'error' object in response")
	}
	if errObj["code"] != "MISSING_TENANT_ID" {
		t.Errorf("expected error code MISSING_TENANT_ID, got %v", errObj["code"])
	}
}

// ---------- Invalid format returns 400 ----------

func TestAuditHandler_InvalidFormat_Returns400(t *testing.T) {
	handler, _, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export?format=xml", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for invalid format, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'error' object in response")
	}
	if errObj["code"] != "INVALID_FORMAT" {
		t.Errorf("expected error code INVALID_FORMAT, got %v", errObj["code"])
	}
}

// ---------- Invalid from/to timestamps returns 400 ----------

func TestAuditHandler_InvalidFromTimestamp_Returns400(t *testing.T) {
	handler, _, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export?from=not-a-date", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for invalid from timestamp, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'error' object in response")
	}
	if errObj["code"] != "INVALID_FROM" {
		t.Errorf("expected error code INVALID_FROM, got %v", errObj["code"])
	}
}

func TestAuditHandler_InvalidToTimestamp_Returns400(t *testing.T) {
	handler, _, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	from := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export?from="+from+"&to=bad-timestamp", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for invalid to timestamp, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'error' object in response")
	}
	if errObj["code"] != "INVALID_TO" {
		t.Errorf("expected error code INVALID_TO, got %v", errObj["code"])
	}
}

// ---------- Successful JSON export ----------

func TestAuditHandler_JSONExport_Success(t *testing.T) {
	handler, mock, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	ts := time.Date(2026, 2, 18, 10, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{
		"request_id", "tenant_id", "timestamp", "media_type", "analysis_results", "policy_actions", "blocked",
	}).AddRow(
		"req-001", "tenant-export", ts, "image",
		[]byte(`{"nsfw_score":0.1}`), []byte(`["log","allow"]`), false,
	).AddRow(
		"req-002", "tenant-export", ts.Add(time.Minute), "image",
		[]byte(`{"nsfw_score":0.95}`), []byte(`["block","alert"]`), true,
	)

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-export", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	from := ts.Add(-time.Hour).Format(time.RFC3339)
	to := ts.Add(time.Hour).Format(time.RFC3339)
	req := httptest.NewRequest("GET",
		fmt.Sprintf("/api/v1/media-governance/audit/export?from=%s&to=%s", from, to), nil)
	req.Header.Set("X-Tenant-ID", "tenant-export")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", ct)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp["tenant_id"] != "tenant-export" {
		t.Errorf("expected tenant_id=tenant-export, got %v", resp["tenant_id"])
	}
	count, ok := resp["count"].(float64)
	if !ok || int(count) != 2 {
		t.Errorf("expected count=2, got %v", resp["count"])
	}
	records, ok := resp["records"].([]interface{})
	if !ok || len(records) != 2 {
		t.Errorf("expected 2 records, got %v", resp["records"])
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestAuditHandler_JSONExport_DefaultFormat(t *testing.T) {
	handler, mock, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	// Empty result set
	rows := sqlmock.NewRows([]string{
		"request_id", "tenant_id", "timestamp", "media_type", "analysis_results", "policy_actions", "blocked",
	})

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-default", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	// No format parameter - should default to json
	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export", nil)
	req.Header.Set("X-Tenant-ID", "tenant-default")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type=application/json for default format, got %q", ct)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	count, ok := resp["count"].(float64)
	if !ok || int(count) != 0 {
		t.Errorf("expected count=0 for empty result, got %v", resp["count"])
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestAuditHandler_JSONExport_WithExplicitFormat(t *testing.T) {
	handler, mock, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	rows := sqlmock.NewRows([]string{
		"request_id", "tenant_id", "timestamp", "media_type", "analysis_results", "policy_actions", "blocked",
	})

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-json", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export?format=json", nil)
	req.Header.Set("X-Tenant-ID", "tenant-json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", ct)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ---------- Successful CSV export ----------

func TestAuditHandler_CSVExport_Success(t *testing.T) {
	handler, mock, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	ts := time.Date(2026, 2, 18, 10, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{
		"request_id", "tenant_id", "timestamp", "media_type", "analysis_results", "policy_actions", "blocked",
	}).AddRow(
		"req-csv-001", "tenant-csv", ts, "image",
		[]byte(`{"nsfw_score":0.05}`), []byte(`["allow"]`), false,
	)

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-csv", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	from := ts.Add(-time.Hour).Format(time.RFC3339)
	to := ts.Add(time.Hour).Format(time.RFC3339)
	req := httptest.NewRequest("GET",
		fmt.Sprintf("/api/v1/media-governance/audit/export?format=csv&from=%s&to=%s", from, to), nil)
	req.Header.Set("X-Tenant-ID", "tenant-csv")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "text/csv" {
		t.Errorf("expected Content-Type=text/csv, got %q", ct)
	}

	disposition := rr.Header().Get("Content-Disposition")
	if disposition == "" {
		t.Error("expected Content-Disposition header to be set for CSV export")
	}

	body := rr.Body.String()
	// Should have header row + 1 data row
	if body == "" {
		t.Error("expected non-empty CSV body")
	}
	// Verify CSV header
	if !strings.Contains(body, "request_id") {
		t.Error("expected CSV to contain 'request_id' header")
	}
	if !strings.Contains(body, "req-csv-001") {
		t.Error("expected CSV to contain request ID 'req-csv-001'")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestAuditHandler_CSVExport_EmptyResult(t *testing.T) {
	handler, mock, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	rows := sqlmock.NewRows([]string{
		"request_id", "tenant_id", "timestamp", "media_type", "analysis_results", "policy_actions", "blocked",
	})

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-csv-empty", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export?format=csv", nil)
	req.Header.Set("X-Tenant-ID", "tenant-csv-empty")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "text/csv" {
		t.Errorf("expected Content-Type=text/csv, got %q", ct)
	}

	body := rr.Body.String()
	// Should have header row only
	if !strings.Contains(body, "request_id") {
		t.Error("expected CSV to contain header row even with empty results")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestAuditHandler_CSVExport_MultipleRecords(t *testing.T) {
	handler, mock, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	ts := time.Date(2026, 2, 18, 10, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{
		"request_id", "tenant_id", "timestamp", "media_type", "analysis_results", "policy_actions", "blocked",
	}).AddRow(
		"req-m-001", "tenant-multi", ts, "image",
		[]byte(`{"nsfw_score":0.1}`), []byte(`["allow"]`), false,
	).AddRow(
		"req-m-002", "tenant-multi", ts.Add(time.Minute), "image",
		[]byte(`{"nsfw_score":0.9}`), []byte(`["block","alert"]`), true,
	).AddRow(
		"req-m-003", "tenant-multi", ts.Add(2*time.Minute), "image",
		[]byte(`{}`), []byte(`[]`), false,
	)

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-multi", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export?format=csv", nil)
	req.Header.Set("X-Tenant-ID", "tenant-multi")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "req-m-001") {
		t.Error("expected CSV to contain req-m-001")
	}
	if !strings.Contains(body, "req-m-002") {
		t.Error("expected CSV to contain req-m-002")
	}
	if !strings.Contains(body, "req-m-003") {
		t.Error("expected CSV to contain req-m-003")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ---------- DB query error returns 500 ----------

func TestAuditHandler_DBQueryError_Returns500(t *testing.T) {
	handler, mock, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-err", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(fmt.Errorf("connection refused"))

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export", nil)
	req.Header.Set("X-Tenant-ID", "tenant-err")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'error' object in response")
	}
	if errObj["code"] != "QUERY_ERROR" {
		t.Errorf("expected error code QUERY_ERROR, got %v", errObj["code"])
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ---------- writeError function ----------

func TestAuditHandler_WriteError_ResponseFormat(t *testing.T) {
	handler, _, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	rr := httptest.NewRecorder()
	handler.writeError(rr, http.StatusTeapot, "TEST_CODE", "Test error message")

	if rr.Code != http.StatusTeapot {
		t.Fatalf("expected status 418, got %d", rr.Code)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", ct)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'error' object in response")
	}
	if errObj["code"] != "TEST_CODE" {
		t.Errorf("expected error code TEST_CODE, got %v", errObj["code"])
	}
	if errObj["message"] != "Test error message" {
		t.Errorf("expected error message 'Test error message', got %v", errObj["message"])
	}
}

func TestAuditHandler_WriteError_DifferentStatusCodes(t *testing.T) {
	handler, _, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	tests := []struct {
		status  int
		code    string
		message string
	}{
		{http.StatusBadRequest, "BAD_REQUEST", "Bad request"},
		{http.StatusForbidden, "FORBIDDEN", "Forbidden"},
		{http.StatusInternalServerError, "INTERNAL", "Internal server error"},
		{http.StatusNotFound, "NOT_FOUND", "Not found"},
	}

	for _, tt := range tests {
		rr := httptest.NewRecorder()
		handler.writeError(rr, tt.status, tt.code, tt.message)

		if rr.Code != tt.status {
			t.Errorf("expected status %d, got %d", tt.status, rr.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode error response for status %d: %v", tt.status, err)
		}
		errObj := resp["error"].(map[string]interface{})
		if errObj["code"] != tt.code {
			t.Errorf("expected error code %q, got %v", tt.code, errObj["code"])
		}
	}
}

// ---------- Professional tier (paid) should have access ----------

func TestAuditHandler_ProfessionalTier_HasAccess(t *testing.T) {
	handler, mock, cleanup := newTestAuditHandlerWithMockDB(t, license.TierProfessional)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	rows := sqlmock.NewRows([]string{
		"request_id", "tenant_id", "timestamp", "media_type", "analysis_results", "policy_actions", "blocked",
	})

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-pro", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export", nil)
	req.Header.Set("X-Tenant-ID", "tenant-pro")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 for professional tier, got %d", rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ---------- queryMediaAuditRecords ----------

func TestAuditHandler_QueryRecords_ScanError(t *testing.T) {
	handler, mock, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	// Return rows with wrong column count to trigger scan error
	rows := sqlmock.NewRows([]string{
		"request_id", "tenant_id", "timestamp", "media_type", "analysis_results", "policy_actions", "blocked",
	}).AddRow(
		"req-bad", "tenant-scan-err", "not-a-time", "image",
		[]byte(`{}`), []byte(`[]`), false,
	)

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-scan-err", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export", nil)
	req.Header.Set("X-Tenant-ID", "tenant-scan-err")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// Should return 500 due to scan error
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500 for scan error, got %d", rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ---------- queryMediaAuditRecords edge cases ----------

func TestAuditHandler_QueryRecords_InvalidJSON_StillReturnsRecords(t *testing.T) {
	handler, mock, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	ts := time.Date(2026, 2, 18, 10, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{
		"request_id", "tenant_id", "timestamp", "media_type", "analysis_results", "policy_actions", "blocked",
	}).AddRow(
		"req-bad-json", "tenant-bad", ts, "image",
		[]byte(`not-valid-json`), []byte(`also-not-json`), false,
	)

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-bad", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export", nil)
	req.Header.Set("X-Tenant-ID", "tenant-bad")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// Should still succeed - invalid JSON is logged as warning, not an error
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 despite invalid JSON in fields, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	count, ok := resp["count"].(float64)
	if !ok || int(count) != 1 {
		t.Errorf("expected count=1, got %v", resp["count"])
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestAuditHandler_QueryRecords_EmptyJSONFields(t *testing.T) {
	handler, mock, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	ts := time.Date(2026, 2, 18, 10, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{
		"request_id", "tenant_id", "timestamp", "media_type", "analysis_results", "policy_actions", "blocked",
	}).AddRow(
		"req-empty", "tenant-empty", ts, "image",
		[]byte(``), []byte(``), false,
	)

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-empty", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export?format=json", nil)
	req.Header.Set("X-Tenant-ID", "tenant-empty")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 with empty JSON fields, got %d", rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestAuditHandler_CSVExport_WithPolicyActions(t *testing.T) {
	handler, mock, cleanup := newTestAuditHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	ts := time.Date(2026, 2, 18, 10, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{
		"request_id", "tenant_id", "timestamp", "media_type", "analysis_results", "policy_actions", "blocked",
	}).AddRow(
		"req-actions", "tenant-actions", ts, "image",
		[]byte(`{"nsfw_score":0.9}`), []byte(`["block","alert","log"]`), true,
	).AddRow(
		"req-no-actions", "tenant-actions", ts, "image",
		[]byte(`{}`), []byte(`[]`), false,
	)

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-actions", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/audit/export?format=csv", nil)
	req.Header.Set("X-Tenant-ID", "tenant-actions")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	// First record should have policy actions
	if !strings.Contains(body, "block") {
		t.Error("expected CSV to contain 'block' action")
	}
	if !strings.Contains(body, "true") {
		t.Error("expected CSV to contain 'true' for blocked field")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}
