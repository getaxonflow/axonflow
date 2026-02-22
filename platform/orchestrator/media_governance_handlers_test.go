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
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"axonflow/platform/agent/license"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
)

// newTestHandlerWithMockDB creates a MediaGovernanceHandler backed by a sqlmock DB.
// Returns the handler, the sqlmock instance for expectation setup, and a cleanup func.
func newTestHandlerWithMockDB(t *testing.T, tier license.Tier) (*MediaGovernanceHandler, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}

	store := &MediaGovernanceConfigStore{
		db:    db,
		cache: make(map[string]*MediaGovernanceConfig),
	}
	lc := newMockLicenseChecker(tier)
	handler := NewMediaGovernanceHandler(store, lc)

	return handler, mock, func() { db.Close() }
}

// ---------- handleGetStatus ----------

func TestHandleGetStatus_CommunityTier(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var status MediaGovernanceStatus
	if err := json.NewDecoder(rr.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if status.Available {
		t.Error("expected Available=false for community tier")
	}
	if status.EnabledByDefault {
		t.Error("expected EnabledByDefault=false for community tier")
	}
	if status.PerTenantControl {
		t.Error("expected PerTenantControl=false for community tier")
	}
	if status.Tier != string(license.TierCommunity) {
		t.Errorf("expected Tier=%q, got %q", license.TierCommunity, status.Tier)
	}
}

func TestHandleGetStatus_EnterpriseTier(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var status MediaGovernanceStatus
	if err := json.NewDecoder(rr.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !status.Available {
		t.Error("expected Available=true for enterprise tier")
	}
	if !status.EnabledByDefault {
		t.Error("expected EnabledByDefault=true for enterprise tier")
	}
	if !status.PerTenantControl {
		t.Error("expected PerTenantControl=true for enterprise tier")
	}
	if status.Tier != string(license.TierEnterprise) {
		t.Errorf("expected Tier=%q, got %q", license.TierEnterprise, status.Tier)
	}
}

func TestHandleGetStatus_EvaluationTier(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEvaluation)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var status MediaGovernanceStatus
	if err := json.NewDecoder(rr.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !status.Available {
		t.Error("expected Available=true for evaluation tier")
	}
	if !status.EnabledByDefault {
		t.Error("expected EnabledByDefault=true for evaluation tier")
	}
	// Evaluation is NOT a paid tier, so PerTenantControl should be false
	if status.PerTenantControl {
		t.Error("expected PerTenantControl=false for evaluation tier")
	}
	if status.Tier != string(license.TierEvaluation) {
		t.Errorf("expected Tier=%q, got %q", license.TierEvaluation, status.Tier)
	}
}

func TestHandleGetStatus_ProfessionalTier(t *testing.T) {
	lc := newMockLicenseChecker(license.TierProfessional)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var status MediaGovernanceStatus
	if err := json.NewDecoder(rr.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Professional is a paid tier, so PerTenantControl should be true
	if !status.PerTenantControl {
		t.Error("expected PerTenantControl=true for professional tier")
	}
	if status.Tier != string(license.TierProfessional) {
		t.Errorf("expected Tier=%q, got %q", license.TierProfessional, status.Tier)
	}
}

func TestHandleGetStatus_ResponseContentType(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", ct)
	}
}

func TestHandleGetStatus_ResponseStructure(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	var raw map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&raw); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	expectedFields := []string{"available", "enabled_by_default", "per_tenant_control", "tier"}
	for _, field := range expectedFields {
		if _, exists := raw[field]; !exists {
			t.Errorf("expected field %q in status response", field)
		}
	}
}

// ---------- handleGetConfig ----------

func TestHandleGetConfig_MissingTenantHeader(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/config", nil)
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

func TestHandleGetConfig_EmptyTenantHeader(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/config", nil)
	req.Header.Set("X-Tenant-ID", "")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for empty X-Tenant-ID, got %d", rr.Code)
	}
}

func TestHandleGetConfig_ErrorResponseContentType(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	// Missing tenant header triggers a 400 error response
	req := httptest.NewRequest("GET", "/api/v1/media-governance/config", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type=application/json for error response, got %q", ct)
	}
}

func TestHandleGetConfig_NoDBRow_ReturnsDefaultConfig(t *testing.T) {
	handler, mock, cleanup := newTestHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	// Simulate no row found in DB (sql.ErrNoRows triggers nil config return)
	mock.ExpectQuery("SELECT").
		WithArgs("tenant-new").
		WillReturnError(sql.ErrNoRows)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/config", nil)
	req.Header.Set("X-Tenant-ID", "tenant-new")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var cfg MediaGovernanceConfig
	if err := json.NewDecoder(rr.Body).Decode(&cfg); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if cfg.TenantID != "tenant-new" {
		t.Errorf("expected TenantID=tenant-new, got %q", cfg.TenantID)
	}
	// Enterprise tier has media governance enabled by default
	if !cfg.Enabled {
		t.Error("expected Enabled=true for enterprise tier default config")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestHandleGetConfig_DBError_Returns500(t *testing.T) {
	handler, mock, cleanup := newTestHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-err").
		WillReturnError(fmt.Errorf("connection refused"))

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/config", nil)
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
	if errObj["code"] != "INTERNAL_ERROR" {
		t.Errorf("expected error code INTERNAL_ERROR, got %v", errObj["code"])
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestHandleGetConfig_ExistingConfig_ReturnsStoredConfig(t *testing.T) {
	handler, mock, cleanup := newTestHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	rows := sqlmock.NewRows([]string{
		"tenant_id", "enabled", "allowed_analyzers", "updated_at", "updated_by",
	}).AddRow("tenant-existing", false, []byte(`["nsfw","text-in-image"]`), time.Date(2026, 2, 18, 10, 0, 0, 0, time.UTC), "admin@example.com")

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-existing").
		WillReturnRows(rows)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/config", nil)
	req.Header.Set("X-Tenant-ID", "tenant-existing")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var cfg MediaGovernanceConfig
	if err := json.NewDecoder(rr.Body).Decode(&cfg); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if cfg.TenantID != "tenant-existing" {
		t.Errorf("expected TenantID=tenant-existing, got %q", cfg.TenantID)
	}
	if cfg.Enabled {
		t.Error("expected Enabled=false from stored config")
	}
	if len(cfg.AllowedAnalyzers) != 2 {
		t.Errorf("expected 2 allowed analyzers, got %d", len(cfg.AllowedAnalyzers))
	}
	if cfg.UpdatedBy != "admin@example.com" {
		t.Errorf("expected UpdatedBy=admin@example.com, got %q", cfg.UpdatedBy)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ---------- handleUpdateConfig ----------

func TestHandleUpdateConfig_MissingTenantHeader(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"enabled": true}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
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

func TestHandleUpdateConfig_InvalidRequestBody(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-test")
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
	if errObj["code"] != "INVALID_REQUEST" {
		t.Errorf("expected error code INVALID_REQUEST, got %v", errObj["code"])
	}
}

func TestHandleUpdateConfig_CommunityTier_EnabledForbidden(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"enabled": true}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-community")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'error' object in response")
	}
	if errObj["code"] != "TIER_RESTRICTED" {
		t.Errorf("expected error code ENTERPRISE_REQUIRED, got %v", errObj["code"])
	}
}

func TestHandleUpdateConfig_CommunityTier_DisableForbidden(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"enabled": false}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-community")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rr.Code)
	}
}

func TestHandleUpdateConfig_CommunityTier_AnalyzersForbidden(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"allowed_analyzers": ["nsfw", "text-in-image"]}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-community")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'error' object in response")
	}
	if errObj["code"] != "TIER_RESTRICTED" {
		t.Errorf("expected error code ENTERPRISE_REQUIRED, got %v", errObj["code"])
	}
}

func TestHandleUpdateConfig_EvaluationTier_EnabledForbidden(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEvaluation)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"enabled": false}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-eval")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 for evaluation tier per-tenant toggle, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'error' object in response")
	}
	if errObj["code"] != "TIER_RESTRICTED" {
		t.Errorf("expected error code ENTERPRISE_REQUIRED, got %v", errObj["code"])
	}
}

func TestHandleUpdateConfig_EvaluationTier_AnalyzersForbidden(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEvaluation)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"allowed_analyzers": ["nsfw"]}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-eval")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 for evaluation tier analyzer config, got %d", rr.Code)
	}
}

func TestHandleUpdateConfig_EnterpriseTier_EnabledAllowed(t *testing.T) {
	handler, mock, cleanup := newTestHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	// GetFromDB returns no existing config
	mock.ExpectQuery("SELECT").
		WithArgs("tenant-ent").
		WillReturnError(sql.ErrNoRows)

	// Upsert inserts the new config
	mock.ExpectExec("INSERT INTO media_governance_config").
		WillReturnResult(sqlmock.NewResult(0, 1))

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"enabled": true}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-ent")
	req.Header.Set("X-User-ID", "admin@enterprise.com")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var cfg MediaGovernanceConfig
	if err := json.NewDecoder(rr.Body).Decode(&cfg); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if cfg.TenantID != "tenant-ent" {
		t.Errorf("expected TenantID=tenant-ent, got %q", cfg.TenantID)
	}
	if !cfg.Enabled {
		t.Error("expected Enabled=true after enterprise update")
	}
	if cfg.UpdatedBy != "admin@enterprise.com" {
		t.Errorf("expected UpdatedBy=admin@enterprise.com, got %q", cfg.UpdatedBy)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestHandleUpdateConfig_EnterpriseTier_SetAnalyzers(t *testing.T) {
	handler, mock, cleanup := newTestHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	// GetFromDB returns no existing config
	mock.ExpectQuery("SELECT").
		WithArgs("tenant-ent").
		WillReturnError(sql.ErrNoRows)

	// Upsert
	mock.ExpectExec("INSERT INTO media_governance_config").
		WillReturnResult(sqlmock.NewResult(0, 1))

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"allowed_analyzers": ["nsfw", "violence-detection", "text-in-image"]}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-ent")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var cfg MediaGovernanceConfig
	if err := json.NewDecoder(rr.Body).Decode(&cfg); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(cfg.AllowedAnalyzers) != 3 {
		t.Errorf("expected 3 allowed analyzers, got %d", len(cfg.AllowedAnalyzers))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestHandleUpdateConfig_EnterpriseTier_DBGetError(t *testing.T) {
	handler, mock, cleanup := newTestHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-ent").
		WillReturnError(fmt.Errorf("db connection lost"))

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"enabled": true}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-ent")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestHandleUpdateConfig_EnterpriseTier_DBUpsertError(t *testing.T) {
	handler, mock, cleanup := newTestHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	// GetFromDB returns no row
	mock.ExpectQuery("SELECT").
		WithArgs("tenant-ent").
		WillReturnError(sql.ErrNoRows)

	// Upsert fails
	mock.ExpectExec("INSERT INTO media_governance_config").
		WillReturnError(fmt.Errorf("disk full"))

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"enabled": false}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-ent")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestHandleUpdateConfig_CommunityTier_EmptyBody_Rejected(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	// Community tier is rejected before body is decoded
	body := `{}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-community")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 for community tier PUT, got %d", rr.Code)
	}
}

func TestHandleUpdateConfig_UserID_FromHeader(t *testing.T) {
	handler, mock, cleanup := newTestHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-uid").
		WillReturnError(sql.ErrNoRows)

	mock.ExpectExec("INSERT INTO media_governance_config").
		WillReturnResult(sqlmock.NewResult(0, 1))

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"enabled": true}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-uid")
	req.Header.Set("X-User-ID", "custom-user@test.com")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var cfg MediaGovernanceConfig
	if err := json.NewDecoder(rr.Body).Decode(&cfg); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if cfg.UpdatedBy != "custom-user@test.com" {
		t.Errorf("expected UpdatedBy=custom-user@test.com, got %q", cfg.UpdatedBy)
	}
}

func TestHandleUpdateConfig_UserID_DefaultsToSystem(t *testing.T) {
	handler, mock, cleanup := newTestHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	mock.ExpectQuery("SELECT").
		WithArgs("tenant-sys").
		WillReturnError(sql.ErrNoRows)

	mock.ExpectExec("INSERT INTO media_governance_config").
		WillReturnResult(sqlmock.NewResult(0, 1))

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"enabled": true}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-sys")
	// No X-User-ID header
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var cfg MediaGovernanceConfig
	if err := json.NewDecoder(rr.Body).Decode(&cfg); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if cfg.UpdatedBy != "system" {
		t.Errorf("expected UpdatedBy=system when no X-User-ID, got %q", cfg.UpdatedBy)
	}
}

// ---------- CORS handling for OPTIONS ----------

func TestHandleCORS_StatusEndpoint(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/media-governance/status", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 for OPTIONS, got %d", rr.Code)
	}

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("expected Access-Control-Allow-Origin=http://localhost:3000, got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got != "GET, PUT, OPTIONS" {
		t.Errorf("expected Access-Control-Allow-Methods='GET, PUT, OPTIONS', got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("expected Access-Control-Allow-Headers to be set")
	}
	if got := rr.Header().Get("Access-Control-Max-Age"); got != "86400" {
		t.Errorf("expected Access-Control-Max-Age=86400, got %q", got)
	}
}

func TestHandleCORS_ConfigGetEndpoint(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/media-governance/config", nil)
	req.Header.Set("Origin", "https://app.getaxonflow.com")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 for OPTIONS, got %d", rr.Code)
	}

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.getaxonflow.com" {
		t.Errorf("expected Access-Control-Allow-Origin=https://app.getaxonflow.com, got %q", got)
	}
}

func TestHandleCORS_ConfigPutEndpoint(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/media-governance/config", nil)
	req.Header.Set("Origin", "https://staging.getaxonflow.com")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 for OPTIONS, got %d", rr.Code)
	}

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://staging.getaxonflow.com" {
		t.Errorf("expected Access-Control-Allow-Origin=https://staging.getaxonflow.com, got %q", got)
	}
}

func TestHandleCORS_DisallowedOrigin(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/media-governance/status", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 for OPTIONS, got %d", rr.Code)
	}

	// Disallowed origin should NOT get Access-Control-Allow-Origin set
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected empty Access-Control-Allow-Origin for disallowed origin, got %q", got)
	}

	// Other CORS headers should still be present
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got != "GET, PUT, OPTIONS" {
		t.Errorf("expected Access-Control-Allow-Methods='GET, PUT, OPTIONS', got %q", got)
	}
}

func TestHandleCORS_NoOriginHeader(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/media-governance/status", nil)
	// No Origin header
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 for OPTIONS, got %d", rr.Code)
	}

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected empty Access-Control-Allow-Origin when no Origin header, got %q", got)
	}
}

// ---------- isMediaGovernanceAvailable ----------

func TestIsMediaGovernanceAvailable_CommunityTier_EnvEnabled(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	// Set env var override
	os.Setenv("MEDIA_GOVERNANCE_ENABLED", "true")
	defer os.Unsetenv("MEDIA_GOVERNANCE_ENABLED")

	if !handler.isMediaGovernanceAvailable() {
		t.Error("expected isMediaGovernanceAvailable=true when MEDIA_GOVERNANCE_ENABLED=true")
	}
}

func TestIsMediaGovernanceAvailable_CommunityTier_EnvDisabled(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	// Ensure env var is not set
	os.Unsetenv("MEDIA_GOVERNANCE_ENABLED")

	if handler.isMediaGovernanceAvailable() {
		t.Error("expected isMediaGovernanceAvailable=false for community tier without env override")
	}
}

func TestIsMediaGovernanceAvailable_CommunityTier_EnvOneValue(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	os.Setenv("MEDIA_GOVERNANCE_ENABLED", "1")
	defer os.Unsetenv("MEDIA_GOVERNANCE_ENABLED")

	if !handler.isMediaGovernanceAvailable() {
		t.Error("expected isMediaGovernanceAvailable=true when MEDIA_GOVERNANCE_ENABLED=1")
	}
}

func TestIsMediaGovernanceAvailable_EnterpriseTier(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	os.Unsetenv("MEDIA_GOVERNANCE_ENABLED")

	if !handler.isMediaGovernanceAvailable() {
		t.Error("expected isMediaGovernanceAvailable=true for enterprise tier")
	}
}

// ---------- getTenantID fallback paths ----------

func TestGetTenantID_XTenantIDHeader(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Tenant-ID", "tenant-from-header")

	tenantID := handler.getTenantID(req)
	if tenantID != "tenant-from-header" {
		t.Errorf("expected tenant-from-header, got %q", tenantID)
	}
}

func TestGetTenantID_FallbackToXOrgID(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	req := httptest.NewRequest("GET", "/test", nil)
	// No X-Tenant-ID, but X-Org-ID is set
	req.Header.Set("X-Org-ID", "org-fallback")

	tenantID := handler.getTenantID(req)
	if tenantID != "org-fallback" {
		t.Errorf("expected org-fallback, got %q", tenantID)
	}
}

func TestGetTenantID_FallbackToContext(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	req := httptest.NewRequest("GET", "/test", nil)
	// No headers, but context has tenant_id
	ctx := context.WithValue(req.Context(), "tenant_id", "ctx-tenant")
	req = req.WithContext(ctx)

	tenantID := handler.getTenantID(req)
	if tenantID != "ctx-tenant" {
		t.Errorf("expected ctx-tenant, got %q", tenantID)
	}
}

func TestGetTenantID_Empty(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	req := httptest.NewRequest("GET", "/test", nil)
	// No headers, no context value

	tenantID := handler.getTenantID(req)
	if tenantID != "" {
		t.Errorf("expected empty string, got %q", tenantID)
	}
}

// ---------- getUserID fallback paths ----------

func TestGetUserID_XUserIDHeader(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-User-ID", "user@test.com")

	userID := handler.getUserID(req)
	if userID != "user@test.com" {
		t.Errorf("expected user@test.com, got %q", userID)
	}
}

func TestGetUserID_FallbackToContext(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(req.Context(), "user_id", "ctx-user")
	req = req.WithContext(ctx)

	userID := handler.getUserID(req)
	if userID != "ctx-user" {
		t.Errorf("expected ctx-user, got %q", userID)
	}
}

func TestGetUserID_DefaultsToSystem(t *testing.T) {
	lc := newMockLicenseChecker(license.TierEnterprise)
	handler := NewMediaGovernanceHandler(nil, lc)

	req := httptest.NewRequest("GET", "/test", nil)

	userID := handler.getUserID(req)
	if userID != "system" {
		t.Errorf("expected system, got %q", userID)
	}
}

// ---------- handleGetStatus with env override ----------

func TestHandleGetStatus_CommunityTier_WithEnvOverride(t *testing.T) {
	lc := newMockLicenseChecker(license.TierCommunity)
	handler := NewMediaGovernanceHandler(nil, lc)

	os.Setenv("MEDIA_GOVERNANCE_ENABLED", "true")
	defer os.Unsetenv("MEDIA_GOVERNANCE_ENABLED")

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var status MediaGovernanceStatus
	if err := json.NewDecoder(rr.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Community + env override means Available should be true
	if !status.Available {
		t.Error("expected Available=true with MEDIA_GOVERNANCE_ENABLED=true on community tier")
	}
	// But PerTenantControl stays false since community is not a paid tier
	if status.PerTenantControl {
		t.Error("expected PerTenantControl=false for community tier even with env override")
	}
}

// ---------- handleUpdateConfig: X-Org-ID fallback ----------

func TestHandleUpdateConfig_XOrgID_Fallback(t *testing.T) {
	handler, mock, cleanup := newTestHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	mock.ExpectQuery("SELECT").
		WithArgs("org-tenant").
		WillReturnError(sql.ErrNoRows)

	mock.ExpectExec("INSERT INTO media_governance_config").
		WillReturnResult(sqlmock.NewResult(0, 1))

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"enabled": true}`
	req := httptest.NewRequest("PUT", "/api/v1/media-governance/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Use X-Org-ID instead of X-Tenant-ID
	req.Header.Set("X-Org-ID", "org-tenant")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var cfg MediaGovernanceConfig
	if err := json.NewDecoder(rr.Body).Decode(&cfg); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if cfg.TenantID != "org-tenant" {
		t.Errorf("expected TenantID=org-tenant, got %q", cfg.TenantID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ---------- handleGetConfig: X-Org-ID fallback ----------

func TestHandleGetConfig_XOrgID_Fallback(t *testing.T) {
	handler, mock, cleanup := newTestHandlerWithMockDB(t, license.TierEnterprise)
	defer cleanup()

	mock.ExpectQuery("SELECT").
		WithArgs("org-get-tenant").
		WillReturnError(sql.ErrNoRows)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/media-governance/config", nil)
	req.Header.Set("X-Org-ID", "org-get-tenant")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var cfg MediaGovernanceConfig
	if err := json.NewDecoder(rr.Body).Decode(&cfg); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if cfg.TenantID != "org-get-tenant" {
		t.Errorf("expected TenantID=org-get-tenant, got %q", cfg.TenantID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}
