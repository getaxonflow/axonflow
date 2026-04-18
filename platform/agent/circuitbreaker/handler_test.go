// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - Circuit Breaker Handler Tests

//go:build enterprise

package circuitbreaker

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
)

func setupTestHandler(t *testing.T) (*Handler, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}

	repo := NewRepository(db)
	cb := New(repo, Config{})
	handler := NewHandler(cb)

	return handler, mock, func() { db.Close() }
}

func TestTrip_MissingOrgID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"scope": "global"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	// Missing X-Org-ID header

	w := httptest.NewRecorder()
	handler.Trip(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestTrip_MissingUserID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"scope": "global"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	// Missing X-User-ID header

	w := httptest.NewRecorder()
	handler.Trip(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error == "" {
		t.Error("Expected error about missing X-User-ID")
	}
}

func TestTrip_InvalidJSON(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "user-1")

	w := httptest.NewRecorder()
	handler.Trip(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestTrip_InvalidScope(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"scope": "invalid_scope"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "user-1")

	w := httptest.NewRecorder()
	handler.Trip(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestTrip_NonGlobalScopeRequiresScopeID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"scope": "tenant"}` // tenant scope without scope_id
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "user-1")

	w := httptest.NewRecorder()
	handler.Trip(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error == "" {
		t.Error("Expected error about missing scope_id")
	}
}

func TestHandler_Trip_Success(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	body := `{"scope": "global", "comment": "Emergency stop test"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "user-1")

	w := httptest.NewRecorder()
	handler.Trip(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Success {
		t.Error("Expected success=true")
	}
}

func TestHandler_Trip_WithDuration(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	body := `{"scope": "global", "duration_minutes": 60}` // 1 hour
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "user-1")

	w := httptest.NewRecorder()
	handler.Trip(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}
}

func TestReset_MissingOrgID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"scope": "global"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/reset", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.Reset(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestReset_MissingUserID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"scope": "global"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/reset", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.Reset(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHandler_Reset_Success(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	// First trip
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	tripBody := `{"scope": "global"}`
	tripReq := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(tripBody))
	tripReq.Header.Set("Content-Type", "application/json")
	tripReq.Header.Set("X-Org-ID", "org-1")
	tripReq.Header.Set("X-User-ID", "user-1")

	tripW := httptest.NewRecorder()
	handler.Trip(tripW, tripReq)

	// Then reset
	mock.ExpectExec("UPDATE circuit_breaker").
		WillReturnResult(sqlmock.NewResult(0, 1))

	resetBody := `{"scope": "global"}`
	resetReq := httptest.NewRequest("POST", "/api/v1/circuit-breaker/reset", bytes.NewBufferString(resetBody))
	resetReq.Header.Set("Content-Type", "application/json")
	resetReq.Header.Set("X-Org-ID", "org-1")
	resetReq.Header.Set("X-User-ID", "user-2")

	resetW := httptest.NewRecorder()
	handler.Reset(resetW, resetReq)

	if resetW.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, resetW.Code, resetW.Body.String())
	}
}

func TestCheck_MissingOrgID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"tenant_id": "tenant-1"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/check", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.Check(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCheck_Allowed(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"tenant_id": "tenant-1", "client_id": "client-1"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/check", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.Check(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	data := resp.Data.(map[string]interface{})
	if data["allowed"] != true {
		t.Error("Expected allowed=true when no circuits are open")
	}
}

func TestCheck_Blocked(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	// Trip the circuit first
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	tripBody := `{"scope": "global"}`
	tripReq := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(tripBody))
	tripReq.Header.Set("Content-Type", "application/json")
	tripReq.Header.Set("X-Org-ID", "org-1")
	tripReq.Header.Set("X-User-ID", "user-1")

	tripW := httptest.NewRecorder()
	handler.Trip(tripW, tripReq)

	// Check should be blocked
	checkBody := `{"tenant_id": "tenant-1"}`
	checkReq := httptest.NewRequest("POST", "/api/v1/circuit-breaker/check", bytes.NewBufferString(checkBody))
	checkReq.Header.Set("Content-Type", "application/json")
	checkReq.Header.Set("X-Org-ID", "org-1")

	checkW := httptest.NewRecorder()
	handler.Check(checkW, checkReq)

	if checkW.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, checkW.Code)
	}

	var resp APIResponse
	json.Unmarshal(checkW.Body.Bytes(), &resp)

	data := resp.Data.(map[string]interface{})
	if data["allowed"] != false {
		t.Error("Expected allowed=false when global circuit is open")
	}
}

func TestStatus_MissingOrgID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/status", nil)
	w := httptest.NewRecorder()

	handler.Status(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestStatus_Success(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	// Mock empty result for active circuits
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "scope", "scope_id", "state",
			"trip_reason", "tripped_by", "tripped_by_email", "trip_comment",
			"tripped_at", "expires_at", "reset_by", "reset_at",
			"error_count", "violation_count", "created_at", "updated_at",
		}))

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/status", nil)
	req.Header.Set("X-Org-ID", "org-1")
	w := httptest.NewRecorder()

	handler.Status(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if !resp.Success {
		t.Error("Expected success=true")
	}
}

func TestHistory_MissingOrgID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/history", nil)
	w := httptest.NewRecorder()

	handler.History(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHistory_Success(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	now := time.Now()
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "scope", "scope_id", "state",
			"trip_reason", "tripped_by", "tripped_by_email", "trip_comment",
			"tripped_at", "expires_at", "reset_by", "reset_at",
			"error_count", "violation_count", "created_at", "updated_at",
		}).AddRow(
			"circuit-1", "org-1", "global", "", "closed",
			"manual", "user-1", "user@example.com", "Test trip",
			now, nil, "user-2", now.Add(time.Hour),
			0, 0, now, now,
		))

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/history?limit=10", nil)
	req.Header.Set("X-Org-ID", "org-1")
	w := httptest.NewRecorder()

	handler.History(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestRegisterRoutes(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	routes := []struct {
		path   string
		method string
	}{
		{"/api/v1/circuit-breaker/trip", "POST"},
		{"/api/v1/circuit-breaker/reset", "POST"},
		{"/api/v1/circuit-breaker/check", "POST"},
		{"/api/v1/circuit-breaker/status", "GET"},
		{"/api/v1/circuit-breaker/history", "GET"},
		{"/api/v1/emergency-stop", "POST"},
		{"/api/v1/emergency-stop/release", "POST"},
	}

	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, nil)
		match := &mux.RouteMatch{}
		if !r.Match(req, match) {
			t.Errorf("Route %s %s not registered", route.method, route.path)
		}
	}
}

func TestNewHandler(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	handler := NewHandler(cb)

	if handler == nil {
		t.Error("Expected non-nil handler")
	}
	if handler.cb != cb {
		t.Error("Expected handler to reference the provided circuit breaker")
	}
}

// --- Config endpoint tests ---

func TestHandler_GetConfig_Global(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/config", nil)
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.GetConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	data := resp.Data.(map[string]interface{})
	if data["source"] != "global" {
		t.Errorf("Expected source=global, got %v", data["source"])
	}
}

func TestHandler_GetConfig_MissingOrgID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/config", nil)
	w := httptest.NewRecorder()
	handler.GetConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandler_GetConfig_Tenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{
		ErrorThreshold:           10,
		PolicyViolationThreshold: 20,
		PolicyViolationWindow:    5 * time.Minute,
		DefaultTimeout:           30 * time.Minute,
		MaxTimeout:               1 * time.Hour,
		EnableAutoRecovery:       true,
	})
	handler := NewHandler(cb)

	now := time.Now()
	mock.ExpectQuery("SELECT").
		WithArgs("org-1", "tenant-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "tenant_id",
			"error_threshold", "violation_threshold", "window_seconds",
			"default_timeout_seconds", "max_timeout_seconds", "enable_auto_recovery",
			"created_at", "updated_at",
		}).AddRow("config-1", "org-1", "tenant-1",
			5, nil, nil, nil, nil, nil, now, now))

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/config?tenant_id=tenant-1", nil)
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.GetConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	data := resp.Data.(map[string]interface{})
	if data["source"] != "tenant" {
		t.Errorf("Expected source=tenant, got %v", data["source"])
	}
	if data["error_threshold"] != float64(5) {
		t.Errorf("Expected error_threshold=5, got %v", data["error_threshold"])
	}
}

func TestHandler_GetConfig_TenantNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{ErrorThreshold: 10})
	handler := NewHandler(cb)

	mock.ExpectQuery("SELECT").
		WithArgs("org-1", "tenant-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "tenant_id",
			"error_threshold", "violation_threshold", "window_seconds",
			"default_timeout_seconds", "max_timeout_seconds", "enable_auto_recovery",
			"created_at", "updated_at",
		}))

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/config?tenant_id=tenant-1", nil)
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.GetConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	data := resp.Data.(map[string]interface{})
	if data["source"] != "global" {
		t.Errorf("Expected source=global (no tenant override), got %v", data["source"])
	}
}

func TestHandler_UpdateConfig_Success(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectExec("INSERT INTO circuit_breaker_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	body := `{"tenant_id":"tenant-1","error_threshold":5,"violation_threshold":10}`
	req := httptest.NewRequest("PUT", "/api/v1/circuit-breaker/config", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.UpdateConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_UpdateConfig_MissingTenantID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"error_threshold":5}`
	req := httptest.NewRequest("PUT", "/api/v1/circuit-breaker/config", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.UpdateConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandler_UpdateConfig_MissingOrgID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"tenant_id":"tenant-1","error_threshold":5}`
	req := httptest.NewRequest("PUT", "/api/v1/circuit-breaker/config", bytes.NewBufferString(body))

	w := httptest.NewRecorder()
	handler.UpdateConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandler_UpdateConfig_InvalidJSON(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("PUT", "/api/v1/circuit-breaker/config", bytes.NewBufferString("not json"))
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.UpdateConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandler_UpdateConfig_NegativeThreshold(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"tenant_id":"tenant-1","error_threshold":-1}`
	req := httptest.NewRequest("PUT", "/api/v1/circuit-breaker/config", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.UpdateConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for negative threshold, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_UpdateConfig_ZeroThreshold(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"tenant_id":"tenant-1","violation_threshold":0}`
	req := httptest.NewRequest("PUT", "/api/v1/circuit-breaker/config", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.UpdateConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for zero threshold, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_UpdateConfig_NegativeWindowSeconds(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"tenant_id":"tenant-1","window_seconds":-10}`
	req := httptest.NewRequest("PUT", "/api/v1/circuit-breaker/config", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.UpdateConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for negative window_seconds, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Notification endpoint tests ---

func TestHandler_ListNotifications(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	now := time.Now()
	mock.ExpectQuery("SELECT").
		WithArgs("org-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "tenant_id", "type", "url", "secret", "active", "created_at", "updated_at",
		}).AddRow("notif-1", "org-1", "", "webhook", "https://example.com", "secret", true, now, now))

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/notifications", nil)
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.ListNotifications(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	data := resp.Data.(map[string]interface{})
	if data["count"] != float64(1) {
		t.Errorf("Expected count=1, got %v", data["count"])
	}
}

func TestHandler_ListNotifications_MissingOrgID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/notifications", nil)
	w := httptest.NewRecorder()
	handler.ListNotifications(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandler_CreateNotification_Success(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectExec("INSERT INTO circuit_breaker_notifications").
		WillReturnResult(sqlmock.NewResult(1, 1))

	body := `{"type":"webhook","url":"https://example.com/webhook","secret":"my-secret"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/notifications", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.CreateNotification(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_CreateNotification_InvalidType(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"type":"email","url":"https://example.com"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/notifications", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.CreateNotification(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandler_CreateNotification_MissingURL(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"type":"webhook"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/notifications", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.CreateNotification(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandler_CreateNotification_InvalidURL(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"type":"webhook","url":"ftp://not-valid"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/notifications", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.CreateNotification(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandler_CreateNotification_MissingOrgID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"type":"webhook","url":"https://example.com"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/notifications", bytes.NewBufferString(body))

	w := httptest.NewRecorder()
	handler.CreateNotification(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandler_CreateNotification_InvalidJSON(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/notifications", bytes.NewBufferString("not json"))
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.CreateNotification(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandler_UpdateNotification_Success(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	now := time.Now()
	mock.ExpectQuery("SELECT").
		WithArgs("notif-1", "org-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "tenant_id", "type", "url", "secret", "active", "created_at", "updated_at",
		}).AddRow("notif-1", "org-1", "", "webhook", "https://old.com", "secret", true, now, now))

	mock.ExpectExec("UPDATE circuit_breaker_notifications").
		WillReturnResult(sqlmock.NewResult(0, 1))

	body := `{"url":"https://new.com/webhook"}`
	req := httptest.NewRequest("PUT", "/api/v1/circuit-breaker/notifications/notif-1", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "org-1")
	req = mux.SetURLVars(req, map[string]string{"id": "notif-1"})

	w := httptest.NewRecorder()
	handler.UpdateNotification(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_UpdateNotification_NotFound(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectQuery("SELECT").
		WithArgs("nonexistent", "org-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "tenant_id", "type", "url", "secret", "active", "created_at", "updated_at",
		}))

	body := `{"url":"https://new.com"}`
	req := httptest.NewRequest("PUT", "/api/v1/circuit-breaker/notifications/nonexistent", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "org-1")
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})

	w := httptest.NewRecorder()
	handler.UpdateNotification(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestHandler_UpdateNotification_MissingOrgID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	body := `{"url":"https://new.com"}`
	req := httptest.NewRequest("PUT", "/api/v1/circuit-breaker/notifications/notif-1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "notif-1"})

	w := httptest.NewRecorder()
	handler.UpdateNotification(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandler_UpdateNotification_InvalidType(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	now := time.Now()
	mock.ExpectQuery("SELECT").
		WithArgs("notif-1", "org-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "tenant_id", "type", "url", "secret", "active", "created_at", "updated_at",
		}).AddRow("notif-1", "org-1", "", "webhook", "https://example.com", nil, true, now, now))

	body := `{"type":"invalid"}`
	req := httptest.NewRequest("PUT", "/api/v1/circuit-breaker/notifications/notif-1", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "org-1")
	req = mux.SetURLVars(req, map[string]string{"id": "notif-1"})

	w := httptest.NewRecorder()
	handler.UpdateNotification(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandler_DeleteNotification_Success(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectExec("DELETE FROM circuit_breaker_notifications").
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := httptest.NewRequest("DELETE", "/api/v1/circuit-breaker/notifications/notif-1", nil)
	req.Header.Set("X-Org-ID", "org-1")
	req = mux.SetURLVars(req, map[string]string{"id": "notif-1"})

	w := httptest.NewRecorder()
	handler.DeleteNotification(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestHandler_DeleteNotification_NotFound(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectExec("DELETE FROM circuit_breaker_notifications").
		WillReturnResult(sqlmock.NewResult(0, 0))

	req := httptest.NewRequest("DELETE", "/api/v1/circuit-breaker/notifications/nonexistent", nil)
	req.Header.Set("X-Org-ID", "org-1")
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})

	w := httptest.NewRecorder()
	handler.DeleteNotification(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestHandler_DeleteNotification_MissingOrgID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("DELETE", "/api/v1/circuit-breaker/notifications/notif-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "notif-1"})

	w := httptest.NewRecorder()
	handler.DeleteNotification(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestRegisterRoutes_IncludesNewEndpoints(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	newRoutes := []struct {
		path   string
		method string
	}{
		{"/api/v1/circuit-breaker/config", "GET"},
		{"/api/v1/circuit-breaker/config", "PUT"},
		{"/api/v1/circuit-breaker/notifications", "GET"},
		{"/api/v1/circuit-breaker/notifications", "POST"},
		{"/api/v1/circuit-breaker/notifications/notif-1", "PUT"},
		{"/api/v1/circuit-breaker/notifications/notif-1", "DELETE"},
	}

	for _, route := range newRoutes {
		req := httptest.NewRequest(route.method, route.path, nil)
		match := &mux.RouteMatch{}
		if !r.Match(req, match) {
			t.Errorf("Route %s %s not registered", route.method, route.path)
		}
	}
}
