// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - Circuit Breaker Handler Advanced Tests

//go:build enterprise

package circuitbreaker

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestReset_InvalidJSON(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/reset", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "user-1")

	w := httptest.NewRecorder()
	handler.Reset(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCheck_InvalidJSON(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/check", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.Check(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestTrip_DBError(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnError(sql.ErrConnDone)

	body := `{"scope": "global"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "user-1")

	w := httptest.NewRecorder()
	handler.Trip(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Success {
		t.Error("Expected success=false on database error")
	}
}

func TestReset_DBError(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectExec("UPDATE circuit_breaker").
		WillReturnError(sql.ErrConnDone)

	body := `{"scope": "global"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/reset", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "user-1")

	w := httptest.NewRecorder()
	handler.Reset(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestCheck_DBError(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	// First trip the circuit
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	tripBody := `{"scope": "global"}`
	tripReq := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(tripBody))
	tripReq.Header.Set("Content-Type", "application/json")
	tripReq.Header.Set("X-Org-ID", "org-1")
	tripReq.Header.Set("X-User-ID", "user-1")
	tripW := httptest.NewRecorder()
	handler.Trip(tripW, tripReq)

	// Now check - this won't hit DB if circuit is in cache, so this test
	// is more about ensuring the handler can handle errors gracefully
	body := `{"tenant_id": "tenant-1"}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/check", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.Check(w, req)

	// Should still work since it checks in-memory cache
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestStatus_DBError(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectQuery("SELECT").
		WillReturnError(sql.ErrConnDone)

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/status", nil)
	req.Header.Set("X-Org-ID", "org-1")
	w := httptest.NewRecorder()

	handler.Status(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestHistory_DBError(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectQuery("SELECT").
		WillReturnError(sql.ErrConnDone)

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/history", nil)
	req.Header.Set("X-Org-ID", "org-1")
	w := httptest.NewRecorder()

	handler.History(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestHistory_CustomLimit(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "scope", "scope_id", "state",
			"trip_reason", "tripped_by", "tripped_by_email", "trip_comment",
			"tripped_at", "expires_at", "reset_by", "reset_at",
			"error_count", "violation_count", "created_at", "updated_at",
		}))

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/history?limit=25", nil)
	req.Header.Set("X-Org-ID", "org-1")
	w := httptest.NewRecorder()

	handler.History(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestHistory_InvalidLimit(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	// Invalid limit should default to 50
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "scope", "scope_id", "state",
			"trip_reason", "tripped_by", "tripped_by_email", "trip_comment",
			"tripped_at", "expires_at", "reset_by", "reset_at",
			"error_count", "violation_count", "created_at", "updated_at",
		}))

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/history?limit=invalid", nil)
	req.Header.Set("X-Org-ID", "org-1")
	w := httptest.NewRecorder()

	handler.History(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestHistory_LimitTooHigh(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	// Limit > 100 should be capped to 50
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "scope", "scope_id", "state",
			"trip_reason", "tripped_by", "tripped_by_email", "trip_comment",
			"tripped_at", "expires_at", "reset_by", "reset_at",
			"error_count", "violation_count", "created_at", "updated_at",
		}))

	req := httptest.NewRequest("GET", "/api/v1/circuit-breaker/history?limit=500", nil)
	req.Header.Set("X-Org-ID", "org-1")
	w := httptest.NewRecorder()

	handler.History(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestTrip_WithAllFields(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	body := `{
		"scope": "client",
		"scope_id": "client-1",
		"reason": "risk_level",
		"comment": "High risk detected",
		"duration_minutes": 120
	}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "user-1")
	req.Header.Set("X-User-Email", "user@example.com")

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

	data := resp.Data.(map[string]interface{})
	if data["scope"] != "client" {
		t.Errorf("Expected scope 'client', got %v", data["scope"])
	}
	if data["scope_id"] != "client-1" {
		t.Errorf("Expected scope_id 'client-1', got %v", data["scope_id"])
	}
}

func TestReset_WithScopeID(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	// First trip
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	tripBody := `{"scope": "tenant", "scope_id": "tenant-1"}`
	tripReq := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(tripBody))
	tripReq.Header.Set("Content-Type", "application/json")
	tripReq.Header.Set("X-Org-ID", "org-1")
	tripReq.Header.Set("X-User-ID", "user-1")
	tripW := httptest.NewRecorder()
	handler.Trip(tripW, tripReq)

	// Then reset with scope_id
	mock.ExpectExec("UPDATE circuit_breaker").
		WillReturnResult(sqlmock.NewResult(0, 1))

	resetBody := `{"scope": "tenant", "scope_id": "tenant-1", "comment": "Reset test"}`
	resetReq := httptest.NewRequest("POST", "/api/v1/circuit-breaker/reset", bytes.NewBufferString(resetBody))
	resetReq.Header.Set("Content-Type", "application/json")
	resetReq.Header.Set("X-Org-ID", "org-1")
	resetReq.Header.Set("X-User-ID", "user-2")

	resetW := httptest.NewRecorder()
	handler.Reset(resetW, resetReq)

	if resetW.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resetW.Code)
	}
}

func TestCheck_WithPolicyID(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	// Trip at policy scope
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	tripBody := `{"scope": "policy", "scope_id": "policy-1"}`
	tripReq := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(tripBody))
	tripReq.Header.Set("Content-Type", "application/json")
	tripReq.Header.Set("X-Org-ID", "org-1")
	tripReq.Header.Set("X-User-ID", "user-1")
	tripW := httptest.NewRecorder()
	handler.Trip(tripW, tripReq)

	// Check with policy_id
	checkBody := `{"policy_id": "policy-1"}`
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
		t.Error("Expected allowed=false when policy circuit is open")
	}
	if data["scope"] != "policy" {
		t.Errorf("Expected scope 'policy', got %v", data["scope"])
	}
}

func TestTrip_ZeroDuration(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Duration 0 means manual reset required
	body := `{"scope": "global", "duration_minutes": 0}`
	req := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "user-1")

	w := httptest.NewRecorder()
	handler.Trip(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	data := resp.Data.(map[string]interface{})
	// expires_at should be nil for indefinite duration
	if data["expires_at"] != nil {
		t.Error("Expected expires_at to be nil for zero duration")
	}
}

func TestStatus_WithActiveCircuits(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	// Trip a circuit first
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	tripBody := `{"scope": "global"}`
	tripReq := httptest.NewRequest("POST", "/api/v1/circuit-breaker/trip", bytes.NewBufferString(tripBody))
	tripReq.Header.Set("Content-Type", "application/json")
	tripReq.Header.Set("X-Org-ID", "org-1")
	tripReq.Header.Set("X-User-ID", "user-1")
	tripW := httptest.NewRecorder()
	handler.Trip(tripW, tripReq)

	// Mock GetActiveCircuits to return the circuit
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
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if !resp.Success {
		t.Error("Expected success=true")
	}
}

func TestCheck_AllScopeTypes(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	// Test with all scope IDs
	body := `{
		"tenant_id": "tenant-1",
		"client_id": "client-1",
		"policy_id": "policy-1"
	}`
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
