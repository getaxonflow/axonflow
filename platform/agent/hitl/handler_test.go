// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - HITL Queue Handler Tests

//go:build enterprise

package hitl

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axonflow/platform/agent/license"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// setupTestHandler builds a handler whose Service has the tier provider
// pinned to Evaluation. Existing handler tests assume the request flow
// reaches the DB layer; the tier gate added in #1998 would otherwise
// short-circuit them at 403. Tests that specifically exercise the
// Community-tier rejection path call setupTestHandlerCommunityTier.
func setupTestHandler(t *testing.T) (*Handler, sqlmock.Sqlmock, func()) {
	return setupTestHandlerWithTier(t, license.TierEvaluation)
}

func setupTestHandlerCommunityTier(t *testing.T) (*Handler, sqlmock.Sqlmock, func()) {
	return setupTestHandlerWithTier(t, license.TierCommunity)
}

func setupTestHandlerWithTier(t *testing.T, tier license.Tier) (*Handler, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}

	repo := NewRepository(db)
	svc := NewService(repo, ServiceConfig{
		DefaultExpiry: 24 * time.Hour,
		MaxExpiry:     168 * time.Hour,
	})
	svc.SetTierProviderForTest(func(_ context.Context) license.Tier { return tier })
	handler := NewHandler(svc)

	cleanup := func() {
		db.Close()
	}

	return handler, mock, cleanup
}

func TestListRequests(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	// Mock count query
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// Mock list query
	requestID1 := uuid.New()
	requestID2 := uuid.New()
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by",
			"expires_at", "created_at", "updated_at",
		}).
			AddRow(1, requestID1, "org-1", "tenant-1", "client-1", nil,
				"SELECT * FROM users", "sql", nil,
				"policy-1", "PII Detection", "Contains PII", "high",
				"14", "EU_AI_Act", "high-risk_ai_system",
				"pending", nil, nil, nil, nil, nil,
				nil, nil,
				time.Now().Add(24*time.Hour), time.Now(), time.Now()).
			AddRow(2, requestID2, "org-1", "tenant-1", "client-2", nil,
				"SELECT * FROM orders", "sql", nil,
				"policy-2", "Data Access", "Sensitive data", "medium",
				"14", "EU_AI_Act", "high-risk_ai_system",
				"pending", nil, nil, nil, nil, nil,
				nil, nil,
				time.Now().Add(24*time.Hour), time.Now(), time.Now()))

	req := httptest.NewRequest("GET", "/api/v1/hitl/queue?status=pending&limit=10", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Errorf("Expected success=true, got false: %s", resp.Error)
	}
	if resp.Meta == nil || resp.Meta.Total != 2 {
		t.Errorf("Expected total=2, got %v", resp.Meta)
	}
}

func TestCreateRequest_Success(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	// Mock INSERT
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(1, time.Now(), time.Now()))

	// Mock history INSERT
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).
			AddRow(1, time.Now()))

	input := CreateRequestInput{
		ClientID:            "client-1",
		OriginalQuery:       "SELECT * FROM users",
		RequestType:         "sql",
		TriggeredPolicyID:   "policy-1",
		TriggeredPolicyName: "PII Detection",
		TriggerReason:       "Contains PII data",
		Severity:            "high",
		EUAIActArticle:      "14",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Errorf("Expected success=true, got false: %s", resp.Error)
	}
}

// TestCreateRequest_CommunityTierForbidden asserts that a Community-tier
// process returns 403 Forbidden with the tier-rejection error wording.
// Added in #1998 to close the parallel bypass on the agent's
// `POST /api/v1/hitl/queue` endpoint (Fix B).
func TestCreateRequest_CommunityTierForbidden(t *testing.T) {
	handler, mock, cleanup := setupTestHandlerCommunityTier(t)
	defer cleanup()

	// No DB mock expectations registered: if the handler short-circuits
	// at the tier gate (correct behavior), no DB query fires. Any query
	// that fires will be flagged by sqlmock.

	input := CreateRequestInput{
		ClientID:            "client-1",
		OriginalQuery:       "rm -rf /",
		RequestType:         "shell_command",
		TriggeredPolicyID:   "policy-1",
		TriggeredPolicyName: "Destructive command",
		TriggerReason:       "deletion attempt",
		Severity:            "high",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d: %s", w.Code, w.Body.String())
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Success {
		t.Error("Expected success=false")
	}
	if resp.Error == "" {
		t.Error("Expected non-empty error message")
	}
	// The error body must surface the upgrade hint so the caller can
	// tell the user how to unblock — guards against a future refactor
	// that swallows the message.
	if !strings.Contains(resp.Error, "Evaluation") {
		t.Errorf("Expected error to mention 'Evaluation' license tier, got: %q", resp.Error)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB query fired despite tier-gate rejection: %v", err)
	}
}

func TestCreateRequest_MissingOrgHeader(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	input := CreateRequestInput{
		ClientID: "client-1",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Missing X-Org-ID and X-Tenant-ID
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetRequest(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	// Mock SELECT
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk_ai_system",
			"pending", nil, nil, nil, nil, nil,
			nil, nil,
			time.Now().Add(24*time.Hour), time.Now(), time.Now(),
		))

	req := httptest.NewRequest("GET", "/api/v1/hitl/queue/"+requestID.String(), nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetRequest_NotFound(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	// Mock SELECT returning no rows
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by",
			"expires_at", "created_at", "updated_at",
		}))

	req := httptest.NewRequest("GET", "/api/v1/hitl/queue/"+requestID.String(), nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetRequest_InvalidID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/hitl/queue/invalid-uuid", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestApproveRequest(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	// Mock GetByRequestID
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk_ai_system",
			"pending", nil, nil, nil, nil, nil,
			nil, nil,
			time.Now().Add(24*time.Hour), time.Now(), time.Now(),
		))

	// Mock UPDATE
	mock.ExpectQuery("UPDATE hitl_approval_queue").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))

	// Mock history INSERT
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(1, time.Now()))

	input := ReviewInput{
		ReviewerID:    "reviewer-1",
		ReviewerEmail: "reviewer@example.com",
		ReviewerRole:  "admin",
		Comment:       "Approved after review",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/"+requestID.String()+"/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRejectRequest(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	// Mock GetByRequestID
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk_ai_system",
			"pending", nil, nil, nil, nil, nil,
			nil, nil,
			time.Now().Add(24*time.Hour), time.Now(), time.Now(),
		))

	// Mock UPDATE
	mock.ExpectQuery("UPDATE hitl_approval_queue").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))

	// Mock history INSERT
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(1, time.Now()))

	input := ReviewInput{
		ReviewerID:    "reviewer-1",
		ReviewerEmail: "reviewer@example.com",
		Comment:       "Request denied - policy violation",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/"+requestID.String()+"/reject", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOverrideRequest(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	// Mock GetByRequestID
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk_ai_system",
			"pending", nil, nil, nil, nil, nil,
			nil, nil,
			time.Now().Add(24*time.Hour), time.Now(), time.Now(),
		))

	// Mock UPDATE
	mock.ExpectQuery("UPDATE hitl_approval_queue").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))

	// Mock history INSERT
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(1, time.Now()))

	input := OverrideInput{
		Justification:     "Emergency override - customer escalation",
		AuthorizedByID:    "admin-1",
		AuthorizedByEmail: "admin@example.com",
		AuthorizedByRole:  "super_admin",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/"+requestID.String()+"/override", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetStats(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	// Mock get_hitl_pending_count function
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"total_pending", "high_priority", "critical_priority", "oldest_pending_hours",
		}).AddRow(10, 5, 2, 3.5))

	req := httptest.NewRequest("GET", "/api/v1/hitl/stats", nil)
	req.Header.Set("X-Org-ID", "org-1")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Errorf("Expected success=true, got false: %s", resp.Error)
	}
}

func TestGetStats_MissingOrgHeader(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/hitl/stats", nil)
	// Missing X-Org-ID
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExpireStale(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	// Mock expire_hitl_requests function
	mock.ExpectQuery("SELECT expire_hitl_requests").
		WillReturnRows(sqlmock.NewRows([]string{"expire_hitl_requests"}).AddRow(5))

	req := httptest.NewRequest("POST", "/api/v1/hitl/expire", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Errorf("Expected success=true, got false: %s", resp.Error)
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		remoteAddr string
		expected string
	}{
		{
			name:       "X-Forwarded-For single IP",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.1"},
			remoteAddr: "10.0.0.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:       "X-Forwarded-For multiple IPs",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.1, 10.0.0.2, 10.0.0.3"},
			remoteAddr: "10.0.0.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:       "X-Real-IP",
			headers:    map[string]string{"X-Real-IP": "192.168.1.1"},
			remoteAddr: "10.0.0.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:       "RemoteAddr fallback",
			headers:    map[string]string{},
			remoteAddr: "10.0.0.1:12345",
			expected:   "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := getClientIP(req)
			if ip != tt.expected {
				t.Errorf("Expected IP %q, got %q", tt.expected, ip)
			}
		})
	}
}

func TestParseInt(t *testing.T) {
	tests := []struct {
		input      string
		defaultVal int
		expected   int
	}{
		{"10", 5, 10},
		{"", 5, 5},
		{"invalid", 5, 5},
		{"0", 5, 0},
		{"-1", 5, -1},
	}

	for _, tt := range tests {
		result := parseInt(tt.input, tt.defaultVal)
		if result != tt.expected {
			t.Errorf("parseInt(%q, %d) = %d, expected %d", tt.input, tt.defaultVal, result, tt.expected)
		}
	}
}

func TestCreateRequest_InvalidJSON(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue", bytes.NewReader([]byte("{invalid json")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Success {
		t.Error("Expected success=false")
	}
}

func TestApproveRequest_InvalidJSON(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/"+requestID.String()+"/approve", bytes.NewReader([]byte("{invalid")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestApproveRequest_InvalidID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	input := ReviewInput{
		ReviewerID:    "reviewer-1",
		ReviewerEmail: "reviewer@example.com",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/invalid-uuid/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestApproveRequest_NotFound(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	// Mock GetByRequestID returning nil
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by",
			"expires_at", "created_at", "updated_at",
		}))

	input := ReviewInput{
		ReviewerID:    "reviewer-1",
		ReviewerEmail: "reviewer@example.com",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/"+requestID.String()+"/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestApproveRequest_Conflict(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	// Mock GetByRequestID returning an expired request
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk_ai_system",
			"pending", nil, nil, nil, nil, nil,
			nil, nil,
			time.Now().Add(-1*time.Hour), time.Now(), time.Now(),
		))

	input := ReviewInput{
		ReviewerID:    "reviewer-1",
		ReviewerEmail: "reviewer@example.com",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/"+requestID.String()+"/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected status 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRejectRequest_InvalidJSON(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/"+requestID.String()+"/reject", bytes.NewReader([]byte("bad json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRejectRequest_InvalidID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	input := ReviewInput{
		ReviewerID:    "reviewer-1",
		ReviewerEmail: "reviewer@example.com",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/not-a-uuid/reject", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRejectRequest_NotFound(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by",
			"expires_at", "created_at", "updated_at",
		}))

	input := ReviewInput{
		ReviewerID:    "reviewer-1",
		ReviewerEmail: "reviewer@example.com",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/"+requestID.String()+"/reject", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRejectRequest_Conflict(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	// Mock GetByRequestID returning an already approved request
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk_ai_system",
			"approved", "other-reviewer", "other@example.com", "admin", "Done", time.Now(),
			nil, nil,
			time.Now().Add(24*time.Hour), time.Now(), time.Now(),
		))

	input := ReviewInput{
		ReviewerID:    "reviewer-1",
		ReviewerEmail: "reviewer@example.com",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/"+requestID.String()+"/reject", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected status 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOverrideRequest_InvalidJSON(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/"+requestID.String()+"/override", bytes.NewReader([]byte("{")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOverrideRequest_InvalidID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	input := OverrideInput{
		Justification:     "Emergency",
		AuthorizedByID:    "admin-1",
		AuthorizedByEmail: "admin@example.com",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/bad-uuid/override", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOverrideRequest_NotFound(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by",
			"expires_at", "created_at", "updated_at",
		}))

	input := OverrideInput{
		Justification:     "Emergency",
		AuthorizedByID:    "admin-1",
		AuthorizedByEmail: "admin@example.com",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/"+requestID.String()+"/override", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOverrideRequest_MissingJustification(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()

	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk_ai_system",
			"pending", nil, nil, nil, nil, nil,
			nil, nil,
			time.Now().Add(24*time.Hour), time.Now(), time.Now(),
		))

	input := OverrideInput{
		Justification:     "", // Missing
		AuthorizedByID:    "admin-1",
		AuthorizedByEmail: "admin@example.com",
	}
	body, _ := json.Marshal(input)

	req := httptest.NewRequest("POST", "/api/v1/hitl/queue/"+requestID.String()+"/override", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetRequestHistory(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	requestID := uuid.New()
	now := time.Now()

	mock.ExpectQuery("SELECT").
		WithArgs(requestID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "action",
			"actor_id", "actor_email", "actor_role", "actor_ip",
			"comment", "justification",
			"previous_status", "new_status", "created_at",
		}).
			AddRow(1, requestID, "org-1", "tenant-1", "created",
				nil, nil, nil, nil,
				nil, nil,
				nil, "pending", now).
			AddRow(2, requestID, "org-1", "tenant-1", "approved",
				"reviewer-1", "reviewer@example.com", "admin", "192.168.1.1",
				"Looks good", nil,
				"pending", "approved", now.Add(1*time.Hour)))

	req := httptest.NewRequest("GET", "/api/v1/hitl/queue/"+requestID.String()+"/history", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Errorf("Expected success=true, got false: %s", resp.Error)
	}
}

func TestGetRequestHistory_InvalidID(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/hitl/queue/invalid-uuid/history", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListRequests_WithMultipleFilters(t *testing.T) {
	handler, mock, cleanup := setupTestHandler(t)
	defer cleanup()

	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	requestID := uuid.New()
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by",
			"expires_at", "created_at", "updated_at",
		}).
			AddRow(1, requestID, "org-1", "tenant-1", "client-1", "user-1",
				"SELECT * FROM users", "sql", nil,
				"policy-1", "PII Detection", "Contains PII", "high",
				"14", "EU_AI_Act", "high-risk_ai_system",
				"pending", nil, nil, nil, nil, nil,
				nil, nil,
				time.Now().Add(24*time.Hour), time.Now(), time.Now()))

	req := httptest.NewRequest("GET", "/api/v1/hitl/queue?status=pending&severity=high&policy_id=policy-1&client_id=client-1&user_id=user-1&limit=20&offset=0&order_by=created_at&order_dir=ASC", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Errorf("Expected success=true, got false: %s", resp.Error)
	}
}
