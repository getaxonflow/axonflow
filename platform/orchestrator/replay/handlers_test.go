// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

func newTestHandler() (*Handler, *MockRepository) {
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))
	handler := NewHandlerWithLogger(service, log.New(io.Discard, "", 0))
	return handler, repo
}

func setupRouter(h *Handler) *mux.Router {
	r := mux.NewRouter()
	h.RegisterRoutes(r)
	return r
}

func TestNewHandler(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo)
	handler := NewHandler(service)

	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	if handler.service != service {
		t.Error("expected service to be set")
	}
	if handler.logger == nil {
		t.Error("expected logger to be set")
	}
}

func TestNewHandlerWithLogger(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo)
	logger := log.New(io.Discard, "", 0)

	handler := NewHandlerWithLogger(service, logger)
	if handler.logger != logger {
		t.Error("expected custom logger to be set")
	}

	// Test with nil logger
	handler2 := NewHandlerWithLogger(service, nil)
	if handler2.logger == nil {
		t.Error("expected default logger when nil passed")
	}
}

func TestHandler_RegisterRoutes(t *testing.T) {
	h, _ := newTestHandler()
	r := setupRouter(h)

	// Verify routes are registered
	routes := []struct {
		path   string
		method string
	}{
		{"/api/v1/executions", "GET"},
		{"/api/v1/executions/{id}", "GET"},
		{"/api/v1/executions/{id}/steps", "GET"},
		{"/api/v1/executions/{id}/steps/{stepIndex}", "GET"},
		{"/api/v1/executions/{id}/timeline", "GET"},
		{"/api/v1/executions/{id}/export", "GET"},
		{"/api/v1/executions/{id}", "DELETE"},
	}

	for _, route := range routes {
		match := &mux.RouteMatch{}
		req := httptest.NewRequest(route.method, route.path, nil)
		if !r.Match(req, match) {
			t.Errorf("route %s %s not registered", route.method, route.path)
		}
	}
}

func TestHandler_ListExecutions(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	// Add test data
	now := time.Now()
	repo.AddSummary(&ExecutionSummary{
		RequestID:  "req-1",
		Status:     ExecutionStatusCompleted,
		TotalSteps: 2,
		StartedAt:  now,
	})
	repo.AddSummary(&ExecutionSummary{
		RequestID:  "req-2",
		Status:     ExecutionStatusRunning,
		TotalSteps: 3,
		StartedAt:  now,
	})

	// Make request
	req := httptest.NewRequest("GET", "/api/v1/executions?limit=10", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var response ListExecutionsResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Total != 2 {
		t.Errorf("expected total 2, got %d", response.Total)
	}
	if len(response.Executions) != 2 {
		t.Errorf("expected 2 executions, got %d", len(response.Executions))
	}
}

func TestHandler_ListExecutions_WithFilters(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	// Add test data
	now := time.Now()
	repo.AddSummary(&ExecutionSummary{
		RequestID:    "req-1",
		Status:       ExecutionStatusCompleted,
		WorkflowName: "workflow-a",
		TotalSteps:   2,
		StartedAt:    now,
	})
	repo.AddSummary(&ExecutionSummary{
		RequestID:    "req-2",
		Status:       ExecutionStatusFailed,
		WorkflowName: "workflow-b",
		TotalSteps:   3,
		StartedAt:    now,
	})

	// Filter by status
	req := httptest.NewRequest("GET", "/api/v1/executions?status=completed", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var response ListExecutionsResponse
	_ = json.NewDecoder(w.Body).Decode(&response)

	if response.Total != 1 {
		t.Errorf("expected 1 completed, got %d", response.Total)
	}

	// Filter by workflow_id
	req = httptest.NewRequest("GET", "/api/v1/executions?workflow_id=workflow-a", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	_ = json.NewDecoder(w.Body).Decode(&response)
	if response.Total != 1 {
		t.Errorf("expected 1 for workflow-a, got %d", response.Total)
	}
}

func TestHandler_ListExecutions_Pagination(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	// Add test data
	for i := 0; i < 10; i++ {
		repo.AddSummary(&ExecutionSummary{
			RequestID:  string(rune('a'+i)) + "-req",
			Status:     ExecutionStatusCompleted,
			TotalSteps: 1,
		})
	}

	// Test limit and offset
	req := httptest.NewRequest("GET", "/api/v1/executions?limit=3&offset=2", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var response ListExecutionsResponse
	_ = json.NewDecoder(w.Body).Decode(&response)

	if response.Total != 10 {
		t.Errorf("expected total 10, got %d", response.Total)
	}
	if response.Limit != 3 {
		t.Errorf("expected limit 3, got %d", response.Limit)
	}
	if response.Offset != 2 {
		t.Errorf("expected offset 2, got %d", response.Offset)
	}
}

func TestHandler_ListExecutions_TimeFilter(t *testing.T) {
	h, _ := newTestHandler()
	r := setupRouter(h)

	// Test with time filters (verify parsing)
	startTime := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	endTime := time.Now().Format(time.RFC3339)
	req := httptest.NewRequest("GET", "/api/v1/executions?start_time="+startTime+"&end_time="+endTime, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestHandler_ListExecutions_CORS(t *testing.T) {
	h, _ := newTestHandler()
	r := setupRouter(h)

	req := httptest.NewRequest("OPTIONS", "/api/v1/executions", nil)
	req.Header.Set("Origin", "https://app.getaxonflow.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 for OPTIONS, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://app.getaxonflow.com" {
		t.Error("expected CORS origin header")
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("expected CORS methods header")
	}
}

func TestHandler_ListExecutions_Error(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	repo.ListSummariesErr = ErrInvalidInput

	req := httptest.NewRequest("GET", "/api/v1/executions", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}
}

func TestHandler_GetExecution(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	// Add test data
	repo.AddSummary(&ExecutionSummary{
		RequestID:  "req-123",
		Status:     ExecutionStatusCompleted,
		TotalSteps: 2,
		StartedAt:  time.Now(),
	})
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 0,
		StepName:  "step-1",
		Status:    StepStatusCompleted,
	})

	req := httptest.NewRequest("GET", "/api/v1/executions/req-123", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var exec Execution
	if err := json.NewDecoder(w.Body).Decode(&exec); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if exec.Summary.RequestID != "req-123" {
		t.Error("expected request ID to match")
	}
	if len(exec.Steps) != 1 {
		t.Errorf("expected 1 step, got %d", len(exec.Steps))
	}
}

func TestHandler_GetExecution_NotFound(t *testing.T) {
	h, _ := newTestHandler()
	r := setupRouter(h)

	req := httptest.NewRequest("GET", "/api/v1/executions/nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}

	var errResp ErrorResponse
	_ = json.NewDecoder(w.Body).Decode(&errResp)
	if errResp.Code != "NOT_FOUND" {
		t.Errorf("expected error code NOT_FOUND, got %s", errResp.Code)
	}
}

func TestHandler_GetExecution_CORS(t *testing.T) {
	h, _ := newTestHandler()
	r := setupRouter(h)

	req := httptest.NewRequest("OPTIONS", "/api/v1/executions/req-123", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 for OPTIONS, got %d", w.Code)
	}
}

func TestHandler_GetSteps(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	// Add test data
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 0,
		StepName:  "step-1",
	})
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 1,
		StepName:  "step-2",
	})

	req := httptest.NewRequest("GET", "/api/v1/executions/req-123/steps", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var steps []ExecutionSnapshot
	if err := json.NewDecoder(w.Body).Decode(&steps); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(steps))
	}
}

func TestHandler_GetSteps_Error(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	repo.GetSnapshotsErr = ErrInvalidInput

	req := httptest.NewRequest("GET", "/api/v1/executions/req-123/steps", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}
}

func TestHandler_GetStep(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	// Add test data
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 0,
		StepName:  "step-1",
		Status:    StepStatusCompleted,
	})

	req := httptest.NewRequest("GET", "/api/v1/executions/req-123/steps/0", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var step ExecutionSnapshot
	if err := json.NewDecoder(w.Body).Decode(&step); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if step.StepName != "step-1" {
		t.Errorf("expected step-1, got %s", step.StepName)
	}
}

func TestHandler_GetStep_NotFound(t *testing.T) {
	h, _ := newTestHandler()
	r := setupRouter(h)

	req := httptest.NewRequest("GET", "/api/v1/executions/req-123/steps/0", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

func TestHandler_GetStep_InvalidIndex(t *testing.T) {
	h, _ := newTestHandler()
	r := setupRouter(h)

	req := httptest.NewRequest("GET", "/api/v1/executions/req-123/steps/invalid", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHandler_GetTimeline(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	now := time.Now()
	completedAt := now.Add(100 * time.Millisecond)
	duration := 100

	// Add test data
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID:   "req-123",
		StepIndex:   0,
		StepName:    "step-1",
		Status:      StepStatusCompleted,
		StartedAt:   now,
		CompletedAt: &completedAt,
		DurationMs:  &duration,
	})
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID:    "req-123",
		StepIndex:    1,
		StepName:     "step-2",
		Status:       StepStatusFailed,
		StartedAt:    completedAt,
		ErrorMessage: "error",
	})

	req := httptest.NewRequest("GET", "/api/v1/executions/req-123/timeline", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var timeline []TimelineEntry
	if err := json.NewDecoder(w.Body).Decode(&timeline); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(timeline) != 2 {
		t.Errorf("expected 2 timeline entries, got %d", len(timeline))
	}
	if timeline[1].HasError != true {
		t.Error("expected step-2 to have error")
	}
}

func TestHandler_GetTimeline_NotFound(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	repo.GetSnapshotsErr = ErrNotFound

	req := httptest.NewRequest("GET", "/api/v1/executions/req-123/timeline", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

func TestHandler_ExportExecution(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	// Add test data
	repo.AddSummary(&ExecutionSummary{
		RequestID:  "req-123",
		Status:     ExecutionStatusCompleted,
		TotalSteps: 1,
		StartedAt:  time.Now(),
	})
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 0,
		StepName:  "step-1",
		Status:    StepStatusCompleted,
	})

	req := httptest.NewRequest("GET", "/api/v1/executions/req-123/export", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Check headers
	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("expected Content-Type application/json")
	}
	if w.Header().Get("Content-Disposition") != "attachment; filename=execution-req-123.json" {
		t.Error("expected Content-Disposition header")
	}
}

func TestHandler_ExportExecution_WithOptions(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	// Add test data
	repo.AddSummary(&ExecutionSummary{
		RequestID:     "req-123",
		Status:        ExecutionStatusCompleted,
		TotalSteps:    1,
		StartedAt:     time.Now(),
		InputSummary:  json.RawMessage(`{"prompt": "test"}`),
		OutputSummary: json.RawMessage(`{"response": "result"}`),
	})
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID:       "req-123",
		StepIndex:       0,
		StepName:        "step-1",
		Status:          StepStatusCompleted,
		Input:           json.RawMessage(`{"data": "in"}`),
		Output:          json.RawMessage(`{"data": "out"}`),
		PoliciesChecked: []string{"p1"},
	})

	// Export without input/output
	req := httptest.NewRequest("GET", "/api/v1/executions/req-123/export?include_input=false&include_output=false&include_policies=false", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var export struct {
		Execution *Execution `json:"execution"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &export)

	if export.Execution.Summary.InputSummary != nil {
		t.Error("expected input summary to be redacted")
	}
	if export.Execution.Steps[0].Input != nil {
		t.Error("expected step input to be redacted")
	}
}

func TestHandler_ExportExecution_NotFound(t *testing.T) {
	h, _ := newTestHandler()
	r := setupRouter(h)

	req := httptest.NewRequest("GET", "/api/v1/executions/nonexistent/export", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

func TestHandler_DeleteExecution(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	// Add test data
	repo.AddSummary(&ExecutionSummary{
		RequestID: "req-123",
		Status:    ExecutionStatusCompleted,
	})

	req := httptest.NewRequest("DELETE", "/api/v1/executions/req-123", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d", w.Code)
	}

	// Verify deletion
	if repo.GetSummaryCount() != 0 {
		t.Error("expected summary to be deleted")
	}
}

func TestHandler_DeleteExecution_NotFound(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	repo.DeleteErr = ErrNotFound

	req := httptest.NewRequest("DELETE", "/api/v1/executions/nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

func TestHandler_TenantOrgHeaders(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)

	// Add test data
	repo.AddSummary(&ExecutionSummary{
		RequestID: "req-1",
		Status:    ExecutionStatusCompleted,
		OrgID:     "org-123",
		TenantID:  "tenant-456",
	})
	repo.AddSummary(&ExecutionSummary{
		RequestID: "req-2",
		Status:    ExecutionStatusCompleted,
		OrgID:     "org-other",
		TenantID:  "tenant-other",
	})

	// Request with tenant/org headers
	req := httptest.NewRequest("GET", "/api/v1/executions", nil)
	req.Header.Set("X-Tenant-ID", "tenant-456")
	req.Header.Set("X-Org-ID", "org-123")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var response ListExecutionsResponse
	_ = json.NewDecoder(w.Body).Decode(&response)

	if response.Total != 1 {
		t.Errorf("expected 1 execution for tenant/org, got %d", response.Total)
	}
}

func TestHandler_CORS_AllowedOrigins(t *testing.T) {
	h, _ := newTestHandler()
	r := setupRouter(h)

	allowedOrigins := []string{
		"https://app.getaxonflow.com",
		"https://staging.getaxonflow.com",
		"https://demo.getaxonflow.com",
		"https://customer.getaxonflow.com",
		"http://localhost:3000",
		"http://localhost:8080",
		"http://localhost:8081",
	}

	for _, origin := range allowedOrigins {
		req := httptest.NewRequest("OPTIONS", "/api/v1/executions", nil)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != origin {
			t.Errorf("expected CORS origin %s to be allowed", origin)
		}
	}

	// Test disallowed origin
	req := httptest.NewRequest("OPTIONS", "/api/v1/executions", nil)
	req.Header.Set("Origin", "https://malicious.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") == "https://malicious.com" {
		t.Error("expected malicious origin to not be allowed")
	}
}

func TestHandler_WriteJSON(t *testing.T) {
	h, _ := newTestHandler()

	// Test that writeJSON sets correct headers
	w := httptest.NewRecorder()
	h.writeJSON(w, http.StatusOK, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("expected Content-Type application/json")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("expected default CORS header for responses")
	}
}

func TestHandler_WriteError(t *testing.T) {
	h, _ := newTestHandler()

	w := httptest.NewRecorder()
	h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid input")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	var errResp ErrorResponse
	_ = json.NewDecoder(w.Body).Decode(&errResp)

	if errResp.Code != "BAD_REQUEST" {
		t.Errorf("expected code BAD_REQUEST, got %s", errResp.Code)
	}
	if errResp.Message != "Invalid input" {
		t.Errorf("expected message 'Invalid input', got '%s'", errResp.Message)
	}
	if errResp.Error != "bad_request" {
		t.Errorf("expected error 'bad_request', got '%s'", errResp.Error)
	}
}
