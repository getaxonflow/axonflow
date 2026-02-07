// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/shared/execution"
)

// --- Mock Repository for handler tests ---

type mockRepo struct {
	mu         sync.Mutex
	executions map[string]*execution.ExecutionStatus
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		executions: make(map[string]*execution.ExecutionStatus),
	}
}

func (m *mockRepo) Create(_ context.Context, exec *execution.ExecutionStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if exec == nil {
		return execution.ErrInvalidExecution
	}
	cp := *exec
	cp.Steps = append([]execution.StepStatus{}, exec.Steps...)
	m.executions[exec.ExecutionID] = &cp
	return nil
}

func (m *mockRepo) Get(_ context.Context, id string) (*execution.ExecutionStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	exec, ok := m.executions[id]
	if !ok {
		return nil, execution.ErrExecutionNotFound
	}
	cp := *exec
	cp.Steps = append([]execution.StepStatus{}, exec.Steps...)
	return &cp, nil
}

func (m *mockRepo) Update(_ context.Context, exec *execution.ExecutionStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if exec == nil {
		return execution.ErrInvalidExecution
	}
	if _, ok := m.executions[exec.ExecutionID]; !ok {
		return execution.ErrExecutionNotFound
	}
	cp := *exec
	cp.Steps = append([]execution.StepStatus{}, exec.Steps...)
	m.executions[exec.ExecutionID] = &cp
	return nil
}

func (m *mockRepo) List(_ context.Context, req execution.ListExecutionsRequest) ([]execution.ExecutionStatus, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var results []execution.ExecutionStatus
	for _, exec := range m.executions {
		if req.ExecutionType != nil && exec.ExecutionType != *req.ExecutionType {
			continue
		}
		if req.Status != nil && exec.Status != *req.Status {
			continue
		}
		results = append(results, *exec)
	}
	start := req.Offset
	if start > len(results) {
		start = len(results)
	}
	end := start + req.Limit
	if end > len(results) {
		end = len(results)
	}
	return results[start:end], len(results), nil
}

func (m *mockRepo) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.executions[id]; !ok {
		return execution.ErrExecutionNotFound
	}
	delete(m.executions, id)
	return nil
}

func (m *mockRepo) UpdateStatus(_ context.Context, id string, status execution.ExecutionStatusValue, completedAt *time.Time, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	exec, ok := m.executions[id]
	if !ok {
		return execution.ErrExecutionNotFound
	}
	exec.Status = status
	exec.CompletedAt = completedAt
	exec.Error = errMsg
	exec.UpdatedAt = time.Now()
	return nil
}

func (m *mockRepo) UpdateSteps(_ context.Context, id string, steps []execution.StepStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	exec, ok := m.executions[id]
	if !ok {
		return execution.ErrExecutionNotFound
	}
	exec.Steps = append([]execution.StepStatus{}, steps...)
	exec.UpdatedAt = time.Now()
	return nil
}

func (m *mockRepo) UpdateCost(_ context.Context, id string, estimated, actual *float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	exec, ok := m.executions[id]
	if !ok {
		return execution.ErrExecutionNotFound
	}
	if estimated != nil {
		exec.EstimatedCostUSD = estimated
	}
	if actual != nil {
		exec.ActualCostUSD = actual
	}
	return nil
}

// --- Helper to seed executions ---

func seedExecution(repo *mockRepo, id string, execType execution.ExecutionType, status execution.ExecutionStatusValue, metadata map[string]interface{}) {
	now := time.Now()
	exec := &execution.ExecutionStatus{
		ExecutionID:   id,
		ExecutionType: execType,
		Name:          "test-" + id,
		Status:        status,
		TotalSteps:    3,
		StartedAt:     now,
		Steps:         []execution.StepStatus{},
		Metadata:      metadata,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	repo.mu.Lock()
	repo.executions[id] = exec
	repo.mu.Unlock()
}

func newTestHandler(repo *mockRepo) *UnifiedExecutionHandler {
	return NewUnifiedExecutionHandler(repo, nil, nil, nil, nil)
}

// --- Tests ---

func TestUnifiedHandler_ListExecutions_Empty(t *testing.T) {
	repo := newMockRepo()
	handler := newTestHandler(repo)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions", nil)
	rr := httptest.NewRecorder()

	handler.ListExecutions(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp execution.ListExecutionsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp.Total != 0 {
		t.Errorf("Total = %d, want 0", resp.Total)
	}
}

func TestUnifiedHandler_ListExecutions_WithResults(t *testing.T) {
	repo := newMockRepo()
	seedExecution(repo, "exec-1", execution.ExecutionTypeWCP, execution.StatusRunning, nil)
	seedExecution(repo, "exec-2", execution.ExecutionTypeMAP, execution.StatusCompleted, nil)
	handler := newTestHandler(repo)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions?limit=10", nil)
	rr := httptest.NewRecorder()

	handler.ListExecutions(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp execution.ListExecutionsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d, want 2", resp.Total)
	}
}

func TestUnifiedHandler_ListExecutions_WithFilters(t *testing.T) {
	repo := newMockRepo()
	seedExecution(repo, "exec-1", execution.ExecutionTypeWCP, execution.StatusRunning, nil)
	seedExecution(repo, "exec-2", execution.ExecutionTypeMAP, execution.StatusCompleted, nil)
	handler := newTestHandler(repo)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions?execution_type=wcp_workflow", nil)
	rr := httptest.NewRecorder()

	handler.ListExecutions(rr, req)

	var resp execution.ListExecutionsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("Total = %d, want 1 (WCP only)", resp.Total)
	}
}

func TestUnifiedHandler_GetExecutionStatus_Found(t *testing.T) {
	repo := newMockRepo()
	seedExecution(repo, "exec-1", execution.ExecutionTypeWCP, execution.StatusRunning, nil)
	handler := newTestHandler(repo)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}", handler.GetExecutionStatus)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions/exec-1", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	var exec execution.ExecutionStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &exec); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if exec.ExecutionID != "exec-1" {
		t.Errorf("ExecutionID = %q, want %q", exec.ExecutionID, "exec-1")
	}
}

func TestUnifiedHandler_GetExecutionStatus_NotFound(t *testing.T) {
	repo := newMockRepo()
	handler := newTestHandler(repo)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}", handler.GetExecutionStatus)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions/nonexistent", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestUnifiedHandler_GetExecutionStatus_EmptyID(t *testing.T) {
	repo := newMockRepo()
	handler := newTestHandler(repo)

	// No mux vars — empty ID
	req := httptest.NewRequest("GET", "/api/v1/unified/executions/", nil)
	rr := httptest.NewRecorder()

	handler.GetExecutionStatus(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestUnifiedHandler_CancelExecution_NotFound(t *testing.T) {
	repo := newMockRepo()
	handler := newTestHandler(repo)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}/cancel", handler.CancelExecution)

	body := `{"reason":"testing"}`
	req := httptest.NewRequest("POST", "/api/v1/unified/executions/nonexistent/cancel", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestUnifiedHandler_CancelExecution_AlreadyTerminal(t *testing.T) {
	repo := newMockRepo()
	seedExecution(repo, "exec-1", execution.ExecutionTypeWCP, execution.StatusCompleted, nil)
	handler := newTestHandler(repo)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}/cancel", handler.CancelExecution)

	body := `{"reason":"testing"}`
	req := httptest.NewRequest("POST", "/api/v1/unified/executions/exec-1/cancel", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestUnifiedHandler_CancelExecution_EmptyBody(t *testing.T) {
	repo := newMockRepo()
	seedExecution(repo, "exec-1", execution.ExecutionTypeWCP, execution.StatusRunning,
		map[string]interface{}{"workflow_id": "wf_123"})
	handler := newTestHandler(repo) // No WCP service — will fail with internal error

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}/cancel", handler.CancelExecution)

	req := httptest.NewRequest("POST", "/api/v1/unified/executions/exec-1/cancel", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should not panic; will return 500 because WCP service is nil
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d (WCP service not available)", rr.Code, http.StatusInternalServerError)
	}
}

func TestUnifiedHandler_StreamExecutionStatus_SSEHeaders(t *testing.T) {
	repo := newMockRepo()
	// Seed a completed execution so it returns immediately
	seedExecution(repo, "exec-1", execution.ExecutionTypeWCP, execution.StatusCompleted, nil)
	hub := execution.NewEventHub()
	handler := NewUnifiedExecutionHandler(repo, nil, nil, hub, nil)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}/stream", handler.StreamExecutionStatus)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions/exec-1/stream", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/event-stream")
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want %q", cc, "no-cache")
	}

	// Body should contain the initial SSE event
	body := rr.Body.String()
	if !bytes.Contains([]byte(body), []byte("event: status")) {
		t.Errorf("Body should contain initial SSE event, got: %s", body)
	}
}

func TestUnifiedHandler_StreamExecutionStatus_NotFound(t *testing.T) {
	repo := newMockRepo()
	hub := execution.NewEventHub()
	handler := NewUnifiedExecutionHandler(repo, nil, nil, hub, nil)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}/stream", handler.StreamExecutionStatus)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions/nonexistent/stream", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestUnifiedHandler_StreamExecutionStatus_NoEventHub(t *testing.T) {
	repo := newMockRepo()
	seedExecution(repo, "exec-1", execution.ExecutionTypeWCP, execution.StatusRunning, nil)
	handler := NewUnifiedExecutionHandler(repo, nil, nil, nil, nil) // No event hub

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}/stream", handler.StreamExecutionStatus)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions/exec-1/stream", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestUnifiedHandler_RegisterRoutes(t *testing.T) {
	repo := newMockRepo()
	handler := newTestHandler(repo)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Walk the routes and count
	routeCount := 0
	_ = router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		routeCount++
		return nil
	})

	if routeCount != 4 {
		t.Errorf("Route count = %d, want 4 (list, get, cancel, stream)", routeCount)
	}
}

func TestUnifiedHandler_CORS(t *testing.T) {
	repo := newMockRepo()
	handler := newTestHandler(repo)

	req := httptest.NewRequest("OPTIONS", "/api/v1/unified/executions", nil)
	rr := httptest.NewRecorder()

	handler.ListExecutions(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if methods := rr.Header().Get("Access-Control-Allow-Methods"); methods != "GET, POST, OPTIONS" {
		t.Errorf("Allow-Methods = %q, want %q", methods, "GET, POST, OPTIONS")
	}
}
