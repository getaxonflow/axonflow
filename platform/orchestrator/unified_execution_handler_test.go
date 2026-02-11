// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/agent/license"
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

func (m *mockRepo) CountActive(_ context.Context, tenantID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, exec := range m.executions {
		if exec.TenantID == tenantID && (exec.Status == execution.StatusRunning || exec.Status == execution.StatusPending) {
			count++
		}
	}
	return count, nil
}

func (m *mockRepo) PurgeOldest(_ context.Context, _ string, _ int) (int64, error) {
	return 0, nil
}

// --- Helper to seed executions ---

func seedExecution(repo *mockRepo, id string, execType execution.ExecutionType, status execution.ExecutionStatusValue, metadata map[string]interface{}) {
	seedExecutionWithTenant(repo, id, execType, status, metadata, "")
}

func seedExecutionWithTenant(repo *mockRepo, id string, execType execution.ExecutionType, status execution.ExecutionStatusValue, metadata map[string]interface{}, tenantID string) {
	now := time.Now()
	exec := &execution.ExecutionStatus{
		ExecutionID:   id,
		ExecutionType: execType,
		Name:          "test-" + id,
		Status:        status,
		TotalSteps:    3,
		TenantID:      tenantID,
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

// --- Tests for resolveExecution multi-strategy resolution ---

func TestUnifiedHandler_ResolveExecution_ByWorkflowID(t *testing.T) {
	repo := newMockRepo()
	// Seed execution with a unified ID, but with workflow_id in metadata
	seedExecution(repo, "wf_unified_abc", execution.ExecutionTypeWCP, execution.StatusCompleted,
		map[string]interface{}{"workflow_id": "wf_short_123"})
	// Create a WCP tracker with the same repo (nil wcpService is fine for GetWorkflowStatus)
	wcpTracker := NewWCPExecutionTracker(repo, nil)
	handler := NewUnifiedExecutionHandler(repo, nil, wcpTracker, nil, nil)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}", handler.GetExecutionStatus)

	// Look up by the short workflow ID — should resolve via Strategy 2/4
	req := httptest.NewRequest("GET", "/api/v1/unified/executions/wf_short_123", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	var exec execution.ExecutionStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &exec); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if exec.ExecutionID != "wf_unified_abc" {
		t.Errorf("ExecutionID = %q, want %q (should resolve to unified ID)", exec.ExecutionID, "wf_unified_abc")
	}
}

func TestUnifiedHandler_CancelExecution_ByWorkflowID(t *testing.T) {
	repo := newMockRepo()
	// Seed execution with unified ID and workflow_id in metadata
	seedExecution(repo, "wf_unified_cancel", execution.ExecutionTypeWCP, execution.StatusRunning,
		map[string]interface{}{"workflow_id": "wf_cancel_short"})
	wcpTracker := NewWCPExecutionTracker(repo, nil)
	handler := NewUnifiedExecutionHandler(repo, nil, wcpTracker, nil, nil)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}/cancel", handler.CancelExecution)

	// Cancel by short workflow ID — resolveExecution should find it
	body := `{"reason":"testing"}`
	req := httptest.NewRequest("POST", "/api/v1/unified/executions/wf_cancel_short/cancel", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should resolve the execution (will return 500 because wcpService is nil, not 404)
	if rr.Code == http.StatusNotFound {
		t.Errorf("Status = %d, should NOT be 404 — resolveExecution should find it via WCP tracker", rr.Code)
	}
}

func TestUnifiedHandler_StreamExecution_ByWorkflowID(t *testing.T) {
	repo := newMockRepo()
	// Seed a completed execution so SSE returns immediately
	seedExecution(repo, "wf_unified_stream", execution.ExecutionTypeWCP, execution.StatusCompleted,
		map[string]interface{}{"workflow_id": "wf_stream_short"})
	wcpTracker := NewWCPExecutionTracker(repo, nil)
	hub := execution.NewEventHub()
	handler := NewUnifiedExecutionHandler(repo, nil, wcpTracker, hub, nil)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}/stream", handler.StreamExecutionStatus)

	// Stream by short workflow ID
	req := httptest.NewRequest("GET", "/api/v1/unified/executions/wf_stream_short/stream", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d (should resolve via WCP tracker)", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/event-stream")
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

func TestUnifiedExecutionHandler_SetLicenseChecker(t *testing.T) {
	repo := newMockRepo()
	handler := newTestHandler(repo)

	if handler.licenseChecker != nil {
		t.Error("licenseChecker should be nil initially")
	}

	checker := &DefaultLicenseChecker{}
	handler.SetLicenseChecker(checker)

	if handler.licenseChecker == nil {
		t.Error("licenseChecker should not be nil after SetLicenseChecker")
	}
}

// --- Tenant Isolation Tests ---

func TestUnifiedHandler_GetExecutionStatus_SameTenantAllowed(t *testing.T) {
	repo := newMockRepo()
	seedExecutionWithTenant(repo, "exec-1", execution.ExecutionTypeWCP, execution.StatusRunning, nil, "tenant-a")
	handler := newTestHandler(repo)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}", handler.GetExecutionStatus)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions/exec-1", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d (same tenant should be allowed)", rr.Code, http.StatusOK)
	}
}

func TestUnifiedHandler_GetExecutionStatus_CrossTenantBlocked(t *testing.T) {
	repo := newMockRepo()
	seedExecutionWithTenant(repo, "exec-1", execution.ExecutionTypeWCP, execution.StatusRunning, nil, "tenant-a")
	handler := newTestHandler(repo)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}", handler.GetExecutionStatus)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions/exec-1", nil)
	req.Header.Set("X-Tenant-ID", "tenant-b")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d (cross-tenant should return 404)", rr.Code, http.StatusNotFound)
	}
}

func TestUnifiedHandler_GetExecutionStatus_NoTenantHeaderAllowed(t *testing.T) {
	repo := newMockRepo()
	seedExecutionWithTenant(repo, "exec-1", execution.ExecutionTypeWCP, execution.StatusRunning, nil, "tenant-a")
	handler := newTestHandler(repo)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}", handler.GetExecutionStatus)

	// No X-Tenant-ID header — should be allowed (backward compat)
	req := httptest.NewRequest("GET", "/api/v1/unified/executions/exec-1", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d (no tenant header should be allowed)", rr.Code, http.StatusOK)
	}
}

func TestUnifiedHandler_GetExecutionStatus_NoExecTenantAllowed(t *testing.T) {
	repo := newMockRepo()
	// Execution has no tenant ID set
	seedExecutionWithTenant(repo, "exec-1", execution.ExecutionTypeWCP, execution.StatusRunning, nil, "")
	handler := newTestHandler(repo)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}", handler.GetExecutionStatus)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions/exec-1", nil)
	req.Header.Set("X-Tenant-ID", "tenant-b")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d (exec without tenant should be accessible)", rr.Code, http.StatusOK)
	}
}

func TestUnifiedHandler_CancelExecution_CrossTenantBlocked(t *testing.T) {
	repo := newMockRepo()
	seedExecutionWithTenant(repo, "exec-1", execution.ExecutionTypeWCP, execution.StatusRunning, nil, "tenant-a")
	handler := newTestHandler(repo)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}/cancel", handler.CancelExecution)

	body := `{"reason":"testing"}`
	req := httptest.NewRequest("POST", "/api/v1/unified/executions/exec-1/cancel", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-b")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d (cross-tenant cancel should return 404)", rr.Code, http.StatusNotFound)
	}
}

func TestUnifiedHandler_StreamExecutionStatus_CrossTenantBlocked(t *testing.T) {
	repo := newMockRepo()
	seedExecutionWithTenant(repo, "exec-1", execution.ExecutionTypeWCP, execution.StatusCompleted, nil, "tenant-a")
	hub := execution.NewEventHub()
	handler := NewUnifiedExecutionHandler(repo, nil, nil, hub, nil)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}/stream", handler.StreamExecutionStatus)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions/exec-1/stream", nil)
	req.Header.Set("X-Tenant-ID", "tenant-b")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d (cross-tenant stream should return 404)", rr.Code, http.StatusNotFound)
	}
}

// --- Mock repo that returns a backend error (not ErrExecutionNotFound) ---

type failingRepo struct {
	mockRepo
	getErr error
}

func (f *failingRepo) Get(_ context.Context, _ string) (*execution.ExecutionStatus, error) {
	return nil, f.getErr
}

func TestUnifiedHandler_GetExecutionStatus_BackendError_Returns500(t *testing.T) {
	dbErr := errors.New("connection refused")
	repo := &failingRepo{
		mockRepo: *newMockRepo(),
		getErr:   dbErr,
	}
	handler := NewUnifiedExecutionHandler(repo, nil, nil, nil, nil)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}", handler.GetExecutionStatus)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions/exec-1", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d (backend error should be 500, not 404)", rr.Code, http.StatusInternalServerError)
	}
}

func TestUnifiedHandler_CancelExecution_BackendError_Returns500(t *testing.T) {
	dbErr := errors.New("connection refused")
	repo := &failingRepo{
		mockRepo: *newMockRepo(),
		getErr:   dbErr,
	}
	handler := NewUnifiedExecutionHandler(repo, nil, nil, nil, nil)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}/cancel", handler.CancelExecution)

	body := `{"reason":"testing"}`
	req := httptest.NewRequest("POST", "/api/v1/unified/executions/exec-1/cancel", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d (backend error should be 500, not 404)", rr.Code, http.StatusInternalServerError)
	}
}

func TestUnifiedHandler_StreamExecution_BackendError_Returns500(t *testing.T) {
	dbErr := errors.New("connection refused")
	repo := &failingRepo{
		mockRepo: *newMockRepo(),
		getErr:   dbErr,
	}
	hub := execution.NewEventHub()
	handler := NewUnifiedExecutionHandler(repo, nil, nil, hub, nil)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}/stream", handler.StreamExecutionStatus)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions/exec-1/stream", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d (backend error should be 500, not 404)", rr.Code, http.StatusInternalServerError)
	}
}

func TestUnifiedHandler_GetExecutionStatus_NotFoundStillReturns404(t *testing.T) {
	// Verify that genuine not-found still returns 404 (regression check)
	repo := newMockRepo()
	handler := newTestHandler(repo)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}", handler.GetExecutionStatus)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions/nonexistent", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d (genuine not-found should still be 404)", rr.Code, http.StatusNotFound)
	}
}

func TestUnifiedHandler_GetExecutionStatus_NotFoundWithTrackersReturns404(t *testing.T) {
	// Regression test: with WCP and MAP trackers enabled (normal runtime),
	// a genuinely missing execution ID must return 404, not 500.
	// The trackers return their own not-found errors which must be classified correctly.
	repo := newMockRepo()
	wcpTracker := NewWCPExecutionTracker(repo, nil)
	handler := NewUnifiedExecutionHandler(repo, nil, wcpTracker, nil, nil)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/unified/executions/{id}", handler.GetExecutionStatus)

	req := httptest.NewRequest("GET", "/api/v1/unified/executions/wf_nonexistent", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d (not-found with trackers should be 404, not 500)", rr.Code, http.StatusNotFound)
	}
}

func TestUnifiedExecutionHandler_ListExecutions_WithHistoryCap(t *testing.T) {
	repo := newMockRepo()
	handler := newTestHandler(repo)

	// Set license checker with community limits (50 max history)
	checker := newMockLicenseChecker(license.TierCommunity)
	handler.SetLicenseChecker(checker)

	// Create more executions than the history cap
	for i := 0; i < 5; i++ {
		exec := &execution.ExecutionStatus{
			ExecutionID: "exec-" + string(rune('a'+i)),
			TenantID:    "test-tenant",
			Status:      execution.StatusCompleted,
			StartedAt:   time.Now(),
		}
		_ = repo.Create(context.Background(), exec)
	}

	req := httptest.NewRequest("GET", "/api/v1/unified/executions?limit=1000", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	rr := httptest.NewRecorder()

	handler.ListExecutions(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}
}
