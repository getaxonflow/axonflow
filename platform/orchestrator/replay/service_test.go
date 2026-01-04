// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"testing"
	"time"
)

func TestNewService(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo)

	if service == nil {
		t.Fatal("expected non-nil service")
	}
	if service.repo != repo {
		t.Error("expected repo to be set")
	}
	if service.executions == nil {
		t.Error("expected executions map to be initialized")
	}
}

func TestNewServiceWithLogger(t *testing.T) {
	repo := NewMockRepository()
	logger := log.New(io.Discard, "", 0)

	service := NewServiceWithLogger(repo, logger)
	if service == nil {
		t.Fatal("expected non-nil service")
	}
	if service.logger != logger {
		t.Error("expected custom logger to be set")
	}

	// Test with nil logger (should use default)
	service2 := NewServiceWithLogger(repo, nil)
	if service2.logger == nil {
		t.Error("expected default logger when nil passed")
	}
}

func TestService_StartExecution(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	err := service.StartExecution(ctx, "req-123", "test-workflow", 5, "org-1", "tenant-1", "user-1")
	if err != nil {
		t.Fatalf("StartExecution failed: %v", err)
	}

	// Verify summary was saved
	if repo.GetSummaryCount() != 1 {
		t.Errorf("expected 1 summary, got %d", repo.GetSummaryCount())
	}

	// Verify summary fields
	summary, err := repo.GetSummary(ctx, "req-123")
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}
	if summary.WorkflowName != "test-workflow" {
		t.Errorf("expected workflow name 'test-workflow', got '%s'", summary.WorkflowName)
	}
	if summary.TotalSteps != 5 {
		t.Errorf("expected 5 total steps, got %d", summary.TotalSteps)
	}
	if summary.Status != ExecutionStatusRunning {
		t.Errorf("expected status 'running', got '%s'", summary.Status)
	}
	if summary.OrgID != "org-1" {
		t.Errorf("expected org ID 'org-1', got '%s'", summary.OrgID)
	}

	// Verify in-memory cache
	service.mu.RLock()
	_, cached := service.executions["req-123"]
	service.mu.RUnlock()
	if !cached {
		t.Error("expected execution to be cached in memory")
	}
}

func TestService_StartExecution_Error(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	repo.SaveSummaryErr = errors.New("database error")
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	err := service.StartExecution(ctx, "req-123", "test-workflow", 5, "", "", "")
	if err == nil {
		t.Error("expected error when save fails")
	}
}

func TestService_RecordStep(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Start execution first
	_ = service.StartExecution(ctx, "req-123", "test-workflow", 3, "", "", "")

	// Record a step
	snapshot := &ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 0,
		StepName:  "step-1",
		Status:    StepStatusCompleted,
		StartedAt: time.Now(),
		TokensIn:  100,
		TokensOut: 50,
		CostUSD:   0.001,
	}

	err := service.RecordStep(ctx, snapshot)
	if err != nil {
		t.Fatalf("RecordStep failed: %v", err)
	}

	// Verify snapshot was saved
	if repo.GetSnapshotCount("req-123") != 1 {
		t.Errorf("expected 1 snapshot, got %d", repo.GetSnapshotCount("req-123"))
	}
}

func TestService_RecordStep_NilSnapshot(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	err := service.RecordStep(ctx, nil)
	if err != ErrInvalidInput {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestService_RecordStep_SaveError(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	repo.SaveSnapshotErr = errors.New("database error")
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	snapshot := &ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 0,
		StepName:  "step-1",
		Status:    StepStatusRunning,
	}

	err := service.RecordStep(ctx, snapshot)
	if err == nil {
		t.Error("expected error when save fails")
	}
}

func TestService_RecordStep_UpdatesProgress(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Start execution
	_ = service.StartExecution(ctx, "req-123", "test-workflow", 2, "", "", "")

	// Record first completed step
	snapshot1 := &ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 0,
		StepName:  "step-1",
		Status:    StepStatusCompleted,
		StartedAt: time.Now(),
		TokensIn:  100,
		TokensOut: 50,
		CostUSD:   0.001,
	}
	_ = service.RecordStep(ctx, snapshot1)

	// Wait for async update
	time.Sleep(50 * time.Millisecond)

	// Check progress was updated
	service.mu.RLock()
	summary := service.executions["req-123"]
	service.mu.RUnlock()

	if summary == nil {
		t.Fatal("expected summary to be in cache")
	}
	if summary.CompletedSteps != 1 {
		t.Errorf("expected 1 completed step, got %d", summary.CompletedSteps)
	}
	if summary.TotalTokens != 150 {
		t.Errorf("expected 150 total tokens, got %d", summary.TotalTokens)
	}
}

func TestService_CompleteExecution(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Start execution
	_ = service.StartExecution(ctx, "req-123", "test-workflow", 1, "", "", "")

	// Complete execution
	output := json.RawMessage(`{"result": "success"}`)
	err := service.CompleteExecution(ctx, "req-123", output)
	if err != nil {
		t.Fatalf("CompleteExecution failed: %v", err)
	}

	// Verify status updated
	summary, _ := repo.GetSummary(ctx, "req-123")
	if summary.Status != ExecutionStatusCompleted {
		t.Errorf("expected status 'completed', got '%s'", summary.Status)
	}
	if summary.CompletedAt == nil {
		t.Error("expected completed_at to be set")
	}
	if summary.DurationMs == nil {
		t.Error("expected duration_ms to be set")
	}
	if string(summary.OutputSummary) != `{"result": "success"}` {
		t.Errorf("expected output summary, got %s", string(summary.OutputSummary))
	}

	// Verify removed from cache
	service.mu.RLock()
	_, cached := service.executions["req-123"]
	service.mu.RUnlock()
	if cached {
		t.Error("expected execution to be removed from cache")
	}
}

func TestService_CompleteExecution_NotInCache(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Add summary directly to repo (not in cache)
	summary := &ExecutionSummary{
		RequestID:  "req-123",
		Status:     ExecutionStatusRunning,
		TotalSteps: 1,
		StartedAt:  time.Now(),
	}
	repo.AddSummary(summary)

	// Complete execution
	err := service.CompleteExecution(ctx, "req-123", nil)
	if err != nil {
		t.Fatalf("CompleteExecution failed: %v", err)
	}

	// Verify status updated
	summary, _ = repo.GetSummary(ctx, "req-123")
	if summary.Status != ExecutionStatusCompleted {
		t.Errorf("expected status 'completed', got '%s'", summary.Status)
	}
}

func TestService_CompleteExecution_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	err := service.CompleteExecution(ctx, "nonexistent", nil)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestService_FailExecution(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Start execution
	_ = service.StartExecution(ctx, "req-123", "test-workflow", 1, "", "", "")

	// Fail execution
	err := service.FailExecution(ctx, "req-123", "something went wrong")
	if err != nil {
		t.Fatalf("FailExecution failed: %v", err)
	}

	// Verify status updated
	summary, _ := repo.GetSummary(ctx, "req-123")
	if summary.Status != ExecutionStatusFailed {
		t.Errorf("expected status 'failed', got '%s'", summary.Status)
	}
	if summary.ErrorMessage != "something went wrong" {
		t.Errorf("expected error message, got '%s'", summary.ErrorMessage)
	}

	// Verify removed from cache
	service.mu.RLock()
	_, cached := service.executions["req-123"]
	service.mu.RUnlock()
	if cached {
		t.Error("expected execution to be removed from cache")
	}
}

func TestService_FailExecution_NotInCache(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Add summary directly to repo
	summary := &ExecutionSummary{
		RequestID:  "req-123",
		Status:     ExecutionStatusRunning,
		TotalSteps: 1,
		StartedAt:  time.Now(),
	}
	repo.AddSummary(summary)

	// Fail execution
	err := service.FailExecution(ctx, "req-123", "error")
	if err != nil {
		t.Fatalf("FailExecution failed: %v", err)
	}

	// Verify status
	summary, _ = repo.GetSummary(ctx, "req-123")
	if summary.Status != ExecutionStatusFailed {
		t.Errorf("expected status 'failed', got '%s'", summary.Status)
	}
}

func TestService_FailExecution_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	err := service.FailExecution(ctx, "nonexistent", "error")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestService_GetExecution(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Add test data
	summary := &ExecutionSummary{
		RequestID:  "req-123",
		Status:     ExecutionStatusCompleted,
		TotalSteps: 2,
		StartedAt:  time.Now(),
	}
	repo.AddSummary(summary)
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 0,
		StepName:  "step-1",
		Status:    StepStatusCompleted,
	})
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 1,
		StepName:  "step-2",
		Status:    StepStatusCompleted,
	})

	exec, err := service.GetExecution(ctx, "req-123")
	if err != nil {
		t.Fatalf("GetExecution failed: %v", err)
	}
	if exec.Summary.RequestID != "req-123" {
		t.Error("expected request ID to match")
	}
	if len(exec.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(exec.Steps))
	}
}

func TestService_GetExecution_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	_, err := service.GetExecution(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestService_ListExecutions(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Add test data
	for i := 0; i < 5; i++ {
		repo.AddSummary(&ExecutionSummary{
			RequestID:  string(rune('a'+i)) + "-req",
			Status:     ExecutionStatusCompleted,
			TotalSteps: 1,
			StartedAt:  time.Now(),
		})
	}

	// Test basic list
	summaries, total, err := service.ListExecutions(ctx, ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListExecutions failed: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if len(summaries) != 5 {
		t.Errorf("expected 5 summaries, got %d", len(summaries))
	}

	// Test with limit
	summaries, total, err = service.ListExecutions(ctx, ListOptions{Limit: 2})
	if err != nil {
		t.Fatalf("ListExecutions failed: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if len(summaries) != 2 {
		t.Errorf("expected 2 summaries, got %d", len(summaries))
	}
}

func TestService_ListExecutions_WithFilters(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Add test data
	repo.AddSummary(&ExecutionSummary{
		RequestID:  "req-1",
		Status:     ExecutionStatusCompleted,
		OrgID:      "org-1",
		TotalSteps: 1,
		StartedAt:  time.Now(),
	})
	repo.AddSummary(&ExecutionSummary{
		RequestID:  "req-2",
		Status:     ExecutionStatusFailed,
		OrgID:      "org-1",
		TotalSteps: 1,
		StartedAt:  time.Now(),
	})
	repo.AddSummary(&ExecutionSummary{
		RequestID:  "req-3",
		Status:     ExecutionStatusCompleted,
		OrgID:      "org-2",
		TotalSteps: 1,
		StartedAt:  time.Now(),
	})

	// Filter by status
	summaries, total, _ := service.ListExecutions(ctx, ListOptions{
		Status: "completed",
		Limit:  10,
	})
	if total != 2 {
		t.Errorf("expected 2 completed, got %d", total)
	}

	// Filter by org
	summaries, total, _ = service.ListExecutions(ctx, ListOptions{
		OrgID: "org-1",
		Limit: 10,
	})
	if total != 2 {
		t.Errorf("expected 2 for org-1, got %d", total)
	}
	if len(summaries) != 2 {
		t.Errorf("expected 2 summaries, got %d", len(summaries))
	}
}

func TestService_GetStep(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Add test data
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 0,
		StepName:  "step-1",
		Status:    StepStatusCompleted,
	})

	step, err := service.GetStep(ctx, "req-123", 0)
	if err != nil {
		t.Fatalf("GetStep failed: %v", err)
	}
	if step.StepName != "step-1" {
		t.Errorf("expected step name 'step-1', got '%s'", step.StepName)
	}
}

func TestService_GetStep_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	_, err := service.GetStep(ctx, "req-123", 0)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestService_GetSteps(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

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

	steps, err := service.GetSteps(ctx, "req-123")
	if err != nil {
		t.Fatalf("GetSteps failed: %v", err)
	}
	if len(steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(steps))
	}
}

func TestService_ExportExecution(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Add test data
	now := time.Now()
	repo.AddSummary(&ExecutionSummary{
		RequestID:     "req-123",
		Status:        ExecutionStatusCompleted,
		TotalSteps:    1,
		StartedAt:     now,
		InputSummary:  json.RawMessage(`{"prompt": "test"}`),
		OutputSummary: json.RawMessage(`{"response": "result"}`),
	})
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID:        "req-123",
		StepIndex:        0,
		StepName:         "step-1",
		Status:           StepStatusCompleted,
		StartedAt:        now,
		Input:            json.RawMessage(`{"data": "input"}`),
		Output:           json.RawMessage(`{"data": "output"}`),
		PoliciesChecked:  []string{"policy-1"},
		PoliciesTriggered: []PolicyEvent{{PolicyID: "p1", Action: "warn"}},
	})

	// Export with all options enabled
	data, err := service.ExportExecution(ctx, "req-123", ExportOptions{
		Format:          ExportFormatJSON,
		IncludeInput:    true,
		IncludeOutput:   true,
		IncludePolicies: true,
	})
	if err != nil {
		t.Fatalf("ExportExecution failed: %v", err)
	}

	// Verify export contains data
	var export struct {
		ExportedAt time.Time  `json:"exported_at"`
		Format     string     `json:"format"`
		Execution  *Execution `json:"execution"`
	}
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatalf("failed to unmarshal export: %v", err)
	}
	if export.Execution == nil {
		t.Fatal("expected execution in export")
	}
	if export.Execution.Steps[0].Input == nil {
		t.Error("expected input to be included")
	}
	if export.Execution.Steps[0].Output == nil {
		t.Error("expected output to be included")
	}
	if export.Execution.Steps[0].PoliciesChecked == nil {
		t.Error("expected policies to be included")
	}
}

func TestService_ExportExecution_Redacted(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

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
		RequestID:        "req-123",
		StepIndex:        0,
		StepName:         "step-1",
		Status:           StepStatusCompleted,
		StartedAt:        time.Now(),
		Input:            json.RawMessage(`{"data": "input"}`),
		Output:           json.RawMessage(`{"data": "output"}`),
		PoliciesChecked:  []string{"policy-1"},
		PoliciesTriggered: []PolicyEvent{{PolicyID: "p1"}},
	})

	// Export with options disabled
	data, err := service.ExportExecution(ctx, "req-123", ExportOptions{
		Format:          ExportFormatJSON,
		IncludeInput:    false,
		IncludeOutput:   false,
		IncludePolicies: false,
	})
	if err != nil {
		t.Fatalf("ExportExecution failed: %v", err)
	}

	var export struct {
		Execution *Execution `json:"execution"`
	}
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatalf("failed to unmarshal export: %v", err)
	}

	// Verify redaction
	if export.Execution.Summary.InputSummary != nil {
		t.Error("expected input summary to be redacted")
	}
	if export.Execution.Summary.OutputSummary != nil {
		t.Error("expected output summary to be redacted")
	}
	if export.Execution.Steps[0].Input != nil {
		t.Error("expected step input to be redacted")
	}
	if export.Execution.Steps[0].Output != nil {
		t.Error("expected step output to be redacted")
	}
	if export.Execution.Steps[0].PoliciesChecked != nil {
		t.Error("expected policies checked to be redacted")
	}
	if export.Execution.Steps[0].PoliciesTriggered != nil {
		t.Error("expected policies triggered to be redacted")
	}
}

func TestService_ExportExecution_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	_, err := service.ExportExecution(ctx, "nonexistent", ExportOptions{})
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestService_GetTimeline(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

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
		ErrorMessage: "error occurred",
	})
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 2,
		StepName:  "step-3",
		Status:    StepStatusPaused,
		StartedAt: completedAt,
	})

	timeline, err := service.GetTimeline(ctx, "req-123")
	if err != nil {
		t.Fatalf("GetTimeline failed: %v", err)
	}
	if len(timeline) != 3 {
		t.Fatalf("expected 3 timeline entries, got %d", len(timeline))
	}

	// Verify first entry
	if timeline[0].StepName != "step-1" {
		t.Errorf("expected step-1, got %s", timeline[0].StepName)
	}
	if timeline[0].HasError {
		t.Error("expected step-1 to not have error")
	}
	if timeline[0].HasApproval {
		t.Error("expected step-1 to not have approval")
	}

	// Verify second entry (failed)
	if !timeline[1].HasError {
		t.Error("expected step-2 to have error")
	}

	// Verify third entry (paused/approval)
	if !timeline[2].HasApproval {
		t.Error("expected step-3 to have approval")
	}
}

func TestService_GetTimeline_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	repo.GetSnapshotsErr = ErrNotFound
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	_, err := service.GetTimeline(ctx, "req-123")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestService_DeleteExecution(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Start execution (adds to cache)
	_ = service.StartExecution(ctx, "req-123", "test-workflow", 1, "", "", "")

	// Verify in cache
	service.mu.RLock()
	_, cached := service.executions["req-123"]
	service.mu.RUnlock()
	if !cached {
		t.Error("expected execution to be in cache")
	}

	// Delete execution
	err := service.DeleteExecution(ctx, "req-123")
	if err != nil {
		t.Fatalf("DeleteExecution failed: %v", err)
	}

	// Verify removed from cache
	service.mu.RLock()
	_, cached = service.executions["req-123"]
	service.mu.RUnlock()
	if cached {
		t.Error("expected execution to be removed from cache")
	}
}

func TestService_IsHealthy(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Should be healthy by default
	if !service.IsHealthy(ctx) {
		t.Error("expected service to be healthy")
	}

	// Simulate unhealthy
	repo.PingErr = errors.New("db unavailable")
	if service.IsHealthy(ctx) {
		t.Error("expected service to be unhealthy")
	}
}

func TestService_GetExecutionCount(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Add test data
	repo.AddSummary(&ExecutionSummary{RequestID: "req-1", Status: ExecutionStatusCompleted})
	repo.AddSummary(&ExecutionSummary{RequestID: "req-2", Status: ExecutionStatusCompleted})
	repo.AddSummary(&ExecutionSummary{RequestID: "req-3", Status: ExecutionStatusFailed})

	// Get count of all
	count, err := service.GetExecutionCount(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("GetExecutionCount failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}

	// Get count by status
	count, err = service.GetExecutionCount(ctx, ListOptions{Status: "completed"})
	if err != nil {
		t.Fatalf("GetExecutionCount failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
}

func TestService_UpdateExecutionProgress_NotCached(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))

	// Add summary to repo but not cache
	summary := &ExecutionSummary{
		RequestID:  "req-123",
		Status:     ExecutionStatusRunning,
		TotalSteps: 2,
		StartedAt:  time.Now(),
	}
	repo.AddSummary(summary)

	// Record completed step (should load from repo and update)
	snapshot := &ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 0,
		StepName:  "step-1",
		Status:    StepStatusCompleted,
		StartedAt: time.Now(),
		TokensIn:  100,
		TokensOut: 50,
	}
	err := service.RecordStep(ctx, snapshot)
	if err != nil {
		t.Fatalf("RecordStep failed: %v", err)
	}

	// Wait for async update
	time.Sleep(50 * time.Millisecond)

	// Verify summary was loaded into cache
	service.mu.RLock()
	cached, exists := service.executions["req-123"]
	service.mu.RUnlock()

	if !exists {
		t.Error("expected summary to be cached after progress update")
	}
	if cached != nil && cached.CompletedSteps != 1 {
		t.Errorf("expected 1 completed step, got %d", cached.CompletedSteps)
	}
}
