// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestNoOpRepository_Implements_Interface(t *testing.T) {
	var _ Repository = (*NoOpRepository)(nil)
}

func TestNoOpRepository_SaveSnapshot(t *testing.T) {
	repo := &NoOpRepository{}
	ctx := context.Background()

	err := repo.SaveSnapshot(ctx, &ExecutionSnapshot{})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestNoOpRepository_UpdateSnapshot(t *testing.T) {
	repo := &NoOpRepository{}
	ctx := context.Background()

	err := repo.UpdateSnapshot(ctx, &ExecutionSnapshot{})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestNoOpRepository_GetSnapshot(t *testing.T) {
	repo := &NoOpRepository{}
	ctx := context.Background()

	snapshot, err := repo.GetSnapshot(ctx, "req-123", 0)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
	if snapshot != nil {
		t.Error("expected nil snapshot")
	}
}

func TestNoOpRepository_GetSnapshots(t *testing.T) {
	repo := &NoOpRepository{}
	ctx := context.Background()

	snapshots, err := repo.GetSnapshots(ctx, "req-123")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(snapshots) != 0 {
		t.Errorf("expected empty slice, got %d items", len(snapshots))
	}
}

func TestNoOpRepository_DeleteSnapshots(t *testing.T) {
	repo := &NoOpRepository{}
	ctx := context.Background()

	err := repo.DeleteSnapshots(ctx, "req-123")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestNoOpRepository_SaveSummary(t *testing.T) {
	repo := &NoOpRepository{}
	ctx := context.Background()

	err := repo.SaveSummary(ctx, &ExecutionSummary{})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestNoOpRepository_UpdateSummary(t *testing.T) {
	repo := &NoOpRepository{}
	ctx := context.Background()

	err := repo.UpdateSummary(ctx, &ExecutionSummary{})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestNoOpRepository_GetSummary(t *testing.T) {
	repo := &NoOpRepository{}
	ctx := context.Background()

	summary, err := repo.GetSummary(ctx, "req-123")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
	if summary != nil {
		t.Error("expected nil summary")
	}
}

func TestNoOpRepository_ListSummaries(t *testing.T) {
	repo := &NoOpRepository{}
	ctx := context.Background()

	summaries, total, err := repo.ListSummaries(ctx, ListOptions{})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected empty slice, got %d items", len(summaries))
	}
	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
}

func TestNoOpRepository_DeleteSummary(t *testing.T) {
	repo := &NoOpRepository{}
	ctx := context.Background()

	err := repo.DeleteSummary(ctx, "req-123")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestNoOpRepository_GetExecution(t *testing.T) {
	repo := &NoOpRepository{}
	ctx := context.Background()

	exec, err := repo.GetExecution(ctx, "req-123")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
	if exec != nil {
		t.Error("expected nil execution")
	}
}

func TestNoOpRepository_DeleteExecution(t *testing.T) {
	repo := &NoOpRepository{}
	ctx := context.Background()

	err := repo.DeleteExecution(ctx, "req-123")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestNoOpRepository_Ping(t *testing.T) {
	repo := &NoOpRepository{}
	ctx := context.Background()

	err := repo.Ping(ctx)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// MockRepository tests

func TestMockRepository_Implements_Interface(t *testing.T) {
	var _ Repository = (*MockRepository)(nil)
}

func TestMockRepository_NewMockRepository(t *testing.T) {
	repo := NewMockRepository()

	if repo == nil {
		t.Fatal("expected non-nil repo")
	}
	if repo.snapshots == nil {
		t.Error("expected snapshots map to be initialized")
	}
	if repo.summaries == nil {
		t.Error("expected summaries map to be initialized")
	}
}

func TestMockRepository_SaveAndGetSnapshot(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	snapshot := &ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 0,
		StepName:  "step-1",
		Status:    StepStatusCompleted,
		StartedAt: time.Now(),
		Input:     json.RawMessage(`{"test": true}`),
	}

	// Save
	err := repo.SaveSnapshot(ctx, snapshot)
	if err != nil {
		t.Fatalf("SaveSnapshot failed: %v", err)
	}

	// Get
	retrieved, err := repo.GetSnapshot(ctx, "req-123", 0)
	if err != nil {
		t.Fatalf("GetSnapshot failed: %v", err)
	}

	if retrieved.StepName != "step-1" {
		t.Error("step name mismatch")
	}
}

func TestMockRepository_GetSnapshot_NotFound(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	_, err := repo.GetSnapshot(ctx, "nonexistent", 0)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMockRepository_UpdateSnapshot(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Save initial
	snapshot := &ExecutionSnapshot{
		RequestID: "req-123",
		StepIndex: 0,
		StepName:  "step-1",
		Status:    StepStatusRunning,
	}
	_ = repo.SaveSnapshot(ctx, snapshot)

	// Update
	snapshot.Status = StepStatusCompleted
	err := repo.UpdateSnapshot(ctx, snapshot)
	if err != nil {
		t.Fatalf("UpdateSnapshot failed: %v", err)
	}

	// Verify
	retrieved, _ := repo.GetSnapshot(ctx, "req-123", 0)
	if retrieved.Status != StepStatusCompleted {
		t.Error("expected status to be updated")
	}
}

func TestMockRepository_GetSnapshots(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Add multiple snapshots
	for i := 0; i < 3; i++ {
		repo.AddSnapshot(&ExecutionSnapshot{
			RequestID: "req-123",
			StepIndex: i,
			StepName:  string(rune('a' + i)),
		})
	}

	snapshots, err := repo.GetSnapshots(ctx, "req-123")
	if err != nil {
		t.Fatalf("GetSnapshots failed: %v", err)
	}
	if len(snapshots) != 3 {
		t.Errorf("expected 3 snapshots, got %d", len(snapshots))
	}
}

func TestMockRepository_DeleteSnapshots(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Add snapshots
	repo.AddSnapshot(&ExecutionSnapshot{RequestID: "req-123", StepIndex: 0})
	repo.AddSnapshot(&ExecutionSnapshot{RequestID: "req-123", StepIndex: 1})

	// Delete
	err := repo.DeleteSnapshots(ctx, "req-123")
	if err != nil {
		t.Fatalf("DeleteSnapshots failed: %v", err)
	}

	// Verify
	snapshots, _ := repo.GetSnapshots(ctx, "req-123")
	if len(snapshots) != 0 {
		t.Error("expected snapshots to be deleted")
	}
}

func TestMockRepository_SaveAndGetSummary(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	summary := &ExecutionSummary{
		RequestID:    "req-123",
		WorkflowName: "test-workflow",
		Status:       ExecutionStatusRunning,
		TotalSteps:   5,
		StartedAt:    time.Now(),
	}

	// Save
	err := repo.SaveSummary(ctx, summary)
	if err != nil {
		t.Fatalf("SaveSummary failed: %v", err)
	}

	// Get
	retrieved, err := repo.GetSummary(ctx, "req-123")
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}

	if retrieved.WorkflowName != "test-workflow" {
		t.Error("workflow name mismatch")
	}
}

func TestMockRepository_GetSummary_NotFound(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	_, err := repo.GetSummary(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMockRepository_UpdateSummary(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Save initial
	summary := &ExecutionSummary{
		RequestID: "req-123",
		Status:    ExecutionStatusRunning,
	}
	_ = repo.SaveSummary(ctx, summary)

	// Update
	summary.Status = ExecutionStatusCompleted
	err := repo.UpdateSummary(ctx, summary)
	if err != nil {
		t.Fatalf("UpdateSummary failed: %v", err)
	}

	// Verify
	retrieved, _ := repo.GetSummary(ctx, "req-123")
	if retrieved.Status != ExecutionStatusCompleted {
		t.Error("expected status to be updated")
	}
}

func TestMockRepository_ListSummaries(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Add summaries
	for i := 0; i < 5; i++ {
		repo.AddSummary(&ExecutionSummary{
			RequestID: string(rune('a'+i)) + "-req",
			Status:    ExecutionStatusCompleted,
		})
	}

	summaries, total, err := repo.ListSummaries(ctx, ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListSummaries failed: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if len(summaries) != 5 {
		t.Errorf("expected 5 summaries, got %d", len(summaries))
	}
}

func TestMockRepository_ListSummaries_WithFilters(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Add summaries with different statuses
	repo.AddSummary(&ExecutionSummary{RequestID: "req-1", Status: ExecutionStatusCompleted, OrgID: "org-1"})
	repo.AddSummary(&ExecutionSummary{RequestID: "req-2", Status: ExecutionStatusFailed, OrgID: "org-1"})
	repo.AddSummary(&ExecutionSummary{RequestID: "req-3", Status: ExecutionStatusCompleted, OrgID: "org-2"})

	// Filter by status
	summaries, total, _ := repo.ListSummaries(ctx, ListOptions{Status: "completed", Limit: 10})
	if total != 2 {
		t.Errorf("expected 2 completed, got %d", total)
	}

	// Filter by org
	summaries, total, _ = repo.ListSummaries(ctx, ListOptions{OrgID: "org-1", Limit: 10})
	if total != 2 {
		t.Errorf("expected 2 for org-1, got %d", total)
	}
	if len(summaries) != 2 {
		t.Errorf("expected 2 summaries, got %d", len(summaries))
	}
}

func TestMockRepository_ListSummaries_Pagination(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Add summaries
	for i := 0; i < 10; i++ {
		repo.AddSummary(&ExecutionSummary{
			RequestID: string(rune('a'+i)) + "-req",
			Status:    ExecutionStatusCompleted,
		})
	}

	// Test offset
	summaries, total, _ := repo.ListSummaries(ctx, ListOptions{Limit: 3, Offset: 5})
	if total != 10 {
		t.Errorf("expected total 10, got %d", total)
	}
	if len(summaries) != 3 {
		t.Errorf("expected 3 summaries (offset 5, limit 3), got %d", len(summaries))
	}

	// Test offset beyond range
	summaries, total, _ = repo.ListSummaries(ctx, ListOptions{Limit: 10, Offset: 15})
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries (offset 15), got %d", len(summaries))
	}
}

func TestMockRepository_DeleteSummary(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Add summary
	repo.AddSummary(&ExecutionSummary{RequestID: "req-123"})

	// Delete
	err := repo.DeleteSummary(ctx, "req-123")
	if err != nil {
		t.Fatalf("DeleteSummary failed: %v", err)
	}

	// Verify
	if repo.GetSummaryCount() != 0 {
		t.Error("expected summary to be deleted")
	}
}

func TestMockRepository_GetExecution(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Add summary and snapshots
	repo.AddSummary(&ExecutionSummary{
		RequestID:  "req-123",
		Status:     ExecutionStatusCompleted,
		TotalSteps: 2,
	})
	repo.AddSnapshot(&ExecutionSnapshot{RequestID: "req-123", StepIndex: 0})
	repo.AddSnapshot(&ExecutionSnapshot{RequestID: "req-123", StepIndex: 1})

	exec, err := repo.GetExecution(ctx, "req-123")
	if err != nil {
		t.Fatalf("GetExecution failed: %v", err)
	}

	if exec.Summary.RequestID != "req-123" {
		t.Error("summary request ID mismatch")
	}
	if len(exec.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(exec.Steps))
	}
}

func TestMockRepository_GetExecution_NotFound(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	_, err := repo.GetExecution(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMockRepository_DeleteExecution(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Add summary and snapshots
	repo.AddSummary(&ExecutionSummary{RequestID: "req-123"})
	repo.AddSnapshot(&ExecutionSnapshot{RequestID: "req-123", StepIndex: 0})

	// Delete
	err := repo.DeleteExecution(ctx, "req-123")
	if err != nil {
		t.Fatalf("DeleteExecution failed: %v", err)
	}

	// Verify both deleted
	if repo.GetSummaryCount() != 0 {
		t.Error("expected summary to be deleted")
	}
	if repo.GetSnapshotCount("req-123") != 0 {
		t.Error("expected snapshots to be deleted")
	}
}

func TestMockRepository_Ping(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Default: healthy
	err := repo.Ping(ctx)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Inject error
	repo.PingErr = ErrInvalidInput
	err = repo.Ping(ctx)
	if err != ErrInvalidInput {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestMockRepository_ErrorInjection(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Test all error injection fields
	repo.SaveSnapshotErr = ErrInvalidInput
	if err := repo.SaveSnapshot(ctx, &ExecutionSnapshot{}); err != ErrInvalidInput {
		t.Error("expected SaveSnapshotErr to be returned")
	}

	repo.UpdateSnapshotErr = ErrInvalidInput
	if err := repo.UpdateSnapshot(ctx, &ExecutionSnapshot{}); err != ErrInvalidInput {
		t.Error("expected UpdateSnapshotErr to be returned")
	}

	repo.GetSnapshotErr = ErrInvalidInput
	if _, err := repo.GetSnapshot(ctx, "req", 0); err != ErrInvalidInput {
		t.Error("expected GetSnapshotErr to be returned")
	}

	repo.GetSnapshotsErr = ErrInvalidInput
	if _, err := repo.GetSnapshots(ctx, "req"); err != ErrInvalidInput {
		t.Error("expected GetSnapshotsErr to be returned")
	}

	repo.SaveSummaryErr = ErrInvalidInput
	if err := repo.SaveSummary(ctx, &ExecutionSummary{}); err != ErrInvalidInput {
		t.Error("expected SaveSummaryErr to be returned")
	}

	repo.UpdateSummaryErr = ErrInvalidInput
	if err := repo.UpdateSummary(ctx, &ExecutionSummary{}); err != ErrInvalidInput {
		t.Error("expected UpdateSummaryErr to be returned")
	}

	repo.GetSummaryErr = ErrInvalidInput
	if _, err := repo.GetSummary(ctx, "req"); err != ErrInvalidInput {
		t.Error("expected GetSummaryErr to be returned")
	}

	repo.ListSummariesErr = ErrInvalidInput
	if _, _, err := repo.ListSummaries(ctx, ListOptions{}); err != ErrInvalidInput {
		t.Error("expected ListSummariesErr to be returned")
	}

	repo.GetExecutionErr = ErrInvalidInput
	if _, err := repo.GetExecution(ctx, "req"); err != ErrInvalidInput {
		t.Error("expected GetExecutionErr to be returned")
	}

	repo.DeleteErr = ErrInvalidInput
	if err := repo.DeleteSnapshots(ctx, "req"); err != ErrInvalidInput {
		t.Error("expected DeleteErr to be returned")
	}
	if err := repo.DeleteSummary(ctx, "req"); err != ErrInvalidInput {
		t.Error("expected DeleteErr to be returned")
	}
	if err := repo.DeleteExecution(ctx, "req"); err != ErrInvalidInput {
		t.Error("expected DeleteErr to be returned")
	}
}

func TestMockRepository_HelperMethods(t *testing.T) {
	repo := NewMockRepository()

	// Test AddSnapshot
	repo.AddSnapshot(&ExecutionSnapshot{RequestID: "req-1", StepIndex: 0})
	repo.AddSnapshot(&ExecutionSnapshot{RequestID: "req-1", StepIndex: 1})
	repo.AddSnapshot(&ExecutionSnapshot{RequestID: "req-2", StepIndex: 0})

	if repo.GetSnapshotCount("req-1") != 2 {
		t.Error("expected 2 snapshots for req-1")
	}
	if repo.GetSnapshotCount("req-2") != 1 {
		t.Error("expected 1 snapshot for req-2")
	}

	// Test AddSummary
	repo.AddSummary(&ExecutionSummary{RequestID: "req-1"})
	repo.AddSummary(&ExecutionSummary{RequestID: "req-2"})
	repo.AddSummary(&ExecutionSummary{RequestID: "req-3"})

	if repo.GetSummaryCount() != 3 {
		t.Errorf("expected 3 summaries, got %d", repo.GetSummaryCount())
	}
}
