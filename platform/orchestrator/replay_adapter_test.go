// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"testing"
	"time"

	"axonflow/platform/orchestrator/replay"
)

func TestNewReplayServiceAdapter(t *testing.T) {
	repo := replay.NewMockRepository()
	service := replay.NewServiceWithLogger(repo, log.New(io.Discard, "", 0))
	adapter := NewReplayServiceAdapter(service)

	if adapter == nil {
		t.Fatal("expected non-nil adapter")
	}
	if adapter.service != service {
		t.Error("expected service to be set")
	}
}

func TestReplayServiceAdapter_StartExecution(t *testing.T) {
	repo := replay.NewMockRepository()
	service := replay.NewServiceWithLogger(repo, log.New(io.Discard, "", 0))
	adapter := NewReplayServiceAdapter(service)

	ctx := context.Background()
	err := adapter.StartExecution(ctx, "req-123", "test-workflow", 3, "org-1", "tenant-1", "user-1")
	if err != nil {
		t.Fatalf("StartExecution failed: %v", err)
	}

	// Verify summary was created
	summary, err := repo.GetSummary(ctx, "req-123")
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}
	if summary.WorkflowName != "test-workflow" {
		t.Errorf("expected workflow name 'test-workflow', got '%s'", summary.WorkflowName)
	}
	if summary.TotalSteps != 3 {
		t.Errorf("expected 3 total steps, got %d", summary.TotalSteps)
	}
}

func TestReplayServiceAdapter_RecordStep(t *testing.T) {
	repo := replay.NewMockRepository()
	service := replay.NewServiceWithLogger(repo, log.New(io.Discard, "", 0))
	adapter := NewReplayServiceAdapter(service)

	ctx := context.Background()
	_ = adapter.StartExecution(ctx, "req-123", "test-workflow", 3, "", "", "")

	// Record a step
	now := time.Now()
	completedAt := now.Add(100 * time.Millisecond)
	duration := 100

	snapshot := &ReplaySnapshotInput{
		RequestID:   "req-123",
		StepIndex:   0,
		StepName:    "step-1",
		Status:      "completed",
		StartedAt:   now,
		CompletedAt: &completedAt,
		DurationMs:  &duration,
		Input:       json.RawMessage(`{"prompt": "test"}`),
		Output:      json.RawMessage(`{"response": "result"}`),
		Provider:    "openai",
		Model:       "gpt-4",
		TokensIn:    100,
		TokensOut:   50,
		CostUSD:     0.005,
		Error:       "",
	}

	err := adapter.RecordStep(ctx, snapshot)
	if err != nil {
		t.Fatalf("RecordStep failed: %v", err)
	}

	// Verify snapshot was saved
	savedSnapshot, err := repo.GetSnapshot(ctx, "req-123", 0)
	if err != nil {
		t.Fatalf("GetSnapshot failed: %v", err)
	}
	if savedSnapshot.StepName != "step-1" {
		t.Errorf("expected step name 'step-1', got '%s'", savedSnapshot.StepName)
	}
	if savedSnapshot.Provider != "openai" {
		t.Errorf("expected provider 'openai', got '%s'", savedSnapshot.Provider)
	}
	if savedSnapshot.TokensIn != 100 {
		t.Errorf("expected tokens_in 100, got %d", savedSnapshot.TokensIn)
	}
}

func TestReplayServiceAdapter_RecordStep_NilSnapshot(t *testing.T) {
	repo := replay.NewMockRepository()
	service := replay.NewServiceWithLogger(repo, log.New(io.Discard, "", 0))
	adapter := NewReplayServiceAdapter(service)

	ctx := context.Background()
	err := adapter.RecordStep(ctx, nil)
	if err != nil {
		t.Errorf("RecordStep with nil should not error, got %v", err)
	}
}

func TestReplayServiceAdapter_CompleteExecution(t *testing.T) {
	repo := replay.NewMockRepository()
	service := replay.NewServiceWithLogger(repo, log.New(io.Discard, "", 0))
	adapter := NewReplayServiceAdapter(service)

	ctx := context.Background()
	_ = adapter.StartExecution(ctx, "req-123", "test-workflow", 1, "", "", "")

	outputSummary := json.RawMessage(`{"result": "success"}`)
	err := adapter.CompleteExecution(ctx, "req-123", outputSummary)
	if err != nil {
		t.Fatalf("CompleteExecution failed: %v", err)
	}

	// Verify status updated
	summary, _ := repo.GetSummary(ctx, "req-123")
	if summary.Status != replay.ExecutionStatusCompleted {
		t.Errorf("expected status 'completed', got '%s'", summary.Status)
	}
	if string(summary.OutputSummary) != `{"result": "success"}` {
		t.Errorf("expected output summary to be set")
	}
}

func TestReplayServiceAdapter_FailExecution(t *testing.T) {
	repo := replay.NewMockRepository()
	service := replay.NewServiceWithLogger(repo, log.New(io.Discard, "", 0))
	adapter := NewReplayServiceAdapter(service)

	ctx := context.Background()
	_ = adapter.StartExecution(ctx, "req-123", "test-workflow", 1, "", "", "")

	err := adapter.FailExecution(ctx, "req-123", "something went wrong")
	if err != nil {
		t.Fatalf("FailExecution failed: %v", err)
	}

	// Verify status updated
	summary, _ := repo.GetSummary(ctx, "req-123")
	if summary.Status != replay.ExecutionStatusFailed {
		t.Errorf("expected status 'failed', got '%s'", summary.Status)
	}
	if summary.ErrorMessage != "something went wrong" {
		t.Errorf("expected error message 'something went wrong', got '%s'", summary.ErrorMessage)
	}
}

func TestReplayServiceAdapter_RecordStep_TypeConversion(t *testing.T) {
	repo := replay.NewMockRepository()
	service := replay.NewServiceWithLogger(repo, log.New(io.Discard, "", 0))
	adapter := NewReplayServiceAdapter(service)

	ctx := context.Background()
	_ = adapter.StartExecution(ctx, "req-123", "test-workflow", 1, "", "", "")

	// Test all field mappings
	now := time.Now()
	completedAt := now.Add(500 * time.Millisecond)
	duration := 500

	snapshot := &ReplaySnapshotInput{
		RequestID:   "req-123",
		StepIndex:   0,
		StepName:    "test-step",
		Status:      "running",
		StartedAt:   now,
		CompletedAt: &completedAt,
		DurationMs:  &duration,
		Input:       json.RawMessage(`{"key": "input_value"}`),
		Output:      json.RawMessage(`{"key": "output_value"}`),
		Provider:    "anthropic",
		Model:       "claude-3-5-sonnet",
		TokensIn:    200,
		TokensOut:   100,
		CostUSD:     0.01,
		Error:       "test error",
	}

	err := adapter.RecordStep(ctx, snapshot)
	if err != nil {
		t.Fatalf("RecordStep failed: %v", err)
	}

	// Verify all fields were converted correctly
	saved, _ := repo.GetSnapshot(ctx, "req-123", 0)

	if saved.RequestID != "req-123" {
		t.Error("RequestID mismatch")
	}
	if saved.StepIndex != 0 {
		t.Error("StepIndex mismatch")
	}
	if saved.StepName != "test-step" {
		t.Error("StepName mismatch")
	}
	if saved.Status != replay.StepStatus("running") {
		t.Errorf("Status mismatch: got %s", saved.Status)
	}
	if !saved.StartedAt.Equal(now) {
		t.Error("StartedAt mismatch")
	}
	if saved.CompletedAt == nil || !saved.CompletedAt.Equal(completedAt) {
		t.Error("CompletedAt mismatch")
	}
	if saved.DurationMs == nil || *saved.DurationMs != 500 {
		t.Error("DurationMs mismatch")
	}
	if string(saved.Input) != `{"key": "input_value"}` {
		t.Error("Input mismatch")
	}
	if string(saved.Output) != `{"key": "output_value"}` {
		t.Error("Output mismatch")
	}
	if saved.Provider != "anthropic" {
		t.Error("Provider mismatch")
	}
	if saved.Model != "claude-3-5-sonnet" {
		t.Error("Model mismatch")
	}
	if saved.TokensIn != 200 {
		t.Error("TokensIn mismatch")
	}
	if saved.TokensOut != 100 {
		t.Error("TokensOut mismatch")
	}
	if saved.CostUSD != 0.01 {
		t.Error("CostUSD mismatch")
	}
	if saved.ErrorMessage != "test error" {
		t.Error("ErrorMessage mismatch")
	}
}

func TestReplayServiceAdapter_ImplementsInterface(t *testing.T) {
	// Verify adapter implements ReplayRecorder interface
	repo := replay.NewMockRepository()
	service := replay.NewServiceWithLogger(repo, log.New(io.Discard, "", 0))
	adapter := NewReplayServiceAdapter(service)

	var _ ReplayRecorder = adapter
}
