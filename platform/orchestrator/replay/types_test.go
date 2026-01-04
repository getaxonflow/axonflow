// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewExecutionSnapshot(t *testing.T) {
	snapshot := NewExecutionSnapshot("req-123", "step-1", 0)

	if snapshot == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snapshot.RequestID != "req-123" {
		t.Errorf("expected request ID 'req-123', got '%s'", snapshot.RequestID)
	}
	if snapshot.StepName != "step-1" {
		t.Errorf("expected step name 'step-1', got '%s'", snapshot.StepName)
	}
	if snapshot.StepIndex != 0 {
		t.Errorf("expected step index 0, got %d", snapshot.StepIndex)
	}
	if snapshot.Status != StepStatusPending {
		t.Errorf("expected status 'pending', got '%s'", snapshot.Status)
	}
	if snapshot.StartedAt.IsZero() {
		t.Error("expected started_at to be set")
	}
	if snapshot.PoliciesChecked == nil {
		t.Error("expected policies_checked to be initialized")
	}
	if snapshot.PoliciesTriggered == nil {
		t.Error("expected policies_triggered to be initialized")
	}
}

func TestNewExecutionSummary(t *testing.T) {
	summary := NewExecutionSummary("req-123", 5)

	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if summary.RequestID != "req-123" {
		t.Errorf("expected request ID 'req-123', got '%s'", summary.RequestID)
	}
	if summary.TotalSteps != 5 {
		t.Errorf("expected total steps 5, got %d", summary.TotalSteps)
	}
	if summary.Status != ExecutionStatusPending {
		t.Errorf("expected status 'pending', got '%s'", summary.Status)
	}
	if summary.StartedAt.IsZero() {
		t.Error("expected started_at to be set")
	}
}

func TestExecutionSnapshot_MarkCompleted(t *testing.T) {
	snapshot := NewExecutionSnapshot("req-123", "step-1", 0)
	time.Sleep(10 * time.Millisecond) // Ensure duration > 0

	output := json.RawMessage(`{"result": "success"}`)
	snapshot.MarkCompleted(output)

	if snapshot.Status != StepStatusCompleted {
		t.Errorf("expected status 'completed', got '%s'", snapshot.Status)
	}
	if snapshot.CompletedAt == nil {
		t.Error("expected completed_at to be set")
	}
	if snapshot.DurationMs == nil || *snapshot.DurationMs <= 0 {
		t.Error("expected duration_ms to be positive")
	}
	if string(snapshot.Output) != `{"result": "success"}` {
		t.Errorf("expected output to be set, got '%s'", string(snapshot.Output))
	}
}

func TestExecutionSnapshot_MarkFailed(t *testing.T) {
	snapshot := NewExecutionSnapshot("req-123", "step-1", 0)
	time.Sleep(10 * time.Millisecond)

	snapshot.MarkFailed("something went wrong")

	if snapshot.Status != StepStatusFailed {
		t.Errorf("expected status 'failed', got '%s'", snapshot.Status)
	}
	if snapshot.CompletedAt == nil {
		t.Error("expected completed_at to be set")
	}
	if snapshot.DurationMs == nil || *snapshot.DurationMs <= 0 {
		t.Error("expected duration_ms to be positive")
	}
	if snapshot.ErrorMessage != "something went wrong" {
		t.Errorf("expected error message, got '%s'", snapshot.ErrorMessage)
	}
}

func TestExecutionSnapshot_MarkRunning(t *testing.T) {
	snapshot := NewExecutionSnapshot("req-123", "step-1", 0)
	originalStartedAt := snapshot.StartedAt

	time.Sleep(10 * time.Millisecond)
	snapshot.MarkRunning()

	if snapshot.Status != StepStatusRunning {
		t.Errorf("expected status 'running', got '%s'", snapshot.Status)
	}
	if !snapshot.StartedAt.After(originalStartedAt) {
		t.Error("expected started_at to be updated")
	}
}

func TestExecutionSnapshot_SetLLMDetails(t *testing.T) {
	snapshot := NewExecutionSnapshot("req-123", "step-1", 0)

	snapshot.SetLLMDetails("anthropic", "claude-3-5-sonnet", 100, 50, 0.001)

	if snapshot.Provider != "anthropic" {
		t.Errorf("expected provider 'anthropic', got '%s'", snapshot.Provider)
	}
	if snapshot.Model != "claude-3-5-sonnet" {
		t.Errorf("expected model 'claude-3-5-sonnet', got '%s'", snapshot.Model)
	}
	if snapshot.TokensIn != 100 {
		t.Errorf("expected tokens_in 100, got %d", snapshot.TokensIn)
	}
	if snapshot.TokensOut != 50 {
		t.Errorf("expected tokens_out 50, got %d", snapshot.TokensOut)
	}
	if snapshot.CostUSD != 0.001 {
		t.Errorf("expected cost_usd 0.001, got %f", snapshot.CostUSD)
	}
}

func TestExecutionSnapshot_AddPolicyEvent(t *testing.T) {
	snapshot := NewExecutionSnapshot("req-123", "step-1", 0)

	event := PolicyEvent{
		PolicyID:   "pol-1",
		PolicyName: "PII Detection",
		Action:     "block",
		Matched:    "email address",
		Resolution: "blocked",
	}
	snapshot.AddPolicyEvent(event)

	if len(snapshot.PoliciesTriggered) != 1 {
		t.Fatalf("expected 1 policy event, got %d", len(snapshot.PoliciesTriggered))
	}
	if snapshot.PoliciesTriggered[0].PolicyID != "pol-1" {
		t.Error("expected policy ID to match")
	}

	// Add another event
	snapshot.AddPolicyEvent(PolicyEvent{PolicyID: "pol-2"})
	if len(snapshot.PoliciesTriggered) != 2 {
		t.Errorf("expected 2 policy events, got %d", len(snapshot.PoliciesTriggered))
	}
}

func TestExecutionSnapshot_AddPolicyChecked(t *testing.T) {
	snapshot := NewExecutionSnapshot("req-123", "step-1", 0)

	snapshot.AddPolicyChecked("pol-1")
	snapshot.AddPolicyChecked("pol-2")
	snapshot.AddPolicyChecked("pol-3")

	if len(snapshot.PoliciesChecked) != 3 {
		t.Errorf("expected 3 policies checked, got %d", len(snapshot.PoliciesChecked))
	}
	if snapshot.PoliciesChecked[0] != "pol-1" {
		t.Error("expected first policy to be 'pol-1'")
	}
}

func TestStepStatusConstants(t *testing.T) {
	// Verify status values
	statuses := map[StepStatus]string{
		StepStatusPending:   "pending",
		StepStatusRunning:   "running",
		StepStatusCompleted: "completed",
		StepStatusFailed:    "failed",
		StepStatusPaused:    "paused",
	}

	for status, expected := range statuses {
		if string(status) != expected {
			t.Errorf("expected status '%s', got '%s'", expected, string(status))
		}
	}
}

func TestExecutionStatusConstants(t *testing.T) {
	// Verify status values
	statuses := map[ExecutionStatus]string{
		ExecutionStatusPending:   "pending",
		ExecutionStatusRunning:   "running",
		ExecutionStatusCompleted: "completed",
		ExecutionStatusFailed:    "failed",
	}

	for status, expected := range statuses {
		if string(status) != expected {
			t.Errorf("expected status '%s', got '%s'", expected, string(status))
		}
	}
}

func TestExportFormatConstants(t *testing.T) {
	if string(ExportFormatJSON) != "json" {
		t.Errorf("expected format 'json', got '%s'", string(ExportFormatJSON))
	}
}

func TestExecutionSnapshot_JSONSerialization(t *testing.T) {
	now := time.Now().UTC()
	completedAt := now.Add(100 * time.Millisecond)
	duration := 100

	snapshot := &ExecutionSnapshot{
		ID:          1,
		RequestID:   "req-123",
		StepIndex:   0,
		StepName:    "test-step",
		Status:      StepStatusCompleted,
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
		PoliciesChecked:   []string{"pol-1"},
		PoliciesTriggered: []PolicyEvent{{PolicyID: "pol-1", Action: "warn"}},
	}

	// Serialize
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("failed to marshal snapshot: %v", err)
	}

	// Deserialize
	var decoded ExecutionSnapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal snapshot: %v", err)
	}

	// Verify fields
	if decoded.RequestID != snapshot.RequestID {
		t.Error("request ID mismatch")
	}
	if decoded.StepName != snapshot.StepName {
		t.Error("step name mismatch")
	}
	if decoded.Status != snapshot.Status {
		t.Error("status mismatch")
	}
	if decoded.Provider != snapshot.Provider {
		t.Error("provider mismatch")
	}
	if decoded.TokensIn != snapshot.TokensIn {
		t.Error("tokens_in mismatch")
	}
}

func TestExecutionSummary_JSONSerialization(t *testing.T) {
	now := time.Now().UTC()
	completedAt := now.Add(5 * time.Second)
	duration := 5000

	summary := &ExecutionSummary{
		RequestID:      "req-123",
		WorkflowName:   "test-workflow",
		Status:         ExecutionStatusCompleted,
		TotalSteps:     3,
		CompletedSteps: 3,
		StartedAt:      now,
		CompletedAt:    &completedAt,
		DurationMs:     &duration,
		TotalTokens:    500,
		TotalCostUSD:   0.025,
		OrgID:          "org-1",
		TenantID:       "tenant-1",
		UserID:         "user-1",
		InputSummary:   json.RawMessage(`{"prompt": "test"}`),
		OutputSummary:  json.RawMessage(`{"response": "done"}`),
	}

	// Serialize
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("failed to marshal summary: %v", err)
	}

	// Deserialize
	var decoded ExecutionSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal summary: %v", err)
	}

	// Verify fields
	if decoded.RequestID != summary.RequestID {
		t.Error("request ID mismatch")
	}
	if decoded.WorkflowName != summary.WorkflowName {
		t.Error("workflow name mismatch")
	}
	if decoded.Status != summary.Status {
		t.Error("status mismatch")
	}
	if decoded.TotalTokens != summary.TotalTokens {
		t.Error("total tokens mismatch")
	}
	if decoded.OrgID != summary.OrgID {
		t.Error("org ID mismatch")
	}
}

func TestExecution_JSONSerialization(t *testing.T) {
	exec := &Execution{
		Summary: &ExecutionSummary{
			RequestID:  "req-123",
			Status:     ExecutionStatusCompleted,
			TotalSteps: 2,
			StartedAt:  time.Now().UTC(),
		},
		Steps: []ExecutionSnapshot{
			{
				RequestID: "req-123",
				StepIndex: 0,
				StepName:  "step-1",
				Status:    StepStatusCompleted,
			},
			{
				RequestID: "req-123",
				StepIndex: 1,
				StepName:  "step-2",
				Status:    StepStatusCompleted,
			},
		},
	}

	// Serialize
	data, err := json.Marshal(exec)
	if err != nil {
		t.Fatalf("failed to marshal execution: %v", err)
	}

	// Deserialize
	var decoded Execution
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal execution: %v", err)
	}

	if decoded.Summary.RequestID != exec.Summary.RequestID {
		t.Error("summary request ID mismatch")
	}
	if len(decoded.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(decoded.Steps))
	}
}

func TestTimelineEntry_JSONSerialization(t *testing.T) {
	now := time.Now().UTC()
	completedAt := now.Add(100 * time.Millisecond)
	duration := 100

	entry := TimelineEntry{
		StepIndex:   0,
		StepName:    "test-step",
		Status:      StepStatusCompleted,
		StartedAt:   now,
		CompletedAt: &completedAt,
		DurationMs:  &duration,
		HasError:    false,
		HasApproval: false,
	}

	// Serialize
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal timeline entry: %v", err)
	}

	// Deserialize
	var decoded TimelineEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal timeline entry: %v", err)
	}

	if decoded.StepName != entry.StepName {
		t.Error("step name mismatch")
	}
	if decoded.Status != entry.Status {
		t.Error("status mismatch")
	}
}

func TestPolicyEvent_JSONSerialization(t *testing.T) {
	event := PolicyEvent{
		PolicyID:   "pol-123",
		PolicyName: "PII Detection",
		Action:     "block",
		Matched:    "SSN pattern",
		Resolution: "blocked",
	}

	// Serialize
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal policy event: %v", err)
	}

	// Deserialize
	var decoded PolicyEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal policy event: %v", err)
	}

	if decoded.PolicyID != event.PolicyID {
		t.Error("policy ID mismatch")
	}
	if decoded.PolicyName != event.PolicyName {
		t.Error("policy name mismatch")
	}
	if decoded.Action != event.Action {
		t.Error("action mismatch")
	}
}

func TestListOptions_Defaults(t *testing.T) {
	opts := ListOptions{}

	// Verify zero values
	if opts.Limit != 0 {
		t.Error("expected limit to be 0 by default")
	}
	if opts.Offset != 0 {
		t.Error("expected offset to be 0 by default")
	}
	if opts.OrgID != "" {
		t.Error("expected org_id to be empty by default")
	}
	if opts.StartTime != nil {
		t.Error("expected start_time to be nil by default")
	}
}

func TestExportOptions_Defaults(t *testing.T) {
	opts := ExportOptions{}

	// Verify zero values
	if opts.Format != "" {
		t.Error("expected format to be empty by default")
	}
	if opts.IncludeInput {
		t.Error("expected include_input to be false by default")
	}
	if opts.IncludeOutput {
		t.Error("expected include_output to be false by default")
	}
	if opts.IncludePolicies {
		t.Error("expected include_policies to be false by default")
	}
}
