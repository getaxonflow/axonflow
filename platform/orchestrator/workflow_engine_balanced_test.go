// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"context"
	"testing"
)

// =============================================================================
// ExecuteWorkflowBalanced tests
// =============================================================================

// TestExecuteWorkflowBalanced_NilEngine verifies that calling ExecuteWorkflowBalanced
// on an engine with nil storage panics or errors gracefully. Since the method
// dereferences e.storage inside ExecuteWorkflowWithParallelSupport, we test that
// an engine without storage returns an error rather than silently succeeding.
func TestExecuteWorkflowBalanced_NilStorage(t *testing.T) {
	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"function-call": NewFunctionCallProcessor(),
		},
		storage: nil,
	}

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "nil-storage-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "test"},
			},
		},
	}

	ctx := context.Background()

	// With nil storage, SaveExecution will panic. Recover and verify.
	defer func() {
		if r := recover(); r != nil {
			// Expected: nil storage causes panic in SaveExecution
			t.Logf("Recovered expected panic from nil storage: %v", r)
		}
	}()

	_, err := engine.ExecuteWorkflowBalanced(ctx, workflow, map[string]interface{}{}, UserContext{})
	if err == nil {
		t.Error("Expected error or panic when storage is nil")
	}
}

// TestExecuteWorkflowBalanced_NilStepProcessors verifies that an engine with nil
// stepProcessors map does not panic on workflow creation (the failure comes from
// unknown step type during execution).
func TestExecuteWorkflowBalanced_NilStepProcessors(t *testing.T) {
	engine := &WorkflowEngine{
		stepProcessors: nil,
		storage:        NewInMemoryWorkflowStorage(),
	}

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "nil-processors-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "test"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, map[string]interface{}{}, UserContext{})

	// The step should fail because there is no processor for "function-call"
	if err == nil {
		t.Error("Expected error when stepProcessors map is nil")
	}

	if execution == nil {
		t.Fatal("Expected non-nil execution even on failure")
	}

	if execution.Status != "failed" {
		t.Errorf("Expected status 'failed', got %q", execution.Status)
	}
}

// TestExecuteWorkflowBalanced_MixedStepTypes tests a workflow with mixed step
// types. ExecuteWorkflowBalanced calls groupStepsForBalancedExecution for logging
// and then delegates to ExecuteWorkflowWithParallelSupport with parallel enabled.
// We use function-call steps (which always succeed) combined with an llm-call
// step (via mock router) to verify the end-to-end path.
func TestExecuteWorkflowBalanced_MixedStepTypes(t *testing.T) {
	engine := NewWorkflowEngine()
	mockRouter := NewMockLLMRouter()
	engine.InitializeWithDependencies(mockRouter, nil)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "balanced-mixed-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "fetch-data", Type: "function-call", Function: "data-validator"},
				{Name: "analyze", Type: "llm-call", Provider: "mock", Prompt: "Analyze this"},
				{Name: "synthesize-results", Type: "function-call", Function: "risk-calculator"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, map[string]interface{}{
		"query": "test query",
	}, UserContext{ID: 1, TenantID: "test-tenant", Role: "user"})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if execution == nil {
		t.Fatal("Expected non-nil execution")
	}

	if execution.Status != "completed" {
		t.Errorf("Expected status 'completed', got %q", execution.Status)
	}

	if len(execution.Steps) != 3 {
		t.Errorf("Expected 3 steps, got %d", len(execution.Steps))
	}

	// Verify all steps completed
	for i, step := range execution.Steps {
		if step.Status != "completed" {
			t.Errorf("Step %d (%s) expected 'completed', got %q", i, step.Name, step.Status)
		}
	}

	// Verify execution metadata
	if execution.WorkflowName != "balanced-mixed-test" {
		t.Errorf("Expected workflow name 'balanced-mixed-test', got %q", execution.WorkflowName)
	}

	if execution.UserContext.TenantID != "test-tenant" {
		t.Errorf("Expected tenant 'test-tenant', got %q", execution.UserContext.TenantID)
	}

	// Verify mock router was called for the llm-call step
	if mockRouter.RouteRequestCalls != 1 {
		t.Errorf("Expected 1 RouteRequest call for llm-call step, got %d", mockRouter.RouteRequestCalls)
	}
}

// TestExecuteWorkflowBalanced_OnlySequentialLLMSteps tests a workflow that has
// only llm-call steps. In balanced mode, these should all run sequentially
// (rate-limit sensitive).
func TestExecuteWorkflowBalanced_OnlySequentialLLMSteps(t *testing.T) {
	engine := NewWorkflowEngine()
	mockRouter := NewMockLLMRouter()
	engine.InitializeWithDependencies(mockRouter, nil)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "balanced-llm-only-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "analyze-first", Type: "llm-call", Provider: "mock", Prompt: "First analysis"},
				{Name: "analyze-second", Type: "llm-call", Provider: "mock", Prompt: "Second analysis"},
				{Name: "analyze-third", Type: "llm-call", Provider: "mock", Prompt: "Third analysis"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, map[string]interface{}{}, UserContext{ID: 2, Role: "user"})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if execution.Status != "completed" {
		t.Errorf("Expected 'completed', got %q", execution.Status)
	}

	if len(execution.Steps) != 3 {
		t.Errorf("Expected 3 steps, got %d", len(execution.Steps))
	}

	// All steps should have completed status
	for i, step := range execution.Steps {
		if step.Status != "completed" {
			t.Errorf("Step %d (%s): expected 'completed', got %q", i, step.Name, step.Status)
		}
	}

	// Verify mock router was called for each LLM step
	if mockRouter.RouteRequestCalls != 3 {
		t.Errorf("Expected 3 RouteRequest calls, got %d", mockRouter.RouteRequestCalls)
	}
}

// TestExecuteWorkflowBalanced_OnlyParallelFunctionSteps tests a workflow with
// multiple function-call steps, simulating the case where all steps could run in
// parallel (analogous to connector-call steps being I/O-bound). In balanced mode,
// ExecuteWorkflowBalanced delegates to ExecuteWorkflowWithParallelSupport with
// parallel=true, so the first N-1 steps run in parallel and the last runs
// sequentially.
func TestExecuteWorkflowBalanced_OnlyParallelFunctionSteps(t *testing.T) {
	engine := NewWorkflowEngine()

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "balanced-parallel-only-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "fetch-flights", Type: "function-call", Function: "data-validator"},
				{Name: "fetch-hotels", Type: "function-call", Function: "risk-calculator"},
				{Name: "fetch-cars", Type: "function-call", Function: "auto-moderate"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, map[string]interface{}{}, UserContext{ID: 3, Role: "user"})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if execution.Status != "completed" {
		t.Errorf("Expected 'completed', got %q", execution.Status)
	}

	if len(execution.Steps) != 3 {
		t.Errorf("Expected 3 steps, got %d", len(execution.Steps))
	}

	// All steps should complete
	for i, step := range execution.Steps {
		if step.Status != "completed" {
			t.Errorf("Step %d (%s): expected 'completed', got %q", i, step.Name, step.Status)
		}
	}
}

// TestExecuteWorkflowBalanced_EmptyWorkflow tests a workflow with zero steps.
// This verifies that balanced execution handles the edge case gracefully.
func TestExecuteWorkflowBalanced_EmptyWorkflow(t *testing.T) {
	engine := NewWorkflowEngine()

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "balanced-empty-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, map[string]interface{}{}, UserContext{})

	if err != nil {
		t.Fatalf("Unexpected error on empty workflow: %v", err)
	}

	if execution == nil {
		t.Fatal("Expected non-nil execution")
	}

	if execution.Status != "completed" {
		t.Errorf("Expected 'completed' for empty workflow, got %q", execution.Status)
	}

	if len(execution.Steps) != 0 {
		t.Errorf("Expected 0 steps, got %d", len(execution.Steps))
	}
}

// TestExecuteWorkflowBalanced_ErrorPropagation tests that errors from the
// underlying ExecuteWorkflowWithParallelSupport propagate correctly through
// ExecuteWorkflowBalanced.
func TestExecuteWorkflowBalanced_ErrorPropagation(t *testing.T) {
	engine := NewWorkflowEngine()

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "balanced-error-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "good-step", Type: "function-call", Function: "data-validator"},
				{Name: "bad-step", Type: "unknown-type-that-does-not-exist"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, map[string]interface{}{}, UserContext{ID: 5, Role: "admin"})

	if err == nil {
		t.Error("Expected error from unknown step type")
	}

	if execution == nil {
		t.Fatal("Expected non-nil execution even on error")
	}

	if execution.Status != "failed" {
		t.Errorf("Expected 'failed', got %q", execution.Status)
	}

	if execution.Error == "" {
		t.Error("Expected error message to be set on execution")
	}
}

// TestExecuteWorkflowBalanced_ErrorPropagation_AllBadSteps tests that a workflow
// where the first step already fails returns the expected error.
func TestExecuteWorkflowBalanced_ErrorPropagation_AllBadSteps(t *testing.T) {
	engine := NewWorkflowEngine()

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "balanced-all-bad-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "bad-step-1", Type: "nonexistent-processor"},
				{Name: "bad-step-2", Type: "also-nonexistent"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, nil, UserContext{})

	if err == nil {
		t.Error("Expected error when all steps have unknown types")
	}

	if execution == nil {
		t.Fatal("Expected non-nil execution even on error")
	}

	if execution.Status != "failed" {
		t.Errorf("Expected 'failed', got %q", execution.Status)
	}
}

// TestExecuteWorkflowBalanced_NilInput tests that nil input maps are handled
// gracefully (ExecuteWorkflowWithParallelSupport initializes them).
func TestExecuteWorkflowBalanced_NilInput(t *testing.T) {
	engine := NewWorkflowEngine()

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "balanced-nil-input-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "data-validator"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, nil, UserContext{})

	if err != nil {
		t.Fatalf("Unexpected error with nil input: %v", err)
	}

	if execution.Status != "completed" {
		t.Errorf("Expected 'completed', got %q", execution.Status)
	}
}

// TestExecuteWorkflowBalanced_SingleStep tests the edge case of a single-step
// workflow in balanced mode. groupStepsForBalancedExecution should return a
// single sequential group.
func TestExecuteWorkflowBalanced_SingleStep(t *testing.T) {
	engine := NewWorkflowEngine()

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "balanced-single-step-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "only-step", Type: "function-call", Function: "data-validator"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, map[string]interface{}{}, UserContext{})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if execution.Status != "completed" {
		t.Errorf("Expected 'completed', got %q", execution.Status)
	}

	if len(execution.Steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(execution.Steps))
	}

	if execution.Steps[0].Name != "only-step" {
		t.Errorf("Expected step name 'only-step', got %q", execution.Steps[0].Name)
	}
}

// TestExecuteWorkflowBalanced_WithReplayRecorder tests that replay recording
// works correctly through the balanced execution path.
func TestExecuteWorkflowBalanced_WithReplayRecorder(t *testing.T) {
	engine := NewWorkflowEngine()
	recorder := &mockReplayRecorder{}
	engine.SetReplayRecorder(recorder)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "balanced-replay-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "data-validator"},
				{Name: "step2", Type: "function-call", Function: "risk-calculator"},
				{Name: "step3", Type: "function-call", Function: "auto-moderate"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, map[string]interface{}{}, UserContext{ID: 10, TenantID: "replay-tenant"})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if execution.Status != "completed" {
		t.Errorf("Expected 'completed', got %q", execution.Status)
	}

	// Verify StartExecution was called
	if len(recorder.startCalls) != 1 {
		t.Fatalf("Expected 1 StartExecution call, got %d", len(recorder.startCalls))
	}
	if recorder.startCalls[0].WorkflowName != "balanced-replay-test" {
		t.Errorf("Expected workflow name 'balanced-replay-test', got %q", recorder.startCalls[0].WorkflowName)
	}
	if recorder.startCalls[0].TotalSteps != 3 {
		t.Errorf("Expected 3 total steps, got %d", recorder.startCalls[0].TotalSteps)
	}
	if recorder.startCalls[0].TenantID != "replay-tenant" {
		t.Errorf("Expected tenant 'replay-tenant', got %q", recorder.startCalls[0].TenantID)
	}

	// Verify RecordStep was called for each step
	if len(recorder.stepCalls) != 3 {
		t.Fatalf("Expected 3 RecordStep calls, got %d", len(recorder.stepCalls))
	}
	for i, call := range recorder.stepCalls {
		if call.Snapshot.Status != "completed" {
			t.Errorf("Step %d: expected 'completed', got %q", i, call.Snapshot.Status)
		}
	}

	// Verify CompleteExecution was called
	if len(recorder.completeCalls) != 1 {
		t.Fatalf("Expected 1 CompleteExecution call, got %d", len(recorder.completeCalls))
	}

	// Verify no FailExecution calls
	if len(recorder.failCalls) != 0 {
		t.Errorf("Expected 0 FailExecution calls, got %d", len(recorder.failCalls))
	}
}

// TestExecuteWorkflowBalanced_ErrorWithReplayRecorder tests that the replay
// recorder's FailExecution is called when balanced execution fails.
func TestExecuteWorkflowBalanced_ErrorWithReplayRecorder(t *testing.T) {
	engine := NewWorkflowEngine()
	recorder := &mockReplayRecorder{}
	engine.SetReplayRecorder(recorder)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "balanced-replay-failure-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "good-step", Type: "function-call", Function: "data-validator"},
				{Name: "bad-step", Type: "unknown-type"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, map[string]interface{}{}, UserContext{ID: 11, TenantID: "fail-replay-tenant"})

	if err == nil {
		t.Fatal("Expected error from unknown step type")
	}

	if execution.Status != "failed" {
		t.Errorf("Expected 'failed', got %q", execution.Status)
	}

	// Verify StartExecution was called
	if len(recorder.startCalls) != 1 {
		t.Fatalf("Expected 1 StartExecution call, got %d", len(recorder.startCalls))
	}

	// Verify FailExecution was called
	if len(recorder.failCalls) != 1 {
		t.Fatalf("Expected 1 FailExecution call, got %d", len(recorder.failCalls))
	}
	if recorder.failCalls[0].ErrMsg == "" {
		t.Error("FailExecution error message should not be empty")
	}

	// Verify CompleteExecution was NOT called
	if len(recorder.completeCalls) != 0 {
		t.Errorf("Expected 0 CompleteExecution calls on failure, got %d", len(recorder.completeCalls))
	}
}

// TestExecuteWorkflowBalanced_OutputTemplateResolution tests that output
// templates are resolved correctly when using balanced execution.
func TestExecuteWorkflowBalanced_OutputTemplateResolution(t *testing.T) {
	engine := NewWorkflowEngine()

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "balanced-output-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "validate", Type: "function-call", Function: "data-validator"},
			},
			Output: map[string]string{
				"validation_result": "{{steps.validate.output.status}}",
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, map[string]interface{}{}, UserContext{})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if execution.Status != "completed" {
		t.Errorf("Expected 'completed', got %q", execution.Status)
	}

	// Output should have the resolved template
	if execution.Output == nil {
		t.Fatal("Expected non-nil output")
	}

	if _, exists := execution.Output["validation_result"]; !exists {
		t.Error("Expected 'validation_result' key in output")
	}
}

// TestExecuteWorkflowBalanced_TimingFields tests that timing fields are properly
// set on the execution and its steps when using balanced mode.
func TestExecuteWorkflowBalanced_TimingFields(t *testing.T) {
	engine := NewWorkflowEngine()

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "balanced-timing-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "data-validator"},
				{Name: "step2", Type: "function-call", Function: "risk-calculator"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, map[string]interface{}{}, UserContext{})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if execution.StartTime.IsZero() {
		t.Error("Expected start time to be set")
	}

	if execution.EndTime == nil {
		t.Error("Expected end time to be set")
	}

	if execution.EndTime != nil && execution.EndTime.Before(execution.StartTime) {
		t.Error("End time should not be before start time")
	}

	for i, step := range execution.Steps {
		if step.StartTime.IsZero() {
			t.Errorf("Step %d (%s): expected start time to be set", i, step.Name)
		}
		if step.EndTime == nil {
			t.Errorf("Step %d (%s): expected end time to be set", i, step.Name)
		}
		if step.ProcessTime == "" {
			t.Errorf("Step %d (%s): expected process time to be set", i, step.Name)
		}
	}
}

// TestExecuteWorkflowBalanced_ExecutionStoredInStorage verifies that the
// execution is persisted in storage and can be retrieved.
func TestExecuteWorkflowBalanced_ExecutionStoredInStorage(t *testing.T) {
	engine := NewWorkflowEngine()

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "balanced-storage-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "data-validator"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowBalanced(ctx, workflow, map[string]interface{}{}, UserContext{})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Retrieve from storage
	retrieved, err := engine.GetExecution(execution.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve execution from storage: %v", err)
	}

	if retrieved.ID != execution.ID {
		t.Errorf("Expected execution ID %q, got %q", execution.ID, retrieved.ID)
	}

	if retrieved.Status != "completed" {
		t.Errorf("Expected stored execution status 'completed', got %q", retrieved.Status)
	}

	if retrieved.WorkflowName != "balanced-storage-test" {
		t.Errorf("Expected workflow name 'balanced-storage-test', got %q", retrieved.WorkflowName)
	}
}
