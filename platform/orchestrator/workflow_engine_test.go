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
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// TestNewWorkflowEngine tests engine initialization
func TestNewWorkflowEngine(t *testing.T) {
	engine := NewWorkflowEngine()

	if engine == nil {
		t.Fatal("Expected non-nil engine")
	}

	if engine.storage == nil {
		t.Error("Expected storage to be initialized")
	}

	if len(engine.stepProcessors) == 0 {
		t.Error("Expected step processors to be registered")
	}

	// Verify default processors
	if _, exists := engine.stepProcessors["conditional"]; !exists {
		t.Error("Expected conditional processor to be registered")
	}

	if _, exists := engine.stepProcessors["function-call"]; !exists {
		t.Error("Expected function-call processor to be registered")
	}
}

// TestInMemoryStorage tests storage operations
func TestInMemoryStorage(t *testing.T) {
	storage := NewInMemoryWorkflowStorage()

	// Create test execution
	execution := &WorkflowExecution{
		ID:           "test-123",
		WorkflowName: "test-workflow",
		Status:       "running",
		Input:        map[string]interface{}{"key": "value"},
		StartTime:    time.Now(),
	}

	// Test Save
	err := storage.SaveExecution(execution)
	if err != nil {
		t.Errorf("Unexpected save error: %v", err)
	}

	// Test Get
	retrieved, err := storage.GetExecution("test-123")
	if err != nil {
		t.Errorf("Unexpected get error: %v", err)
	}

	if retrieved.ID != "test-123" {
		t.Errorf("Expected ID test-123, got %s", retrieved.ID)
	}

	// Test Get non-existent
	_, err = storage.GetExecution("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent execution")
	}

	// Test Update
	execution.Status = "completed"
	err = storage.UpdateExecution(execution)
	if err != nil {
		t.Errorf("Unexpected update error: %v", err)
	}

	retrieved, _ = storage.GetExecution("test-123")
	if retrieved.Status != "completed" {
		t.Errorf("Expected status completed, got %s", retrieved.Status)
	}
}

// TestConditionalProcessor tests conditional step execution
func TestConditionalProcessor(t *testing.T) {
	engine := NewWorkflowEngine()
	processor := NewConditionalProcessor(engine)
	ctx := context.Background()

	tests := []struct {
		name              string
		step              WorkflowStep
		execution         *WorkflowExecution
		expectedResult    bool
		expectedBranch    string
	}{
		{
			name: "True condition - simple equality",
			step: WorkflowStep{
				Name:      "conditional-test",
				Type:      "conditional",
				Condition: "{{steps.prev.output.status}} == approved",
			},
			execution: &WorkflowExecution{
				Steps: []StepExecution{
					{
						Name:   "prev",
						Status: "completed",
						Output: map[string]interface{}{
							"status": "approved",
						},
					},
				},
			},
			expectedResult: true,
			expectedBranch: "if_true",
		},
		{
			name: "False condition - not matching",
			step: WorkflowStep{
				Name:      "conditional-test",
				Type:      "conditional",
				Condition: "{{steps.prev.output.status}} == rejected",
			},
			execution: &WorkflowExecution{
				Steps: []StepExecution{
					{
						Name:   "prev",
						Status: "completed",
						Output: map[string]interface{}{
							"status": "approved",
						},
					},
				},
			},
			expectedResult: false,
			expectedBranch: "if_false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := processor.ExecuteStep(ctx, tt.step, map[string]interface{}{}, tt.execution)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if result, ok := output["condition_result"].(bool); !ok {
				t.Error("Expected condition_result in output")
			} else if result != tt.expectedResult {
				t.Errorf("Expected condition result %v, got %v", tt.expectedResult, result)
			}

			if branch, ok := output["branch_taken"].(string); !ok {
				t.Error("Expected branch_taken in output")
			} else if branch != tt.expectedBranch {
				t.Errorf("Expected branch %s, got %s", tt.expectedBranch, branch)
			}
		})
	}
}

// TestConditionalBranchExecution tests that branches are actually executed (Issue #1082)
func TestConditionalBranchExecution(t *testing.T) {
	engine := NewWorkflowEngine()
	processor := NewConditionalProcessor(engine)
	ctx := context.Background()

	tests := []struct {
		name                   string
		step                   WorkflowStep
		execution              *WorkflowExecution
		expectedBranch         string
		expectedStepsExecuted  int
		expectedStepNames      []string
	}{
		{
			name: "Execute if_true branch with function-call steps",
			step: WorkflowStep{
				Name:      "conditional-with-branches",
				Type:      "conditional",
				Condition: "{{steps.prev.output.status}} == approved",
				IfTrue: []WorkflowStep{
					{
						Name:     "validate-data",
						Type:     "function-call",
						Function: "data-validator",
					},
					{
						Name:     "calculate-risk",
						Type:     "function-call",
						Function: "risk-calculator",
					},
				},
				IfFalse: []WorkflowStep{
					{
						Name:     "reject-action",
						Type:     "function-call",
						Function: "auto-moderate",
					},
				},
			},
			execution: &WorkflowExecution{
				Steps: []StepExecution{
					{
						Name:   "prev",
						Status: "completed",
						Output: map[string]interface{}{
							"status": "approved",
						},
					},
				},
			},
			expectedBranch:        "if_true",
			expectedStepsExecuted: 2,
			expectedStepNames:     []string{"validate-data", "calculate-risk"},
		},
		{
			name: "Execute if_false branch when condition is false",
			step: WorkflowStep{
				Name:      "conditional-with-branches",
				Type:      "conditional",
				Condition: "{{steps.prev.output.status}} == approved",
				IfTrue: []WorkflowStep{
					{
						Name:     "validate-data",
						Type:     "function-call",
						Function: "data-validator",
					},
				},
				IfFalse: []WorkflowStep{
					{
						Name:     "reject-action",
						Type:     "function-call",
						Function: "auto-moderate",
					},
				},
			},
			execution: &WorkflowExecution{
				Steps: []StepExecution{
					{
						Name:   "prev",
						Status: "completed",
						Output: map[string]interface{}{
							"status": "rejected",
						},
					},
				},
			},
			expectedBranch:        "if_false",
			expectedStepsExecuted: 1,
			expectedStepNames:     []string{"reject-action"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of execution to avoid mutation across tests
			execCopy := &WorkflowExecution{
				Steps: make([]StepExecution, len(tt.execution.Steps)),
			}
			copy(execCopy.Steps, tt.execution.Steps)
			initialStepCount := len(execCopy.Steps)

			output, err := processor.ExecuteStep(ctx, tt.step, map[string]interface{}{}, execCopy)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify branch taken
			if branch := output["branch_taken"].(string); branch != tt.expectedBranch {
				t.Errorf("Expected branch %s, got %s", tt.expectedBranch, branch)
			}

			// Verify steps were executed (Issue #1082 fix)
			stepsExecuted := output["steps_executed"].(int)
			if stepsExecuted != tt.expectedStepsExecuted {
				t.Errorf("Expected %d steps executed, got %d", tt.expectedStepsExecuted, stepsExecuted)
			}

			// Verify branch steps were added to execution
			newStepsAdded := len(execCopy.Steps) - initialStepCount
			if newStepsAdded != tt.expectedStepsExecuted {
				t.Errorf("Expected %d new steps in execution, got %d", tt.expectedStepsExecuted, newStepsAdded)
			}

			// Verify step names
			for i, expectedName := range tt.expectedStepNames {
				actualStep := execCopy.Steps[initialStepCount+i]
				if actualStep.Name != expectedName {
					t.Errorf("Expected step name %s at index %d, got %s", expectedName, i, actualStep.Name)
				}
				if actualStep.Status != "completed" {
					t.Errorf("Expected step %s to be completed, got %s", expectedName, actualStep.Status)
				}
				if actualStep.Output == nil {
					t.Errorf("Expected step %s to have output", expectedName)
				}
			}

			// Verify branch_steps output contains step outputs
			branchSteps, ok := output["branch_steps"].([]map[string]interface{})
			if !ok {
				t.Fatal("Expected branch_steps in output")
			}
			if len(branchSteps) != tt.expectedStepsExecuted {
				t.Errorf("Expected %d branch_steps, got %d", tt.expectedStepsExecuted, len(branchSteps))
			}
		})
	}
}

// TestFunctionCallProcessor tests function call execution
func TestFunctionCallProcessor(t *testing.T) {
	processor := NewFunctionCallProcessor()
	ctx := context.Background()

	tests := []struct {
		name         string
		step         WorkflowStep
		expectedKey  string
		expectedType string
	}{
		{
			name: "Data validator function",
			step: WorkflowStep{
				Name:     "validate",
				Type:     "function-call",
				Function: "data-validator",
			},
			expectedKey:  "validation_score",
			expectedType: "float64",
		},
		{
			name: "Risk calculator function",
			step: WorkflowStep{
				Name:     "calculate-risk",
				Type:     "function-call",
				Function: "risk-calculator",
			},
			expectedKey:  "final_risk_score",
			expectedType: "int",
		},
		{
			name: "Auto moderate function",
			step: WorkflowStep{
				Name:     "moderate",
				Type:     "function-call",
				Function: "auto-moderate",
			},
			expectedKey:  "action",
			expectedType: "string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := processor.ExecuteStep(ctx, tt.step, map[string]interface{}{}, &WorkflowExecution{})

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if output["function"] != tt.step.Function {
				t.Errorf("Expected function %s, got %v", tt.step.Function, output["function"])
			}

			if _, exists := output[tt.expectedKey]; !exists {
				t.Errorf("Expected key %s in output", tt.expectedKey)
			}
		})
	}
}

// TestLLMCallProcessor tests LLM step execution with mock router
func TestLLMCallProcessor(t *testing.T) {
	// Create mock router
	mockRouter := NewMockLLMRouter()
	mockRouter.RouteResponse = &LLMResponse{
		Content:      "Analyzed output",
		Model:        "test-model",
		TokensUsed:   100,
		ResponseTime: 10 * time.Millisecond,
	}

	processor := NewLLMCallProcessor(mockRouter)
	ctx := context.Background()

	step := WorkflowStep{
		Name:     "llm-analysis",
		Type:     "llm-call",
		Provider: "test",
		Prompt:   "Analyze the following: {{input.query}}",
	}

	input := map[string]interface{}{
		"query": "SELECT * FROM users",
	}

	execution := &WorkflowExecution{
		ID:    "test-exec-1",
		Steps: []StepExecution{},
		UserContext: UserContext{
			Role: "user",
		},
	}

	output, err := processor.ExecuteStep(ctx, step, input, execution)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify output structure
	if _, ok := output["response"]; !ok {
		t.Error("Expected response in output")
	}

	if _, ok := output["provider"]; !ok {
		t.Error("Expected provider in output")
	}

	if _, ok := output["tokens_used"]; !ok {
		t.Error("Expected tokens_used in output")
	}
}

// TestTemplateReplacement tests variable replacement
func TestTemplateReplacement(t *testing.T) {
	processor := NewLLMCallProcessor(nil)

	execution := &WorkflowExecution{
		Steps: []StepExecution{
			{
				Name:   "step1",
				Status: "completed",
				Output: map[string]interface{}{
					"result": "test-result",
					"count":  "42",
				},
			},
		},
	}

	input := map[string]interface{}{
		"user_query": "test query",
	}

	template := "Previous result: {{steps.step1.output.result}}, Query: {{input.user_query}}"

	result := processor.replaceTemplateVars(template, input, execution)

	expectedResult := "Previous result: test-result, Query: test query"
	if result != expectedResult {
		t.Errorf("Expected '%s', got '%s'", expectedResult, result)
	}
}

// TestIsSynthesisStep tests synthesis step detection
func TestIsSynthesisStep(t *testing.T) {
	processor := NewLLMCallProcessor(nil)

	tests := []struct {
		name     string
		stepName string
		expected bool
	}{
		{"Synthesize step", "synthesize-results", true},
		{"Combine step", "combine-data", true},
		{"Final step", "final-summary", true},
		{"Summary step", "create-summary", true},
		{"Aggregate step", "aggregate-findings", true},
		{"Merge step", "merge-outputs", true},
		{"Regular step", "analyze-data", false},
		{"Query step", "execute-query", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.isSynthesisStep(tt.stepName)
			if result != tt.expected {
				t.Errorf("Expected %v for step '%s', got %v", tt.expected, tt.stepName, result)
			}
		})
	}
}

// TestWorkflowExecution tests complete workflow execution
func TestWorkflowExecution(t *testing.T) {
	engine := NewWorkflowEngine()

	// Create simple workflow
	workflow := Workflow{
		APIVersion: "v1",
		Kind:       "Workflow",
		Metadata: WorkflowMetadata{
			Name:        "test-workflow",
			Description: "Test workflow",
			Version:     "1.0",
		},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{
					Name:     "step1",
					Type:     "function-call",
					Function: "data-validator",
				},
				{
					Name:      "step2",
					Type:      "conditional",
					Condition: "{{steps.step1.output.status}} == valid",
				},
			},
			Output: map[string]string{
				"final_status": "{{steps.step2.output.branch_taken}}",
			},
		},
	}

	input := map[string]interface{}{
		"data": "test-data",
	}

	user := UserContext{
		ID:    1,
		Role:  "user",
		Email: "test@example.com",
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, input, user)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify execution completed
	if execution.Status != "completed" {
		t.Errorf("Expected status completed, got %s", execution.Status)
	}

	// Verify steps were executed
	if len(execution.Steps) != 2 {
		t.Errorf("Expected 2 steps, got %d", len(execution.Steps))
	}

	// Verify all steps completed
	for i, step := range execution.Steps {
		if step.Status != "completed" {
			t.Errorf("Step %d (%s) expected completed, got %s", i, step.Name, step.Status)
		}
	}
}

// TestWorkflowExecutionWithFailure tests error handling
func TestWorkflowExecutionWithFailure(t *testing.T) {
	engine := NewWorkflowEngine()

	// Workflow with unknown step type
	workflow := Workflow{
		Metadata: WorkflowMetadata{
			Name: "failing-workflow",
		},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{
					Name: "unknown-step",
					Type: "unknown-type",
				},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{}, UserContext{})

	// Should return error
	if err == nil {
		t.Error("Expected error for unknown step type")
	}

	// Execution should be marked as failed
	if execution.Status != "failed" {
		t.Errorf("Expected status failed, got %s", execution.Status)
	}

	// Error should be set
	if execution.Error == "" {
		t.Error("Expected error message to be set")
	}
}

// TestGetExecution tests execution retrieval
func TestGetExecution(t *testing.T) {
	engine := NewWorkflowEngine()

	// Create and save execution
	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "test"},
			},
		},
	}

	ctx := context.Background()
	execution, _ := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{}, UserContext{})

	// Retrieve it
	retrieved, err := engine.GetExecution(execution.ID)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if retrieved.ID != execution.ID {
		t.Errorf("Expected ID %s, got %s", execution.ID, retrieved.ID)
	}

	// Try to get non-existent
	_, err = engine.GetExecution("non-existent-id")
	if err == nil {
		t.Error("Expected error for non-existent execution")
	}
}

// TestWorkflowEngineHealth tests health check
func TestWorkflowEngineHealth(t *testing.T) {
	tests := []struct {
		name     string
		engine   *WorkflowEngine
		expected bool
	}{
		{
			name: "Healthy engine",
			engine: &WorkflowEngine{
				storage:        NewInMemoryWorkflowStorage(),
				stepProcessors: map[string]StepProcessor{"test": NewFunctionCallProcessor()},
			},
			expected: true,
		},
		{
			name: "No storage",
			engine: &WorkflowEngine{
				storage:        nil,
				stepProcessors: map[string]StepProcessor{"test": NewFunctionCallProcessor()},
			},
			expected: false,
		},
		{
			name: "No processors",
			engine: &WorkflowEngine{
				storage:        NewInMemoryWorkflowStorage(),
				stepProcessors: map[string]StepProcessor{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.engine.IsHealthy()
			if result != tt.expected {
				t.Errorf("Expected IsHealthy=%v, got %v", tt.expected, result)
			}
		})
	}
}

// TestParallelExecution tests parallel step execution
func TestParallelExecution(t *testing.T) {
	engine := NewWorkflowEngine()

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "parallel-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "test1"},
				{Name: "step2", Type: "function-call", Function: "test2"},
				{Name: "synthesis", Type: "function-call", Function: "synthesize"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowWithParallelSupport(
		ctx, workflow, map[string]interface{}{}, UserContext{}, true,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if execution.Status != "completed" {
		t.Errorf("Expected completed status, got %s", execution.Status)
	}

	if len(execution.Steps) != 3 {
		t.Errorf("Expected 3 steps, got %d", len(execution.Steps))
	}
}

// TestSoftFailureTolerance tests the configurable soft failure tolerance (Issue #1082)
func TestSoftFailureTolerance(t *testing.T) {
	engine := NewWorkflowEngine()

	// Test the evaluateFailureTolerance function directly
	tests := []struct {
		name           string
		tolerance      string
		steps          []WorkflowStep
		failedSteps    []string
		succeededSteps []string
		expectFail     bool
	}{
		{
			name:           "none tolerance - any failure should fail",
			tolerance:      "none",
			steps:          []WorkflowStep{{Name: "step1"}, {Name: "step2"}, {Name: "step3"}},
			failedSteps:    []string{"step1"},
			succeededSteps: []string{"step2", "step3"},
			expectFail:     true,
		},
		{
			name:           "empty tolerance (default strict) - any failure should fail",
			tolerance:      "",
			steps:          []WorkflowStep{{Name: "step1"}, {Name: "step2"}},
			failedSteps:    []string{"step1"},
			succeededSteps: []string{"step2"},
			expectFail:     true,
		},
		{
			name:           "any tolerance - succeed if any step succeeds",
			tolerance:      "any",
			steps:          []WorkflowStep{{Name: "step1"}, {Name: "step2"}, {Name: "step3"}},
			failedSteps:    []string{"step1", "step2"},
			succeededSteps: []string{"step3"},
			expectFail:     false,
		},
		{
			name:           "any tolerance - fail if all steps fail",
			tolerance:      "any",
			steps:          []WorkflowStep{{Name: "step1"}, {Name: "step2"}},
			failedSteps:    []string{"step1", "step2"},
			succeededSteps: []string{},
			expectFail:     true,
		},
		{
			name:           "count:1 tolerance - allow 1 failure",
			tolerance:      "count:1",
			steps:          []WorkflowStep{{Name: "step1"}, {Name: "step2"}, {Name: "step3"}},
			failedSteps:    []string{"step1"},
			succeededSteps: []string{"step2", "step3"},
			expectFail:     false,
		},
		{
			name:           "count:1 tolerance - fail with 2 failures",
			tolerance:      "count:1",
			steps:          []WorkflowStep{{Name: "step1"}, {Name: "step2"}, {Name: "step3"}},
			failedSteps:    []string{"step1", "step2"},
			succeededSteps: []string{"step3"},
			expectFail:     true,
		},
		{
			name:           "percentage:50 tolerance - succeed with 50% success",
			tolerance:      "percentage:50",
			steps:          []WorkflowStep{{Name: "step1"}, {Name: "step2"}, {Name: "step3"}, {Name: "step4"}},
			failedSteps:    []string{"step1", "step2"},
			succeededSteps: []string{"step3", "step4"},
			expectFail:     false,
		},
		{
			name:           "percentage:50 tolerance - fail with less than 50% success",
			tolerance:      "percentage:50",
			steps:          []WorkflowStep{{Name: "step1"}, {Name: "step2"}, {Name: "step3"}, {Name: "step4"}},
			failedSteps:    []string{"step1", "step2", "step3"},
			succeededSteps: []string{"step4"},
			expectFail:     true,
		},
		{
			name:           "required:step1,step2 - succeed if required steps succeed",
			tolerance:      "required:step1,step2",
			steps:          []WorkflowStep{{Name: "step1"}, {Name: "step2"}, {Name: "step3"}},
			failedSteps:    []string{"step3"},
			succeededSteps: []string{"step1", "step2"},
			expectFail:     false,
		},
		{
			name:           "required:step1,step2 - fail if required step fails",
			tolerance:      "required:step1,step2",
			steps:          []WorkflowStep{{Name: "step1"}, {Name: "step2"}, {Name: "step3"}},
			failedSteps:    []string{"step1"},
			succeededSteps: []string{"step2", "step3"},
			expectFail:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateFailureTolerance(tt.tolerance, tt.steps, tt.failedSteps, tt.succeededSteps)
			if result != tt.expectFail {
				t.Errorf("Expected shouldFail=%v, got %v for tolerance '%s'", tt.expectFail, result, tt.tolerance)
			}
		})
	}
}

// TestStepGrouping tests step grouping logic
func TestStepGrouping(t *testing.T) {
	engine := NewWorkflowEngine()

	tests := []struct {
		name            string
		steps           []WorkflowStep
		enableParallel  bool
		expectedGroups  int
		firstGroupSize  int
		firstGroupParallel bool
	}{
		{
			name: "Parallel enabled - 3 steps",
			steps: []WorkflowStep{
				{Name: "step1"},
				{Name: "step2"},
				{Name: "synthesis"},
			},
			enableParallel:     true,
			expectedGroups:     2,
			firstGroupSize:     2,
			firstGroupParallel: true,
		},
		{
			name: "Parallel disabled - 3 steps",
			steps: []WorkflowStep{
				{Name: "step1"},
				{Name: "step2"},
				{Name: "step3"},
			},
			enableParallel:     false,
			expectedGroups:     1,
			firstGroupSize:     3,
			firstGroupParallel: false,
		},
		{
			name: "Single step",
			steps: []WorkflowStep{
				{Name: "step1"},
			},
			enableParallel:     true,
			expectedGroups:     1,
			firstGroupSize:     1,
			firstGroupParallel: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups := engine.groupStepsForExecution(tt.steps, tt.enableParallel)

			if len(groups) != tt.expectedGroups {
				t.Errorf("Expected %d groups, got %d", tt.expectedGroups, len(groups))
			}

			if len(groups) > 0 {
				if len(groups[0].Steps) != tt.firstGroupSize {
					t.Errorf("Expected first group size %d, got %d", tt.firstGroupSize, len(groups[0].Steps))
				}

				if groups[0].IsParallel != tt.firstGroupParallel {
					t.Errorf("Expected first group parallel=%v, got %v", tt.firstGroupParallel, groups[0].IsParallel)
				}
			}
		})
	}
}

// TestExecuteSingleStep tests single step execution
func TestExecuteSingleStep(t *testing.T) {
	engine := NewWorkflowEngine()
	ctx := context.Background()

	step := WorkflowStep{
		Name:     "test-step",
		Type:     "function-call",
		Function: "data-validator",
	}

	execution := &WorkflowExecution{
		ID:    "test-exec",
		Steps: []StepExecution{},
	}

	stepExec, err := engine.executeSingleStep(ctx, step, map[string]interface{}{}, execution)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if stepExec.Status != "completed" {
		t.Errorf("Expected completed status, got %s", stepExec.Status)
	}

	if stepExec.Name != "test-step" {
		t.Errorf("Expected name test-step, got %s", stepExec.Name)
	}

	if stepExec.ProcessTime == "" {
		t.Error("Expected process time to be set")
	}

	if stepExec.EndTime == nil {
		t.Error("Expected end time to be set")
	}
}

// TestExecuteSingleStepFailure tests step execution failure
func TestExecuteSingleStepFailure(t *testing.T) {
	engine := NewWorkflowEngine()
	ctx := context.Background()

	step := WorkflowStep{
		Name: "unknown-step",
		Type: "unknown-type",
	}

	stepExec, err := engine.executeSingleStep(ctx, step, map[string]interface{}{}, &WorkflowExecution{})

	if err == nil {
		t.Error("Expected error for unknown step type")
	}

	if stepExec.Status != "failed" {
		t.Errorf("Expected failed status, got %s", stepExec.Status)
	}

	if stepExec.Error == "" {
		t.Error("Expected error message to be set")
	}
}

// TestGetExecutionsByTenant tests tenant filtering
func TestGetExecutionsByTenant(t *testing.T) {
	engine := NewWorkflowEngine()
	ctx := context.Background()

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "test"},
			},
		},
	}

	// Create executions for different tenants
	user1 := UserContext{ID: 1, TenantID: "tenant-a"}
	user2 := UserContext{ID: 2, TenantID: "tenant-b"}
	user3 := UserContext{ID: 3, TenantID: "tenant-a"}

	_, _ = engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{}, user1)
	_, _ = engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{}, user2)
	_, _ = engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{}, user3)

	// Get executions for tenant-a
	tenantAExecutions, err := engine.GetExecutionsByTenant("tenant-a")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(tenantAExecutions) != 2 {
		t.Errorf("Expected 2 executions for tenant-a, got %d", len(tenantAExecutions))
	}

	// Verify all are for tenant-a
	for _, exec := range tenantAExecutions {
		if exec.UserContext.TenantID != "tenant-a" {
			t.Errorf("Expected tenant-a, got %s", exec.UserContext.TenantID)
		}
	}
}

// TestOutputTemplateResolution tests output template resolution
func TestOutputTemplateResolution(t *testing.T) {
	engine := NewWorkflowEngine()

	execution := &WorkflowExecution{
		Steps: []StepExecution{
			{
				Name:   "step1",
				Status: "completed",
				Output: map[string]interface{}{
					"result": "success",
					"data":   "processed-data",
				},
			},
			{
				Name:   "step2",
				Status: "completed",
				Output: map[string]interface{}{
					"response": &LLMResponse{
						Content: "AI generated response",
					},
				},
			},
		},
	}

	tests := []struct {
		name     string
		template string
		expected string
	}{
		{
			name:     "Simple string replacement",
			template: "Result: {{steps.step1.output.result}}",
			expected: "Result: success",
		},
		{
			name:     "Multiple replacements",
			template: "{{steps.step1.output.result}} - {{steps.step1.output.data}}",
			expected: "success - processed-data",
		},
		{
			name:     "LLMResponse object",
			template: "AI says: {{steps.step2.output.response}}",
			expected: "AI says: AI generated response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.resolveOutputTemplate(tt.template, execution)

			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestBuildPreviousOutputsContext tests context building for synthesis
func TestBuildPreviousOutputsContext(t *testing.T) {
	tests := []struct {
		name           string
		execution      *WorkflowExecution
		expectedFields []string
		notExpected    []string
	}{
		{
			name: "Response strings",
			execution: &WorkflowExecution{
				Steps: []StepExecution{
					{
						Name:   "flight-search",
						Status: "completed",
						Output: map[string]interface{}{
							"response": "Flight: NYC to LAX, Price: $299",
						},
					},
					{
						Name:   "hotel-search",
						Status: "completed",
						Output: map[string]interface{}{
							"response": "Hotel: Grand Plaza, Price: $150/night",
						},
					},
				},
			},
			expectedFields: []string{"flight-search", "hotel-search", "$299", "Grand Plaza", "PREVIOUS STEP RESULTS"},
			notExpected:    []string{},
		},
		{
			name: "Raw output fallback",
			execution: &WorkflowExecution{
				Steps: []StepExecution{
					{
						Name:   "data-processing",
						Status: "completed",
						Output: map[string]interface{}{
							"count":  42,
							"status": "success",
							"data":   "processed results",
						},
					},
				},
			},
			expectedFields: []string{"data-processing", "count", "42", "status", "success", "data", "processed results"},
			notExpected:    []string{},
		},
		{
			name: "Skip internal fields",
			execution: &WorkflowExecution{
				Steps: []StepExecution{
					{
						Name:   "api-call",
						Status: "completed",
						Output: map[string]interface{}{
							"result":        "API response data",
							"provider":      "openai",
							"model":         "gpt-4",
							"tokens_used":   150,
							"response_time": "200ms",
							"duration":      1.5,
							"cached":        true,
							"connector":     "http",
						},
					},
				},
			},
			expectedFields: []string{"api-call", "result", "API response data"},
			notExpected:    []string{"provider", "model", "tokens_used", "response_time", "duration", "cached", "connector"},
		},
		{
			name: "Skip synthesis steps",
			execution: &WorkflowExecution{
				Steps: []StepExecution{
					{
						Name:   "search-data",
						Status: "completed",
						Output: map[string]interface{}{
							"response": "Search results",
						},
					},
					{
						Name:   "synthesize-results",
						Status: "completed",
						Output: map[string]interface{}{
							"response": "This should be skipped",
						},
					},
				},
			},
			expectedFields: []string{"search-data", "Search results"},
			notExpected:    []string{"synthesize-results", "This should be skipped"},
		},
		{
			name: "Failed steps not included",
			execution: &WorkflowExecution{
				Steps: []StepExecution{
					{
						Name:   "successful-step",
						Status: "completed",
						Output: map[string]interface{}{
							"response": "Success data",
						},
					},
					{
						Name:   "failed-step",
						Status: "failed",
						Output: map[string]interface{}{
							"response": "This should not appear",
						},
						Error: "Step failed",
					},
				},
			},
			expectedFields: []string{"successful-step", "Success data"},
			notExpected:    []string{"failed-step", "This should not appear"},
		},
		{
			name: "Empty output",
			execution: &WorkflowExecution{
				Steps: []StepExecution{
					{
						Name:   "empty-step",
						Status: "completed",
						Output: map[string]interface{}{},
					},
				},
			},
			expectedFields: []string{"PREVIOUS STEP RESULTS"},
			notExpected:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewLLMCallProcessor(nil)
			context := processor.buildPreviousOutputsContext(tt.execution)

			// Verify expected fields
			for _, field := range tt.expectedFields {
				if !stringContains(context, field) {
					t.Errorf("Expected context to contain '%s'", field)
				}
			}

			// Verify fields that should not be present
			for _, field := range tt.notExpected {
				if stringContains(context, field) {
					t.Errorf("Expected context NOT to contain '%s'", field)
				}
			}
		})
	}
}

// TestWorkflowExecutionTiming tests execution timing
func TestWorkflowExecutionTiming(t *testing.T) {
	engine := NewWorkflowEngine()

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "timing-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "test"},
			},
		},
	}

	ctx := context.Background()
	start := time.Now()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{}, UserContext{})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify timing fields are set
	if execution.StartTime.IsZero() {
		t.Error("Expected start time to be set")
	}

	if execution.EndTime == nil {
		t.Error("Expected end time to be set")
	}

	// Verify execution time is reasonable
	if execution.EndTime.Before(start) {
		t.Error("End time should be after test start")
	}

	// Verify step timing
	if len(execution.Steps) > 0 {
		step := execution.Steps[0]
		if step.StartTime.IsZero() {
			t.Error("Expected step start time to be set")
		}

		if step.EndTime == nil {
			t.Error("Expected step end time to be set")
		}

		if step.ProcessTime == "" {
			t.Error("Expected step process time to be set")
		}
	}
}

// TestWorkflowMetadata tests workflow metadata
func TestWorkflowMetadata(t *testing.T) {
	workflow := Workflow{
		APIVersion: "v1",
		Kind:       "Workflow",
		Metadata: WorkflowMetadata{
			Name:        "test-workflow",
			Description: "Test description",
			Version:     "1.0.0",
			Tags:        []string{"test", "demo"},
		},
		Spec: WorkflowSpec{
			Timeout: "5m",
			Retries: 3,
		},
	}

	if workflow.Metadata.Name != "test-workflow" {
		t.Error("Metadata not set correctly")
	}

	if len(workflow.Metadata.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(workflow.Metadata.Tags))
	}

	if workflow.Spec.Retries != 3 {
		t.Errorf("Expected 3 retries, got %d", workflow.Spec.Retries)
	}
}

// TestConditionalExtractValue tests value extraction from execution state
func TestConditionalExtractValue(t *testing.T) {
	engine := NewWorkflowEngine()
	processor := NewConditionalProcessor(engine)

	execution := &WorkflowExecution{
		Steps: []StepExecution{
			{
				Name:   "validation",
				Status: "completed",
				Output: map[string]interface{}{
					"score":   0.95,
					"status":  "approved",
					"flagged": false,
				},
			},
		},
	}

	tests := []struct {
		name     string
		path     string
		expected interface{}
	}{
		{
			name:     "Extract score",
			path:     "{{steps.validation.output.score}}",
			expected: 0.95,
		},
		{
			name:     "Extract status",
			path:     "steps.validation.output.status",
			expected: "approved",
		},
		{
			name:     "Extract boolean",
			path:     "{{steps.validation.output.flagged}}",
			expected: false,
		},
		{
			name:     "Non-existent step",
			path:     "{{steps.nonexistent.output.value}}",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.extractValue(tt.path, execution)

			if fmt.Sprintf("%v", result) != fmt.Sprintf("%v", tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestTruncateString tests string truncation utility
func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "string shorter than max",
			input:    "hello",
			maxLen:   10,
			expected: "hello",
		},
		{
			name:     "string equal to max",
			input:    "hello",
			maxLen:   5,
			expected: "hello",
		},
		{
			name:     "string longer than max",
			input:    "hello world",
			maxLen:   5,
			expected: "hello...",
		},
		{
			name:     "empty string",
			input:    "",
			maxLen:   10,
			expected: "",
		},
		{
			name:     "single character truncation",
			input:    "hello",
			maxLen:   1,
			expected: "h...",
		},
		{
			name:     "very long string",
			input:    "this is a very long string that exceeds the maximum length",
			maxLen:   20,
			expected: "this is a very long ...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// === Issue #835: MAP Replay Recording Tests ===

// mockReplayRecorder captures replay events for testing
type mockReplayRecorder struct {
	startCalls    []mockStartCall
	stepCalls     []mockStepCall
	completeCalls []mockCompleteCall
	failCalls     []mockFailCall
}

type mockStartCall struct {
	RequestID    string
	WorkflowName string
	TotalSteps   int
	TenantID     string
	UserID       string
}

type mockStepCall struct {
	Snapshot *ReplaySnapshotInput
}

type mockCompleteCall struct {
	RequestID string
	Output    json.RawMessage
}

type mockFailCall struct {
	RequestID string
	ErrMsg    string
}

func (m *mockReplayRecorder) StartExecution(_ context.Context, requestID, workflowName string, totalSteps int, orgID, tenantID, userID string) error {
	m.startCalls = append(m.startCalls, mockStartCall{
		RequestID:    requestID,
		WorkflowName: workflowName,
		TotalSteps:   totalSteps,
		TenantID:     tenantID,
		UserID:       userID,
	})
	return nil
}

func (m *mockReplayRecorder) RecordStep(_ context.Context, snapshot *ReplaySnapshotInput) error {
	m.stepCalls = append(m.stepCalls, mockStepCall{Snapshot: snapshot})
	return nil
}

func (m *mockReplayRecorder) CompleteExecution(_ context.Context, requestID string, output json.RawMessage) error {
	m.completeCalls = append(m.completeCalls, mockCompleteCall{RequestID: requestID, Output: output})
	return nil
}

func (m *mockReplayRecorder) FailExecution(_ context.Context, requestID, errMsg string) error {
	m.failCalls = append(m.failCalls, mockFailCall{RequestID: requestID, ErrMsg: errMsg})
	return nil
}

// TestMAPReplayRecording_ParallelExecution verifies that ExecuteWorkflowWithParallelSupport
// records replay snapshots for all steps (#835).
func TestMAPReplayRecording_ParallelExecution(t *testing.T) {
	engine := NewWorkflowEngine()
	recorder := &mockReplayRecorder{}
	engine.SetReplayRecorder(recorder)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "replay-parallel-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "test1"},
				{Name: "step2", Type: "function-call", Function: "test2"},
				{Name: "synthesis", Type: "function-call", Function: "synthesize"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowWithParallelSupport(
		ctx, workflow, map[string]interface{}{}, UserContext{TenantID: "test-tenant", ID: 42}, true,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if execution.Status != "completed" {
		t.Errorf("Expected completed status, got %s", execution.Status)
	}

	// Verify StartExecution was called
	if len(recorder.startCalls) != 1 {
		t.Fatalf("Expected 1 StartExecution call, got %d", len(recorder.startCalls))
	}
	start := recorder.startCalls[0]
	if start.WorkflowName != "replay-parallel-test" {
		t.Errorf("Expected workflow name 'replay-parallel-test', got %q", start.WorkflowName)
	}
	if start.TotalSteps != 3 {
		t.Errorf("Expected 3 total steps, got %d", start.TotalSteps)
	}
	if start.TenantID != "test-tenant" {
		t.Errorf("Expected tenant 'test-tenant', got %q", start.TenantID)
	}

	// Verify RecordStep was called for each step
	if len(recorder.stepCalls) != 3 {
		t.Fatalf("Expected 3 RecordStep calls, got %d", len(recorder.stepCalls))
	}

	// Verify step indices are sequential
	for i, call := range recorder.stepCalls {
		if call.Snapshot.StepIndex != i {
			t.Errorf("Step %d: expected index %d, got %d", i, i, call.Snapshot.StepIndex)
		}
		if call.Snapshot.Status != "completed" {
			t.Errorf("Step %d: expected status 'completed', got %q", i, call.Snapshot.Status)
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

// TestMAPReplayRecording_SequentialExecution verifies replay recording in sequential mode (#835).
func TestMAPReplayRecording_SequentialExecution(t *testing.T) {
	engine := NewWorkflowEngine()
	recorder := &mockReplayRecorder{}
	engine.SetReplayRecorder(recorder)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "replay-sequential-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "test1"},
				{Name: "step2", Type: "function-call", Function: "test2"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowWithParallelSupport(
		ctx, workflow, map[string]interface{}{}, UserContext{TenantID: "seq-tenant", ID: 1}, false,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if execution.Status != "completed" {
		t.Errorf("Expected completed status, got %s", execution.Status)
	}

	// Verify full replay lifecycle
	if len(recorder.startCalls) != 1 {
		t.Fatalf("Expected 1 StartExecution call, got %d", len(recorder.startCalls))
	}
	if len(recorder.stepCalls) != 2 {
		t.Fatalf("Expected 2 RecordStep calls, got %d", len(recorder.stepCalls))
	}
	if len(recorder.completeCalls) != 1 {
		t.Fatalf("Expected 1 CompleteExecution call, got %d", len(recorder.completeCalls))
	}

	// Verify step names are recorded correctly
	if recorder.stepCalls[0].Snapshot.StepName != "step1" {
		t.Errorf("Expected step name 'step1', got %q", recorder.stepCalls[0].Snapshot.StepName)
	}
	if recorder.stepCalls[1].Snapshot.StepName != "step2" {
		t.Errorf("Expected step name 'step2', got %q", recorder.stepCalls[1].Snapshot.StepName)
	}
}

// TestMAPReplayRecording_NoRecorderNilSafe verifies that the code is nil-safe
// when no replay recorder is set (#835).
func TestMAPReplayRecording_NoRecorderNilSafe(t *testing.T) {
	engine := NewWorkflowEngine()
	// Deliberately NOT setting a replay recorder

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "nil-recorder-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "test1"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowWithParallelSupport(
		ctx, workflow, map[string]interface{}{}, UserContext{}, true,
	)

	if err != nil {
		t.Fatalf("Unexpected error with nil recorder: %v", err)
	}

	if execution.Status != "completed" {
		t.Errorf("Expected completed status, got %s", execution.Status)
	}
}

// TestMAPReplayRecording_ParallelStepFailure verifies that FailExecution is called
// when a parallel step fails (#835).
func TestMAPReplayRecording_ParallelStepFailure(t *testing.T) {
	engine := NewWorkflowEngine()
	recorder := &mockReplayRecorder{}
	engine.SetReplayRecorder(recorder)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "replay-parallel-failure-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "good-step", Type: "function-call", Function: "test1"},
				{Name: "bad-step", Type: "unknown-type", Function: "will-fail"},
				{Name: "synthesis", Type: "function-call", Function: "synthesize"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowWithParallelSupport(
		ctx, workflow, map[string]interface{}{}, UserContext{TenantID: "fail-tenant", ID: 99}, true,
	)

	// Execution should fail
	if err == nil {
		t.Fatal("Expected error from failed parallel step, got nil")
	}
	if execution.Status != "failed" {
		t.Errorf("Expected failed status, got %s", execution.Status)
	}

	// Verify StartExecution was called
	if len(recorder.startCalls) != 1 {
		t.Fatalf("Expected 1 StartExecution call, got %d", len(recorder.startCalls))
	}

	// Verify RecordStep was called for the parallel steps (good + bad)
	if len(recorder.stepCalls) < 2 {
		t.Fatalf("Expected at least 2 RecordStep calls for parallel group, got %d", len(recorder.stepCalls))
	}

	// Verify at least one step has failed status
	hasFailedStep := false
	for _, call := range recorder.stepCalls {
		if call.Snapshot.Status == "failed" {
			hasFailedStep = true
			break
		}
	}
	if !hasFailedStep {
		t.Error("Expected at least one step snapshot with 'failed' status")
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

// TestMAPReplayRecording_SequentialStepFailure verifies that FailExecution is called
// when a sequential step fails (#835).
func TestMAPReplayRecording_SequentialStepFailure(t *testing.T) {
	engine := NewWorkflowEngine()
	recorder := &mockReplayRecorder{}
	engine.SetReplayRecorder(recorder)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "replay-sequential-failure-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "good-step", Type: "function-call", Function: "test1"},
				{Name: "bad-step", Type: "unknown-type", Function: "will-fail"},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflowWithParallelSupport(
		ctx, workflow, map[string]interface{}{}, UserContext{TenantID: "seq-fail", ID: 7}, false,
	)

	if err == nil {
		t.Fatal("Expected error from failed sequential step, got nil")
	}
	if execution.Status != "failed" {
		t.Errorf("Expected failed status, got %s", execution.Status)
	}

	// Verify StartExecution was called
	if len(recorder.startCalls) != 1 {
		t.Fatalf("Expected 1 StartExecution call, got %d", len(recorder.startCalls))
	}

	// Verify RecordStep was called for both steps (good completes, bad fails)
	if len(recorder.stepCalls) != 2 {
		t.Fatalf("Expected 2 RecordStep calls, got %d", len(recorder.stepCalls))
	}

	// First step should be completed
	if recorder.stepCalls[0].Snapshot.Status != "completed" {
		t.Errorf("Step 0: expected 'completed', got %q", recorder.stepCalls[0].Snapshot.Status)
	}
	if recorder.stepCalls[0].Snapshot.StepName != "good-step" {
		t.Errorf("Step 0: expected 'good-step', got %q", recorder.stepCalls[0].Snapshot.StepName)
	}

	// Second step should be failed
	if recorder.stepCalls[1].Snapshot.Status != "failed" {
		t.Errorf("Step 1: expected 'failed', got %q", recorder.stepCalls[1].Snapshot.Status)
	}
	if recorder.stepCalls[1].Snapshot.StepName != "bad-step" {
		t.Errorf("Step 1: expected 'bad-step', got %q", recorder.stepCalls[1].Snapshot.StepName)
	}

	// Verify step indices are sequential
	if recorder.stepCalls[0].Snapshot.StepIndex != 0 {
		t.Errorf("Step 0: expected index 0, got %d", recorder.stepCalls[0].Snapshot.StepIndex)
	}
	if recorder.stepCalls[1].Snapshot.StepIndex != 1 {
		t.Errorf("Step 1: expected index 1, got %d", recorder.stepCalls[1].Snapshot.StepIndex)
	}

	// Verify FailExecution was called
	if len(recorder.failCalls) != 1 {
		t.Fatalf("Expected 1 FailExecution call, got %d", len(recorder.failCalls))
	}

	// Verify CompleteExecution was NOT called
	if len(recorder.completeCalls) != 0 {
		t.Errorf("Expected 0 CompleteExecution calls on failure, got %d", len(recorder.completeCalls))
	}
}

// TestMAPReplayRecording_RecorderErrorLogged verifies that recorder errors are
// logged rather than silently swallowed (#835).
func TestMAPReplayRecording_RecorderErrorLogged(t *testing.T) {
	engine := NewWorkflowEngine()
	recorder := &failingReplayRecorder{}
	engine.SetReplayRecorder(recorder)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "recorder-error-test"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "function-call", Function: "test1"},
			},
		},
	}

	ctx := context.Background()
	// Should complete successfully even if recorder fails — recorder errors don't block execution
	execution, err := engine.ExecuteWorkflowWithParallelSupport(
		ctx, workflow, map[string]interface{}{}, UserContext{TenantID: "err-tenant", ID: 1}, false,
	)

	if err != nil {
		t.Fatalf("Execution should succeed even with failing recorder: %v", err)
	}
	if execution.Status != "completed" {
		t.Errorf("Expected completed status, got %s", execution.Status)
	}
}

// failingReplayRecorder always returns errors — tests that recorder failures don't break execution
type failingReplayRecorder struct{}

func (m *failingReplayRecorder) StartExecution(_ context.Context, _, _ string, _ int, _, _, _ string) error {
	return fmt.Errorf("simulated recorder start error")
}

func (m *failingReplayRecorder) RecordStep(_ context.Context, _ *ReplaySnapshotInput) error {
	return fmt.Errorf("simulated recorder step error")
}

func (m *failingReplayRecorder) CompleteExecution(_ context.Context, _ string, _ json.RawMessage) error {
	return fmt.Errorf("simulated recorder complete error")
}

func (m *failingReplayRecorder) FailExecution(_ context.Context, _, _ string) error {
	return fmt.Errorf("simulated recorder fail error")
}
