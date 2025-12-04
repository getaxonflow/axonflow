// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
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
	processor := NewConditionalProcessor()
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
	mockRouter := &LLMRouter{
		providers: map[string]LLMProvider{
			"test": &TestMockProvider{
				name:         "test",
				healthy:      true,
				responseTime: 10 * time.Millisecond,
				costPerToken: 0.00001,
			},
		},
		weights: map[string]float64{
			"test": 1.0,
		},
		loadBalancer:   NewLoadBalancer(),
		metricsTracker: NewProviderMetricsTracker(),
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
	processor := NewConditionalProcessor()

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
