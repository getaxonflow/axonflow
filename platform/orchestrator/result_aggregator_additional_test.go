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
	"strings"
	"testing"
)

// Additional tests for result_aggregator.go to reach 80%+ coverage
// These tests complement phase7_test.go by covering untested functions

// Test extractSynthesizedResult with different response types
func TestResultAggregator_ExtractSynthesizedResult(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
	aggregator := NewResultAggregator(router)

	tests := []struct {
		name      string
		response  interface{}
		want      string
		wantError bool
	}{
		{
			name:      "LLMResponse type",
			response:  &LLMResponse{Content: "synthesized content"},
			want:      "synthesized content",
			wantError: false,
		},
		{
			name:      "string type",
			response:  "direct string response",
			want:      "direct string response",
			wantError: false,
		},
		{
			name:      "invalid type - int",
			response:  12345,
			want:      "",
			wantError: true,
		},
		{
			name:      "invalid type - map",
			response:  map[string]string{"key": "value"},
			want:      "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := aggregator.extractSynthesizedResult(tt.response)

			if (err != nil) != tt.wantError {
				t.Errorf("extractSynthesizedResult() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if result != tt.want {
				t.Errorf("extractSynthesizedResult() = %q, want %q", result, tt.want)
			}
		})
	}
}

// Test AggregateWithCustomPrompt with successful synthesis
func TestResultAggregator_AggregateWithCustomPrompt_Success(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
	aggregator := NewResultAggregator(router)

	taskResults := []StepExecution{
		{
			Name:        "task1",
			Status:      "completed",
			ProcessTime: "10ms",
			Output: map[string]interface{}{
				"response": &LLMResponse{Content: "Task 1 result"},
			},
		},
		{
			Name:        "task2",
			Status:      "completed",
			ProcessTime: "20ms",
			Output: map[string]interface{}{
				"response": &LLMResponse{Content: "Task 2 result"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{
		TenantID: "test-tenant",
		Role:     "user",
		Email:    "test@example.com",
	}
	customPrompt := "Synthesize these results in a specific format: concise bullet points"

	// Will fall back to concatenation since we're using invalid API key
	result, err := aggregator.AggregateWithCustomPrompt(ctx, taskResults, customPrompt, user)

	if err != nil {
		t.Fatalf("AggregateWithCustomPrompt() error = %v", err)
	}

	// Should use fallback concatenation
	if !strings.Contains(result, "Task 1 result") || !strings.Contains(result, "Task 2 result") {
		t.Error("Expected result to contain task results via fallback")
	}
}

// Test AggregateWithCustomPrompt with no successful tasks
func TestResultAggregator_AggregateWithCustomPrompt_NoSuccessfulTasks(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
	aggregator := NewResultAggregator(router)

	taskResults := []StepExecution{
		{
			Name:        "task1",
			Status:      "failed",
			ProcessTime: "10ms",
			Error:       "Task failed",
		},
	}

	ctx := context.Background()
	user := UserContext{
		TenantID: "test-tenant",
		Role:     "user",
		Email:    "test@example.com",
	}
	customPrompt := "Synthesize these results"

	_, err := aggregator.AggregateWithCustomPrompt(ctx, taskResults, customPrompt, user)

	if err == nil {
		t.Error("AggregateWithCustomPrompt() should return error for no successful tasks")
	}

	expectedError := "no successful task results"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Error should contain '%s', got: %s", expectedError, err.Error())
	}
}

// Test AggregateWithCustomPrompt with LLM failure (fallback to concatenation)
func TestResultAggregator_AggregateWithCustomPrompt_LLMFailure(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey:    "invalid-key",
		AnthropicKey: "invalid-key",
	}
	router := NewLLMRouter(config)
	aggregator := NewResultAggregator(router)

	taskResults := []StepExecution{
		{
			Name:        "task1",
			Status:      "completed",
			ProcessTime: "10ms",
			Output: map[string]interface{}{
				"response": &LLMResponse{Content: "Result 1"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{
		TenantID: "test-tenant",
		Role:     "user",
		Email:    "test@example.com",
	}
	customPrompt := "Custom synthesis prompt"

	result, err := aggregator.AggregateWithCustomPrompt(ctx, taskResults, customPrompt, user)

	if err != nil {
		t.Fatalf("AggregateWithCustomPrompt() should not error on LLM failure (fallback), got: %v", err)
	}

	// Should use simple concatenation fallback
	if !strings.Contains(result, "Result 1") {
		t.Error("Result should contain task result via fallback")
	}

	if !strings.Contains(result, "Custom aggregation") {
		t.Error("Result should reference custom aggregation in fallback")
	}
}

// Test simpleConcatenation with various output formats
func TestResultAggregator_SimpleConcatenation_VariousFormats(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
	aggregator := NewResultAggregator(router)

	taskResults := []StepExecution{
		{
			Name:        "task1",
			ProcessTime: "10ms",
			Output: map[string]interface{}{
				"response": &LLMResponse{Content: "LLMResponse content"},
			},
		},
		{
			Name:        "task2",
			ProcessTime: "20ms",
			Output: map[string]interface{}{
				"response": "String response",
			},
		},
		{
			Name:        "task3",
			ProcessTime: "15ms",
			Output: map[string]interface{}{
				"result": "Different key",
			},
		},
	}

	result := aggregator.simpleConcatenation(taskResults, "Test query")

	// Should contain original query
	if !strings.Contains(result, "Test query") {
		t.Error("Concatenation should contain original query")
	}

	// Should contain all task names
	if !strings.Contains(result, "task1") {
		t.Error("Concatenation should contain task1")
	}
	if !strings.Contains(result, "task2") {
		t.Error("Concatenation should contain task2")
	}
	if !strings.Contains(result, "task3") {
		t.Error("Concatenation should contain task3")
	}

	// Should contain LLMResponse content
	if !strings.Contains(result, "LLMResponse content") {
		t.Error("Concatenation should contain LLMResponse content")
	}

	// Should contain string response
	if !strings.Contains(result, "String response") {
		t.Error("Concatenation should contain string response")
	}

	// Should note it's using simple concatenation
	if !strings.Contains(result, "simple concatenation") {
		t.Error("Concatenation should note it's using simple concatenation")
	}
}

// Test AggregateResults with mixed success/failure and output types
func TestResultAggregator_AggregateResults_MixedOutputTypes(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
	aggregator := NewResultAggregator(router)

	taskResults := []StepExecution{
		{
			Name:        "task1",
			Status:      "completed",
			ProcessTime: "10ms",
			Output: map[string]interface{}{
				"response": &LLMResponse{Content: "Success 1"},
			},
		},
		{
			Name:        "task2",
			Status:      "failed",
			ProcessTime: "5ms",
			Error:       "Task failed",
		},
		{
			Name:        "task3",
			Status:      "completed",
			ProcessTime: "15ms",
			Output: map[string]interface{}{
				"response": "String result",
			},
		},
		{
			Name:        "task4",
			Status:      "completed",
			ProcessTime: "12ms",
			Output: map[string]interface{}{
				"data": "Different key",
			},
		},
	}

	ctx := context.Background()
	user := UserContext{
		TenantID: "test-tenant",
		Role:     "user",
		Email:    "test@example.com",
	}

	result, err := aggregator.AggregateResults(ctx, taskResults, "test query", user)

	if err != nil {
		t.Fatalf("AggregateResults() error = %v", err)
	}

	// Should only aggregate successful results (task1, task3, task4)
	if result == "" {
		t.Error("AggregateResults() should return non-empty result for mixed results")
	}

	// Should contain successful task results via fallback
	if !strings.Contains(result, "Success 1") || !strings.Contains(result, "String result") {
		t.Error("Result should contain successful task outputs")
	}
}

// Test buildSynthesisPrompt with edge cases
func TestResultAggregator_BuildSynthesisPrompt_EdgeCases(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
	aggregator := NewResultAggregator(router)

	tests := []struct {
		name    string
		query   string
		results []StepExecution
	}{
		{
			name:  "Single task with LLMResponse",
			query: "What is the weather?",
			results: []StepExecution{
				{
					Name:        "weather_check",
					Status:      "completed",
					ProcessTime: "100ms",
					Output: map[string]interface{}{
						"response": &LLMResponse{Content: "It's sunny"},
					},
				},
			},
		},
		{
			name:  "Single task with string output",
			query: "Get status",
			results: []StepExecution{
				{
					Name:        "status_check",
					Status:      "completed",
					ProcessTime: "50ms",
					Output: map[string]interface{}{
						"response": "All systems operational",
					},
				},
			},
		},
		{
			name:  "Single task with no response key",
			query: "Process data",
			results: []StepExecution{
				{
					Name:        "data_processor",
					Status:      "completed",
					ProcessTime: "75ms",
					Output: map[string]interface{}{
						"data": "Processed data",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prompt := aggregator.buildSynthesisPrompt(tt.query, tt.results)

			// Check prompt contains key elements
			if !strings.Contains(prompt, tt.query) {
				t.Error("Prompt should contain original query")
			}

			if !strings.Contains(prompt, tt.results[0].Name) {
				t.Error("Prompt should contain task name")
			}

			if !strings.Contains(prompt, "synthesize") || !strings.Contains(prompt, "Synthesize") {
				t.Error("Prompt should contain synthesis instructions")
			}

			if !strings.Contains(prompt, "Task 1:") {
				t.Error("Prompt should label tasks")
			}
		})
	}
}
