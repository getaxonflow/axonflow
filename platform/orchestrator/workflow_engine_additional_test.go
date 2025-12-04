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
	"testing"
)

// TestInitializeWithDependencies tests workflow engine initialization with external dependencies
func TestInitializeWithDependencies(t *testing.T) {
	engine := NewWorkflowEngine()

	// Test with nil router and client (graceful handling)
	engine.InitializeWithDependencies(nil, nil)

	// Should still have api-call processor registered
	if processor, exists := engine.stepProcessors["api-call"]; !exists || processor == nil {
		t.Error("api-call processor should be registered even with nil client")
	}

	// Should have connector-call processor registered
	if processor, exists := engine.stepProcessors["connector-call"]; !exists || processor == nil {
		t.Error("connector-call processor should be registered")
	}

	// llm-call processor should NOT be registered (router was nil)
	if _, exists := engine.stepProcessors["llm-call"]; exists {
		t.Error("llm-call processor should not be registered when router is nil")
	}
}

// TestInitializeWithDependencies_WithRouter tests initialization with LLM router
func TestInitializeWithDependencies_WithRouter(t *testing.T) {
	engine := NewWorkflowEngine()

	// Create real router with test config
	config := LLMRouterConfig{
		OpenAIKey: "test-key-init",
	}
	router := NewLLMRouter(config)

	engine.InitializeWithDependencies(router, nil)

	// Should have llm-call processor registered
	if processor, exists := engine.stepProcessors["llm-call"]; !exists || processor == nil {
		t.Error("llm-call processor should be registered when router is provided")
	}

	// Should have connector-call processor
	if processor, exists := engine.stepProcessors["connector-call"]; !exists || processor == nil {
		t.Error("connector-call processor should be registered")
	} else {
		_, ok := processor.(*MCPConnectorProcessor)
		if !ok {
			t.Error("connector-call processor should be MCPConnectorProcessor type")
		}
		// Note: fallbackProvider removed - business logic moved to clients
	}
}

// TestListRecentExecutions tests listing recent workflow executions
func TestListRecentExecutions(t *testing.T) {
	engine := NewWorkflowEngine()

	// Test with various limits
	limits := []int{0, 10, 100}

	for _, limit := range limits {
		executions, err := engine.ListRecentExecutions(limit)

		if err != nil {
			t.Errorf("ListRecentExecutions(%d) unexpected error: %v", limit, err)
		}

		if executions == nil {
			t.Errorf("ListRecentExecutions(%d) should return empty slice, not nil", limit)
		}

		// Currently returns empty list (demo implementation)
		if len(executions) != 0 {
			t.Errorf("ListRecentExecutions(%d) expected 0 executions, got %d", limit, len(executions))
		}
	}
}

// TestIsSynthesisStep_Additional tests synthesis step detection
func TestIsSynthesisStep_Additional(t *testing.T) {
	engine := NewWorkflowEngine()

	tests := []struct {
		stepName string
		want     bool
	}{
		// Synthesis steps (should return true)
		{"synthesize_results", true},
		{"Synthesize Final Answer", true},
		{"combine_data", true},
		{"Combine Results", true},
		{"final_output", true},
		{"Final Summary", true},
		{"summary_step", true},
		{"Generate Summary", true},
		{"aggregate_results", true},
		{"Aggregate Data", true},
		{"merge_responses", true},
		{"Merge All", true},

		// Non-synthesis steps (should return false)
		{"fetch_data", false},
		{"call_api", false},
		{"process_request", false},
		{"validate_input", false},
		{"", false},
		{"step1", false},
		{"llm_call", false},
	}

	for _, tt := range tests {
		t.Run(tt.stepName, func(t *testing.T) {
			got := engine.isSynthesisStep(tt.stepName)
			if got != tt.want {
				t.Errorf("isSynthesisStep(%q) = %v, want %v", tt.stepName, got, tt.want)
			}
		})
	}
}

// Note: Tests for generateFallbackSynthesis removed - business logic moved to clients

// TestParseStructuredResponse tests JSON response parsing
func TestParseStructuredResponse(t *testing.T) {
	processor := NewLLMCallProcessor(nil)

	tests := []struct {
		name      string
		response  interface{}
		wantErr   bool
		wantValue string
	}{
		{
			name:      "valid JSON string",
			response:  `{"result": "success", "data": "test"}`,
			wantErr:   false,
			wantValue: "success",
		},
		{
			name:      "valid JSON with nested objects",
			response:  `{"status": "ok", "user": {"name": "John", "age": 30}}`,
			wantErr:   false,
			wantValue: "ok",
		},
		{
			name:     "invalid JSON string",
			response: `{invalid json}`,
			wantErr:  true,
		},
		{
			name:     "non-string response",
			response: 12345,
			wantErr:  true,
		},
		{
			name:     "empty string",
			response: ``,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := processor.parseStructuredResponse(tt.response)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseStructuredResponse() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseStructuredResponse() unexpected error: %v", err)
				return
			}

			if parsed == nil {
				t.Error("parseStructuredResponse() returned nil parsed result")
				return
			}

			// For valid JSON, check that we got expected value
			if tt.wantValue != "" {
				// First test has "result": "success"
				if tt.name == "valid JSON string" {
					if result, ok := parsed["result"].(string); !ok || result != tt.wantValue {
						t.Errorf("Expected result=%s, got %v", tt.wantValue, parsed["result"])
					}
				}
				// Second test has "status": "ok"
				if tt.name == "valid JSON with nested objects" {
					if status, ok := parsed["status"].(string); !ok || status != tt.wantValue {
						t.Errorf("Expected status=%s, got %v", tt.wantValue, parsed["status"])
					}
				}
			}
		})
	}
}

// TestWorkflowEngineIsHealthy tests health check
func TestWorkflowEngineIsHealthy_Initialized(t *testing.T) {
	engine := NewWorkflowEngine()

	// Engine created with NewWorkflowEngine should have some processors
	if !engine.IsHealthy() {
		t.Error("Newly created WorkflowEngine should be healthy")
	}
}

// TestWorkflowEngineIsHealthy_NoProcessors tests unhealthy state
func TestWorkflowEngineIsHealthy_NoProcessors(t *testing.T) {
	// Create engine with no processors
	engine := &WorkflowEngine{
		storage:        NewInMemoryWorkflowStorage(),
		stepProcessors: make(map[string]StepProcessor),
	}

	if engine.IsHealthy() {
		t.Error("WorkflowEngine with no processors should be unhealthy")
	}
}

// TestWorkflowEngineIsHealthy_NoStorage tests unhealthy state without storage
func TestWorkflowEngineIsHealthy_NoStorage(t *testing.T) {
	// Create engine with nil storage
	engine := &WorkflowEngine{
		storage:        nil,
		stepProcessors: map[string]StepProcessor{"test": nil},
	}

	if engine.IsHealthy() {
		t.Error("WorkflowEngine with nil storage should be unhealthy")
	}
}
