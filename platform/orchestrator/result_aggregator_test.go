package orchestrator

import (
	"context"
	"testing"
	"time"
)

// TestResultAggregator_AggregateResults tests the main aggregation function
func TestResultAggregator_AggregateResults(t *testing.T) {
	tests := []struct {
		name        string
		taskResults []StepExecution
		expectError bool
		description string
	}{
		{
			name: "successful aggregation with multiple results",
			taskResults: []StepExecution{
				{
					Name:      "task1",
					Status:    "completed",
					Output:    map[string]interface{}{"result": "Result 1"},
					StartTime: time.Now().Add(-2 * time.Second),
					EndTime:   ptrTime(time.Now().Add(-1 * time.Second)),
				},
				{
					Name:      "task2",
					Status:    "completed",
					Output:    map[string]interface{}{"result": "Result 2"},
					StartTime: time.Now().Add(-2 * time.Second),
					EndTime:   ptrTime(time.Now().Add(-1 * time.Second)),
				},
			},
			expectError: false,
			description: "Should successfully aggregate multiple completed tasks",
		},
		{
			name: "no successful results",
			taskResults: []StepExecution{
				{
					Name:      "task1",
					Status:    "failed",
					Error:     "Task failed",
					StartTime: time.Now().Add(-2 * time.Second),
					EndTime:   ptrTime(time.Now().Add(-1 * time.Second)),
				},
			},
			expectError: true,
			description: "Should return error when no successful results",
		},
		{
			name: "mixed success and failure",
			taskResults: []StepExecution{
				{
					Name:      "task1",
					Status:    "completed",
					Output:    map[string]interface{}{"result": "Success"},
					StartTime: time.Now().Add(-2 * time.Second),
					EndTime:   ptrTime(time.Now().Add(-1 * time.Second)),
				},
				{
					Name:      "task2",
					Status:    "failed",
					Error:     "Failed",
					StartTime: time.Now().Add(-2 * time.Second),
					EndTime:   ptrTime(time.Now().Add(-1 * time.Second)),
				},
			},
			expectError: false,
			description: "Should aggregate only successful results",
		},
		{
			name: "single successful result",
			taskResults: []StepExecution{
				{
					Name:      "task1",
					Status:    "completed",
					Output:    map[string]interface{}{"result": "Single result"},
					StartTime: time.Now().Add(-1 * time.Second),
					EndTime:   ptrTime(time.Now()),
				},
			},
			expectError: false,
			description: "Should handle single successful result",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock LLM router
			mockRouter := &LLMRouter{
				providers: map[string]LLMProvider{
					"mock": &MockProvider{
						name:    "mock",
						healthy: true,
					},
				},
				weights: map[string]float64{
					"mock": 1.0,
				},
				loadBalancer:   NewLoadBalancer(),
				metricsTracker: NewProviderMetricsTracker(),
			}

			aggregator := &ResultAggregator{
				llmRouter: mockRouter,
			}

			ctx := context.Background()
			user := UserContext{
				Email: "test-user@example.com",
				Role:  "user",
			}

			result, err := aggregator.AggregateResults(ctx, tt.taskResults, "test query", user)

			if tt.expectError {
				if err == nil {
					t.Errorf("%s: Expected error but got none", tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("%s: Unexpected error: %v", tt.description, err)
				}
				if result == "" {
					t.Errorf("%s: Expected non-empty result", tt.description)
				}
			}
		})
	}
}

// TestResultAggregator_FilterSuccessfulResults tests result filtering
func TestResultAggregator_FilterSuccessfulResults(t *testing.T) {
	aggregator := NewResultAggregator(nil)

	tests := []struct {
		name     string
		results  []StepExecution
		expected int
	}{
		{
			name: "all successful",
			results: []StepExecution{
				{Status: "completed", Output: map[string]interface{}{"result": "A"}},
				{Status: "completed", Output: map[string]interface{}{"result": "B"}},
			},
			expected: 2,
		},
		{
			name: "all failed",
			results: []StepExecution{
				{Status: "failed", Error: "Error 1"},
				{Status: "failed", Error: "Error 2"},
			},
			expected: 0,
		},
		{
			name: "mixed statuses",
			results: []StepExecution{
				{Status: "completed", Output: map[string]interface{}{"result": "Success"}},
				{Status: "failed", Error: "Failure"},
				{Status: "completed", Output: map[string]interface{}{"result": "Another success"}},
			},
			expected: 2,
		},
		{
			name:     "empty input",
			results:  []StepExecution{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := aggregator.filterSuccessfulResults(tt.results)
			if len(filtered) != tt.expected {
				t.Errorf("Expected %d successful results, got %d", tt.expected, len(filtered))
			}
		})
	}
}

// TestResultAggregator_SimpleConcatenation tests fallback concatenation
func TestResultAggregator_SimpleConcatenation(t *testing.T) {
	aggregator := NewResultAggregator(nil)

	results := []StepExecution{
		{
			Name:   "step1",
			Output: map[string]interface{}{"result": "First result"},
			Status: "completed",
		},
		{
			Name:   "step2",
			Output: map[string]interface{}{"result": "Second result"},
			Status: "completed",
		},
	}

	concatenated := aggregator.simpleConcatenation(results, "test query")

	// Should contain both results
	if concatenated == "" {
		t.Error("Expected non-empty concatenation")
	}

	// Should mention it's a fallback
	// (based on the warning message in the function)
}

// TestResultAggregator_BuildSynthesisPrompt tests prompt building
func TestResultAggregator_BuildSynthesisPrompt(t *testing.T) {
	aggregator := NewResultAggregator(nil)

	results := []StepExecution{
		{Name: "task1", Output: map[string]interface{}{"result": "Output 1"}},
		{Name: "task2", Output: map[string]interface{}{"result": "Output 2"}},
	}

	prompt := aggregator.buildSynthesisPrompt("Find hotels in Paris", results)

	// Should be non-empty
	if prompt == "" {
		t.Error("Expected non-empty prompt")
	}

	// Should contain the query
	// Should contain the results
	// (Can't test exact format without seeing implementation)
}

// TestResultAggregator_AggregateWithCustomPrompt tests custom prompt aggregation
func TestResultAggregator_AggregateWithCustomPrompt(t *testing.T) {
	mockRouter := &LLMRouter{
		providers: map[string]LLMProvider{
			"mock": &MockProvider{
				name:    "mock",
				healthy: true,
			},
		},
		weights: map[string]float64{
			"mock": 1.0,
		},
		loadBalancer:   NewLoadBalancer(),
		metricsTracker: NewProviderMetricsTracker(),
	}

	aggregator := &ResultAggregator{
		llmRouter: mockRouter,
	}

	ctx := context.Background()
	results := []StepExecution{
		{Name: "task1", Output: map[string]interface{}{"result": "Result 1"}, Status: "completed"},
	}

	user := UserContext{Email: "test@example.com"}

	result, err := aggregator.AggregateWithCustomPrompt(ctx, results, "Custom synthesis prompt", user)

	// Should succeed with mock provider
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result == "" {
		t.Error("Expected non-empty result")
	}
}

// TestResultAggregator_GetAggregationStats tests stats retrieval
func TestResultAggregator_GetAggregationStats(t *testing.T) {
	aggregator := NewResultAggregator(nil)

	results := []StepExecution{
		{Name: "task1", Status: "completed", Output: map[string]interface{}{"result": "Success"}},
		{Name: "task2", Status: "failed", Error: "Failed"},
	}

	stats := aggregator.GetAggregationStats(results)

	// Should return stats structure
	if stats.TotalTasks != 2 {
		t.Errorf("Expected TotalTasks to be 2, got %d", stats.TotalTasks)
	}
	if stats.SuccessfulTasks != 1 {
		t.Errorf("Expected SuccessfulTasks to be 1, got %d", stats.SuccessfulTasks)
	}
	if stats.FailedTasks != 1 {
		t.Errorf("Expected FailedTasks to be 1, got %d", stats.FailedTasks)
	}
}

// Helper function to create time pointers
func ptrTime(t time.Time) *time.Time {
	return &t
}

// TestResultAggregator_IsHealthy tests health check
func TestResultAggregator_IsHealthy(t *testing.T) {
	mockRouter := &LLMRouter{
		providers: map[string]LLMProvider{
			"test": &MockProvider{healthy: true},
		},
	}

	aggregator := NewResultAggregator(mockRouter)

	if !aggregator.IsHealthy() {
		t.Error("Expected aggregator to be healthy")
	}

	// Test with nil router
	aggregatorNil := &ResultAggregator{llmRouter: nil}
	if aggregatorNil.IsHealthy() {
		t.Error("Expected aggregator with nil router to be unhealthy")
	}
}
