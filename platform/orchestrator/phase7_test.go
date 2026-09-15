// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Result Aggregator Tests
// ============================================================================

// TestNewResultAggregator verifies proper initialization
func TestNewResultAggregator(t *testing.T) {
	router := NewMockLLMRouter()

	aggregator := NewResultAggregator(router)

	if aggregator == nil {
		t.Fatal("Expected aggregator to be initialized")
	}

	if aggregator.llmRouter == nil {
		t.Error("Expected llmRouter to be set")
	}

	if !aggregator.IsHealthy() {
		t.Error("Expected aggregator to be healthy")
	}
}

// TestFilterSuccessfulResults verifies filtering logic
func TestFilterSuccessfulResults(t *testing.T) {
	router := NewMockLLMRouter()
	aggregator := NewResultAggregator(router)

	taskResults := []StepExecution{
		{
			Name:   "task1",
			Status: "completed",
			Output: map[string]interface{}{"result": "Result 1"},
		},
		{
			Name:   "task2",
			Status: "failed",
			Error:  "Error occurred",
		},
		{
			Name:   "task3",
			Status: "completed",
			Output: map[string]interface{}{"result": "Result 3"},
		},
	}

	successful := aggregator.filterSuccessfulResults(taskResults)

	if len(successful) != 2 {
		t.Errorf("Expected 2 successful results, got %d", len(successful))
	}

	if successful[0].Name != "task1" || successful[1].Name != "task3" {
		t.Error("Expected task1 and task3 to be filtered")
	}
}

// TestSimpleConcatenation verifies fallback concatenation
func TestSimpleConcatenation(t *testing.T) {
	router := NewMockLLMRouter()
	aggregator := NewResultAggregator(router)

	taskResults := []StepExecution{
		{
			Name:   "task1",
			Status: "completed",
			Output: map[string]interface{}{"result": "Flight search: Found 5 options"},
		},
		{
			Name:   "task2",
			Status: "completed",
			Output: map[string]interface{}{"result": "Hotel search: Found 10 hotels"},
		},
	}

	result := aggregator.simpleConcatenation(taskResults, "Plan a trip")

	if !strings.Contains(result, "Flight search") {
		t.Error("Expected concatenated result to contain flight search")
	}

	if !strings.Contains(result, "Hotel search") {
		t.Error("Expected concatenated result to contain hotel search")
	}

	if !strings.Contains(result, "Plan a trip") {
		t.Error("Expected result to reference original query")
	}
}

// TestBuildSynthesisPromptResultAggregator verifies synthesis prompt construction
func TestBuildSynthesisPromptResultAggregator(t *testing.T) {
	router := NewMockLLMRouter()
	aggregator := NewResultAggregator(router)

	taskResults := []StepExecution{
		{
			Name:   "flight_search",
			Status: "completed",
			Output: map[string]interface{}{"result": "5 flights found"},
		},
		{
			Name:   "hotel_search",
			Status: "completed",
			Output: map[string]interface{}{"result": "10 hotels found"},
		},
	}

	prompt := aggregator.buildSynthesisPrompt("Plan a vacation", taskResults)

	if !strings.Contains(prompt, "Plan a vacation") {
		t.Error("Expected prompt to contain original query")
	}

	if !strings.Contains(prompt, "flight_search") {
		t.Error("Expected prompt to contain task name")
	}

	if !strings.Contains(prompt, "5 flights found") {
		t.Error("Expected prompt to contain task result")
	}
}

// TestAggregateResultsWithFallback tests fallback to concatenation
func TestAggregateResultsWithFallback(t *testing.T) {
	// Create a mock router that simulates an error condition
	router := NewMockLLMRouter()
	router.RouteError = fmt.Errorf("provider error")
	aggregator := NewResultAggregator(router)

	ctx := context.Background()

	taskResults := []StepExecution{
		{
			Name:   "task1",
			Status: "completed",
			Output: map[string]interface{}{"result": "Result 1"},
		},
		{
			Name:   "task2",
			Status: "completed",
			Output: map[string]interface{}{"result": "Result 2"},
		},
	}

	user := UserContext{
		TenantID: "test-tenant",
		Role:     "user",
		Email:    "test@example.com",
	}

	result, err := aggregator.AggregateResults(ctx, taskResults, "Test query", user)

	// Should fall back to concatenation when LLM fails
	if err != nil {
		t.Fatalf("AggregateResults should not error with fallback: %v", err)
	}

	if !strings.Contains(result, "Result 1") || !strings.Contains(result, "Result 2") {
		t.Error("Expected fallback concatenation to include all results")
	}
}

// TestGetAggregationStats verifies stats calculation
func TestGetAggregationStats(t *testing.T) {
	router := NewMockLLMRouter()
	aggregator := NewResultAggregator(router)

	now := time.Now()
	endTime1 := now
	endTime2 := now
	endTime3 := now

	taskResults := []StepExecution{
		{
			Name:      "task1",
			Status:    "completed",
			StartTime: now.Add(-100 * time.Millisecond),
			EndTime:   &endTime1,
		},
		{
			Name:      "task2",
			Status:    "failed",
			StartTime: now.Add(-50 * time.Millisecond),
			EndTime:   &endTime2,
		},
		{
			Name:      "task3",
			Status:    "completed",
			StartTime: now.Add(-75 * time.Millisecond),
			EndTime:   &endTime3,
		},
	}

	stats := aggregator.GetAggregationStats(taskResults)

	if stats.TotalTasks != 3 {
		t.Errorf("Expected 3 total tasks, got %d", stats.TotalTasks)
	}

	if stats.SuccessfulTasks != 2 {
		t.Errorf("Expected 2 successful tasks, got %d", stats.SuccessfulTasks)
	}

	if stats.FailedTasks != 1 {
		t.Errorf("Expected 1 failed task, got %d", stats.FailedTasks)
	}

	expectedRate := 66.67
	if stats.SuccessRate < expectedRate-1 || stats.SuccessRate > expectedRate+1 {
		t.Errorf("Expected success rate around %.2f%%, got %.2f%%", expectedRate, stats.SuccessRate)
	}
}

// TestAggregateEmptyResults verifies handling of empty results
func TestAggregateEmptyResults(t *testing.T) {
	router := NewMockLLMRouter()
	aggregator := NewResultAggregator(router)

	ctx := context.Background()
	user := UserContext{
		TenantID: "test-tenant",
		Role:     "user",
		Email:    "test@example.com",
	}

	// Empty task results
	taskResults := []StepExecution{}

	result, err := aggregator.AggregateResults(ctx, taskResults, "Test query", user)

	// Empty results should return error
	if err == nil {
		t.Error("Expected error for empty results")
	}

	if result != "" {
		t.Logf("Got result even with error: %s", result)
	}
}

// ============================================================================
// Metrics Collector Tests
// ============================================================================

// TestNewMetricsCollector verifies initialization
func TestNewMetricsCollector(t *testing.T) {
	collector := NewMetricsCollector()
	defer collector.Close()

	if collector == nil {
		t.Fatal("Expected collector to be initialized")
	}

	if collector.metrics == nil {
		t.Error("Expected metrics to be initialized")
	}

	if collector.metrics.RequestMetrics == nil {
		t.Error("Expected RequestMetrics map to be initialized")
	}

	if collector.metrics.ProviderMetrics == nil {
		t.Error("Expected ProviderMetrics map to be initialized")
	}
}

// TestRecordRequest verifies request recording
func TestRecordRequest(t *testing.T) {
	collector := NewMetricsCollector()
	defer collector.Close()

	// Record multiple requests
	collector.RecordRequest("sql", "openai", 50*time.Millisecond)
	collector.RecordRequest("sql", "openai", 100*time.Millisecond)
	collector.RecordRequest("chat", "anthropic", 75*time.Millisecond)

	metrics := collector.GetMetrics()

	// Verify SQL requests
	sqlMetrics, exists := metrics.RequestMetrics["sql"]
	if !exists {
		t.Fatal("Expected sql metrics to exist")
	}

	if sqlMetrics.TotalRequests != 2 {
		t.Errorf("Expected 2 SQL requests, got %d", sqlMetrics.TotalRequests)
	}

	// Verify chat requests
	chatMetrics, exists := metrics.RequestMetrics["chat"]
	if !exists {
		t.Fatal("Expected chat metrics to exist")
	}

	if chatMetrics.TotalRequests != 1 {
		t.Errorf("Expected 1 chat request, got %d", chatMetrics.TotalRequests)
	}
}

// TestRecordBlockedRequest verifies blocked request tracking
func TestRecordBlockedRequest(t *testing.T) {
	collector := NewMetricsCollector()
	defer collector.Close()

	collector.RecordBlockedRequest("sql", "sql_injection")
	collector.RecordBlockedRequest("sql", "sql_injection")
	collector.RecordBlockedRequest("sql", "dangerous_query")

	metrics := collector.GetMetrics()

	if metrics.PolicyMetrics.BlockedByPolicy != 3 {
		t.Errorf("Expected 3 blocked requests, got %d", metrics.PolicyMetrics.BlockedByPolicy)
	}

	sqlInjectionCount, exists := metrics.PolicyMetrics.PolicyHitRate["sql_injection"]
	if !exists || sqlInjectionCount != 2 {
		t.Errorf("Expected 2 sql_injection blocks, got %d", sqlInjectionCount)
	}
}

// TestRecordPolicyEvaluation verifies policy evaluation tracking
func TestRecordPolicyEvaluation(t *testing.T) {
	collector := NewMetricsCollector()
	defer collector.Close()

	collector.RecordPolicyEvaluation(5*time.Millisecond, 0.25, []string{"policy1"})
	collector.RecordPolicyEvaluation(10*time.Millisecond, 0.75, []string{"policy2"})
	collector.RecordPolicyEvaluation(15*time.Millisecond, 0.90, []string{"policy3"})

	metrics := collector.GetMetrics()

	if metrics.PolicyMetrics.TotalEvaluations != 3 {
		t.Errorf("Expected 3 policy evaluations, got %d", metrics.PolicyMetrics.TotalEvaluations)
	}

	// Verify risk bucketing
	// 0.25 → "low" (score < 0.4)
	// 0.75 → "high" (0.6 <= score < 0.8)
	// 0.90 → "very_high" (score >= 0.8)

	if metrics.PolicyMetrics.RiskScoreDistribution["low"] != 1 {
		t.Errorf("Expected 1 low-risk evaluation, got %d", metrics.PolicyMetrics.RiskScoreDistribution["low"])
	}

	if metrics.PolicyMetrics.RiskScoreDistribution["high"] != 1 {
		t.Errorf("Expected 1 high-risk evaluation, got %d", metrics.PolicyMetrics.RiskScoreDistribution["high"])
	}

	if metrics.PolicyMetrics.RiskScoreDistribution["very_high"] != 1 {
		t.Errorf("Expected 1 very_high-risk evaluation, got %d", metrics.PolicyMetrics.RiskScoreDistribution["very_high"])
	}
}

// TestRecordRedaction verifies redaction tracking
func TestRecordRedaction(t *testing.T) {
	collector := NewMetricsCollector()
	defer collector.Close()

	// RecordRedaction takes field count, not type
	collector.RecordRedaction(2) // 2 fields redacted
	collector.RecordRedaction(1) // 1 field redacted
	collector.RecordRedaction(3) // 3 fields redacted

	metrics := collector.GetMetrics()

	expectedTotal := int64(6) // 2 + 1 + 3
	if metrics.PolicyMetrics.RedactionCount != expectedTotal {
		t.Errorf("Expected %d total redactions, got %d", expectedTotal, metrics.PolicyMetrics.RedactionCount)
	}
}

// TestRecordProviderUsage verifies provider usage tracking
func TestRecordProviderUsage(t *testing.T) {
	collector := NewMetricsCollector()
	defer collector.Close()

	collector.RecordProviderUsage("openai", 1000, 0.02)     // 1000 tokens, $0.02
	collector.RecordProviderUsage("openai", 1500, 0.03)     // 1500 tokens, $0.03
	collector.RecordProviderUsage("anthropic", 1200, 0.025) // 1200 tokens, $0.025

	metrics := collector.GetMetrics()

	// Verify OpenAI metrics - RecordProviderUsage only tracks tokens and cost, not request count
	openaiMetrics, exists := metrics.ProviderMetrics["openai"]
	if !exists {
		t.Fatal("Expected OpenAI metrics to exist")
	}

	if openaiMetrics.TotalTokens != 2500 {
		t.Errorf("Expected 2500 total tokens, got %d", openaiMetrics.TotalTokens)
	}

	expectedCost := 0.05 // 0.02 + 0.03
	if openaiMetrics.TotalCost < expectedCost-0.001 || openaiMetrics.TotalCost > expectedCost+0.001 {
		t.Errorf("Expected total cost around %.3f, got %.3f", expectedCost, openaiMetrics.TotalCost)
	}

	// Verify Anthropic metrics
	anthropicMetrics, exists := metrics.ProviderMetrics["anthropic"]
	if !exists {
		t.Fatal("Expected Anthropic metrics to exist")
	}

	if anthropicMetrics.TotalTokens != 1200 {
		t.Errorf("Expected 1200 tokens for Anthropic, got %d", anthropicMetrics.TotalTokens)
	}
}

// TestRecordProviderError verifies error tracking
func TestRecordProviderError(t *testing.T) {
	collector := NewMetricsCollector()
	defer collector.Close()

	collector.RecordProviderError("openai")
	collector.RecordProviderError("openai")
	collector.RecordProviderError("openai")

	metrics := collector.GetMetrics()

	openaiMetrics, exists := metrics.ProviderMetrics["openai"]
	if !exists {
		t.Fatal("Expected OpenAI metrics to exist")
	}

	if openaiMetrics.ErrorCount != 3 {
		t.Errorf("Expected 3 errors, got %d", openaiMetrics.ErrorCount)
	}
}

// TestMetricsReset verifies reset functionality
func TestMetricsReset(t *testing.T) {
	collector := NewMetricsCollector()
	defer collector.Close()

	// Add some metrics
	collector.RecordRequest("sql", "openai", 50*time.Millisecond)
	collector.RecordBlockedRequest("sql", "sql_injection")
	collector.RecordRedaction(2)

	// Verify metrics exist
	metrics := collector.GetMetrics()
	if metrics.PolicyMetrics.BlockedByPolicy == 0 {
		t.Error("Expected blocked requests before reset")
	}

	// Reset
	collector.ResetMetrics()

	// Verify metrics cleared
	metrics = collector.GetMetrics()
	if metrics.PolicyMetrics.BlockedByPolicy != 0 {
		t.Error("Expected metrics to be reset")
	}

	if metrics.PolicyMetrics.RedactionCount != 0 {
		t.Error("Expected redactions to be reset")
	}
}

// TestConcurrentMetricRecording verifies thread safety
func TestConcurrentMetricRecording(t *testing.T) {
	collector := NewMetricsCollector()
	defer collector.Close()

	done := make(chan bool, 100)

	// Launch 100 concurrent metric recordings
	for i := 0; i < 100; i++ {
		go func(index int) {
			collector.RecordRequest("sql", "openai", 50*time.Millisecond)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	metrics := collector.GetMetrics()
	sqlMetrics, exists := metrics.RequestMetrics["sql"]

	if !exists {
		t.Fatal("Expected SQL metrics to exist")
	}

	if sqlMetrics.TotalRequests != 100 {
		t.Errorf("Expected 100 requests, got %d (thread safety issue)", sqlMetrics.TotalRequests)
	}
}

// TestMetricsPercentileCalculation verifies percentile calculation
func TestMetricsPercentileCalculation(t *testing.T) {
	collector := NewMetricsCollector()
	defer collector.Close()

	// Record requests with known latencies
	collector.RecordRequest("sql", "openai", 10*time.Millisecond)
	collector.RecordRequest("sql", "openai", 20*time.Millisecond)
	collector.RecordRequest("sql", "openai", 30*time.Millisecond)
	collector.RecordRequest("sql", "openai", 40*time.Millisecond)
	collector.RecordRequest("sql", "openai", 100*time.Millisecond) // P95 outlier

	metrics := collector.GetMetrics()
	sqlMetrics := metrics.RequestMetrics["sql"]

	// P95 should be the highest value (100ms)
	expectedP95 := 100 * time.Millisecond
	tolerance := 20 * time.Millisecond
	if sqlMetrics.P95ResponseTime < expectedP95-tolerance || sqlMetrics.P95ResponseTime > expectedP95+tolerance {
		t.Errorf("Expected P95 around %v, got %v", expectedP95, sqlMetrics.P95ResponseTime)
	}
}

// ============================================================================
// Response Processor Tests
// ============================================================================

// TestResponseValidation verifies response validation rules
func TestResponseValidation(t *testing.T) {
	processor := NewResponseProcessor()

	tests := []struct {
		name       string
		response   *LLMResponse
		shouldPass bool
	}{
		{
			name: "Valid response",
			response: &LLMResponse{
				Content: "Valid response",
				Model:   "gpt-4",
			},
			shouldPass: true,
		},
		{
			name: "Empty content",
			response: &LLMResponse{
				Content: "",
				Model:   "gpt-4",
			},
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// validateResponse takes interface{}, not *LLMResponse
			// It validates the processed data, not the raw response
			err := processor.validateResponse(tt.response.Content)

			hasError := err != nil
			shouldFail := !tt.shouldPass

			if hasError != shouldFail {
				t.Errorf("Expected validation error=%v, got error=%v (%v)", shouldFail, hasError, err)
			}
		})
	}
}
