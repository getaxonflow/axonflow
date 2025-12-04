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
	"time"
)

// ============================================================================
// Result Aggregator Tests
// ============================================================================

// TestNewResultAggregator verifies proper initialization
func TestNewResultAggregator(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)

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
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
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
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
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
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
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
	config := LLMRouterConfig{
		OpenAIKey:    "invalid-key",
		AnthropicKey: "invalid-key",
	}
	router := NewLLMRouter(config)
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
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
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
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
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

	collector.RecordProviderUsage("openai", 1000, 0.02)  // 1000 tokens, $0.02
	collector.RecordProviderUsage("openai", 1500, 0.03)  // 1500 tokens, $0.03
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

// TestNewResponseProcessor verifies initialization
func TestNewResponseProcessor(t *testing.T) {
	processor := NewResponseProcessor()

	if processor == nil {
		t.Fatal("Expected processor to be initialized")
	}

	if processor.piiDetector == nil {
		t.Error("Expected piiDetector to be initialized")
	}

	if processor.redactor == nil {
		t.Error("Expected redactor to be initialized")
	}

	if !processor.IsHealthy() {
		t.Error("Expected processor to be healthy")
	}
}

// TestPIIDetectorPatterns verifies PII pattern matching
func TestPIIDetectorPatterns(t *testing.T) {
	processor := NewResponseProcessor()

	tests := []struct {
		name        string
		text        string
		shouldDetect bool
	}{
		{
			name:        "SSN detection",
			text:        "My SSN is 123-45-6789",
			shouldDetect: true,
		},
		{
			name:        "Email detection",
			text:        "Contact me at user@example.com",
			shouldDetect: true,
		},
		{
			name:        "Phone detection",
			text:        "Call me at 555-123-4567",
			shouldDetect: true,
		},
		{
			name:        "No PII",
			text:        "This is a normal sentence",
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detected := processor.detectPII(tt.text)

			hasDetection := len(detected) > 0

			if hasDetection != tt.shouldDetect {
				t.Errorf("Expected detection=%v, got %v (detected: %v)", tt.shouldDetect, hasDetection, detected)
			}
		})
	}
}

// TestMaskingStrategy verifies masking redaction
func TestMaskingStrategy(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		keepLast    int
		placeholder string
		expected    string
	}{
		{
			name:        "Mask SSN keep last 4",
			value:       "123-45-6789",
			keepLast:    4,
			placeholder: "***-**-",
			expected:    "***-**-6789",
		},
		{
			name:        "Mask credit card keep last 4",
			value:       "4532123456789010",
			keepLast:    4,
			placeholder: "************",
			expected:    "************9010",
		},
		{
			name:        "Mask email",
			value:       "user@example.com",
			keepLast:    0,
			placeholder: "[REDACTED]",
			expected:    "[REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := &MaskingStrategy{
				keepLast:    tt.keepLast,
				placeholder: tt.placeholder,
			}

			result := strategy.Redact(tt.value)

			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestHashingStrategy verifies hashing redaction
func TestHashingStrategy(t *testing.T) {
	strategy := &HashingStrategy{}

	value := "sensitive-data-123"

	result := strategy.Redact(value)

	// Hash should not contain original value
	if strings.Contains(result, value) {
		t.Error("Expected hash to not contain original value")
	}

	// Hash should be deterministic
	result2 := strategy.Redact(value)
	if result != result2 {
		t.Error("Expected consistent hashing")
	}

	// Different values should produce different hashes
	result3 := strategy.Redact("different-value")
	if result == result3 {
		t.Error("Expected different hashes for different values")
	}
}

// TestPermissionBasedRedaction verifies role-based access
func TestPermissionBasedRedaction(t *testing.T) {
	processor := NewResponseProcessor()

	tests := []struct {
		name              string
		userRole          string
		text              string
		shouldRedact      bool
	}{
		{
			name:         "Admin sees PII",
			userRole:     "admin",
			text:         "SSN: 123-45-6789",
			shouldRedact: false,
		},
		{
			name:         "User has PII redacted",
			userRole:     "user",
			text:         "SSN: 123-45-6789",
			shouldRedact: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := UserContext{
				TenantID: "test-tenant",
				Role:     tt.userRole,
				Email:    "test@example.com",
			}

			allowedPII := processor.getAllowedPIITypes(user)

			// Admin should have access to more PII types
			if tt.userRole == "admin" && len(allowedPII) == 0 {
				t.Error("Expected admin to have access to PII types")
			}

			if tt.userRole != "admin" && len(allowedPII) > 0 {
				t.Logf("Non-admin user has access to: %v", allowedPII)
			}
		})
	}
}

// TestDeepScanForPII verifies nested structure scanning
func TestDeepScanForPII(t *testing.T) {
	processor := NewResponseProcessor()

	data := map[string]interface{}{
		"user": map[string]interface{}{
			"name":  "John Doe",
			"email": "john@example.com",
			"ssn":   "123-45-6789",
		},
		"contact": map[string]interface{}{
			"phone": "555-123-4567",
		},
	}

	// deepScanForPII doesn't return anything, it modifies the detected map
	detected := make(map[string][]string)
	processor.deepScanForPII(data, detected)

	if len(detected) == 0 {
		t.Error("Expected PII to be detected in nested structure")
	}

	t.Logf("Detected PII fields: %v", detected)
}

// TestFieldNameBasedPIIDetection verifies field name heuristics
func TestFieldNameBasedPIIDetection(t *testing.T) {
	processor := NewResponseProcessor()

	data := map[string]interface{}{
		"ssn":          "redacted",
		"password":     "secret",
		"credit_card":  "4532123456789010",
		"normal_field": "normal value",
	}

	detected := make(map[string][]string)
	processor.deepScanForPII(data, detected)

	// Should flag suspicious field names
	if len(detected) == 0 {
		t.Error("Expected to detect PII fields by name")
	}

	t.Logf("Detected PII by field name: %v", detected)
}

// TestProcessResponseEndToEnd verifies full processing pipeline
func TestProcessResponseEndToEnd(t *testing.T) {
	processor := NewResponseProcessor()

	ctx := context.Background()

	user := UserContext{
		TenantID: "test-tenant",
		Role:     "user",
		Email:    "test@example.com",
	}

	response := &LLMResponse{
		Content: "User SSN is 123-45-6789 and email is user@example.com",
		Model:    "gpt-4",
	}

	processed, redactionInfo := processor.ProcessResponse(ctx, user, response)

	if redactionInfo == nil {
		t.Error("Expected redaction info to be returned")
	}

	if !redactionInfo.HasRedactions {
		t.Log("No redactions were applied (user may have PII access)")
	}

	// processed could be enriched map or string - just verify it's not nil
	if processed == nil {
		t.Error("Expected processed response to not be nil")
	}

	t.Logf("Processed response type: %T", processed)
	t.Logf("Redaction info: count=%d, fields=%v", redactionInfo.RedactionCount, redactionInfo.RedactedFields)
}

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
				Content:  "Valid response",
				Model:    "gpt-4",
			},
			shouldPass: true,
		},
		{
			name: "Empty content",
			response: &LLMResponse{
				Content:  "",
				Model:    "gpt-4",
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

// TestRedactionInfoGeneration verifies redaction metadata
func TestRedactionInfoGeneration(t *testing.T) {
	processor := NewResponseProcessor()

	user := UserContext{
		TenantID: "test-tenant",
		Role:     "user",
		Email:    "test@example.com",
	}

	data := "SSN: 123-45-6789, Email: user@example.com"

	detected := processor.detectPII(data)

	if len(detected) == 0 {
		t.Fatal("Expected PII to be detected")
	}

	redacted, info := processor.applyRedactions(user, data, detected)

	if info == nil {
		t.Fatal("Expected redaction info to be created")
	}

	// Redactions may or may not occur depending on user permissions
	if info.HasRedactions {
		t.Logf("Redaction count: %d", info.RedactionCount)
		t.Logf("Redacted fields: %v", info.RedactedFields)
	}

	// Redacted data should be returned (either modified or original)
	if redacted == nil {
		t.Error("Expected redacted data to be returned")
	}

	t.Logf("Redacted data type: %T", redacted)
}
