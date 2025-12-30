// Copyright 2025 AxonFlow
package orchestrator

import (
	"context"
	"regexp"
	"testing"
	"time"
)

// Benchmark Tests for Orchestrator Utility Functions
// Run with: go test -bench=. -benchmem

// BenchmarkNewPIIDetector benchmarks PII detector creation
func BenchmarkNewPIIDetector(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewPIIDetector()
	}
}

// BenchmarkNewRedactor benchmarks redactor creation
func BenchmarkNewRedactor(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewRedactor()
	}
}

// BenchmarkNewResponseProcessor benchmarks response processor creation
func BenchmarkNewResponseProcessor(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewResponseProcessor()
	}
}

// BenchmarkNewDynamicPolicyEngine benchmarks policy engine creation
func BenchmarkNewDynamicPolicyEngine(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewDynamicPolicyEngine()
	}
}

// BenchmarkNewMockLLMRouter benchmarks mock LLM router creation
func BenchmarkNewMockLLMRouter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewMockLLMRouter()
	}
}

// BenchmarkDestinationToIATA benchmarks IATA code conversion
func BenchmarkDestinationToIATA(b *testing.B) {
	destinations := []string{"London", "New York", "Paris", "Tokyo", "Los Angeles"}
	for i := 0; i < b.N; i++ {
		_ = DestinationToIATA(destinations[i%len(destinations)])
	}
}

// BenchmarkNewMetricsCollector benchmarks metrics collector creation
func BenchmarkNewMetricsCollector(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewMetricsCollector()
	}
}

// BenchmarkMetricsCollector_RecordRequest benchmarks metrics recording
func BenchmarkMetricsCollector_RecordRequest(b *testing.B) {
	collector := NewMetricsCollector()
	for i := 0; i < b.N; i++ {
		collector.RecordRequest("sql", "openai", 50*time.Millisecond)
	}
}

// BenchmarkMetricsCollector_GetMetrics benchmarks metrics retrieval
func BenchmarkMetricsCollector_GetMetrics(b *testing.B) {
	collector := NewMetricsCollector()
	for i := 0; i < 100; i++ {
		collector.RecordRequest("sql", "openai", 50*time.Millisecond)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = collector.GetMetrics()
	}
}

// BenchmarkNewPolicyCache benchmarks policy cache creation
func BenchmarkNewPolicyCache(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewPolicyCache(5 * time.Minute)
	}
}

// BenchmarkPolicyCache_Get benchmarks policy cache retrieval
func BenchmarkPolicyCache_Get(b *testing.B) {
	cache := NewPolicyCache(5 * time.Minute)
	cache.Set("test-policy", &DynamicPolicy{ID: "test", Name: "Test"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Get("test-policy")
	}
}

// BenchmarkPolicyCache_Set benchmarks policy cache updates
func BenchmarkPolicyCache_Set(b *testing.B) {
	cache := NewPolicyCache(5 * time.Minute)
	for i := 0; i < b.N; i++ {
		cache.Set("policy-"+string(rune(i%100)), &DynamicPolicy{ID: "test"})
	}
}

// BenchmarkRegexCompilation benchmarks regex compilation
func BenchmarkRegexCompilation(b *testing.B) {
	pattern := `\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`
	for i := 0; i < b.N; i++ {
		_, _ = regexp.Compile("(?i)" + pattern)
	}
}

// BenchmarkRegexMatching benchmarks regex matching
func BenchmarkRegexMatching(b *testing.B) {
	pattern := regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	text := "Contact me at john.doe@example.com for more details"
	for i := 0; i < b.N; i++ {
		_ = pattern.MatchString(text)
	}
}

// BenchmarkContextPropagation benchmarks context propagation
func BenchmarkContextPropagation(b *testing.B) {
	parent := context.Background()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(parent, 30*time.Second)
		_ = ctx
		cancel()
	}
}
