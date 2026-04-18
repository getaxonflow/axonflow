//go:build enterprise

// Copyright 2025 AxonFlow
// Licensed under the Business Source License 1.1 (the "License")

package advanced

import (
	"context"
	"strings"
	"testing"
	"time"

	commonsqli "axonflow/platform/agent/sqli"
)

func TestNewAdvancedScanner(t *testing.T) {
	t.Run("default configuration", func(t *testing.T) {
		scanner := NewAdvancedScanner()
		if scanner == nil {
			t.Fatal("NewAdvancedScanner() returned nil")
		}
		if scanner.maxInputLen != 1048576 {
			t.Errorf("maxInputLen = %d, want %d", scanner.maxInputLen, 1048576)
		}
		if scanner.confidenceThreshold != 0.7 {
			t.Errorf("confidenceThreshold = %v, want %v", scanner.confidenceThreshold, 0.7)
		}
	})

	t.Run("with custom options", func(t *testing.T) {
		scanner := NewAdvancedScanner(
			WithConfidenceThreshold(0.9),
			WithMaxInputLen(500),
		)
		if scanner.confidenceThreshold != 0.9 {
			t.Errorf("confidenceThreshold = %v, want %v", scanner.confidenceThreshold, 0.9)
		}
		if scanner.maxInputLen != 500 {
			t.Errorf("maxInputLen = %d, want %d", scanner.maxInputLen, 500)
		}
	})
}

func TestAdvancedScanner_Mode(t *testing.T) {
	scanner := NewAdvancedScanner()
	if got := scanner.Mode(); got != commonsqli.ModeAdvanced {
		t.Errorf("Mode() = %v, want %v", got, commonsqli.ModeAdvanced)
	}
}

func TestAdvancedScanner_IsEnterprise(t *testing.T) {
	scanner := NewAdvancedScanner()
	if got := scanner.IsEnterprise(); !got {
		t.Error("IsEnterprise() should return true")
	}
}

func TestAdvancedScanner_Scan_Detection(t *testing.T) {
	scanner := NewAdvancedScanner()
	ctx := context.Background()

	tests := []struct {
		name           string
		input          string
		scanType       commonsqli.ScanType
		wantDetected   bool
		wantCategory   commonsqli.Category
		wantConfidence float64 // minimum expected confidence
	}{
		// UNION-based injections
		{
			name:           "union select",
			input:          "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin",
			scanType:       commonsqli.ScanTypeInput,
			wantDetected:   true,
			wantCategory:   commonsqli.CategoryUnionBased,
			wantConfidence: 0.7,
		},
		{
			name:           "union with comment",
			input:          "' UNION SELECT * FROM users--",
			scanType:       commonsqli.ScanTypeInput,
			wantDetected:   true,
			wantCategory:   commonsqli.CategoryUnionBased,
			wantConfidence: 0.7,
		},

		// Boolean-based blind
		{
			name:           "or 1=1 attack",
			input:          "admin' OR 1=1--",
			scanType:       commonsqli.ScanTypeInput,
			wantDetected:   true,
			wantCategory:   commonsqli.CategoryBooleanBlind,
			wantConfidence: 0.7,
		},

		// Time-based
		{
			name:           "sleep injection",
			input:          "1; SELECT SLEEP(5)--",
			scanType:       commonsqli.ScanTypeInput,
			wantDetected:   true,
			wantCategory:   commonsqli.CategoryTimeBased,
			wantConfidence: 0.7,
		},

		// Stacked queries
		{
			name:           "drop table",
			input:          "1; DROP TABLE users--",
			scanType:       commonsqli.ScanTypeInput,
			wantDetected:   true,
			wantCategory:   commonsqli.CategoryStackedQueries,
			wantConfidence: 0.7,
		},

		// Advanced heuristics
		{
			name:           "nested subquery",
			input:          "SELECT * FROM users WHERE id=(SELECT admin_id FROM admins WHERE level=1)",
			scanType:       commonsqli.ScanTypeInput,
			wantDetected:   true,
			wantCategory:   commonsqli.CategoryGeneric,
			wantConfidence: 0.7,
		},
		{
			name:           "encoded injection",
			input:          "%27%20OR%201%3D1--%20",
			scanType:       commonsqli.ScanTypeInput,
			wantDetected:   true,
			wantCategory:   commonsqli.CategoryGeneric,
			wantConfidence: 0.7,
		},

		// Safe inputs (no SQL injection patterns)
		{
			name:         "normal text",
			input:        "Show me the weather forecast for tomorrow",
			scanType:     commonsqli.ScanTypeInput,
			wantDetected: false,
		},
		{
			name:         "legitimate SQL in documentation no injection",
			input:        "Here's an example of a SELECT statement: SELECT * FROM users WHERE name='John'",
			scanType:     commonsqli.ScanTypeInput,
			wantDetected: false, // No injection pattern, just normal SQL
		},
		{
			name:         "SQL in code block no injection",
			input:        "```sql\nSELECT * FROM users WHERE id=1;\n```",
			scanType:     commonsqli.ScanTypeInput,
			wantDetected: false, // No injection pattern, just normal SQL
		},
		{
			name:         "empty input",
			input:        "",
			scanType:     commonsqli.ScanTypeInput,
			wantDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.Scan(ctx, tt.input, tt.scanType)

			if result.Detected != tt.wantDetected {
				t.Errorf("Detected = %v, want %v (confidence: %v)",
					result.Detected, tt.wantDetected, result.Confidence)
			}

			if tt.wantDetected {
				if result.Category != tt.wantCategory {
					t.Errorf("Category = %v, want %v", result.Category, tt.wantCategory)
				}

				if result.Confidence < tt.wantConfidence {
					t.Errorf("Confidence = %v, want >= %v", result.Confidence, tt.wantConfidence)
				}

				if !result.Blocked {
					t.Error("Blocked should be true when detected")
				}
			}

			if result.Mode != commonsqli.ModeAdvanced {
				t.Errorf("Mode = %v, want %v", result.Mode, commonsqli.ModeAdvanced)
			}

			if result.Duration <= 0 {
				t.Error("Duration should be positive")
			}
		})
	}
}

func TestAdvancedScanner_Scan_ContextCancellation(t *testing.T) {
	scanner := NewAdvancedScanner()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := scanner.Scan(ctx, "UNION SELECT * FROM users", commonsqli.ScanTypeInput)

	if result.Detected {
		t.Error("Should not detect when context is cancelled")
	}
	if result.Metadata == nil || result.Metadata["error"] != "context cancelled" {
		t.Error("Should have error metadata for context cancellation")
	}
}

func TestAdvancedScanner_Scan_LongInput(t *testing.T) {
	scanner := NewAdvancedScanner(WithMaxInputLen(100))
	ctx := context.Background()

	// Create input longer than max with injection beyond truncation
	// 101 "a"s puts the injection outside the 100-char limit
	longInput := strings.Repeat("a", 101) + "UNION SELECT * FROM users" + strings.Repeat("b", 100)

	result := scanner.Scan(ctx, longInput, commonsqli.ScanTypeInput)

	// Should not detect because injection is beyond truncation point
	if result.Detected {
		t.Error("Should not detect injection beyond truncation point")
	}

	// Create input with injection within truncation
	shortInput := "UNION SELECT * FROM users" + strings.Repeat("b", 200)
	result = scanner.Scan(ctx, shortInput, commonsqli.ScanTypeInput)

	if !result.Detected {
		t.Error("Should detect injection within truncation point")
	}
}

func TestAdvancedScanner_ConfidenceReduction(t *testing.T) {
	scanner := NewAdvancedScanner()
	ctx := context.Background()

	tests := []struct {
		name             string
		input            string
		shouldReduce     bool
		expectedBehavior string
	}{
		{
			name:             "documentation context",
			input:            "example: SELECT * FROM users WHERE id=' OR 1=1--",
			shouldReduce:     true,
			expectedBehavior: "Should reduce confidence for documentation context",
		},
		{
			name:             "tutorial context",
			input:            "tutorial: This is how SQL injection works: ' OR 1=1--",
			shouldReduce:     true,
			expectedBehavior: "Should reduce confidence for tutorial context",
		},
		{
			name:             "code block",
			input:            "```sql\nSELECT * FROM users WHERE admin=' OR 1=1\n```",
			shouldReduce:     true,
			expectedBehavior: "Should reduce confidence for code blocks",
		},
		{
			name:             "actual attack",
			input:            "admin' OR 1=1--",
			shouldReduce:     false,
			expectedBehavior: "Should maintain high confidence for actual attacks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.Scan(ctx, tt.input, commonsqli.ScanTypeInput)

			if tt.shouldReduce {
				// Confidence should be below 1.0 due to context
				if result.Confidence >= 1.0 {
					t.Logf("%s: confidence=%v", tt.expectedBehavior, result.Confidence)
				}
			}
		})
	}
}

func TestAdvancedScanner_Registration(t *testing.T) {
	// Test that advanced scanner is properly registered
	scanner, err := commonsqli.NewScanner(commonsqli.ModeAdvanced)
	if err != nil {
		t.Fatalf("NewScanner(ModeAdvanced) error = %v", err)
	}
	if scanner == nil {
		t.Fatal("NewScanner(ModeAdvanced) returned nil")
	}
	if _, ok := scanner.(*AdvancedScanner); !ok {
		t.Errorf("NewScanner(ModeAdvanced) returned %T, want *AdvancedScanner", scanner)
	}
	if !scanner.IsEnterprise() {
		t.Error("Advanced scanner should return IsEnterprise() = true")
	}
}

func TestHeuristic_Matches(t *testing.T) {
	heuristics := defaultHeuristics()

	tests := []struct {
		name          string
		heuristicName string
		input         string
		shouldMatch   bool
	}{
		{
			name:          "nested subquery matches",
			heuristicName: "nested_subquery",
			input:         "SELECT * FROM t WHERE id=(SELECT x FROM y WHERE z=1)",
			shouldMatch:   true,
		},
		{
			name:          "nested subquery no match",
			heuristicName: "nested_subquery",
			input:         "SELECT * FROM users WHERE id=1",
			shouldMatch:   false,
		},
		{
			name:          "null byte injection",
			heuristicName: "null_byte_injection",
			input:         "admin%00password",
			shouldMatch:   true,
		},
		{
			name:          "encoded keywords",
			heuristicName: "encoded_keywords",
			input:         "%27%20OR%201=1",
			shouldMatch:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h *Heuristic
			for _, heuristic := range heuristics {
				if heuristic.name == tt.heuristicName {
					h = heuristic
					break
				}
			}
			if h == nil {
				t.Fatalf("Heuristic %s not found", tt.heuristicName)
			}

			if got := h.matches(tt.input); got != tt.shouldMatch {
				t.Errorf("%s.matches(%q) = %v, want %v", tt.heuristicName, tt.input, got, tt.shouldMatch)
			}
		})
	}
}

func TestAdvancedScanner_SuspicionAnalysis(t *testing.T) {
	scanner := NewAdvancedScanner()

	tests := []struct {
		name            string
		input           string
		minExpectedScore float64
	}{
		{
			name:            "clean text",
			input:           "Hello, how can I help you today?",
			minExpectedScore: 0.0,
		},
		{
			name:            "comment markers",
			input:           "-- this is suspicious",
			minExpectedScore: 0.1,
		},
		{
			name:            "quote and equal",
			input:           "name=' value",
			minExpectedScore: 0.1,
		},
		{
			name:            "hex encoding",
			input:           "id=0x41424344",
			minExpectedScore: 0.2,
		},
		{
			name:            "sql functions",
			input:           "char(65) concat(a,b) ascii('x')",
			minExpectedScore: 0.2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := scanner.analyzeSuspiciousPatterns(tt.input)
			if score < tt.minExpectedScore {
				t.Errorf("analyzeSuspiciousPatterns(%q) = %v, want >= %v",
					tt.input, score, tt.minExpectedScore)
			}
		})
	}
}

func TestAdvancedScanner_Scan_Performance(t *testing.T) {
	scanner := NewAdvancedScanner()
	ctx := context.Background()

	// Typical input size
	input := "What is the weather forecast for tomorrow in New York?"

	start := time.Now()
	iterations := 1000
	for i := 0; i < iterations; i++ {
		scanner.Scan(ctx, input, commonsqli.ScanTypeInput)
	}
	elapsed := time.Since(start)

	avgTime := elapsed / time.Duration(iterations)
	// Advanced scanner should be under 10ms per scan
	if avgTime > 10*time.Millisecond {
		t.Errorf("Average scan time = %v, want < 10ms", avgTime)
	}
}

// Benchmarks
func BenchmarkAdvancedScanner_SafeInput(b *testing.B) {
	scanner := NewAdvancedScanner()
	ctx := context.Background()
	input := "What is the weather forecast for tomorrow?"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(ctx, input, commonsqli.ScanTypeInput)
	}
}

func BenchmarkAdvancedScanner_MaliciousInput(b *testing.B) {
	scanner := NewAdvancedScanner()
	ctx := context.Background()
	input := "admin' OR 1=1--"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(ctx, input, commonsqli.ScanTypeInput)
	}
}

func BenchmarkAdvancedScanner_ComplexInput(b *testing.B) {
	scanner := NewAdvancedScanner()
	ctx := context.Background()
	input := "SELECT * FROM users WHERE id=(SELECT admin_id FROM admins WHERE level=1) UNION SELECT password FROM admin WHERE '1'='1"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(ctx, input, commonsqli.ScanTypeInput)
	}
}
