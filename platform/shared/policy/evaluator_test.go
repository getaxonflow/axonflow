package policy

import (
	"regexp"
	"testing"
)

func TestPatternEvaluator_Evaluate(t *testing.T) {
	evaluator := NewPatternEvaluator(true)

	// Test SSN pattern
	ssnPolicy := &CompiledPolicy{
		PolicyID:   "test_ssn",
		Name:       "SSN Detection",
		Category:   CategoryPIIUS,
		Pattern:    regexp.MustCompile(`\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b`),
		PatternStr: `\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b`,
		Severity:   SeverityCritical,
		Phase:      PhaseBoth,
		Enabled:    true,
	}

	tests := []struct {
		name      string
		input     string
		policy    *CompiledPolicy
		wantMatch bool
	}{
		{
			name:      "SSN found",
			input:     "My SSN is 123-45-6789",
			policy:    ssnPolicy,
			wantMatch: true,
		},
		{
			name:      "SSN not found",
			input:     "No sensitive data here",
			policy:    ssnPolicy,
			wantMatch: false,
		},
		{
			name:      "Invalid SSN rejected by validator",
			input:     "Invalid 000-12-3456",
			policy:    ssnPolicy,
			wantMatch: false, // 000 area is invalid
		},
		{
			name: "Disabled policy",
			input: "My SSN is 123-45-6789",
			policy: &CompiledPolicy{
				PolicyID: "disabled",
				Pattern:  ssnPolicy.Pattern,
				Enabled:  false,
			},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := evaluator.Evaluate(tt.input, tt.policy)
			gotMatch := match != nil
			if gotMatch != tt.wantMatch {
				t.Errorf("Evaluate() match = %v, want %v", gotMatch, tt.wantMatch)
			}
		})
	}
}

func TestPatternEvaluator_EvaluateAll(t *testing.T) {
	evaluator := NewPatternEvaluator(false) // Disable validators for counting all matches

	emailPolicy := &CompiledPolicy{
		PolicyID:   "test_email",
		Name:       "Email Detection",
		Category:   CategoryPIIGlobal,
		Pattern:    regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
		PatternStr: `\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`,
		Severity:   SeverityMedium,
		Phase:      PhaseResponse,
		Enabled:    true,
	}

	tests := []struct {
		name       string
		input      string
		wantCount  int
	}{
		{
			name:      "Multiple emails",
			input:     "Contact: user1@example.com or user2@test.org",
			wantCount: 2,
		},
		{
			name:      "Single email",
			input:     "Email: admin@company.com",
			wantCount: 1,
		},
		{
			name:      "No emails",
			input:     "No email addresses here",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := evaluator.EvaluateAll(tt.input, emailPolicy)
			if len(matches) != tt.wantCount {
				t.Errorf("EvaluateAll() count = %d, want %d", len(matches), tt.wantCount)
			}
		})
	}
}

func TestPatternEvaluator_EvaluateMultiple(t *testing.T) {
	evaluator := NewPatternEvaluator(false)

	policies := []CompiledPolicy{
		{
			PolicyID:       "sqli_union",
			Name:           "SQL Injection - UNION",
			Category:       CategorySecuritySQLi,
			Pattern:        regexp.MustCompile(`(?i)union\s+select`),
			PatternStr:     `(?i)union\s+select`,
			Severity:       SeverityCritical,
			Phase:          PhaseRequest,
			ActionRequest:  ActionBlock,
			Enabled:        true,
		},
		{
			PolicyID:       "sqli_drop",
			Name:           "SQL Injection - DROP",
			Category:       CategorySecuritySQLi,
			Pattern:        regexp.MustCompile(`(?i)drop\s+table`),
			PatternStr:     `(?i)drop\s+table`,
			Severity:       SeverityCritical,
			Phase:          PhaseRequest,
			ActionRequest:  ActionBlock,
			Enabled:        true,
		},
	}

	tests := []struct {
		name       string
		input      string
		phase      Phase
		wantCount  int
		wantBlock  bool
	}{
		{
			name:      "UNION injection",
			input:     "SELECT * FROM users UNION SELECT * FROM passwords",
			phase:     PhaseRequest,
			wantCount: 1,
			wantBlock: true,
		},
		{
			name:      "DROP injection",
			input:     "DROP TABLE users",
			phase:     PhaseRequest,
			wantCount: 1,
			wantBlock: true,
		},
		{
			name:      "Clean query",
			input:     "SELECT id, name FROM users WHERE active = true",
			phase:     PhaseRequest,
			wantCount: 0,
			wantBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := evaluator.EvaluateMultiple(tt.input, policies, tt.phase)
			if len(matches) != tt.wantCount {
				t.Errorf("EvaluateMultiple() count = %d, want %d", len(matches), tt.wantCount)
			}
			if tt.wantBlock && len(matches) > 0 && matches[0].Action != ActionBlock {
				t.Errorf("EvaluateMultiple() action = %v, want %v", matches[0].Action, ActionBlock)
			}
		})
	}
}

func TestPatternEvaluator_RegexCache(t *testing.T) {
	evaluator := NewPatternEvaluator(false)

	// Compile same pattern multiple times
	pattern := `\b\d{3}-\d{2}-\d{4}\b`

	for i := 0; i < 10; i++ {
		re, err := evaluator.getCompiledRegex(pattern)
		if err != nil {
			t.Fatalf("getCompiledRegex() error = %v", err)
		}
		if re == nil {
			t.Fatal("getCompiledRegex() returned nil")
		}
	}

	// Check cache stats
	stats := evaluator.GetStats()
	if stats.CachedPatterns != 1 {
		t.Errorf("CachedPatterns = %d, want 1", stats.CachedPatterns)
	}
}

func TestPatternEvaluator_InvalidPattern(t *testing.T) {
	evaluator := NewPatternEvaluator(false)

	// Invalid regex pattern
	_, err := evaluator.getCompiledRegex(`[invalid`)
	if err == nil {
		t.Error("getCompiledRegex() expected error for invalid pattern")
	}
}

func TestPatternEvaluator_ContextExtraction(t *testing.T) {
	evaluator := NewPatternEvaluator(true)
	evaluator.SetContextWindow(10)

	text := "prefix_1234567890_suffix"
	context := evaluator.extractContext(text, 7, 17)

	// Should include 10 chars before and after
	if len(context) == 0 {
		t.Error("extractContext() returned empty string")
	}

	// Check boundary handling
	context = evaluator.extractContext("short", 0, 5)
	if context != "short" {
		t.Errorf("extractContext() boundary handling failed, got %q", context)
	}
}

func TestPatternEvaluator_RegisterValidator(t *testing.T) {
	evaluator := NewPatternEvaluator(true)

	// Register custom validator
	customValidator := func(match, context string) (bool, float64) {
		return match == "VALID", 0.99
	}
	evaluator.RegisterValidator("custom_type", customValidator)

	// Verify registration
	stats := evaluator.GetStats()
	found := false
	for _, t := range stats.RegisteredTypes {
		if t == "custom_type" {
			found = true
			break
		}
	}
	if !found {
		t.Error("RegisterValidator() custom validator not found in registry")
	}
}

func TestPatternEvaluator_ClearCache(t *testing.T) {
	evaluator := NewPatternEvaluator(false)

	// Add some patterns to cache
	evaluator.getCompiledRegex(`\d+`)
	evaluator.getCompiledRegex(`\w+`)

	stats := evaluator.GetStats()
	if stats.CachedPatterns != 2 {
		t.Errorf("Before clear: CachedPatterns = %d, want 2", stats.CachedPatterns)
	}

	evaluator.ClearCache()

	stats = evaluator.GetStats()
	if stats.CachedPatterns != 0 {
		t.Errorf("After clear: CachedPatterns = %d, want 0", stats.CachedPatterns)
	}
}
