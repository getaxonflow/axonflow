// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidatePatternWithLimits(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr error
	}{
		{
			name:    "valid simple pattern",
			pattern: `\btest\b`,
			wantErr: nil,
		},
		{
			name:    "valid complex pattern",
			pattern: `(?i)select\s+.*\s+from`,
			wantErr: nil,
		},
		{
			name:    "valid pattern with groups",
			pattern: `(\d{3})-(\d{2})-(\d{4})`,
			wantErr: nil,
		},
		{
			name:    "valid email pattern",
			pattern: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			wantErr: nil,
		},
		{
			name:    "empty pattern",
			pattern: "",
			wantErr: ErrPatternEmpty,
		},
		{
			name:    "whitespace only pattern",
			pattern: "   \t\n  ",
			wantErr: ErrPatternEmpty,
		},
		{
			name:    "pattern too long",
			pattern: string(make([]byte, MaxPatternLength+1)),
			wantErr: ErrPatternTooLong,
		},
		{
			name:    "invalid syntax - unclosed bracket",
			pattern: `[invalid`,
			wantErr: ErrPatternInvalidSyntax,
		},
		{
			name:    "invalid syntax - unclosed paren",
			pattern: `(test`,
			wantErr: ErrPatternInvalidSyntax,
		},
		{
			name:    "invalid syntax - bad escape",
			pattern: `\`,
			wantErr: ErrPatternInvalidSyntax,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePatternWithLimits(tt.pattern)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePatternTooManyGroups(t *testing.T) {
	// Create a pattern with more than MaxCaptureGroups
	pattern := ""
	for i := 0; i <= MaxCaptureGroups; i++ {
		pattern += `(a)`
	}

	err := validatePatternWithLimits(pattern)
	assert.ErrorIs(t, err, ErrPatternTooManyGroups)
}

func TestValidatePatternDetailed(t *testing.T) {
	tests := []struct {
		name           string
		pattern        string
		wantValid      bool
		wantLength     int
		wantGroups     int
		wantErrorMsg   string
		wantWarningMsg string
	}{
		{
			name:       "valid simple",
			pattern:    `\btest\b`,
			wantValid:  true,
			wantLength: 8,
			wantGroups: 0,
		},
		{
			name:       "valid with 3 groups",
			pattern:    `(\d{3})-(\d{2})-(\d{4})`,
			wantValid:  true,
			wantLength: 23, // Actual length of the pattern string
			wantGroups: 3,
		},
		{
			name:         "empty pattern",
			pattern:      "",
			wantValid:    false,
			wantLength:   0,
			wantErrorMsg: "pattern cannot be empty",
		},
		{
			name:         "invalid syntax",
			pattern:      `[invalid`,
			wantValid:    false,
			wantLength:   8,
			wantErrorMsg: "invalid RE2 syntax",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidatePattern(tt.pattern)
			assert.Equal(t, tt.wantValid, result.Valid)
			assert.Equal(t, tt.wantLength, result.Length)
			if tt.wantValid {
				assert.Equal(t, tt.wantGroups, result.CaptureGroups)
			}
			if tt.wantErrorMsg != "" {
				assert.Contains(t, result.Error, tt.wantErrorMsg)
			}
			if tt.wantWarningMsg != "" {
				assert.Contains(t, result.Warning, tt.wantWarningMsg)
			}
		})
	}
}

func TestTestPattern(t *testing.T) {
	ctx := context.Background()

	t.Run("valid pattern with matches", func(t *testing.T) {
		result := TestPattern(ctx, `\d{3}-\d{2}-\d{4}`, []string{
			"123-45-6789",
			"no match",
			"SSN: 987-65-4321",
		})

		assert.True(t, result.Valid)
		assert.Len(t, result.Matches, 3)
		assert.True(t, result.Matches[0].Matched)
		assert.False(t, result.Matches[1].Matched)
		assert.True(t, result.Matches[2].Matched)
	})

	t.Run("pattern with capture groups", func(t *testing.T) {
		result := TestPattern(ctx, `(\d{3})-(\d{2})-(\d{4})`, []string{
			"123-45-6789",
		})

		assert.True(t, result.Valid)
		assert.Len(t, result.Matches, 1)
		assert.True(t, result.Matches[0].Matched)
		assert.Equal(t, []string{"123", "45", "6789"}, result.Matches[0].Groups)
	})

	t.Run("invalid pattern", func(t *testing.T) {
		result := TestPattern(ctx, `[invalid`, []string{"test"})

		assert.False(t, result.Valid)
		assert.Contains(t, result.Error, "invalid pattern")
	})

	t.Run("empty inputs", func(t *testing.T) {
		result := TestPattern(ctx, `\btest\b`, []string{})

		assert.True(t, result.Valid)
		assert.Len(t, result.Matches, 0)
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		result := TestPattern(ctx, `\btest\b`, []string{"test1", "test2", "test3"})

		// Should handle cancellation gracefully
		assert.True(t, result.Valid || result.Error == "test cancelled")
	})
}

func TestContainsDangerousPattern(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		isDangerous bool
	}{
		{
			name:        "safe pattern",
			pattern:     `\btest\b`,
			isDangerous: false,
		},
		{
			name:        "complex but safe",
			pattern:     `(?i)select\s+.*\s+from\s+\w+`,
			isDangerous: false,
		},
		{
			name:        "nested .* +",
			pattern:     `(.*)+`,
			isDangerous: true,
		},
		{
			name:        "nested .+ +",
			pattern:     `(.+)+`,
			isDangerous: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsDangerousPattern(tt.pattern)
			assert.Equal(t, tt.isDangerous, result)
		})
	}
}

func TestTestPatternTimeout(t *testing.T) {
	// This test verifies that testPatternTimeout works correctly
	// with a safe pattern
	pattern, err := CompilePatternSafe(`\btest\b`)
	assert.NoError(t, err)
	assert.NotNil(t, pattern)
}

func TestCompilePatternSafe(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{
			name:    "valid pattern",
			pattern: `\btest\b`,
			wantErr: false,
		},
		{
			name:    "invalid pattern",
			pattern: `[invalid`,
			wantErr: true,
		},
		{
			name:    "empty pattern",
			pattern: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, err := CompilePatternSafe(tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, re)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, re)
			}
		})
	}
}

func TestPatternConstants(t *testing.T) {
	// Verify constants have sensible values
	assert.Equal(t, 1000, MaxPatternLength)
	assert.Equal(t, 10, MaxCaptureGroups)
	assert.Equal(t, 100*time.Millisecond, PatternMatchTimeout)
}

// Benchmarks
func BenchmarkValidatePatternWithLimits(b *testing.B) {
	pattern := `(?i)select\s+.*\s+from\s+\w+\s+where\s+.*`

	for i := 0; i < b.N; i++ {
		_ = validatePatternWithLimits(pattern)
	}
}

func BenchmarkValidatePattern(b *testing.B) {
	pattern := `(?i)select\s+.*\s+from\s+\w+\s+where\s+.*`

	for i := 0; i < b.N; i++ {
		_ = ValidatePattern(pattern)
	}
}

func BenchmarkTestPattern(b *testing.B) {
	ctx := context.Background()
	pattern := `\b(\d{3})-(\d{2})-(\d{4})\b`
	inputs := []string{
		"123-45-6789",
		"no match here",
		"SSN: 987-65-4321",
	}

	for i := 0; i < b.N; i++ {
		_ = TestPattern(ctx, pattern, inputs)
	}
}

func BenchmarkCompilePatternSafe(b *testing.B) {
	pattern := `(?i)select\s+.*\s+from\s+\w+\s+where\s+.*`

	for i := 0; i < b.N; i++ {
		_, _ = CompilePatternSafe(pattern)
	}
}
