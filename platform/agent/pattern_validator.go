// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Pattern validation constants
const (
	// MaxPatternLength is the maximum allowed length for a regex pattern.
	MaxPatternLength = 1000

	// MaxCaptureGroups is the maximum number of capture groups allowed.
	MaxCaptureGroups = 10

	// PatternMatchTimeout is the timeout for pattern matching tests.
	PatternMatchTimeout = 100 * time.Millisecond
)

// Pattern validation errors
var (
	ErrPatternTooLong          = errors.New("pattern exceeds maximum length")
	ErrPatternTooManyGroups    = errors.New("pattern has too many capture groups")
	ErrPatternMatchTimeout     = errors.New("pattern matching timed out")
	ErrPatternEmpty            = errors.New("pattern cannot be empty")
	ErrPatternInvalidSyntax    = errors.New("pattern has invalid RE2 syntax")
	ErrPatternDangerousBackref = errors.New("pattern contains potentially dangerous backreferences")
)

// PatternValidationResult contains the result of pattern validation.
type PatternValidationResult struct {
	Valid   bool   `json:"valid"`
	Error   string `json:"error,omitempty"`
	Warning string `json:"warning,omitempty"`

	// Metrics
	Length        int `json:"length"`
	CaptureGroups int `json:"capture_groups"`
}

// PatternTestResult contains the result of testing a pattern against inputs.
type PatternTestResult struct {
	Valid   bool     `json:"valid"`
	Error   string   `json:"error,omitempty"`
	Matches []Match  `json:"matches,omitempty"`
	Pattern string   `json:"pattern"`
	Inputs  []string `json:"inputs"`
}

// Match represents a single match result.
type Match struct {
	Input   string   `json:"input"`
	Matched bool     `json:"matched"`
	Groups  []string `json:"groups,omitempty"`
}

// validatePatternWithLimits validates that a pattern is valid RE2 regex with safety checks.
// This includes length limits, capture group limits, and timeout testing.
// Note: There's a simpler validateRE2Pattern in db_policies.go that only checks for
// unsupported Perl regex syntax. This function does more comprehensive validation.
func validatePatternWithLimits(pattern string) error {
	// Check empty
	if strings.TrimSpace(pattern) == "" {
		return ErrPatternEmpty
	}

	// Check length
	if len(pattern) > MaxPatternLength {
		return ErrPatternTooLong
	}

	// Compile pattern (RE2 syntax check)
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPatternInvalidSyntax, err)
	}

	// Check capture groups
	numGroups := re.NumSubexp()
	if numGroups > MaxCaptureGroups {
		return ErrPatternTooManyGroups
	}

	// Test for catastrophic backtracking patterns
	// Go's regexp uses RE2 which is guaranteed linear time, but we still
	// check for excessively complex patterns that could cause issues
	if containsDangerousPattern(pattern) {
		return ErrPatternDangerousBackref
	}

	// Test pattern matching with timeout
	if err := testPatternTimeout(re); err != nil {
		return err
	}

	return nil
}

// ValidatePattern validates a pattern and returns detailed results.
func ValidatePattern(pattern string) *PatternValidationResult {
	result := &PatternValidationResult{
		Valid:  true,
		Length: len(pattern),
	}

	// Check empty
	if strings.TrimSpace(pattern) == "" {
		result.Valid = false
		result.Error = "pattern cannot be empty"
		return result
	}

	// Check length
	if len(pattern) > MaxPatternLength {
		result.Valid = false
		result.Error = fmt.Sprintf("pattern exceeds maximum length of %d characters", MaxPatternLength)
		return result
	}

	// Compile pattern
	re, err := regexp.Compile(pattern)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("invalid RE2 syntax: %v", err)
		return result
	}

	// Check capture groups
	result.CaptureGroups = re.NumSubexp()
	if result.CaptureGroups > MaxCaptureGroups {
		result.Valid = false
		result.Error = fmt.Sprintf("pattern has %d capture groups, maximum is %d", result.CaptureGroups, MaxCaptureGroups)
		return result
	}

	// Check for potentially problematic patterns (warning only)
	if containsDangerousPattern(pattern) {
		result.Warning = "pattern contains potentially problematic nested quantifiers"
	}

	// Test pattern matching
	if err := testPatternTimeout(re); err != nil {
		result.Valid = false
		result.Error = "pattern matching timed out"
		return result
	}

	return result
}

// TestPattern tests a pattern against a list of inputs and returns match results.
func TestPattern(ctx context.Context, pattern string, inputs []string) *PatternTestResult {
	result := &PatternTestResult{
		Pattern: pattern,
		Inputs:  inputs,
	}

	// Validate pattern first
	re, err := regexp.Compile(pattern)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("invalid pattern: %v", err)
		return result
	}

	result.Valid = true
	result.Matches = make([]Match, 0, len(inputs))

	for _, input := range inputs {
		select {
		case <-ctx.Done():
			result.Error = "test cancelled"
			return result
		default:
		}

		match := Match{
			Input:   input,
			Matched: re.MatchString(input),
		}

		if match.Matched {
			// Get capture groups
			matches := re.FindStringSubmatch(input)
			if len(matches) > 1 {
				match.Groups = matches[1:]
			}
		}

		result.Matches = append(result.Matches, match)
	}

	return result
}

// containsDangerousPattern checks for patterns that might cause performance issues.
// Go's RE2 is safe from catastrophic backtracking, but we still want to warn
// about excessively complex patterns.
func containsDangerousPattern(pattern string) bool {
	// Check for nested quantifiers like (a+)+ or (a*)* which can be slow
	// even in RE2 for very long inputs
	dangerousPatterns := []string{
		`(\+\+)`,       // a++ (not actually RE2 syntax)
		`(\*\+)`,       // a*+ (not actually RE2 syntax)
		`(\+\*)`,       // a+* (not actually RE2 syntax)
		`\(\.\*\)\+`,   // (.*)+ nested
		`\(\.\+\)\+`,   // (.+)+ nested
		`\(\.\*\)\*`,   // (.*)* nested
		`\(\.\+\)\*`,   // (.+)* nested
	}

	for _, dp := range dangerousPatterns {
		if matched, _ := regexp.MatchString(dp, pattern); matched {
			return true
		}
	}

	return false
}

// testPatternTimeout tests that the pattern can match within the timeout.
func testPatternTimeout(re *regexp.Regexp) error {
	// Test with a reasonable input that should match quickly
	testInputs := []string{
		"",                                         // Empty
		"hello world",                              // Simple string
		"test123test456test789",                    // Repeated pattern
		strings.Repeat("a", 100),                   // Repeated character
		strings.Repeat("ab", 50),                   // Repeated pair
		"SELECT * FROM users WHERE id = 1",         // SQL-like
		"user@example.com",                         // Email-like
		"123-45-6789",                              // SSN-like
	}

	done := make(chan bool, 1)
	go func() {
		for _, input := range testInputs {
			re.MatchString(input)
		}
		done <- true
	}()

	select {
	case <-done:
		return nil
	case <-time.After(PatternMatchTimeout):
		return ErrPatternMatchTimeout
	}
}

// CompilePatternSafe compiles a pattern with validation.
// Returns the compiled regex or an error with details.
func CompilePatternSafe(pattern string) (*regexp.Regexp, error) {
	if err := validatePatternWithLimits(pattern); err != nil {
		return nil, err
	}
	return regexp.Compile(pattern)
}
