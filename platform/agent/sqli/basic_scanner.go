package sqli

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// BasicScanner implements pattern-based SQL injection detection.
// It uses regex patterns to identify common SQL injection techniques.
// This scanner is available in the Community edition.
type BasicScanner struct {
	patterns     *PatternSet
	maxInputLen  int
	snippetLen   int
}

// BasicScannerOption is a functional option for configuring BasicScanner.
type BasicScannerOption func(*BasicScanner)

// WithPatternSet sets a custom pattern set for the scanner.
func WithPatternSet(ps *PatternSet) BasicScannerOption {
	return func(s *BasicScanner) {
		s.patterns = ps
	}
}

// WithMaxInputLength sets the maximum input length to scan.
func WithMaxInputLength(maxLen int) BasicScannerOption {
	return func(s *BasicScanner) {
		s.maxInputLen = maxLen
	}
}

// WithSnippetLength sets the length of the input snippet in results.
func WithSnippetLength(length int) BasicScannerOption {
	return func(s *BasicScanner) {
		s.snippetLen = length
	}
}

// NewBasicScanner creates a new basic scanner with the given options.
func NewBasicScanner(opts ...BasicScannerOption) *BasicScanner {
	s := &BasicScanner{
		patterns:    NewPatternSet(),
		maxInputLen: 1048576, // 1MB default
		snippetLen:  100,     // 100 chars for logging
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Scan checks the content for SQL injection patterns.
func (s *BasicScanner) Scan(ctx context.Context, content string, scanType ScanType) *Result {
	start := time.Now()

	// Check context cancellation
	select {
	case <-ctx.Done():
		return &Result{
			Detected: false,
			ScanType: scanType,
			Mode:     ModeBasic,
			Duration: time.Since(start),
			Metadata: map[string]any{"error": "context cancelled"},
		}
	default:
	}

	// Truncate if too long
	if len(content) > s.maxInputLen {
		content = content[:s.maxInputLen]
	}

	// Scan with all patterns
	for _, pattern := range s.patterns.Patterns() {
		if pattern.Regex.MatchString(content) {
			return &Result{
				Detected:   true,
				Blocked:    true, // Basic scanner always recommends blocking
				Pattern:    pattern.Name,
				Category:   pattern.Category,
				Confidence: 1.0, // Pattern match is binary
				Input:      s.sanitizeInput(content),
				ScanType:   scanType,
				Mode:       ModeBasic,
				Duration:   time.Since(start),
				Metadata: map[string]any{
					"pattern_description": pattern.Description,
					"severity":            pattern.Severity,
				},
			}
		}
	}

	return &Result{
		Detected: false,
		Blocked:  false,
		ScanType: scanType,
		Mode:     ModeBasic,
		Duration: time.Since(start),
	}
}

// Mode returns ModeBasic.
func (s *BasicScanner) Mode() Mode {
	return ModeBasic
}

// IsEnterprise returns false as basic scanner is in Community edition.
func (s *BasicScanner) IsEnterprise() bool {
	return false
}

// sanitizeInput creates a safe snippet of the input for logging.
// It truncates the input and masks potentially sensitive data.
func (s *BasicScanner) sanitizeInput(input string) string {
	if len(input) <= s.snippetLen {
		return sanitizeForLog(input)
	}
	return sanitizeForLog(input[:s.snippetLen]) + "..."
}

// Precompiled masking regexes for performance
var (
	passwordMaskRegex = regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['"]?[^'"\s]+['"]?`)
	apiKeyMaskRegex   = regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*['"]?[^'"\s]+['"]?`)
	tokenMaskRegex    = regexp.MustCompile(`(?i)(token|bearer)\s*[=:]\s*['"]?[^'"\s]+['"]?`)
)

// sanitizeForLog removes or masks sensitive patterns in the input.
func sanitizeForLog(input string) string {
	// Replace newlines with spaces first
	input = strings.ReplaceAll(input, "\n", " ")

	// Replace potential password fields
	input = passwordMaskRegex.ReplaceAllString(input, "[REDACTED_PASSWORD]")
	// Replace potential API keys
	input = apiKeyMaskRegex.ReplaceAllString(input, "[REDACTED_KEY]")
	// Replace potential tokens
	input = tokenMaskRegex.ReplaceAllString(input, "[REDACTED_TOKEN]")

	return input
}

func init() {
	// Register basic scanner in the registry
	RegisterScanner(ModeBasic, func() Scanner {
		return NewBasicScanner()
	})
}
