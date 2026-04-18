//go:build enterprise

// Copyright 2025 AxonFlow
// Licensed under the Business Source License 1.1 (the "License")

package advanced

import (
	"context"
	"regexp"
	"strings"
	"time"

	commonsqli "axonflow/platform/agent/sqli"
)

// AdvancedScanner implements heuristic-based SQL injection detection.
// It provides higher accuracy than the basic scanner through:
// - Context-aware analysis
// - Probabilistic confidence scoring
// - Multi-stage detection pipeline
// - False positive reduction
type AdvancedScanner struct {
	basicScanner        commonsqli.Scanner
	heuristics          []*Heuristic
	maxInputLen         int
	snippetLen          int
	confidenceThreshold float64
}

// AdvancedScannerOption configures the AdvancedScanner.
type AdvancedScannerOption func(*AdvancedScanner)

// WithConfidenceThreshold sets the minimum confidence for detection.
func WithConfidenceThreshold(threshold float64) AdvancedScannerOption {
	return func(s *AdvancedScanner) {
		s.confidenceThreshold = threshold
	}
}

// WithMaxInputLen sets the maximum input length to scan.
func WithMaxInputLen(maxLen int) AdvancedScannerOption {
	return func(s *AdvancedScanner) {
		s.maxInputLen = maxLen
	}
}

// NewAdvancedScanner creates a new advanced scanner.
func NewAdvancedScanner(opts ...AdvancedScannerOption) *AdvancedScanner {
	s := &AdvancedScanner{
		basicScanner:        commonsqli.MustNewScanner(commonsqli.ModeBasic),
		heuristics:          defaultHeuristics(),
		maxInputLen:         1048576, // 1MB
		snippetLen:          100,
		confidenceThreshold: 0.7, // 70% confidence minimum
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Scan checks content for SQL injection using advanced heuristics.
func (s *AdvancedScanner) Scan(ctx context.Context, content string, scanType commonsqli.ScanType) *commonsqli.Result {
	start := time.Now()

	// Check context cancellation
	select {
	case <-ctx.Done():
		return &commonsqli.Result{
			Detected: false,
			ScanType: scanType,
			Mode:     commonsqli.ModeAdvanced,
			Duration: time.Since(start),
			Metadata: map[string]any{"error": "context cancelled"},
		}
	default:
	}

	// Truncate if too long
	if len(content) > s.maxInputLen {
		content = content[:s.maxInputLen]
	}

	// Stage 1: Run basic pattern matching first (fast path)
	basicResult := s.basicScanner.Scan(ctx, content, scanType)
	if basicResult.Detected {
		// Basic scanner found something, apply heuristics for confidence
		confidence := s.calculateConfidence(content, basicResult)

		return &commonsqli.Result{
			Detected:   confidence >= s.confidenceThreshold,
			Blocked:    confidence >= s.confidenceThreshold,
			Pattern:    basicResult.Pattern,
			Category:   basicResult.Category,
			Confidence: confidence,
			Input:      s.sanitizeInput(content),
			ScanType:   scanType,
			Mode:       commonsqli.ModeAdvanced,
			Duration:   time.Since(start),
			Metadata: map[string]any{
				"stage":           "pattern_match",
				"basic_pattern":   basicResult.Pattern,
				"basic_category":  basicResult.Category,
				"heuristic_boost": confidence - 1.0,
			},
		}
	}

	// Stage 2: Run heuristic analysis for patterns basic scanner might miss
	for _, h := range s.heuristics {
		if h.matches(content) {
			confidence := h.confidence(content)
			if confidence >= s.confidenceThreshold {
				return &commonsqli.Result{
					Detected:   true,
					Blocked:    true,
					Pattern:    h.name,
					Category:   h.category,
					Confidence: confidence,
					Input:      s.sanitizeInput(content),
					ScanType:   scanType,
					Mode:       commonsqli.ModeAdvanced,
					Duration:   time.Since(start),
					Metadata: map[string]any{
						"stage":       "heuristic",
						"heuristic":   h.name,
						"description": h.description,
					},
				}
			}
		}
	}

	// Stage 3: Analyze suspicious patterns with lower confidence
	suspicionScore := s.analyzeSuspiciousPatterns(content)
	if suspicionScore >= s.confidenceThreshold {
		return &commonsqli.Result{
			Detected:   true,
			Blocked:    true,
			Pattern:    "heuristic_analysis",
			Category:   commonsqli.CategoryGeneric,
			Confidence: suspicionScore,
			Input:      s.sanitizeInput(content),
			ScanType:   scanType,
			Mode:       commonsqli.ModeAdvanced,
			Duration:   time.Since(start),
			Metadata: map[string]any{
				"stage":           "suspicion_analysis",
				"suspicion_score": suspicionScore,
			},
		}
	}

	// No injection detected
	return &commonsqli.Result{
		Detected:   false,
		Blocked:    false,
		ScanType:   scanType,
		Mode:       commonsqli.ModeAdvanced,
		Duration:   time.Since(start),
		Confidence: 1.0 - suspicionScore, // Confidence that it's safe
	}
}

// Mode returns ModeAdvanced.
func (s *AdvancedScanner) Mode() commonsqli.Mode {
	return commonsqli.ModeAdvanced
}

// IsEnterprise returns true.
func (s *AdvancedScanner) IsEnterprise() bool {
	return true
}

// calculateConfidence adjusts confidence based on heuristics.
func (s *AdvancedScanner) calculateConfidence(content string, basicResult *commonsqli.Result) float64 {
	confidence := basicResult.Confidence // Start at 1.0 from basic

	// Reduce confidence for likely false positives
	lowerContent := strings.ToLower(content)

	// Check for legitimate SQL education/documentation context
	// These contexts strongly indicate the SQL is being discussed, not executed
	if strings.Contains(lowerContent, "example") ||
		strings.Contains(lowerContent, "tutorial") ||
		strings.Contains(lowerContent, "documentation") {
		confidence -= 0.5
	}

	// Check for code blocks (likely discussing SQL, not injecting)
	// Code blocks are strong indicators of educational/documentation content
	if strings.Contains(content, "```sql") ||
		strings.Contains(content, "```SQL") ||
		strings.Contains(content, "```") ||
		strings.Contains(content, "<code>") {
		confidence -= 0.5
	}

	// Check for quoted context (discussing SQL injection)
	quoteCount := strings.Count(content, "\"") + strings.Count(content, "'")
	if quoteCount > 4 {
		confidence -= 0.1
	}

	// Boost confidence for high-risk indicators
	if strings.Contains(lowerContent, "password") ||
		strings.Contains(lowerContent, "admin") ||
		strings.Contains(lowerContent, "root") {
		confidence += 0.1
	}

	// Boost for multiple SQLi techniques combined
	techniques := 0
	if strings.Contains(lowerContent, "union") {
		techniques++
	}
	if strings.Contains(lowerContent, "select") && strings.Contains(lowerContent, "from") {
		techniques++
	}
	if strings.Contains(lowerContent, "or 1=1") || strings.Contains(lowerContent, "or 1 = 1") {
		techniques++
	}
	if strings.Contains(lowerContent, "--") || strings.Contains(lowerContent, "/*") {
		techniques++
	}
	if techniques > 2 {
		confidence += 0.2
	}

	// Clamp to 0.0-1.0
	if confidence < 0.0 {
		confidence = 0.0
	}
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// analyzeSuspiciousPatterns checks for patterns that might indicate SQL injection
// even if they don't match specific signatures.
func (s *AdvancedScanner) analyzeSuspiciousPatterns(content string) float64 {
	score := 0.0
	lowerContent := strings.ToLower(content)

	// Check for unusual character combinations
	if strings.Contains(content, "' ") || strings.Contains(content, "\" ") {
		score += 0.1
	}
	if strings.Contains(content, "= '") || strings.Contains(content, "=\"") {
		score += 0.1
	}

	// Check for comment markers
	if strings.Contains(content, "--") {
		score += 0.15
	}
	if strings.Contains(content, "/*") || strings.Contains(content, "*/") {
		score += 0.15
	}
	if strings.Contains(content, "#") && strings.Contains(lowerContent, "select") {
		score += 0.2
	}

	// Check for SQL keywords in unusual positions
	if strings.HasSuffix(strings.TrimSpace(lowerContent), "or") ||
		strings.HasSuffix(strings.TrimSpace(lowerContent), "and") {
		score += 0.2
	}

	// Check for hex encoding
	hexPattern := regexp.MustCompile(`0x[0-9a-fA-F]{4,}`)
	if hexPattern.MatchString(content) {
		score += 0.3
	}

	// Check for excessive special characters
	specialCount := 0
	for _, c := range content {
		if c == '\'' || c == '"' || c == ';' || c == '-' {
			specialCount++
		}
	}
	if len(content) > 0 && float64(specialCount)/float64(len(content)) > 0.1 {
		score += 0.2
	}

	// Check for SQL function patterns
	if strings.Contains(lowerContent, "concat(") ||
		strings.Contains(lowerContent, "char(") ||
		strings.Contains(lowerContent, "ascii(") ||
		strings.Contains(lowerContent, "substring(") {
		score += 0.25
	}

	// Clamp to 0.0-1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// sanitizeInput creates a safe snippet of the input for logging.
func (s *AdvancedScanner) sanitizeInput(input string) string {
	if len(input) <= s.snippetLen {
		return strings.ReplaceAll(input, "\n", " ")
	}
	return strings.ReplaceAll(input[:s.snippetLen], "\n", " ") + "..."
}

// Heuristic represents a heuristic rule for advanced detection.
type Heuristic struct {
	name        string
	category    commonsqli.Category
	description string
	pattern     *regexp.Regexp
	weight      float64
}

// matches checks if the heuristic matches the content.
func (h *Heuristic) matches(content string) bool {
	if h.pattern == nil {
		return false
	}
	return h.pattern.MatchString(content)
}

// confidence returns the confidence score for this heuristic.
func (h *Heuristic) confidence(content string) float64 {
	if !h.matches(content) {
		return 0.0
	}
	return h.weight
}

// defaultHeuristics returns the built-in heuristic rules.
func defaultHeuristics() []*Heuristic {
	return []*Heuristic{
		{
			name:        "nested_subquery",
			category:    commonsqli.CategoryGeneric,
			description: "Detects nested subqueries that might bypass simple pattern matching",
			pattern:     regexp.MustCompile(`(?i)\(\s*SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\)`),
			weight:      0.8,
		},
		{
			name:        "case_obfuscation",
			category:    commonsqli.CategoryGeneric,
			description: "Detects mixed case obfuscation (e.g., sElEcT, UnIoN)",
			// Only match truly mixed case - patterns like sElEcT or UnIoN
			// Exclude all-uppercase (SELECT) and all-lowercase (select)
			// These patterns require alternating case
			pattern:     regexp.MustCompile(`(?:s[A-Z][a-z]|S[a-z][A-Z])[eE][cC][tT]|(?:u[A-Z][a-z]|U[a-z][A-Z])[oO][nN]`),
			weight:      0.75,
		},
		{
			name:        "whitespace_obfuscation",
			category:    commonsqli.CategoryGeneric,
			description: "Detects unusual whitespace patterns",
			pattern:     regexp.MustCompile(`(?i)union\s{2,}select|select\s{2,}.*\s{2,}from`),
			weight:      0.7,
		},
		{
			name:        "null_byte_injection",
			category:    commonsqli.CategoryGeneric,
			description: "Detects null byte injection attempts",
			pattern:     regexp.MustCompile(`%00|\\x00|\x00`),
			weight:      0.9,
		},
		{
			name:        "encoded_keywords",
			category:    commonsqli.CategoryGeneric,
			description: "Detects URL-encoded SQL keywords",
			pattern:     regexp.MustCompile(`(?i)%27|%22|%2D%2D|%23|%3B`),
			weight:      0.8,
		},
		{
			name:        "double_encoding",
			category:    commonsqli.CategoryGeneric,
			description: "Detects double URL encoding",
			pattern:     regexp.MustCompile(`%25[0-9a-fA-F]{2}`),
			weight:      0.85,
		},
		{
			name:        "conditional_error",
			category:    commonsqli.CategoryErrorBased,
			description: "Detects conditional error-based injection",
			pattern:     regexp.MustCompile(`(?i)\bIF\s*\(\s*\d+\s*=\s*\d+\s*,`),
			weight:      0.85,
		},
		{
			name:        "order_by_injection",
			category:    commonsqli.CategoryGeneric,
			description: "Detects ORDER BY injection for column enumeration",
			pattern:     regexp.MustCompile(`(?i)ORDER\s+BY\s+\d+\s*(,\s*\d+)*\s*(--|#|/\*)`),
			weight:      0.75,
		},
		{
			name:        "having_injection",
			category:    commonsqli.CategoryBooleanBlind,
			description: "Detects HAVING clause injection",
			pattern:     regexp.MustCompile(`(?i)HAVING\s+\d+\s*=\s*\d+`),
			weight:      0.8,
		},
		{
			name:        "group_by_injection",
			category:    commonsqli.CategoryGeneric,
			description: "Detects GROUP BY injection",
			pattern:     regexp.MustCompile(`(?i)GROUP\s+BY\s+.*\s*(--|#|/\*)`),
			weight:      0.7,
		},
	}
}

func init() {
	// Register advanced scanner
	commonsqli.RegisterScanner(commonsqli.ModeAdvanced, func() commonsqli.Scanner {
		return NewAdvancedScanner()
	})
}
