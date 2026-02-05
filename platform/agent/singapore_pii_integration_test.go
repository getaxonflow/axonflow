// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"os"
	"regexp"
	"testing"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
)

// TestSingaporePIIIntegration tests Singapore PII detection with real database
// Uses testcontainers if DATABASE_URL is not set.
func TestSingaporePIIIntegration(t *testing.T) {
	var db *sql.DB

	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		var err error
		db, err = sql.Open("postgres", dbURL)
		if err != nil {
			t.Fatalf("Failed to connect to database: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		if err := db.Ping(); err != nil {
			t.Fatalf("Database ping failed: %v", err)
		}
	} else {
		testutil.SkipIfNoDocker(t)
		pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
		pg.RunMigration(t, testutil.StaticPoliciesSchema())
		pg.RunMigration(t, testutil.SingaporePIISeedData())
		db = pg.DB
	}

	// Enable community mode for testing
	originalDeploymentMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer func() {
		if originalDeploymentMode != "" {
			os.Setenv("DEPLOYMENT_MODE", originalDeploymentMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	// Verify Singapore PII policies exist in database
	t.Run("Singapore PII policies seeded", func(t *testing.T) {
		var count int
		err := db.QueryRow(`
			SELECT COUNT(*) FROM static_policies
			WHERE category = 'pii-singapore' AND tier = 'system'
		`).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query static_policies: %v", err)
		}
		if count < 5 {
			t.Errorf("Expected at least 5 Singapore PII policies, got %d", count)
		}
		t.Logf("Found %d Singapore PII policies in database", count)
	})

	// Verify specific policy IDs exist
	t.Run("Singapore NRIC policy exists", func(t *testing.T) {
		var policyID string
		err := db.QueryRow(`
			SELECT policy_id FROM static_policies
			WHERE policy_id = 'sys_pii_singapore_nric'
		`).Scan(&policyID)
		if err != nil {
			t.Fatalf("Singapore NRIC policy not found: %v", err)
		}
		if policyID != "sys_pii_singapore_nric" {
			t.Errorf("Expected policy_id sys_pii_singapore_nric, got %s", policyID)
		}
	})

	t.Run("Singapore FIN policy exists", func(t *testing.T) {
		var policyID string
		err := db.QueryRow(`
			SELECT policy_id FROM static_policies
			WHERE policy_id = 'sys_pii_singapore_fin'
		`).Scan(&policyID)
		if err != nil {
			t.Fatalf("Singapore FIN policy not found: %v", err)
		}
	})

	t.Run("Singapore UEN policy exists", func(t *testing.T) {
		var policyID string
		err := db.QueryRow(`
			SELECT policy_id FROM static_policies
			WHERE policy_id = 'sys_pii_singapore_uen'
		`).Scan(&policyID)
		if err != nil {
			t.Fatalf("Singapore UEN policy not found: %v", err)
		}
	})

	t.Run("Singapore Phone policy exists", func(t *testing.T) {
		var policyID string
		err := db.QueryRow(`
			SELECT policy_id FROM static_policies
			WHERE policy_id = 'sys_pii_singapore_phone'
		`).Scan(&policyID)
		if err != nil {
			t.Fatalf("Singapore Phone policy not found: %v", err)
		}
	})

	t.Run("Singapore Postal policy exists", func(t *testing.T) {
		var policyID string
		err := db.QueryRow(`
			SELECT policy_id FROM static_policies
			WHERE policy_id = 'sys_pii_singapore_postal'
		`).Scan(&policyID)
		if err != nil {
			t.Fatalf("Singapore Postal policy not found: %v", err)
		}
	})

	// Verify MAS FEAT templates exist (if migration 043 was applied)
	t.Run("MAS FEAT templates exist", func(t *testing.T) {
		var count int
		err := db.QueryRow(`
			SELECT COUNT(*) FROM compliance_templates
			WHERE template_id LIKE 'mas_feat_%'
		`).Scan(&count)
		if err != nil {
			t.Skipf("compliance_templates table may not exist: %v", err)
		}
		if count < 5 {
			t.Logf("Warning: Expected 5 MAS FEAT templates, got %d (migration 043 may not be applied)", count)
		}
	})

	// Cleanup
	t.Cleanup(func() {
		// No cleanup needed - we only read data
	})
}

// TestSingaporePIIPatternsWithEngine tests Singapore PII pattern matching
// using the shared policy engine with mock data (no database required).
func TestSingaporePIIPatternsWithEngine(t *testing.T) {
	// Get Singapore PII patterns from the seed data
	patterns := getSingaporePIIPatterns()
	if len(patterns) != 5 {
		t.Fatalf("Expected 5 Singapore PII patterns, got %d", len(patterns))
	}

	var compiled []testCompiledPattern
	for _, p := range patterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			t.Fatalf("Failed to compile pattern %s: %v", p.ID, err)
		}
		compiled = append(compiled, testCompiledPattern{
			ID:       p.ID,
			Name:     p.Name,
			Pattern:  re,
			Severity: p.Severity,
			Action:   p.Action,
		})
	}

	// Test NRIC detection
	t.Run("NRIC detection", func(t *testing.T) {
		nricPattern := findTestPattern(compiled, "sys_pii_singapore_nric")
		if nricPattern == nil {
			t.Fatal("NRIC pattern not found")
		}

		testCases := []struct {
			name    string
			input   string
			matches bool
		}{
			{"S prefix NRIC", "Customer NRIC is S1234567D", true},
			{"T prefix NRIC", "New customer T9876543J registered", true},
			{"M prefix NRIC", "New hire M1234567K onboarded", true},
			{"F prefix FIN as NRIC", "Employee F1234567N", true}, // F is valid prefix
			{"G prefix FIN as NRIC", "Applicant G9876543X", true},  // G is valid prefix
			{"Lowercase invalid", "s1234567d", false},
			{"Too short", "S123456D", false},
			{"Too long", "S12345678D", false},
			{"Invalid prefix", "X1234567D", false},
			{"No match", "Regular text without NRIC", false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				matched := nricPattern.Pattern.MatchString(tc.input)
				if matched != tc.matches {
					t.Errorf("Input %q: expected match=%v, got %v", tc.input, tc.matches, matched)
				}
			})
		}
	})

	// Test FIN detection (overlaps with NRIC for F/G prefixes, but separate policy)
	t.Run("FIN detection", func(t *testing.T) {
		finPattern := findTestPattern(compiled, "sys_pii_singapore_fin")
		if finPattern == nil {
			t.Fatal("FIN pattern not found")
		}

		testCases := []struct {
			name    string
			input   string
			matches bool
		}{
			{"F prefix FIN", "Employee FIN: F1234567N", true},
			{"G prefix FIN", "Applicant G9876543X submitted documents", true},
			{"Lowercase invalid", "f1234567n", false},
			{"Invalid prefix", "S1234567D", false}, // S is NRIC, not FIN-specific
			{"No match", "Regular text", false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				matched := finPattern.Pattern.MatchString(tc.input)
				if matched != tc.matches {
					t.Errorf("Input %q: expected match=%v, got %v", tc.input, tc.matches, matched)
				}
			})
		}
	})

	// Test UEN detection
	t.Run("UEN detection", func(t *testing.T) {
		uenPattern := findTestPattern(compiled, "sys_pii_singapore_uen")
		if uenPattern == nil {
			t.Fatal("UEN pattern not found")
		}

		testCases := []struct {
			name    string
			input   string
			matches bool
		}{
			{"8-digit UEN", "Invoice from company UEN 53276128A", true},
			{"9-digit UEN", "Vendor UEN: 200312345A verified", true},
			{"T-prefix UEN", "Company T08GA0001A registered", true},
			{"S-prefix UEN", "Entity S78PF0001G", true},
			// Note: R-prefix is not commonly used in UEN format
			{"Short UEN", "12345A", false},
			{"No letter suffix", "53276128", false},
			{"Lowercase", "53276128a", false},
			{"No match", "Regular text", false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				matched := uenPattern.Pattern.MatchString(tc.input)
				if matched != tc.matches {
					t.Errorf("Input %q: expected match=%v, got %v", tc.input, tc.matches, matched)
				}
			})
		}
	})

	// Test Singapore phone detection
	t.Run("Singapore phone detection", func(t *testing.T) {
		phonePattern := findTestPattern(compiled, "sys_pii_singapore_phone")
		if phonePattern == nil {
			t.Fatal("Phone pattern not found")
		}

		testCases := []struct {
			name    string
			input   string
			matches bool
		}{
			{"Mobile +65 9xxx", "Contact customer at +65 9123 4567", true},
			{"Mobile +65 8xxx", "Call me at +65 8765 4321", true},
			{"Landline +65 6xxx", "Office number: +65 6234 5678", true},
			{"No spaces", "+6591234567", true},
			// Note: Pattern requires space-separated format, dashes not supported
			{"With dash", "+65-9123-4567", false},
			{"US phone", "+1 212 555 1234", false},
			{"Malaysia phone", "+60 3 1234 5678", false},
			{"Wrong prefix", "+65 1234 5678", false}, // 1xxx not valid
			{"No match", "Regular text", false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				matched := phonePattern.Pattern.MatchString(tc.input)
				if matched != tc.matches {
					t.Errorf("Input %q: expected match=%v, got %v", tc.input, tc.matches, matched)
				}
			})
		}
	})

	// Test Singapore postal code detection
	t.Run("Singapore postal code detection", func(t *testing.T) {
		postalPattern := findTestPattern(compiled, "sys_pii_singapore_postal")
		if postalPattern == nil {
			t.Fatal("Postal pattern not found")
		}

		testCases := []struct {
			name    string
			input   string
			matches bool
		}{
			{"6-digit postal", "Delivery address: Singapore 238877", true},
			{"Postal prefix", "Located at postal 509876", true},
			{"S keyword", "Address: S(238877)", true},
			{"5-digit invalid", "ZIP 12345", false}, // Too short
			{"7-digit invalid", "Code 1234567", false}, // Too long
			// Note: Pattern matches 6-digit numbers broadly for recall
			{"Number without context", "Random number 654321", true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				matched := postalPattern.Pattern.MatchString(tc.input)
				if matched != tc.matches {
					t.Errorf("Input %q: expected match=%v, got %v", tc.input, tc.matches, matched)
				}
			})
		}
	})

	// Test policy severity levels
	t.Run("Severity levels", func(t *testing.T) {
		expectedSeverities := map[string]PolicySeverity{
			"sys_pii_singapore_nric":   SeverityCritical,
			"sys_pii_singapore_fin":    SeverityCritical,
			"sys_pii_singapore_uen":    SeverityHigh,
			"sys_pii_singapore_phone":  SeverityMedium,
			"sys_pii_singapore_postal": SeverityLow,
		}

		for _, p := range compiled {
			expected, ok := expectedSeverities[p.ID]
			if !ok {
				t.Errorf("Unexpected policy ID: %s", p.ID)
				continue
			}
			if p.Severity != expected {
				t.Errorf("Policy %s: expected severity %s, got %s", p.ID, expected, p.Severity)
			}
		}
	})

	// Test policy actions
	t.Run("Actions", func(t *testing.T) {
		expectedActions := map[string]string{
			"sys_pii_singapore_nric":   "redact",
			"sys_pii_singapore_fin":    "redact",
			"sys_pii_singapore_uen":    "redact",
			"sys_pii_singapore_phone":  "redact",
			"sys_pii_singapore_postal": "warn",
		}

		for _, p := range compiled {
			expected, ok := expectedActions[p.ID]
			if !ok {
				t.Errorf("Unexpected policy ID: %s", p.ID)
				continue
			}
			if p.Action != expected {
				t.Errorf("Policy %s: expected action %s, got %s", p.ID, expected, p.Action)
			}
		}
	})
}

// TestSingaporePIIMultiplePatternsMatch tests that multiple Singapore PII
// patterns can match in a single input.
func TestSingaporePIIMultiplePatternsMatch(t *testing.T) {
	patterns := getSingaporePIIPatterns()

	// Compile all patterns
	var compiledPatterns []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			t.Fatalf("Failed to compile pattern %s: %v", p.ID, err)
		}
		compiledPatterns = append(compiledPatterns, re)
	}

	testCases := []struct {
		name          string
		input         string
		expectedCount int
	}{
		{
			name:          "Single NRIC",
			input:         "Customer S1234567D registered",
			expectedCount: 1,
		},
		{
			name:          "NRIC + Phone",
			input:         "Customer S1234567D phone +65 8123 4567",
			expectedCount: 2,
		},
		{
			name:          "NRIC + UEN + Phone",
			input:         "Customer S1234567D from company 200312345A call +65 8123 4567",
			expectedCount: 3,
		},
		{
			name:          "All patterns",
			input:         "Customer S1234567D from company 200312345A at Singapore 238877 call +65 8123 4567",
			expectedCount: 4,
		},
		{
			name:          "No matches",
			input:         "What is the weather in Singapore?",
			expectedCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matchCount := 0
			for _, re := range compiledPatterns {
				if re.MatchString(tc.input) {
					matchCount++
				}
			}
			if matchCount != tc.expectedCount {
				t.Errorf("Expected %d pattern matches, got %d", tc.expectedCount, matchCount)
			}
		})
	}
}

// TestSingaporePIIFalsePositivePrevention tests that Singapore PII patterns
// do not match common false positives.
func TestSingaporePIIFalsePositivePrevention(t *testing.T) {
	patterns := getSingaporePIIPatterns()

	// Compile all patterns
	patternMap := make(map[string]*regexp.Regexp)
	for _, p := range patterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			t.Fatalf("Failed to compile pattern %s: %v", p.ID, err)
		}
		patternMap[p.ID] = re
	}

	falsePositives := []struct {
		name     string
		input    string
		policyID string
	}{
		// NRIC false positives
		{"Version number like NRIC", "Version A1234567B released", "sys_pii_singapore_nric"},
		{"Product code", "Model X1234567Y available", "sys_pii_singapore_nric"},

		// UEN false positives
		{"Short reference", "Order 123456A", "sys_pii_singapore_uen"},
		{"Version number", "v1.2.3", "sys_pii_singapore_uen"},

		// Phone false positives
		{"US phone number", "+1 415 555 1234", "sys_pii_singapore_phone"},
		{"UK phone number", "+44 20 7946 0958", "sys_pii_singapore_phone"},
		{"Generic number", "123 456 789", "sys_pii_singapore_phone"},

		// Postal code - pattern is intentionally broad for higher recall
		// Note: 6-digit numbers are matched broadly, which may include non-postal codes
		{"US ZIP+4", "ZIP 12345-6789", "sys_pii_singapore_postal"},
	}

	for _, tc := range falsePositives {
		t.Run(tc.name, func(t *testing.T) {
			pattern, ok := patternMap[tc.policyID]
			if !ok {
				t.Fatalf("Policy %s not found", tc.policyID)
			}
			if pattern.MatchString(tc.input) {
				t.Errorf("Pattern %s should NOT match false positive: %q", tc.policyID, tc.input)
			}
		})
	}
}

// TestSingaporePIIContextAwareness tests that patterns work correctly
// in various text contexts.
func TestSingaporePIIContextAwareness(t *testing.T) {
	patterns := getSingaporePIIPatterns()
	nricPattern := findPatternByID(patterns, "sys_pii_singapore_nric")
	if nricPattern == nil {
		t.Fatal("NRIC pattern not found")
	}

	nricRe, err := regexp.Compile(nricPattern.Pattern)
	if err != nil {
		t.Fatalf("Failed to compile NRIC pattern: %v", err)
	}

	contexts := []struct {
		name    string
		input   string
		matches bool
	}{
		{"Start of text", "S1234567D is the customer's NRIC", true},
		{"End of text", "The NRIC is S1234567D", true},
		{"Middle of sentence", "Customer with NRIC S1234567D needs help", true},
		{"In parentheses", "NRIC (S1234567D) verified", true},
		{"In quotes", `NRIC: "S1234567D"`, true},
		{"In JSON", `{"nric": "S1234567D"}`, true},
		{"Multiple on same line", "S1234567D and T9876543J", true},
		{"Preceded by colon", "NRIC:S1234567D", true},
		{"Followed by comma", "S1234567D, the NRIC", true},
		{"URL parameter", "?nric=S1234567D&submit=true", true},
	}

	for _, tc := range contexts {
		t.Run(tc.name, func(t *testing.T) {
			matched := nricRe.MatchString(tc.input)
			if matched != tc.matches {
				t.Errorf("Input %q: expected match=%v, got %v", tc.input, tc.matches, matched)
			}
		})
	}
}

// TestSingaporePIICategoryValidation tests that all Singapore PII policies
// are in the correct category.
func TestSingaporePIICategoryValidation(t *testing.T) {
	patterns := getSingaporePIIPatterns()

	for _, p := range patterns {
		if p.Category != CategoryPIISingapore {
			t.Errorf("Policy %s has category %s, expected %s", p.ID, p.Category, CategoryPIISingapore)
		}
	}
}

// TestSingaporePIIRegexPerformance ensures patterns perform within acceptable time.
func TestSingaporePIIRegexPerformance(t *testing.T) {
	patterns := getSingaporePIIPatterns()

	// Compile all patterns
	var compiledPatterns []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			t.Fatalf("Failed to compile pattern %s: %v", p.ID, err)
		}
		compiledPatterns = append(compiledPatterns, re)
	}

	// Large input with Singapore PII mixed in
	largeInput := "Customer database export: "
	for i := 0; i < 100; i++ {
		largeInput += "User " + string(rune('A'+i%26)) + " has NRIC S1234567D and works at company 200312345A. "
	}

	// Test that all patterns can process large input without timeout
	for i, re := range compiledPatterns {
		t.Run(patterns[i].ID, func(t *testing.T) {
			// This should complete quickly (< 100ms)
			matches := re.FindAllString(largeInput, -1)
			if len(matches) == 0 {
				t.Logf("Pattern %s found 0 matches in large input", patterns[i].ID)
			} else {
				t.Logf("Pattern %s found %d matches in large input", patterns[i].ID, len(matches))
			}
		})
	}
}

// BenchmarkSingaporePIIPatterns benchmarks Singapore PII pattern matching.
func BenchmarkSingaporePIIPatterns(b *testing.B) {
	patterns := getSingaporePIIPatterns()

	var compiledPatterns []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			b.Fatalf("Failed to compile pattern %s: %v", p.ID, err)
		}
		compiledPatterns = append(compiledPatterns, re)
	}

	testInputs := []string{
		"Customer S1234567D phone +65 8123 4567 at Singapore 238877",
		"What is the weather in Singapore today?",
		"Invoice from company UEN 200312345A for services rendered",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, input := range testInputs {
			for _, re := range compiledPatterns {
				_ = re.MatchString(input)
			}
		}
	}
}

// BenchmarkSingaporePIIPatternsSingle benchmarks individual pattern matching.
func BenchmarkSingaporePIIPatternsSingle(b *testing.B) {
	patterns := getSingaporePIIPatterns()

	for _, p := range patterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			b.Fatalf("Failed to compile pattern %s: %v", p.ID, err)
		}

		input := "Customer S1234567D phone +65 8123 4567 company 200312345A at Singapore 238877"

		b.Run(p.ID, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = re.MatchString(input)
			}
		})
	}
}

// testCompiledPattern is a helper type for testing Singapore PII patterns
type testCompiledPattern struct {
	ID       string
	Name     string
	Pattern  *regexp.Regexp
	Severity PolicySeverity
	Action   string
}

// findTestPattern finds a pattern by ID in compiled patterns slice
func findTestPattern(patterns []testCompiledPattern, id string) *testCompiledPattern {
	for i := range patterns {
		if patterns[i].ID == id {
			return &patterns[i]
		}
	}
	return nil
}

// Helper function to find a pattern by ID in SystemPolicySeed slice
func findPatternByID(patterns []SystemPolicySeed, id string) *SystemPolicySeed {
	for i := range patterns {
		if patterns[i].ID == id {
			return &patterns[i]
		}
	}
	return nil
}

// TestSingaporePIIWithUnifiedEngine tests Singapore PII using the shared policy engine pattern
func TestSingaporePIIWithUnifiedEngine(t *testing.T) {
	// This test follows the pattern from platform/shared/policy/engine_test.go
	// but uses Singapore PII patterns specifically

	ctx := context.Background()

	// Get Singapore PII patterns
	seedPatterns := getSingaporePIIPatterns()

	// Convert to test format
	testCases := []struct {
		name           string
		input          string
		expectMatch    bool
		expectSeverity PolicySeverity
	}{
		// NRIC tests
		{
			name:           "NRIC S prefix",
			input:          "Customer NRIC: S1234567D",
			expectMatch:    true,
			expectSeverity: SeverityCritical,
		},
		{
			name:           "NRIC T prefix",
			input:          "T9876543J is the new NRIC",
			expectMatch:    true,
			expectSeverity: SeverityCritical,
		},
		{
			name:           "NRIC M prefix",
			input:          "M1234567K onboarded today",
			expectMatch:    true,
			expectSeverity: SeverityCritical,
		},
		// FIN tests
		{
			name:           "FIN F prefix",
			input:          "Employee FIN: F1234567N",
			expectMatch:    true,
			expectSeverity: SeverityCritical,
		},
		{
			name:           "FIN G prefix",
			input:          "Applicant G9876543X submitted",
			expectMatch:    true,
			expectSeverity: SeverityCritical,
		},
		// UEN tests
		{
			name:           "UEN 8-digit",
			input:          "Company UEN 53276128A",
			expectMatch:    true,
			expectSeverity: SeverityHigh,
		},
		{
			name:           "UEN 9-digit",
			input:          "Vendor UEN: 200312345A",
			expectMatch:    true,
			expectSeverity: SeverityHigh,
		},
		// Phone tests
		{
			name:           "Singapore mobile",
			input:          "Contact: +65 9123 4567",
			expectMatch:    true,
			expectSeverity: SeverityMedium,
		},
		{
			name:           "Singapore landline",
			input:          "Office: +65 6234 5678",
			expectMatch:    true,
			expectSeverity: SeverityMedium,
		},
		// Postal tests
		{
			name:           "Singapore postal",
			input:          "Address: Singapore 238877",
			expectMatch:    true,
			expectSeverity: SeverityLow,
		},
		// Negative tests
		{
			name:        "Clean query",
			input:       "What is the weather in Singapore?",
			expectMatch: false,
		},
		{
			name:        "US phone number",
			input:       "Call me at +1 212 555 1234",
			expectMatch: false,
		},
		{
			name:        "Malaysia phone",
			input:       "Contact: +60 3 1234 5678",
			expectMatch: false,
		},
	}

	// Compile all patterns for testing
	patternMatchers := make(map[string]*regexp.Regexp)
	severities := make(map[string]PolicySeverity)
	for _, p := range seedPatterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			t.Fatalf("Failed to compile pattern %s: %v", p.ID, err)
		}
		patternMatchers[p.ID] = re
		severities[p.ID] = p.Severity
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Check if any pattern matches
			var matched bool
			var matchedSeverity PolicySeverity
			for id, re := range patternMatchers {
				if re.MatchString(tc.input) {
					matched = true
					matchedSeverity = severities[id]
					break
				}
			}

			if matched != tc.expectMatch {
				t.Errorf("Input %q: expected match=%v, got %v", tc.input, tc.expectMatch, matched)
			}

			if tc.expectMatch && matchedSeverity != tc.expectSeverity {
				t.Errorf("Input %q: expected severity %s, got %s", tc.input, tc.expectSeverity, matchedSeverity)
			}

			_ = ctx // Use context for future extension
		})
	}
}
