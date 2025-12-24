// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"regexp"
	"testing"
)

// TestGetStaticSystemPolicies verifies all 53 static system policies are correctly defined
func TestGetStaticSystemPolicies(t *testing.T) {
	policies := GetStaticSystemPolicies()

	// Verify total count
	expectedCount := 53
	if len(policies) != expectedCount {
		t.Errorf("Expected %d static policies, got %d", expectedCount, len(policies))
	}

	// Verify all policies have required fields
	for _, p := range policies {
		if p.ID == "" {
			t.Error("Policy has empty ID")
		}
		if p.Name == "" {
			t.Errorf("Policy %s has empty Name", p.ID)
		}
		if p.Pattern == "" {
			t.Errorf("Policy %s has empty Pattern", p.ID)
		}
		if p.Category == "" {
			t.Errorf("Policy %s has empty Category", p.ID)
		}
		if p.Severity == "" {
			t.Errorf("Policy %s has empty Severity", p.ID)
		}
		if p.Action == "" {
			t.Errorf("Policy %s has empty Action", p.ID)
		}
	}
}

// TestStaticPolicyPatternsCompile verifies all static policy patterns are valid RE2 regex
func TestStaticPolicyPatternsCompile(t *testing.T) {
	policies := GetStaticSystemPolicies()

	for _, p := range policies {
		_, err := regexp.Compile(p.Pattern)
		if err != nil {
			t.Errorf("Policy %s has invalid regex pattern: %v\nPattern: %s", p.ID, err, p.Pattern)
		}
	}
}

// TestStaticPolicyCategoryDistribution verifies the expected distribution of policies by category
func TestStaticPolicyCategoryDistribution(t *testing.T) {
	policies := GetStaticSystemPolicies()

	// Count by category
	categoryCounts := make(map[PolicyCategory]int)
	for _, p := range policies {
		categoryCounts[p.Category]++
	}

	// Verify expected counts per category
	expectedCounts := map[PolicyCategory]int{
		CategorySecuritySQLi:  37, // SQL injection patterns
		CategorySecurityAdmin: 4,  // Admin access patterns
		CategoryPIIGlobal:     7,  // Global PII patterns
		CategoryPIIUS:         2,  // US-specific PII patterns
		CategoryPIIEU:         1,  // EU-specific PII patterns
		CategoryPIIIndia:      2,  // India-specific PII patterns
	}

	for category, expected := range expectedCounts {
		actual := categoryCounts[category]
		if actual != expected {
			t.Errorf("Category %s: expected %d policies, got %d", category, expected, actual)
		}
	}

	// Verify no unexpected categories
	for category := range categoryCounts {
		if _, ok := expectedCounts[category]; !ok {
			t.Errorf("Unexpected category found: %s", category)
		}
	}
}

// TestGetDynamicSystemPolicies verifies all 10 dynamic system policies are correctly defined
func TestGetDynamicSystemPolicies(t *testing.T) {
	policies := GetDynamicSystemPolicies()

	// Verify total count
	expectedCount := 10
	if len(policies) != expectedCount {
		t.Errorf("Expected %d dynamic policies, got %d", expectedCount, len(policies))
	}

	// Verify all policies have required fields
	for _, p := range policies {
		if p.ID == "" {
			t.Error("Policy has empty ID")
		}
		if p.Name == "" {
			t.Errorf("Policy %s has empty Name", p.ID)
		}
		if p.PolicyType == "" {
			t.Errorf("Policy %s has empty PolicyType", p.ID)
		}
		if p.Category == "" {
			t.Errorf("Policy %s has empty Category", p.ID)
		}
		if p.Conditions == "" {
			t.Errorf("Policy %s has empty Conditions", p.ID)
		}
		if p.Actions == "" {
			t.Errorf("Policy %s has empty Actions", p.ID)
		}
	}
}

// TestDynamicPolicyConditionsAreValidJSON verifies all dynamic policy conditions are valid JSON
func TestDynamicPolicyConditionsAreValidJSON(t *testing.T) {
	policies := GetDynamicSystemPolicies()

	for _, p := range policies {
		var conditions []interface{}
		if err := json.Unmarshal([]byte(p.Conditions), &conditions); err != nil {
			t.Errorf("Policy %s has invalid Conditions JSON: %v\nConditions: %s", p.ID, err, p.Conditions)
		}

		var actions []interface{}
		if err := json.Unmarshal([]byte(p.Actions), &actions); err != nil {
			t.Errorf("Policy %s has invalid Actions JSON: %v\nActions: %s", p.ID, err, p.Actions)
		}
	}
}

// TestDynamicPolicyCategoryDistribution verifies the expected distribution of dynamic policies
func TestDynamicPolicyCategoryDistribution(t *testing.T) {
	policies := GetDynamicSystemPolicies()

	// Count by category
	categoryCounts := make(map[PolicyCategory]int)
	for _, p := range policies {
		categoryCounts[p.Category]++
	}

	// Verify expected counts per category
	expectedCounts := map[PolicyCategory]int{
		CategoryDynamicRisk:       2, // Risk-based policies
		CategoryDynamicCompliance: 3, // Compliance policies
		CategoryDynamicSecurity:   2, // Security policies
		CategoryDynamicCost:       2, // Cost control policies
		CategoryDynamicAccess:     1, // Access control policies
	}

	for category, expected := range expectedCounts {
		actual := categoryCounts[category]
		if actual != expected {
			t.Errorf("Category %s: expected %d policies, got %d", category, expected, actual)
		}
	}
}

// TestGetSystemPolicyCounts verifies the counts returned by GetSystemPolicyCounts
func TestGetSystemPolicyCounts(t *testing.T) {
	counts := GetSystemPolicyCounts()

	// Verify static policy categories
	expectedStaticCounts := map[PolicyCategory]int{
		CategorySecuritySQLi:  37,
		CategorySecurityAdmin: 4,
		CategoryPIIGlobal:     7,
		CategoryPIIUS:         2,
		CategoryPIIEU:         1,
		CategoryPIIIndia:      2,
	}

	for category, expected := range expectedStaticCounts {
		actual := counts[category]
		if actual != expected {
			t.Errorf("Category %s: expected %d, got %d", category, expected, actual)
		}
	}

	// Verify dynamic policy categories
	expectedDynamicCounts := map[PolicyCategory]int{
		CategoryDynamicRisk:       2,
		CategoryDynamicCompliance: 3,
		CategoryDynamicSecurity:   2,
		CategoryDynamicCost:       2,
		CategoryDynamicAccess:     1,
	}

	for category, expected := range expectedDynamicCounts {
		actual := counts[category]
		if actual != expected {
			t.Errorf("Category %s: expected %d, got %d", category, expected, actual)
		}
	}
}

// TestGetTotalSystemPolicyCount verifies the total count
func TestGetTotalSystemPolicyCount(t *testing.T) {
	total := GetTotalSystemPolicyCount()
	expected := 63 // 53 static + 10 dynamic

	if total != expected {
		t.Errorf("Expected total %d, got %d", expected, total)
	}
}

// TestStaticPolicyIDsAreUnique verifies all static policy IDs are unique
func TestStaticPolicyIDsAreUnique(t *testing.T) {
	policies := GetStaticSystemPolicies()
	ids := make(map[string]bool)

	for _, p := range policies {
		if ids[p.ID] {
			t.Errorf("Duplicate policy ID found: %s", p.ID)
		}
		ids[p.ID] = true
	}
}

// TestDynamicPolicyIDsAreUnique verifies all dynamic policy IDs are unique
func TestDynamicPolicyIDsAreUnique(t *testing.T) {
	policies := GetDynamicSystemPolicies()
	ids := make(map[string]bool)

	for _, p := range policies {
		if ids[p.ID] {
			t.Errorf("Duplicate policy ID found: %s", p.ID)
		}
		ids[p.ID] = true
	}
}

// TestStaticPolicyIDsStartWithSys verifies all static policy IDs follow naming convention
func TestStaticPolicyIDsStartWithSys(t *testing.T) {
	policies := GetStaticSystemPolicies()

	for _, p := range policies {
		if len(p.ID) < 4 || p.ID[:4] != "sys_" {
			t.Errorf("Policy ID %s does not start with 'sys_' prefix", p.ID)
		}
	}
}

// TestDynamicPolicyIDsStartWithSysDyn verifies all dynamic policy IDs follow naming convention
func TestDynamicPolicyIDsStartWithSysDyn(t *testing.T) {
	policies := GetDynamicSystemPolicies()

	for _, p := range policies {
		if len(p.ID) < 8 || p.ID[:8] != "sys_dyn_" {
			t.Errorf("Policy ID %s does not start with 'sys_dyn_' prefix", p.ID)
		}
	}
}

// TestStaticPolicySeveritiesAreValid verifies all static policies have valid severity levels
func TestStaticPolicySeveritiesAreValid(t *testing.T) {
	policies := GetStaticSystemPolicies()
	validSeverities := map[PolicySeverity]bool{
		SeverityCritical: true,
		SeverityHigh:     true,
		SeverityMedium:   true,
		SeverityLow:      true,
	}

	for _, p := range policies {
		if !validSeverities[p.Severity] {
			t.Errorf("Policy %s has invalid severity: %s", p.ID, p.Severity)
		}
	}
}

// TestStaticPolicyActionsAreValid verifies all static policies have valid actions
func TestStaticPolicyActionsAreValid(t *testing.T) {
	policies := GetStaticSystemPolicies()
	validActions := map[string]bool{
		"block":  true,
		"redact": true,
		"warn":   true,
		"log":    true,
	}

	for _, p := range policies {
		if !validActions[p.Action] {
			t.Errorf("Policy %s has invalid action: %s", p.ID, p.Action)
		}
	}
}

// TestStaticPolicyPrioritiesArePositive verifies all static policies have positive priorities
func TestStaticPolicyPrioritiesArePositive(t *testing.T) {
	policies := GetStaticSystemPolicies()

	for _, p := range policies {
		if p.Priority <= 0 {
			t.Errorf("Policy %s has non-positive priority: %d", p.ID, p.Priority)
		}
	}
}

// TestDynamicPolicyPrioritiesArePositive verifies all dynamic policies have positive priorities
func TestDynamicPolicyPrioritiesArePositive(t *testing.T) {
	policies := GetDynamicSystemPolicies()

	for _, p := range policies {
		if p.Priority <= 0 {
			t.Errorf("Policy %s has non-positive priority: %d", p.ID, p.Priority)
		}
	}
}

// TestSQLiPatternsMatchExpectedQueries tests that SQL injection patterns match expected attacks
func TestSQLiPatternsMatchExpectedQueries(t *testing.T) {
	policies := GetStaticSystemPolicies()

	// Filter to only SQLi patterns
	var sqliPatterns []*regexp.Regexp
	for _, p := range policies {
		if p.Category == CategorySecuritySQLi {
			compiled, err := regexp.Compile(p.Pattern)
			if err != nil {
				t.Fatalf("Failed to compile pattern %s: %v", p.ID, err)
			}
			sqliPatterns = append(sqliPatterns, compiled)
		}
	}

	// Test cases that should match
	shouldMatch := []string{
		"SELECT * FROM users UNION SELECT * FROM admin",
		"' OR '1'='1",
		"; DROP TABLE users;",
		"SLEEP(5)",
		"WAITFOR DELAY '0:0:5'",
		"INFORMATION_SCHEMA.TABLES",
	}

	for _, query := range shouldMatch {
		matched := false
		for _, pattern := range sqliPatterns {
			if pattern.MatchString(query) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("Expected SQLi pattern to match: %s", query)
		}
	}
}

// TestPIIPatternsMatchExpectedData tests that PII patterns match expected sensitive data
func TestPIIPatternsMatchExpectedData(t *testing.T) {
	policies := GetStaticSystemPolicies()

	// Filter to only PII patterns
	piiPatterns := make(map[string]*regexp.Regexp)
	for _, p := range policies {
		if p.Category == CategoryPIIGlobal || p.Category == CategoryPIIUS ||
			p.Category == CategoryPIIEU || p.Category == CategoryPIIIndia {
			compiled, err := regexp.Compile(p.Pattern)
			if err != nil {
				t.Fatalf("Failed to compile pattern %s: %v", p.ID, err)
			}
			piiPatterns[p.ID] = compiled
		}
	}

	// Test cases
	tests := []struct {
		name      string
		input     string
		expectPII bool
	}{
		{
			name:      "US SSN format",
			input:     "SSN: 123-45-6789",
			expectPII: true,
		},
		{
			name:      "Credit card number",
			input:     "Card: 4111111111111111",
			expectPII: true,
		},
		{
			name:      "Email address",
			input:     "Email: test@example.com",
			expectPII: true,
		},
		{
			name:      "Indian PAN",
			input:     "PAN: ABCDE1234F",
			expectPII: true,
		},
		{
			name:      "No PII present",
			input:     "Hello, this is a normal message",
			expectPII: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := false
			for _, pattern := range piiPatterns {
				if pattern.MatchString(tt.input) {
					matched = true
					break
				}
			}
			if matched != tt.expectPII {
				t.Errorf("Input '%s': expected PII match=%v, got=%v", tt.input, tt.expectPII, matched)
			}
		})
	}
}

// BenchmarkGetStaticSystemPolicies benchmarks the static policy loading
func BenchmarkGetStaticSystemPolicies(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetStaticSystemPolicies()
	}
}

// BenchmarkGetDynamicSystemPolicies benchmarks the dynamic policy loading
func BenchmarkGetDynamicSystemPolicies(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetDynamicSystemPolicies()
	}
}
