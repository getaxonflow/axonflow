package policy

import (
	"regexp"
	"testing"
)

func TestFieldRedactor_ApplyToRows(t *testing.T) {
	redactor := NewFieldRedactor()

	// Create test policies
	ssnPolicy := CompiledPolicy{
		PolicyID:   "test_ssn",
		PatternStr: `\b\d{3}-\d{2}-\d{4}\b`,
		Category:   CategoryPIIUS,
		Severity:   SeverityCritical,
	}

	emailPolicy := CompiledPolicy{
		PolicyID:   "test_email",
		PatternStr: `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		Category:   CategoryPIIGlobal,
		Severity:   SeverityMedium,
	}

	// Create test rows
	rows := []map[string]interface{}{
		{"id": 1, "name": "John Doe", "ssn": "123-45-6789", "email": "john@example.com"},
		{"id": 2, "name": "Jane Smith", "ssn": "987-65-4321", "email": "jane@test.org"},
	}

	// Create redaction plans
	plans := []RedactionPlan{
		{
			Match:    PolicyMatch{PolicyID: "test_ssn"},
			Policy:   ssnPolicy,
			Strategy: StrategyMask,
		},
		{
			Match:    PolicyMatch{PolicyID: "test_email"},
			Policy:   emailPolicy,
			Strategy: StrategyPartial,
		},
	}

	// Apply redactions
	result, redacted := redactor.Apply(rows, "rows", plans)

	// Verify result is still []map[string]interface{}
	resultRows, ok := result.([]map[string]interface{})
	if !ok {
		t.Fatal("Apply() did not return []map[string]interface{}")
	}

	// Verify redactions were applied
	if len(redacted) == 0 {
		t.Error("Apply() should have redacted fields")
	}

	// Check SSN was masked
	for _, row := range resultRows {
		ssn := row["ssn"].(string)
		if ssn == "123-45-6789" || ssn == "987-65-4321" {
			t.Errorf("SSN should have been redacted, got %q", ssn)
		}
	}
}

func TestFieldRedactor_Strategies(t *testing.T) {
	redactor := NewFieldRedactor()

	tests := []struct {
		name     string
		strategy RedactionStrategy
		input    string
		piiType  string
		validate func(string) bool
	}{
		{
			name:     "Mask strategy",
			strategy: StrategyMask,
			input:    "123-45-6789",
			piiType:  "ssn",
			validate: func(s string) bool { return len(s) == 11 && s[0] == '1' && s[10] == '9' },
		},
		{
			name:     "Partial strategy",
			strategy: StrategyPartial,
			input:    "john@example.com",
			piiType:  "email",
			validate: func(s string) bool { return len(s) > 4 && s[:2] == "jo" },
		},
		{
			name:     "Remove strategy",
			strategy: StrategyRemove,
			input:    "123-45-6789",
			piiType:  "ssn",
			validate: func(s string) bool { return s == "[REDACTED:ssn]" },
		},
		{
			name:     "Hash strategy",
			strategy: StrategyHash,
			input:    "123-45-6789",
			piiType:  "ssn",
			validate: func(s string) bool { return len(s) > 5 && s[:5] == "HASH_" },
		},
		{
			name:     "Tokenize strategy",
			strategy: StrategyTokenize,
			input:    "123-45-6789",
			piiType:  "ssn",
			validate: func(s string) bool { return len(s) > 6 && s[:6] == "TOKEN_" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := redactor.getStrategy(tt.strategy)
			result := fn(tt.input, tt.piiType)
			if !tt.validate(result) {
				t.Errorf("Strategy %v: got %q for input %q", tt.strategy, result, tt.input)
			}
		})
	}
}

func TestFieldRedactor_ApplyToString(t *testing.T) {
	redactor := NewFieldRedactor()

	policy := CompiledPolicy{
		PolicyID:   "test_ssn",
		PatternStr: `\b\d{3}-\d{2}-\d{4}\b`,
		Category:   CategoryPIIUS,
		Severity:   SeverityCritical,
	}

	plans := []RedactionPlan{
		{
			Match:    PolicyMatch{PolicyID: "test_ssn"},
			Policy:   policy,
			Strategy: StrategyRemove,
		},
	}

	input := "Customer SSN is 123-45-6789 for reference"
	result, redacted := redactor.Apply(input, "string", plans)

	resultStr, ok := result.(string)
	if !ok {
		t.Fatal("Apply() did not return string")
	}

	if len(redacted) != 1 {
		t.Errorf("Expected 1 redaction, got %d", len(redacted))
	}

	if resultStr == input {
		t.Error("String should have been redacted")
	}

	expected := "Customer SSN is [REDACTED:ssn] for reference"
	if resultStr != expected {
		t.Errorf("Got %q, want %q", resultStr, expected)
	}
}

func TestFieldRedactor_ApplyToMap(t *testing.T) {
	redactor := NewFieldRedactor()

	policy := CompiledPolicy{
		PolicyID:   "test_email",
		PatternStr: `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		Category:   CategoryPIIGlobal,
		Severity:   SeverityMedium,
	}

	plans := []RedactionPlan{
		{
			Match:    PolicyMatch{PolicyID: "test_email"},
			Policy:   policy,
			Strategy: StrategyMask,
		},
	}

	input := map[string]interface{}{
		"user": map[string]interface{}{
			"name":  "John Doe",
			"email": "john@example.com",
		},
		"status": "active",
	}

	result, redacted := redactor.Apply(input, "json", plans)

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("Apply() did not return map")
	}

	// Check nested field was redacted
	userMap := resultMap["user"].(map[string]interface{})
	email := userMap["email"].(string)
	if email == "john@example.com" {
		t.Error("Nested email should have been redacted")
	}

	// Check redaction was recorded
	if len(redacted) == 0 {
		t.Error("Expected redaction record")
	}
}

func TestFieldRedactor_EmptyPlans(t *testing.T) {
	redactor := NewFieldRedactor()

	input := "Some text with SSN 123-45-6789"
	result, redacted := redactor.Apply(input, "string", nil)

	// Should return unchanged
	if result != input {
		t.Error("Empty plans should return unchanged content")
	}
	if len(redacted) != 0 {
		t.Error("Empty plans should have no redactions")
	}
}

func TestFieldRedactor_RegisterStrategy(t *testing.T) {
	redactor := NewFieldRedactor()

	// Register custom strategy
	customStrategy := RedactionStrategy("custom")
	redactor.RegisterStrategy(customStrategy, func(value, piiType string) string {
		return "CUSTOM_REDACTED"
	})

	fn := redactor.getStrategy(customStrategy)
	result := fn("test", "type")
	if result != "CUSTOM_REDACTED" {
		t.Errorf("Custom strategy got %q, want CUSTOM_REDACTED", result)
	}
}

func TestFieldRedactor_SetDefaultStrategy(t *testing.T) {
	redactor := NewFieldRedactor()
	redactor.SetDefaultStrategy(StrategyRemove)

	// Unknown strategy should fall back to default
	fn := redactor.getStrategy("unknown_strategy")
	result := fn("test", "type")
	if result != "[REDACTED:type]" {
		t.Errorf("Default strategy got %q, want [REDACTED:type]", result)
	}
}

func TestGetRedactionStrategy(t *testing.T) {
	tests := []struct {
		category PolicyCategory
		severity Severity
		want     RedactionStrategy
	}{
		{CategoryPIIUS, SeverityCritical, StrategyMask},
		{CategoryPIIIndia, SeverityCritical, StrategyMask},
		{CategoryPIIGlobal, SeverityHigh, StrategyMask},
		{CategoryPIIGlobal, SeverityMedium, StrategyPartial},
		{CategorySecuritySQLi, SeverityCritical, StrategyMask},
		// #2965: pii-indonesia is masked like every other national-ID PII
		// category. Pinned at a NON-critical severity so the assertion exercises
		// the explicit category branch, not the critical-severity short-circuit
		// that was previously masking the omission.
		{CategoryPIIIndonesia, SeverityMedium, StrategyMask},
		{CategoryPIIIndonesia, SeverityHigh, StrategyMask},
		{CategoryPIISingapore, SeverityMedium, StrategyMask},
	}

	for _, tt := range tests {
		t.Run(string(tt.category)+"_"+string(tt.severity), func(t *testing.T) {
			got := GetRedactionStrategy(tt.category, tt.severity)
			if got != tt.want {
				t.Errorf("GetRedactionStrategy(%v, %v) = %v, want %v",
					tt.category, tt.severity, got, tt.want)
			}
		})
	}
}

// TestGetRedactionStrategy_EveryPIICategoryExplicit is the #2965 census guard:
// every registered pii-* category MUST resolve to an explicit PII strategy
// (mask or partial), never the generic StrategyRemove default. It evaluates at
// SeverityMedium so the critical-severity short-circuit (which returns
// StrategyMask for ANYTHING) cannot hide a category that would otherwise fall
// through — the exact way pii-indonesia's missing branch went unnoticed. A
// newly-seeded pii-* category with no explicit entry fails here.
func TestGetRedactionStrategy_EveryPIICategoryExplicit(t *testing.T) {
	piiCategories := []PolicyCategory{
		CategoryPIIGlobal,
		CategoryPIIUS,
		CategoryPIIIndia,
		CategoryPIIEU,
		CategoryPIISingapore,
		CategoryPIIIndonesia,
		// Forward-compat: a pii-* jurisdiction NOT explicitly cased in
		// GetRedactionStrategy must still mask (via the pii-* fallback), never
		// fall through to the generic StrategyRemove. This synthetic probe is
		// what makes the census actually forward-safe (#2965 R3): before the
		// fallback existed, an un-cased pii-* returned StrategyRemove and this
		// row would fail.
		PolicyCategory("pii-future-locale"),
	}
	for _, cat := range piiCategories {
		t.Run(string(cat), func(t *testing.T) {
			// Guard against forgetting to update this census: the list must
			// cover every pii-* constant the convention recognizes.
			if !IsPIIPolicyCategory(cat) {
				t.Fatalf("%q is not a pii-* category — fix the test list", cat)
			}
			got := GetRedactionStrategy(cat, SeverityMedium)
			if got == StrategyRemove {
				t.Errorf("GetRedactionStrategy(%s, medium) fell through to the generic default %q; "+
					"PII categories need an explicit mask/partial strategy", cat, got)
			}
			if got != StrategyMask && got != StrategyPartial {
				t.Errorf("GetRedactionStrategy(%s, medium) = %q; want an explicit PII strategy (mask/partial)", cat, got)
			}
		})
	}
}

func TestFieldRedactor_MultipleRedactionsInField(t *testing.T) {
	redactor := NewFieldRedactor()

	ssnPolicy := CompiledPolicy{
		PolicyID:   "test_ssn",
		PatternStr: `\d{3}-\d{2}-\d{4}`,
		Category:   CategoryPIIUS,
		Severity:   SeverityCritical,
	}
	ssnPolicy.Pattern = regexp.MustCompile(ssnPolicy.PatternStr)

	plans := []RedactionPlan{
		{
			Match:    PolicyMatch{PolicyID: "test_ssn"},
			Policy:   ssnPolicy,
			Strategy: StrategyRemove,
		},
	}

	input := "SSNs: 123-45-6789 and 987-65-4321"
	result, redacted := redactor.Apply(input, "string", plans)

	resultStr := result.(string)
	if len(redacted) != 2 {
		t.Errorf("Expected 2 redactions, got %d", len(redacted))
	}

	// Both SSNs should be redacted
	if resultStr == input {
		t.Error("Both SSNs should have been redacted")
	}
}
