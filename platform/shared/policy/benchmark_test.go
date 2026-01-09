package policy

import (
	"context"
	"regexp"
	"testing"
)

// Benchmark policies - representative set for production use
var benchmarkPolicies = []CompiledPolicy{
	{
		PolicyID:      "sqli_union",
		Category:      CategorySecuritySQLi,
		Pattern:       regexp.MustCompile(`(?i)union\s+(?:all\s+)?select`),
		PatternStr:    `(?i)union\s+(?:all\s+)?select`,
		Severity:      SeverityCritical,
		Phase:         PhaseBoth,
		ActionRequest: ActionBlock,
		Enabled:       true,
		Priority:      100,
	},
	{
		PolicyID:      "sqli_drop",
		Category:      CategorySecuritySQLi,
		Pattern:       regexp.MustCompile(`(?i)drop\s+table`),
		PatternStr:    `(?i)drop\s+table`,
		Severity:      SeverityCritical,
		Phase:         PhaseRequest,
		ActionRequest: ActionBlock,
		Enabled:       true,
		Priority:      100,
	},
	{
		PolicyID:       "pii_ssn",
		Category:       CategoryPIIUS,
		Pattern:        regexp.MustCompile(`\b\d{3}[- ]?\d{2}[- ]?\d{4}\b`),
		PatternStr:     `\b\d{3}[- ]?\d{2}[- ]?\d{4}\b`,
		Severity:       SeverityCritical,
		Phase:          PhaseBoth,
		ActionRequest:  ActionBlock,
		ActionResponse: ActionRedact,
		Enabled:        true,
		Priority:       90,
	},
	{
		PolicyID:       "pii_credit_card",
		Category:       CategoryPIIGlobal,
		Pattern:        regexp.MustCompile(`\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b`),
		PatternStr:     `\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b`,
		Severity:       SeverityCritical,
		Phase:          PhaseBoth,
		ActionRequest:  ActionBlock,
		ActionResponse: ActionRedact,
		Enabled:        true,
		Priority:       90,
	},
	{
		PolicyID:       "pii_email",
		Category:       CategoryPIIGlobal,
		Pattern:        regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
		PatternStr:     `\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`,
		Severity:       SeverityMedium,
		Phase:          PhaseResponse,
		ActionResponse: ActionRedact,
		Enabled:        true,
		Priority:       50,
	},
	{
		PolicyID:       "pii_phone",
		Category:       CategoryPIIGlobal,
		Pattern:        regexp.MustCompile(`\b(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}\b`),
		PatternStr:     `\b(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}\b`,
		Severity:       SeverityMedium,
		Phase:          PhaseResponse,
		ActionResponse: ActionRedact,
		Enabled:        true,
		Priority:       50,
	},
	{
		PolicyID:       "pii_aadhaar",
		Category:       CategoryPIIIndia,
		Pattern:        regexp.MustCompile(`\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b`),
		PatternStr:     `\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b`,
		Severity:       SeverityCritical,
		Phase:          PhaseBoth,
		ActionRequest:  ActionBlock,
		ActionResponse: ActionRedact,
		Enabled:        true,
		Priority:       90,
	},
	{
		PolicyID:       "pii_pan",
		Category:       CategoryPIIIndia,
		Pattern:        regexp.MustCompile(`\b[A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z]\b`),
		PatternStr:     `\b[A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z]\b`,
		Severity:       SeverityCritical,
		Phase:          PhaseBoth,
		ActionRequest:  ActionBlock,
		ActionResponse: ActionRedact,
		Enabled:        true,
		Priority:       90,
	},
}

// Benchmark inputs
var (
	cleanQuery      = "SELECT id, name, status FROM users WHERE active = true AND created_at > '2024-01-01'"
	sqliQuery       = "SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin_users"
	cleanResponse   = `{"id": 1, "name": "John Doe", "status": "active", "created_at": "2024-01-15"}`
	piiResponse     = `{"id": 1, "name": "John Doe", "ssn": "123-45-6789", "email": "john@example.com", "phone": "555-123-4567"}`
	largeCleanQuery = generateLargeQuery(1000)
)

func generateLargeQuery(words int) string {
	base := "SELECT column1, column2, column3, column4, column5 FROM table1 WHERE "
	for i := 0; i < words; i++ {
		if i > 0 {
			base += " AND "
		}
		base += "field" + string(rune('a'+i%26)) + " = 'value'"
	}
	return base
}

func BenchmarkEvaluateRequest_CleanQuery(b *testing.B) {
	engine := createTestEngine(benchmarkPolicies)
	ctx := context.Background()
	opts := EvalOptions{TenantID: "test-tenant"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateRequest(ctx, cleanQuery, opts)
	}
}

func BenchmarkEvaluateRequest_SQLiQuery(b *testing.B) {
	engine := createTestEngine(benchmarkPolicies)
	ctx := context.Background()
	opts := EvalOptions{TenantID: "test-tenant"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateRequest(ctx, sqliQuery, opts)
	}
}

func BenchmarkEvaluateRequest_LargeQuery(b *testing.B) {
	engine := createTestEngine(benchmarkPolicies)
	ctx := context.Background()
	opts := EvalOptions{TenantID: "test-tenant"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateRequest(ctx, largeCleanQuery, opts)
	}
}

func BenchmarkEvaluateResponse_CleanData(b *testing.B) {
	engine := createTestEngine(benchmarkPolicies)
	ctx := context.Background()
	opts := EvalOptions{TenantID: "test-tenant"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateResponse(ctx, cleanResponse, opts)
	}
}

func BenchmarkEvaluateResponse_PIIData(b *testing.B) {
	engine := createTestEngine(benchmarkPolicies)
	ctx := context.Background()
	opts := EvalOptions{TenantID: "test-tenant"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateResponse(ctx, piiResponse, opts)
	}
}

func BenchmarkEvaluateResponse_Rows(b *testing.B) {
	engine := createTestEngine(benchmarkPolicies)
	ctx := context.Background()
	opts := EvalOptions{TenantID: "test-tenant"}

	rows := []map[string]interface{}{
		{"id": 1, "name": "John", "email": "john@example.com", "ssn": "123-45-6789"},
		{"id": 2, "name": "Jane", "email": "jane@test.org", "ssn": "987-65-4321"},
		{"id": 3, "name": "Bob", "email": "bob@company.com", "phone": "555-123-4567"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateResponse(ctx, rows, opts)
	}
}

func BenchmarkEvaluateResponse_LargeRows(b *testing.B) {
	engine := createTestEngine(benchmarkPolicies)
	ctx := context.Background()
	opts := EvalOptions{TenantID: "test-tenant"}

	// Create 100 rows
	rows := make([]map[string]interface{}, 100)
	for i := 0; i < 100; i++ {
		rows[i] = map[string]interface{}{
			"id":      i,
			"name":    "User Name",
			"email":   "user@example.com",
			"address": "123 Main Street, City, State 12345",
			"notes":   "This is a longer text field with various content",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateResponse(ctx, rows, opts)
	}
}

func BenchmarkPatternEvaluator_SinglePattern(b *testing.B) {
	evaluator := NewPatternEvaluator(false)
	policy := &benchmarkPolicies[0] // SQLi UNION

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evaluator.Evaluate(cleanQuery, policy)
	}
}

func BenchmarkPatternEvaluator_AllPatterns(b *testing.B) {
	evaluator := NewPatternEvaluator(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evaluator.EvaluateMultiple(cleanQuery, benchmarkPolicies, PhaseRequest)
	}
}

func BenchmarkPatternEvaluator_WithValidators(b *testing.B) {
	evaluator := NewPatternEvaluator(true)
	policy := &benchmarkPolicies[2] // SSN with validator

	input := "SSN: 123-45-6789"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evaluator.Evaluate(input, policy)
	}
}

func BenchmarkRedactor_SingleField(b *testing.B) {
	redactor := NewFieldRedactor()
	plans := []RedactionPlan{
		{
			Match:    PolicyMatch{PolicyID: "pii_ssn"},
			Policy:   benchmarkPolicies[2],
			Strategy: StrategyMask,
		},
	}

	input := "SSN: 123-45-6789"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		redactor.Apply(input, "string", plans)
	}
}

func BenchmarkRedactor_MultipleRows(b *testing.B) {
	redactor := NewFieldRedactor()
	plans := []RedactionPlan{
		{
			Match:    PolicyMatch{PolicyID: "pii_ssn"},
			Policy:   benchmarkPolicies[2],
			Strategy: StrategyMask,
		},
	}

	rows := []map[string]interface{}{
		{"ssn": "123-45-6789"},
		{"ssn": "987-65-4321"},
		{"ssn": "111-22-3333"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		redactor.Apply(rows, "rows", plans)
	}
}

func BenchmarkCache_Hit(b *testing.B) {
	cache := NewPolicyCache(5*60*1000000000, 1000) // 5 minute TTL
	cache.Set("test-tenant", nil, benchmarkPolicies)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get("test-tenant", nil, PhaseRequest)
	}
}

func BenchmarkCache_Miss(b *testing.B) {
	cache := NewPolicyCache(5*60*1000000000, 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get("nonexistent-tenant", nil, PhaseRequest)
	}
}

func BenchmarkValidateCreditCard(b *testing.B) {
	card := "4111111111111111"
	context := "payment card"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateCreditCard(card, context)
	}
}

func BenchmarkValidateSSN(b *testing.B) {
	ssn := "123-45-6789"
	context := "SSN field"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateSSN(ssn, context)
	}
}

func BenchmarkValidateIBAN(b *testing.B) {
	iban := "DE89370400440532013000"
	context := "bank transfer"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateIBAN(iban, context)
	}
}

// BenchmarkEvaluateRequest_Parallel tests concurrent request evaluation
func BenchmarkEvaluateRequest_Parallel(b *testing.B) {
	engine := createTestEngine(benchmarkPolicies)
	ctx := context.Background()
	opts := EvalOptions{TenantID: "test-tenant"}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			engine.EvaluateRequest(ctx, cleanQuery, opts)
		}
	})
}

// BenchmarkEvaluateResponse_Parallel tests concurrent response evaluation
func BenchmarkEvaluateResponse_Parallel(b *testing.B) {
	engine := createTestEngine(benchmarkPolicies)
	ctx := context.Background()
	opts := EvalOptions{TenantID: "test-tenant"}

	rows := []map[string]interface{}{
		{"id": 1, "name": "John", "email": "john@example.com"},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			engine.EvaluateResponse(ctx, rows, opts)
		}
	})
}
