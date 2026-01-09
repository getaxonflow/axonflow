package policy

import (
	"context"
	"regexp"
	"testing"
	"time"
)

func TestPolicyLoader_GetPolicies_FromCache(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)
	loader := NewPolicyLoader(nil, cache)

	// Pre-populate cache
	policies := []CompiledPolicy{
		{
			PolicyID: "test1",
			Phase:    PhaseRequest,
			Enabled:  true,
		},
	}
	cache.Set("tenant1", nil, policies)

	// Should get from cache (no DB needed)
	result, err := loader.GetPolicies(context.Background(), "tenant1", nil, PhaseRequest)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(result))
	}
}

func TestPolicyLoader_GetPolicies_CacheMiss_NoDB(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)
	loader := NewPolicyLoader(nil, cache)

	// No cache, no DB - should error
	_, err := loader.GetPolicies(context.Background(), "tenant1", nil, PhaseRequest)
	if err == nil {
		t.Error("Expected error when cache miss and no DB")
	}
}

func TestPolicyLoader_FilterByPhase(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)
	loader := NewPolicyLoader(nil, cache)

	policies := []CompiledPolicy{
		{PolicyID: "request_only", Phase: PhaseRequest},
		{PolicyID: "response_only", Phase: PhaseResponse},
		{PolicyID: "both_phases", Phase: PhaseBoth},
	}

	// Test request phase filter
	requestPolicies := loader.filterByPhase(policies, PhaseRequest)
	if len(requestPolicies) != 2 { // request_only and both_phases
		t.Errorf("Expected 2 request policies, got %d", len(requestPolicies))
	}

	// Test response phase filter
	responsePolicies := loader.filterByPhase(policies, PhaseResponse)
	if len(responsePolicies) != 2 { // response_only and both_phases
		t.Errorf("Expected 2 response policies, got %d", len(responsePolicies))
	}
}

func TestPolicyLoader_GetValidatorForPolicy_SSN(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)
	loader := NewPolicyLoader(nil, cache)

	// SSN policy should get a validator
	validator := loader.getValidatorForPolicy("pii_ssn", CategoryPIIUS)
	if validator == nil {
		t.Error("Expected SSN validator for PII US category")
	}

	// Test the validator
	valid, conf := validator("123-45-6789", "ssn field")
	if !valid {
		t.Error("Expected valid SSN")
	}
	if conf < 0.9 {
		t.Errorf("Expected high confidence, got %f", conf)
	}
}

func TestPolicyLoader_GetValidatorForPolicy_CreditCard(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)
	loader := NewPolicyLoader(nil, cache)

	// Credit card policy should get a validator
	validator := loader.getValidatorForPolicy("pii_credit_card", CategoryPIIGlobal)
	if validator == nil {
		t.Error("Expected credit card validator for PII Global category")
	}
}

func TestPolicyLoader_GetValidatorForPolicy_Security(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)
	loader := NewPolicyLoader(nil, cache)

	// Security policies should NOT have validators
	validator := loader.getValidatorForPolicy("sqli_union", CategorySecuritySQLi)
	if validator != nil {
		t.Error("Security policies should not have validators")
	}
}

func TestPolicyLoader_ValidatorMapping(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)
	loader := NewPolicyLoader(nil, cache)

	tests := []struct {
		policyID     string
		category     PolicyCategory
		hasValidator bool
	}{
		{"pii_ssn", CategoryPIIUS, true},
		{"pii_aadhaar", CategoryPIIIndia, true},
		{"pii_pan", CategoryPIIIndia, true},
		{"pii_credit_card", CategoryPIIGlobal, true},
		{"pii_email", CategoryPIIGlobal, true},
		{"pii_iban", CategoryPIIEU, true},
		{"sqli_union", CategorySecuritySQLi, false},
		{"dangerous_cmd", CategorySecurityDangerous, false},
	}

	for _, tt := range tests {
		validator := loader.getValidatorForPolicy(tt.policyID, tt.category)
		hasValidator := validator != nil

		if hasValidator != tt.hasValidator {
			t.Errorf("PolicyID %s, Category %v: expected validator=%v, got %v",
				tt.policyID, tt.category, tt.hasValidator, hasValidator)
		}
	}
}

func TestCompiledPolicy_GetActionForPhase(t *testing.T) {
	policy := CompiledPolicy{
		ActionRequest:  ActionBlock,
		ActionResponse: ActionRedact,
	}

	if policy.GetActionForPhase(PhaseRequest) != ActionBlock {
		t.Error("Expected block for request phase")
	}

	if policy.GetActionForPhase(PhaseResponse) != ActionRedact {
		t.Error("Expected redact for response phase")
	}
}

func TestCompiledPolicy_GetActionForPhase_Fallback(t *testing.T) {
	// Test category-based fallback (Issue #891: PII is non-blocking)

	// Security policy with critical severity should block
	securityPolicy := CompiledPolicy{
		Category: CategorySecuritySQLi,
		Severity: SeverityCritical,
	}
	if securityPolicy.GetActionForPhase(PhaseRequest) != ActionBlock {
		t.Error("Expected block for security category")
	}

	// PII policy should redact (non-blocking per Issue #891)
	piiPolicy := CompiledPolicy{
		Category: CategoryPIIUS,
		Severity: SeverityCritical,
	}
	if piiPolicy.GetActionForPhase(PhaseRequest) != ActionRedact {
		t.Errorf("Expected redact for PII request phase, got %v", piiPolicy.GetActionForPhase(PhaseRequest))
	}
	if piiPolicy.GetActionForPhase(PhaseResponse) != ActionRedact {
		t.Errorf("Expected redact for PII response phase, got %v", piiPolicy.GetActionForPhase(PhaseResponse))
	}

	// Admin access should warn
	adminPolicy := CompiledPolicy{
		Category: CategoryAdminAccess,
		Severity: SeverityHigh,
	}
	if adminPolicy.GetActionForPhase(PhaseRequest) != ActionWarn {
		t.Error("Expected warn for admin access")
	}

	// Unknown category defaults to log
	unknownPolicy := CompiledPolicy{
		Severity: SeverityCritical,
	}
	if unknownPolicy.GetActionForPhase(PhaseRequest) != ActionLog {
		t.Errorf("Expected log for unknown category, got %v", unknownPolicy.GetActionForPhase(PhaseRequest))
	}
}

func TestPolicyMatch_Fields(t *testing.T) {
	match := PolicyMatch{
		PolicyID:   "test_policy",
		PolicyName: "Test Policy",
		Category:   CategoryPIIUS,
		Severity:   SeverityCritical,
		Action:     ActionBlock,
		MatchText:  "123-45-6789",
		StartIndex: 10,
		EndIndex:   21,
		Confidence: 0.95,
		FieldPath:  "rows[0].ssn",
	}

	if match.PolicyID != "test_policy" {
		t.Error("PolicyID mismatch")
	}
	if match.Confidence != 0.95 {
		t.Error("Confidence mismatch")
	}
	if match.StartIndex != 10 {
		t.Error("StartIndex mismatch")
	}
	if match.EndIndex != 21 {
		t.Error("EndIndex mismatch")
	}
}

func TestRedactedField_Fields(t *testing.T) {
	field := RedactedField{
		Path:        "rows[0].ssn",
		OriginalLen: 11,
		RedactedTo:  "[REDACTED:ssn]",
		PolicyID:    "pii_ssn",
		PIIType:     "ssn",
	}

	if field.Path != "rows[0].ssn" {
		t.Error("Path mismatch")
	}
}

func TestRedactionPlan_Fields(t *testing.T) {
	plan := RedactionPlan{
		Match: PolicyMatch{
			PolicyID: "test",
		},
		Policy: CompiledPolicy{
			PolicyID: "test",
			Pattern:  regexp.MustCompile(`\d+`),
		},
		Strategy: StrategyMask,
	}

	if plan.Strategy != StrategyMask {
		t.Error("Strategy mismatch")
	}
}

func TestGetValidatorForCategory(t *testing.T) {
	tests := []struct {
		category     PolicyCategory
		hasValidator bool
	}{
		{CategoryPIIUS, true},
		{CategoryPIIIndia, true},
		{CategoryPIIGlobal, true},
		{CategoryPIIEU, true},
		{CategorySecuritySQLi, false},
		{"unknown", false},
	}

	for _, tt := range tests {
		validator := GetValidatorForCategory(tt.category)
		if (validator != nil) != tt.hasValidator {
			t.Errorf("Category %v: expected validator=%v, got %v",
				tt.category, tt.hasValidator, validator != nil)
		}
	}
}

func TestPolicyLoader_PhaseFiltering(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)
	loader := NewPolicyLoader(nil, cache)

	// Test with all phases
	policies := []CompiledPolicy{
		{PolicyID: "req", Phase: PhaseRequest},
		{PolicyID: "resp", Phase: PhaseResponse},
		{PolicyID: "both", Phase: PhaseBoth},
	}

	// Request phase filter
	filtered := loader.filterByPhase(policies, PhaseRequest)
	if len(filtered) != 2 {
		t.Errorf("Request filter: expected 2, got %d", len(filtered))
	}

	// Response phase filter
	filtered = loader.filterByPhase(policies, PhaseResponse)
	if len(filtered) != 2 {
		t.Errorf("Response filter: expected 2, got %d", len(filtered))
	}

	// Both phases filter (should return all)
	filtered = loader.filterByPhase(policies, PhaseBoth)
	if len(filtered) != 3 {
		t.Errorf("Both filter: expected 3, got %d", len(filtered))
	}
}
