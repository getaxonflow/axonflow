package policy

import (
	"context"
	"regexp"
	"testing"
	"time"
)

// mockPolicyLoader is a mock loader for testing without database.
type mockPolicyLoader struct {
	policies []CompiledPolicy
	err      error
}

func (m *mockPolicyLoader) GetPolicies(ctx context.Context, tenantID string, orgID *string, phase Phase) ([]CompiledPolicy, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.policies, nil
}

// createTestEngine creates an engine with mock policies for testing.
func createTestEngine(policies []CompiledPolicy) *UnifiedPolicyEngine {
	config := DefaultEngineConfig()
	config.RefreshInterval = 0 // Disable background refresh
	config.EnableMetrics = false

	cache := NewPolicyCache(config.CacheTTL, config.MaxPatternCache)

	engine := &UnifiedPolicyEngine{
		config:    config,
		cache:     cache,
		loader:    NewPolicyLoader(nil, cache), // Loader with nil DB, uses cache
		evaluator: NewPatternEvaluator(config.EnableValidators),
		redactor:  NewFieldRedactor(),
		metrics:   NewMetricsCollector(&NoOpAuditQueue{}),
		stopChan:  make(chan struct{}),
	}

	// Pre-populate cache with test policies
	engine.cache.Set("test-tenant", nil, policies)
	engine.initialized = true

	return engine
}

func TestUnifiedPolicyEngine_EvaluateRequest_Block(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli_union",
			Name:          "SQL Injection - UNION",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)union\s+select`),
			PatternStr:    `(?i)union\s+select`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
			Priority:      100,
		},
	}

	engine := createTestEngine(policies)

	result := engine.EvaluateRequest(context.Background(), "SELECT * FROM users UNION SELECT * FROM passwords", EvalOptions{
		TenantID: "test-tenant",
	})

	if !result.Blocked {
		t.Error("Expected request to be blocked")
	}

	if result.BlockedBy == nil {
		t.Error("BlockedBy should not be nil")
	}

	if result.BlockedBy.PolicyID != "sqli_union" {
		t.Errorf("BlockedBy.PolicyID = %q, want sqli_union", result.BlockedBy.PolicyID)
	}

	if len(result.MatchedPolicies) != 1 {
		t.Errorf("MatchedPolicies count = %d, want 1", len(result.MatchedPolicies))
	}
}

func TestUnifiedPolicyEngine_EvaluateRequest_Allow(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli_union",
			Name:          "SQL Injection - UNION",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)union\s+select`),
			PatternStr:    `(?i)union\s+select`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
	}

	engine := createTestEngine(policies)

	result := engine.EvaluateRequest(context.Background(), "SELECT id, name FROM users WHERE active = true", EvalOptions{
		TenantID: "test-tenant",
	})

	if result.Blocked {
		t.Error("Expected request to be allowed")
	}

	if len(result.MatchedPolicies) != 0 {
		t.Errorf("MatchedPolicies count = %d, want 0", len(result.MatchedPolicies))
	}
}

func TestUnifiedPolicyEngine_EvaluateResponse_Redact(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_email",
			Name:           "Email Detection",
			Category:       CategoryPIIGlobal,
			Pattern:        regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			PatternStr:     `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
			Severity:       SeverityMedium,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	rows := []map[string]interface{}{
		{"id": 1, "name": "John", "email": "john@example.com"},
		{"id": 2, "name": "Jane", "email": "jane@test.org"},
	}

	result := engine.EvaluateResponse(context.Background(), rows, EvalOptions{
		TenantID: "test-tenant",
	})

	if result.Blocked {
		t.Error("Expected response to not be blocked")
	}

	if !result.Redacted {
		t.Error("Expected response to be redacted")
	}

	if len(result.RedactedFields) < 2 {
		t.Errorf("RedactedFields count = %d, want >= 2", len(result.RedactedFields))
	}

	// Verify emails were redacted
	resultRows := result.Content.([]map[string]interface{})
	for _, row := range resultRows {
		email := row["email"].(string)
		if email == "john@example.com" || email == "jane@test.org" {
			t.Errorf("Email should have been redacted, got %q", email)
		}
	}
}

func TestUnifiedPolicyEngine_EvaluateResponse_Block(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_ssn",
			Name:           "SSN Detection",
			Category:       CategoryPIIUS,
			Pattern:        regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			PatternStr:     `\b\d{3}-\d{2}-\d{4}\b`,
			Severity:       SeverityCritical,
			Phase:          PhaseResponse,
			ActionResponse: ActionBlock, // Block instead of redact
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	rows := []map[string]interface{}{
		{"id": 1, "name": "John", "ssn": "123-45-6789"},
	}

	result := engine.EvaluateResponse(context.Background(), rows, EvalOptions{
		TenantID: "test-tenant",
	})

	if !result.Blocked {
		t.Error("Expected response to be blocked")
	}
}

func TestUnifiedPolicyEngine_CategoryFiltering(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID: "sqli",
			Category: CategorySecuritySQLi,
			Pattern:  regexp.MustCompile(`(?i)union\s+select`),
			Phase:    PhaseRequest,
			Enabled:  true,
		},
		{
			PolicyID: "pii_email",
			Category: CategoryPIIGlobal,
			Pattern:  regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			Phase:    PhaseRequest,
			Enabled:  true,
		},
	}

	engine := createTestEngine(policies)

	// Test with category filter - only SQLi
	result := engine.EvaluateRequest(context.Background(), "test@example.com", EvalOptions{
		TenantID:   "test-tenant",
		Categories: []PolicyCategory{CategorySecuritySQLi},
	})

	if len(result.MatchedPolicies) != 0 {
		t.Error("Email should not match when filtering for SQLi only")
	}

	// Test with skip category
	result = engine.EvaluateRequest(context.Background(), "test@example.com", EvalOptions{
		TenantID:       "test-tenant",
		SkipCategories: []PolicyCategory{CategoryPIIGlobal},
	})

	if len(result.MatchedPolicies) != 0 {
		t.Error("Email should not match when skipping PII category")
	}
}

func TestUnifiedPolicyEngine_MaxRedactions(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_email",
			Category:       CategoryPIIGlobal,
			Pattern:        regexp.MustCompile(`email\d`),
			PatternStr:     `email\d`,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	// Create content with many matches
	content := "email1 email2 email3 email4 email5"

	result := engine.EvaluateResponse(context.Background(), content, EvalOptions{
		TenantID:      "test-tenant",
		MaxRedactions: 2,
	})

	if len(result.RedactedFields) > 2 {
		t.Errorf("RedactedFields = %d, want <= 2", len(result.RedactedFields))
	}
}

func TestUnifiedPolicyEngine_GracefulDegradation(t *testing.T) {
	config := DefaultEngineConfig()
	config.GracefulDegradation = true
	config.RefreshInterval = 0

	engine := &UnifiedPolicyEngine{
		db:        nil, // No database
		config:    config,
		cache:     NewPolicyCache(config.CacheTTL, config.MaxPatternCache),
		evaluator: NewPatternEvaluator(config.EnableValidators),
		redactor:  NewFieldRedactor(),
		metrics:   NewMetricsCollector(&NoOpAuditQueue{}),
		stopChan:  make(chan struct{}),
	}
	engine.loader = NewPolicyLoader(nil, engine.cache)
	engine.initialized = true

	// #2862: the request plane fails CLOSED on a policy-load error even under
	// GracefulDegradation — a gate that could not scan for SQLi must not admit
	// the request. (Was previously asserted fail-open, which silently disabled
	// enforcement on a DB blip; symmetric with the #2820 response-plane fix.)
	result := engine.EvaluateRequest(context.Background(), "SELECT * UNION SELECT *", EvalOptions{
		TenantID: "test-tenant",
	})

	if !result.Blocked {
		t.Error("request plane must fail CLOSED (block) when policies cannot be loaded")
	}
	if !result.EvaluationError {
		t.Error("a couldn't-scan block must set EvaluationError to distinguish it from a policy verdict")
	}
}

func TestUnifiedPolicyEngine_DefaultTenant(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID: "test",
			Category: CategorySecuritySQLi,
			Pattern:  regexp.MustCompile(`test`),
			Phase:    PhaseRequest,
			Enabled:  true,
		},
	}

	engine := createTestEngine(policies)
	engine.cache.Set("global", nil, policies) // Cache for default tenant

	result := engine.EvaluateRequest(context.Background(), "test", EvalOptions{
		// TenantID not set, should use default
	})

	// Should use "global" as default tenant
	if result.PoliciesEvaluated == 0 {
		t.Error("Should have evaluated policies using default tenant")
	}
}

func TestUnifiedPolicyEngine_GetStats(t *testing.T) {
	engine := createTestEngine(nil)
	stats := engine.GetStats()

	if stats == nil {
		t.Fatal("GetStats() returned nil")
	}

	if _, ok := stats["cache_stats"]; !ok {
		t.Error("Stats missing cache_stats")
	}

	if _, ok := stats["evaluator_stats"]; !ok {
		t.Error("Stats missing evaluator_stats")
	}

	if _, ok := stats["config"]; !ok {
		t.Error("Stats missing config")
	}
}

func TestUnifiedPolicyEngine_InvalidateCache(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID: "test",
			Category: CategorySecuritySQLi,
			Pattern:  regexp.MustCompile(`test`),
			Phase:    PhaseRequest,
			Enabled:  true,
		},
	}

	engine := createTestEngine(policies)

	// Verify cache hit
	result1 := engine.EvaluateRequest(context.Background(), "test", EvalOptions{
		TenantID: "test-tenant",
	})
	if result1.PoliciesEvaluated != 1 {
		t.Error("Should have found policy in cache")
	}

	// Invalidate cache
	engine.InvalidateCache("test-tenant", nil)

	// Cache should be empty (no DB, so no reload)
	cacheStats := engine.cache.GetStats()
	if cacheStats.CachedTenants > 0 {
		t.Error("Cache should be empty after invalidation")
	}
}

func TestBuildPolicyInfo(t *testing.T) {
	request := &RequestResult{
		Blocked:           false,
		PoliciesEvaluated: 5,
		MatchedPolicies:   []PolicyMatch{{PolicyID: "p1"}},
		ProcessingTimeMs:  2,
	}

	response := &ResponseResult{
		Blocked:           false,
		PoliciesEvaluated: 10,
		MatchedPolicies:   []PolicyMatch{{PolicyID: "p2"}},
		RedactedFields:    []RedactedField{{Path: "field1"}},
		ProcessingTimeMs:  3,
	}

	info := BuildPolicyInfo(request, response)

	if info.PoliciesEvaluated != 15 {
		t.Errorf("PoliciesEvaluated = %d, want 15", info.PoliciesEvaluated)
	}

	if info.RedactionsApplied != 1 {
		t.Errorf("RedactionsApplied = %d, want 1", info.RedactionsApplied)
	}

	if info.ProcessingTimeMs != 5 {
		t.Errorf("ProcessingTimeMs = %d, want 5", info.ProcessingTimeMs)
	}

	if len(info.MatchedPolicies) != 2 {
		t.Errorf("MatchedPolicies count = %d, want 2", len(info.MatchedPolicies))
	}
}

func TestGetRedactedFieldPaths(t *testing.T) {
	result := &ResponseResult{
		RedactedFields: []RedactedField{
			{Path: "rows[0].ssn"},
			{Path: "rows[1].email"},
		},
	}

	paths := GetRedactedFieldPaths(result)

	if len(paths) != 2 {
		t.Errorf("Paths count = %d, want 2", len(paths))
	}

	if paths[0] != "rows[0].ssn" {
		t.Errorf("paths[0] = %q, want rows[0].ssn", paths[0])
	}
}

func TestMergePolicyInfo(t *testing.T) {
	tests := []struct {
		name     string
		request  *PolicyInfo
		response *PolicyInfo
		want     *PolicyInfo
	}{
		{
			name:     "Both nil",
			request:  nil,
			response: nil,
			want:     nil,
		},
		{
			name:    "Request only",
			request: &PolicyInfo{PoliciesEvaluated: 5, Blocked: true, BlockReason: "SQLi"},
			want:    &PolicyInfo{PoliciesEvaluated: 5, Blocked: true, BlockReason: "SQLi"},
		},
		{
			name:     "Response only",
			response: &PolicyInfo{PoliciesEvaluated: 10, RedactionsApplied: 3},
			want:     &PolicyInfo{PoliciesEvaluated: 10, RedactionsApplied: 3},
		},
		{
			name:     "Both merged",
			request:  &PolicyInfo{PoliciesEvaluated: 5, ProcessingTimeMs: 2},
			response: &PolicyInfo{PoliciesEvaluated: 10, RedactionsApplied: 3, ProcessingTimeMs: 3},
			want:     &PolicyInfo{PoliciesEvaluated: 15, RedactionsApplied: 3, ProcessingTimeMs: 5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergePolicyInfo(tt.request, tt.response)
			if tt.want == nil {
				if got != nil {
					t.Error("Expected nil result")
				}
				return
			}
			if got.PoliciesEvaluated != tt.want.PoliciesEvaluated {
				t.Errorf("PoliciesEvaluated = %d, want %d", got.PoliciesEvaluated, tt.want.PoliciesEvaluated)
			}
		})
	}
}

func TestGlobalEngine_SetAndGet(t *testing.T) {
	// Test SetGlobalEngine and GetGlobalEngine
	cache := NewPolicyCache(5*time.Minute, 100)
	engine := &UnifiedPolicyEngine{
		config:      DefaultEngineConfig(),
		cache:       cache,
		loader:      NewPolicyLoader(nil, cache),
		evaluator:   NewPatternEvaluator(false),
		redactor:    NewFieldRedactor(),
		metrics:     NewMetricsCollector(&NoOpAuditQueue{}),
		stopChan:    make(chan struct{}),
		initialized: true,
	}

	// Set global engine
	SetGlobalEngine(engine)

	// Get global engine
	got := GetGlobalEngine()
	if got != engine {
		t.Error("GetGlobalEngine did not return the same engine")
	}

	// Clear for other tests
	SetGlobalEngine(nil)
}

func TestGlobalEngine_Nil(t *testing.T) {
	// Ensure global engine is nil
	SetGlobalEngine(nil)

	got := GetGlobalEngine()
	if got != nil {
		t.Error("Expected nil global engine")
	}
}

func TestUnifiedPolicyEngine_Stop(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID: "test",
			Phase:    PhaseRequest,
			Pattern:  regexp.MustCompile(`test`),
		},
	}
	engine := createTestEngine(policies)

	// Stop should not panic
	engine.Stop()

	// Calling stop again should be safe
	engine.Stop()
}

func TestUnifiedPolicyEngine_EvaluateResponse_String(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_ssn",
			Name:           "SSN Detection",
			Category:       CategoryPIIUS,
			Pattern:        regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			PatternStr:     `\d{3}-\d{2}-\d{4}`,
			Severity:       SeverityCritical,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	// Test with string content
	content := "Customer SSN: 123-45-6789"
	result := engine.EvaluateResponse(context.Background(), content, EvalOptions{
		TenantID: "test-tenant",
	})

	if !result.Redacted {
		t.Error("Expected string to be redacted")
	}

	resultStr, ok := result.Content.(string)
	if !ok {
		t.Fatal("Expected string result")
	}
	if resultStr == content {
		t.Error("Content should have been modified")
	}
}

func TestUnifiedPolicyEngine_EvaluateResponse_JSON(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_email",
			Category:       CategoryPIIGlobal,
			Pattern:        regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			PatternStr:     `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			Severity:       SeverityMedium,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	// Test with map content (JSON)
	content := map[string]interface{}{
		"name":  "John",
		"email": "john@example.com",
	}

	result := engine.EvaluateResponse(context.Background(), content, EvalOptions{
		TenantID: "test-tenant",
	})

	if !result.Redacted {
		t.Error("Expected JSON to be redacted")
	}

	resultMap, ok := result.Content.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map result")
	}
	if resultMap["email"] == "john@example.com" {
		t.Error("Email should have been redacted")
	}
}

func TestDefaultEngineConfig(t *testing.T) {
	config := DefaultEngineConfig()

	if config.CacheTTL != 5*time.Minute {
		t.Errorf("CacheTTL = %v, want 5m", config.CacheTTL)
	}

	if config.MaxPatternCache != 1000 {
		t.Errorf("MaxPatternCache = %d, want 1000", config.MaxPatternCache)
	}

	if !config.EnableValidators {
		t.Error("EnableValidators should be true by default")
	}

	if !config.GracefulDegradation {
		t.Error("GracefulDegradation should be true by default")
	}
}

func TestUnifiedPolicyEngine_EvaluateResponse_BlockSecurityPattern(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "dangerous_pattern",
			Name:           "Dangerous Response Pattern",
			Category:       CategorySecurityDangerous,
			Pattern:        regexp.MustCompile(`CONFIDENTIAL-SECRET`),
			PatternStr:     `CONFIDENTIAL-SECRET`,
			Severity:       SeverityCritical,
			Phase:          PhaseResponse,
			ActionResponse: ActionBlock,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	result := engine.EvaluateResponse(context.Background(), "Contains CONFIDENTIAL-SECRET data", EvalOptions{
		TenantID: "test-tenant",
	})

	if !result.Blocked {
		t.Error("Expected response to be blocked")
	}
	if result.BlockedBy == nil {
		t.Error("BlockedBy should not be nil")
	}
}

func TestUnifiedPolicyEngine_EvaluateResponse_Rows(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_ssn",
			Name:           "SSN Detection",
			Category:       CategoryPIIUS,
			Pattern:        regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			PatternStr:     `\d{3}-\d{2}-\d{4}`,
			Severity:       SeverityCritical,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	// Test with database rows
	rows := []map[string]interface{}{
		{"id": 1, "name": "Alice", "ssn": "123-45-6789"},
		{"id": 2, "name": "Bob", "ssn": "987-65-4321"},
	}

	result := engine.EvaluateResponse(context.Background(), rows, EvalOptions{
		TenantID: "test-tenant",
	})

	if !result.Redacted {
		t.Error("Expected rows to be redacted")
	}

	resultRows, ok := result.Content.([]map[string]interface{})
	if !ok {
		t.Fatal("Expected rows result")
	}
	if len(resultRows) != 2 {
		t.Errorf("Expected 2 rows, got %d", len(resultRows))
	}
}

func TestUnifiedPolicyEngine_EvaluateRequest_CategoryFilter(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli_union",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)union\s+select`),
			PatternStr:    `(?i)union\s+select`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
		{
			PolicyID:      "pii_ssn",
			Category:      CategoryPIIUS,
			Pattern:       regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			PatternStr:    `\d{3}-\d{2}-\d{4}`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
	}

	engine := createTestEngine(policies)

	// Only check SQLi, skip PII
	result := engine.EvaluateRequest(context.Background(), "123-45-6789 UNION SELECT * FROM users", EvalOptions{
		TenantID:       "test-tenant",
		Categories:     []PolicyCategory{CategorySecuritySQLi},
		SkipCategories: []PolicyCategory{CategoryPIIUS},
	})

	if !result.Blocked {
		t.Error("Expected SQLi to be blocked")
	}
	if result.BlockedBy.PolicyID != "sqli_union" {
		t.Errorf("Expected blocked by sqli_union, got %s", result.BlockedBy.PolicyID)
	}
}

func TestUnifiedPolicyEngine_EvaluateResponse_WithMaxRedactions(t *testing.T) {
	// Test that MaxRedactions option is respected
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_ssn",
			Category:       CategoryPIIUS,
			Pattern:        regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			PatternStr:     `\d{3}-\d{2}-\d{4}`,
			Severity:       SeverityCritical,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	// Content with SSN that should match
	content := "SSN: 123-45-6789"
	result := engine.EvaluateResponse(context.Background(), content, EvalOptions{
		TenantID:      "test-tenant",
		MaxRedactions: 100, // High limit, should work
	})

	// Should have at least one redaction (verifies MaxRedactions path is taken)
	if !result.Redacted {
		t.Error("Expected content to be redacted")
	}
}

func TestUnifiedPolicyEngine_EvaluateResponse_EmptyContent(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_ssn",
			Category:       CategoryPIIUS,
			Pattern:        regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			PatternStr:     `\d{3}-\d{2}-\d{4}`,
			Severity:       SeverityCritical,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	result := engine.EvaluateResponse(context.Background(), "", EvalOptions{
		TenantID: "test-tenant",
	})

	if result.Redacted {
		t.Error("Empty content should not be redacted")
	}
}

func TestUnifiedPolicyEngine_EvaluateResponse_NestedMap(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_email",
			Category:       CategoryPIIGlobal,
			Pattern:        regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			PatternStr:     `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			Severity:       SeverityMedium,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	// Nested map content
	content := map[string]interface{}{
		"user": map[string]interface{}{
			"name":  "John",
			"email": "john@example.com",
		},
	}

	result := engine.EvaluateResponse(context.Background(), content, EvalOptions{
		TenantID: "test-tenant",
	})

	if !result.Redacted {
		t.Error("Expected nested map to be redacted")
	}
}

func TestUnifiedPolicyEngine_DefaultTenantFallback(t *testing.T) {
	config := DefaultEngineConfig()
	config.RefreshInterval = 0
	config.EnableMetrics = false
	config.DefaultTenant = "default-tenant"

	cache := NewPolicyCache(config.CacheTTL, config.MaxPatternCache)
	engine := &UnifiedPolicyEngine{
		config:    config,
		cache:     cache,
		loader:    NewPolicyLoader(nil, cache),
		evaluator: NewPatternEvaluator(config.EnableValidators),
		redactor:  NewFieldRedactor(),
		metrics:   NewMetricsCollector(&NoOpAuditQueue{}),
		stopChan:  make(chan struct{}),
	}

	// Pre-populate cache with default tenant policies
	policies := []CompiledPolicy{
		{
			PolicyID:      "test",
			Pattern:       regexp.MustCompile(`test`),
			PatternStr:    "test",
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
	}
	engine.cache.Set("default-tenant", nil, policies)
	engine.initialized = true

	// Request without tenant ID should use default
	result := engine.EvaluateRequest(context.Background(), "test input", EvalOptions{})

	if !result.Blocked {
		t.Error("Expected default tenant policy to be applied")
	}
}

func TestGetRedactedFieldPaths_Nil(t *testing.T) {
	result := GetRedactedFieldPaths(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}

	result = GetRedactedFieldPaths(&ResponseResult{RedactedFields: nil})
	if result != nil {
		t.Error("Expected nil for empty redacted fields")
	}
}

func TestGetRedactedFieldPaths_WithFields(t *testing.T) {
	response := &ResponseResult{
		RedactedFields: []RedactedField{
			{Path: "user.ssn"},
			{Path: "user.email"},
		},
	}

	paths := GetRedactedFieldPaths(response)
	if len(paths) != 2 {
		t.Errorf("Expected 2 paths, got %d", len(paths))
	}
	if paths[0] != "user.ssn" {
		t.Errorf("Expected user.ssn, got %s", paths[0])
	}
}

func TestUnifiedPolicyEngine_EvaluateResponse_ArrayInMap(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_ssn",
			Category:       CategoryPIIUS,
			Pattern:        regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			PatternStr:     `\d{3}-\d{2}-\d{4}`,
			Severity:       SeverityCritical,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	// Content with array inside map (tests appendStrings with []interface{})
	content := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{"name": "Alice", "ssn": "123-45-6789"},
			map[string]interface{}{"name": "Bob", "ssn": "987-65-4321"},
		},
	}

	result := engine.EvaluateResponse(context.Background(), content, EvalOptions{
		TenantID: "test-tenant",
	})

	if !result.Redacted {
		t.Error("Expected array content to be redacted")
	}
}

func TestUnifiedPolicyEngine_EvaluateResponse_UnknownContentType(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_ssn",
			Category:       CategoryPIIUS,
			Pattern:        regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			PatternStr:     `\d{3}-\d{2}-\d{4}`,
			Severity:       SeverityCritical,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	// Content with non-standard type (tests default fmt.Sprintf path)
	content := struct{ SSN string }{"123-45-6789"}

	result := engine.EvaluateResponse(context.Background(), content, EvalOptions{
		TenantID: "test-tenant",
	})

	// Should still detect the SSN in the fmt.Sprintf output
	if result.PoliciesEvaluated == 0 {
		t.Error("Expected policies to be evaluated")
	}
}

func TestUnifiedPolicyEngine_FilterByCategories_ExcludeOnly(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`UNION`),
			PatternStr:    `UNION`,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
		{
			PolicyID:      "pii_ssn",
			Category:      CategoryPIIUS,
			Pattern:       regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			PatternStr:    `\d{3}-\d{2}-\d{4}`,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
	}

	engine := createTestEngine(policies)

	// Exclude SQLi but include everything else
	result := engine.EvaluateRequest(context.Background(), "UNION 123-45-6789", EvalOptions{
		TenantID:       "test-tenant",
		SkipCategories: []PolicyCategory{CategorySecuritySQLi},
	})

	// Should be blocked by PII, not SQLi
	if !result.Blocked {
		t.Error("Expected PII block")
	}
	if result.BlockedBy.PolicyID != "pii_ssn" {
		t.Errorf("Expected blocked by pii_ssn, got %s", result.BlockedBy.PolicyID)
	}
}

func TestUnifiedPolicyEngine_GetStats_FullStructure(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID: "test",
			Phase:    PhaseRequest,
			Pattern:  regexp.MustCompile(`test`),
		},
	}
	engine := createTestEngine(policies)

	stats := engine.GetStats()
	if stats == nil {
		t.Fatal("GetStats returned nil")
	}

	if _, ok := stats["initialized"]; !ok {
		t.Error("Expected initialized in stats")
	}
	if _, ok := stats["cache_stats"]; !ok {
		t.Error("Expected cache_stats in stats")
	}
	if _, ok := stats["config"]; !ok {
		t.Error("Expected config in stats")
	}
}

// =============================================================================
// ActionOverrides Tests
// =============================================================================

func TestEvaluateRequest_ActionOverrides(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:   "pii_email",
			Name:       "Email Detection",
			Category:   CategoryPIIGlobal,
			Pattern:    regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			PatternStr: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			Severity:   SeverityMedium,
			Phase:      PhaseBoth,
			Enabled:    true,
			// No ActionRequest set — defaults to redact for PII via GetActionForPhase
		},
	}

	engine := createTestEngine(policies)

	// Override PII to "log" — should NOT block
	result := engine.EvaluateRequest(context.Background(), "Contact john@example.com", EvalOptions{
		TenantID: "test-tenant",
		ActionOverrides: map[PolicyCategory]Action{
			CategoryPIIGlobal: ActionLog,
		},
	})

	if result.Blocked {
		t.Error("Expected request NOT to be blocked when PII overridden to log")
	}
	if len(result.MatchedPolicies) != 1 {
		t.Fatalf("Expected 1 matched policy, got %d", len(result.MatchedPolicies))
	}
	if result.MatchedPolicies[0].Action != ActionLog {
		t.Errorf("Expected action=log, got %s", result.MatchedPolicies[0].Action)
	}
}

func TestEvaluateRequest_ActionOverrides_SQLiToWarn(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli_union",
			Name:          "SQL Injection - UNION",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)union\s+select`),
			PatternStr:    `(?i)union\s+select`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
	}

	engine := createTestEngine(policies)

	// Override SQLi from block to warn
	result := engine.EvaluateRequest(context.Background(), "SELECT * FROM users UNION SELECT * FROM passwords", EvalOptions{
		TenantID: "test-tenant",
		ActionOverrides: map[PolicyCategory]Action{
			CategorySecuritySQLi: ActionWarn,
		},
	})

	if result.Blocked {
		t.Error("Expected request NOT to be blocked when SQLi overridden to warn")
	}
	if len(result.MatchedPolicies) != 1 {
		t.Fatalf("Expected 1 matched policy, got %d", len(result.MatchedPolicies))
	}
	if result.MatchedPolicies[0].Action != ActionWarn {
		t.Errorf("Expected action=warn, got %s", result.MatchedPolicies[0].Action)
	}
}

func TestEvaluateResponse_ActionOverrides(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_email",
			Name:           "Email Detection",
			Category:       CategoryPIIGlobal,
			Pattern:        regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			PatternStr:     `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			Severity:       SeverityMedium,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	// Override PII to block instead of redact
	result := engine.EvaluateResponse(context.Background(), "Contact john@example.com", EvalOptions{
		TenantID: "test-tenant",
		ActionOverrides: map[PolicyCategory]Action{
			CategoryPIIGlobal: ActionBlock,
		},
	})

	if !result.Blocked {
		t.Error("Expected response to be blocked when PII overridden to block")
	}
	if result.Redacted {
		t.Error("Should NOT redact when action overridden to block")
	}
}

func TestEvaluateResponse_ActionOverrides_PIIToLog(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_email",
			Name:           "Email Detection",
			Category:       CategoryPIIGlobal,
			Pattern:        regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			PatternStr:     `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			Severity:       SeverityMedium,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	content := "Contact john@example.com"
	// Override PII to log — should NOT redact
	result := engine.EvaluateResponse(context.Background(), content, EvalOptions{
		TenantID: "test-tenant",
		ActionOverrides: map[PolicyCategory]Action{
			CategoryPIIGlobal: ActionLog,
		},
	})

	if result.Blocked {
		t.Error("Expected response NOT to be blocked")
	}
	if result.Redacted {
		t.Error("Expected response NOT to be redacted when PII overridden to log")
	}
	if len(result.MatchedPolicies) != 1 {
		t.Fatalf("Expected 1 matched policy, got %d", len(result.MatchedPolicies))
	}
	if result.MatchedPolicies[0].Action != ActionLog {
		t.Errorf("Expected action=log, got %s", result.MatchedPolicies[0].Action)
	}
}

func TestEvaluateRequest_ActionOverrides_EmptyMap(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli_union",
			Name:          "SQL Injection - UNION",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)union\s+select`),
			PatternStr:    `(?i)union\s+select`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
	}

	engine := createTestEngine(policies)

	// Empty ActionOverrides map — should use default behavior
	result := engine.EvaluateRequest(context.Background(), "SELECT * FROM users UNION SELECT * FROM passwords", EvalOptions{
		TenantID:        "test-tenant",
		ActionOverrides: map[PolicyCategory]Action{},
	})

	if !result.Blocked {
		t.Error("Expected request to be blocked with empty overrides (default behavior)")
	}
}

func TestEvaluateRequest_ActionOverrides_NilMap(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli_union",
			Name:          "SQL Injection - UNION",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)union\s+select`),
			PatternStr:    `(?i)union\s+select`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
	}

	engine := createTestEngine(policies)

	// Nil ActionOverrides — should use default behavior
	result := engine.EvaluateRequest(context.Background(), "SELECT * FROM users UNION SELECT * FROM passwords", EvalOptions{
		TenantID: "test-tenant",
	})

	if !result.Blocked {
		t.Error("Expected request to be blocked with nil overrides (default behavior)")
	}
}

func TestEvaluateResponse_ActionOverrides_OnlyCategoryMatched(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "pii_email",
			Name:           "Email Detection",
			Category:       CategoryPIIGlobal,
			Pattern:        regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			PatternStr:     `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			Severity:       SeverityMedium,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
		},
	}

	engine := createTestEngine(policies)

	// Override a different category — PII-Global should still use default (redact)
	result := engine.EvaluateResponse(context.Background(), "Contact john@example.com", EvalOptions{
		TenantID: "test-tenant",
		ActionOverrides: map[PolicyCategory]Action{
			CategorySecuritySQLi: ActionLog, // Override SQLi, not PII
		},
	})

	if result.Blocked {
		t.Error("Expected response NOT to be blocked")
	}
	if !result.Redacted {
		t.Error("Expected PII to still be redacted (override was for different category)")
	}
}

func TestUnifiedPolicyEngine_InvalidateCache_EmptiesCache(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID: "test",
			Phase:    PhaseRequest,
			Pattern:  regexp.MustCompile(`test`),
		},
	}
	engine := createTestEngine(policies)

	// Should not panic
	engine.InvalidateCache("test-tenant", nil)

	// Cache should be empty for that tenant
	stats := engine.cache.GetStats()
	if stats.CachedTenants != 0 {
		t.Errorf("Expected 0 cached tenants after invalidation, got %d", stats.CachedTenants)
	}
}

func TestEvaluateRequest_ParametersSQLi(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli_union",
			Name:          "SQL Injection - UNION",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)union\s+select`),
			PatternStr:    `(?i)union\s+select`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
	}

	engine := createTestEngine(policies)

	result := engine.EvaluateRequest(context.Background(), "Look up this customer", EvalOptions{
		TenantID: "test-tenant",
		Parameters: map[string]interface{}{
			"customer_id": "1 UNION SELECT * FROM passwords --",
		},
	})

	if !result.Blocked {
		t.Fatal("Expected request to be blocked due to SQLi in parameter")
	}
	if result.BlockedBy == nil || result.BlockedBy.PolicyID != "sqli_union" {
		t.Error("Expected BlockedBy to reference sqli_union policy")
	}
	if len(result.MatchedPolicies) != 1 {
		t.Fatalf("Expected 1 matched policy, got %d", len(result.MatchedPolicies))
	}
	if result.MatchedPolicies[0].FieldPath != "parameter 'customer_id'" {
		t.Errorf("Expected FieldPath 'parameter \\'customer_id\\'', got %q", result.MatchedPolicies[0].FieldPath)
	}
}

func TestEvaluateRequest_ParametersPII(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:   "pii_ssn",
			Name:       "US SSN Detection",
			Category:   CategoryPIIUS,
			Pattern:    regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			PatternStr: `\d{3}-\d{2}-\d{4}`,
			Severity:   SeverityCritical,
			Phase:      PhaseBoth,
			Enabled:    true,
			// No ActionRequest set — PII defaults to redact, not block
		},
	}

	engine := createTestEngine(policies)

	result := engine.EvaluateRequest(context.Background(), "Update the employee record", EvalOptions{
		TenantID: "test-tenant",
		Parameters: map[string]interface{}{
			"ssn": "123-45-6789",
		},
	})

	if result.Blocked {
		t.Error("Expected request NOT to be blocked (PII defaults to redact)")
	}
	if len(result.MatchedPolicies) != 1 {
		t.Fatalf("Expected 1 matched policy, got %d", len(result.MatchedPolicies))
	}
	if result.MatchedPolicies[0].PolicyID != "pii_ssn" {
		t.Errorf("Expected matched policy pii_ssn, got %s", result.MatchedPolicies[0].PolicyID)
	}
	if result.MatchedPolicies[0].FieldPath != "parameter 'ssn'" {
		t.Errorf("Expected FieldPath 'parameter \\'ssn\\'', got %q", result.MatchedPolicies[0].FieldPath)
	}
}

func TestEvaluateRequest_NilParameters(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli_union",
			Name:          "SQL Injection - UNION",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)union\s+select`),
			PatternStr:    `(?i)union\s+select`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
	}

	engine := createTestEngine(policies)

	// Nil parameters — backward compatible, should not panic
	result := engine.EvaluateRequest(context.Background(), "What is the weather today?", EvalOptions{
		TenantID:   "test-tenant",
		Parameters: nil,
	})

	if result.Blocked {
		t.Error("Expected request NOT to be blocked with clean statement and nil parameters")
	}
	if len(result.MatchedPolicies) != 0 {
		t.Errorf("Expected 0 matched policies, got %d", len(result.MatchedPolicies))
	}
}

func TestEvaluateRequest_NumericParametersNoFalsePositives(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli_union",
			Name:          "SQL Injection - UNION",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)union\s+select`),
			PatternStr:    `(?i)union\s+select`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
		{
			PolicyID:   "pii_ssn",
			Name:       "US SSN Detection",
			Category:   CategoryPIIUS,
			Pattern:    regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			PatternStr: `\d{3}-\d{2}-\d{4}`,
			Severity:   SeverityCritical,
			Phase:      PhaseBoth,
			Enabled:    true,
		},
	}

	engine := createTestEngine(policies)

	result := engine.EvaluateRequest(context.Background(), "Fetch metrics", EvalOptions{
		TenantID: "test-tenant",
		Parameters: map[string]interface{}{
			"page":     42,
			"limit":    100,
			"active":   true,
			"ratio":    3.14,
			"order_id": int64(999999),
		},
	})

	if result.Blocked {
		t.Error("Expected request NOT to be blocked — ordinary numeric/bool values should not match")
	}
	if len(result.MatchedPolicies) != 0 {
		t.Errorf("Expected 0 matched policies for ordinary numeric/bool parameters, got %d", len(result.MatchedPolicies))
	}
}

func TestEvaluateRequest_NumericParameterPIIDetected(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:   "pii_credit_card",
			Name:       "Credit Card Detection",
			Category:   CategoryPIIGlobal,
			Pattern:    regexp.MustCompile(`\b\d{13,19}\b`),
			PatternStr: `\b\d{13,19}\b`,
			Severity:   SeverityCritical,
			Phase:      PhaseBoth,
			Enabled:    true,
		},
	}

	engine := createTestEngine(policies)

	// A credit card number passed as an integer should still be detected
	result := engine.EvaluateRequest(context.Background(), "Process payment", EvalOptions{
		TenantID: "test-tenant",
		Parameters: map[string]interface{}{
			"card_number": int64(4111111111111111),
		},
	})

	if len(result.MatchedPolicies) == 0 {
		t.Error("Expected numeric parameter to be scanned and PII detected, but got 0 matches")
	}
}

func TestEvaluateRequest_Float64ParameterPIIDetected(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:   "pii_credit_card",
			Name:       "Credit Card Detection",
			Category:   CategoryPIIGlobal,
			Pattern:    regexp.MustCompile(`\b\d{13,19}\b`),
			PatternStr: `\b\d{13,19}\b`,
			Severity:   SeverityCritical,
			Phase:      PhaseBoth,
			Enabled:    true,
		},
	}

	engine := createTestEngine(policies)

	// JSON decodes numbers as float64 — this must still match PII patterns.
	// Before the fix, float64(4111111111111111) was formatted as "4.111111111111111e+15"
	// which would NOT match \b\d{13,19}\b.
	result := engine.EvaluateRequest(context.Background(), "Process payment", EvalOptions{
		TenantID: "test-tenant",
		Parameters: map[string]interface{}{
			"card_number": float64(4111111111111111),
		},
	})

	if len(result.MatchedPolicies) == 0 {
		t.Error("Expected float64 parameter to be scanned and PII detected, but got 0 matches")
	}
}

func TestEvaluateRequest_BoolParametersSkipped(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli_drop",
			Name:          "SQL Injection - DROP TABLE",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)drop\s+table`),
			PatternStr:    `(?i)drop\s+table`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
	}

	engine := createTestEngine(policies)

	result := engine.EvaluateRequest(context.Background(), "Check status", EvalOptions{
		TenantID: "test-tenant",
		Parameters: map[string]interface{}{
			"active":   true,
			"verified": false,
		},
	})

	if result.Blocked {
		t.Error("Expected bool parameters to be skipped entirely")
	}
	if len(result.MatchedPolicies) != 0 {
		t.Errorf("Expected 0 matched policies for bool parameters, got %d", len(result.MatchedPolicies))
	}
}

func TestEvaluateRequest_NestedParametersSQLi(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli_drop",
			Name:          "SQL Injection - DROP TABLE",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)drop\s+table`),
			PatternStr:    `(?i)drop\s+table`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
		},
	}

	engine := createTestEngine(policies)

	result := engine.EvaluateRequest(context.Background(), "Process this order", EvalOptions{
		TenantID: "test-tenant",
		Parameters: map[string]interface{}{
			"order": map[string]interface{}{
				"id":   "12345",
				"note": "; DROP TABLE orders --",
			},
		},
	})

	if !result.Blocked {
		t.Fatal("Expected request to be blocked due to SQLi in nested parameter")
	}
	if result.BlockedBy == nil || result.BlockedBy.PolicyID != "sqli_drop" {
		t.Error("Expected BlockedBy to reference sqli_drop policy")
	}
	if len(result.MatchedPolicies) != 1 {
		t.Fatalf("Expected 1 matched policy, got %d", len(result.MatchedPolicies))
	}
	if result.MatchedPolicies[0].FieldPath != "parameter 'order'" {
		t.Errorf("Expected FieldPath 'parameter \\'order\\'', got %q", result.MatchedPolicies[0].FieldPath)
	}
}

// TestEvaluateRequest_DedupSamePolicyAcrossQueryAndParameter is a regression
// test for the duplicate-match bug that produced
// "matched_policies": ["sys_sqli_grant", "sys_sqli_grant"] in API responses
// when a single policy's pattern hit both the query string and a parameter
// value. The engine should record each PolicyID at most once in
// MatchedPolicies — the parameter scan should be allowed to drive the block
// decision but must not append a second entry for an already-matched policy.
func TestEvaluateRequest_DedupSamePolicyAcrossQueryAndParameter(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli_grant",
			Name:          "GRANT Privileges",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)\bGRANT\s+`),
			PatternStr:    `(?i)\bGRANT\s+`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionLog, // log-only so the loop continues into params
			Enabled:       true,
			Priority:      100,
		},
	}

	engine := createTestEngine(policies)

	// Both the query string and the parameter contain "GRANT ..." so the
	// pattern matches in both contexts. Pre-fix: MatchedPolicies length 2.
	// Post-fix: length 1.
	result := engine.EvaluateRequest(context.Background(), "GRANT SELECT ON foo TO bar", EvalOptions{
		TenantID: "test-tenant",
		Parameters: map[string]interface{}{
			"echo": "GRANT INSERT ON baz TO qux",
		},
	})

	if len(result.MatchedPolicies) != 1 {
		t.Fatalf("expected exactly 1 entry in MatchedPolicies (dedup); got %d: %+v",
			len(result.MatchedPolicies), result.MatchedPolicies)
	}
	if result.MatchedPolicies[0].PolicyID != "sqli_grant" {
		t.Errorf("expected PolicyID=sqli_grant, got %q", result.MatchedPolicies[0].PolicyID)
	}
}

// TestEvaluateRequest_DedupAcrossMultipleParameters verifies that the same
// policy matching in TWO different parameters also dedups to one entry,
// not two. A pre-existing single-list semantic is what callers expect.
func TestEvaluateRequest_DedupAcrossMultipleParameters(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sqli_drop",
			Name:          "DROP TABLE",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`),
			PatternStr:    `(?i)\bDROP\s+TABLE\b`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionLog,
			Enabled:       true,
		},
	}

	engine := createTestEngine(policies)

	result := engine.EvaluateRequest(context.Background(), "benign query", EvalOptions{
		TenantID: "test-tenant",
		Parameters: map[string]interface{}{
			"a": "DROP TABLE users",
			"b": "DROP TABLE accounts",
		},
	})

	if len(result.MatchedPolicies) != 1 {
		t.Errorf("expected dedup to 1 entry across multiple params; got %d", len(result.MatchedPolicies))
	}
}
