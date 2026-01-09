package policy

import (
	"context"
	"regexp"
	"testing"
)

func TestMetricsCollector_RecordEvaluation(t *testing.T) {
	queue := &NoOpAuditQueue{}
	collector := NewMetricsCollector(queue)

	ctx := context.Background()
	opts := EvalOptions{TenantID: "tenant1"}
	matches := []PolicyMatch{{PolicyID: "test1"}}

	// Record a request evaluation
	collector.RecordEvaluation(ctx, "request", opts, matches, true, 5)

	stats := collector.GetStats()
	if stats == nil {
		t.Fatal("GetStats returned nil")
	}

	// Check specific stats
	if stats["request_evaluations"].(int64) != 1 {
		t.Errorf("Expected 1 request evaluation, got %v", stats["request_evaluations"])
	}
	if stats["blocked_requests"].(int64) != 1 {
		t.Errorf("Expected 1 blocked request, got %v", stats["blocked_requests"])
	}
}

func TestMetricsCollector_RecordEvaluation_Response(t *testing.T) {
	queue := &NoOpAuditQueue{}
	collector := NewMetricsCollector(queue)

	ctx := context.Background()
	opts := EvalOptions{TenantID: "tenant1"}

	// Record a response evaluation (blocked)
	collector.RecordEvaluation(ctx, "response", opts, nil, true, 10)

	stats := collector.GetStats()
	if stats["response_evaluations"].(int64) != 1 {
		t.Errorf("Expected 1 response evaluation, got %v", stats["response_evaluations"])
	}
	if stats["blocked_responses"].(int64) != 1 {
		t.Errorf("Expected 1 blocked response, got %v", stats["blocked_responses"])
	}
}

func TestMetricsCollector_RecordRedaction(t *testing.T) {
	queue := &NoOpAuditQueue{}
	collector := NewMetricsCollector(queue)

	collector.RecordRedaction(3)
	collector.RecordRedaction(2)

	stats := collector.GetStats()
	if stats["redactions_applied"].(int64) != 5 {
		t.Errorf("Expected 5 redactions, got %v", stats["redactions_applied"])
	}
}

func TestMetricsCollector_RecordViolation(t *testing.T) {
	queue := &NoOpAuditQueue{}
	collector := NewMetricsCollector(queue)

	ctx := context.Background()
	opts := EvalOptions{TenantID: "tenant1"}
	policy := &CompiledPolicy{
		PolicyID: "test_policy",
		Name:     "Test Policy",
		Category: CategorySecuritySQLi,
		Severity: SeverityCritical,
	}

	// Should not panic with NoOpAuditQueue
	collector.RecordViolation(ctx, opts, policy, "DROP TABLE users")
}

func TestMetricsCollector_RecordError(t *testing.T) {
	queue := &NoOpAuditQueue{}
	collector := NewMetricsCollector(queue)

	collector.RecordError("load")
	collector.RecordError("evaluation")
	collector.RecordError("load")

	stats := collector.GetStats()
	if stats["load_errors"].(int64) != 2 {
		t.Errorf("Expected 2 load errors, got %v", stats["load_errors"])
	}
	if stats["evaluation_errors"].(int64) != 1 {
		t.Errorf("Expected 1 evaluation error, got %v", stats["evaluation_errors"])
	}
}

func TestMetricsCollector_Reset(t *testing.T) {
	queue := &NoOpAuditQueue{}
	collector := NewMetricsCollector(queue)

	ctx := context.Background()
	opts := EvalOptions{TenantID: "tenant1"}

	// Add some metrics
	collector.RecordEvaluation(ctx, "request", opts, nil, true, 5)
	collector.RecordRedaction(3)
	collector.RecordError("load")

	// Verify metrics before reset
	statsBefore := collector.GetStats()
	if statsBefore["request_evaluations"].(int64) != 1 {
		t.Error("Expected metrics before reset")
	}

	// Reset
	collector.Reset()

	// Verify metrics after reset
	statsAfter := collector.GetStats()
	if statsAfter["request_evaluations"].(int64) != 0 {
		t.Errorf("Expected 0 after reset, got %v", statsAfter["request_evaluations"])
	}
	if statsAfter["redactions_applied"].(int64) != 0 {
		t.Errorf("Expected 0 redactions after reset, got %v", statsAfter["redactions_applied"])
	}
}

func TestMetricsCollector_GetStats(t *testing.T) {
	queue := &NoOpAuditQueue{}
	collector := NewMetricsCollector(queue)

	ctx := context.Background()
	opts := EvalOptions{TenantID: "tenant1"}

	// Generate various metrics
	collector.RecordEvaluation(ctx, "request", opts, nil, false, 2)
	collector.RecordEvaluation(ctx, "response", opts, nil, false, 3)
	collector.RecordRedaction(1)
	collector.RecordError("load")

	stats := collector.GetStats()
	if stats == nil {
		t.Fatal("GetStats returned nil")
	}

	// Verify all expected fields exist
	expectedFields := []string{
		"request_evaluations",
		"response_evaluations",
		"blocked_requests",
		"blocked_responses",
		"redactions_applied",
		"policies_matched",
		"avg_request_time_ms",
		"avg_response_time_ms",
		"load_errors",
		"evaluation_errors",
	}

	for _, field := range expectedFields {
		if _, ok := stats[field]; !ok {
			t.Errorf("Missing expected field: %s", field)
		}
	}
}

func TestNoOpAuditQueue_Methods(t *testing.T) {
	queue := &NoOpAuditQueue{}

	// These should not panic and return nil errors
	err := queue.LogViolation(AuditEntry{})
	if err != nil {
		t.Errorf("LogViolation returned error: %v", err)
	}

	err = queue.LogMetric(AuditEntry{})
	if err != nil {
		t.Errorf("LogMetric returned error: %v", err)
	}

	err = queue.LogPolicyEvaluation(PolicyEvaluationEntry{})
	if err != nil {
		t.Errorf("LogPolicyEvaluation returned error: %v", err)
	}
}

func TestMetricsCollector_NilAuditQueue(t *testing.T) {
	// Should handle nil audit queue gracefully
	collector := NewMetricsCollector(nil)

	ctx := context.Background()
	opts := EvalOptions{TenantID: "tenant1"}
	policy := &CompiledPolicy{
		PolicyID: "test",
		Category: CategorySecuritySQLi,
		Severity: SeverityCritical,
	}

	// Should not panic with nil queue
	collector.RecordEvaluation(ctx, "request", opts, nil, false, 0)
	collector.RecordViolation(ctx, opts, policy, "test")

	stats := collector.GetStats()
	if stats == nil {
		t.Fatal("GetStats returned nil")
	}
}

func TestMetricsCollector_AverageLatency(t *testing.T) {
	queue := &NoOpAuditQueue{}
	collector := NewMetricsCollector(queue)

	ctx := context.Background()
	opts := EvalOptions{TenantID: "tenant1"}

	// Record multiple evaluations with different latencies (in milliseconds)
	collector.RecordEvaluation(ctx, "request", opts, nil, false, 10) // 10ms
	collector.RecordEvaluation(ctx, "request", opts, nil, false, 20) // 20ms

	stats := collector.GetStats()
	avgTime := stats["avg_request_time_ms"].(float64)

	// Average should be 15ms
	if avgTime < 14.0 || avgTime > 16.0 {
		t.Errorf("Expected avg ~15ms, got %f", avgTime)
	}
}

func TestPolicyCategory_Values(t *testing.T) {
	tests := []struct {
		category PolicyCategory
		expected string
	}{
		{CategorySecuritySQLi, "security-sqli"},
		{CategorySecurityDangerous, "security-dangerous"},
		{CategoryPIIUS, "pii-us"},
		{CategoryPIIIndia, "pii-india"},
		{CategoryPIIGlobal, "pii-global"},
		{CategoryPIIEU, "pii-eu"},
	}

	for _, tt := range tests {
		if string(tt.category) != tt.expected {
			t.Errorf("Category %s != %s", tt.category, tt.expected)
		}
	}
}

func TestSeverity_Values(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
	}

	for _, tt := range tests {
		if string(tt.severity) != tt.expected {
			t.Errorf("Severity %s != %s", tt.severity, tt.expected)
		}
	}
}

func TestAction_Values(t *testing.T) {
	tests := []struct {
		action   Action
		expected string
	}{
		{ActionBlock, "block"},
		{ActionRedact, "redact"},
		{ActionAllow, "allow"},
		{ActionLog, "log"},
		{ActionWarn, "warn"},
	}

	for _, tt := range tests {
		if string(tt.action) != tt.expected {
			t.Errorf("Action %s != %s", tt.action, tt.expected)
		}
	}
}

func TestPhase_Values(t *testing.T) {
	tests := []struct {
		phase    Phase
		expected string
	}{
		{PhaseRequest, "request"},
		{PhaseResponse, "response"},
		{PhaseBoth, "both"},
	}

	for _, tt := range tests {
		if string(tt.phase) != tt.expected {
			t.Errorf("Phase %s != %s", tt.phase, tt.expected)
		}
	}
}

func TestRedactionStrategy_Values(t *testing.T) {
	tests := []struct {
		strategy RedactionStrategy
		expected string
	}{
		{StrategyMask, "mask"},
		{StrategyPartial, "partial"},
		{StrategyRemove, "remove"},
		{StrategyHash, "hash"},
		{StrategyTokenize, "tokenize"},
	}

	for _, tt := range tests {
		if string(tt.strategy) != tt.expected {
			t.Errorf("Strategy %s != %s", tt.strategy, tt.expected)
		}
	}
}

func TestAuditEntry_Fields(t *testing.T) {
	entry := AuditEntry{
		Type:     "violation",
		Severity: "critical",
		TenantID: "tenant1",
		UserID:   "user1",
		Details: map[string]interface{}{
			"policy_id": "test_policy",
		},
	}

	if entry.Type != "violation" {
		t.Error("Type mismatch")
	}
	if entry.TenantID != "tenant1" {
		t.Error("TenantID mismatch")
	}
}

func TestPolicyEvaluationEntry_Fields(t *testing.T) {
	entry := PolicyEvaluationEntry{
		Type:              "request_evaluation",
		TenantID:          "tenant1",
		PoliciesEvaluated: 10,
		MatchedPolicies:   []string{"p1", "p2"},
		Blocked:           true,
		ProcessingTimeMs:  5,
	}

	if entry.TenantID != "tenant1" {
		t.Error("TenantID mismatch")
	}
	if entry.PoliciesEvaluated != 10 {
		t.Error("PoliciesEvaluated mismatch")
	}
}

func TestPolicyInfo_Fields(t *testing.T) {
	info := PolicyInfo{
		PoliciesEvaluated: 10,
		Blocked:           true,
		BlockReason:       "SQLi detected",
		RedactionsApplied: 5,
		ProcessingTimeMs:  3,
	}

	if info.PoliciesEvaluated != 10 {
		t.Error("PoliciesEvaluated mismatch")
	}
	if !info.Blocked {
		t.Error("Blocked mismatch")
	}
}

func TestBuildPolicyInfo_BothResults(t *testing.T) {
	request := &RequestResult{
		Blocked:           false,
		PoliciesEvaluated: 5,
		MatchedPolicies:   []PolicyMatch{{PolicyID: "p1"}},
		ProcessingTimeMs:  2,
	}

	response := &ResponseResult{
		Blocked:          false,
		PoliciesEvaluated: 10,
		Redacted:          true,
		RedactedFields:    []RedactedField{{Path: "field1"}, {Path: "field2"}},
		ProcessingTimeMs:  3,
	}

	info := BuildPolicyInfo(request, response)

	if info.PoliciesEvaluated != 15 {
		t.Errorf("PoliciesEvaluated = %d, want 15", info.PoliciesEvaluated)
	}
	if info.RedactionsApplied != 2 {
		t.Errorf("RedactionsApplied = %d, want 2", info.RedactionsApplied)
	}
	if info.ProcessingTimeMs != 5 {
		t.Errorf("ProcessingTimeMs = %d, want 5", info.ProcessingTimeMs)
	}
}

func TestBuildPolicyInfo_RequestOnly(t *testing.T) {
	request := &RequestResult{
		Blocked:           true,
		BlockedBy:         &CompiledPolicy{PolicyID: "sqli", Name: "SQLi Detection"},
		BlockReason:       "SQL injection detected",
		PoliciesEvaluated: 5,
		ProcessingTimeMs:  2,
	}

	info := BuildPolicyInfo(request, nil)

	if !info.Blocked {
		t.Error("Expected Blocked=true")
	}
	if info.BlockReason == "" {
		t.Error("Expected BlockReason to be set")
	}
}

// Note: TestGetRedactedFieldPaths is in engine_test.go

func TestMergePolicyInfo_BothNil(t *testing.T) {
	result := MergePolicyInfo(nil, nil)
	if result != nil {
		t.Error("Expected nil for both nil inputs")
	}
}

func TestMergePolicyInfo_OneNil(t *testing.T) {
	request := &PolicyInfo{PoliciesEvaluated: 5}
	result := MergePolicyInfo(request, nil)
	if result.PoliciesEvaluated != 5 {
		t.Error("Expected request info when response is nil")
	}

	response := &PolicyInfo{PoliciesEvaluated: 10}
	result = MergePolicyInfo(nil, response)
	if result.PoliciesEvaluated != 10 {
		t.Error("Expected response info when request is nil")
	}
}

func TestEvalOptions_Fields(t *testing.T) {
	orgID := "org123"
	opts := EvalOptions{
		TenantID:       "tenant1",
		OrganizationID: &orgID,
		ConnectorName:  "postgres",
		UserID:         "user1",
		Categories:     []PolicyCategory{CategorySecuritySQLi, CategoryPIIUS},
		SkipCategories: []PolicyCategory{CategoryPIIGlobal},
		MaxRedactions:  100,
	}

	if opts.TenantID != "tenant1" {
		t.Error("TenantID mismatch")
	}
	if *opts.OrganizationID != "org123" {
		t.Error("OrganizationID mismatch")
	}
	if len(opts.Categories) != 2 {
		t.Error("Categories mismatch")
	}
	if opts.MaxRedactions != 100 {
		t.Error("MaxRedactions mismatch")
	}
}

func TestEngineConfig_Defaults(t *testing.T) {
	config := DefaultEngineConfig()

	if config.CacheTTL == 0 {
		t.Error("Expected non-zero CacheTTL")
	}
	if config.MaxPatternCache == 0 {
		t.Error("Expected non-zero MaxPatternCache")
	}
	if !config.EnableValidators {
		t.Error("Expected validators enabled by default")
	}
	if !config.GracefulDegradation {
		t.Error("Expected graceful degradation enabled by default")
	}
}

func TestCompiledPolicy_FullFields(t *testing.T) {
	policy := CompiledPolicy{
		ID:             "uuid-123-456",
		PolicyID:       "pii_ssn",
		Name:           "SSN Detection",
		Category:       CategoryPIIUS,
		Tier:           "enterprise",
		Pattern:        regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
		PatternStr:     `\d{3}-\d{2}-\d{4}`,
		Severity:       SeverityCritical,
		Description:    "Detects US Social Security Numbers",
		Phase:          PhaseBoth,
		ActionRequest:  ActionBlock,
		ActionResponse: ActionRedact,
		Enabled:        true,
		Priority:       100,
		TenantID:       "tenant1",
	}

	if policy.PolicyID != "pii_ssn" {
		t.Error("PolicyID mismatch")
	}
	if policy.Priority != 100 {
		t.Error("Priority mismatch")
	}
	if policy.Pattern == nil {
		t.Error("Pattern should be set")
	}
}
