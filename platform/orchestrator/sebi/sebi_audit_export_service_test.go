// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build enterprise

package sebi

import (
	"encoding/json"
	"testing"
	"time"
)

// =============================================================================
// Service Constructor Tests
// =============================================================================

func TestNewSEBIAuditExportService(t *testing.T) {
	// Test with nil DB and nil storage (valid case - DB might be set later)
	service := NewSEBIAuditExportService(nil, nil)
	if service == nil {
		t.Error("NewSEBIAuditExportService should return non-nil service even with nil DB")
	}
	if service.db != nil {
		t.Error("Service DB should be nil when created with nil")
	}
	if service.storageBackend != nil {
		t.Error("Service storageBackend should be nil when created with nil")
	}
}

// =============================================================================
// Random String Generation Tests
// =============================================================================

func TestRandomString_Length(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"length 1", 1},
		{"length 5", 5},
		{"length 8", 8},
		{"length 16", 16},
		{"length 32", 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := randomString(tt.length)
			if len(result) != tt.length {
				t.Errorf("randomString(%d) returned string of length %d", tt.length, len(result))
			}
		})
	}
}

func TestRandomString_ValidCharacters(t *testing.T) {
	const validChars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := randomString(100) // Generate longer string to increase coverage
	for i, c := range result {
		if !containsRune(validChars, c) {
			t.Errorf("randomString produced invalid character at position %d: %c", i, c)
		}
	}
}

// containsRune checks if a rune exists in a string
func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func TestRandomString_ProducesVariedOutput(t *testing.T) {
	// Test that multiple calls produce different results
	// Using longer strings to make collision virtually impossible
	first := randomString(32)
	second := randomString(32)
	if first == second {
		t.Errorf("randomString produced identical results: %s", first)
	}
}

// =============================================================================
// Contains Helper Tests
// =============================================================================

func TestContains(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   bool
	}{
		{"hello world", "world", true},
		{"hello world", "hello", true},
		{"hello world", "xyz", false},
		{"", "", true},
		{"hello", "", true},
		{"", "hello", false},
		{"abc", "abc", true},
		{"abc", "abcd", false},
	}

	for _, tt := range tests {
		result := contains(tt.s, tt.substr)
		if result != tt.want {
			t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, result, tt.want)
		}
	}
}

func TestContainsAt(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		start  int
		want   bool
	}{
		{"hello world", "world", 0, true},
		{"hello world", "world", 6, true},
		{"hello world", "hello", 0, true},
		{"hello world", "hello", 6, false},
		{"hello world", "xyz", 0, false},
		{"abc", "abc", 0, true},
		{"abc", "c", 2, true},
	}

	for _, tt := range tests {
		result := containsAt(tt.s, tt.substr, tt.start)
		if result != tt.want {
			t.Errorf("containsAt(%q, %q, %d) = %v, want %v", tt.s, tt.substr, tt.start, result, tt.want)
		}
	}
}

// =============================================================================
// Unit Tests for Service Helper Functions
// =============================================================================

func TestCalculateViolationsSummary(t *testing.T) {
	service := &SEBIAuditExportServiceImpl{}

	tests := []struct {
		name       string
		violations []SEBIPolicyViolationRecord
		wantTotal  int
		wantBySeverity map[string]int
		wantByType     map[string]int
	}{
		{
			name:       "empty violations",
			violations: []SEBIPolicyViolationRecord{},
			wantTotal:  0,
			wantBySeverity: map[string]int{},
			wantByType:     map[string]int{},
		},
		{
			name: "single violation",
			violations: []SEBIPolicyViolationRecord{
				{ID: "1", ViolationType: "pii_detected", Severity: "critical"},
			},
			wantTotal: 1,
			wantBySeverity: map[string]int{"critical": 1},
			wantByType:     map[string]int{"pii_detected": 1},
		},
		{
			name: "multiple violations - same severity",
			violations: []SEBIPolicyViolationRecord{
				{ID: "1", ViolationType: "pii_detected", Severity: "critical"},
				{ID: "2", ViolationType: "unauthorized_access", Severity: "critical"},
				{ID: "3", ViolationType: "pii_detected", Severity: "critical"},
			},
			wantTotal: 3,
			wantBySeverity: map[string]int{"critical": 3},
			wantByType:     map[string]int{"pii_detected": 2, "unauthorized_access": 1},
		},
		{
			name: "multiple violations - mixed severity",
			violations: []SEBIPolicyViolationRecord{
				{ID: "1", ViolationType: "pii_detected", Severity: "critical"},
				{ID: "2", ViolationType: "data_leak", Severity: "high"},
				{ID: "3", ViolationType: "rate_limit", Severity: "medium"},
				{ID: "4", ViolationType: "pii_detected", Severity: "critical"},
				{ID: "5", ViolationType: "suspicious_query", Severity: "low"},
			},
			wantTotal: 5,
			wantBySeverity: map[string]int{"critical": 2, "high": 1, "medium": 1, "low": 1},
			wantByType:     map[string]int{"pii_detected": 2, "data_leak": 1, "rate_limit": 1, "suspicious_query": 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := service.calculateViolationsSummary(tt.violations)

			if summary.Total != tt.wantTotal {
				t.Errorf("Total: expected %d, got %d", tt.wantTotal, summary.Total)
			}

			for severity, count := range tt.wantBySeverity {
				if summary.BySeverity[severity] != count {
					t.Errorf("BySeverity[%s]: expected %d, got %d", severity, count, summary.BySeverity[severity])
				}
			}

			for vType, count := range tt.wantByType {
				if summary.ByType[vType] != count {
					t.Errorf("ByType[%s]: expected %d, got %d", vType, count, summary.ByType[vType])
				}
			}
		})
	}
}

func TestCalculateViolationsSummary_TopViolations(t *testing.T) {
	service := &SEBIAuditExportServiceImpl{}

	// Create violations with different counts
	violations := []SEBIPolicyViolationRecord{}

	// 10 pii_detected
	for i := 0; i < 10; i++ {
		violations = append(violations, SEBIPolicyViolationRecord{
			ID: string(rune(i)), ViolationType: "pii_detected", Severity: "critical",
		})
	}
	// 8 unauthorized_access
	for i := 0; i < 8; i++ {
		violations = append(violations, SEBIPolicyViolationRecord{
			ID: string(rune(i + 10)), ViolationType: "unauthorized_access", Severity: "high",
		})
	}
	// 6 data_leak
	for i := 0; i < 6; i++ {
		violations = append(violations, SEBIPolicyViolationRecord{
			ID: string(rune(i + 20)), ViolationType: "data_leak", Severity: "high",
		})
	}
	// 4 rate_limit
	for i := 0; i < 4; i++ {
		violations = append(violations, SEBIPolicyViolationRecord{
			ID: string(rune(i + 30)), ViolationType: "rate_limit", Severity: "medium",
		})
	}
	// 2 suspicious_query
	for i := 0; i < 2; i++ {
		violations = append(violations, SEBIPolicyViolationRecord{
			ID: string(rune(i + 40)), ViolationType: "suspicious_query", Severity: "low",
		})
	}

	summary := service.calculateViolationsSummary(violations)

	// Should have 5 top violations (limit)
	if len(summary.TopViolations) != 5 {
		t.Errorf("expected 5 top violations, got %d", len(summary.TopViolations))
	}

	// First should be pii_detected with 10 occurrences
	if summary.TopViolations[0].Type != "pii_detected" {
		t.Errorf("expected first top violation to be pii_detected, got %s", summary.TopViolations[0].Type)
	}
	if summary.TopViolations[0].Count != 10 {
		t.Errorf("expected first top violation count to be 10, got %d", summary.TopViolations[0].Count)
	}
}

func TestCalculateComplianceScore(t *testing.T) {
	service := &SEBIAuditExportServiceImpl{}

	tests := []struct {
		name          string
		violations    *ViolationsSummary
		expectedScore float64
	}{
		{
			name:          "no violations",
			violations:    nil,
			expectedScore: 100,
		},
		{
			name: "no critical or high violations",
			violations: &ViolationsSummary{
				BySeverity: map[string]int{"medium": 5, "low": 10},
			},
			expectedScore: 100,
		},
		{
			name: "one critical violation",
			violations: &ViolationsSummary{
				BySeverity: map[string]int{"critical": 1},
			},
			expectedScore: 95, // 100 - 5
		},
		{
			name: "multiple critical violations",
			violations: &ViolationsSummary{
				BySeverity: map[string]int{"critical": 5},
			},
			expectedScore: 75, // 100 - 25
		},
		{
			name: "high violations",
			violations: &ViolationsSummary{
				BySeverity: map[string]int{"high": 5},
			},
			expectedScore: 90, // 100 - 10
		},
		{
			name: "mixed critical and high",
			violations: &ViolationsSummary{
				BySeverity: map[string]int{"critical": 2, "high": 5},
			},
			expectedScore: 80, // 100 - 10 - 10
		},
		{
			name: "score floors at 0",
			violations: &ViolationsSummary{
				BySeverity: map[string]int{"critical": 100},
			},
			expectedScore: 0, // Would be -400, floors at 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &SEBIAuditExportData{}
			summary := &SEBIAuditExportSummary{
				ViolationsSummary: tt.violations,
			}

			score := service.calculateComplianceScore(data, summary)

			if score != tt.expectedScore {
				t.Errorf("expected score %f, got %f", tt.expectedScore, score)
			}
		})
	}
}

func TestGenerateRecommendations(t *testing.T) {
	service := &SEBIAuditExportServiceImpl{}

	tests := []struct {
		name                   string
		checks                 []SEBIComplianceCheck
		expectedRecommendations int
	}{
		{
			name: "all checks pass",
			checks: []SEBIComplianceCheck{
				{Name: "Retention Configuration", Status: "pass"},
				{Name: "PII Detection Policies", Status: "pass"},
			},
			expectedRecommendations: 0,
		},
		{
			name: "retention check fails",
			checks: []SEBIComplianceCheck{
				{Name: "Retention Configuration", Status: "fail"},
				{Name: "PII Detection Policies", Status: "pass"},
			},
			expectedRecommendations: 1,
		},
		{
			name: "multiple checks fail",
			checks: []SEBIComplianceCheck{
				{Name: "Retention Configuration", Status: "fail"},
				{Name: "PII Detection Policies", Status: "fail"},
				{Name: "Human Oversight", Status: "warning"},
			},
			expectedRecommendations: 3,
		},
		{
			name: "all checks fail",
			checks: []SEBIComplianceCheck{
				{Name: "Retention Configuration", Status: "fail"},
				{Name: "PII Detection Policies", Status: "fail"},
				{Name: "Human Oversight", Status: "warning"},
				{Name: "Audit Logging", Status: "fail"},
				{Name: "Decision Chain Tracing", Status: "warning"},
			},
			expectedRecommendations: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recommendations := service.generateRecommendations(tt.checks)

			if len(recommendations) != tt.expectedRecommendations {
				t.Errorf("expected %d recommendations, got %d: %v",
					tt.expectedRecommendations, len(recommendations), recommendations)
			}
		})
	}
}

func TestGenerateExportID(t *testing.T) {
	// Test that export IDs are unique and have the expected format
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateExportID()

		// Check format: exp_<timestamp>_<random>
		if len(id) < 15 {
			t.Errorf("export ID too short: %s", id)
		}
		if id[:4] != "exp_" {
			t.Errorf("export ID should start with 'exp_': %s", id)
		}

		// Check uniqueness
		if ids[id] {
			t.Errorf("duplicate export ID generated: %s", id)
		}
		ids[id] = true
	}
}

func TestIsTableNotExistsError(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		expected bool
	}{
		{"nil error", "", false},
		{"table does not exist", "relation \"my_table\" does not exist", true},
		{"no such table SQLite", "no such table: my_table", true},
		{"permission denied", "permission denied for table my_table", false},
		{"connection error", "connection refused", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.errStr != "" {
				err = &testError{msg: tt.errStr}
			}

			result := isTableNotExistsError(err)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// =============================================================================
// Data Type JSON Serialization Tests
// =============================================================================

func TestSEBIPolicyViolationRecord_JSONRoundTrip(t *testing.T) {
	original := SEBIPolicyViolationRecord{
		ID:            "pv_123",
		Timestamp:     time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC),
		ViolationType: "pii_detected",
		Severity:      "critical",
		Description:   "PAN number detected in user query",
		PolicyID:      "pol_456",
		PolicyName:    "Indian PII Detection",
		AgentID:       "agent_789",
		UserID:        42,
		RequestID:     "req_abc",
		Action:        "redacted",
		Details: map[string]interface{}{
			"pii_type": "pan",
			"location": "input",
		},
		Remediation: "PAN number automatically redacted before LLM processing",
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal back
	var decoded SEBIPolicyViolationRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify key fields survive round-trip
	if decoded.ID != original.ID {
		t.Errorf("ID mismatch: got %s, want %s", decoded.ID, original.ID)
	}
	if decoded.ViolationType != original.ViolationType {
		t.Errorf("ViolationType mismatch: got %s, want %s", decoded.ViolationType, original.ViolationType)
	}
	if decoded.Severity != original.Severity {
		t.Errorf("Severity mismatch: got %s, want %s", decoded.Severity, original.Severity)
	}
}

func TestSEBILLMCallRecord_JSONRoundTrip(t *testing.T) {
	original := SEBILLMCallRecord{
		ID:              "llm_123",
		Timestamp:       time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC),
		RequestID:       "req_abc",
		Provider:        "openai",
		Model:           "gpt-4",
		InputTokens:     150,
		OutputTokens:    200,
		LatencyMs:       450,
		Cost:            0.0045,
		PolicyDecision:  "redacted",
		RedactedFields:  []string{"pan", "aadhaar"},
		ComplianceFlags: []string{"sebi_aiml", "dpdp"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded SEBILLMCallRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.Provider != original.Provider {
		t.Errorf("Provider mismatch: got %s, want %s", decoded.Provider, original.Provider)
	}
	if decoded.InputTokens != original.InputTokens {
		t.Errorf("InputTokens mismatch: got %d, want %d", decoded.InputTokens, original.InputTokens)
	}
	if len(decoded.RedactedFields) != len(original.RedactedFields) {
		t.Errorf("RedactedFields count mismatch: got %d, want %d", len(decoded.RedactedFields), len(original.RedactedFields))
	}
}

func TestSEBIDecisionChainRecord_JSONRoundTrip(t *testing.T) {
	ptMs := 150
	original := SEBIDecisionChainRecord{
		ID:                "dc_123",
		RequestID:         "req_abc",
		Timestamp:         time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC),
		DecisionType:      "policy_enforcement",
		DecisionOutcome:   "blocked",
		RiskLevel:         "high",
		ModelID:           "model_v2",
		RequiresReview:    true,
		PoliciesEvaluated: "{policy-1,policy-2}",
		PolicyTriggered:   "policy-1",
		ProcessingTimeMs:  &ptMs,
		InputFactors: []DecisionFactor{
			{Name: "query_risk", Value: "high", Weight: 0.4},
			{Name: "user_role", Value: "external", Weight: 0.3},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded SEBIDecisionChainRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.RiskLevel != original.RiskLevel {
		t.Errorf("RiskLevel mismatch: got %s, want %s", decoded.RiskLevel, original.RiskLevel)
	}
	if len(decoded.InputFactors) != len(original.InputFactors) {
		t.Errorf("InputFactors count mismatch: got %d, want %d", len(decoded.InputFactors), len(original.InputFactors))
	}
	if decoded.RequiresReview != original.RequiresReview {
		t.Errorf("RequiresReview mismatch: got %v, want %v", decoded.RequiresReview, original.RequiresReview)
	}
}

func TestSEBIHITLRecord_JSONRoundTrip(t *testing.T) {
	original := SEBIHITLRecord{
		ID:                   "hitl_123",
		RequestID:            "req_abc",
		Timestamp:            time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC),
		TriggerReason:        "high_risk_decision",
		ReviewerID:           42,
		ReviewerEmail:        "reviewer@company.com",
		Decision:             "approved",
		Notes:                "Reviewed and approved for processing",
		ReviewTimeMs:         5000,
		OriginalResponseHash: "orig_hash",
		ModifiedResponseHash: "mod_hash",
		ComplianceFlags:      []string{"sebi_aiml"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded SEBIHITLRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.Decision != original.Decision {
		t.Errorf("Decision mismatch: got %s, want %s", decoded.Decision, original.Decision)
	}
	if decoded.ReviewTimeMs != original.ReviewTimeMs {
		t.Errorf("ReviewTimeMs mismatch: got %d, want %d", decoded.ReviewTimeMs, original.ReviewTimeMs)
	}
}

func TestSEBIPIIRedactionRecord_JSONRoundTrip(t *testing.T) {
	original := SEBIPIIRedactionRecord{
		ID:                  "pii_123",
		RequestID:           "req_abc",
		Timestamp:           time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC),
		PIIType:             "pan",
		RedactionMethod:     "mask",
		Location:            "input.query",
		DetectionConfidence: 0.99,
		UserID:              42,
		ComplianceFramework: "SEBI_AI_ML",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded SEBIPIIRedactionRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.PIIType != original.PIIType {
		t.Errorf("PIIType mismatch: got %s, want %s", decoded.PIIType, original.PIIType)
	}
	if decoded.DetectionConfidence != original.DetectionConfidence {
		t.Errorf("DetectionConfidence mismatch: got %f, want %f", decoded.DetectionConfidence, original.DetectionConfidence)
	}
}

// =============================================================================
// Export Summary Tests
// =============================================================================

func TestSEBIAuditExportSummary_RecordsByType(t *testing.T) {
	summary := &SEBIAuditExportSummary{
		TotalRecords:  500,
		RecordsByType: make(map[SEBIAuditDataType]int),
	}

	summary.RecordsByType[SEBIDataTypePolicyViolations] = 100
	summary.RecordsByType[SEBIDataTypeLLMCalls] = 200
	summary.RecordsByType[SEBIDataTypeDecisionChain] = 100
	summary.RecordsByType[SEBIDataTypeHITLOversight] = 50
	summary.RecordsByType[SEBIDataTypePIIRedactions] = 50

	// Verify counts sum to total
	total := 0
	for _, count := range summary.RecordsByType {
		total += count
	}

	if total != summary.TotalRecords {
		t.Errorf("Sum of RecordsByType (%d) should equal TotalRecords (%d)", total, summary.TotalRecords)
	}
}
