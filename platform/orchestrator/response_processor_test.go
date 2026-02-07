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

package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// Test NewResponseProcessor initialization
func TestResponseProcessor_Initialization(t *testing.T) {
	processor := NewResponseProcessor()

	if processor == nil {
		t.Fatal("NewResponseProcessor() returned nil")
	}

	if processor.piiDetector == nil {
		t.Error("piiDetector not initialized")
	}

	if processor.redactor == nil {
		t.Error("redactor not initialized")
	}

	if processor.enricher == nil {
		t.Error("enricher not initialized")
	}

	if len(processor.validationRules) == 0 {
		t.Error("validationRules not initialized")
	}
}

// Test ProcessResponse with plain text (no JSON)
func TestProcessResponse_PlainText_NoPII(t *testing.T) {
	processor := NewResponseProcessor()
	ctx := context.Background()
	user := UserContext{
		ID:          1,
		Email:       "test@example.com",
		Role:        "user",
		Permissions: []string{},
		TenantID:    "test-tenant",
	}

	response := &LLMResponse{
		Content: "This is a normal response with no sensitive data.",
		Model:   "test-model",
	}

	result, redactionInfo := processor.ProcessResponse(ctx, user, response)

	if result == nil {
		t.Fatal("ProcessResponse() returned nil result")
	}

	if redactionInfo.HasRedactions {
		t.Error("Expected no redactions for plain text")
	}

	if redactionInfo.RedactionCount != 0 {
		t.Errorf("Expected 0 redactions, got %d", redactionInfo.RedactionCount)
	}
}

// Test ProcessResponse with SSN detection
func TestProcessResponse_DetectsAndRedactsSSN(t *testing.T) {
	processor := NewResponseProcessor()
	ctx := context.Background()
	user := UserContext{
		ID:          1,
		Email:       "test@example.com",
		Role:        "user",
		Permissions: []string{}, // No permissions to view PII
		TenantID:    "test-tenant",
	}

	response := &LLMResponse{
		Content: "User SSN is 123-45-6789 and should be redacted.",
		Model:   "test-model",
	}

	result, redactionInfo := processor.ProcessResponse(ctx, user, response)

	if result == nil {
		t.Fatal("ProcessResponse() returned nil result")
	}

	if !redactionInfo.HasRedactions {
		t.Error("Expected redactions for SSN")
	}

	if redactionInfo.RedactionCount == 0 {
		t.Error("Expected at least 1 redaction")
	}

	// Result should not contain the original SSN
	resultStr := getString(result)
	if strings.Contains(resultStr, "123-45-6789") {
		t.Error("SSN should be redacted but was found in result")
	}
}

// Test ProcessResponse with admin user (should not redact)
func TestProcessResponse_AdminUser_NoRedaction(t *testing.T) {
	processor := NewResponseProcessor()
	ctx := context.Background()
	user := UserContext{
		ID:          1,
		Email:       "admin@example.com",
		Role:        "admin", // Admin role
		Permissions: []string{},
		TenantID:    "test-tenant",
	}

	response := &LLMResponse{
		Content: "User SSN is 123-45-6789.",
		Model:   "test-model",
	}

	result, redactionInfo := processor.ProcessResponse(ctx, user, response)

	if result == nil {
		t.Fatal("ProcessResponse() returned nil result")
	}

	// Admin should see everything - no redactions
	if redactionInfo.HasRedactions {
		t.Error("Admin user should not have redactions")
	}

	// Original SSN should still be present
	resultStr := getString(result)
	if !strings.Contains(resultStr, "123-45-6789") {
		t.Error("Admin should see original SSN")
	}
}

// Test ProcessResponse with user having view_full_pii permission
func TestProcessResponse_ViewFullPII_Permission(t *testing.T) {
	processor := NewResponseProcessor()
	ctx := context.Background()
	user := UserContext{
		ID:          1,
		Email:       "test@example.com",
		Role:        "user",
		Permissions: []string{"view_full_pii"}, // Can see all PII
		TenantID:    "test-tenant",
	}

	response := &LLMResponse{
		Content: "User SSN is 123-45-6789 and email is user@example.com.",
		Model:   "test-model",
	}

	result, _ := processor.ProcessResponse(ctx, user, response)

	if result == nil {
		t.Fatal("ProcessResponse() returned nil result")
	}

	// User with view_full_pii should see everything
	resultStr := getString(result)
	if !strings.Contains(resultStr, "123-45-6789") {
		t.Error("User with view_full_pii should see SSN")
	}

	if !strings.Contains(resultStr, "user@example.com") {
		t.Error("User with view_full_pii should see email")
	}
}

// Test detectPII with multiple PII types
func TestDetectPII_MultiplePIITypes(t *testing.T) {
	processor := NewResponseProcessor()

	testCases := []struct {
		name          string
		input         string
		expectedTypes []string
	}{
		{
			name:          "SSN detection",
			input:         "SSN: 123-45-6789",
			expectedTypes: []string{"ssn"},
		},
		{
			name:          "Email detection",
			input:         "Contact: user@example.com",
			expectedTypes: []string{"email"},
		},
		{
			name:          "Phone detection",
			input:         "Call me at (555) 123-4567",
			expectedTypes: []string{"phone"},
		},
		{
			name:          "Credit card detection",
			input:         "Card: 4532-0151-1283-0366", // Valid Visa card (passes Luhn)
			expectedTypes: []string{"credit_card"},
		},
		{
			name:          "Multiple PII types",
			input:         "SSN: 123-45-6789, Email: user@example.com, Phone: 555-123-4567",
			expectedTypes: []string{"ssn", "email", "phone"},
		},
		{
			name:          "No PII",
			input:         "This is normal text with no sensitive data",
			expectedTypes: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			detected := processor.detectPII(tc.input)

			if len(tc.expectedTypes) == 0 && len(detected) > 0 {
				t.Errorf("Expected no PII detection, but found: %v", detected)
				return
			}

			for _, expectedType := range tc.expectedTypes {
				if _, found := detected[expectedType]; !found {
					t.Errorf("Expected to detect %s but did not find it", expectedType)
				}
			}
		})
	}
}

// Test isAllowed with different permission scenarios
func TestIsAllowed(t *testing.T) {
	processor := NewResponseProcessor()

	tests := []struct {
		name       string
		piiType    string
		allowedPII []string
		want       bool
	}{
		{
			name:       "admin wildcard allows all",
			piiType:    "ssn",
			allowedPII: []string{"*"},
			want:       true,
		},
		{
			name:       "specific permission allows type",
			piiType:    "ssn",
			allowedPII: []string{"ssn", "email"},
			want:       true,
		},
		{
			name:       "no permission denies type",
			piiType:    "ssn",
			allowedPII: []string{"email"},
			want:       false,
		},
		{
			name:       "empty permissions denies all",
			piiType:    "ssn",
			allowedPII: []string{},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := processor.isAllowed(tt.piiType, tt.allowedPII)
			if got != tt.want {
				t.Errorf("isAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test getAllowedPIITypes with different user roles/permissions
func TestGetAllowedPIITypes(t *testing.T) {
	processor := NewResponseProcessor()

	tests := []struct {
		name string
		user UserContext
		want []string
	}{
		{
			name: "admin role gets wildcard",
			user: UserContext{Role: "admin", Permissions: []string{}},
			want: []string{"*"},
		},
		{
			name: "view_full_pii permission",
			user: UserContext{Role: "user", Permissions: []string{"view_full_pii"}},
			want: []string{"ssn", "credit_card", "bank_account", "email", "phone", "address"},
		},
		{
			name: "view_basic_pii permission",
			user: UserContext{Role: "user", Permissions: []string{"view_basic_pii"}},
			want: []string{"email", "phone"},
		},
		{
			name: "no permissions",
			user: UserContext{Role: "user", Permissions: []string{}},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := processor.getAllowedPIITypes(tt.user)

			// For wildcard, just check it exists
			if len(tt.want) == 1 && tt.want[0] == "*" {
				if len(got) != 1 || got[0] != "*" {
					t.Errorf("getAllowedPIITypes() = %v, want wildcard", got)
				}
				return
			}

			// Check all expected types are present
			for _, expected := range tt.want {
				found := false
				for _, actual := range got {
					if actual == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("getAllowedPIITypes() missing expected type: %s", expected)
				}
			}
		})
	}
}

// Test redactString
func TestRedactString(t *testing.T) {
	processor := NewResponseProcessor()

	tests := []struct {
		name        string
		input       string
		detectedPII map[string][]string
		allowedPII  []string
		wantContain string
		wantNotContain string
	}{
		{
			name:  "redact SSN when not allowed",
			input: "User SSN: 123-45-6789",
			detectedPII: map[string][]string{
				"ssn": {"123-45-6789"},
			},
			allowedPII:      []string{},
			wantNotContain:  "123-45-6789",
			wantContain:     "XXX-XX-",
		},
		{
			name:  "keep SSN when allowed",
			input: "User SSN: 123-45-6789",
			detectedPII: map[string][]string{
				"ssn": {"123-45-6789"},
			},
			allowedPII:      []string{"ssn"},
			wantContain:     "123-45-6789",
			wantNotContain:  "",
		},
		{
			name:  "no redaction when no PII detected",
			input: "Normal text",
			detectedPII: map[string][]string{},
			allowedPII:  []string{},
			wantContain: "Normal text",
			wantNotContain: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &RedactionInfo{}
			result := processor.redactString(tt.input, tt.detectedPII, tt.allowedPII, info)

			if tt.wantContain != "" && !strings.Contains(result, tt.wantContain) {
				t.Errorf("redactString() result should contain %q, got %q", tt.wantContain, result)
			}

			if tt.wantNotContain != "" && strings.Contains(result, tt.wantNotContain) {
				t.Errorf("redactString() result should not contain %q, got %q", tt.wantNotContain, result)
			}
		})
	}
}

// Test shouldRedactField
func TestShouldRedactField(t *testing.T) {
	processor := NewResponseProcessor()

	tests := []struct {
		name       string
		fieldName  string
		allowedPII []string
		want       bool
	}{
		{
			name:       "SSN field without permission",
			fieldName:  "user_ssn",
			allowedPII: []string{},
			want:       true,
		},
		{
			name:       "SSN field with permission",
			fieldName:  "user_ssn",
			allowedPII: []string{"ssn"},
			want:       false,
		},
		{
			name:       "credit_card field without permission",
			fieldName:  "payment_card_number",
			allowedPII: []string{},
			want:       true,
		},
		{
			name:       "normal field",
			fieldName:  "user_name",
			allowedPII: []string{},
			want:       false,
		},
		{
			name:       "admin with wildcard",
			fieldName:  "user_ssn",
			allowedPII: []string{"*"},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := processor.shouldRedactField(tt.fieldName, tt.allowedPII)
			if got != tt.want {
				t.Errorf("shouldRedactField(%q) = %v, want %v", tt.fieldName, got, tt.want)
			}
		})
	}
}

// Test IsHealthy
func TestResponseProcessor_IsHealthy(t *testing.T) {
	processor := NewResponseProcessor()

	if !processor.IsHealthy() {
		t.Error("ResponseProcessor should always report healthy")
	}
}

// Test NewPIIDetector
func TestNewPIIDetector(t *testing.T) {
	detector := NewPIIDetector()

	if detector == nil {
		t.Fatal("NewPIIDetector() returned nil")
	}

	expectedPatterns := []string{"ssn", "credit_card", "email", "phone", "ip_address", "bank_account"}

	for _, pattern := range expectedPatterns {
		if _, exists := detector.patterns[pattern]; !exists {
			t.Errorf("Expected pattern %q to be initialized", pattern)
		}
	}
}

// Test NewRedactor
func TestNewRedactor(t *testing.T) {
	redactor := NewRedactor()

	if redactor == nil {
		t.Fatal("NewRedactor() returned nil")
	}

	expectedStrategies := []string{"ssn", "credit_card", "email", "phone", "ip_address", "bank_account", "default"}

	for _, strategy := range expectedStrategies {
		if _, exists := redactor.redactionStrategies[strategy]; !exists {
			t.Errorf("Expected strategy %q to be initialized", strategy)
		}
	}
}

// Test MaskingStrategy
func TestMaskingStrategy_Redact(t *testing.T) {
	tests := []struct {
		name        string
		strategy    *MaskingStrategy
		input       string
		wantContain string
	}{
		{
			name:        "SSN masking keeps last 4",
			strategy:    &MaskingStrategy{keepLast: 4, placeholder: "XXX-XX-"},
			input:       "123-45-6789",
			wantContain: "6789",
		},
		{
			name:        "credit card masking keeps last 4",
			strategy:    &MaskingStrategy{keepLast: 4, placeholder: "****-****-****-"},
			input:       "4532-0151-1283-0366",
			wantContain: "0366",
		},
		{
			name:        "full masking (keepLast: 0)",
			strategy:    &MaskingStrategy{keepLast: 0, placeholder: "***"},
			input:       "sensitive-data",
			wantContain: "***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.strategy.Redact(tt.input)

			if !strings.Contains(result, tt.wantContain) {
				t.Errorf("MaskingStrategy.Redact() = %q, should contain %q", result, tt.wantContain)
			}

			// Original value should not be fully present (unless keepLast covers it all)
			if tt.strategy.keepLast == 0 && result == tt.input {
				t.Error("MaskingStrategy.Redact() should not return original value when keepLast=0")
			}
		})
	}
}

// Test HashingStrategy
func TestHashingStrategy_Redact(t *testing.T) {
	strategy := &HashingStrategy{}

	input := "user@example.com"
	result := strategy.Redact(input)

	// Should return a hashed representation
	if result == input {
		t.Error("HashingStrategy.Redact() should not return original value")
	}

	if !strings.Contains(result, "HASHED") {
		t.Errorf("HashingStrategy.Redact() = %q, should contain 'HASHED'", result)
	}
}

// Test redactMap with nested structures
func TestRedactMap(t *testing.T) {
	processor := NewResponseProcessor()

	input := map[string]interface{}{
		"user_name": "John Doe",
		"user_ssn":  "123-45-6789",
		"email":     "john@example.com",
	}

	detectedPII := map[string][]string{
		"ssn":   {"123-45-6789"},
		"email": {"john@example.com"},
	}

	allowedPII := []string{} // No permissions
	info := &RedactionInfo{}

	result := processor.redactMap(input, detectedPII, allowedPII, info)

	// user_ssn field should be redacted (field name suggests PII)
	if userSSN, ok := result["user_ssn"]; ok {
		if userSSN != "[REDACTED]" {
			t.Errorf("user_ssn field should be [REDACTED], got %v", userSSN)
		}
	} else {
		t.Error("user_ssn field missing from result")
	}

	// Should have recorded redactions
	if !info.HasRedactions {
		t.Error("Expected HasRedactions to be true")
	}

	if info.RedactionCount == 0 {
		t.Error("Expected RedactionCount > 0")
	}
}

// Test redactSlice
func TestRedactSlice(t *testing.T) {
	processor := NewResponseProcessor()

	input := []interface{}{
		"Normal text",
		"SSN: 123-45-6789",
		"Email: user@example.com",
	}

	detectedPII := map[string][]string{
		"ssn":   {"123-45-6789"},
		"email": {"user@example.com"},
	}

	allowedPII := []string{} // No permissions
	info := &RedactionInfo{}

	result := processor.redactSlice(input, detectedPII, allowedPII, info)

	if len(result) != len(input) {
		t.Errorf("Expected slice length %d, got %d", len(input), len(result))
	}

	// First element should remain unchanged
	if result[0] != "Normal text" {
		t.Errorf("Expected first element to be 'Normal text', got %v", result[0])
	}
}

// Helper function to extract string representation from result
func getString(result interface{}) string {
	if m, ok := result.(map[string]interface{}); ok {
		if data, ok := m["data"]; ok {
			return fmt.Sprint(data)
		}
		return fmt.Sprint(m)
	}
	return fmt.Sprint(result)
}

// TestMaskingStrategy_GetPlaceholder tests the GetPlaceholder method
func TestMaskingStrategy_GetPlaceholder(t *testing.T) {
	strategy := &MaskingStrategy{
		placeholder: "***",
		keepLast:    4,
	}

	result := strategy.GetPlaceholder()
	if result != "***" {
		t.Errorf("Expected placeholder '***', got '%s'", result)
	}
}

// TestHashingStrategy_GetPlaceholder tests the GetPlaceholder method
func TestHashingStrategy_GetPlaceholder(t *testing.T) {
	strategy := &HashingStrategy{}

	result := strategy.GetPlaceholder()
	if result != "[HASHED]" {
		t.Errorf("Expected placeholder '[HASHED]', got '%s'", result)
	}
}

// TestDefaultStrategy_Redact tests the Redact method
func TestDefaultStrategy_Redact(t *testing.T) {
	strategy := &DefaultStrategy{}

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "simple value",
			value: "secret123",
			want:  "[REDACTED]",
		},
		{
			name:  "empty value",
			value: "",
			want:  "[REDACTED]",
		},
		{
			name:  "long value",
			value: "this is a very long secret value with lots of text",
			want:  "[REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strategy.Redact(tt.value)
			if result != tt.want {
				t.Errorf("Expected '%s', got '%s'", tt.want, result)
			}
		})
	}
}

// TestDefaultStrategy_GetPlaceholder tests the GetPlaceholder method
func TestDefaultStrategy_GetPlaceholder(t *testing.T) {
	strategy := &DefaultStrategy{}

	result := strategy.GetPlaceholder()
	if result != "[REDACTED]" {
		t.Errorf("Expected placeholder '[REDACTED]', got '%s'", result)
	}
}

// TestRedactData tests the redactData dispatcher function
func TestRedactData(t *testing.T) {
	processor := NewResponseProcessor()
	info := &RedactionInfo{}

	tests := []struct {
		name        string
		data        interface{}
		detectedPII map[string][]string
		allowedPII  []string
		checkType   string
		checkValue  interface{}
	}{
		{
			name: "string data",
			data: "test string with 123-45-6789",
			detectedPII: map[string][]string{
				"ssn": {"123-45-6789"},
			},
			allowedPII: []string{},
			checkType:  "string",
		},
		{
			name: "map data",
			data: map[string]interface{}{
				"email": "test@example.com",
			},
			detectedPII: map[string][]string{
				"email": {"test@example.com"},
			},
			allowedPII: []string{},
			checkType:  "map",
		},
		{
			name: "slice data",
			data: []interface{}{"item1", "item2"},
			detectedPII: map[string][]string{},
			allowedPII: []string{},
			checkType:  "slice",
		},
		{
			name:        "integer data (default case)",
			data:        12345,
			detectedPII: map[string][]string{},
			allowedPII:  []string{},
			checkType:   "default",
			checkValue:  12345,
		},
		{
			name:        "bool data (default case)",
			data:        true,
			detectedPII: map[string][]string{},
			allowedPII:  []string{},
			checkType:   "default",
			checkValue:  true,
		},
		{
			name:        "nil data (default case)",
			data:        nil,
			detectedPII: map[string][]string{},
			allowedPII:  []string{},
			checkType:   "default",
			checkValue:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.redactData(tt.data, tt.detectedPII, tt.allowedPII, info)

			switch tt.checkType {
			case "string":
				if _, ok := result.(string); !ok {
					t.Errorf("Expected string result, got %T", result)
				}
			case "map":
				if _, ok := result.(map[string]interface{}); !ok {
					t.Errorf("Expected map result, got %T", result)
				}
			case "slice":
				if _, ok := result.([]interface{}); !ok {
					t.Errorf("Expected slice result, got %T", result)
				}
			case "default":
				if result != tt.checkValue {
					t.Errorf("Expected %v, got %v", tt.checkValue, result)
				}
			}
		})
	}
}

// TestRedactor_GetStrategy tests redaction strategy selection
func TestRedactor_GetStrategy(t *testing.T) {
	redactor := NewRedactor()

	tests := []struct {
		name         string
		piiType      string
		expectedType string
	}{
		{
			name:         "existing strategy - ssn",
			piiType:      "ssn",
			expectedType: "*orchestrator.MaskingStrategy",
		},
		{
			name:         "existing strategy - email",
			piiType:      "email",
			expectedType: "*orchestrator.HashingStrategy",
		},
		{
			name:         "nonexistent strategy - falls back to default",
			piiType:      "unknown_type",
			expectedType: "*orchestrator.DefaultStrategy", // default is DefaultStrategy
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := redactor.getStrategy(tt.piiType)

			strategyType := fmt.Sprintf("%T", strategy)
			if strategyType != tt.expectedType {
				t.Errorf("Expected strategy type %s, got %s", tt.expectedType, strategyType)
			}
		})
	}
}

// TestNewResponseEnricher tests enricher initialization
func TestNewResponseEnricher(t *testing.T) {
	enricher := NewResponseEnricher()

	if enricher == nil {
		t.Fatal("NewResponseEnricher should not return nil")
	}

	if len(enricher.enrichmentRules) == 0 {
		t.Error("NewResponseEnricher should initialize with enrichment rules")
	}

	// Verify required enrichment rules exist
	foundTimestamp := false
	foundRequestContext := false

	for _, rule := range enricher.enrichmentRules {
		if rule.Name == "timestamp" {
			foundTimestamp = true
		}
		if rule.Name == "request_context" {
			foundRequestContext = true
		}
	}

	if !foundTimestamp {
		t.Error("NewResponseEnricher should include 'timestamp' enrichment rule")
	}

	if !foundRequestContext {
		t.Error("NewResponseEnricher should include 'request_context' enrichment rule")
	}
}

// TestResponseEnricher_TimestampEnrichment tests timestamp enrichment
func TestResponseEnricher_TimestampEnrichment(t *testing.T) {
	enricher := NewResponseEnricher()
	ctx := context.Background()
	response := map[string]interface{}{
		"data": "test",
	}

	// Find and test timestamp enricher
	for _, rule := range enricher.enrichmentRules {
		if rule.Name == "timestamp" {
			enrichment := rule.Enricher(ctx, response)

			if _, ok := enrichment["processed_at"]; !ok {
				t.Error("Timestamp enricher should add 'processed_at' field")
			}
		}
	}
}

// TestResponseEnricher_RequestContextEnrichment tests request context enrichment
func TestResponseEnricher_RequestContextEnrichment(t *testing.T) {
	enricher := NewResponseEnricher()

	// Test with request ID in context
	ctx := context.WithValue(context.Background(), "request_id", "test-req-123")
	response := map[string]interface{}{
		"data": "test",
	}

	for _, rule := range enricher.enrichmentRules {
		if rule.Name == "request_context" {
			enrichment := rule.Enricher(ctx, response)

			if enrichment["request_id"] != "test-req-123" {
				t.Errorf("Expected request_id 'test-req-123', got %v", enrichment["request_id"])
			}
		}
	}

	// Test without request ID in context
	ctxEmpty := context.Background()
	for _, rule := range enricher.enrichmentRules {
		if rule.Name == "request_context" {
			enrichment := rule.Enricher(ctxEmpty, response)

			// Should return empty map if no request_id
			if len(enrichment) != 0 {
				t.Error("Request context enricher should return empty map when no request_id in context")
			}
		}
	}
}

// TestProcessResponse_MapWithNestedPII tests deep scanning of nested structures
func TestProcessResponse_MapWithNestedPII(t *testing.T) {
	processor := NewResponseProcessor()
	ctx := context.Background()
	user := UserContext{
		ID:    1,
		Email: "test@example.com",
		Role:  "user",
	}

	response := &LLMResponse{
		Content: `{"user": {"name": "John", "ssn": "123-45-6789", "nested": {"email": "john@example.com"}}}`,
	}

	result, info := processor.ProcessResponse(ctx, user, response)

	if !info.HasRedactions {
		t.Error("Expected redactions for nested PII")
	}

	// Convert result to map to check redactions
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}

	// Check that nested SSN was redacted
	if userData, ok := resultMap["user"].(map[string]interface{}); ok {
		if ssnVal, exists := userData["ssn"]; exists {
			if ssnStr, ok := ssnVal.(string); ok && ssnStr == "123-45-6789" {
				t.Error("SSN should have been redacted")
			}
		}
	}
}

// TestProcessResponse_SliceWithPII tests PII detection in array structures
func TestProcessResponse_SliceWithPII(t *testing.T) {
	processor := NewResponseProcessor()
	ctx := context.Background()
	user := UserContext{
		ID:    1,
		Email: "test@example.com",
		Role:  "user",
	}

	response := &LLMResponse{
		Content: `{"users": [{"name": "User1", "email": "user1@test.com"}, {"name": "User2", "ssn": "987-65-4321"}]}`,
	}

	result, info := processor.ProcessResponse(ctx, user, response)

	if !info.HasRedactions {
		t.Error("Expected redactions for PII in array")
	}

	if len(info.RedactedFields) == 0 {
		t.Error("Expected at least one redacted field")
	}

	// Result should still be valid
	if result == nil {
		t.Error("Result should not be nil")
	}
}

// TestProcessResponse_ComplexJSON tests complex nested JSON structures
func TestProcessResponse_ComplexJSON(t *testing.T) {
	processor := NewResponseProcessor()
	ctx := context.WithValue(context.Background(), "request_id", "test-req-123")
	user := UserContext{
		ID:    1,
		Email: "test@example.com",
		Role:  "user",
	}

	response := &LLMResponse{
		Content: `{
			"results": [
				{"id": 1, "data": "safe data"},
				{"id": 2, "data": "more safe data"}
			],
			"metadata": {
				"count": 2,
				"processing_time": 150
			}
		}`,
	}

	result, info := processor.ProcessResponse(ctx, user, response)

	// Should process without redactions (no PII)
	if info.HasRedactions {
		t.Error("Should not have redactions for safe data")
	}

	// Check result is valid map
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}

	// Result should be non-empty
	if len(resultMap) == 0 {
		t.Error("Result map should not be empty")
	}
}

// TestDeepScanForPII_DeeplyNestedStructures tests recursive PII scanning
func TestDeepScanForPII_DeeplyNestedStructures(t *testing.T) {
	processor := NewResponseProcessor()

	tests := []struct {
		name        string
		data        map[string]interface{}
		expectPII   bool
		expectedMin int
	}{
		{
			name: "3 levels deep - nested map with SSN field",
			data: map[string]interface{}{
				"level1": map[string]interface{}{
					"level2": map[string]interface{}{
						"ssn": "123-45-6789",
					},
				},
			},
			expectPII:   true,
			expectedMin: 1,
		},
		{
			name: "PII in field name",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"email": "test@example.com",
					"phone": "555-1234",
				},
			},
			expectPII:   true,
			expectedMin: 1,
		},
		{
			name: "Mixed types no PII",
			data: map[string]interface{}{
				"string": "test",
				"number": 123,
				"bool":   true,
				"nested": map[string]interface{}{
					"data": "safe data",
				},
			},
			expectPII:   false,
			expectedMin: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detected := make(map[string][]string)
			processor.deepScanForPII(tt.data, detected)

			hasPII := len(detected) > 0
			if hasPII != tt.expectPII {
				t.Errorf("Expected PII detection: %v, got: %v (detected: %v)", tt.expectPII, hasPII, detected)
			}

			if tt.expectPII && len(detected) < tt.expectedMin {
				t.Errorf("Expected at least %d PII types, got %d: %v", tt.expectedMin, len(detected), detected)
			}
		})
	}
}

// TestNewResponseProcessorWithConfig tests creating processor with custom configuration
func TestNewResponseProcessorWithConfig(t *testing.T) {
	tests := []struct {
		name        string
		useEnhanced bool
		config      PIIDetectorConfig
	}{
		{
			name:        "with enhanced detector enabled",
			useEnhanced: true,
			config:      DefaultPIIDetectorConfig(),
		},
		{
			name:        "with enhanced detector disabled",
			useEnhanced: false,
			config:      DefaultPIIDetectorConfig(),
		},
		{
			name:        "with custom confidence threshold",
			useEnhanced: true,
			config: PIIDetectorConfig{
				MinConfidence:    0.9,
				EnabledTypes:     []PIIType{PIITypeSSN, PIITypeCreditCard},
				EnableValidation: true,
				ContextWindow:    100,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewResponseProcessorWithConfig(tt.useEnhanced, tt.config)

			if processor == nil {
				t.Fatal("NewResponseProcessorWithConfig should not return nil")
			}

			if processor.useEnhancedDetector != tt.useEnhanced {
				t.Errorf("useEnhancedDetector = %v, want %v", processor.useEnhancedDetector, tt.useEnhanced)
			}

			if processor.piiDetector == nil {
				t.Error("piiDetector should not be nil")
			}

			if processor.enhancedPIIDetector == nil {
				t.Error("enhancedPIIDetector should not be nil")
			}

			if processor.redactor == nil {
				t.Error("redactor should not be nil")
			}

			if processor.enricher == nil {
				t.Error("enricher should not be nil")
			}
		})
	}
}

// TestSetUseEnhancedDetector tests toggling the enhanced detector
func TestSetUseEnhancedDetector(t *testing.T) {
	processor := NewResponseProcessor()

	// Default should be true
	if !processor.useEnhancedDetector {
		t.Error("Default useEnhancedDetector should be true")
	}

	// Disable enhanced detector
	processor.SetUseEnhancedDetector(false)
	if processor.useEnhancedDetector {
		t.Error("After SetUseEnhancedDetector(false), should be false")
	}

	// Re-enable enhanced detector
	processor.SetUseEnhancedDetector(true)
	if !processor.useEnhancedDetector {
		t.Error("After SetUseEnhancedDetector(true), should be true")
	}
}

// TestDetectPIIEnhanced tests the enhanced PII detection method
func TestDetectPIIEnhanced(t *testing.T) {
	processor := NewResponseProcessor()

	tests := []struct {
		name           string
		data           interface{}
		expectResults  bool
		minResultCount int
	}{
		{
			name:           "string with SSN",
			data:           "My SSN is 123-45-6789",
			expectResults:  true,
			minResultCount: 1,
		},
		{
			name:           "string with credit card",
			data:           "Pay with card 4532015112830366",
			expectResults:  true,
			minResultCount: 1,
		},
		{
			name:           "string with multiple PII types",
			data:           "SSN: 123-45-6789 and email: test@example.com",
			expectResults:  true,
			minResultCount: 2,
		},
		{
			name:           "clean text - no PII",
			data:           "This is a simple text without any sensitive data.",
			expectResults:  false,
			minResultCount: 0,
		},
		{
			name:           "map data converted to string",
			data:           map[string]string{"ssn": "123-45-6789"},
			expectResults:  true,
			minResultCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := processor.detectPIIEnhanced(tt.data)

			hasResults := len(results) > 0
			if hasResults != tt.expectResults {
				t.Errorf("Expected results: %v, got: %v (count: %d)", tt.expectResults, hasResults, len(results))
			}

			if tt.expectResults && len(results) < tt.minResultCount {
				t.Errorf("Expected at least %d results, got %d", tt.minResultCount, len(results))
			}

			// Verify result structure
			for _, result := range results {
				if result.Type == "" {
					t.Error("Result type should not be empty")
				}
				if result.Value == "" {
					t.Error("Result value should not be empty")
				}
				if result.Confidence <= 0 || result.Confidence > 1 {
					t.Errorf("Confidence should be between 0 and 1, got %f", result.Confidence)
				}
			}
		})
	}
}

// TestDetectPIIEnhanced_NilDetector tests behavior when enhanced detector is nil
func TestDetectPIIEnhanced_NilDetector(t *testing.T) {
	processor := &ResponseProcessor{
		enhancedPIIDetector: nil,
	}

	results := processor.detectPIIEnhanced("test data with SSN 123-45-6789")

	if results != nil {
		t.Error("Should return nil when enhanced detector is nil")
	}
}

// TestDetectPII_WithEnhancedDisabled tests fallback to legacy detector
func TestDetectPII_WithEnhancedDisabled(t *testing.T) {
	processor := NewResponseProcessor()
	processor.SetUseEnhancedDetector(false)

	data := "My SSN is 123-45-6789 and email is test@example.com"
	detected := processor.detectPII(data)

	// Should still detect PII using legacy detector
	if len(detected) == 0 {
		t.Error("Legacy detector should still detect PII")
	}
}

// TestDetectPII_WithEnhancedEnabled tests enhanced detector usage
func TestDetectPII_WithEnhancedEnabled(t *testing.T) {
	processor := NewResponseProcessor()
	processor.SetUseEnhancedDetector(true)

	data := "My SSN is 123-45-6789"
	detected := processor.detectPII(data)

	if len(detected) == 0 {
		t.Error("Enhanced detector should detect SSN")
	}

	// Check that SSN was detected
	foundSSN := false
	for piiType := range detected {
		if piiType == string(PIITypeSSN) || piiType == "ssn" {
			foundSSN = true
			break
		}
	}
	if !foundSSN {
		t.Errorf("Expected to find SSN type in detected PII: %v", detected)
	}
}
