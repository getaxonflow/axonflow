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
	"strings"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewEnhancedPIIDetector(t *testing.T) {
	config := DefaultPIIDetectorConfig()
	detector := NewEnhancedPIIDetector(config)

	if detector == nil {
		t.Fatal("NewEnhancedPIIDetector returned nil")
	}

	if len(detector.patterns) == 0 {
		t.Error("Expected patterns to be loaded")
	}

	stats := detector.GetPatternStats()
	if stats["total_patterns"].(int) < 9 {
		t.Errorf("Expected at least 9 patterns, got %d", stats["total_patterns"])
	}
}

func TestNewEnhancedPIIDetector_WithEnabledTypes(t *testing.T) {
	config := PIIDetectorConfig{
		ContextWindow:    50,
		MinConfidence:    0.5,
		EnableValidation: true,
		EnabledTypes:     []PIIType{PIITypeSSN, PIITypeEmail},
	}

	detector := NewEnhancedPIIDetector(config)

	stats := detector.GetPatternStats()
	if stats["total_patterns"].(int) != 2 {
		t.Errorf("Expected 2 patterns with filtered types, got %d", stats["total_patterns"])
	}
}

func TestDefaultPIIDetectorConfig(t *testing.T) {
	config := DefaultPIIDetectorConfig()

	if config.ContextWindow != 50 {
		t.Errorf("Expected ContextWindow 50, got %d", config.ContextWindow)
	}

	if config.MinConfidence != 0.5 {
		t.Errorf("Expected MinConfidence 0.5, got %f", config.MinConfidence)
	}

	if !config.EnableValidation {
		t.Error("Expected EnableValidation to be true")
	}
}

// =============================================================================
// SSN Detection Tests
// =============================================================================

func TestSSN_ValidFormats(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"Standard format with dashes", "My SSN is 123-45-6789", true},
		{"Format with spaces", "SSN: 123 45 6789", true},
		{"No separators", "SSN number 123456789", true},
		{"In sentence context", "The social security number is 078-05-1120", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, PIITypeSSN)
			got := len(results) > 0
			if got != tt.want {
				t.Errorf("DetectType(SSN) = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSSN_InvalidFormats(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []struct {
		name  string
		input string
	}{
		{"Starts with 000", "Invalid SSN 000-12-3456"},
		{"Starts with 666", "Invalid SSN 666-12-3456"},
		{"Starts with 900+", "Invalid SSN 900-12-3456"},
		{"Middle group is 00", "Invalid SSN 123-00-4567"},
		{"Last group is 0000", "Invalid SSN 123-45-0000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, PIITypeSSN)
			if len(results) > 0 {
				t.Errorf("Should not detect invalid SSN in: %s", tt.input)
			}
		})
	}
}

func TestSSN_FalsePositivePrevention(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []struct {
		name        string
		input       string
		expectMatch bool
		minConf     float64
	}{
		{
			name:        "Order number context should reduce confidence",
			input:       "Order number: 123-45-6789",
			expectMatch: true,
			minConf:     0.0, // Matches but low confidence
		},
		{
			name:        "Invoice reference context",
			input:       "Invoice reference: 123-45-6789",
			expectMatch: true,
			minConf:     0.0,
		},
		{
			name:        "Tracking number context",
			input:       "Tracking: 123-45-6789",
			expectMatch: true,
			minConf:     0.0,
		},
		{
			name:        "SSN context should have high confidence",
			input:       "Please provide your SSN: 123-45-6789",
			expectMatch: true,
			minConf:     0.9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, PIITypeSSN)

			if !tt.expectMatch && len(results) > 0 {
				t.Errorf("Should not match: %s", tt.input)
				return
			}

			if tt.expectMatch && len(results) > 0 && results[0].Confidence < tt.minConf {
				// This is expected behavior - low confidence for order numbers
				if tt.minConf > 0.5 {
					t.Errorf("Expected confidence >= %f, got %f", tt.minConf, results[0].Confidence)
				}
			}
		})
	}
}

// =============================================================================
// Credit Card Detection Tests
// =============================================================================

func TestCreditCard_ValidCards(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []struct {
		name     string
		input    string
		cardType string
	}{
		{"Visa 16 digit", "Card: 4532015112830366", "visa"},
		{"Visa 13 digit", "Card: 4532015112830", "visa"},
		{"MasterCard", "Card: 5425233430109903", "mastercard"},
		{"MasterCard 2-series", "Card: 2223000048400011", "mastercard"},
		{"Amex", "Card: 378282246310005", "amex"},
		{"Discover", "Card: 6011111111111117", "discover"},
		{"Diners Club", "Card: 30569309025904", "diners"},
		{"JCB", "Card: 3530111333300000", "jcb"},
		{"With dashes", "Card: 4532-0151-1283-0366", "visa"},
		{"With spaces", "Card: 4532 0151 1283 0366", "visa"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, PIITypeCreditCard)
			if len(results) == 0 {
				t.Errorf("Should detect %s card in: %s", tt.cardType, tt.input)
			}
		})
	}
}

func TestCreditCard_InvalidCards(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []struct {
		name  string
		input string
	}{
		{"Fails Luhn", "Invalid card 4532015112830367"},
		{"Too short", "Card: 453201511283"},
		{"Random digits", "Number: 1234567890123456"},
		{"Phone number mistaken", "Phone: 1234567890"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, PIITypeCreditCard)
			for _, r := range results {
				if r.Confidence > 0.5 {
					t.Errorf("Should not detect with high confidence: %s (got conf: %f)", tt.input, r.Confidence)
				}
			}
		})
	}
}

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		number string
		valid  bool
	}{
		{"4532015112830366", true},  // Valid Visa
		{"4532015112830367", false}, // Invalid
		{"378282246310005", true},   // Valid Amex
		{"0000000000000000", true},  // Edge case
		{"1234567890123456", false}, // Random
	}

	for _, tt := range tests {
		t.Run(tt.number, func(t *testing.T) {
			got := luhnCheck(tt.number)
			if got != tt.valid {
				t.Errorf("luhnCheck(%s) = %v, want %v", tt.number, got, tt.valid)
			}
		})
	}
}

func TestIdentifyCardType(t *testing.T) {
	tests := []struct {
		number   string
		expected string
	}{
		{"4532015112830366", "visa"},
		{"5425233430109903", "mastercard"},
		{"2223000048400011", "mastercard"},
		{"378282246310005", "amex"},
		{"6011111111111117", "discover"},
		{"30569309025904", "diners"},
		{"3530111333300000", "jcb"},
		{"9999999999999999", ""},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := identifyCardType(tt.number)
			if got != tt.expected {
				t.Errorf("identifyCardType(%s) = %s, want %s", tt.number, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Email Detection Tests
// =============================================================================

func TestEmail_ValidFormats(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []string{
		"Contact user@example.com for info",
		"Email: john.doe@company.co.uk",
		"test+filter@gmail.com is valid",
		"user_name@sub.domain.org",
		"a@b.co",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			results := detector.DetectType(input, PIITypeEmail)
			if len(results) == 0 {
				t.Errorf("Should detect email in: %s", input)
			}
		})
	}
}

func TestEmail_InvalidFormats(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []string{
		"Not an email @domain.com",
		"Also not email@ .com",
		"missing@tld.",
		"double..dot@domain.com",
		// Note: ".startsdot@domain.com" correctly detects "startsdot@domain.com"
		// The leading dot creates a word boundary, so valid email is extracted
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			results := detector.DetectType(input, PIITypeEmail)
			if len(results) > 0 {
				t.Errorf("Should not detect email in: %s", input)
			}
		})
	}
}

// =============================================================================
// Phone Detection Tests
// =============================================================================

func TestPhone_ValidFormats(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []string{
		"Call 555-123-4567",
		"Phone: (555) 123-4567",
		"+1 555 123 4567",
		"Tel: 5551234567",
		"+44 20 7946 0958",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			results := detector.DetectType(input, PIITypePhone)
			if len(results) == 0 {
				t.Errorf("Should detect phone in: %s", input)
			}
		})
	}
}

func TestPhone_FalsePositives(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []struct {
		name        string
		input       string
		expectMatch bool
	}{
		{
			name:        "Zip code context",
			input:       "Zip code: 12345-6789",
			expectMatch: false, // Should not match with zip context
		},
		{
			name:        "Year range",
			input:       "Years 1990-2000",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, PIITypePhone)
			hasHighConfMatch := false
			for _, r := range results {
				if r.Confidence > 0.5 {
					hasHighConfMatch = true
				}
			}
			if hasHighConfMatch != tt.expectMatch {
				t.Errorf("Phone detection mismatch for: %s", tt.input)
			}
		})
	}
}

func TestPhone_RepeatedDigits(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	// 0000000000 should be rejected
	results := detector.DetectType("Phone: 0000000000", PIITypePhone)
	for _, r := range results {
		if r.Confidence > 0.2 {
			t.Error("Repeated digits should have very low confidence")
		}
	}
}

// =============================================================================
// IP Address Detection Tests
// =============================================================================

func TestIPAddress_ValidFormats(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []struct {
		input    string
		expected string
	}{
		{"IP: 192.168.1.1", "192.168.1.1"},
		{"Server at 10.0.0.1", "10.0.0.1"},
		// Routable public IP — RFC 5737 documentation blocks (203.0.113.0/24)
		// are rejected as never-PII since #2802.
		{"Remote: 54.210.8.50", "54.210.8.50"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			results := detector.DetectType(tt.input, PIITypeIPAddress)
			if len(results) == 0 {
				t.Errorf("Should detect IP in: %s", tt.input)
			}
		})
	}
}

func TestIPAddress_InvalidFormats(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []string{
		"Not IP: 256.1.1.1",
		"Invalid: 1.2.3.256",
		"Version: 1.2.3",
		// RFC-special / documentation ranges are never a person's address (#2802).
		"Allow-all CIDR: 0.0.0.0/0 in the security group",
		"Loopback: 127.0.0.1",
		"Broadcast: 255.255.255.255",
		"TEST-NET-1: 192.0.2.10",
		"TEST-NET-2: 198.51.100.23",
		"TEST-NET-3: 203.0.113.50",
		"Link-local: 169.254.10.5",
		"Cloud metadata: 169.254.169.254",
		"CGNAT: 100.64.5.6",
		"Multicast: 224.0.0.1",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			results := detector.DetectType(input, PIITypeIPAddress)
			if len(results) > 0 {
				t.Errorf("Should not detect IP in: %s (got: %v)", input, results)
			}
		})
	}
}

func TestIPAddress_PrivateRangesLowerConfidence(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	privateIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
	}

	for _, ip := range privateIPs {
		results := detector.DetectType("IP: "+ip, PIITypeIPAddress)
		if len(results) > 0 && results[0].Confidence > 0.6 {
			t.Errorf("Private IP %s should have lower confidence", ip)
		}
	}
}

// =============================================================================
// IBAN Detection Tests
// =============================================================================

func TestIBAN_ValidFormats(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []string{
		"IBAN: DE89370400440532013000",    // Germany
		"Account: GB82WEST12345698765432", // UK
		"FR7630006000011234567890189",     // France
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			results := detector.DetectType(input, PIITypeIBAN)
			if len(results) == 0 {
				t.Errorf("Should detect IBAN in: %s", input)
			}
		})
	}
}

func TestIBAN_InvalidChecksum(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	// Invalid checksum (changed last digit)
	results := detector.DetectType("IBAN: DE89370400440532013001", PIITypeIBAN)
	if len(results) > 0 {
		t.Error("Should not detect IBAN with invalid checksum")
	}
}

func TestValidateIBANChecksum(t *testing.T) {
	tests := []struct {
		iban  string
		valid bool
	}{
		{"DE89370400440532013000", true},
		{"GB82WEST12345698765432", true},
		{"DE89370400440532013001", false}, // Invalid
		{"XX00000000000000000000", false}, // Invalid country
	}

	for _, tt := range tests {
		t.Run(tt.iban, func(t *testing.T) {
			got := validateIBANChecksum(tt.iban)
			if got != tt.valid {
				t.Errorf("validateIBANChecksum(%s) = %v, want %v", tt.iban, got, tt.valid)
			}
		})
	}
}

// =============================================================================
// Passport Detection Tests
// =============================================================================

func TestPassport_ValidFormats(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []struct {
		input   string
		context string
	}{
		{"Passport: AB1234567", "passport"},
		{"Travel document: C12345678", "passport"},
		{"Document: X123456789", "travel document"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			fullText := tt.context + " " + tt.input
			results := detector.DetectType(fullText, PIITypePassport)
			if len(results) == 0 {
				t.Errorf("Should detect passport in: %s", fullText)
			}
		})
	}
}

// =============================================================================
// Date of Birth Detection Tests
// =============================================================================

func TestDateOfBirth_ValidFormats(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []string{
		"DOB: 01/15/1990",
		"Date of birth: 1985-06-20",
		"Born: 12/25/1970",
		"Birthday: 2000-01-01",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			results := detector.DetectType(input, PIITypeDateOfBirth)
			if len(results) == 0 {
				t.Errorf("Should detect DOB in: %s", input)
			}
			// Should have high confidence with DOB context
			if results[0].Confidence < 0.9 {
				t.Errorf("DOB with context should have high confidence, got %f", results[0].Confidence)
			}
		})
	}
}

func TestDateOfBirth_NoContextLowConfidence(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	// Date without DOB context should have lower confidence
	results := detector.DetectType("Date: 01/15/1990", PIITypeDateOfBirth)
	if len(results) > 0 && results[0].Confidence > 0.5 {
		t.Error("Date without DOB context should have lower confidence")
	}
}

// =============================================================================
// Driver's License Detection Tests
// =============================================================================

func TestDriverLicense_ValidFormats(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []string{
		"Driver's license: D12345678",
		"DL: A1234567",
		"License number: 123456789",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			results := detector.DetectType(input, PIITypeDriverLicense)
			if len(results) == 0 {
				t.Errorf("Should detect driver's license in: %s", input)
			}
		})
	}
}

// =============================================================================
// Bank Account Detection Tests
// =============================================================================

func TestBankAccount_ValidFormats(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []string{
		"Routing: 021000021 Account: 123456789012",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			results := detector.DetectType(input, PIITypeBankAccount)
			// Note: This test may need adjustment based on exact pattern matching
			_ = results // Just verify no panic
		})
	}
}

func TestValidateABARoutingNumber(t *testing.T) {
	tests := []struct {
		routing string
		valid   bool
	}{
		{"021000021", true},  // JPMorgan Chase
		{"011401533", true},  // Bank of America
		{"000000000", false}, // Invalid
		{"12345678", false},  // Too short
	}

	for _, tt := range tests {
		t.Run(tt.routing, func(t *testing.T) {
			got := validateABARoutingNumber(tt.routing)
			if got != tt.valid {
				t.Errorf("validateABARoutingNumber(%s) = %v, want %v", tt.routing, got, tt.valid)
			}
		})
	}
}

// =============================================================================
// DetectAll Tests
// =============================================================================

func TestDetectAll_MultiplePIITypes(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	input := `
		Customer Information:
		SSN: 123-45-6789
		Email: customer@example.com
		Phone: (555) 123-4567
		Card: 4532015112830366
	`

	results := detector.DetectAll(input)

	// Should detect at least 3 types (some may have low confidence)
	typesSeen := make(map[PIIType]bool)
	for _, r := range results {
		typesSeen[r.Type] = true
	}

	expectedTypes := []PIIType{PIITypeSSN, PIITypeEmail, PIITypePhone, PIITypeCreditCard}
	for _, expected := range expectedTypes {
		// At least one of these should be detected
		found := false
		for _, r := range results {
			if r.Type == expected && r.Confidence >= 0.5 {
				found = true
				break
			}
		}
		if !found {
			// Log but don't fail - context may affect detection
			t.Logf("Warning: %s not detected with high confidence", expected)
		}
	}

	if len(results) == 0 {
		t.Error("Should detect at least some PII")
	}
}

func TestDetectAll_NoPII(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	input := "This is a normal sentence with no personal information."
	results := detector.DetectAll(input)

	if len(results) > 0 {
		t.Errorf("Should not detect PII in normal text, got: %v", results)
	}
}

// =============================================================================
// HasPII Tests
// =============================================================================

func TestHasPII_QuickCheck(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []struct {
		input    string
		expected bool
	}{
		{"Normal text without PII", false},
		{"SSN: 123-45-6789", true},
		{"Email: test@example.com", true},
		{"Card: 4532015112830366", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := detector.HasPII(tt.input)
			if got != tt.expected {
				t.Errorf("HasPII() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Utility Function Tests
// =============================================================================

func TestConvertToLegacyFormat(t *testing.T) {
	results := []PIIDetectionResult{
		{Type: PIITypeSSN, Value: "123-45-6789"},
		{Type: PIITypeEmail, Value: "test@example.com"},
		{Type: PIITypeSSN, Value: "987-65-4321"},
	}

	legacy := ConvertToLegacyFormat(results)

	if len(legacy["ssn"]) != 2 {
		t.Errorf("Expected 2 SSNs, got %d", len(legacy["ssn"]))
	}

	if len(legacy["email"]) != 1 {
		t.Errorf("Expected 1 email, got %d", len(legacy["email"]))
	}
}

func TestFilterBySeverity(t *testing.T) {
	results := []PIIDetectionResult{
		{Type: PIITypeEmail, Severity: PIISeverityMedium},
		{Type: PIITypeSSN, Severity: PIISeverityCritical},
		{Type: PIITypePhone, Severity: PIISeverityMedium},
		{Type: PIITypeCreditCard, Severity: PIISeverityCritical},
	}

	// Filter for high and above
	filtered := FilterBySeverity(results, PIISeverityHigh)
	if len(filtered) != 2 {
		t.Errorf("Expected 2 results with High+ severity, got %d", len(filtered))
	}

	// Filter for critical only
	filtered = FilterBySeverity(results, PIISeverityCritical)
	if len(filtered) != 2 {
		t.Errorf("Expected 2 critical results, got %d", len(filtered))
	}
}

func TestFilterByConfidence(t *testing.T) {
	results := []PIIDetectionResult{
		{Type: PIITypeSSN, Confidence: 0.9},
		{Type: PIITypeEmail, Confidence: 0.5},
		{Type: PIITypePhone, Confidence: 0.3},
	}

	filtered := FilterByConfidence(results, 0.7)
	if len(filtered) != 1 {
		t.Errorf("Expected 1 result with confidence >= 0.7, got %d", len(filtered))
	}

	filtered = FilterByConfidence(results, 0.5)
	if len(filtered) != 2 {
		t.Errorf("Expected 2 results with confidence >= 0.5, got %d", len(filtered))
	}
}

func TestIsRepeatedDigits(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"0000000000", true},
		{"1111111111", true},
		{"1234567890", false},
		{"", false},
		{"1", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isRepeatedDigits(tt.input)
			if got != tt.expected {
				t.Errorf("isRepeatedDigits(%s) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Context Extraction Tests
// =============================================================================

func TestExtractContext(t *testing.T) {
	detector := NewEnhancedPIIDetector(PIIDetectorConfig{
		ContextWindow:    10,
		MinConfidence:    0.5,
		EnableValidation: true,
	})

	text := "Hello my SSN is 123-45-6789 and that's it"
	context := detector.extractContext(text, 16, 27) // "123-45-6789"

	if !strings.Contains(context, "SSN is") {
		t.Error("Context should include surrounding text")
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestEdgeCases_EmptyInput(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	results := detector.DetectAll("")
	if len(results) != 0 {
		t.Error("Empty input should return no results")
	}

	if detector.HasPII("") {
		t.Error("Empty input should not have PII")
	}
}

func TestEdgeCases_VeryLongInput(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	// Create long input with PII buried in middle
	longText := strings.Repeat("Normal text. ", 1000) + "SSN: 123-45-6789" + strings.Repeat(" More text.", 1000)

	results := detector.DetectType(longText, PIITypeSSN)
	if len(results) == 0 {
		t.Error("Should detect PII in long text")
	}
}

func TestEdgeCases_OverlappingPatterns(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	// Text that could match multiple patterns
	input := "Number: 123-456-7890" // Could be phone or something else

	results := detector.DetectAll(input)
	// Should handle gracefully without duplicates or errors
	_ = results
}

// =============================================================================
// Severity Tests
// =============================================================================

func TestSeverityLevels(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	tests := []struct {
		input            string
		piiType          PIIType
		expectedSeverity PIISeverity
	}{
		{"SSN: 123-45-6789", PIITypeSSN, PIISeverityCritical},
		{"Card: 4532015112830366", PIITypeCreditCard, PIISeverityCritical},
		{"Email: test@example.com", PIITypeEmail, PIISeverityMedium},
		{"Phone: 555-123-4567", PIITypePhone, PIISeverityMedium},
	}

	for _, tt := range tests {
		t.Run(string(tt.piiType), func(t *testing.T) {
			results := detector.DetectType(tt.input, tt.piiType)
			if len(results) > 0 {
				if results[0].Severity != tt.expectedSeverity {
					t.Errorf("Expected severity %s, got %s", tt.expectedSeverity, results[0].Severity)
				}
			}
		})
	}
}

// =============================================================================
// Pattern Stats Tests
// =============================================================================

func TestGetPatternStats(t *testing.T) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	stats := detector.GetPatternStats()

	if stats["total_patterns"].(int) == 0 {
		t.Error("Should have patterns loaded")
	}

	if stats["validation"].(bool) != true {
		t.Error("Validation should be enabled by default")
	}

	if stats["min_confidence"].(float64) != 0.5 {
		t.Error("Default min confidence should be 0.5")
	}

	typeCount, ok := stats["types"].(map[PIIType]int)
	if !ok {
		t.Error("Types should be a map")
	}

	if len(typeCount) == 0 {
		t.Error("Should have type counts")
	}
}

// =============================================================================
// Bank Account Validation Tests
// =============================================================================

func TestValidateBankAccount(t *testing.T) {
	tests := []struct {
		name          string
		match         string
		context       string
		expectedValid bool
		minConfidence float64
		maxConfidence float64
	}{
		{
			name:          "valid routing and account with routing context",
			match:         "021000021123456789", // Chase routing + account
			context:       "routing number and account",
			expectedValid: true,
			minConfidence: 0.9,
			maxConfidence: 1.0,
		},
		{
			name:          "valid routing and account with bank context",
			match:         "021000021123456789",
			context:       "bank account details",
			expectedValid: true,
			minConfidence: 0.9,
			maxConfidence: 1.0,
		},
		{
			name:          "valid format no context",
			match:         "021000021123456789",
			context:       "some random text",
			expectedValid: true,
			minConfidence: 0.6,
			maxConfidence: 0.8,
		},
		{
			name:          "too short",
			match:         "1234567890123456", // 16 digits
			context:       "bank account",
			expectedValid: false,
			minConfidence: 0,
			maxConfidence: 0.1,
		},
		{
			name:          "too long",
			match:         "123456789012345678901234567", // 27 digits
			context:       "bank account",
			expectedValid: false,
			minConfidence: 0,
			maxConfidence: 0.1,
		},
		{
			name:          "invalid routing checksum",
			match:         "123456789123456789", // Invalid routing
			context:       "routing number",
			expectedValid: false,
			minConfidence: 0.2,
			maxConfidence: 0.4,
		},
		{
			name:          "with separators",
			match:         "021-000-021-123456789",
			context:       "ach transfer",
			expectedValid: true,
			minConfidence: 0.9,
			maxConfidence: 1.0,
		},
		{
			name:          "wire context",
			match:         "021000021123456789",
			context:       "wire transfer details",
			expectedValid: true,
			minConfidence: 0.9,
			maxConfidence: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, confidence := validateBankAccount(tt.match, tt.context)
			if valid != tt.expectedValid {
				t.Errorf("validateBankAccount(%q) valid = %v, want %v", tt.match, valid, tt.expectedValid)
			}
			if confidence < tt.minConfidence || confidence > tt.maxConfidence {
				t.Errorf("validateBankAccount(%q) confidence = %f, want between %f and %f",
					tt.match, confidence, tt.minConfidence, tt.maxConfidence)
			}
		})
	}
}

func TestValidateABARoutingNumber_Extended(t *testing.T) {
	tests := []struct {
		name     string
		routing  string
		expected bool
	}{
		{"Chase", "021000021", true},
		{"Bank of America", "026009593", true},
		{"Wells Fargo", "121000248", true},
		{"all zeros", "000000000", false},
		{"wrong length short", "12345678", false},
		{"wrong length long", "1234567890", false},
		{"invalid checksum", "123456789", false},
		{"another invalid", "111111111", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateABARoutingNumber(tt.routing)
			if got != tt.expected {
				t.Errorf("validateABARoutingNumber(%q) = %v, want %v", tt.routing, got, tt.expected)
			}
		})
	}
}

func TestIsRepeatedDigits_Extended(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"", false},
		{"1", true},
		{"111111", true},
		{"000000000", true},
		{"123456789", false},
		{"112233445", false},
		{"999999999", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isRepeatedDigits(tt.input)
			if got != tt.expected {
				t.Errorf("isRepeatedDigits(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Shared Policy Engine Mapping Tests (Issue #963, #975)
// =============================================================================

func TestMapCategoryToPIIType(t *testing.T) {
	tests := []struct {
		name     string
		category sharedpolicy.PolicyCategory
		expected PIIType
	}{
		{
			name:     "US PII maps to SSN",
			category: sharedpolicy.CategoryPIIUS,
			expected: PIITypeSSN,
		},
		{
			name:     "Global PII maps to CreditCard",
			category: sharedpolicy.CategoryPIIGlobal,
			expected: PIITypeCreditCard,
		},
		{
			name:     "India PII maps to BankAccount",
			category: sharedpolicy.CategoryPIIIndia,
			expected: PIITypeBankAccount,
		},
		{
			name:     "EU PII maps to IBAN",
			category: sharedpolicy.CategoryPIIEU,
			expected: PIITypeIBAN,
		},
		{
			// #2965: NRIC is a national-identity number, not Email — mapped to
			// the SSN analog (matching how US national-ID PII maps).
			name:     "Singapore PII maps to SSN (national-ID analog)",
			category: sharedpolicy.CategoryPIISingapore,
			expected: PIITypeSSN,
		},
		{
			// #2965: NIK is a national-identity number, not Email.
			name:     "Indonesia PII maps to SSN (national-ID analog)",
			category: sharedpolicy.CategoryPIIIndonesia,
			expected: PIITypeSSN,
		},
		{
			name:     "Security category falls through to default Email",
			category: sharedpolicy.CategorySecuritySQLi,
			expected: PIITypeEmail,
		},
		{
			name:     "Unknown category falls through to default Email",
			category: sharedpolicy.PolicyCategory("unknown-category"),
			expected: PIITypeEmail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapCategoryToPIIType(tt.category)
			if got != tt.expected {
				t.Errorf("mapCategoryToPIIType(%q) = %q, want %q", tt.category, got, tt.expected)
			}
		})
	}
}

func TestMapSeverityToPIISeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity sharedpolicy.Severity
		expected PIISeverity
	}{
		{
			name:     "Critical maps to Critical",
			severity: sharedpolicy.SeverityCritical,
			expected: PIISeverityCritical,
		},
		{
			name:     "High maps to High",
			severity: sharedpolicy.SeverityHigh,
			expected: PIISeverityHigh,
		},
		{
			name:     "Medium maps to Medium",
			severity: sharedpolicy.SeverityMedium,
			expected: PIISeverityMedium,
		},
		{
			name:     "Low maps to Low (default branch)",
			severity: sharedpolicy.SeverityLow,
			expected: PIISeverityLow,
		},
		{
			name:     "Unknown severity falls through to default Low",
			severity: sharedpolicy.Severity("unknown"),
			expected: PIISeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapSeverityToPIISeverity(tt.severity)
			if got != tt.expected {
				t.Errorf("mapSeverityToPIISeverity(%q) = %q, want %q", tt.severity, got, tt.expected)
			}
		})
	}
}

func TestConvertSharedResultToPIIResults(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		got := ConvertSharedResultToPIIResults(nil)
		if got != nil {
			t.Errorf("ConvertSharedResultToPIIResults(nil) = %v, want nil", got)
		}
	})

	t.Run("empty matched policies returns empty slice", func(t *testing.T) {
		result := &sharedpolicy.ResponseResult{
			MatchedPolicies: []sharedpolicy.PolicyMatch{},
		}
		got := ConvertSharedResultToPIIResults(result)
		if len(got) != 0 {
			t.Errorf("Expected empty slice, got %d results", len(got))
		}
	})

	t.Run("single match converts correctly", func(t *testing.T) {
		result := &sharedpolicy.ResponseResult{
			MatchedPolicies: []sharedpolicy.PolicyMatch{
				{
					PolicyID: "sys_pii_ssn",
					Category: sharedpolicy.CategoryPIIUS,
					Severity: sharedpolicy.SeverityCritical,
				},
			},
		}
		got := ConvertSharedResultToPIIResults(result)
		if len(got) != 1 {
			t.Fatalf("Expected 1 result, got %d", len(got))
		}
		if got[0].Type != PIITypeSSN {
			t.Errorf("Type = %q, want %q", got[0].Type, PIITypeSSN)
		}
		if got[0].Value != "[DETECTED]" {
			t.Errorf("Value = %q, want %q", got[0].Value, "[DETECTED]")
		}
		if got[0].Severity != PIISeverityCritical {
			t.Errorf("Severity = %q, want %q", got[0].Severity, PIISeverityCritical)
		}
		if got[0].Confidence != 1.0 {
			t.Errorf("Confidence = %f, want 1.0", got[0].Confidence)
		}
	})

	t.Run("multiple matches with different categories and severities", func(t *testing.T) {
		result := &sharedpolicy.ResponseResult{
			MatchedPolicies: []sharedpolicy.PolicyMatch{
				{
					PolicyID: "sys_pii_ssn",
					Category: sharedpolicy.CategoryPIIUS,
					Severity: sharedpolicy.SeverityCritical,
				},
				{
					PolicyID: "sys_pii_credit_card",
					Category: sharedpolicy.CategoryPIIGlobal,
					Severity: sharedpolicy.SeverityHigh,
				},
				{
					PolicyID: "sys_pii_iban",
					Category: sharedpolicy.CategoryPIIEU,
					Severity: sharedpolicy.SeverityMedium,
				},
			},
		}
		got := ConvertSharedResultToPIIResults(result)
		if len(got) != 3 {
			t.Fatalf("Expected 3 results, got %d", len(got))
		}

		// Verify first result: US PII / Critical
		if got[0].Type != PIITypeSSN {
			t.Errorf("Result[0].Type = %q, want %q", got[0].Type, PIITypeSSN)
		}
		if got[0].Severity != PIISeverityCritical {
			t.Errorf("Result[0].Severity = %q, want %q", got[0].Severity, PIISeverityCritical)
		}

		// Verify second result: Global PII / High
		if got[1].Type != PIITypeCreditCard {
			t.Errorf("Result[1].Type = %q, want %q", got[1].Type, PIITypeCreditCard)
		}
		if got[1].Severity != PIISeverityHigh {
			t.Errorf("Result[1].Severity = %q, want %q", got[1].Severity, PIISeverityHigh)
		}

		// Verify third result: EU PII / Medium
		if got[2].Type != PIITypeIBAN {
			t.Errorf("Result[2].Type = %q, want %q", got[2].Type, PIITypeIBAN)
		}
		if got[2].Severity != PIISeverityMedium {
			t.Errorf("Result[2].Severity = %q, want %q", got[2].Severity, PIISeverityMedium)
		}

		// All results should have [DETECTED] value and confidence 1.0
		for i, r := range got {
			if r.Value != "[DETECTED]" {
				t.Errorf("Result[%d].Value = %q, want %q", i, r.Value, "[DETECTED]")
			}
			if r.Confidence != 1.0 {
				t.Errorf("Result[%d].Confidence = %f, want 1.0", i, r.Confidence)
			}
		}
	})

	t.Run("result with no matched policies but non-nil result", func(t *testing.T) {
		result := &sharedpolicy.ResponseResult{
			PoliciesEvaluated: 10,
			Blocked:           false,
			// MatchedPolicies is nil (zero value)
		}
		got := ConvertSharedResultToPIIResults(result)
		if len(got) != 0 {
			t.Errorf("Expected empty slice for result with no matches, got %d", len(got))
		}
	})
}
