//go:build !enterprise

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

package rbi

import (
	"testing"
)

func TestNewIndiaPIIDetector(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	if detector == nil {
		t.Error("Expected non-nil detector")
	}

	// Community edition should have patterns loaded
	stats := detector.GetPatternStats()
	totalPatterns, ok := stats["total_patterns"].(int)
	if !ok || totalPatterns == 0 {
		t.Error("Expected patterns to be loaded in Community edition")
	}
}

func TestIsEnabled(t *testing.T) {
	// Community edition should have India PII detection enabled
	if !IsEnabled() {
		t.Error("Expected IsEnabled() to return true for Community edition")
	}
}

func TestDetectAadhaar(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid Aadhaar without separators",
			input:    "My Aadhaar number is 234567890123",
			expected: true,
		},
		{
			name:     "valid Aadhaar with spaces",
			input:    "Aadhaar: 2345 6789 0123",
			expected: true,
		},
		{
			name:     "valid Aadhaar with hyphens",
			input:    "ID: 2345-6789-0123",
			expected: true,
		},
		{
			name:     "invalid Aadhaar starting with 0",
			input:    "Invalid: 0345 6789 0123",
			expected: false,
		},
		{
			name:     "invalid Aadhaar starting with 1",
			input:    "Invalid: 1345 6789 0123",
			expected: false,
		},
		{
			name:     "no Aadhaar",
			input:    "This text has no Aadhaar number",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndiaPIITypeAadhaar)
			hasAadhaar := len(results) > 0
			if hasAadhaar != tt.expected {
				t.Errorf("DetectType(%q, Aadhaar) = %v, want %v", tt.input, hasAadhaar, tt.expected)
			}
		})
	}
}

func TestDetectPAN(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid PAN - individual",
			input:    "PAN: ABCDE1234F",
			expected: true,
		},
		{
			name:     "valid PAN - company",
			input:    "Company PAN: AABCC1234D",
			expected: true,
		},
		{
			name:     "invalid PAN - wrong format",
			input:    "Invalid: ABC123456",
			expected: false,
		},
		{
			name:     "no PAN",
			input:    "This text has no PAN number",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndiaPIITypePAN)
			hasPAN := len(results) > 0
			if hasPAN != tt.expected {
				t.Errorf("DetectType(%q, PAN) = %v, want %v", tt.input, hasPAN, tt.expected)
			}
		})
	}
}

func TestDetectUPI(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid UPI ID",
			input:    "Pay to: user123@ybl",
			expected: true,
		},
		{
			name:     "valid UPI ID with paytm",
			input:    "UPI: john.doe@paytm",
			expected: true,
		},
		{
			name:     "invalid - too short",
			input:    "Invalid: a@b",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndiaPIITypeUPI)
			hasUPI := len(results) > 0
			if hasUPI != tt.expected {
				t.Errorf("DetectType(%q, UPI) = %v, want %v", tt.input, hasUPI, tt.expected)
			}
		})
	}
}

func TestDetectAll(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	// Text with multiple PII types
	text := "User details: PAN ABCDE1234F, Aadhaar 2345 6789 0123, UPI user@ybl"
	results := detector.DetectAll(text)

	if len(results) < 3 {
		t.Errorf("Expected at least 3 PII detections, got %d", len(results))
	}

	// Check that we found different types
	foundTypes := make(map[IndiaPIIType]bool)
	for _, r := range results {
		foundTypes[r.Type] = true
	}

	expectedTypes := []IndiaPIIType{IndiaPIITypePAN, IndiaPIITypeAadhaar, IndiaPIITypeUPI}
	for _, et := range expectedTypes {
		if !foundTypes[et] {
			t.Errorf("Expected to find %s in detections", et)
		}
	}
}

func TestHasIndiaPII(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "has PAN",
			input:    "PAN: ABCDE1234F",
			expected: true,
		},
		{
			name:     "has Aadhaar",
			input:    "Aadhaar: 2345 6789 0123",
			expected: true,
		},
		{
			name:     "no PII",
			input:    "This is plain text with no PII",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.HasIndiaPII(tt.input)
			if result != tt.expected {
				t.Errorf("HasIndiaPII(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestHasCriticalPII(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "has Aadhaar (critical)",
			input:    "Aadhaar: 2345 6789 0123",
			expected: true,
		},
		{
			name:     "has PAN (critical)",
			input:    "PAN: ABCDE1234F",
			expected: true,
		},
		{
			name:     "has pincode only (not critical)",
			input:    "Pincode: 560001",
			expected: false,
		},
		{
			name:     "no PII",
			input:    "No PII here",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.HasCriticalPII(tt.input)
			if result != tt.expected {
				t.Errorf("HasCriticalPII(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCheckRequestForPII(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	tests := []struct {
		name            string
		query           string
		blockOnCritical bool
		expectHasPII    bool
		expectCritical  bool
		expectBlock     bool
	}{
		{
			name:            "no PII",
			query:           "What is the weather today?",
			blockOnCritical: true,
			expectHasPII:    false,
			expectCritical:  false,
			expectBlock:     false,
		},
		{
			name:            "has critical PII with blocking",
			query:           "My PAN is ABCDE1234F",
			blockOnCritical: true,
			expectHasPII:    true,
			expectCritical:  true,
			expectBlock:     true,
		},
		{
			name:            "has critical PII without blocking",
			query:           "My PAN is ABCDE1234F",
			blockOnCritical: false,
			expectHasPII:    true,
			expectCritical:  true,
			expectBlock:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckRequestForPII(detector, tt.query, tt.blockOnCritical)

			if result.HasPII != tt.expectHasPII {
				t.Errorf("HasPII = %v, want %v", result.HasPII, tt.expectHasPII)
			}
			if result.CriticalPII != tt.expectCritical {
				t.Errorf("CriticalPII = %v, want %v", result.CriticalPII, tt.expectCritical)
			}
			if result.BlockRecommended != tt.expectBlock {
				t.Errorf("BlockRecommended = %v, want %v", result.BlockRecommended, tt.expectBlock)
			}
		})
	}
}

func TestMaskIndiaPII(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		piiType  IndiaPIIType
		expected string
	}{
		{
			name:     "mask Aadhaar",
			value:    "234567890123",
			piiType:  IndiaPIITypeAadhaar,
			expected: "XXXX XXXX 0123",
		},
		{
			name:     "mask PAN",
			value:    "ABCDE1234F",
			piiType:  IndiaPIITypePAN,
			expected: "AB******4F",
		},
		{
			name:     "mask UPI",
			value:    "user123@ybl",
			piiType:  IndiaPIITypeUPI,
			expected: "use***@ybl",
		},
		{
			name:     "mask phone",
			value:    "9876543210",
			piiType:  IndiaPIITypeIndianPhone,
			expected: "XXXXXX3210",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskIndiaPII(tt.value, tt.piiType)
			if result != tt.expected {
				t.Errorf("maskIndiaPII(%q, %s) = %q, want %q", tt.value, tt.piiType, result, tt.expected)
			}
		})
	}
}

func TestFilterBySeverity(t *testing.T) {
	results := []IndiaPIIDetectionResult{
		{Type: IndiaPIITypePincode, Severity: IndiaPIISeverityLow},
		{Type: IndiaPIITypeIndianPhone, Severity: IndiaPIISeverityMedium},
		{Type: IndiaPIITypePAN, Severity: IndiaPIISeverityCritical},
	}

	filtered := FilterIndiaPIIBySeverity(results, IndiaPIISeverityHigh)

	if len(filtered) != 1 {
		t.Errorf("Expected 1 result (critical only), got %d", len(filtered))
	}

	if len(filtered) > 0 && filtered[0].Severity != IndiaPIISeverityCritical {
		t.Errorf("Expected critical severity, got %s", filtered[0].Severity)
	}
}

func TestGetPatternStats(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	stats := detector.GetPatternStats()

	// Check edition is community
	if edition, ok := stats["edition"].(string); !ok || edition != "community" {
		t.Errorf("Expected edition=community, got %v", stats["edition"])
	}

	// Check validation is disabled
	if validation, ok := stats["validation_enabled"].(bool); !ok || validation {
		t.Errorf("Expected validation_enabled=false, got %v", stats["validation_enabled"])
	}

	// Check patterns are loaded
	if total, ok := stats["total_patterns"].(int); !ok || total == 0 {
		t.Errorf("Expected total_patterns > 0, got %v", stats["total_patterns"])
	}
}

func TestGetRBISensitiveData(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	text := "PAN: ABCDE1234F, Aadhaar: 2345 6789 0123"
	categorized := detector.GetRBISensitiveData(text)

	// Should have tax_identifier (PAN) and national_identity (Aadhaar)
	if _, ok := categorized["tax_identifier"]; !ok {
		t.Error("Expected tax_identifier category")
	}
	if _, ok := categorized["national_identity"]; !ok {
		t.Error("Expected national_identity category")
	}
}

func TestDetectionConfidence(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	results := detector.DetectAll("PAN: ABCDE1234F")

	if len(results) == 0 {
		t.Fatal("Expected at least one detection")
	}

	// Community edition should have 0.7 confidence (pattern-only)
	if results[0].Confidence != 0.7 {
		t.Errorf("Expected confidence=0.7 for Community edition, got %v", results[0].Confidence)
	}
}

func TestDetectionMasking(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	results := detector.DetectAll("PAN: ABCDE1234F")

	if len(results) == 0 {
		t.Fatal("Expected at least one detection")
	}

	// Check that masked value is different from original
	if results[0].MaskedValue == results[0].Value {
		t.Error("Expected masked value to be different from original")
	}

	// Check mask format for PAN
	if results[0].MaskedValue != "AB******4F" {
		t.Errorf("Expected masked PAN 'AB******4F', got %q", results[0].MaskedValue)
	}
}

func TestNilDetectorCheckRequestForPII(t *testing.T) {
	// Should not panic and return safe default
	result := CheckRequestForPII(nil, "test query with PAN ABCDE1234F", true)

	if result == nil {
		t.Fatal("Expected non-nil result for nil detector")
	}
	if result.HasPII {
		t.Error("Expected HasPII=false for nil detector")
	}
	if result.BlockRecommended {
		t.Error("Expected BlockRecommended=false for nil detector")
	}
}

func TestEmailFiltering(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	// Note: The UPI regex matches partial email addresses like "john@gmail" from "john@gmail.com"
	// because the handle part [a-zA-Z0-9]{2,49} doesn't include dots.
	// The email filter checks for known email provider names (gmail, yahoo, etc.)
	tests := []struct {
		name        string
		input       string
		expectUPI   bool
		description string
	}{
		{
			name:        "valid UPI ID",
			input:       "Pay to: user123@ybl",
			expectUPI:   true,
			description: "known UPI handle should be detected",
		},
		{
			name:        "email address - gmail",
			input:       "Contact: john@gmail.com",
			expectUPI:   false,
			description: "gmail provider should be filtered (matched as john@gmail)",
		},
		{
			name:        "email address - yahoo",
			input:       "Email: user@yahoo.com",
			expectUPI:   false,
			description: "yahoo provider should be filtered (matched as user@yahoo)",
		},
		{
			name:        "email address - outlook",
			input:       "Contact: info@outlook.com",
			expectUPI:   false,
			description: "outlook provider should be filtered",
		},
		{
			name:        "unknown domain - could be UPI",
			input:       "Contact: user@custombank",
			expectUPI:   true,
			description: "unknown handles could be legitimate UPI IDs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndiaPIITypeUPI)
			hasUPI := len(results) > 0
			if hasUPI != tt.expectUPI {
				t.Errorf("%s: DetectType(%q, UPI) = %v, want %v",
					tt.description, tt.input, hasUPI, tt.expectUPI)
			}
		})
	}
}

func TestConvenienceMethods(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	t.Run("DetectUPIIDs", func(t *testing.T) {
		results := detector.DetectUPIIDs("Pay to: user123@ybl")
		if len(results) == 0 {
			t.Error("Expected DetectUPIIDs to find UPI ID")
		}
		if len(results) > 0 && results[0].Type != IndiaPIITypeUPI {
			t.Errorf("Expected type UPI, got %s", results[0].Type)
		}
	})

	t.Run("DetectAadhaar", func(t *testing.T) {
		results := detector.DetectAadhaar("Aadhaar: 2345 6789 0123")
		if len(results) == 0 {
			t.Error("Expected DetectAadhaar to find Aadhaar number")
		}
		if len(results) > 0 && results[0].Type != IndiaPIITypeAadhaar {
			t.Errorf("Expected type Aadhaar, got %s", results[0].Type)
		}
	})

	t.Run("DetectPAN", func(t *testing.T) {
		results := detector.DetectPAN("PAN: ABCDE1234F")
		if len(results) == 0 {
			t.Error("Expected DetectPAN to find PAN number")
		}
		if len(results) > 0 && results[0].Type != IndiaPIITypePAN {
			t.Errorf("Expected type PAN, got %s", results[0].Type)
		}
	})

	t.Run("HasUPIID_positive", func(t *testing.T) {
		if !detector.HasUPIID("Pay to: user123@ybl") {
			t.Error("Expected HasUPIID to return true for valid UPI")
		}
	})

	t.Run("HasUPIID_email_filtered", func(t *testing.T) {
		if detector.HasUPIID("Contact: john@gmail.com") {
			t.Error("Expected HasUPIID to return false for email address")
		}
	})
}

func TestGetPatternStatsExtendedFields(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	stats := detector.GetPatternStats()

	// Check new fields added in code review
	if _, ok := stats["min_confidence"]; !ok {
		t.Error("Expected min_confidence in stats")
	}
	if _, ok := stats["context_window"]; !ok {
		t.Error("Expected context_window in stats")
	}
}

// TestCreditCardNotDetectedAsAadhaar verifies that credit card numbers are NOT
// incorrectly detected as Aadhaar numbers. This is the fix for Issue #649.
//
// The Aadhaar pattern `[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}` was matching
// the first 12 digits of 16-digit credit cards like `4111-1111-1111-1111`.
func TestCreditCardNotDetectedAsAadhaar(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	tests := []struct {
		name           string
		input          string
		expectAadhaar  bool
		description    string
	}{
		// Credit cards that should NOT be detected as Aadhaar
		{
			name:          "Visa with hyphens",
			input:         "Card: 4111-1111-1111-1111",
			expectAadhaar: false,
			description:   "16-digit Visa card with hyphens should not match Aadhaar",
		},
		{
			name:          "Visa with spaces",
			input:         "Card: 4111 1111 1111 1111",
			expectAadhaar: false,
			description:   "16-digit Visa card with spaces should not match Aadhaar",
		},
		{
			name:          "Visa continuous",
			input:         "Card: 4111111111111111",
			expectAadhaar: false,
			description:   "16-digit Visa card without separators should not match Aadhaar",
		},
		{
			name:          "Mastercard with hyphens",
			input:         "Card: 5500-0000-0000-0004",
			expectAadhaar: false,
			description:   "16-digit Mastercard with hyphens should not match Aadhaar",
		},
		{
			name:          "Mastercard with spaces",
			input:         "Card: 5500 0000 0000 0004",
			expectAadhaar: false,
			description:   "16-digit Mastercard with spaces should not match Aadhaar",
		},
		{
			name:          "Amex with hyphens",
			input:         "Card: 3782-8224-6310-005",
			expectAadhaar: false,
			description:   "15-digit Amex with hyphens should not match Aadhaar",
		},
		{
			name:          "Credit card starting with 2 (could look like Aadhaar)",
			input:         "Card: 2221-0012-3456-7891",
			expectAadhaar: false,
			description:   "Mastercard starting with 2 should not match Aadhaar",
		},
		{
			name:          "Credit card starting with 5 (could look like Aadhaar)",
			input:         "Card: 5105-1051-0510-5100",
			expectAadhaar: false,
			description:   "Mastercard starting with 5 should not match Aadhaar",
		},
		{
			name:          "JCB with hyphens",
			input:         "Card: 3530-1113-3330-0000",
			expectAadhaar: false,
			description:   "16-digit JCB card should not match Aadhaar",
		},
		{
			name:          "JCB continuous",
			input:         "Card: 3530111333300000",
			expectAadhaar: false,
			description:   "16-digit JCB card without separators should not match Aadhaar",
		},
		{
			name:          "Diners Club with hyphens",
			input:         "Card: 3056-9309-0259-04",
			expectAadhaar: false,
			description:   "14-digit Diners Club should not match Aadhaar (different grouping)",
		},
		// Actual Aadhaar numbers that SHOULD be detected
		{
			name:          "Valid Aadhaar with spaces",
			input:         "Aadhaar: 2345 6789 0123",
			expectAadhaar: true,
			description:   "Valid 12-digit Aadhaar with spaces should be detected",
		},
		{
			name:          "Valid Aadhaar with hyphens",
			input:         "Aadhaar: 2345-6789-0123",
			expectAadhaar: true,
			description:   "Valid 12-digit Aadhaar with hyphens should be detected",
		},
		{
			name:          "Valid Aadhaar continuous",
			input:         "Aadhaar: 234567890123",
			expectAadhaar: true,
			description:   "Valid 12-digit Aadhaar without separators should be detected",
		},
		{
			name:          "Aadhaar at end of sentence",
			input:         "My Aadhaar is 2345 6789 0123.",
			expectAadhaar: true,
			description:   "Aadhaar followed by punctuation should be detected",
		},
		{
			name:          "Aadhaar followed by text",
			input:         "Aadhaar: 2345 6789 0123 is my ID",
			expectAadhaar: true,
			description:   "Aadhaar followed by non-digit text should be detected",
		},
		// Edge cases
		{
			name:          "12 digits followed by letter (no word boundary)",
			input:         "Number: 4111-1111-1111a",
			expectAadhaar: false, // Regex \b requires word boundary - no boundary between digit and letter
			description:   "12 digits followed immediately by letter has no word boundary, so regex won't match",
		},
		{
			name:          "Text with both patterns",
			input:         "Aadhaar: 2345 6789 0123 and Card: 4111-1111-1111-1111",
			expectAadhaar: true, // Should detect the Aadhaar but not the credit card
			description:   "Should detect Aadhaar but not credit card in same text",
		},
		{
			name:          "12 digits at end of sentence",
			input:         "Number is 4111-1111-1111.",
			expectAadhaar: true, // Punctuation creates word boundary, looks like valid Aadhaar
			description:   "12 digits followed by punctuation should be detected (word boundary exists)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndiaPIITypeAadhaar)
			hasAadhaar := len(results) > 0
			if hasAadhaar != tt.expectAadhaar {
				t.Errorf("%s: DetectType(%q, Aadhaar) = %v, want %v",
					tt.description, tt.input, hasAadhaar, tt.expectAadhaar)
			}
		})
	}
}

// TestCreditCardCrossPatternFalsePositives tests the DetectAll function
// to ensure credit cards don't trigger India PII false positives across all types.
func TestCreditCardCrossPatternFalsePositives(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	creditCards := []string{
		"4111-1111-1111-1111",      // Visa test card
		"4111 1111 1111 1111",      // Visa with spaces
		"5500-0000-0000-0004",      // Mastercard
		"3782-8224-6310-005",       // Amex (15 digits)
		"6011-0000-0000-0004",      // Discover
		"2221-0012-3456-7891",      // Mastercard 2-series
		"3530-1113-3330-0000",      // JCB (16 digits, starts with 35)
		"3056-9309-0259-04",        // Diners Club (14 digits, 4-6-4 format)
		"3852-0000-0232-37",        // Diners Club International
	}

	for _, cc := range creditCards {
		t.Run("DetectAll_"+cc, func(t *testing.T) {
			input := "Payment card: " + cc
			results := detector.DetectAll(input)

			// Check that NO Aadhaar detection occurred
			for _, r := range results {
				if r.Type == IndiaPIITypeAadhaar {
					t.Errorf("Credit card %q incorrectly detected as Aadhaar. Matched: %q",
						cc, r.Value)
				}
			}
		})
	}
}

// TestIsLikelyCreditCard tests the helper function directly
func TestIsLikelyCreditCard(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		matchEnd int
		expected bool
	}{
		{
			name:     "hyphen + 4 digits (Visa/MC)",
			text:     "4111-1111-1111-1111",
			matchEnd: 14, // after "4111-1111-1111"
			expected: true,
		},
		{
			name:     "space + 4 digits (Visa/MC)",
			text:     "4111 1111 1111 1111",
			matchEnd: 14, // after "4111 1111 1111"
			expected: true,
		},
		{
			name:     "4 digits directly (continuous)",
			text:     "4111111111111111",
			matchEnd: 12, // after first 12 digits
			expected: true,
		},
		{
			name:     "hyphen + 3 digits (Amex)",
			text:     "3782-8224-6310-005",
			matchEnd: 14, // after "3782-8224-6310"
			expected: true,
		},
		{
			name:     "space + 3 digits (Amex)",
			text:     "3782 8224 6310 005",
			matchEnd: 14, // after "3782 8224 6310"
			expected: true,
		},
		{
			name:     "3 digits directly (continuous Amex)",
			text:     "378282246310005",
			matchEnd: 12, // after first 12 digits
			expected: true,
		},
		{
			name:     "end of string",
			text:     "2345 6789 0123",
			matchEnd: 14, // at end
			expected: false,
		},
		{
			name:     "followed by text",
			text:     "2345 6789 0123 is my ID",
			matchEnd: 14, // after the number
			expected: false,
		},
		{
			name:     "followed by punctuation",
			text:     "2345-6789-0123.",
			matchEnd: 14, // before the period
			expected: false,
		},
		{
			name:     "hyphen + 2 digits (Diners Club suffix)",
			text:     "4111-1111-1111-11",
			matchEnd: 14,
			expected: true, // 2+ digits after separator = credit card
		},
		{
			name:     "followed by letters",
			text:     "4111-1111-1111-abcd",
			matchEnd: 14,
			expected: false,
		},
		{
			name:     "only 1 digit after separator",
			text:     "4111-1111-1111-1",
			matchEnd: 14,
			expected: false,
		},
		{
			name:     "2 digits directly (continuous)",
			text:     "411111111111XX",
			matchEnd: 12, // after first 12 digits, followed by "XX"
			expected: false, // XX is not digits
		},
		{
			name:     "2 digits directly (valid continuation)",
			text:     "41111111111111",
			matchEnd: 12, // after first 12 digits, followed by "11"
			expected: true, // 2+ digits = credit card
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLikelyCreditCard(tt.text, tt.matchEnd)
			if result != tt.expected {
				t.Errorf("isLikelyCreditCard(%q, %d) = %v, want %v",
					tt.text, tt.matchEnd, result, tt.expected)
			}
		})
	}
}

// TestIsDigitString tests the helper function
func TestIsDigitString(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"1234", true},
		{"0000", true},
		{"1111", true},
		{"123a", false},
		{"abcd", false},
		{"", true}, // empty string has no non-digits
		{"12-34", false},
		{"12 34", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isDigitString(tt.input)
			if result != tt.expected {
				t.Errorf("isDigitString(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestHasCriticalPIIWithCreditCard ensures HasCriticalPII doesn't false positive on credit cards
func TestHasCriticalPIIWithCreditCard(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "credit card only",
			input:    "Payment card: 4111-1111-1111-1111",
			expected: false, // Credit card should NOT trigger critical PII
		},
		{
			name:     "actual Aadhaar",
			input:    "Aadhaar: 2345 6789 0123",
			expected: true, // Aadhaar IS critical PII
		},
		{
			name:     "actual PAN",
			input:    "PAN: ABCDE1234F",
			expected: true, // PAN IS critical PII
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.HasCriticalPII(tt.input)
			if result != tt.expected {
				t.Errorf("HasCriticalPII(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestCheckRequestForPIIWithCreditCard ensures CheckRequestForPII doesn't recommend
// blocking on credit card numbers (they should be handled by credit card policy, not Aadhaar policy)
func TestCheckRequestForPIIWithCreditCard(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	// Credit card should NOT trigger India PII blocking
	result := CheckRequestForPII(detector, "Process payment with card 4111-1111-1111-1111", true)

	if result.HasPII {
		// Check if it incorrectly detected Aadhaar
		for _, d := range result.Detections {
			if d.Type == IndiaPIITypeAadhaar {
				t.Errorf("Credit card incorrectly detected as Aadhaar: %q", d.Value)
			}
		}
	}

	if result.BlockRecommended {
		t.Error("Credit card should not trigger block recommendation from India PII check")
	}
}
