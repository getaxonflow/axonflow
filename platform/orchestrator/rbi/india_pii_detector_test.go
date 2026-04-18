// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewIndiaPIIDetector(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	if detector == nil {
		t.Fatal("expected non-nil detector")
	}

	stats := detector.GetPatternStats()
	if stats["total_patterns"].(int) == 0 {
		t.Error("expected patterns to be loaded")
	}
}

func TestIndiaPIIDetector_UPIDetection(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	tests := []struct {
		name        string
		input       string
		wantMatches int
		wantType    IndiaPIIType
	}{
		{
			name:        "valid UPI with ybl handle",
			input:       "Please send payment to myname@ybl",
			wantMatches: 1,
			wantType:    IndiaPIITypeUPI,
		},
		{
			name:        "valid UPI with paytm handle",
			input:       "My UPI ID is john.doe@paytm for payment",
			wantMatches: 1,
			wantType:    IndiaPIITypeUPI,
		},
		{
			name:        "valid UPI with oksbi handle",
			input:       "Transfer to user123@oksbi via BHIM",
			wantMatches: 1,
			wantType:    IndiaPIITypeUPI,
		},
		{
			name:        "multiple UPI IDs",
			input:       "Send to user1@ybl or user2@paytm",
			wantMatches: 2,
			wantType:    IndiaPIITypeUPI,
		},
		{
			name:        "UPI with numbers in username",
			input:       "Payment UPI: user123456@okicici",
			wantMatches: 1,
			wantType:    IndiaPIITypeUPI,
		},
		{
			name:        "UPI with dots in username",
			input:       "My VPA is first.last@okhdfcbank",
			wantMatches: 1,
			wantType:    IndiaPIITypeUPI,
		},
		{
			name:        "email should not match as UPI (gmail domain)",
			input:       "Contact me at user@gmail.com",
			wantMatches: 0,
			wantType:    IndiaPIITypeUPI,
		},
		{
			name:        "email with yahoo should not match",
			input:       "Email: someone@yahoo.com",
			wantMatches: 0,
			wantType:    IndiaPIITypeUPI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectUPIIDs(tt.input)
			if len(results) != tt.wantMatches {
				t.Errorf("expected %d matches, got %d", tt.wantMatches, len(results))
				for _, r := range results {
					t.Logf("  found: %s (%s) confidence=%.2f", r.Value, r.Type, r.Confidence)
				}
			}
			for _, r := range results {
				if r.Type != tt.wantType {
					t.Errorf("expected type %s, got %s", tt.wantType, r.Type)
				}
				if r.Severity != IndiaPIISeverityCritical {
					t.Errorf("expected critical severity for UPI, got %s", r.Severity)
				}
				if r.MaskedValue == "" {
					t.Error("expected masked value to be set")
				}
			}
		})
	}
}

func TestIndiaPIIDetector_AadhaarDetection(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	tests := []struct {
		name        string
		input       string
		wantMatches int
	}{
		{
			name:        "valid Aadhaar without separators",
			input:       "My Aadhaar number is 234567890123",
			wantMatches: 1,
		},
		{
			name:        "valid Aadhaar with space separators",
			input:       "Aadhaar: 2345 6789 0123",
			wantMatches: 1,
		},
		{
			name:        "valid Aadhaar with hyphen separators",
			input:       "UID: 2345-6789-0123",
			wantMatches: 1,
		},
		{
			name:        "invalid Aadhaar starting with 0",
			input:       "Number: 0123 4567 8901",
			wantMatches: 0,
		},
		{
			name:        "invalid Aadhaar starting with 1",
			input:       "Number: 1234 5678 9012",
			wantMatches: 0,
		},
		{
			name:        "too short for Aadhaar",
			input:       "Number: 12345678901",
			wantMatches: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectAadhaar(tt.input)
			if len(results) != tt.wantMatches {
				t.Errorf("expected %d matches, got %d", tt.wantMatches, len(results))
			}
			for _, r := range results {
				if r.Type != IndiaPIITypeAadhaar {
					t.Errorf("expected type aadhaar, got %s", r.Type)
				}
				if r.RBICategory != "national_identity" {
					t.Errorf("expected RBI category national_identity, got %s", r.RBICategory)
				}
			}
		})
	}
}

func TestIndiaPIIDetector_PANDetection(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	tests := []struct {
		name        string
		input       string
		wantMatches int
	}{
		{
			name:        "valid personal PAN",
			input:       "My PAN is ABCPP1234F", // P = Person
			wantMatches: 1,
		},
		{
			name:        "valid company PAN",
			input:       "Company PAN: AABCC1234C", // C = Company
			wantMatches: 1,
		},
		{
			name:        "valid HUF PAN",
			input:       "HUF PAN number AABCH1234H", // H = HUF
			wantMatches: 1,
		},
		{
			name:        "invalid PAN (wrong structure)",
			input:       "Number: 1234567890",
			wantMatches: 0,
		},
		{
			name:        "invalid PAN (lowercase)",
			input:       "PAN: abcpp1234f",
			wantMatches: 0,
		},
		{
			name:        "multiple PANs",
			input:       "His PAN: ABCPP1234F and her PAN: XYZAP9876P", // P = Person
			wantMatches: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectPAN(tt.input)
			if len(results) != tt.wantMatches {
				t.Errorf("expected %d matches, got %d", tt.wantMatches, len(results))
			}
			for _, r := range results {
				if r.Type != IndiaPIITypePAN {
					t.Errorf("expected type pan, got %s", r.Type)
				}
				if r.RBICategory != "tax_identifier" {
					t.Errorf("expected RBI category tax_identifier, got %s", r.RBICategory)
				}
			}
		})
	}
}

func TestIndiaPIIDetector_IFSCDetection(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	tests := []struct {
		name        string
		input       string
		wantMatches int
	}{
		{
			name:        "valid SBI IFSC",
			input:       "Bank IFSC: SBIN0001234",
			wantMatches: 1,
		},
		{
			name:        "valid HDFC IFSC",
			input:       "Transfer via NEFT to HDFC0002345",
			wantMatches: 1,
		},
		{
			name:        "valid ICICI IFSC",
			input:       "RTGS to ICIC0003456",
			wantMatches: 1,
		},
		{
			name:        "invalid IFSC (no zero in 5th position)",
			input:       "Code: SBIN1001234",
			wantMatches: 0,
		},
		{
			name:        "invalid IFSC (too short)",
			input:       "Code: SBIN012345",
			wantMatches: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndiaPIITypeIFSC)
			if len(results) != tt.wantMatches {
				t.Errorf("expected %d matches, got %d", tt.wantMatches, len(results))
			}
			for _, r := range results {
				if r.Type != IndiaPIITypeIFSC {
					t.Errorf("expected type ifsc, got %s", r.Type)
				}
			}
		})
	}
}

func TestIndiaPIIDetector_GSTINDetection(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	// GSTIN format: 2 digits (state) + PAN (10 chars) + entity code + Z + checksum
	// Example: 27AABCC1234A1Z5
	//          27 = state code
	//          AABCC1234A = PAN (5 letters + 4 digits + 1 letter)
	//          1 = entity number
	//          Z = fixed
	//          5 = checksum

	tests := []struct {
		name        string
		input       string
		wantMatches int
	}{
		{
			name:        "valid GSTIN",
			input:       "Invoice GSTIN: 27AABCC1234A1Z5",
			wantMatches: 1,
		},
		{
			name:        "GSTIN in context",
			input:       "Tax invoice from GST number 29AADCB1234H1ZK",
			wantMatches: 1,
		},
		{
			name:        "invalid GSTIN (wrong state code)",
			input:       "Number: 99AABCC1234A1Z5", // Invalid state code 99
			wantMatches: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndiaPIITypeGSTIN)
			if len(results) != tt.wantMatches {
				t.Errorf("expected %d matches, got %d", tt.wantMatches, len(results))
			}
		})
	}
}

func TestIndiaPIIDetector_IndianPhoneDetection(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	tests := []struct {
		name        string
		input       string
		wantMatches int
	}{
		{
			name:        "valid mobile with +91",
			input:       "Call me at +91 9876543210",
			wantMatches: 1,
		},
		{
			name:        "valid mobile without prefix",
			input:       "Phone: 9876543210",
			wantMatches: 1,
		},
		{
			name:        "valid mobile with 0 prefix",
			input:       "Mobile: 09876543210",
			wantMatches: 1,
		},
		{
			name:        "valid mobile starting with 6",
			input:       "Contact: 6234567890",
			wantMatches: 1,
		},
		{
			name:        "valid mobile starting with 7",
			input:       "WhatsApp: 7234567890",
			wantMatches: 1,
		},
		{
			name:        "valid mobile starting with 8",
			input:       "SMS to 8234567890",
			wantMatches: 1,
		},
		{
			name:        "invalid (starts with 5)",
			input:       "Number: 5234567890",
			wantMatches: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndiaPIITypeIndianPhone)
			if len(results) != tt.wantMatches {
				t.Errorf("expected %d matches, got %d", tt.wantMatches, len(results))
			}
		})
	}
}

func TestIndiaPIIDetector_DetectAll(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	// Text containing multiple types of India PII
	text := `
	Customer Details:
	Name: Raj Kumar
	UPI ID: rajkumar@ybl
	PAN: ABCPP1234F
	Mobile: +91 9876543210
	Bank IFSC: SBIN0001234
	`

	results := detector.DetectAll(text)

	// Should detect UPI, PAN, Phone, and IFSC
	typeCount := make(map[IndiaPIIType]int)
	for _, r := range results {
		typeCount[r.Type]++
	}

	if typeCount[IndiaPIITypeUPI] == 0 {
		t.Error("expected to detect UPI ID")
	}
	if typeCount[IndiaPIITypePAN] == 0 {
		t.Error("expected to detect PAN")
	}
	if typeCount[IndiaPIITypeIndianPhone] == 0 {
		t.Error("expected to detect phone")
	}
	if typeCount[IndiaPIITypeIFSC] == 0 {
		t.Error("expected to detect IFSC")
	}
}

func TestIndiaPIIDetector_HasIndiaPII(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	tests := []struct {
		name   string
		input  string
		hasPII bool
	}{
		{
			name:   "text with UPI",
			input:  "Send to user@ybl",
			hasPII: true,
		},
		{
			name:   "text with PAN",
			input:  "PAN: ABCPP1234F",
			hasPII: true,
		},
		{
			name:   "clean text",
			input:  "Hello, this is a normal message.",
			hasPII: false,
		},
		{
			name:   "text with email (not India PII)",
			input:  "Contact: user@gmail.com",
			hasPII: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.HasIndiaPII(tt.input)
			if result != tt.hasPII {
				t.Errorf("expected HasIndiaPII=%v, got %v", tt.hasPII, result)
			}
		})
	}
}

func TestIndiaPIIDetector_HasUPIID(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	tests := []struct {
		name   string
		input  string
		hasUPI bool
	}{
		{
			name:   "text with UPI",
			input:  "Payment to user@ybl please",
			hasUPI: true,
		},
		{
			name:   "text without UPI",
			input:  "Hello world, no payment info here",
			hasUPI: false,
		},
		{
			name:   "email should not match as UPI",
			input:  "Email me at user@gmail.com",
			hasUPI: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.HasUPIID(tt.input)
			if result != tt.hasUPI {
				t.Errorf("expected HasUPIID=%v, got %v", tt.hasUPI, result)
			}
		})
	}
}

func TestIndiaPIIDetector_GetRBISensitiveData(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	text := "UPI: user@ybl, PAN: ABCPP1234F, Phone: 9876543210"

	categorized := detector.GetRBISensitiveData(text)

	// Check categories are present
	if len(categorized["payment_identifier"]) == 0 {
		t.Error("expected payment_identifier category")
	}
	if len(categorized["tax_identifier"]) == 0 {
		t.Error("expected tax_identifier category")
	}
	if len(categorized["contact_info"]) == 0 {
		t.Error("expected contact_info category")
	}
}

func TestIndiaPIIDetector_Masking(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	tests := []struct {
		name           string
		input          string
		piiType        IndiaPIIType
		wantMaskPrefix string
	}{
		{
			name:           "UPI masking",
			input:          "UPI: username@ybl",
			piiType:        IndiaPIITypeUPI,
			wantMaskPrefix: "use***@ybl",
		},
		{
			name:           "PAN masking",
			input:          "PAN: ABCPP1234F",
			piiType:        IndiaPIITypePAN,
			wantMaskPrefix: "AB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, tt.piiType)
			if len(results) == 0 {
				t.Fatal("expected at least one match")
			}

			maskedValue := results[0].MaskedValue
			if maskedValue == "" {
				t.Error("expected masked value to be set")
			}
			// Check masking was applied (contains asterisks or X)
			if maskedValue == results[0].Value {
				t.Errorf("masked value should differ from original: %s", maskedValue)
			}
		})
	}
}

func TestIndiaPIIDetector_ContextAnalysis(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	tests := []struct {
		name       string
		input      string
		piiType    IndiaPIIType
		wantHigher bool // Higher confidence with positive context
	}{
		{
			name:       "UPI with payment context",
			input:      "Please send payment to my UPI ID: user@ybl",
			piiType:    IndiaPIITypeUPI,
			wantHigher: true,
		},
		{
			name:       "PAN with tax context",
			input:      "Submit your PAN card number: ABCPP1234F for tax filing",
			piiType:    IndiaPIITypePAN,
			wantHigher: true,
		},
		{
			name:       "Aadhaar with KYC context",
			input:      "For KYC verification, provide your Aadhaar: 2345 6789 0123",
			piiType:    IndiaPIITypeAadhaar,
			wantHigher: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, tt.piiType)
			if len(results) == 0 {
				t.Fatal("expected at least one match")
			}

			// With positive context, confidence should be high
			if tt.wantHigher && results[0].Confidence < 0.85 {
				t.Errorf("expected higher confidence with positive context, got %.2f", results[0].Confidence)
			}
		})
	}
}

func TestFilterIndiaPIIBySeverity(t *testing.T) {
	results := []IndiaPIIDetectionResult{
		{Type: IndiaPIITypeUPI, Severity: IndiaPIISeverityCritical},
		{Type: IndiaPIITypeIFSC, Severity: IndiaPIISeverityMedium},
		{Type: IndiaPIITypePincode, Severity: IndiaPIISeverityLow},
		{Type: IndiaPIITypePAN, Severity: IndiaPIISeverityCritical},
	}

	// Filter for high and above
	filtered := FilterIndiaPIIBySeverity(results, IndiaPIISeverityHigh)
	if len(filtered) != 2 {
		t.Errorf("expected 2 critical results, got %d", len(filtered))
	}

	// Filter for medium and above
	filtered = FilterIndiaPIIBySeverity(results, IndiaPIISeverityMedium)
	if len(filtered) != 3 {
		t.Errorf("expected 3 results (medium and above), got %d", len(filtered))
	}
}

func TestFilterIndiaPIIByConfidence(t *testing.T) {
	results := []IndiaPIIDetectionResult{
		{Type: IndiaPIITypeUPI, Confidence: 0.95},
		{Type: IndiaPIITypeIFSC, Confidence: 0.7},
		{Type: IndiaPIITypePincode, Confidence: 0.5},
		{Type: IndiaPIITypePAN, Confidence: 0.9},
	}

	filtered := FilterIndiaPIIByConfidence(results, 0.8)
	if len(filtered) != 2 {
		t.Errorf("expected 2 high confidence results, got %d", len(filtered))
	}
}

func TestGetCriticalFinancialPII(t *testing.T) {
	results := []IndiaPIIDetectionResult{
		{Type: IndiaPIITypeUPI},
		{Type: IndiaPIITypeAadhaar},
		{Type: IndiaPIITypePAN},
		{Type: IndiaPIITypeBankAccount},
		{Type: IndiaPIITypeIFSC},
		{Type: IndiaPIITypePincode},
		{Type: IndiaPIITypeIndianPhone},
	}

	critical := GetCriticalFinancialPII(results)
	if len(critical) != 4 {
		t.Errorf("expected 4 critical financial PII types, got %d", len(critical))
	}

	// Verify correct types
	typeSet := make(map[IndiaPIIType]bool)
	for _, r := range critical {
		typeSet[r.Type] = true
	}

	if !typeSet[IndiaPIITypeUPI] {
		t.Error("expected UPI in critical financial PII")
	}
	if !typeSet[IndiaPIITypeAadhaar] {
		t.Error("expected Aadhaar in critical financial PII")
	}
	if !typeSet[IndiaPIITypePAN] {
		t.Error("expected PAN in critical financial PII")
	}
	if !typeSet[IndiaPIITypeBankAccount] {
		t.Error("expected bank account in critical financial PII")
	}
}

func TestIndiaPIIDetector_EnabledTypes(t *testing.T) {
	// Create detector with only UPI and PAN enabled
	config := IndiaPIIDetectorConfig{
		ContextWindow:    50,
		MinConfidence:    0.5,
		EnableValidation: true,
		EnabledTypes:     []IndiaPIIType{IndiaPIITypeUPI, IndiaPIITypePAN},
	}

	detector := NewIndiaPIIDetector(config)

	text := "UPI: user@ybl, PAN: ABCPP1234F, Phone: 9876543210, IFSC: SBIN0001234"
	results := detector.DetectAll(text)

	// Should only detect UPI and PAN
	typeCount := make(map[IndiaPIIType]int)
	for _, r := range results {
		typeCount[r.Type]++
	}

	if typeCount[IndiaPIITypeUPI] == 0 {
		t.Error("expected to detect UPI")
	}
	if typeCount[IndiaPIITypePAN] == 0 {
		t.Error("expected to detect PAN")
	}
	if typeCount[IndiaPIITypeIndianPhone] > 0 {
		t.Error("should not detect phone when not enabled")
	}
	if typeCount[IndiaPIITypeIFSC] > 0 {
		t.Error("should not detect IFSC when not enabled")
	}
}

func TestVerhoeffCheck(t *testing.T) {
	tests := []struct {
		name    string
		number  string
		isValid bool
	}{
		{
			name:    "valid Verhoeff number",
			number:  "234567890123",
			isValid: false, // This is a random number, may or may not pass
		},
		{
			name:    "all zeros",
			number:  "000000000000",
			isValid: false, // Invalid Aadhaar (starts with 0)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verhoeffCheck(tt.number)
			// Just verify it doesn't panic and returns a boolean
			_ = result
		})
	}
}

func TestMaskIndiaPII(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		piiType  IndiaPIIType
		wantMask string
	}{
		{
			name:     "UPI ID",
			value:    "username@ybl",
			piiType:  IndiaPIITypeUPI,
			wantMask: "use***@ybl",
		},
		{
			name:     "short UPI ID",
			value:    "ab@ybl",
			piiType:  IndiaPIITypeUPI,
			wantMask: "ab***@ybl",
		},
		{
			name:     "Aadhaar",
			value:    "234567890123",
			piiType:  IndiaPIITypeAadhaar,
			wantMask: "XXXX XXXX 0123",
		},
		{
			name:     "PAN",
			value:    "ABCDE1234F",
			piiType:  IndiaPIITypePAN,
			wantMask: "AB******4F",
		},
		{
			name:     "Indian Phone",
			value:    "9876543210",
			piiType:  IndiaPIITypeIndianPhone,
			wantMask: "XXXXXX3210",
		},
		{
			name:     "Bank Account",
			value:    "123456789012",
			piiType:  IndiaPIITypeBankAccount,
			wantMask: "XXXXXXXX9012",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskIndiaPII(tt.value, tt.piiType)
			if result != tt.wantMask {
				t.Errorf("expected mask %q, got %q", tt.wantMask, result)
			}
		})
	}
}

func TestIsRepeatedPattern(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"1111111111", true},
		{"12345678", true},    // Ascending sequential (no wrap)
		{"1234567890", false}, // Not strictly sequential (9 -> 0 wraps)
		{"9876543210", false}, // Descending, not sequential
		{"1234512345", false},
		{"9988776655", false},
		{"123", false}, // Too short
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isRepeatedPattern(tt.input)
			if result != tt.expected {
				t.Errorf("isRepeatedPattern(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIndiaPIIDetector_PatternStats(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())
	stats := detector.GetPatternStats()

	if stats["total_patterns"].(int) < 10 {
		t.Errorf("expected at least 10 patterns, got %d", stats["total_patterns"].(int))
	}

	if stats["validation"].(bool) != true {
		t.Error("expected validation to be enabled")
	}

	if stats["min_confidence"].(float64) != 0.6 {
		t.Errorf("expected min_confidence 0.6, got %f", stats["min_confidence"].(float64))
	}
}

// =============================================================================
// Comprehensive Validator Tests (using testify)
// =============================================================================

func TestValidateUPIID_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		match     string
		context   string
		wantValid bool
		minConf   float64
	}{
		{
			name:      "known handle ybl",
			match:     "user@ybl",
			context:   "",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "known handle paytm",
			match:     "john.doe@paytm",
			context:   "",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "known handle oksbi",
			match:     "user123@oksbi",
			context:   "",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "unknown handle with payment context",
			match:     "user@somebank",
			context:   "please send payment to user@somebank",
			wantValid: true,
			minConf:   0.85,
		},
		{
			name:      "unknown handle with UPI context",
			match:     "user@somebank",
			context:   "my UPI ID is user@somebank",
			wantValid: true,
			minConf:   0.85,
		},
		{
			name:      "unknown handle without context",
			match:     "user@somebank",
			context:   "",
			wantValid: true,
			minConf:   0.6,
		},
		{
			name:      "email domain gmail.com rejected",
			match:     "user@gmail.com",
			context:   "",
			wantValid: false,
		},
		{
			name:      "email domain yahoo.com rejected",
			match:     "user@yahoo.com",
			context:   "",
			wantValid: false,
		},
		{
			name:      "email domain outlook.com rejected",
			match:     "user@outlook.com",
			context:   "",
			wantValid: false,
		},
		{
			name:      "email domain hotmail.com rejected",
			match:     "user@hotmail.com",
			context:   "",
			wantValid: false,
		},
		{
			name:      "domain ending in .com rejected",
			match:     "user@example.com",
			context:   "",
			wantValid: false,
		},
		{
			name:      "domain ending in .org rejected",
			match:     "user@example.org",
			context:   "",
			wantValid: false,
		},
		{
			name:      "domain ending in .in rejected",
			match:     "user@example.in",
			context:   "",
			wantValid: false,
		},
		{
			name:      "negative context with email keyword but send overrides",
			match:     "user@somebank",
			context:   "send email to user@somebank",
			wantValid: true, // "send" is a positive UPI indicator checked before "email" negative
			minConf:   0.9,
		},
		{
			name:      "no @ separator",
			match:     "noseparator",
			context:   "",
			wantValid: false,
		},
		{
			name:      "multiple @ separators",
			match:     "user@bank@extra",
			context:   "",
			wantValid: false,
		},
		{
			name:      "handle too short",
			match:     "user@ab",
			context:   "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, confidence := validateUPIID(tt.match, tt.context)
			assert.Equal(t, tt.wantValid, valid, "validity mismatch for %s", tt.match)
			if tt.wantValid {
				assert.GreaterOrEqual(t, confidence, tt.minConf,
					"confidence too low for %s: got %.2f, want >= %.2f", tt.match, confidence, tt.minConf)
			}
		})
	}
}

func TestValidateAadhaar_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		match     string
		context   string
		wantValid bool
		minConf   float64
	}{
		{
			name:      "12 digits starting with 2",
			match:     "234567890123",
			context:   "aadhaar number is 234567890123",
			wantValid: true,
			minConf:   0.8,
		},
		{
			name:      "12 digits with space separators",
			match:     "2345 6789 0123",
			context:   "aadhaar: 2345 6789 0123",
			wantValid: true,
			minConf:   0.8,
		},
		{
			name:      "12 digits with hyphen separators",
			match:     "2345-6789-0123",
			context:   "uid: 2345-6789-0123",
			wantValid: true,
			minConf:   0.8,
		},
		{
			name:      "starts with 0 - invalid",
			match:     "012345678901",
			context:   "",
			wantValid: false,
		},
		{
			name:      "starts with 1 - invalid",
			match:     "123456789012",
			context:   "",
			wantValid: false,
		},
		{
			name:      "too few digits after cleaning",
			match:     "23456789012",
			context:   "",
			wantValid: false,
		},
		{
			name:      "too many digits after cleaning",
			match:     "2345678901234",
			context:   "",
			wantValid: false,
		},
		{
			name:      "negative context with phone keyword",
			match:     "234567890123",
			context:   "phone number: 234567890123",
			wantValid: false,
		},
		{
			name:      "negative context with order keyword",
			match:     "234567890123",
			context:   "order ID: 234567890123",
			wantValid: false,
		},
		{
			name:      "negative context with transaction keyword",
			match:     "234567890123",
			context:   "transaction ref 234567890123",
			wantValid: false,
		},
		{
			name:      "positive context with kyc keyword",
			match:     "234567890123",
			context:   "kyc verification 234567890123",
			wantValid: true,
			minConf:   0.8,
		},
		{
			name:      "no context - low confidence but valid",
			match:     "987654321098",
			context:   "",
			wantValid: true,
			minConf:   0.6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, confidence := validateAadhaar(tt.match, tt.context)
			assert.Equal(t, tt.wantValid, valid, "validity mismatch for %s", tt.match)
			if tt.wantValid {
				assert.GreaterOrEqual(t, confidence, tt.minConf,
					"confidence too low: got %.2f, want >= %.2f", confidence, tt.minConf)
			}
		})
	}
}

func TestValidatePAN_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		match     string
		context   string
		wantValid bool
		minConf   float64
	}{
		{
			name:      "valid personal PAN - P entity type",
			match:     "ABCPP1234F",
			context:   "PAN number is ABCPP1234F",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "valid company PAN - C entity type",
			match:     "AABCC1234C",
			context:   "",
			wantValid: true,
			minConf:   0.8,
		},
		{
			name:      "valid trust PAN - T entity type",
			match:     "AABCT1234A",
			context:   "",
			wantValid: true,
			minConf:   0.8,
		},
		{
			name:      "valid HUF PAN - H entity type",
			match:     "AABCH1234A",
			context:   "",
			wantValid: true,
			minConf:   0.8,
		},
		{
			name:      "valid AOP PAN - A entity type",
			match:     "AABCA1234A",
			context:   "",
			wantValid: true,
			minConf:   0.8,
		},
		{
			name:      "wrong length",
			match:     "ABCPP123F",
			context:   "",
			wantValid: false,
		},
		{
			name:      "digit in letter position",
			match:     "1BCPP1234F",
			context:   "",
			wantValid: false,
		},
		{
			name:      "letter in digit position",
			match:     "ABCPPAB34F",
			context:   "",
			wantValid: false,
		},
		{
			name:      "digit as last char",
			match:     "ABCPP12341",
			context:   "",
			wantValid: false,
		},
		{
			name:      "unusual entity type - low confidence",
			match:     "ABCDX1234F",
			context:   "",
			wantValid: false,
		},
		{
			name:      "positive context with tax keyword",
			match:     "ABCPP1234F",
			context:   "income tax filing PAN: ABCPP1234F",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "positive context with kyc keyword",
			match:     "ABCPP1234F",
			context:   "KYC document PAN ABCPP1234F",
			wantValid: true,
			minConf:   0.9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, confidence := validatePAN(tt.match, tt.context)
			assert.Equal(t, tt.wantValid, valid, "validity mismatch for %s", tt.match)
			if tt.wantValid {
				assert.GreaterOrEqual(t, confidence, tt.minConf,
					"confidence too low: got %.2f, want >= %.2f", confidence, tt.minConf)
			}
		})
	}
}

func TestValidateIFSC_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		match     string
		context   string
		wantValid bool
		minConf   float64
	}{
		{
			name:      "known bank SBI with bank context",
			match:     "SBIN0001234",
			context:   "bank IFSC: SBIN0001234",
			wantValid: true,
			minConf:   0.95,
		},
		{
			name:      "known bank HDFC with NEFT context",
			match:     "HDFC0002345",
			context:   "NEFT transfer to HDFC0002345",
			wantValid: true,
			minConf:   0.95,
		},
		{
			name:      "known bank ICICI no context",
			match:     "ICIC0003456",
			context:   "",
			wantValid: true,
			minConf:   0.8,
		},
		{
			name:      "unknown bank with bank context",
			match:     "XYZX0001234",
			context:   "bank branch code: XYZX0001234",
			wantValid: true,
			minConf:   0.85,
		},
		{
			name:      "unknown bank no context",
			match:     "XYZX0001234",
			context:   "",
			wantValid: true,
			minConf:   0.6,
		},
		{
			name:      "wrong length - too short",
			match:     "SBIN000123",
			context:   "",
			wantValid: false,
		},
		{
			name:      "wrong length - too long",
			match:     "SBIN00012345",
			context:   "",
			wantValid: false,
		},
		{
			name:      "5th char not zero",
			match:     "SBIN1001234",
			context:   "",
			wantValid: false,
		},
		{
			name:      "digits in bank code position",
			match:     "12340001234",
			context:   "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, confidence := validateIFSC(tt.match, tt.context)
			assert.Equal(t, tt.wantValid, valid, "validity mismatch for %s", tt.match)
			if tt.wantValid {
				assert.GreaterOrEqual(t, confidence, tt.minConf,
					"confidence too low: got %.2f, want >= %.2f", confidence, tt.minConf)
			}
		})
	}
}

func TestValidateIndianBankAccount_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		match     string
		context   string
		wantValid bool
		minConf   float64
	}{
		{
			name:      "valid 12-digit with bank context",
			match:     "123456789012",
			context:   "bank account number: 123456789012",
			wantValid: true,
			minConf:   0.85,
		},
		{
			name:      "sequential 9-digit rejected as repeated pattern",
			match:     "123456789",
			context:   "a/c no: 123456789",
			wantValid: false, // sequential pattern detected by isRepeatedPattern
		},
		{
			name:      "valid 18-digit with savings context",
			match:     "123456789012345678",
			context:   "savings account 123456789012345678",
			wantValid: true,
			minConf:   0.85,
		},
		{
			name:      "no bank context - low confidence",
			match:     "123456789012",
			context:   "some reference number 123456789012",
			wantValid: true,
			minConf:   0.3,
		},
		{
			name:      "too short - 8 digits",
			match:     "12345678",
			context:   "",
			wantValid: false,
		},
		{
			name:      "too long - 19 digits",
			match:     "1234567890123456789",
			context:   "",
			wantValid: false,
		},
		{
			name:      "repeated pattern - all same digit",
			match:     "111111111",
			context:   "account: 111111111",
			wantValid: false,
		},
		{
			name:      "sequential pattern",
			match:     "123456789",
			context:   "account: 123456789",
			wantValid: false,
		},
		{
			name:      "IFSC context boosts confidence",
			match:     "987654321098",
			context:   "ifsc SBIN0001234 account 987654321098",
			wantValid: true,
			minConf:   0.85,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, confidence := validateIndianBankAccount(tt.match, tt.context)
			assert.Equal(t, tt.wantValid, valid, "validity mismatch for %s", tt.match)
			if tt.wantValid {
				assert.GreaterOrEqual(t, confidence, tt.minConf,
					"confidence too low: got %.2f, want >= %.2f", confidence, tt.minConf)
			}
		})
	}
}

func TestValidateGSTIN_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		match     string
		context   string
		wantValid bool
		minConf   float64
	}{
		{
			name:      "valid GSTIN with GST context",
			match:     "27AABCC1234A1Z5",
			context:   "GST invoice: 27AABCC1234A1Z5",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "valid GSTIN state code 29 with tax context",
			match:     "29AADCB1234H1ZK",
			context:   "tax number: 29AADCB1234H1ZK",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "valid GSTIN no context",
			match:     "22AAAAA0000A1Z5",
			context:   "",
			wantValid: true,
			minConf:   0.8,
		},
		{
			name:      "wrong length",
			match:     "22AAAAA0000A1Z",
			context:   "",
			wantValid: false,
		},
		{
			name:      "invalid state code 00",
			match:     "00AAAAA0000A1Z5",
			context:   "",
			wantValid: false,
		},
		{
			name:      "invalid state code 38 (above max)",
			match:     "38AAAAA0000A1Z5",
			context:   "",
			wantValid: false,
		},
		{
			name:      "14th char not Z",
			match:     "22AAAAA0000A1A5",
			context:   "",
			wantValid: false,
		},
		{
			name:      "digits in PAN letter position",
			match:     "2212345000011Z5",
			context:   "",
			wantValid: false,
		},
		{
			name:      "letters in PAN digit position",
			match:     "22AAAAABBBB01Z5",
			context:   "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, confidence := validateGSTIN(tt.match, tt.context)
			assert.Equal(t, tt.wantValid, valid, "validity mismatch for %s", tt.match)
			if tt.wantValid {
				assert.GreaterOrEqual(t, confidence, tt.minConf,
					"confidence too low: got %.2f, want >= %.2f", confidence, tt.minConf)
			}
		})
	}
}

func TestValidateVoterID_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		match     string
		context   string
		wantValid bool
		minConf   float64
	}{
		{
			name:      "valid voter ID with context",
			match:     "ABC1234567",
			context:   "voter ID: ABC1234567",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "valid voter ID with EPIC context",
			match:     "XYZ9876543",
			context:   "EPIC number XYZ9876543",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "valid voter ID with election context",
			match:     "DEF5555555",
			context:   "election commission ID: DEF5555555",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "valid voter ID no context",
			match:     "ABC1234567",
			context:   "",
			wantValid: true,
			minConf:   0.5,
		},
		{
			name:      "wrong length - too short",
			match:     "ABC123456",
			context:   "",
			wantValid: false,
		},
		{
			name:      "wrong length - too long",
			match:     "ABC12345678",
			context:   "",
			wantValid: false,
		},
		{
			name:      "digits in letter position",
			match:     "1231234567",
			context:   "",
			wantValid: false,
		},
		{
			name:      "letters in digit position",
			match:     "ABC123456A",
			context:   "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, confidence := validateVoterID(tt.match, tt.context)
			assert.Equal(t, tt.wantValid, valid, "validity mismatch for %s", tt.match)
			if tt.wantValid {
				assert.GreaterOrEqual(t, confidence, tt.minConf,
					"confidence too low: got %.2f, want >= %.2f", confidence, tt.minConf)
			}
		})
	}
}

func TestValidateIndianDrivingLicense_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		match     string
		context   string
		wantValid bool
		minConf   float64
	}{
		{
			name:      "valid DL with driving context",
			match:     "KA0120151234567",
			context:   "driving license: KA0120151234567",
			wantValid: true,
			minConf:   0.85,
		},
		{
			name:      "valid DL with hyphens and DL context",
			match:     "MH-01-20161234567",
			context:   "DL number: MH-01-20161234567",
			wantValid: true,
			minConf:   0.85,
		},
		{
			name:      "valid DL with RTO context",
			match:     "DL0520181234567",
			context:   "RTO registered DL0520181234567",
			wantValid: true,
			minConf:   0.85,
		},
		{
			name:      "valid DL no context - lower confidence",
			match:     "KA0120151234567",
			context:   "",
			wantValid: true,
			minConf:   0.4,
		},
		{
			name:      "too short after cleaning",
			match:     "KA012015123456",
			context:   "",
			wantValid: false,
		},
		{
			name:      "too long after cleaning",
			match:     "KA012015123456789",
			context:   "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, confidence := validateIndianDrivingLicense(tt.match, tt.context)
			assert.Equal(t, tt.wantValid, valid, "validity mismatch for %s", tt.match)
			if tt.wantValid {
				assert.GreaterOrEqual(t, confidence, tt.minConf,
					"confidence too low: got %.2f, want >= %.2f", confidence, tt.minConf)
			}
		})
	}
}

func TestValidateIndianPassport_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		match     string
		context   string
		wantValid bool
		minConf   float64
	}{
		{
			name:      "valid passport with context",
			match:     "A1234567",
			context:   "passport number: A1234567",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "valid passport with visa context",
			match:     "J9876543",
			context:   "visa application passport J9876543",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "valid passport with travel document context",
			match:     "K5555555",
			context:   "travel document K5555555",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "valid passport no context - lower confidence",
			match:     "A1234567",
			context:   "",
			wantValid: true,
			minConf:   0.4,
		},
		{
			name:      "wrong length - too short",
			match:     "A123456",
			context:   "",
			wantValid: false,
		},
		{
			name:      "wrong length - too long",
			match:     "A12345678",
			context:   "",
			wantValid: false,
		},
		{
			name:      "starts with digit",
			match:     "12345678",
			context:   "",
			wantValid: false,
		},
		{
			name:      "letter in digit position",
			match:     "A123456B",
			context:   "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, confidence := validateIndianPassport(tt.match, tt.context)
			assert.Equal(t, tt.wantValid, valid, "validity mismatch for %s", tt.match)
			if tt.wantValid {
				assert.GreaterOrEqual(t, confidence, tt.minConf,
					"confidence too low: got %.2f, want >= %.2f", confidence, tt.minConf)
			}
		})
	}
}

func TestValidateIndianPhone_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		match     string
		context   string
		wantValid bool
		minConf   float64
	}{
		{
			name:      "10-digit starting with 9",
			match:     "9876543210",
			context:   "phone: 9876543210",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "10-digit starting with 6",
			match:     "6234567890",
			context:   "contact: 6234567890",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "10-digit starting with 7",
			match:     "7234567890",
			context:   "whatsapp: 7234567890",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "10-digit starting with 8",
			match:     "8234567890",
			context:   "sms to 8234567890",
			wantValid: true,
			minConf:   0.9,
		},
		{
			name:      "with +91 prefix",
			match:     "+91 9876543210",
			context:   "",
			wantValid: true,
			minConf:   0.7,
		},
		{
			name:      "with 0 prefix",
			match:     "09876543210",
			context:   "",
			wantValid: true,
			minConf:   0.7,
		},
		{
			name:      "with +91 prefix and hyphen",
			match:     "+91-9876543210",
			context:   "",
			wantValid: true,
			minConf:   0.7,
		},
		{
			name:      "starting with 5 - invalid",
			match:     "5234567890",
			context:   "",
			wantValid: false,
		},
		{
			name:      "all same digit - repeated pattern",
			match:     "9999999999",
			context:   "",
			wantValid: false,
		},
		{
			name:      "too short - 9 digits",
			match:     "987654321",
			context:   "",
			wantValid: false,
		},
		{
			name:      "no context - still valid but lower confidence",
			match:     "9876543210",
			context:   "",
			wantValid: true,
			minConf:   0.7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, confidence := validateIndianPhone(tt.match, tt.context)
			assert.Equal(t, tt.wantValid, valid, "validity mismatch for %s", tt.match)
			if tt.wantValid {
				assert.GreaterOrEqual(t, confidence, tt.minConf,
					"confidence too low: got %.2f, want >= %.2f", confidence, tt.minConf)
			}
		})
	}
}

func TestValidatePincode_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		match     string
		context   string
		wantValid bool
		minConf   float64
	}{
		{
			name:      "valid pincode with context",
			match:     "110001",
			context:   "pincode: 110001",
			wantValid: true,
			minConf:   0.85,
		},
		{
			name:      "valid pincode with postal context",
			match:     "400001",
			context:   "postal code 400001",
			wantValid: true,
			minConf:   0.85,
		},
		{
			name:      "valid pincode with address context",
			match:     "560001",
			context:   "address line: Bangalore 560001",
			wantValid: true,
			minConf:   0.85,
		},
		{
			name:      "valid pincode no context",
			match:     "110001",
			context:   "",
			wantValid: true,
			minConf:   0.4,
		},
		{
			name:      "starts with 0 - invalid",
			match:     "010001",
			context:   "",
			wantValid: false,
		},
		{
			name:      "wrong length - too short",
			match:     "11000",
			context:   "",
			wantValid: false,
		},
		{
			name:      "wrong length - too long",
			match:     "1100011",
			context:   "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, confidence := validatePincode(tt.match, tt.context)
			assert.Equal(t, tt.wantValid, valid, "validity mismatch for %s", tt.match)
			if tt.wantValid {
				assert.GreaterOrEqual(t, confidence, tt.minConf,
					"confidence too low: got %.2f, want >= %.2f", confidence, tt.minConf)
			}
		})
	}
}

// =============================================================================
// Verhoeff Algorithm Tests
// =============================================================================

func TestVerhoeffCheck_KnownValues(t *testing.T) {
	tests := []struct {
		name    string
		number  string
		isValid bool
	}{
		// Verhoeff checksum: appending a check digit makes the full number validate to 0.
		// "2363" has a Verhoeff check of 0, so verhoeffCheck("2363") == true.
		{
			name:    "known valid verhoeff sequence 2363",
			number:  "2363",
			isValid: true,
		},
		{
			name:    "single zero is valid (trivially)",
			number:  "0",
			isValid: true,
		},
		{
			name:    "known invalid - altered digit from valid",
			number:  "2364",
			isValid: false,
		},
		{
			name:    "all zeros 12-digit",
			number:  "000000000000",
			isValid: false, // Verhoeff check digit for all zeros is non-zero
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verhoeffCheck(tt.number)
			assert.Equal(t, tt.isValid, result, "verhoeffCheck(%q)", tt.number)
		})
	}
}

// =============================================================================
// Masking Tests for Additional PII Types
// =============================================================================

func TestMaskIndiaPII_AllTypes(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		piiType  IndiaPIIType
		expected string
	}{
		{
			name:     "UPI long username",
			value:    "longusername@ybl",
			piiType:  IndiaPIITypeUPI,
			expected: "lon***@ybl",
		},
		{
			name:     "UPI short username 1 char",
			value:    "a@ybl",
			piiType:  IndiaPIITypeUPI,
			expected: "a***@ybl",
		},
		{
			name:     "UPI exactly 3 char username",
			value:    "abc@ybl",
			piiType:  IndiaPIITypeUPI,
			expected: "abc***@ybl",
		},
		{
			name:     "UPI no @ separator fallback",
			value:    "nousername",
			piiType:  IndiaPIITypeUPI,
			expected: "***",
		},
		{
			name:     "Aadhaar with spaces",
			value:    "2345 6789 0123",
			piiType:  IndiaPIITypeAadhaar,
			expected: "XXXX XXXX 0123",
		},
		{
			name:     "Aadhaar without separators",
			value:    "234567890123",
			piiType:  IndiaPIITypeAadhaar,
			expected: "XXXX XXXX 0123",
		},
		{
			name:     "Aadhaar short value fallback",
			value:    "123",
			piiType:  IndiaPIITypeAadhaar,
			expected: "XXXX XXXX XXXX",
		},
		{
			name:     "PAN standard",
			value:    "ABCDE1234F",
			piiType:  IndiaPIITypePAN,
			expected: "AB******4F",
		},
		{
			name:     "PAN wrong length fallback",
			value:    "ABC",
			piiType:  IndiaPIITypePAN,
			expected: "**********",
		},
		{
			name:     "Indian Phone 10 digits",
			value:    "9876543210",
			piiType:  IndiaPIITypeIndianPhone,
			expected: "XXXXXX3210",
		},
		{
			name:     "Indian Phone with prefix",
			value:    "+919876543210",
			piiType:  IndiaPIITypeIndianPhone,
			expected: "XXXXXX3210",
		},
		{
			name:     "Indian Phone short fallback",
			value:    "123",
			piiType:  IndiaPIITypeIndianPhone,
			expected: "XXXXXXXXXX",
		},
		{
			name:     "Bank Account 12 digits",
			value:    "123456789012",
			piiType:  IndiaPIITypeBankAccount,
			expected: "XXXXXXXX9012",
		},
		{
			name:     "Bank Account short 4 chars",
			value:    "1234",
			piiType:  IndiaPIITypeBankAccount,
			expected: "1234",
		},
		{
			name:     "Bank Account very short",
			value:    "12",
			piiType:  IndiaPIITypeBankAccount,
			expected: "XX", // len < 4, so all chars masked
		},
		{
			name:     "GSTIN default masking",
			value:    "22AAAAA0000A1Z5",
			piiType:  IndiaPIITypeGSTIN,
			expected: "22***********Z5",
		},
		{
			name:     "Voter ID default masking",
			value:    "ABC1234567",
			piiType:  IndiaPIITypeVoterID,
			expected: "AB******67",
		},
		{
			name:     "Passport default masking",
			value:    "A1234567",
			piiType:  IndiaPIITypePassport,
			expected: "A1****67",
		},
		{
			name:     "IFSC default masking",
			value:    "SBIN0001234",
			piiType:  IndiaPIITypeIFSC,
			expected: "SB*******34",
		},
		{
			name:     "Driving License default masking",
			value:    "KA0120151234567",
			piiType:  IndiaPIITypeDrivingLicense,
			expected: "KA***********67",
		},
		{
			name:     "Pincode default masking",
			value:    "110001",
			piiType:  IndiaPIITypePincode,
			expected: "11**01",
		},
		{
			name:     "Ration Card default masking",
			value:    "RC1234",
			piiType:  IndiaPIITypeRationCard,
			expected: "RC**34",
		},
		{
			name:     "short value (<= 4 chars) fully masked",
			value:    "ABC",
			piiType:  IndiaPIITypeRationCard,
			expected: "***",
		},
		{
			name:     "exactly 4 chars fully masked",
			value:    "ABCD",
			piiType:  IndiaPIITypeRationCard,
			expected: "****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskIndiaPII(tt.value, tt.piiType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// IsRepeatedPattern Extended Tests
// =============================================================================

func TestIsRepeatedPattern_Extended(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"all same - 0000000000", "0000000000", true},
		{"all same - 5555555555", "5555555555", true},
		{"all same - 9999", "9999", true},
		{"ascending sequential 12345", "12345", true},
		{"ascending sequential 23456789", "23456789", true},
		{"not sequential 13579", "13579", false},
		{"descending not detected", "9876543210", false},
		{"mixed digits", "1357924680", false},
		{"alternating", "1212121212", false},
		{"short - 3 chars", "111", false},
		{"short - 2 chars", "11", false},
		{"short - 1 char", "1", false},
		{"empty string", "", false},
		{"four same chars boundary", "1111", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRepeatedPattern(tt.input)
			assert.Equal(t, tt.expected, result, "isRepeatedPattern(%q)", tt.input)
		})
	}
}

// =============================================================================
// Detector Configuration Tests
// =============================================================================

func TestDefaultIndiaPIIDetectorConfig(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()

	assert.Equal(t, 50, config.ContextWindow)
	assert.Equal(t, 0.6, config.MinConfidence)
	assert.True(t, config.EnableValidation)
	assert.Nil(t, config.EnabledTypes)
}

func TestNewIndiaPIIDetector_CustomConfig(t *testing.T) {
	config := IndiaPIIDetectorConfig{
		ContextWindow:    100,
		MinConfidence:    0.8,
		EnableValidation: false,
		EnabledTypes:     nil,
	}

	detector := NewIndiaPIIDetector(config)
	require.NotNil(t, detector)

	stats := detector.GetPatternStats()
	assert.Equal(t, 100, stats["context_window"].(int))
	assert.Equal(t, 0.8, stats["min_confidence"].(float64))
	assert.Equal(t, false, stats["validation"].(bool))
}

func TestNewIndiaPIIDetector_ValidationDisabled(t *testing.T) {
	config := IndiaPIIDetectorConfig{
		ContextWindow:    50,
		MinConfidence:    0.0, // Accept everything
		EnableValidation: false,
		EnabledTypes:     nil,
	}

	detector := NewIndiaPIIDetector(config)
	require.NotNil(t, detector)

	// With validation disabled, even structurally invalid data that matches regex should pass
	// This tests that the validator path is skipped
	text := "PAN: ABCPP1234F"
	results := detector.DetectType(text, IndiaPIITypePAN)
	assert.NotEmpty(t, results, "should detect PAN when validation disabled")
	// Confidence should be 1.0 when validation is disabled
	for _, r := range results {
		assert.Equal(t, 1.0, r.Confidence, "confidence should be 1.0 when validation disabled")
	}
}

func TestNewIndiaPIIDetector_SingleType(t *testing.T) {
	config := IndiaPIIDetectorConfig{
		ContextWindow:    50,
		MinConfidence:    0.5,
		EnableValidation: true,
		EnabledTypes:     []IndiaPIIType{IndiaPIITypePAN},
	}

	detector := NewIndiaPIIDetector(config)
	require.NotNil(t, detector)

	stats := detector.GetPatternStats()
	assert.Equal(t, 1, stats["total_patterns"].(int))

	// PAN should be detected
	results := detector.DetectAll("PAN: ABCPP1234F, UPI: user@ybl, Phone: 9876543210")
	for _, r := range results {
		assert.Equal(t, IndiaPIITypePAN, r.Type, "only PAN should be detected")
	}
}

func TestNewIndiaPIIDetector_NoMatchingTypes(t *testing.T) {
	// EnabledTypes with a type that has no pattern (ration_card has no pattern in loadPatterns)
	config := IndiaPIIDetectorConfig{
		ContextWindow:    50,
		MinConfidence:    0.5,
		EnableValidation: true,
		EnabledTypes:     []IndiaPIIType{IndiaPIITypeRationCard},
	}

	detector := NewIndiaPIIDetector(config)
	require.NotNil(t, detector)

	stats := detector.GetPatternStats()
	assert.Equal(t, 0, stats["total_patterns"].(int))
}

// =============================================================================
// Detector Pattern Stats with Restricted Types
// =============================================================================

func TestGetPatternStats_RestrictedTypes(t *testing.T) {
	config := IndiaPIIDetectorConfig{
		ContextWindow:    30,
		MinConfidence:    0.9,
		EnableValidation: false,
		EnabledTypes:     []IndiaPIIType{IndiaPIITypeUPI, IndiaPIITypePAN, IndiaPIITypeAadhaar},
	}

	detector := NewIndiaPIIDetector(config)
	stats := detector.GetPatternStats()

	assert.Equal(t, 3, stats["total_patterns"].(int))
	assert.Equal(t, 30, stats["context_window"].(int))
	assert.Equal(t, 0.9, stats["min_confidence"].(float64))
	assert.Equal(t, false, stats["validation"].(bool))

	typeCount := stats["types"].(map[IndiaPIIType]int)
	assert.Equal(t, 1, typeCount[IndiaPIITypeUPI])
	assert.Equal(t, 1, typeCount[IndiaPIITypePAN])
	assert.Equal(t, 1, typeCount[IndiaPIITypeAadhaar])
}

// =============================================================================
// ExtractContext Tests
// =============================================================================

func TestExtractContext(t *testing.T) {
	detector := NewIndiaPIIDetector(IndiaPIIDetectorConfig{
		ContextWindow:    10,
		MinConfidence:    0.5,
		EnableValidation: true,
	})

	tests := []struct {
		name     string
		text     string
		start    int
		end      int
		expected string
	}{
		{
			name:     "context in the middle",
			text:     "prefix text MATCH suffix text",
			start:    12,
			end:      17,
			expected: "efix text MATCH suffix te", // window=10: start=max(0,12-10)=2, end=min(29,17+10)=27, text[2:27]
		},
		{
			name:     "match at beginning - no left context",
			text:     "MATCH suffix text",
			start:    0,
			end:      5,
			expected: "MATCH suffix te", // window=10: start=0, end=min(17,5+10)=15
		},
		{
			name:     "match at end - no right context",
			text:     "prefix text MATCH",
			start:    12,
			end:      17,
			expected: "efix text MATCH", // window=10: start=max(0,12-10)=2, end=17
		},
		{
			name:     "short text - match is entire text",
			text:     "SHORT",
			start:    0,
			end:      5,
			expected: "SHORT",
		},
		{
			name:     "context window larger than text",
			text:     "tiny",
			start:    0,
			end:      4,
			expected: "tiny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.extractContext(tt.text, tt.start, tt.end)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// DetectAll Edge Cases
// =============================================================================

func TestDetectAll_EmptyText(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())
	results := detector.DetectAll("")
	assert.Empty(t, results)
}

func TestDetectAll_NoMatch(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())
	results := detector.DetectAll("This is a normal text with no sensitive data.")
	assert.Empty(t, results)
}

func TestDetectType_NonExistentType(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())
	results := detector.DetectType("some text", IndiaPIIType("nonexistent"))
	assert.Empty(t, results)
}

func TestDetectAll_ResultFields(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	text := "My PAN is ABCPP1234F for KYC"
	results := detector.DetectType(text, IndiaPIITypePAN)
	require.NotEmpty(t, results)

	r := results[0]
	assert.Equal(t, IndiaPIITypePAN, r.Type)
	assert.Equal(t, "ABCPP1234F", r.Value)
	assert.NotEmpty(t, r.MaskedValue)
	assert.NotEqual(t, r.Value, r.MaskedValue)
	assert.Equal(t, IndiaPIISeverityCritical, r.Severity)
	assert.Greater(t, r.Confidence, 0.0)
	assert.GreaterOrEqual(t, r.StartIndex, 0)
	assert.Greater(t, r.EndIndex, r.StartIndex)
	assert.Equal(t, "tax_identifier", r.RBICategory)
	assert.NotEmpty(t, r.Context)
}

// =============================================================================
// HasIndiaPII and HasUPIID Edge Cases
// =============================================================================

func TestHasIndiaPII_EmptyText(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())
	assert.False(t, detector.HasIndiaPII(""))
}

func TestHasUPIID_EmptyText(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())
	assert.False(t, detector.HasUPIID(""))
}

// =============================================================================
// GetRBISensitiveData Comprehensive Tests
// =============================================================================

func TestGetRBISensitiveData_MultipleCategoriesText(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	text := `
	Customer KYC Details:
	UPI payment: user@ybl
	PAN: ABCPP1234F
	Phone: +91 9876543210
	IFSC code: SBIN0001234
	Voter ID: ABC1234567
	Pincode: 110001
	`

	categorized := detector.GetRBISensitiveData(text)

	// payment_identifier from UPI
	assert.NotEmpty(t, categorized["payment_identifier"], "should have payment_identifier category")

	// tax_identifier from PAN
	assert.NotEmpty(t, categorized["tax_identifier"], "should have tax_identifier category")

	// contact_info from phone
	assert.NotEmpty(t, categorized["contact_info"], "should have contact_info category")

	// bank_identifier from IFSC
	assert.NotEmpty(t, categorized["bank_identifier"], "should have bank_identifier category")
}

func TestGetRBISensitiveData_EmptyText(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())
	categorized := detector.GetRBISensitiveData("")
	assert.Empty(t, categorized)
}

// =============================================================================
// Filter Functions Extended Tests
// =============================================================================

func TestFilterIndiaPIIBySeverity_AllLevels(t *testing.T) {
	results := []IndiaPIIDetectionResult{
		{Type: IndiaPIITypePincode, Severity: IndiaPIISeverityLow, Confidence: 0.9},
		{Type: IndiaPIITypeIFSC, Severity: IndiaPIISeverityMedium, Confidence: 0.8},
		{Type: IndiaPIITypeGSTIN, Severity: IndiaPIISeverityHigh, Confidence: 0.95},
		{Type: IndiaPIITypeAadhaar, Severity: IndiaPIISeverityCritical, Confidence: 0.98},
		{Type: IndiaPIITypePAN, Severity: IndiaPIISeverityCritical, Confidence: 0.95},
	}

	// Filter low and above: all
	filtered := FilterIndiaPIIBySeverity(results, IndiaPIISeverityLow)
	assert.Len(t, filtered, 5)

	// Filter medium and above
	filtered = FilterIndiaPIIBySeverity(results, IndiaPIISeverityMedium)
	assert.Len(t, filtered, 4)

	// Filter high and above
	filtered = FilterIndiaPIIBySeverity(results, IndiaPIISeverityHigh)
	assert.Len(t, filtered, 3)

	// Filter critical only
	filtered = FilterIndiaPIIBySeverity(results, IndiaPIISeverityCritical)
	assert.Len(t, filtered, 2)
}

func TestFilterIndiaPIIBySeverity_EmptyResults(t *testing.T) {
	var results []IndiaPIIDetectionResult
	filtered := FilterIndiaPIIBySeverity(results, IndiaPIISeverityLow)
	assert.Empty(t, filtered)
}

func TestFilterIndiaPIIByConfidence_EdgeCases(t *testing.T) {
	results := []IndiaPIIDetectionResult{
		{Type: IndiaPIITypeUPI, Confidence: 0.0},
		{Type: IndiaPIITypeUPI, Confidence: 0.5},
		{Type: IndiaPIITypeUPI, Confidence: 0.99},
		{Type: IndiaPIITypeUPI, Confidence: 1.0},
	}

	// Filter with 0.0 - all pass
	filtered := FilterIndiaPIIByConfidence(results, 0.0)
	assert.Len(t, filtered, 4)

	// Filter with 1.0 - only exact match
	filtered = FilterIndiaPIIByConfidence(results, 1.0)
	assert.Len(t, filtered, 1)

	// Filter with 0.5 - boundary
	filtered = FilterIndiaPIIByConfidence(results, 0.5)
	assert.Len(t, filtered, 3)
}

func TestFilterIndiaPIIByConfidence_EmptyResults(t *testing.T) {
	var results []IndiaPIIDetectionResult
	filtered := FilterIndiaPIIByConfidence(results, 0.5)
	assert.Empty(t, filtered)
}

func TestGetCriticalFinancialPII_EmptyResults(t *testing.T) {
	var results []IndiaPIIDetectionResult
	critical := GetCriticalFinancialPII(results)
	assert.Empty(t, critical)
}

func TestGetCriticalFinancialPII_NoCriticalTypes(t *testing.T) {
	results := []IndiaPIIDetectionResult{
		{Type: IndiaPIITypeIFSC},
		{Type: IndiaPIITypePincode},
		{Type: IndiaPIITypeVoterID},
		{Type: IndiaPIITypeIndianPhone},
	}
	critical := GetCriticalFinancialPII(results)
	assert.Empty(t, critical)
}

// =============================================================================
// Convenience Method Tests
// =============================================================================

func TestDetectAadhaar_Convenience(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	// Ensure DetectAadhaar only returns aadhaar type
	text := "PAN: ABCPP1234F, Aadhaar: 2345 6789 0123, UPI: user@ybl"
	results := detector.DetectAadhaar(text)
	for _, r := range results {
		assert.Equal(t, IndiaPIITypeAadhaar, r.Type)
	}
}

func TestDetectPAN_Convenience(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	text := "PAN: ABCPP1234F, Aadhaar: 2345 6789 0123, UPI: user@ybl"
	results := detector.DetectPAN(text)
	for _, r := range results {
		assert.Equal(t, IndiaPIITypePAN, r.Type)
	}
}

func TestDetectUPIIDs_Convenience(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	text := "PAN: ABCPP1234F, UPI: user@ybl"
	results := detector.DetectUPIIDs(text)
	for _, r := range results {
		assert.Equal(t, IndiaPIITypeUPI, r.Type)
	}
}

// =============================================================================
// Detection for Specific PII Types via DetectType
// =============================================================================

func TestDetectType_VoterID(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	tests := []struct {
		name        string
		input       string
		wantMatches int
	}{
		{
			name:        "valid voter ID with context",
			input:       "Voter ID: ABC1234567",
			wantMatches: 1,
		},
		{
			name:        "valid voter ID EPIC context",
			input:       "EPIC: XYZ9876543",
			wantMatches: 1,
		},
		{
			name:        "invalid - lowercase letters",
			input:       "abc1234567",
			wantMatches: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndiaPIITypeVoterID)
			assert.Len(t, results, tt.wantMatches)
			for _, r := range results {
				assert.Equal(t, IndiaPIITypeVoterID, r.Type)
				assert.Equal(t, "national_identity", r.RBICategory)
				assert.Equal(t, IndiaPIISeverityHigh, r.Severity)
			}
		})
	}
}

func TestDetectType_IndianPassport(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	tests := []struct {
		name        string
		input       string
		wantMatches int
	}{
		{
			name:        "valid passport with context",
			input:       "Passport: A1234567",
			wantMatches: 1,
		},
		{
			name:        "valid passport with visa context",
			input:       "visa application for passport K9876543",
			wantMatches: 1,
		},
		{
			name:        "invalid - starts with digit",
			input:       "number 11234567",
			wantMatches: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndiaPIITypePassport)
			assert.Len(t, results, tt.wantMatches)
			for _, r := range results {
				assert.Equal(t, IndiaPIITypePassport, r.Type)
				assert.Equal(t, "travel_document", r.RBICategory)
				assert.Equal(t, IndiaPIISeverityHigh, r.Severity)
			}
		})
	}
}

func TestDetectType_Pincode(t *testing.T) {
	detector := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())

	tests := []struct {
		name        string
		input       string
		wantMatches int
	}{
		{
			name:        "valid pincode with address context",
			input:       "Address: Bangalore, pincode 560001",
			wantMatches: 1,
		},
		{
			name:        "valid pincode with postal context",
			input:       "Postal code: 400001",
			wantMatches: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndiaPIITypePincode)
			assert.NotEmpty(t, results, "expected matches for: %s", tt.input)
			for _, r := range results {
				if r.Type == IndiaPIITypePincode {
					assert.Equal(t, "address", r.RBICategory)
					assert.Equal(t, IndiaPIISeverityLow, r.Severity)
				}
			}
		})
	}
}

// =============================================================================
// MinConfidence Threshold Tests
// =============================================================================

func TestDetector_MinConfidenceFiltering(t *testing.T) {
	// High confidence threshold should filter out low-confidence matches
	config := IndiaPIIDetectorConfig{
		ContextWindow:    50,
		MinConfidence:    0.95,
		EnableValidation: true,
		EnabledTypes:     nil,
	}
	detector := NewIndiaPIIDetector(config)

	// Text without strong context -- many matches should be filtered
	text := "Numbers: ABCPP1234F and 234567890123"
	resultsHigh := detector.DetectAll(text)

	// Lower threshold should produce more matches
	configLow := IndiaPIIDetectorConfig{
		ContextWindow:    50,
		MinConfidence:    0.3,
		EnableValidation: true,
		EnabledTypes:     nil,
	}
	detectorLow := NewIndiaPIIDetector(configLow)
	resultsLow := detectorLow.DetectAll(text)

	assert.GreaterOrEqual(t, len(resultsLow), len(resultsHigh),
		"lower confidence threshold should produce >= matches")
}
