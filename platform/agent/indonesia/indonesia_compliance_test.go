// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package indonesia

import (
	"strings"
	"testing"
)

func TestNIKDetection_ValidProvinces(t *testing.T) {
	detector := NewIndonesiaPIIDetector(DefaultIndonesiaPIIDetectorConfig())

	tests := []struct {
		name     string
		input    string
		wantHit  bool
	}{
		// Valid NIK examples per province
		{"Aceh male", "3174042506780001", true},           // province 31 (Jakarta), DD=25
		{"North Sumatra", "1271045612900001", true},        // province 12, DD=56 (female, 56-40=16)
		{"West Java", "3201011501850001", true},             // province 32, DD=15
		{"Central Java", "3301012312950001", true},          // province 33, DD=23
		{"East Java", "3501011201000001", true},              // province 35, DD=12
		{"Banten", "3601014301950001", true},                 // province 36, DD=43 (female, 43-40=3)
		{"DKI Jakarta", "3174042506780001", true},            // province 31
		{"Bali", "5101012506900001", true},                   // province 51
		{"West Kalimantan", "6101011001850001", true},        // province 61
		{"North Sulawesi", "7101012506900001", true},         // province 71
		{"Maluku", "8101012506900001", true},                 // province 81
		{"Papua", "9101012506900001", true},                  // province 91
		{"North Kalimantan", "6501012506900001", true},       // province 65
		{"West Sulawesi", "7601012506900001", true},          // province 76
		{"North Maluku", "8201012506900001", true},           // province 82
		{"Central Papua", "9401012506900001", true},          // province 94
		{"Riau Islands", "2101012506900001", true},           // province 21
		{"DI Yogyakarta", "3401012506900001", true},          // province 34
		{"Bangka Belitung", "1901012506900001", true},        // province 19

		// Female DD offset (+40): DD=41-71
		{"Female DD=41 (day 1)", "3174044106780001", true},
		{"Female DD=55 (day 15)", "3174045506780001", true},
		{"Female DD=71 (day 31)", "3174047106780001", true},

		// Male DD: 01-31
		{"Male DD=01", "3174040106780001", true},
		{"Male DD=15", "3174041506780001", true},
		{"Male DD=31", "3174043106780001", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndonesiaPIITypeNIK)
			got := len(results) > 0
			if got != tt.wantHit {
				t.Errorf("NIK detection for %q: got hit=%v, want hit=%v", tt.input, got, tt.wantHit)
			}
		})
	}
}

func TestNIKDetection_InvalidInputs(t *testing.T) {
	detector := NewIndonesiaPIIDetector(DefaultIndonesiaPIIDetectorConfig())

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		// Invalid province codes
		{"Province 00", "0001012506780001", false},
		{"Province 10", "1001012506780001", false},
		{"Province 20 (does not exist)", "2001012506780001", false}, // province 20 is not valid
		{"Province 22", "2201012506780001", false}, // gap between 21 and 31
		{"Province 23-30", "2501012506780001", false},
		{"Province 37-50", "4001012506780001", false},
		{"Province 54-60", "5501012506780001", false},
		{"Province 66-70", "6801012506780001", false},
		{"Province 77-80", "7801012506780001", false},
		{"Province 83-90", "8501012506780001", false},
		{"Province 95-99", "9601012506780001", false},

		// Invalid DD
		{"DD=00 invalid", "3174040006780001", false},
		{"DD=32 invalid male", "3174043206780001", false},
		{"DD=40 invalid (neither male nor female)", "3174044006780001", false},
		{"DD=72 invalid female", "3174047206780001", false},

		// Invalid month
		{"Month 00", "3174042500780001", false},
		{"Month 13", "3174042513780001", false},

		// Not 16 digits
		{"15 digits", "317404250678000", false},
		{"17 digits", "31740425067800011", false},

		// Part of longer number (credit card, UUID)
		{"Embedded in longer", "x31740425067800019y", false},
		{"Preceded by digit", "131740425067800019", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndonesiaPIITypeNIK)
			got := len(results) > 0
			if got != tt.wantHit {
				t.Errorf("NIK detection for %q: got hit=%v, want hit=%v", tt.input, got, tt.wantHit)
			}
		})
	}
}

func TestNPWPLegacyDetection(t *testing.T) {
	detector := NewIndonesiaPIIDetector(DefaultIndonesiaPIIDetectorConfig())

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{"Valid NPWP", "01.234.567.8-901.234", true},
		{"Valid NPWP 2", "09.876.543.2-109.876", true},
		{"Valid NPWP in context", "NPWP: 01.234.567.8-901.234 is valid", true},
		{"Missing dots", "012345678901234", false},
		{"Wrong format", "01-234-567-8.901.234", false},
		{"Too short", "01.234.567.8-901", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndonesiaPIITypeNPWPLegacy)
			got := len(results) > 0
			if got != tt.wantHit {
				t.Errorf("NPWP legacy for %q: got=%v, want=%v", tt.input, got, tt.wantHit)
			}
		})
	}
}

func TestNPWPNewDetection(t *testing.T) {
	detector := NewIndonesiaPIIDetector(DefaultIndonesiaPIIDetectorConfig())

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{"With keyword NPWP", "NPWP: 1234567890123456", true},
		{"With keyword tax id", "tax id: 9876543210123456", true},
		{"With keyword nomor pokok", "nomor pokok: 1111222233334444", true},
		{"Case insensitive", "npwp: 1234567890123456", true},
		{"Tax number keyword", "tax number: 1234567890123456", true},
		{"No keyword (should not match — false positive risk)", "1234567890123456", false},
		{"Credit card without keyword", "4532015112830366", false},
		{"Too few digits", "NPWP: 123456789012345", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndonesiaPIITypeNPWPNew)
			got := len(results) > 0
			if got != tt.wantHit {
				t.Errorf("NPWP new for %q: got=%v, want=%v", tt.input, got, tt.wantHit)
			}
		})
	}
}

func TestPhoneDetection(t *testing.T) {
	detector := NewIndonesiaPIIDetector(DefaultIndonesiaPIIDetectorConfig())

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{"Telkomsel +62", "+6281234567890", true},
		{"Indosat 0", "081456789012", true},
		{"XL +62", "+6281712345678", true},
		{"Tri", "089512345678", true},
		{"Smartfren", "088112345678", true},
		{"Minimal length", "+628123456789", true},
		{"With country code space", "0812345678", true},
		{"Not starting with 8", "0712345678", false},
		{"Too short", "+6281234", false},
		{"US number", "+12025551234", false},
		{"India number", "+919876543210", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, IndonesiaPIITypePhone)
			got := len(results) > 0
			if got != tt.wantHit {
				t.Errorf("Phone for %q: got=%v, want=%v", tt.input, got, tt.wantHit)
			}
		})
	}
}

func TestBankAccountDetection(t *testing.T) {
	detector := NewIndonesiaPIIDetector(DefaultIndonesiaPIIDetectorConfig())

	tests := []struct {
		name    string
		input   string
		piiType IndonesiaPIIType
		wantHit bool
	}{
		// BCA (10 digits)
		{"BCA with keyword", "BCA: 1234567890", IndonesiaPIITypeBCA, true},
		{"BCA rekening", "rekening: 1234567890", IndonesiaPIITypeBCA, true},
		{"BCA case insensitive", "bca: 0987654321", IndonesiaPIITypeBCA, true},
		{"BCA no keyword", "1234567890", IndonesiaPIITypeBCA, false},

		// Mandiri (13 digits)
		{"Mandiri with keyword", "Mandiri: 1234567890123", IndonesiaPIITypeMandiri, true},
		{"Bank Mandiri", "bank mandiri: 9876543210123", IndonesiaPIITypeMandiri, true},
		{"Mandiri no keyword", "1234567890123", IndonesiaPIITypeMandiri, false},

		// BRI (15 digits)
		{"BRI with keyword", "BRI: 123456789012345", IndonesiaPIITypeBRI, true},
		{"Bank Rakyat Indonesia", "bank rakyat indonesia: 987654321012345", IndonesiaPIITypeBRI, true},
		{"BRI no keyword", "123456789012345", IndonesiaPIITypeBRI, false},

		// BNI (10 digits)
		{"BNI with keyword", "BNI: 1234567890", IndonesiaPIITypeBNI, true},
		{"Bank Negara Indonesia", "bank negara indonesia: 0987654321", IndonesiaPIITypeBNI, true},
		{"BNI no keyword", "1234567890", IndonesiaPIITypeBNI, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectType(tt.input, tt.piiType)
			got := len(results) > 0
			if got != tt.wantHit {
				t.Errorf("%s for %q: got=%v, want=%v", tt.piiType, tt.input, got, tt.wantHit)
			}
		})
	}
}

func TestFalsePositives(t *testing.T) {
	detector := NewIndonesiaPIIDetector(DefaultIndonesiaPIIDetectorConfig())

	falsePositiveInputs := []struct {
		name  string
		input string
	}{
		{"Credit card Visa", "4532015112830366"},
		{"Credit card Mastercard", "5425233430109903"},
		{"UUID", "550e8400-e29b-41d4-a716-446655440000"},
		{"Timestamp unix", "1716729600000000"},
		{"Random 16 digits no province", "0012345678901234"},
		{"IP address", "192.168.1.1"},
		{"US SSN", "123-45-6789"},
		{"Date string", "2026-05-26T12:00:00Z"},
		{"Plain English", "The quick brown fox jumps over the lazy dog"},
		{"Code snippet", "func main() { fmt.Println(42) }"},
		{"Hex string", "0xDEADBEEF12345678"},
		{"Email address", "user@example.com"},
		{"US phone", "+1-202-555-1234"},
	}

	for _, tt := range falsePositiveInputs {
		t.Run(tt.name, func(t *testing.T) {
			results := detector.DetectAll(tt.input)
			if len(results) > 0 {
				var types []string
				for _, r := range results {
					types = append(types, string(r.Type))
				}
				t.Errorf("False positive on %q: detected %v", tt.input, types)
			}
		})
	}
}

func TestCheckRequestForPII(t *testing.T) {
	detector := NewIndonesiaPIIDetector(DefaultIndonesiaPIIDetectorConfig())

	t.Run("nil detector returns safe", func(t *testing.T) {
		result := CheckRequestForPII(nil, "anything", true)
		if result.HasPII || result.BlockRecommended {
			t.Error("nil detector should return safe result")
		}
	})

	t.Run("empty query returns safe", func(t *testing.T) {
		result := CheckRequestForPII(detector, "", true)
		if result.HasPII || result.BlockRecommended {
			t.Error("empty query should return safe result")
		}
	})

	t.Run("clean query returns safe", func(t *testing.T) {
		result := CheckRequestForPII(detector, "What is the weather in Jakarta?", true)
		if result.HasPII || result.BlockRecommended {
			t.Error("clean query should return safe result")
		}
	})

	t.Run("NIK triggers block when blockOnCritical=true", func(t *testing.T) {
		result := CheckRequestForPII(detector, "My NIK is 3174042506780001", true)
		if !result.HasPII {
			t.Error("should detect PII")
		}
		if !result.CriticalPII {
			t.Error("NIK should be critical PII")
		}
		if !result.BlockRecommended {
			t.Error("should recommend block for critical PII with blockOnCritical=true")
		}
	})

	t.Run("NIK does not block when blockOnCritical=false", func(t *testing.T) {
		result := CheckRequestForPII(detector, "My NIK is 3174042506780001", false)
		if !result.HasPII {
			t.Error("should detect PII")
		}
		if result.BlockRecommended {
			t.Error("should NOT recommend block when blockOnCritical=false")
		}
	})

	t.Run("phone is non-critical", func(t *testing.T) {
		result := CheckRequestForPII(detector, "Call me at +6281234567890", true)
		if !result.HasPII {
			t.Error("should detect phone PII")
		}
		if result.CriticalPII {
			t.Error("phone should not be critical PII")
		}
		if result.BlockRecommended {
			t.Error("phone should not trigger block")
		}
	})
}

func TestMasking(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		piiType IndonesiaPIIType
		wantLen int
	}{
		{"NIK masking", "3174042506780001", IndonesiaPIITypeNIK, 16},
		{"Phone masking", "+6281234567890", IndonesiaPIITypePhone, 14},
		{"NPWP legacy masking", "01.234.567.8-901.234", IndonesiaPIITypeNPWPLegacy, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masked := maskIndonesiaPII(tt.value, tt.piiType)
			if len(masked) != tt.wantLen {
				t.Errorf("masked length = %d, want %d", len(masked), tt.wantLen)
			}
			// Masked value should contain asterisks
			if !strings.Contains(masked, "*") {
				t.Errorf("masked value %q should contain asterisks", masked)
			}
		})
	}
}

func TestIsEnabled(t *testing.T) {
	if !IsEnabled() {
		t.Error("IsEnabled() should return true")
	}
}

func TestDetectAll_MultipleTypes(t *testing.T) {
	detector := NewIndonesiaPIIDetector(DefaultIndonesiaPIIDetectorConfig())

	input := "NIK: 3174042506780001, NPWP: 01.234.567.8-901.234, phone: +6281234567890"
	results := detector.DetectAll(input)

	typeSet := make(map[IndonesiaPIIType]bool)
	for _, r := range results {
		typeSet[r.Type] = true
	}

	if !typeSet[IndonesiaPIITypeNIK] {
		t.Error("should detect NIK")
	}
	if !typeSet[IndonesiaPIITypeNPWPLegacy] {
		t.Error("should detect NPWP legacy")
	}
	if !typeSet[IndonesiaPIITypePhone] {
		t.Error("should detect phone")
	}
}

func TestHasIndonesiaPII(t *testing.T) {
	detector := NewIndonesiaPIIDetector(DefaultIndonesiaPIIDetectorConfig())

	if !detector.HasIndonesiaPII("My NIK is 3174042506780001") {
		t.Error("should detect NIK")
	}
	if detector.HasIndonesiaPII("Hello world") {
		t.Error("should not detect PII in clean text")
	}
}

func TestCreditCardFalsePositive(t *testing.T) {
	detector := NewIndonesiaPIIDetector(DefaultIndonesiaPIIDetectorConfig())

	// Credit card numbers that could look like NIKs if not properly filtered
	inputs := []string{
		"4532015112830366",  // Visa 16-digit
		"5425233430109903",  // Mastercard
		"6011111111111117",  // Discover
	}

	for _, input := range inputs {
		results := detector.DetectType(input, IndonesiaPIITypeNIK)
		if len(results) > 0 {
			t.Errorf("Credit card %q should not match NIK", input)
		}
	}
}

func BenchmarkDetectAll(b *testing.B) {
	detector := NewIndonesiaPIIDetector(DefaultIndonesiaPIIDetectorConfig())
	input := "Customer NIK: 3174042506780001, NPWP: 01.234.567.8-901.234, phone: +6281234567890, BCA: 1234567890"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectAll(input)
	}
}

func BenchmarkCheckRequestForPII(b *testing.B) {
	detector := NewIndonesiaPIIDetector(DefaultIndonesiaPIIDetectorConfig())
	input := "Please process payment for NIK 3174042506780001 to BCA: 1234567890"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckRequestForPII(detector, input, true)
	}
}
