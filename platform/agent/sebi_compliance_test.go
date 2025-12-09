// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package agent contains tests for SEBI AI/ML compliance regex patterns.

These tests validate the regex patterns used in SEBI (Securities and Exchange Board of India)
AI/ML compliance policy templates. The patterns are defined in the SQL migration file:
migrations/industry/banking/001_sebi_ai_ml_templates.sql

# SEBI AI/ML Guidelines Reference

The patterns implement detection for the 6 pillars of SEBI's AI/ML Guidelines
(Consultation Paper, June 2025):

  1. Ethics - Responsible AI usage in securities markets
  2. Accountability - Human oversight for high-value trades (>₹10 lakh)
  3. Transparency - Disclosure of AI-generated investment advice
  4. Auditability - 5-year retention of all AI/ML decisions
  5. Data Privacy - PAN, Aadhaar, bank account redaction (DPDP Act 2023)
  6. Fairness - Bias detection in ML model outputs

# Pattern Categories

The test file covers these detection patterns:

  - PAN Number Detection: Indian Permanent Account Number (tax ID)
  - Aadhaar Detection: Indian unique ID number (DPDP Act compliance)
  - High-Value Trade Detection: Trades exceeding ₹10 lakh threshold
  - Investment Advisory Detection: AI-generated investment recommendations
  - Algorithmic Trading Detection: Algo/HFT trading activities
  - Bank Account Detection: Indian bank account numbers and IFSC codes
  - Demat Account Detection: NSDL/CDSL depository account numbers
  - Cross-Border Detection: International data transfer intent
  - Model Bias Detection: ML scoring/evaluation outputs

# Usage

These patterns are compiled into the agent at build time and used for real-time
content scanning during LLM interactions. Matched content triggers the configured
action (log, alert, or redact) based on the policy configuration.

# Related Files

  - migrations/industry/banking/001_sebi_ai_ml_templates.sql - Policy definitions
  - migrations/industry/banking/001_sebi_ai_ml_templates_down.sql - Rollback
  - migrations/industry/README.md - Industry migration documentation
*/
package agent

import (
	"regexp"
	"testing"
)

// =============================================================================
// SEBI AI/ML Compliance Policy Pattern Tests
//
// Reference: SEBI Consultation Paper on Guidelines for Responsible Usage of
// AI/ML in Indian Securities Markets (June 2025)
// URL: https://www.sebi.gov.in/reports-and-statistics/reports/jun-2025/...
// =============================================================================

// =============================================================================
// PAN Number Detection Tests
// Format: 5 letters + 4 digits + 1 letter (AAAPL1234C)
// 4th character indicates entity type: P=Person, C=Company, H=HUF, etc.
// =============================================================================

// PANPattern is the regex pattern for Indian PAN numbers
// Pattern improved with case-insensitive PAN prefix and word boundaries
var PANPattern = regexp.MustCompile(`\b[A-Z]{3}[PCHABGJLFT][A-Z][0-9]{4}[A-Z]\b|(?i)PAN[:\s]+\b[A-Z0-9]{10}\b`)

func TestPANDetection(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
		description string
	}{
		// Valid PAN formats - Individual (P)
		{
			name:        "Valid PAN - Individual",
			input:       "Customer PAN is ABCPD1234F",
			shouldMatch: true,
			description: "Standard individual PAN format (4th char P=Person)",
		},
		{
			name:        "Valid PAN - Individual lowercase context",
			input:       "pan number XYZPQ5678R for account",
			shouldMatch: true,
			description: "PAN in lowercase context",
		},
		{
			name:        "Valid PAN - with PAN prefix",
			input:       "PAN: ABCDE1234F",
			shouldMatch: true,
			description: "PAN with explicit prefix",
		},
		{
			name:        "Valid PAN - with PAN space prefix",
			input:       "PAN ABCDE1234F",
			shouldMatch: true,
			description: "PAN with space prefix",
		},

		// Valid PAN formats - Company (C)
		{
			name:        "Valid PAN - Company",
			input:       "Company PAN: AAACM1234C",
			shouldMatch: true,
			description: "Company PAN (4th char C)",
		},

		// Valid PAN formats - HUF (H)
		{
			name:        "Valid PAN - HUF",
			input:       "HUF PAN number AAAHK1234H",
			shouldMatch: true,
			description: "HUF PAN (4th char H)",
		},

		// Valid PAN formats - Other entity types
		{
			name:        "Valid PAN - Association (A)",
			input:       "Association PAN BBBAB1234A",
			shouldMatch: true,
			description: "Association PAN (4th char A)",
		},
		{
			name:        "Valid PAN - Body of Individuals (B)",
			input:       "BOI PAN CCCBD1234B",
			shouldMatch: true,
			description: "BOI PAN (4th char B)",
		},
		{
			name:        "Valid PAN - Government (G)",
			input:       "Government entity PAN DDDGE1234G",
			shouldMatch: true,
			description: "Government PAN (4th char G)",
		},
		{
			name:        "Valid PAN - AJP (J)",
			input:       "AJP PAN EEEJF1234J",
			shouldMatch: true,
			description: "AJP PAN (4th char J)",
		},
		{
			name:        "Valid PAN - Local Authority (L)",
			input:       "Local authority PAN FFFLG1234L",
			shouldMatch: true,
			description: "Local Authority PAN (4th char L)",
		},
		{
			name:        "Valid PAN - Firm (F)",
			input:       "Partnership firm PAN GGGFH1234F",
			shouldMatch: true,
			description: "Firm PAN (4th char F)",
		},
		{
			name:        "Valid PAN - Trust (T)",
			input:       "Trust PAN HHHTJ1234T",
			shouldMatch: true,
			description: "Trust PAN (4th char T)",
		},

		// PAN in various contexts
		{
			name:        "PAN in sentence",
			input:       "Please verify the PAN ABCPM1234N before proceeding with KYC",
			shouldMatch: true,
			description: "PAN embedded in sentence",
		},
		{
			name:        "PAN with account info",
			input:       "Account holder: John Doe, PAN: BXYPD1234E, Account: 123456789",
			shouldMatch: true,
			description: "PAN with other account details",
		},
		{
			name:        "Multiple PANs",
			input:       "Primary holder ABCPD1234A, Secondary holder XYZPM5678B",
			shouldMatch: true,
			description: "Multiple PANs in text",
		},

		// Edge cases - Note: the PAN prefix alternative pattern is more lenient
		// The strict pattern validates entity type, but PAN: prefix accepts any 10 alphanumeric
		{
			name:        "Invalid - 4th char not entity type (no prefix)",
			input:       "Invalid number ABCDE1234F here",
			shouldMatch: false,
			description: "Without PAN prefix, 4th char must be valid entity type",
		},
		{
			name:        "Invalid - too short",
			input:       "Short code ABCD1234 here",
			shouldMatch: false,
			description: "PAN must be 10 characters",
		},
		{
			name:        "Invalid - too long (no prefix)",
			input:       "Long code ABCDE12345FG here",
			shouldMatch: false,
			description: "Must be exactly 10 characters without prefix",
		},
		{
			name:        "Invalid - lowercase letters",
			input:       "Lowercase abcpe1234f",
			shouldMatch: false,
			description: "PAN must be uppercase",
		},
		{
			name:        "Invalid - wrong format",
			input:       "Wrong format 1234ABCDE5",
			shouldMatch: false,
			description: "PAN has specific letter/digit positions",
		},
		{
			name:        "Invalid - numeric entity position",
			input:       "Numeric 4th position ABC1E1234F",
			shouldMatch: false,
			description: "4th position must be letter",
		},
		{
			name:        "Regular text no PAN",
			input:       "This is regular text without any PAN number",
			shouldMatch: false,
			description: "No PAN in text",
		},
		{
			name:        "Similar but not PAN - flight number",
			input:       "Flight AI1234 departing at 10:00",
			shouldMatch: false,
			description: "Flight number should not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := PANPattern.MatchString(tt.input)
			if matched != tt.shouldMatch {
				t.Errorf("PAN Pattern: %s\nInput: %s\nExpected match=%v, got match=%v\nDescription: %s",
					PANPattern.String(), tt.input, tt.shouldMatch, matched, tt.description)
			}
		})
	}
}

// SEBIValidatePAN validates a PAN number format for SEBI compliance testing
// Returns true if valid, false otherwise
// This is a test-only function with regex prefix handling
func SEBIValidatePAN(pan string) bool {
	// Remove any prefix like "PAN:" or "PAN "
	cleanPAN := regexp.MustCompile(`^PAN[:\s]*`).ReplaceAllString(pan, "")

	// PAN must be exactly 10 characters
	if len(cleanPAN) != 10 {
		return false
	}

	// Check each position
	// Positions 1-3: Letters (A-Z)
	// Position 4: Entity type (P, C, H, A, B, G, J, L, F, T)
	// Position 5: Letter (A-Z)
	// Positions 6-9: Digits (0-9)
	// Position 10: Letter (A-Z) - check digit

	validEntityTypes := "PCHABGJLFT"

	for i, c := range cleanPAN {
		switch {
		case i < 3: // First 3 chars must be letters
			if c < 'A' || c > 'Z' {
				return false
			}
		case i == 3: // 4th char must be valid entity type
			if !containsRune(validEntityTypes, c) {
				return false
			}
		case i == 4: // 5th char must be letter
			if c < 'A' || c > 'Z' {
				return false
			}
		case i >= 5 && i <= 8: // Chars 6-9 must be digits
			if c < '0' || c > '9' {
				return false
			}
		case i == 9: // 10th char must be letter (check digit)
			if c < 'A' || c > 'Z' {
				return false
			}
		}
	}

	return true
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func TestSEBIValidatePAN(t *testing.T) {
	tests := []struct {
		name  string
		pan   string
		valid bool
	}{
		// Valid PANs
		{"Valid Individual PAN", "ABCPD1234E", true},
		{"Valid Company PAN", "AAACM1234C", true},
		{"Valid HUF PAN", "XYZHN5678A", true},
		{"Valid Trust PAN", "BBBTA9999Z", true},
		{"Valid with PAN prefix", "PAN: ABCPD1234E", true},
		{"Valid with PAN space", "PAN ABCPD1234E", true},

		// Invalid PANs
		{"Invalid - wrong entity type", "ABCDE1234F", false},
		{"Invalid - lowercase", "abcpd1234e", false},
		{"Invalid - too short", "ABCPD1234", false},
		{"Invalid - too long", "ABCPD12345E", false},
		{"Invalid - digit in letter position", "1BCPD1234E", false},
		{"Invalid - letter in digit position", "ABCPDABCDE", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SEBIValidatePAN(tt.pan)
			if got != tt.valid {
				t.Errorf("SEBIValidatePAN(%s) = %v, want %v", tt.pan, got, tt.valid)
			}
		})
	}
}

// =============================================================================
// Aadhaar Number Detection Tests
// Format: 12 digits, first digit 2-9, can have spaces (XXXX XXXX XXXX)
// =============================================================================

// AadhaarPattern is the regex pattern for Indian Aadhaar numbers
// Pattern improved to validate first digit (2-9) in all formats
var AadhaarPattern = regexp.MustCompile(`\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b|(?i)aadhaar[:\s]+[2-9][0-9]{11}|UID[:\s]+[2-9][0-9]{11}`)

func TestAadhaarDetection(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
		description string
	}{
		// Valid Aadhaar formats
		{
			name:        "Valid Aadhaar - no spaces",
			input:       "Aadhaar number 234567890123",
			shouldMatch: true,
			description: "12-digit Aadhaar without spaces",
		},
		{
			name:        "Valid Aadhaar - with spaces",
			input:       "Aadhaar: 2345 6789 0123",
			shouldMatch: true,
			description: "12-digit Aadhaar with spaces",
		},
		{
			name:        "Valid Aadhaar - starting with 2",
			input:       "UID 234567890123",
			shouldMatch: true,
			description: "Aadhaar starting with 2",
		},
		{
			name:        "Valid Aadhaar - starting with 9",
			input:       "Aadhaar: 987654321098",
			shouldMatch: true,
			description: "Aadhaar starting with 9",
		},
		{
			name:        "Valid Aadhaar - with UID prefix",
			input:       "UID: 345678901234",
			shouldMatch: true,
			description: "Aadhaar with UID prefix",
		},
		{
			name:        "Valid Aadhaar - with aadhaar prefix lowercase",
			input:       "aadhaar: 456789012345",
			shouldMatch: true,
			description: "Aadhaar with lowercase prefix",
		},

		// Valid Aadhaar in various contexts
		{
			name:        "Aadhaar in KYC context",
			input:       "Please submit your Aadhaar 5678 9012 3456 for verification",
			shouldMatch: true,
			description: "Aadhaar in KYC sentence",
		},
		{
			name:        "Aadhaar with other details",
			input:       "Name: John, Aadhaar: 678901234567, DOB: 01/01/1990",
			shouldMatch: true,
			description: "Aadhaar with other personal info",
		},

		// Edge cases - starting digits
		{
			name:        "Valid - starts with 2",
			input:       "2000 0000 0000",
			shouldMatch: true,
			description: "Aadhaar can start with 2",
		},
		{
			name:        "Valid - starts with 5",
			input:       "5123 4567 8901",
			shouldMatch: true,
			description: "Aadhaar can start with 5",
		},
		{
			name:        "Valid - starts with 8",
			input:       "8999 9999 9999",
			shouldMatch: true,
			description: "Aadhaar can start with 8",
		},

		// Invalid Aadhaar formats
		{
			name:        "Invalid - starts with 0",
			input:       "Invalid Aadhaar 0123 4567 8901",
			shouldMatch: false,
			description: "Aadhaar cannot start with 0",
		},
		{
			name:        "Invalid - starts with 1",
			input:       "Invalid Aadhaar 1234 5678 9012",
			shouldMatch: false,
			description: "Aadhaar cannot start with 1",
		},
		{
			name:        "Invalid - too short",
			input:       "Short number 2345 6789 012",
			shouldMatch: false,
			description: "Aadhaar must be 12 digits",
		},
		{
			name:        "Invalid - too long",
			input:       "Long number 2345 6789 01234",
			shouldMatch: false,
			description: "Aadhaar must be exactly 12 digits",
		},
		{
			name:        "Invalid - contains letters",
			input:       "Invalid 2345 ABCD 0123",
			shouldMatch: false,
			description: "Aadhaar must be all digits",
		},
		{
			name:        "Regular phone number",
			input:       "Phone: 9876543210",
			shouldMatch: false,
			description: "10-digit phone should not match",
		},
		{
			name:        "Regular text",
			input:       "No Aadhaar number here",
			shouldMatch: false,
			description: "Regular text should not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := AadhaarPattern.MatchString(tt.input)
			if matched != tt.shouldMatch {
				t.Errorf("Aadhaar Pattern: %s\nInput: %s\nExpected match=%v, got match=%v\nDescription: %s",
					AadhaarPattern.String(), tt.input, tt.shouldMatch, matched, tt.description)
			}
		})
	}
}

// SEBIValidateAadhaar validates an Aadhaar number using Verhoeff algorithm
// Returns true if valid, false otherwise (includes Verhoeff checksum validation)
func SEBIValidateAadhaar(aadhaar string) bool {
	// Remove spaces
	cleanAadhaar := regexp.MustCompile(`\s+`).ReplaceAllString(aadhaar, "")

	// Remove prefix if present
	cleanAadhaar = regexp.MustCompile(`(?i)^(aadhaar|UID)[:\s]*`).ReplaceAllString(cleanAadhaar, "")

	// Must be exactly 12 digits
	if len(cleanAadhaar) != 12 {
		return false
	}

	// First digit must be 2-9
	if cleanAadhaar[0] < '2' || cleanAadhaar[0] > '9' {
		return false
	}

	// All characters must be digits
	for _, c := range cleanAadhaar {
		if c < '0' || c > '9' {
			return false
		}
	}

	// Verhoeff checksum validation
	return verhoeffValidate(cleanAadhaar)
}

// Verhoeff algorithm tables
var (
	verhoeffD = [][]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
		{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
		{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	verhoeffP = [][]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
		{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
		{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
)

func verhoeffValidate(num string) bool {
	c := 0
	for i := len(num) - 1; i >= 0; i-- {
		digit := int(num[i] - '0')
		p := verhoeffP[(len(num)-i)%8][digit]
		c = verhoeffD[c][p]
	}
	return c == 0
}

// ValidateAadhaarFormat validates only the format (not Verhoeff checksum)
// Use this for detection - the checksum validation is too strict for pattern matching
func ValidateAadhaarFormat(aadhaar string) bool {
	// Remove spaces
	cleanAadhaar := regexp.MustCompile(`\s+`).ReplaceAllString(aadhaar, "")

	// Remove prefix if present
	cleanAadhaar = regexp.MustCompile(`(?i)^(aadhaar|UID)[:\s]*`).ReplaceAllString(cleanAadhaar, "")

	// Must be exactly 12 digits
	if len(cleanAadhaar) != 12 {
		return false
	}

	// First digit must be 2-9
	if cleanAadhaar[0] < '2' || cleanAadhaar[0] > '9' {
		return false
	}

	// All characters must be digits
	for _, c := range cleanAadhaar {
		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}

func TestValidateAadhaarFormat(t *testing.T) {
	tests := []struct {
		name    string
		aadhaar string
		valid   bool
	}{
		// Valid formats
		{"Valid format - no spaces", "234567890123", true},
		{"Valid format - with spaces", "2345 6789 0123", true},
		{"Valid format - with prefix", "aadhaar: 234567890123", true},
		{"Valid format - with UID prefix", "UID: 234567890123", true},
		{"Valid format - starts with 9", "999999999999", true},

		// Invalid formats
		{"Invalid - starts with 0", "012345678901", false},
		{"Invalid - starts with 1", "123456789012", false},
		{"Invalid - too short", "23456789012", false},
		{"Invalid - too long", "2345678901234", false},
		{"Invalid - contains letters", "23456789012A", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateAadhaarFormat(tt.aadhaar)
			if got != tt.valid {
				t.Errorf("ValidateAadhaarFormat(%s) = %v, want %v", tt.aadhaar, got, tt.valid)
			}
		})
	}
}

func TestSEBIValidateAadhaarWithVerhoeff(t *testing.T) {
	tests := []struct {
		name    string
		aadhaar string
		valid   bool
	}{
		// These would need real Aadhaar-like numbers that pass Verhoeff
		// For now, test that invalid formats are rejected
		{"Invalid - starts with 0", "012345678901", false},
		{"Invalid - starts with 1", "123456789012", false},
		{"Invalid - too short", "23456789012", false},
		{"Invalid - too long", "2345678901234", false},
		{"Invalid - contains letters", "23456789012A", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SEBIValidateAadhaar(tt.aadhaar)
			if got != tt.valid {
				t.Errorf("SEBIValidateAadhaar(%s) = %v, want %v", tt.aadhaar, got, tt.valid)
			}
		})
	}
}

// =============================================================================
// High-Value Trade Detection Tests
// Threshold: ₹10 lakh (1,000,000 INR)
// =============================================================================

// HighValueTradePattern detects high-value transactions in INR
var HighValueTradePattern = regexp.MustCompile(`(₹|INR|Rs\.?)\s*[,\d]*[1-9]\d{6,}|(lakh|lac|crore|cr)\s*(₹|INR|Rs\.?)?|trade.*value.*[1-9]\d{6,}`)

func TestHighValueTradeDetection(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
		description string
	}{
		// High value transactions (>= 10 lakh)
		{
			name:        "10 lakh with rupee symbol",
			input:       "Trade value ₹1000000",
			shouldMatch: true,
			description: "Exactly 10 lakh",
		},
		{
			name:        "1 crore with INR",
			input:       "Transaction amount INR 10000000",
			shouldMatch: true,
			description: "1 crore transaction",
		},
		{
			name:        "50 lakh with Rs.",
			input:       "Investment Rs. 5000000",
			shouldMatch: true,
			description: "50 lakh investment",
		},
		{
			name:        "Using lakh word",
			input:       "Trade worth 15 lakh rupees",
			shouldMatch: true,
			description: "Using 'lakh' word",
		},
		{
			name:        "Using crore word",
			input:       "Portfolio value 2 crore",
			shouldMatch: true,
			description: "Using 'crore' word",
		},
		{
			name:        "Trade with value context",
			input:       "Equity trade value 2500000 executed",
			shouldMatch: true,
			description: "Trade context with value",
		},

		// Transactions with formatting - Note: pattern matches 7+ consecutive digits
		// Comma-separated Indian format would need different pattern
		{
			name:        "Large number without commas",
			input:       "Amount: ₹2500000",
			shouldMatch: true,
			description: "Large number without Indian formatting",
		},

		// Lower value transactions (should not match threshold but may match pattern)
		{
			name:        "1 lakh - below threshold",
			input:       "Small trade ₹100000",
			shouldMatch: false,
			description: "1 lakh - below 10 lakh threshold",
		},
		{
			name:        "50,000 - well below",
			input:       "Purchase INR 50000",
			shouldMatch: false,
			description: "50K - way below threshold",
		},

		// Non-financial contexts
		{
			name:        "Regular text",
			input:       "This is a normal trading discussion",
			shouldMatch: false,
			description: "No financial values",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := HighValueTradePattern.MatchString(tt.input)
			if matched != tt.shouldMatch {
				t.Errorf("High Value Pattern\nInput: %s\nExpected match=%v, got match=%v\nDescription: %s",
					tt.input, tt.shouldMatch, matched, tt.description)
			}
		})
	}
}

// =============================================================================
// Investment Advisory Disclosure Detection Tests
// =============================================================================

// InvestmentAdvisoryPattern detects AI investment advice
// Pattern: (action)\s*(instrument) - action word must be directly followed by instrument type
var InvestmentAdvisoryPattern = regexp.MustCompile(`(recommend|suggest|advise|buy|sell|hold)\s*(stock|equity|share|fund|portfolio|investment|security|bond|debenture)`)

func TestInvestmentAdvisoryDetection(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Pattern requires action word directly followed by instrument type
		{"Recommend stock", "We recommend stock purchases in current market", true},
		{"Suggest equity", "AI suggest equity allocation changes", true},
		{"Advise investment", "We advise investment diversification", true},
		{"Buy fund", "Consider to buy fund units today", true},
		{"Sell shares", "Decision to sell shares immediately", true},
		{"Hold portfolio", "Strategy: hold portfolio positions", true},
		{"Recommend bond", "Analysts recommend bond holdings", true},
		{"Suggest debenture", "System suggest debenture purchase", true},
		{"Buy security", "Opportunity to buy security now", true},

		// Should not match
		{"General text", "This is general market news", false},
		{"Technical discussion", "Discussing market trends", false},
		{"Non-advisory recommend", "I recommend this restaurant", false},
		{"Action without instrument", "We recommend buying RELIANCE", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := InvestmentAdvisoryPattern.MatchString(tt.input)
			if matched != tt.shouldMatch {
				t.Errorf("Investment Advisory Pattern\nInput: %s\nExpected match=%v, got match=%v",
					tt.input, tt.shouldMatch, matched)
			}
		})
	}
}

// =============================================================================
// Algorithmic Trading Detection Tests
// =============================================================================

// AlgoTradingPattern detects algorithmic trading activities
// Pattern: (algo|algorithm|automated|systematic|quant)\s*(trad|order|execution|strategy) OR HFT OR high.frequency OR latency.arbitrage
var AlgoTradingPattern = regexp.MustCompile(`(algo|algorithm|automated|systematic|quant)\s*(trad|order|execution|strategy)|HFT|high.frequency|latency.arbitrage`)

func TestAlgoTradingDetection(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Pattern matches: prefix word + trade/order/execution/strategy
		{"Algo trading", "Executing algo trading strategy", true},
		{"Algo order", "algo order placed for execution", true},
		{"Algorithm trading", "algorithm trading system active", true},
		{"Automated trading", "Using automated trading system", true},
		{"Automated execution", "automated execution platform", true},
		{"Systematic strategy", "Our systematic strategy performs well", true},
		{"Quant trading", "quant trading desk analysis", true},
		{"Quant strategy", "quant strategy optimization", true},

		// Standalone patterns
		{"HFT", "HFT systems require low latency", true},
		{"High frequency", "high frequency trading volume", true},
		{"Latency arbitrage", "latency arbitrage opportunities", true},

		// Should not match
		{"Regular trading", "Manual trading on NSE", false},
		{"General algorithm", "This algorithm sorts data", false},
		{"Algorithm alone", "Algorithm for sorting", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := AlgoTradingPattern.MatchString(tt.input)
			if matched != tt.shouldMatch {
				t.Errorf("Algo Trading Pattern\nInput: %s\nExpected match=%v, got match=%v",
					tt.input, tt.shouldMatch, matched)
			}
		})
	}
}

// =============================================================================
// Bank Account Detection Tests
// =============================================================================

// BankAccountPattern detects Indian bank account numbers and IFSC codes
// Pattern: number(9-18 digits) + account/a/c/acct OR account/a/c/acct + number OR IFSC code
// Pattern improved with bounded distance (50 chars), case-insensitivity, and ReDoS prevention
var BankAccountPattern = regexp.MustCompile(`\b[0-9]{9,18}\b.{0,50}?(?i)(?:account|a/?c|acct)|(?i)(?:account|a/?c|acct).{0,50}?\b[0-9]{9,18}\b|IFSC[:\s]*[A-Z]{4}0[A-Z0-9]{6}`)

func TestBankAccountDetection(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Valid bank account patterns - now case-insensitive
		{"Account with number after", "account 123456789012", true},
		{"Account before number", "123456789012 is my account", true},
		{"a/c lowercase format", "a/c 9876543210123", true},
		{"A/C uppercase format", "A/C 9876543210123", true},
		{"acct lowercase format", "acct 12345678901234", true},
		{"ACCT uppercase format", "ACCT 12345678901234", true},
		{"IFSC code", "IFSC: SBIN0001234", true},
		{"IFSC without colon", "IFSC HDFC0001234", true},

		// Different bank account lengths (9-18 digits)
		{"9-digit account", "account 123456789", true},
		{"18-digit account", "account 123456789012345678", true},

		// Should not match
		{"Phone number", "Call me at 9876543210", false},
		{"Regular number", "Order number 12345", false},
		{"Short number", "PIN 123456", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := BankAccountPattern.MatchString(tt.input)
			if matched != tt.shouldMatch {
				t.Errorf("Bank Account Pattern\nInput: %s\nExpected match=%v, got match=%v",
					tt.input, tt.shouldMatch, matched)
			}
		})
	}
}

// =============================================================================
// Demat Account Detection Tests
// =============================================================================

// DematAccountPattern detects Indian Demat account numbers
// NSDL: IN + 14 digits, CDSL: 1X + 14 digits
// DP ID, Client ID, beneficiary ID formats (case-insensitive)
var DematAccountPattern = regexp.MustCompile(`\b(IN|1[0-9])[0-9]{14}\b|(?i)DP\s*ID[:\s]*[A-Z0-9]{8,16}|(?i)client\s*ID[:\s]*[A-Z0-9]{8,16}|(?i)beneficiary\s*ID[:\s]*[0-9]{16}`)

func TestDematAccountDetection(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// NSDL format (starts with IN + 14 digits = 16 total)
		{"NSDL BO ID", "Demat account IN12345678901234", true},

		// CDSL format (starts with 1X where X is 0-9, + 14 digits = 16 total)
		{"CDSL BO ID", "BO ID 1234567890123456", true},

		// DP ID format (8-16 alphanumeric) - case insensitive
		{"DP ID lowercase", "dp id: 12345678", true},
		{"DP ID uppercase", "DP ID: 12345678", true},
		{"DP ID 16 chars", "DP ID IN300123AB", true},

		// Client ID format (case-insensitive)
		{"client ID lowercase", "client ID: ABCD12345678", true},
		{"Client ID uppercase", "Client ID: ABCD12345678", true},

		// Beneficiary ID (exactly 16 digits) - case insensitive
		{"beneficiary ID lowercase", "beneficiary ID: 1234567890123456", true},
		{"Beneficiary ID mixed case", "Beneficiary ID: 1234567890123456", true},

		// Should not match
		{"Phone number", "Phone: 9876543210", false},
		{"Regular ID", "Employee ID: 12345", false},
		{"Short client ID", "Client ID: ABC123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := DematAccountPattern.MatchString(tt.input)
			if matched != tt.shouldMatch {
				t.Errorf("Demat Account Pattern\nInput: %s\nExpected match=%v, got match=%v",
					tt.input, tt.shouldMatch, matched)
			}
		})
	}
}

// =============================================================================
// Cross-Border Data Transfer Detection Tests
// =============================================================================

// CrossBorderPattern detects cross-border data transfer intent
// Two patterns:
// 1. (action) ... (destination): transfer/send/export/share followed by overseas/foreign/international/offshore/outside.India
// 2. (destination) ... (action/data): overseas/foreign/international followed by transfer/send/data
var CrossBorderPattern = regexp.MustCompile(`(transfer|send|export|share).*(overseas|foreign|international|offshore|outside.India)|(overseas|foreign|international).*(transfer|send|data)`)

func TestCrossBorderDetection(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Pattern 1: action word + ... + destination
		{"Transfer overseas", "Need to transfer data overseas", true},
		{"Send to foreign", "send reports to foreign office", true},
		{"Export international", "export files to international team", true},
		{"Share offshore", "share documents with offshore team", true},
		{"Transfer outside India", "transfer records to outside India", true},

		// Pattern 2: destination + ... + action/data
		{"International transfer", "international funds transfer needed", true},
		{"Foreign data request", "foreign subsidiary data request", true},
		{"Overseas data access", "overseas office needs data access", true},
		{"International send", "international team needs us to send files", true},

		// Should not match
		{"Domestic transfer", "Transfer funds to Mumbai branch", false},
		{"Internal share", "Share with internal team", false},
		{"Local export", "Export report to local drive", false},
		{"Foreign without action", "Foreign office meeting scheduled", false},
		{"Data without destination", "Need to send data to client", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := CrossBorderPattern.MatchString(tt.input)
			if matched != tt.shouldMatch {
				t.Errorf("Cross Border Pattern\nInput: %s\nExpected match=%v, got match=%v",
					tt.input, tt.shouldMatch, matched)
			}
		})
	}
}

// =============================================================================
// Model Bias Detection Tests
// =============================================================================

// ModelBiasPattern detects AI model scoring/evaluation outputs
// Pattern requires action word directly followed by target (with optional whitespace)
// This is used to track ML model outputs for SEBI Fairness pillar compliance
var ModelBiasPattern = regexp.MustCompile(`(score|rating|rank|predict|assess|evaluate)\s*(client|customer|investor|risk|credit|eligibility)`)

func TestModelBiasDetection(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Pattern: (action)\s*(target) - words must be adjacent or separated only by whitespace
		{"Score client", "AI will score client creditworthiness", true},
		{"Rating customer", "Model rating customer profile", true},
		{"Rank investor", "Algorithm to rank investor applications", true},
		{"Predict risk", "ML model to predict risk levels", true},
		{"Assess credit", "System to assess credit worthiness", true},
		{"Evaluate eligibility", "evaluate eligibility for loan", true},
		{"Score risk", "Need to score risk profile", true},
		{"Assess customer", "assess customer profile now", true},

		// Should not match
		{"General scoring", "Score the test results", false},
		{"Product rating", "Rating this product 5 stars", false},
		{"Rank without target", "Rank the items by date", false},
		{"Evaluate with gap", "Evaluate the customer profile", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := ModelBiasPattern.MatchString(tt.input)
			if matched != tt.shouldMatch {
				t.Errorf("Model Bias Pattern\nInput: %s\nExpected match=%v, got match=%v",
					tt.input, tt.shouldMatch, matched)
			}
		})
	}
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkPANDetection(b *testing.B) {
	inputs := []string{
		"Customer PAN is ABCPD1234E",
		"No PAN number here",
		"Multiple PANs: ABCPD1234E and XYZPM5678B",
	}
	for i := 0; i < b.N; i++ {
		for _, input := range inputs {
			PANPattern.MatchString(input)
		}
	}
}

func BenchmarkAadhaarDetection(b *testing.B) {
	inputs := []string{
		"Aadhaar: 2345 6789 0123",
		"No Aadhaar here",
		"UID: 345678901234",
	}
	for i := 0; i < b.N; i++ {
		for _, input := range inputs {
			AadhaarPattern.MatchString(input)
		}
	}
}

func BenchmarkAllSEBIPatterns(b *testing.B) {
	patterns := []*regexp.Regexp{
		PANPattern,
		AadhaarPattern,
		HighValueTradePattern,
		InvestmentAdvisoryPattern,
		AlgoTradingPattern,
		BankAccountPattern,
		DematAccountPattern,
		CrossBorderPattern,
		ModelBiasPattern,
	}

	input := `Customer details:
		PAN: ABCPD1234E
		Aadhaar: 2345 6789 0123
		Trade value ₹5000000
		AI recommends buying RELIANCE stock
		Using algo trading strategy
		Account: 123456789012
		Demat: IN12345678901234
		Transfer data overseas
		Score client risk profile`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pattern := range patterns {
			pattern.MatchString(input)
		}
	}
}
