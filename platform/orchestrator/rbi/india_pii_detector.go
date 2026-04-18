// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// IndiaPIIType represents different categories of India-specific PII
type IndiaPIIType string

const (
	IndiaPIITypeUPI          IndiaPIIType = "upi_id"
	IndiaPIITypeAadhaar      IndiaPIIType = "aadhaar"
	IndiaPIITypePAN          IndiaPIIType = "pan"
	IndiaPIITypeIFSC         IndiaPIIType = "ifsc"
	IndiaPIITypeBankAccount  IndiaPIIType = "bank_account_india"
	IndiaPIITypeGSTIN        IndiaPIIType = "gstin"
	IndiaPIITypeVoterID      IndiaPIIType = "voter_id"
	IndiaPIITypeDrivingLicense IndiaPIIType = "driving_license_india"
	IndiaPIITypePassport     IndiaPIIType = "passport_india"
	IndiaPIITypeRationCard   IndiaPIIType = "ration_card"
	IndiaPIITypeIndianPhone  IndiaPIIType = "phone_india"
	IndiaPIITypePincode      IndiaPIIType = "pincode"
)

// IndiaPIISeverity represents the risk level of detected India PII
type IndiaPIISeverity string

const (
	IndiaPIISeverityLow      IndiaPIISeverity = "low"
	IndiaPIISeverityMedium   IndiaPIISeverity = "medium"
	IndiaPIISeverityHigh     IndiaPIISeverity = "high"
	IndiaPIISeverityCritical IndiaPIISeverity = "critical"
)

// IndiaPIIDetectionResult represents a single India PII detection
type IndiaPIIDetectionResult struct {
	Type        IndiaPIIType     `json:"type"`
	Value       string           `json:"value"`
	MaskedValue string           `json:"masked_value"`
	Severity    IndiaPIISeverity `json:"severity"`
	Confidence  float64          `json:"confidence"`
	StartIndex  int              `json:"start_index"`
	EndIndex    int              `json:"end_index"`
	Context     string           `json:"context,omitempty"`
	RBICategory string           `json:"rbi_category"` // Maps to RBI FREE-AI data category
}

// IndiaPIIPattern represents a compiled pattern for India PII detection
type IndiaPIIPattern struct {
	Type        IndiaPIIType
	Pattern     *regexp.Regexp
	Severity    IndiaPIISeverity
	Validator   func(match string, context string) (bool, float64)
	MinLength   int
	MaxLength   int
	RBICategory string
}

// IndiaPIIDetector provides India-specific PII detection for RBI compliance
type IndiaPIIDetector struct {
	patterns         []*IndiaPIIPattern
	contextWindow    int
	minConfidence    float64
	enableValidation bool
}

// IndiaPIIDetectorConfig configures the India PII detector behavior
type IndiaPIIDetectorConfig struct {
	ContextWindow    int
	MinConfidence    float64
	EnableValidation bool
	EnabledTypes     []IndiaPIIType
}

// DefaultIndiaPIIDetectorConfig returns sensible defaults for RBI compliance
func DefaultIndiaPIIDetectorConfig() IndiaPIIDetectorConfig {
	return IndiaPIIDetectorConfig{
		ContextWindow:    50,
		MinConfidence:    0.6,
		EnableValidation: true,
		EnabledTypes:     nil, // All types enabled
	}
}

// NewIndiaPIIDetector creates a new India-specific PII detector
func NewIndiaPIIDetector(config IndiaPIIDetectorConfig) *IndiaPIIDetector {
	detector := &IndiaPIIDetector{
		contextWindow:    config.ContextWindow,
		minConfidence:    config.MinConfidence,
		enableValidation: config.EnableValidation,
	}
	detector.loadPatterns(config.EnabledTypes)
	return detector
}

// loadPatterns initializes all India-specific PII detection patterns
func (d *IndiaPIIDetector) loadPatterns(enabledTypes []IndiaPIIType) {
	allPatterns := []*IndiaPIIPattern{
		// UPI ID - username@provider format
		{
			Type: IndiaPIITypeUPI,
			// UPI ID format: username@bankhandle
			// Common handles: @ybl, @paytm, @upi, @oksbi, @okicici, @okhdfcbank, @okaxis, etc.
			Pattern:   regexp.MustCompile(`\b[a-zA-Z0-9][a-zA-Z0-9._-]{2,255}@[a-zA-Z][a-zA-Z0-9]{2,49}\b`),
			Severity:  IndiaPIISeverityCritical,
			Validator: validateUPIID,
			MinLength: 7,  // a@ybl
			MaxLength: 256,
			RBICategory: "payment_identifier",
		},
		// Aadhaar - 12-digit unique identification number
		{
			Type: IndiaPIITypeAadhaar,
			// Aadhaar: 12 digits, can have spaces or hyphens after every 4 digits
			Pattern:   regexp.MustCompile(`\b[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b`),
			Severity:  IndiaPIISeverityCritical,
			Validator: validateAadhaar,
			MinLength: 12,
			MaxLength: 14, // With separators
			RBICategory: "national_identity",
		},
		// PAN - Permanent Account Number
		{
			Type: IndiaPIITypePAN,
			// PAN format: 5 letters + 4 digits + 1 letter (e.g., ABCDE1234F)
			Pattern:   regexp.MustCompile(`\b[A-Z]{5}[0-9]{4}[A-Z]\b`),
			Severity:  IndiaPIISeverityCritical,
			Validator: validatePAN,
			MinLength: 10,
			MaxLength: 10,
			RBICategory: "tax_identifier",
		},
		// IFSC Code - Indian Financial System Code
		{
			Type: IndiaPIITypeIFSC,
			// IFSC: 4 letters (bank code) + 0 + 6 alphanumeric (branch code)
			Pattern:   regexp.MustCompile(`\b[A-Z]{4}0[A-Z0-9]{6}\b`),
			Severity:  IndiaPIISeverityMedium,
			Validator: validateIFSC,
			MinLength: 11,
			MaxLength: 11,
			RBICategory: "bank_identifier",
		},
		// Indian Bank Account Number (9-18 digits)
		{
			Type: IndiaPIITypeBankAccount,
			// Indian bank accounts are typically 9-18 digits
			Pattern:   regexp.MustCompile(`\b[0-9]{9,18}\b`),
			Severity:  IndiaPIISeverityCritical,
			Validator: validateIndianBankAccount,
			MinLength: 9,
			MaxLength: 18,
			RBICategory: "bank_account",
		},
		// GSTIN - Goods and Services Tax Identification Number
		{
			Type: IndiaPIITypeGSTIN,
			// GSTIN: 2 digits (state) + 10 char PAN + 1 digit (entity) + Z + 1 checksum
			Pattern:   regexp.MustCompile(`\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]\b`),
			Severity:  IndiaPIISeverityHigh,
			Validator: validateGSTIN,
			MinLength: 15,
			MaxLength: 15,
			RBICategory: "tax_identifier",
		},
		// Voter ID (EPIC)
		{
			Type: IndiaPIITypeVoterID,
			// Voter ID: 3 letters + 7 digits
			Pattern:   regexp.MustCompile(`\b[A-Z]{3}[0-9]{7}\b`),
			Severity:  IndiaPIISeverityHigh,
			Validator: validateVoterID,
			MinLength: 10,
			MaxLength: 10,
			RBICategory: "national_identity",
		},
		// Indian Driving License
		{
			Type: IndiaPIITypeDrivingLicense,
			// Format varies by state: 2 letters (state) + optional hyphen + 13-14 alphanumeric
			Pattern:   regexp.MustCompile(`\b[A-Z]{2}[-]?[0-9]{2}[-\s]?(?:19|20)[0-9]{2}[0-9]{7}\b`),
			Severity:  IndiaPIISeverityHigh,
			Validator: validateIndianDrivingLicense,
			MinLength: 15,
			MaxLength: 18,
			RBICategory: "national_identity",
		},
		// Indian Passport
		{
			Type: IndiaPIITypePassport,
			// Indian Passport: 1 letter + 7 digits (e.g., A1234567)
			Pattern:   regexp.MustCompile(`\b[A-Z][0-9]{7}\b`),
			Severity:  IndiaPIISeverityHigh,
			Validator: validateIndianPassport,
			MinLength: 8,
			MaxLength: 8,
			RBICategory: "travel_document",
		},
		// Indian Mobile Number
		{
			Type: IndiaPIITypeIndianPhone,
			// Indian mobile: +91 or 0 followed by 10 digits starting with 6-9
			Pattern:   regexp.MustCompile(`(?:\+91[\s-]?|0)?[6-9][0-9]{9}\b`),
			Severity:  IndiaPIISeverityMedium,
			Validator: validateIndianPhone,
			MinLength: 10,
			MaxLength: 14,
			RBICategory: "contact_info",
		},
		// Indian Pincode
		{
			Type: IndiaPIITypePincode,
			// 6-digit pincode, first digit cannot be 0
			Pattern:   regexp.MustCompile(`\b[1-9][0-9]{5}\b`),
			Severity:  IndiaPIISeverityLow,
			Validator: validatePincode,
			MinLength: 6,
			MaxLength: 6,
			RBICategory: "address",
		},
	}

	// Filter by enabled types if specified
	if len(enabledTypes) > 0 {
		enabledMap := make(map[IndiaPIIType]bool)
		for _, t := range enabledTypes {
			enabledMap[t] = true
		}
		for _, p := range allPatterns {
			if enabledMap[p.Type] {
				d.patterns = append(d.patterns, p)
			}
		}
	} else {
		d.patterns = allPatterns
	}
}

// DetectAll scans text for all types of India PII
func (d *IndiaPIIDetector) DetectAll(text string) []IndiaPIIDetectionResult {
	var results []IndiaPIIDetectionResult

	for _, pattern := range d.patterns {
		matches := pattern.Pattern.FindAllStringSubmatchIndex(text, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}

			startIdx := match[0]
			endIdx := match[1]
			matchedText := text[startIdx:endIdx]

			// Skip if outside length bounds
			if len(matchedText) < pattern.MinLength || len(matchedText) > pattern.MaxLength {
				continue
			}

			// Extract context
			context := d.extractContext(text, startIdx, endIdx)

			// Validate if enabled
			confidence := 1.0
			if d.enableValidation && pattern.Validator != nil {
				isValid, validatorConfidence := pattern.Validator(matchedText, context)
				if !isValid {
					continue
				}
				confidence = validatorConfidence
			}

			// Skip low confidence matches
			if confidence < d.minConfidence {
				continue
			}

			results = append(results, IndiaPIIDetectionResult{
				Type:        pattern.Type,
				Value:       matchedText,
				MaskedValue: maskIndiaPII(matchedText, pattern.Type),
				Severity:    pattern.Severity,
				Confidence:  confidence,
				StartIndex:  startIdx,
				EndIndex:    endIdx,
				Context:     context,
				RBICategory: pattern.RBICategory,
			})
		}
	}

	return results
}

// DetectType scans text for a specific type of India PII
func (d *IndiaPIIDetector) DetectType(text string, piiType IndiaPIIType) []IndiaPIIDetectionResult {
	var results []IndiaPIIDetectionResult

	for _, pattern := range d.patterns {
		if pattern.Type != piiType {
			continue
		}

		matches := pattern.Pattern.FindAllStringSubmatchIndex(text, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}

			startIdx := match[0]
			endIdx := match[1]
			matchedText := text[startIdx:endIdx]

			if len(matchedText) < pattern.MinLength || len(matchedText) > pattern.MaxLength {
				continue
			}

			context := d.extractContext(text, startIdx, endIdx)

			confidence := 1.0
			if d.enableValidation && pattern.Validator != nil {
				isValid, validatorConfidence := pattern.Validator(matchedText, context)
				if !isValid {
					continue
				}
				confidence = validatorConfidence
			}

			if confidence < d.minConfidence {
				continue
			}

			results = append(results, IndiaPIIDetectionResult{
				Type:        pattern.Type,
				Value:       matchedText,
				MaskedValue: maskIndiaPII(matchedText, pattern.Type),
				Severity:    pattern.Severity,
				Confidence:  confidence,
				StartIndex:  startIdx,
				EndIndex:    endIdx,
				Context:     context,
				RBICategory: pattern.RBICategory,
			})
		}
	}

	return results
}

// DetectUPIIDs is a convenience method to detect only UPI IDs
func (d *IndiaPIIDetector) DetectUPIIDs(text string) []IndiaPIIDetectionResult {
	return d.DetectType(text, IndiaPIITypeUPI)
}

// DetectAadhaar is a convenience method to detect only Aadhaar numbers
func (d *IndiaPIIDetector) DetectAadhaar(text string) []IndiaPIIDetectionResult {
	return d.DetectType(text, IndiaPIITypeAadhaar)
}

// DetectPAN is a convenience method to detect only PAN numbers
func (d *IndiaPIIDetector) DetectPAN(text string) []IndiaPIIDetectionResult {
	return d.DetectType(text, IndiaPIITypePAN)
}

// HasIndiaPII quickly checks if text contains any India PII
func (d *IndiaPIIDetector) HasIndiaPII(text string) bool {
	for _, pattern := range d.patterns {
		if pattern.Pattern.MatchString(text) {
			matches := pattern.Pattern.FindAllString(text, 1)
			if len(matches) > 0 {
				if pattern.Validator != nil {
					isValid, confidence := pattern.Validator(matches[0], "")
					if isValid && confidence >= d.minConfidence {
						return true
					}
				} else {
					return true
				}
			}
		}
	}
	return false
}

// HasUPIID quickly checks if text contains any UPI ID
func (d *IndiaPIIDetector) HasUPIID(text string) bool {
	for _, pattern := range d.patterns {
		if pattern.Type != IndiaPIITypeUPI {
			continue
		}
		if pattern.Pattern.MatchString(text) {
			matches := pattern.Pattern.FindAllString(text, 1)
			if len(matches) > 0 {
				if pattern.Validator != nil {
					isValid, confidence := pattern.Validator(matches[0], "")
					if isValid && confidence >= d.minConfidence {
						return true
					}
				} else {
					return true
				}
			}
		}
	}
	return false
}

// GetRBISensitiveData returns all detections categorized by RBI data category
func (d *IndiaPIIDetector) GetRBISensitiveData(text string) map[string][]IndiaPIIDetectionResult {
	results := d.DetectAll(text)
	categorized := make(map[string][]IndiaPIIDetectionResult)

	for _, r := range results {
		categorized[r.RBICategory] = append(categorized[r.RBICategory], r)
	}

	return categorized
}

// extractContext extracts surrounding text for context analysis
func (d *IndiaPIIDetector) extractContext(text string, start, end int) string {
	contextStart := start - d.contextWindow
	if contextStart < 0 {
		contextStart = 0
	}

	contextEnd := end + d.contextWindow
	if contextEnd > len(text) {
		contextEnd = len(text)
	}

	return text[contextStart:contextEnd]
}

// GetPatternStats returns statistics about loaded patterns
func (d *IndiaPIIDetector) GetPatternStats() map[string]interface{} {
	typeCount := make(map[IndiaPIIType]int)
	severityCount := make(map[IndiaPIISeverity]int)
	categoryCount := make(map[string]int)

	for _, p := range d.patterns {
		typeCount[p.Type]++
		severityCount[p.Severity]++
		categoryCount[p.RBICategory]++
	}

	return map[string]interface{}{
		"total_patterns":   len(d.patterns),
		"types":            typeCount,
		"severities":       severityCount,
		"rbi_categories":   categoryCount,
		"validation":       d.enableValidation,
		"min_confidence":   d.minConfidence,
		"context_window":   d.contextWindow,
	}
}

// =============================================================================
// Validators for India-specific PII
// =============================================================================

// validateUPIID validates UPI ID format
func validateUPIID(match string, context string) (bool, float64) {
	// Split on @
	parts := strings.Split(match, "@")
	if len(parts) != 2 {
		return false, 0
	}

	username := parts[0]
	handle := strings.ToLower(parts[1])

	// Username validation
	if len(username) < 1 || len(username) > 256 {
		return false, 0
	}

	// First char must be alphanumeric
	if !unicode.IsLetter(rune(username[0])) && !unicode.IsDigit(rune(username[0])) {
		return false, 0
	}

	// Handle validation
	if len(handle) < 3 || len(handle) > 50 {
		return false, 0
	}

	// FIRST: Check if it looks like an email domain (reject immediately)
	emailDomains := []string{
		"gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
		"rediffmail.com", "live.com", "msn.com", "aol.com",
		"icloud.com", "protonmail.com", "zoho.com",
		"gmail", "yahoo", "outlook", "hotmail", "mail",
	}

	for _, domain := range emailDomains {
		if handle == domain || strings.HasSuffix(handle, "."+domain) || strings.HasSuffix(handle, ".com") || strings.HasSuffix(handle, ".org") || strings.HasSuffix(handle, ".net") || strings.HasSuffix(handle, ".in") || strings.HasSuffix(handle, ".co.in") {
			return false, 0 // Definitely an email, not a UPI ID
		}
	}

	// Known UPI handles (increases confidence)
	knownHandles := []string{
		"ybl", "paytm", "upi", "oksbi", "okicici", "okhdfcbank", "okaxis",
		"axisbank", "sbi", "icici", "hdfcbank", "apl", "yapl", "rapl",
		"ibl", "pingpay", "waicici", "wasbi", "waaxis", "wahdfcbank",
		"abfspay", "freecharge", "airtel", "jio", "postbank", "barodampay",
		"unionbank", "indus", "kotak", "idbi", "citi", "rbl", "federal",
		"dbs", "hsbc", "sc", "bandhan", "kvb", "idfcfirst", "yesbank",
		"aubank", "equitas", "ujjivan", "dcb", "csb", "idfc", "fino",
		"airtelpaymentsbank", "payzapp", "jupitermoney", "slice",
	}

	for _, known := range knownHandles {
		if handle == known {
			return true, 0.95
		}
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	// Positive indicators
	positiveIndicators := []string{
		"upi", "payment", "pay", "transfer", "send", "receive",
		"gpay", "google pay", "phonepe", "paytm", "bhim",
		"vpa", "virtual payment address",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.9
		}
	}

	// Negative indicators (email addresses)
	negativeIndicators := []string{
		"email", "mail", "gmail", "yahoo", "outlook", "hotmail",
		"@gmail", "@yahoo", "@outlook", "@hotmail",
	}

	for _, indicator := range negativeIndicators {
		if strings.Contains(contextLower, indicator) {
			return false, 0.2
		}
	}

	// Unknown handle but valid format
	return true, 0.7
}

// validateAadhaar validates Aadhaar number with Verhoeff checksum
func validateAadhaar(match string, context string) (bool, float64) {
	// Remove separators
	clean := strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, match)

	if len(clean) != 12 {
		return false, 0
	}

	// First digit cannot be 0 or 1 (as of current UIDAI rules)
	if clean[0] == '0' || clean[0] == '1' {
		return false, 0
	}

	// Context analysis (do this first to help with confidence)
	contextLower := strings.ToLower(context)

	// Common false positives - reject these early
	negativeIndicators := []string{
		"phone", "mobile", "order", "invoice", "ref", "tracking",
		"transaction", "txn",
	}

	for _, indicator := range negativeIndicators {
		if strings.Contains(contextLower, indicator) {
			return false, 0.2
		}
	}

	positiveIndicators := []string{
		"aadhaar", "aadhar", "uid", "uidai", "unique identification",
		"आधार", "kyc",
	}

	hasPositiveContext := false
	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			hasPositiveContext = true
			break
		}
	}

	// Verhoeff checksum validation
	verhoeffValid := verhoeffCheck(clean)

	if hasPositiveContext {
		// With positive context, accept even if Verhoeff fails (could be masked or test data)
		if verhoeffValid {
			return true, 0.98
		}
		return true, 0.85 // Positive context but checksum fails
	}

	// Without context, require valid checksum for higher confidence
	if verhoeffValid {
		return true, 0.8
	}

	// No context, no checksum - could be Aadhaar but low confidence
	return true, 0.65
}

// Verhoeff tables for checksum calculation
var verhoeffD = [][]int{
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

var verhoeffP = [][]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

// verhoeffCheck performs Verhoeff checksum validation
func verhoeffCheck(num string) bool {
	c := 0
	for i := len(num) - 1; i >= 0; i-- {
		c = verhoeffD[c][verhoeffP[(len(num)-i-1)%8][int(num[i]-'0')]]
	}
	return c == 0
}

// validatePAN validates PAN card number
func validatePAN(match string, context string) (bool, float64) {
	if len(match) != 10 {
		return false, 0
	}

	// Validate structure: AAAAA0000A
	// First 5: Letters, Next 4: Digits, Last 1: Letter
	for i := 0; i < 5; i++ {
		if !unicode.IsLetter(rune(match[i])) {
			return false, 0
		}
	}
	for i := 5; i < 9; i++ {
		if !unicode.IsDigit(rune(match[i])) {
			return false, 0
		}
	}
	if !unicode.IsLetter(rune(match[9])) {
		return false, 0
	}

	// 4th character indicates entity type
	// A: AOP, B: BOI, C: Company, F: Firm, G: Government, H: HUF,
	// L: Local Authority, J: Artificial Juridical Person, P: Person, T: Trust
	entityTypes := "ABCFGHJLPT"
	if !strings.Contains(entityTypes, string(match[3])) {
		return false, 0.5 // Unusual but might be valid
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	positiveIndicators := []string{
		"pan", "permanent account", "income tax", "tax id",
		"पैन", "kyc",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.95
		}
	}

	return true, 0.85
}

// validateIFSC validates IFSC code
func validateIFSC(match string, context string) (bool, float64) {
	if len(match) != 11 {
		return false, 0
	}

	// First 4 letters: Bank code
	// 5th character: Always 0
	// Last 6: Branch code (alphanumeric)

	for i := 0; i < 4; i++ {
		if !unicode.IsLetter(rune(match[i])) {
			return false, 0
		}
	}

	if match[4] != '0' {
		return false, 0
	}

	// Known bank codes (increases confidence)
	bankCode := strings.ToUpper(match[0:4])
	knownBanks := []string{
		"SBIN", "HDFC", "ICIC", "AXIS", "KKBK", "IDFB", "YESB", "IDIB",
		"PUNB", "CNRB", "UBIN", "BARB", "CBIN", "CORP", "VIJB", "UTIB",
		"BKID", "MAHB", "ORBC", "FDRL", "SBBJ", "SBHY", "SBMY", "SBOP",
	}

	isKnownBank := false
	for _, bank := range knownBanks {
		if bankCode == bank {
			isKnownBank = true
			break
		}
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	positiveIndicators := []string{
		"ifsc", "branch", "bank", "transfer", "neft", "rtgs", "imps",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			if isKnownBank {
				return true, 0.98
			}
			return true, 0.9
		}
	}

	if isKnownBank {
		return true, 0.85
	}

	return true, 0.7
}

// validateIndianBankAccount validates Indian bank account numbers
func validateIndianBankAccount(match string, context string) (bool, float64) {
	// Indian bank accounts are 9-18 digits
	if len(match) < 9 || len(match) > 18 {
		return false, 0
	}

	// All digits
	for _, ch := range match {
		if !unicode.IsDigit(ch) {
			return false, 0
		}
	}

	// Check for repeated patterns (likely not a real account)
	if isRepeatedPattern(match) {
		return false, 0.2
	}

	// Context is crucial for bank account detection
	contextLower := strings.ToLower(context)

	// Must have bank-related context for high confidence
	positiveIndicators := []string{
		"account", "a/c", "acc no", "acct", "bank",
		"savings", "current", "deposit", "ifsc", "neft", "rtgs",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.9
		}
	}

	// Without bank context, could be phone number, order ID, etc.
	return true, 0.4
}

// validateGSTIN validates GSTIN format
func validateGSTIN(match string, context string) (bool, float64) {
	if len(match) != 15 {
		return false, 0
	}

	// Structure: 2 digits (state) + PAN + entity + Z + checksum
	stateCode, err := strconv.Atoi(match[0:2])
	if err != nil || stateCode < 1 || stateCode > 37 {
		return false, 0
	}

	// Check embedded PAN structure (characters 3-12) - simplified check, no validator call
	panPart := match[2:12]
	if len(panPart) != 10 {
		return false, 0
	}
	// Check PAN structure: AAAAA0000A
	for i := 0; i < 5; i++ {
		if !unicode.IsLetter(rune(panPart[i])) {
			return false, 0
		}
	}
	for i := 5; i < 9; i++ {
		if !unicode.IsDigit(rune(panPart[i])) {
			return false, 0
		}
	}
	if !unicode.IsLetter(rune(panPart[9])) {
		return false, 0
	}

	// 14th character (index 13) should be 'Z'
	if match[13] != 'Z' {
		return false, 0
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	positiveIndicators := []string{
		"gst", "gstin", "goods and service", "tax", "invoice",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.95
		}
	}

	return true, 0.85
}

// validateVoterID validates Voter ID (EPIC) format
func validateVoterID(match string, context string) (bool, float64) {
	if len(match) != 10 {
		return false, 0
	}

	// 3 letters + 7 digits
	for i := 0; i < 3; i++ {
		if !unicode.IsLetter(rune(match[i])) {
			return false, 0
		}
	}
	for i := 3; i < 10; i++ {
		if !unicode.IsDigit(rune(match[i])) {
			return false, 0
		}
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	positiveIndicators := []string{
		"voter", "epic", "election", "eci", "electoral",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.95
		}
	}

	return true, 0.6
}

// validateIndianDrivingLicense validates Indian driving license format
func validateIndianDrivingLicense(match string, context string) (bool, float64) {
	// Basic length check
	cleanMatch := strings.ReplaceAll(strings.ReplaceAll(match, "-", ""), " ", "")
	if len(cleanMatch) < 15 || len(cleanMatch) > 16 {
		return false, 0
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	positiveIndicators := []string{
		"driving", "license", "licence", "dl", "rto",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.9
		}
	}

	return true, 0.5
}

// validateIndianPassport validates Indian passport format
func validateIndianPassport(match string, context string) (bool, float64) {
	if len(match) != 8 {
		return false, 0
	}

	// 1 letter + 7 digits
	if !unicode.IsLetter(rune(match[0])) {
		return false, 0
	}
	for i := 1; i < 8; i++ {
		if !unicode.IsDigit(rune(match[i])) {
			return false, 0
		}
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	positiveIndicators := []string{
		"passport", "travel document", "visa",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.95
		}
	}

	return true, 0.5
}

// validateIndianPhone validates Indian phone numbers
func validateIndianPhone(match string, context string) (bool, float64) {
	// Remove prefix and separators
	clean := strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, match)

	// Remove country code if present
	if strings.HasPrefix(clean, "91") && len(clean) == 12 {
		clean = clean[2:]
	}
	if strings.HasPrefix(clean, "0") && len(clean) == 11 {
		clean = clean[1:]
	}

	if len(clean) != 10 {
		return false, 0
	}

	// Must start with 6-9
	firstDigit := clean[0]
	if firstDigit < '6' || firstDigit > '9' {
		return false, 0
	}

	// Check for repeated patterns
	if isRepeatedPattern(clean) {
		return false, 0.2
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	positiveIndicators := []string{
		"phone", "mobile", "contact", "call", "whatsapp", "sms",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.95
		}
	}

	return true, 0.8
}

// validatePincode validates Indian pincode
func validatePincode(match string, context string) (bool, float64) {
	if len(match) != 6 {
		return false, 0
	}

	// First digit cannot be 0
	if match[0] == '0' {
		return false, 0
	}

	// All must be digits
	for _, ch := range match {
		if !unicode.IsDigit(ch) {
			return false, 0
		}
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	positiveIndicators := []string{
		"pin", "pincode", "postal", "zip", "address",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.9
		}
	}

	return true, 0.5
}

// =============================================================================
// Utility Functions
// =============================================================================

// isRepeatedPattern checks if a string has suspicious repeated patterns
func isRepeatedPattern(s string) bool {
	if len(s) < 4 {
		return false
	}

	// Check all same digit
	first := rune(s[0])
	allSame := true
	for _, ch := range s {
		if ch != first {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}

	// Check sequential patterns like 12345678
	isSequential := true
	for i := 1; i < len(s); i++ {
		if s[i] != s[i-1]+1 {
			isSequential = false
			break
		}
	}
	if isSequential {
		return true
	}

	return false
}

// maskIndiaPII masks sensitive data for logging/display
func maskIndiaPII(value string, piiType IndiaPIIType) string {
	switch piiType {
	case IndiaPIITypeUPI:
		// Show first 3 chars and domain: "abc@ybl" -> "abc***@ybl"
		parts := strings.Split(value, "@")
		if len(parts) == 2 {
			username := parts[0]
			if len(username) <= 3 {
				return username + "***@" + parts[1]
			}
			return username[:3] + "***@" + parts[1]
		}
		return "***"
	case IndiaPIITypeAadhaar:
		// Show last 4: "1234 5678 9012" -> "XXXX XXXX 9012"
		clean := strings.ReplaceAll(strings.ReplaceAll(value, " ", ""), "-", "")
		if len(clean) >= 4 {
			return "XXXX XXXX " + clean[len(clean)-4:]
		}
		return "XXXX XXXX XXXX"
	case IndiaPIITypePAN:
		// Show first 2 and last 2: "ABCDE1234F" -> "AB******4F"
		if len(value) == 10 {
			return value[:2] + "******" + value[8:]
		}
		return "**********"
	case IndiaPIITypeIndianPhone:
		// Show last 4: "+91 9876543210" -> "+91 XXXXXX3210"
		clean := strings.Map(func(r rune) rune {
			if unicode.IsDigit(r) {
				return r
			}
			return -1
		}, value)
		if len(clean) >= 4 {
			return "XXXXXX" + clean[len(clean)-4:]
		}
		return "XXXXXXXXXX"
	case IndiaPIITypeBankAccount:
		// Show last 4
		if len(value) >= 4 {
			return strings.Repeat("X", len(value)-4) + value[len(value)-4:]
		}
		return strings.Repeat("X", len(value))
	default:
		// Default: mask middle portion
		if len(value) <= 4 {
			return strings.Repeat("*", len(value))
		}
		return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
	}
}

// FilterBySeverity filters results by minimum severity
func FilterIndiaPIIBySeverity(results []IndiaPIIDetectionResult, minSeverity IndiaPIISeverity) []IndiaPIIDetectionResult {
	severityOrder := map[IndiaPIISeverity]int{
		IndiaPIISeverityLow:      1,
		IndiaPIISeverityMedium:   2,
		IndiaPIISeverityHigh:     3,
		IndiaPIISeverityCritical: 4,
	}

	minLevel := severityOrder[minSeverity]
	var filtered []IndiaPIIDetectionResult

	for _, r := range results {
		if severityOrder[r.Severity] >= minLevel {
			filtered = append(filtered, r)
		}
	}

	return filtered
}

// FilterByConfidence filters results by minimum confidence
func FilterIndiaPIIByConfidence(results []IndiaPIIDetectionResult, minConfidence float64) []IndiaPIIDetectionResult {
	var filtered []IndiaPIIDetectionResult
	for _, r := range results {
		if r.Confidence >= minConfidence {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// GetCriticalFinancialPII returns only critical financial PII (UPI, Aadhaar, PAN, Bank accounts)
func GetCriticalFinancialPII(results []IndiaPIIDetectionResult) []IndiaPIIDetectionResult {
	criticalTypes := map[IndiaPIIType]bool{
		IndiaPIITypeUPI:         true,
		IndiaPIITypeAadhaar:     true,
		IndiaPIITypePAN:         true,
		IndiaPIITypeBankAccount: true,
	}

	var filtered []IndiaPIIDetectionResult
	for _, r := range results {
		if criticalTypes[r.Type] {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
