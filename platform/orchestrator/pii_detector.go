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

package orchestrator

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// PIIType represents different categories of personally identifiable information
type PIIType string

const (
	PIITypeSSN           PIIType = "ssn"
	PIITypeCreditCard    PIIType = "credit_card"
	PIITypeEmail         PIIType = "email"
	PIITypePhone         PIIType = "phone"
	PIITypeIPAddress     PIIType = "ip_address"
	PIITypeBankAccount   PIIType = "bank_account"
	PIITypeIBAN          PIIType = "iban"
	PIITypePassport      PIIType = "passport"
	PIITypeDateOfBirth   PIIType = "date_of_birth"
	PIITypeDriverLicense PIIType = "driver_license"
	PIITypeAddress       PIIType = "address"
	PIITypeName          PIIType = "name"
)

// PIISeverity represents the risk level of detected PII
type PIISeverity string

const (
	PIISeverityLow      PIISeverity = "low"
	PIISeverityMedium   PIISeverity = "medium"
	PIISeverityHigh     PIISeverity = "high"
	PIISeverityCritical PIISeverity = "critical"
)

// PIIDetectionResult represents a single PII detection
type PIIDetectionResult struct {
	Type       PIIType     `json:"type"`
	Value      string      `json:"value"`
	Severity   PIISeverity `json:"severity"`
	Confidence float64     `json:"confidence"` // 0.0 to 1.0
	StartIndex int         `json:"start_index"`
	EndIndex   int         `json:"end_index"`
	Context    string      `json:"context,omitempty"` // Surrounding text for context
}

// PIIPattern represents a compiled pattern for PII detection
type PIIPattern struct {
	Type       PIIType
	Pattern    *regexp.Regexp
	Severity   PIISeverity
	Validator  func(match string, context string) (bool, float64) // Returns (isValid, confidence)
	MinLength  int
	MaxLength  int
}

// EnhancedPIIDetector provides comprehensive PII detection with validation
type EnhancedPIIDetector struct {
	patterns        []*PIIPattern
	contextWindow   int // Characters around match to include for context
	minConfidence   float64
	enableValidation bool
}

// PIIDetectorConfig configures the PII detector behavior
type PIIDetectorConfig struct {
	ContextWindow    int
	MinConfidence    float64
	EnableValidation bool
	EnabledTypes     []PIIType // Empty means all types enabled
}

// DefaultPIIDetectorConfig returns sensible defaults
func DefaultPIIDetectorConfig() PIIDetectorConfig {
	return PIIDetectorConfig{
		ContextWindow:    50,
		MinConfidence:    0.5,
		EnableValidation: true,
		EnabledTypes:     nil, // All types enabled
	}
}

// NewEnhancedPIIDetector creates a new enhanced PII detector
func NewEnhancedPIIDetector(config PIIDetectorConfig) *EnhancedPIIDetector {
	detector := &EnhancedPIIDetector{
		contextWindow:    config.ContextWindow,
		minConfidence:    config.MinConfidence,
		enableValidation: config.EnableValidation,
	}
	detector.loadPatterns(config.EnabledTypes)
	return detector
}

// loadPatterns initializes all PII detection patterns
func (d *EnhancedPIIDetector) loadPatterns(enabledTypes []PIIType) {
	allPatterns := []*PIIPattern{
		// SSN - US Social Security Number
		{
			Type:      PIITypeSSN,
			Pattern:   regexp.MustCompile(`\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b`),
			Severity:  PIISeverityCritical,
			Validator: validateSSN,
			MinLength: 9,
			MaxLength: 11,
		},
		// Credit Card - Major card networks with Luhn validation
		{
			Type: PIITypeCreditCard,
			// Visa, MasterCard, Amex, Discover, Diners, JCB
			Pattern:   regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b|\b(\d{4})[- ]?(\d{4})[- ]?(\d{4})[- ]?(\d{4})\b`),
			Severity:  PIISeverityCritical,
			Validator: validateCreditCard,
			MinLength: 13,
			MaxLength: 19,
		},
		// Email - RFC 5322 compliant
		{
			Type:      PIITypeEmail,
			Pattern:   regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
			Severity:  PIISeverityMedium,
			Validator: validateEmail,
			MinLength: 5,
			MaxLength: 254,
		},
		// Phone - US and international formats
		{
			Type:      PIITypePhone,
			Pattern:   regexp.MustCompile(`(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}\b|\+[0-9]{1,3}[-.\s]?[0-9]{6,14}\b`),
			Severity:  PIISeverityMedium,
			Validator: validatePhone,
			MinLength: 7,
			MaxLength: 20,
		},
		// IP Address - IPv4 with validation
		{
			Type:      PIITypeIPAddress,
			Pattern:   regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
			Severity:  PIISeverityMedium,
			Validator: validateIPAddress,
			MinLength: 7,
			MaxLength: 15,
		},
		// IBAN - International Bank Account Number
		{
			Type:      PIITypeIBAN,
			Pattern:   regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b`),
			Severity:  PIISeverityCritical,
			Validator: validateIBAN,
			MinLength: 15,
			MaxLength: 34,
		},
		// Passport - Multiple country formats
		{
			Type:      PIITypePassport,
			Pattern:   regexp.MustCompile(`\b[A-Z]{1,2}[0-9]{6,9}\b`),
			Severity:  PIISeverityHigh,
			Validator: validatePassport,
			MinLength: 7,
			MaxLength: 11,
		},
		// Date of Birth - Multiple formats
		{
			Type:      PIITypeDateOfBirth,
			Pattern:   regexp.MustCompile(`\b(?:(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12][0-9]|3[01])[/\-](?:19|20)\d{2}|(?:19|20)\d{2}[/\-](?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12][0-9]|3[01]))\b`),
			Severity:  PIISeverityHigh,
			Validator: validateDateOfBirth,
			MinLength: 8,
			MaxLength: 10,
		},
		// Driver's License - US state formats (simplified)
		{
			Type:      PIITypeDriverLicense,
			Pattern:   regexp.MustCompile(`\b[A-Z][0-9]{7,14}\b|\b[0-9]{7,9}\b`),
			Severity:  PIISeverityHigh,
			Validator: validateDriverLicense,
			MinLength: 7,
			MaxLength: 15,
		},
		// Bank Account - US routing + account
		{
			Type:      PIITypeBankAccount,
			Pattern:   regexp.MustCompile(`\b[0-9]{9}[- ]?[0-9]{8,17}\b`),
			Severity:  PIISeverityCritical,
			Validator: validateBankAccount,
			MinLength: 17,
			MaxLength: 27,
		},
	}

	// Filter by enabled types if specified
	if len(enabledTypes) > 0 {
		enabledMap := make(map[PIIType]bool)
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

// DetectAll scans text for all types of PII
func (d *EnhancedPIIDetector) DetectAll(text string) []PIIDetectionResult {
	var results []PIIDetectionResult

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

			results = append(results, PIIDetectionResult{
				Type:       pattern.Type,
				Value:      matchedText,
				Severity:   pattern.Severity,
				Confidence: confidence,
				StartIndex: startIdx,
				EndIndex:   endIdx,
				Context:    context,
			})
		}
	}

	return results
}

// DetectType scans text for a specific type of PII
func (d *EnhancedPIIDetector) DetectType(text string, piiType PIIType) []PIIDetectionResult {
	var results []PIIDetectionResult

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

			results = append(results, PIIDetectionResult{
				Type:       pattern.Type,
				Value:      matchedText,
				Severity:   pattern.Severity,
				Confidence: confidence,
				StartIndex: startIdx,
				EndIndex:   endIdx,
				Context:    context,
			})
		}
	}

	return results
}

// HasPII quickly checks if text contains any PII
func (d *EnhancedPIIDetector) HasPII(text string) bool {
	for _, pattern := range d.patterns {
		if pattern.Pattern.MatchString(text) {
			// Quick validation for high-confidence patterns
			matches := pattern.Pattern.FindAllString(text, 1)
			if len(matches) > 0 {
				if pattern.Validator != nil {
					isValid, _ := pattern.Validator(matches[0], "")
					if isValid {
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

// extractContext extracts surrounding text for context analysis
func (d *EnhancedPIIDetector) extractContext(text string, start, end int) string {
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
func (d *EnhancedPIIDetector) GetPatternStats() map[string]interface{} {
	typeCount := make(map[PIIType]int)
	severityCount := make(map[PIISeverity]int)

	for _, p := range d.patterns {
		typeCount[p.Type]++
		severityCount[p.Severity]++
	}

	return map[string]interface{}{
		"total_patterns":   len(d.patterns),
		"types":            typeCount,
		"severities":       severityCount,
		"validation":       d.enableValidation,
		"min_confidence":   d.minConfidence,
		"context_window":   d.contextWindow,
	}
}

// =============================================================================
// Validators - Each returns (isValid, confidence)
// =============================================================================

// validateSSN validates US Social Security Numbers
// SSN cannot start with 000, 666, or 900-999
// Cannot have 00 in middle group or 0000 in last group
func validateSSN(match string, context string) (bool, float64) {
	// Remove separators
	clean := strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, match)

	if len(clean) != 9 {
		return false, 0
	}

	// Parse components
	area, _ := strconv.Atoi(clean[0:3])
	group, _ := strconv.Atoi(clean[3:5])
	serial, _ := strconv.Atoi(clean[5:9])

	// Invalid area numbers
	if area == 0 || area == 666 || area >= 900 {
		return false, 0
	}

	// Invalid group or serial
	if group == 0 || serial == 0 {
		return false, 0
	}

	// Context analysis for false positive reduction
	contextLower := strings.ToLower(context)

	// Negative indicators (reduce confidence)
	negativeIndicators := []string{
		"order", "invoice", "ref", "reference", "tracking",
		"confirmation", "booking", "receipt", "po ", "purchase",
		"item", "product", "sku", "model", "serial number",
		"case ", "ticket", "id:", "account #",
	}

	for _, indicator := range negativeIndicators {
		if strings.Contains(contextLower, indicator) {
			return false, 0.3 // Low confidence, likely not an SSN
		}
	}

	// Positive indicators (increase confidence)
	positiveIndicators := []string{
		"ssn", "social security", "social sec", "ss#", "ss #",
		"taxpayer", "tin", "tax id",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.95
		}
	}

	return true, 0.7 // Valid format but no strong context
}

// validateCreditCard validates credit card numbers using Luhn algorithm
func validateCreditCard(match string, context string) (bool, float64) {
	// Remove separators
	clean := strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, match)

	if len(clean) < 13 || len(clean) > 19 {
		return false, 0
	}

	// Luhn algorithm
	if !luhnCheck(clean) {
		return false, 0
	}

	// Identify card type and validate prefix
	cardType := identifyCardType(clean)
	if cardType == "" {
		return false, 0.5 // Passes Luhn but unknown card type
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	// Negative indicators
	negativeIndicators := []string{
		"phone", "fax", "tel:", "call", "mobile",
	}

	for _, indicator := range negativeIndicators {
		if strings.Contains(contextLower, indicator) {
			return false, 0.2
		}
	}

	// Positive indicators
	positiveIndicators := []string{
		"card", "credit", "debit", "visa", "mastercard", "amex",
		"american express", "discover", "payment", "cc#", "cc #",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.95
		}
	}

	return true, 0.85 // Valid Luhn and known card type
}

// luhnCheck performs the Luhn algorithm check
func luhnCheck(number string) bool {
	sum := 0
	alternate := false

	for i := len(number) - 1; i >= 0; i-- {
		digit, _ := strconv.Atoi(string(number[i]))

		if alternate {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}

		sum += digit
		alternate = !alternate
	}

	return sum%10 == 0
}

// identifyCardType identifies the card network from the number prefix
func identifyCardType(number string) string {
	if len(number) < 2 {
		return ""
	}

	prefix1, _ := strconv.Atoi(string(number[0]))
	prefix2, _ := strconv.Atoi(number[0:2])

	// Check JCB first (3528-3589) before Diners (30-35) to avoid overlap
	if len(number) >= 4 {
		prefix4, _ := strconv.Atoi(number[0:4])
		if prefix4 >= 3528 && prefix4 <= 3589 {
			return "jcb"
		}
		if prefix4 == 6011 || (prefix2 >= 64 && prefix2 <= 65) {
			return "discover"
		}
	}

	switch {
	case prefix1 == 4:
		return "visa"
	case prefix2 >= 51 && prefix2 <= 55:
		return "mastercard"
	case prefix2 >= 22 && prefix2 <= 27: // Mastercard 2-series
		return "mastercard"
	case prefix2 == 34 || prefix2 == 37:
		return "amex"
	case prefix2 == 36 || prefix2 == 38 || (prefix2 >= 30 && prefix2 <= 35):
		return "diners"
	}

	return ""
}

// validateEmail validates email format
func validateEmail(match string, context string) (bool, float64) {
	// Basic structure check
	atIndex := strings.LastIndex(match, "@")
	if atIndex < 1 || atIndex >= len(match)-4 {
		return false, 0
	}

	domain := match[atIndex+1:]

	// Must have at least one dot in domain
	if !strings.Contains(domain, ".") {
		return false, 0
	}

	// TLD must be at least 2 characters
	lastDot := strings.LastIndex(domain, ".")
	if len(domain)-lastDot-1 < 2 {
		return false, 0
	}

	// Check for common invalid patterns
	if strings.Contains(match, "..") || strings.HasPrefix(match, ".") {
		return false, 0
	}

	// Common disposable/test email patterns reduce confidence
	disposablePatterns := []string{
		"example.com", "test.com", "localhost", "mailinator",
		"guerrillamail", "tempmail", "throwaway",
	}

	for _, pattern := range disposablePatterns {
		if strings.Contains(strings.ToLower(domain), pattern) {
			return true, 0.5 // Valid but likely test/disposable
		}
	}

	return true, 0.9
}

// validatePhone validates phone number formats
func validatePhone(match string, context string) (bool, float64) {
	// Remove non-digits
	digits := strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, match)

	// US phone should have 10-11 digits (11 with country code)
	// International can have 7-15 digits
	if len(digits) < 7 || len(digits) > 15 {
		return false, 0
	}

	// Check for repeated digits (unlikely to be real phone)
	if isRepeatedDigits(digits) {
		return false, 0.1
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	// Negative indicators
	negativeIndicators := []string{
		"zip", "postal", "code", "year", "date", "amount",
		"price", "total", "quantity", "qty",
	}

	for _, indicator := range negativeIndicators {
		if strings.Contains(contextLower, indicator) {
			return false, 0.2
		}
	}

	// Positive indicators
	positiveIndicators := []string{
		"phone", "tel", "call", "mobile", "cell", "fax",
		"contact", "reach", "dial",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.95
		}
	}

	return true, 0.7
}

// validateIPAddress validates IPv4 addresses
func validateIPAddress(match string, context string) (bool, float64) {
	parts := strings.Split(match, ".")
	if len(parts) != 4 {
		return false, 0
	}

	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false, 0
		}
	}

	// Check for special addresses (reduce PII concern)
	if match == "0.0.0.0" || match == "255.255.255.255" ||
		strings.HasPrefix(match, "127.") || strings.HasPrefix(match, "192.168.") ||
		strings.HasPrefix(match, "10.") || strings.HasPrefix(match, "172.") {
		return true, 0.5 // Valid but likely not personal PII
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	// Version number patterns (e.g., "version 1.2.3.4")
	if strings.Contains(contextLower, "version") || strings.Contains(contextLower, "v.") {
		return false, 0.1
	}

	return true, 0.8
}

// validateIBAN validates International Bank Account Numbers
func validateIBAN(match string, context string) (bool, float64) {
	// Remove spaces
	clean := strings.ReplaceAll(strings.ToUpper(match), " ", "")

	if len(clean) < 15 || len(clean) > 34 {
		return false, 0
	}

	// Check country code (first 2 chars must be letters)
	if !unicode.IsLetter(rune(clean[0])) || !unicode.IsLetter(rune(clean[1])) {
		return false, 0
	}

	// IBAN checksum validation (MOD 97)
	if !validateIBANChecksum(clean) {
		return false, 0
	}

	return true, 0.9
}

// validateIBANChecksum validates IBAN using MOD 97 algorithm
func validateIBANChecksum(iban string) bool {
	// Move first 4 characters to end
	rearranged := iban[4:] + iban[0:4]

	// Convert letters to numbers (A=10, B=11, ..., Z=35)
	var numericStr strings.Builder
	for _, ch := range rearranged {
		if unicode.IsLetter(ch) {
			numericStr.WriteString(strconv.Itoa(int(unicode.ToUpper(ch) - 'A' + 10)))
		} else {
			numericStr.WriteRune(ch)
		}
	}

	// MOD 97 on the numeric string
	numeric := numericStr.String()
	var remainder int
	for _, digit := range numeric {
		remainder = (remainder*10 + int(digit-'0')) % 97
	}

	return remainder == 1
}

// validatePassport validates passport number formats
func validatePassport(match string, context string) (bool, float64) {
	// Basic length check
	if len(match) < 7 || len(match) > 11 {
		return false, 0
	}

	// Check format: 1-2 letters followed by 6-9 digits
	letterCount := 0
	digitCount := 0

	for i, ch := range match {
		if unicode.IsLetter(ch) {
			if i > 1 { // Letters should only be at start
				return false, 0
			}
			letterCount++
		} else if unicode.IsDigit(ch) {
			digitCount++
		} else {
			return false, 0 // Invalid character
		}
	}

	if letterCount < 1 || letterCount > 2 || digitCount < 6 {
		return false, 0
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	// Positive indicators
	positiveIndicators := []string{
		"passport", "travel document", "travel doc",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.95
		}
	}

	// Without context, could be many things (order numbers, etc.)
	return true, 0.5
}

// validateDateOfBirth validates date formats that could be DOB
func validateDateOfBirth(match string, context string) (bool, float64) {
	// Parse the date to check validity
	// This is a simplified check - full validation would need date parsing

	// Context is crucial for DOB
	contextLower := strings.ToLower(context)

	// Positive indicators
	positiveIndicators := []string{
		"dob", "date of birth", "birth date", "birthday", "born",
		"birthdate", "d.o.b",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.95
		}
	}

	// Without DOB context, treat as regular date (lower PII concern)
	return true, 0.4
}

// validateDriverLicense validates driver's license formats
func validateDriverLicense(match string, context string) (bool, float64) {
	// Very loose validation as formats vary widely by state
	if len(match) < 7 || len(match) > 15 {
		return false, 0
	}

	// Context is crucial
	contextLower := strings.ToLower(context)

	// Positive indicators
	positiveIndicators := []string{
		"driver", "license", "dl", "driving", "dmv",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.9
		}
	}

	// Without context, could be many things
	return true, 0.3
}

// validateBankAccount validates US bank routing + account format
func validateBankAccount(match string, context string) (bool, float64) {
	// Remove separators
	clean := strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, match)

	if len(clean) < 17 || len(clean) > 26 {
		return false, 0
	}

	// First 9 digits should be routing number
	routing := clean[0:9]

	// Validate ABA routing number checksum
	if !validateABARoutingNumber(routing) {
		return false, 0.3 // Might still be bank account, just different format
	}

	// Context analysis
	contextLower := strings.ToLower(context)

	positiveIndicators := []string{
		"routing", "account", "bank", "aba", "ach", "wire",
	}

	for _, indicator := range positiveIndicators {
		if strings.Contains(contextLower, indicator) {
			return true, 0.95
		}
	}

	return true, 0.7
}

// validateABARoutingNumber validates US ABA routing number checksum
func validateABARoutingNumber(routing string) bool {
	if len(routing) != 9 {
		return false
	}

	// Reject all-zeros (invalid routing number)
	if routing == "000000000" {
		return false
	}

	// Checksum: 3*(d1+d4+d7) + 7*(d2+d5+d8) + 1*(d3+d6+d9) mod 10 = 0
	weights := []int{3, 7, 1, 3, 7, 1, 3, 7, 1}
	sum := 0

	for i, ch := range routing {
		digit := int(ch - '0')
		sum += digit * weights[i]
	}

	return sum%10 == 0
}

// isRepeatedDigits checks if a string is all the same digit
func isRepeatedDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	first := rune(s[0])
	for _, ch := range s {
		if ch != first {
			return false
		}
	}
	return true
}

// =============================================================================
// Utility Functions for Integration
// =============================================================================

// ConvertToLegacyFormat converts new detection results to legacy map format
func ConvertToLegacyFormat(results []PIIDetectionResult) map[string][]string {
	legacy := make(map[string][]string)
	for _, r := range results {
		legacy[string(r.Type)] = append(legacy[string(r.Type)], r.Value)
	}
	return legacy
}

// FilterBySeverity filters results by minimum severity
func FilterBySeverity(results []PIIDetectionResult, minSeverity PIISeverity) []PIIDetectionResult {
	severityOrder := map[PIISeverity]int{
		PIISeverityLow:      1,
		PIISeverityMedium:   2,
		PIISeverityHigh:     3,
		PIISeverityCritical: 4,
	}

	minLevel := severityOrder[minSeverity]
	var filtered []PIIDetectionResult

	for _, r := range results {
		if severityOrder[r.Severity] >= minLevel {
			filtered = append(filtered, r)
		}
	}

	return filtered
}

// FilterByConfidence filters results by minimum confidence
func FilterByConfidence(results []PIIDetectionResult, minConfidence float64) []PIIDetectionResult {
	var filtered []PIIDetectionResult
	for _, r := range results {
		if r.Confidence >= minConfidence {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
