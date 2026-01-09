package policy

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Built-in validators for semantic PII validation beyond regex matching.
// These improve accuracy by checking checksums and format rules.

// ValidateCreditCard validates credit card numbers using the Luhn algorithm.
// Returns (valid, confidence) where confidence is based on format and context.
func ValidateCreditCard(match string, context string) (bool, float64) {
	// Remove separators
	digits := extractDigits(match)

	// Must be 13-19 digits
	if len(digits) < 13 || len(digits) > 19 {
		return false, 0
	}

	// Luhn algorithm check
	if !luhnCheck(digits) {
		return false, 0
	}

	// Calculate confidence based on context
	confidence := 0.8 // Base confidence for valid Luhn

	// Positive indicators increase confidence
	lowerContext := strings.ToLower(context)
	positiveIndicators := []string{
		"card", "credit", "debit", "payment", "visa", "mastercard", "amex",
		"american express", "discover", "jcb", "diners", "cc", "cvv", "expir",
	}
	for _, indicator := range positiveIndicators {
		if strings.Contains(lowerContext, indicator) {
			confidence = 0.95
			break
		}
	}

	// Negative indicators decrease confidence
	negativeIndicators := []string{
		"phone", "fax", "tel", "id", "order", "invoice", "tracking", "reference",
	}
	for _, indicator := range negativeIndicators {
		if strings.Contains(lowerContext, indicator) {
			confidence -= 0.2
			break
		}
	}

	if confidence < 0.5 {
		confidence = 0.5 // Minimum confidence for valid Luhn
	}

	return true, confidence
}

// luhnCheck implements the Luhn algorithm for credit card validation.
func luhnCheck(digits string) bool {
	sum := 0
	isSecond := false

	// Process from right to left
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')

		if isSecond {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}

		sum += d
		isSecond = !isSecond
	}

	return sum%10 == 0
}

// ValidateSSN validates US Social Security Numbers.
// Returns (valid, confidence) based on SSN format rules and context.
func ValidateSSN(match string, context string) (bool, float64) {
	// Remove separators
	digits := extractDigits(match)

	if len(digits) != 9 {
		return false, 0
	}

	// Extract parts
	area, _ := strconv.Atoi(digits[0:3])
	group, _ := strconv.Atoi(digits[3:5])
	serial, _ := strconv.Atoi(digits[5:9])

	// Invalid area numbers (SSA rules)
	// 000, 666, 900-999 are invalid
	if area == 0 || area == 666 || (area >= 900 && area <= 999) {
		return false, 0
	}

	// Group number cannot be 00
	if group == 0 {
		return false, 0
	}

	// Serial number cannot be 0000
	if serial == 0 {
		return false, 0
	}

	// Calculate confidence based on context
	confidence := 0.6 // Base confidence

	lowerContext := strings.ToLower(context)

	// Strong positive indicators
	strongPositive := []string{"ssn", "social security", "tax id", "taxpayer"}
	for _, indicator := range strongPositive {
		if strings.Contains(lowerContext, indicator) {
			confidence = 0.95
			break
		}
	}

	// Weak positive indicators
	weakPositive := []string{"employee", "applicant", "patient", "member"}
	for _, indicator := range weakPositive {
		if strings.Contains(lowerContext, indicator) {
			if confidence < 0.8 {
				confidence = 0.8
			}
			break
		}
	}

	// Negative indicators
	negativeIndicators := []string{
		"order", "invoice", "tracking", "reference", "phone", "zip", "postal",
		"account", "routing", "sku", "product", "item",
	}
	for _, indicator := range negativeIndicators {
		if strings.Contains(lowerContext, indicator) {
			confidence -= 0.3
			break
		}
	}

	if confidence <= 0.3 {
		return false, 0 // Too likely to be false positive
	}

	return true, confidence
}

// ValidateIBAN validates International Bank Account Numbers using MOD 97.
func ValidateIBAN(match string, context string) (bool, float64) {
	// Remove spaces and convert to uppercase
	iban := strings.ToUpper(strings.ReplaceAll(match, " ", ""))

	// Must be 15-34 characters
	if len(iban) < 15 || len(iban) > 34 {
		return false, 0
	}

	// First two characters must be letters (country code)
	if !unicode.IsLetter(rune(iban[0])) || !unicode.IsLetter(rune(iban[1])) {
		return false, 0
	}

	// Characters 3-4 must be digits (check digits)
	if !unicode.IsDigit(rune(iban[2])) || !unicode.IsDigit(rune(iban[3])) {
		return false, 0
	}

	// MOD 97 check
	// Move first 4 characters to end
	rearranged := iban[4:] + iban[0:4]

	// Convert letters to numbers (A=10, B=11, ..., Z=35)
	var numeric strings.Builder
	for _, c := range rearranged {
		if unicode.IsLetter(c) {
			numeric.WriteString(strconv.Itoa(int(c - 'A' + 10)))
		} else {
			numeric.WriteRune(c)
		}
	}

	// Calculate modulo 97
	remainder := mod97(numeric.String())
	if remainder != 1 {
		return false, 0
	}

	// Calculate confidence
	confidence := 0.9 // High confidence for valid MOD 97

	lowerContext := strings.ToLower(context)
	if strings.Contains(lowerContext, "iban") || strings.Contains(lowerContext, "bank") ||
		strings.Contains(lowerContext, "account") || strings.Contains(lowerContext, "transfer") {
		confidence = 0.95
	}

	return true, confidence
}

// mod97 calculates number mod 97 for large numbers represented as strings.
func mod97(numStr string) int {
	remainder := 0
	for _, c := range numStr {
		digit := int(c - '0')
		remainder = (remainder*10 + digit) % 97
	}
	return remainder
}

// ValidateAadhaar validates Indian Aadhaar numbers.
// Note: Full Verhoeff checksum requires the lookup tables.
func ValidateAadhaar(match string, context string) (bool, float64) {
	// Remove spaces
	digits := extractDigits(match)

	// Must be exactly 12 digits
	if len(digits) != 12 {
		return false, 0
	}

	// First digit must be 2-9 (never 0 or 1)
	if digits[0] < '2' || digits[0] > '9' {
		return false, 0
	}

	// Check for obviously invalid patterns (all same digit)
	if allSameDigit(digits) {
		return false, 0
	}

	// Calculate confidence
	confidence := 0.7

	lowerContext := strings.ToLower(context)
	positiveIndicators := []string{"aadhaar", "aadhar", "uid", "uidai", "unique id"}
	for _, indicator := range positiveIndicators {
		if strings.Contains(lowerContext, indicator) {
			confidence = 0.95
			break
		}
	}

	// Negative indicators (might be credit card or other number)
	negativeIndicators := []string{"card", "credit", "phone", "mobile"}
	for _, indicator := range negativeIndicators {
		if strings.Contains(lowerContext, indicator) {
			confidence -= 0.2
			break
		}
	}

	if confidence < 0.5 {
		confidence = 0.5
	}

	return true, confidence
}

// ValidatePAN validates Indian Permanent Account Numbers (tax ID).
func ValidatePAN(match string, context string) (bool, float64) {
	// Must be exactly 10 characters
	pan := strings.ToUpper(strings.TrimSpace(match))
	if len(pan) != 10 {
		return false, 0
	}

	// Format: AAAAA9999A
	// First 3: letters
	// 4th: entity type (P, C, H, A, B, G, J, L, F, T)
	// 5th: letter
	// 6-9: digits
	// 10th: letter (check digit)

	for i := 0; i < 3; i++ {
		if !unicode.IsLetter(rune(pan[i])) {
			return false, 0
		}
	}

	// 4th character must be valid entity type
	entityTypes := "PCHABGJLFT"
	if !strings.ContainsRune(entityTypes, rune(pan[3])) {
		return false, 0
	}

	if !unicode.IsLetter(rune(pan[4])) {
		return false, 0
	}

	for i := 5; i < 9; i++ {
		if !unicode.IsDigit(rune(pan[i])) {
			return false, 0
		}
	}

	if !unicode.IsLetter(rune(pan[9])) {
		return false, 0
	}

	// Calculate confidence
	confidence := 0.8

	lowerContext := strings.ToLower(context)
	positiveIndicators := []string{"pan", "income tax", "tax id", "permanent account"}
	for _, indicator := range positiveIndicators {
		if strings.Contains(lowerContext, indicator) {
			confidence = 0.95
			break
		}
	}

	return true, confidence
}

// ValidateEmail validates email addresses.
func ValidateEmail(match string, context string) (bool, float64) {
	// Basic format validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(match) {
		return false, 0
	}

	// Check for disposable email domains (lower confidence)
	disposableDomains := []string{
		"tempmail", "throwaway", "guerrillamail", "10minutemail", "mailinator",
	}
	lowerMatch := strings.ToLower(match)
	isDisposable := false
	for _, domain := range disposableDomains {
		if strings.Contains(lowerMatch, domain) {
			isDisposable = true
			break
		}
	}

	confidence := 0.8
	if isDisposable {
		confidence = 0.6
	}

	// Context analysis
	lowerContext := strings.ToLower(context)
	if strings.Contains(lowerContext, "email") || strings.Contains(lowerContext, "contact") ||
		strings.Contains(lowerContext, "address") {
		confidence += 0.1
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return true, confidence
}

// ValidatePhone validates phone numbers.
func ValidatePhone(match string, context string) (bool, float64) {
	// Extract digits
	digits := extractDigits(match)

	// Must be 7-15 digits
	if len(digits) < 7 || len(digits) > 15 {
		return false, 0
	}

	// Check for repeated digits (likely not a real phone number)
	if allSameDigit(digits) {
		return false, 0
	}

	// Calculate confidence
	confidence := 0.6

	lowerContext := strings.ToLower(context)
	positiveIndicators := []string{"phone", "tel", "mobile", "cell", "contact", "call"}
	for _, indicator := range positiveIndicators {
		if strings.Contains(lowerContext, indicator) {
			confidence = 0.85
			break
		}
	}

	// Negative indicators
	negativeIndicators := []string{"zip", "postal", "year", "amount", "price", "id", "code"}
	for _, indicator := range negativeIndicators {
		if strings.Contains(lowerContext, indicator) {
			confidence -= 0.2
			break
		}
	}

	if confidence < 0.4 {
		return false, 0
	}

	return true, confidence
}

// ValidateIPAddress validates IPv4 addresses.
func ValidateIPAddress(match string, context string) (bool, float64) {
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

	confidence := 0.7

	// Check for private/reserved ranges (lower risk)
	firstOctet, _ := strconv.Atoi(parts[0])
	secondOctet, _ := strconv.Atoi(parts[1])

	isPrivate := false
	if firstOctet == 10 || // 10.0.0.0/8
		(firstOctet == 172 && secondOctet >= 16 && secondOctet <= 31) || // 172.16.0.0/12
		(firstOctet == 192 && secondOctet == 168) || // 192.168.0.0/16
		firstOctet == 127 { // 127.0.0.0/8 (loopback)
		isPrivate = true
		confidence = 0.5 // Lower confidence for private IPs
	}

	// Special addresses
	if match == "0.0.0.0" || match == "255.255.255.255" {
		confidence = 0.4
	}

	// Context analysis
	lowerContext := strings.ToLower(context)
	if strings.Contains(lowerContext, "ip") || strings.Contains(lowerContext, "address") ||
		strings.Contains(lowerContext, "server") || strings.Contains(lowerContext, "host") {
		if !isPrivate {
			confidence = 0.85
		}
	}

	// Version numbers are often misdetected as IPs
	if strings.Contains(lowerContext, "version") {
		confidence -= 0.3
	}

	if confidence < 0.3 {
		return false, 0
	}

	return true, confidence
}

// ValidateBankAccount validates US bank routing + account numbers.
func ValidateBankAccount(match string, context string) (bool, float64) {
	digits := extractDigits(match)

	// Format: 9-digit routing + 8-17 digit account
	if len(digits) < 17 || len(digits) > 26 {
		return false, 0
	}

	// Extract routing number (first 9 digits)
	routing := digits[0:9]

	// ABA routing number checksum (3-7-1 weights)
	if !validateABARouting(routing) {
		return false, 0
	}

	confidence := 0.75

	lowerContext := strings.ToLower(context)
	positiveIndicators := []string{"bank", "account", "routing", "aba", "wire", "transfer", "deposit"}
	for _, indicator := range positiveIndicators {
		if strings.Contains(lowerContext, indicator) {
			confidence = 0.9
			break
		}
	}

	return true, confidence
}

// validateABARouting validates US bank routing numbers using the ABA checksum.
func validateABARouting(routing string) bool {
	if len(routing) != 9 {
		return false
	}

	// Convert to digits
	d := make([]int, 9)
	for i, c := range routing {
		d[i] = int(c - '0')
	}

	// ABA checksum: 3*d1 + 7*d2 + d3 + 3*d4 + 7*d5 + d6 + 3*d7 + 7*d8 + d9 ≡ 0 (mod 10)
	sum := 3*d[0] + 7*d[1] + d[2] + 3*d[3] + 7*d[4] + d[5] + 3*d[6] + 7*d[7] + d[8]
	return sum%10 == 0
}

// Helper functions

// extractDigits removes all non-digit characters from a string.
func extractDigits(s string) string {
	var result strings.Builder
	for _, c := range s {
		if unicode.IsDigit(c) {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// allSameDigit checks if all characters in a string are the same digit.
func allSameDigit(s string) bool {
	if len(s) == 0 {
		return false
	}
	first := s[0]
	for _, c := range s {
		if byte(c) != first {
			return false
		}
	}
	return true
}

// GetValidatorForCategory returns the appropriate validator for a policy category.
func GetValidatorForCategory(category PolicyCategory) ValidatorFunc {
	switch category {
	case CategoryPIIGlobal:
		// Global category includes credit cards, email, phone, IP
		return ValidateCreditCard // Most common, can be overridden per pattern
	case CategoryPIIUS:
		return ValidateSSN
	case CategoryPIIIndia:
		return ValidateAadhaar // Can also be PAN, selected by pattern ID
	case CategoryPIIEU:
		return ValidateIBAN
	default:
		return nil
	}
}

// ValidatorRegistry maps PII types to their validators.
var ValidatorRegistry = map[string]ValidatorFunc{
	"credit_card":  ValidateCreditCard,
	"ssn":          ValidateSSN,
	"iban":         ValidateIBAN,
	"aadhaar":      ValidateAadhaar,
	"pan":          ValidatePAN,
	"email":        ValidateEmail,
	"phone":        ValidatePhone,
	"ip_address":   ValidateIPAddress,
	"bank_account": ValidateBankAccount,
}

// GetValidatorByType returns a validator by PII type name.
func GetValidatorByType(piiType string) ValidatorFunc {
	return ValidatorRegistry[strings.ToLower(piiType)]
}
