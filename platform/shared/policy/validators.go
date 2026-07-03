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

	// The pattern's bare-12-digit alternative matches ANY 12-digit number
	// (barcodes, order ids, ledger refs), and EvaluateAll has no confidence
	// threshold, so a match always fires → under PII_ACTION=redact benign 12-digit
	// figures were masked. Validity therefore REQUIRES an Aadhaar/UID label. A
	// Verhoeff check-digit gate is NOT enough on its own here: ~1 in 10 random
	// 12-digit numbers pass the check digit, so it would only cut the false
	// positives 10x, not eliminate them.
	//
	// The label can be in EITHER place: (a) immediately preceding the digits (the
	// pattern's bare-digit alternative, label lives in the left context), or (b)
	// as the PREFIX of the match itself — the pattern's `aadhaar[:\s]+<digits>` /
	// `UID[:\s]+<digits>` alternatives are leftmost, so the match is e.g.
	// "aadhaar 234...". Accept either. For (b) the leading label must be a REAL word
	// (the seed alts have no \b, so a case-insensitive scrape can pull "uid" out of
	// "liqUID 234..." → span "uid 234..."); require the char before the match to be
	// a non-word char, i.e. the left context does not end mid-word.
	left := leftContextOf(match, context)
	labelInLeft := aadhaarLabelRe.MatchString(left)
	labelInMatch := aadhaarLabelInMatchRe.MatchString(match) && !endsWithWordChar(left)
	if !labelInLeft && !labelInMatch {
		return false, 0
	}
	return true, 0.95
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
// ipVersionLabelRe matches a version LABEL that immediately PRECEDES the dotted value
// (anchored at the end of the left context, allowing JSON/punctuation between the label
// and the value: {"ver":"10.20.30.40"}, "version: 2.5.0.1", "firmware 1.2.3.4"). It is
// deliberately restricted to version-SPECIFIC tokens — "release"/"build"/"rev" were
// excluded because they are common English verbs that frequently abut a real IP in ops
// prose ("please release 54.210.8.7 to prod"), where rejecting would drop a real IP
// (a leak — worse than masking a version). Proximity-gated, so a version word merely
// near (not abutting) an IP never rejects; word boundaries keep "server"/"review" out.
var ipVersionLabelRe = regexp.MustCompile(`(?i)\b(version|ver|semver|firmware|revision)\b["':#=.\-\s]*$`)

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

	firstOctet, _ := strconv.Atoi(parts[0])
	secondOctet, _ := strconv.Atoi(parts[1])
	thirdOctet, _ := strconv.Atoi(parts[2])

	// RFC-special / documentation / non-host ranges are never a person's
	// address, so they are not PII to govern (#2802: `0.0.0.0/0` in an
	// AWS-hardening note was flagged as PII). Rejected outright:
	//   * 0.0.0.0/8        — "this network" / unspecified (RFC 6890), incl. the
	//                        `0.0.0.0/0` allow-all CIDR shorthand in prose
	//   * 127.0.0.0/8      — loopback ("connect to 127.0.0.1:8080" is not PII)
	//   * 169.254.0.0/16   — link-local (RFC 3927), incl. cloud metadata 169.254.169.254
	//   * 100.64.0.0/10    — CGNAT shared address space (RFC 6598)
	//   * 224.0.0.0/4 +    — multicast + reserved/experimental (>=224), never a host
	//   * 255.255.255.255  — limited broadcast
	//   * 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — RFC 5737 TEST-NET
	//     documentation blocks, reserved and never routed to a real host
	// Real private-range (RFC 1918) and routable public addresses stay detected.
	if firstOctet == 0 ||
		firstOctet == 127 ||
		firstOctet >= 224 || // multicast + reserved/experimental + 255.255.255.255 broadcast
		(firstOctet == 169 && secondOctet == 254) ||
		(firstOctet == 100 && secondOctet >= 64 && secondOctet <= 127) ||
		(firstOctet == 192 && secondOctet == 0 && thirdOctet == 2) ||
		(firstOctet == 198 && secondOctet == 51 && thirdOctet == 100) ||
		(firstOctet == 203 && secondOctet == 0 && thirdOctet == 113) {
		return false, 0
	}

	// Check for private/reserved ranges (lower risk)
	isPrivate := false
	if firstOctet == 10 || // 10.0.0.0/8
		(firstOctet == 172 && secondOctet >= 16 && secondOctet <= 31) || // 172.16.0.0/12
		(firstOctet == 192 && secondOctet == 168) { // 192.168.0.0/16
		isPrivate = true
		confidence = 0.5 // Lower confidence for private IPs
	}

	// Context analysis
	lowerContext := strings.ToLower(context)
	if strings.Contains(lowerContext, "ip") || strings.Contains(lowerContext, "address") ||
		strings.Contains(lowerContext, "server") || strings.Contains(lowerContext, "host") {
		if !isPrivate {
			confidence = 0.85
		}
	}

	// Version / build numbers are often misdetected as IPs (a 4-part dotted number
	// with octets ≤255 is a valid IPv4 shape). When a version/build LABEL immediately
	// precedes the dotted value it is a version, not an address → reject. Proximity-
	// gated (leftContextOf + end-anchored ipVersionLabelRe) so a real IP merely near a
	// version word elsewhere in the window is still detected — and it covers the "ver"
	// JSON-key form the old full-word "version" substring check missed.
	if ipVersionLabelRe.MatchString(leftContextOf(match, context)) {
		return false, 0
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
	case CategoryPIISingapore:
		// NRIC checksum validation is Enterprise-only (Issue #1076)
		// Pattern-based detection works without validator
		return nil
	default:
		return nil
	}
}

// passportLabelRe / dobLabelRe match an indicator that IMMEDIATELY PRECEDES the
// value — they are anchored at end-of-(left-context) (`$`), allowing only
// whitespace, a short connector word, and a separator between the label and the
// value. This gates on the label that actually MODIFIES this match, not on any
// occurrence of the word anywhere in the ±50-char window: e.g.
// "the company was born in 2018, invoice 03/04/2025" must NOT govern the invoice
// date, because the date's left context ends with "invoice ", not a birth label.
// Word boundaries (\b) also keep "born" out of "airborne"/"reborn"/"newborn" and
// "passport" out of "passporting".
// The trailing separator class includes '.' so a full abbreviation that ends in a
// period ("d.o.b. 01/01/1990") still validates.
var passportLabelRe = regexp.MustCompile(`(?i)\b(passport|travel document|travel doc)\b\s*(?:number|no\.?|num)?\s*[:#=.\-]?\s*$`)
var dobLabelRe = regexp.MustCompile(`(?i)\b(d\.?o\.?b\.?|date of birth|birth ?date|birthday|born)\b\s*(?:of|on|is|was)?\s*[:#=.\-]?\s*$`)

// leftContextOf returns the portion of context immediately preceding match (the
// text to the value's left). Used so the *Label regexes can require the label to
// abut the value rather than merely co-occur in the window. Uses the FIRST
// occurrence of match in context; when the value appears multiple times this
// biases toward under-detection (evaluates the first instance's left), never an
// over-block — the safe direction.
func leftContextOf(match, context string) string {
	if idx := strings.Index(context, match); idx >= 0 {
		return context[:idx]
	}
	return context // fallback: match not located in window → treat whole window as "left"
}

// ValidatePassport validates passport-number-shaped strings: 1-2 leading letters
// followed by 6-9 digits (matching the sys_pii_passport pattern). That pattern is
// broad — it also matches generic uppercase-alphanumeric IDs (SKUs, order/case
// numbers) — and the shared engine's EvaluateAll has no confidence threshold (a
// valid match always fires). The policy's effective action is the deployment's
// PII_ACTION (blocked under PII_ACTION=block, redacted/warned otherwise — the
// pii-global category override replaces the seed action), so a false positive
// CAN block legitimate traffic. Validity therefore requires a passport/travel-
// document label IMMEDIATELY PRECEDING the number; without it the match is
// rejected, so "order X1234567" is not governed as a passport.
//
// Coverage limits (documented, not a regression): only letter-prefixed passport
// formats are covered — all-numeric passports (some jurisdictions) never match
// the sys_pii_passport pattern itself, so they are out of scope here.
func ValidatePassport(match string, context string) (bool, float64) {
	clean := strings.TrimSpace(match)
	letters, digits := 0, 0
	digitsSeen := false
	for _, c := range clean {
		switch {
		case unicode.IsLetter(c):
			if digitsSeen { // letters must all precede the digits (no "1A234567")
				return false, 0
			}
			letters++
		case unicode.IsDigit(c):
			digits++
			digitsSeen = true
		default:
			return false, 0
		}
	}
	if letters < 1 || letters > 2 || digits < 6 || digits > 9 {
		return false, 0
	}
	if passportLabelRe.MatchString(leftContextOf(match, context)) {
		return true, 0.95
	}
	return false, 0
}

// ValidateDOB validates date-of-birth-shaped strings. The sys_pii_dob pattern
// matches ANY date, and EvaluateAll has no confidence threshold, so validity
// REQUIRES a birth-date label IMMEDIATELY PRECEDING the date (dobLabelRe, anchored
// at the value's left edge). A bare birth word elsewhere in the window does NOT
// qualify: "the company was born in 2018, invoice 03/04/2025" leaves the date's
// left context ending in "invoice " → not governed. The policy's effective action
// is the deployment's PII_ACTION (block under PII_ACTION=block, redact/warn
// otherwise), so this proximity gate is what prevents false blocks of ordinary
// dates.
//
// Coverage limits (documented, not a regression): the sys_pii_dob pattern is
// US/ISO only (MM/DD/YYYY, YYYY/MM/DD). Other locale formats (DD/MM/YYYY,
// DD.MM.YYYY, ISO with '-') are not matched by the pattern itself, so a labelled
// DOB in those formats is out of scope here.
func ValidateDOB(match string, context string) (bool, float64) {
	if dobLabelRe.MatchString(leftContextOf(match, context)) {
		return true, 0.95
	}
	return false, 0
}

// sgPostalLabelRe / sgUENLabelRe gate the two broad Singapore numeric detectors
// the same way passportLabelRe/dobLabelRe gate passport/DOB: the label must
// IMMEDIATELY PRECEDE the value (anchored at the end of the left context), not
// merely co-occur in the window. Both detectors are CategoryPIISingapore, whose
// category default validator is nil (accept-all), so before this gate every
// regex match fired unconditionally — and under PII_ACTION=redact the engine
// masked the value, which for a bare JSON number breaks the document and makes
// a downstream PEP (e.g. the Claude Desktop proxy, which re-validates the
// redacted result as JSON) fail-closed on an otherwise-benign response.
var sgPostalLabelRe = regexp.MustCompile(`(?i)\b(singapore|s'?pore|postal\s*code|post\s*code|postcode|zip\s*code)\b\s*(?:is|:|=|#|\-)?\s*$`)
var sgUENLabelRe = regexp.MustCompile(`(?i)\b(uen|unique\s*entity\s*(?:number|no\.?|num)?|entity\s*(?:number|no\.?)|business\s*reg(?:istration)?\s*(?:number|no\.?)?|acra)\b\s*(?:is|:|=|#|\-)?\s*$`)

// ValidateSingaporePostal gates sys_pii_singapore_postal. Its pattern matches ANY
// 6-digit number in 010000–829999 (\b(?:0[1-9]|[1-7]\d|8[0-2])\d{4}\b), so an
// order amount, transaction count, or numeric ID trivially false-matches and is
// masked. EvaluateAll has no confidence threshold (a valid match always fires),
// so validity REQUIRES a Singapore/postal label immediately preceding the value;
// a bare 6-digit number is not governed as a postal code.
//
// Coverage limit (documented, not a regression): a real SG postal code that
// appears with no preceding postal/Singapore label (e.g. a bare "408600" with no
// context) is not governed — the safe direction for a low-severity, warn-default
// locality signal, versus masking arbitrary financial figures.
func ValidateSingaporePostal(match string, context string) (bool, float64) {
	if sgPostalLabelRe.MatchString(leftContextOf(match, context)) {
		return true, 0.95
	}
	return false, 0
}

// ValidateSingaporeUEN gates sys_pii_singapore_uen. The pattern has two alts:
//   - \d{8,9}[A-Z]      — broad: any 8-9 digit run followed by a letter (an
//     invoice/order/SKU id like "12345678X" false-matches). Requires a UEN label.
//   - [TS]\d{2}[A-Z]{2}\d{4}[A-Z] — the structured T/S-prefixed UEN, specific
//     enough to be self-anchoring; accepted without a label.
func ValidateSingaporeUEN(match string, context string) (bool, float64) {
	clean := strings.ToUpper(strings.TrimSpace(match))
	// Structured T/S-prefixed UEN: TyyXXnnnnK — specific, self-anchoring.
	if structuredUENRe.MatchString(clean) {
		return true, 0.95
	}
	// Broad numeric+letter form: only governed with a UEN/entity label adjacent.
	if sgUENLabelRe.MatchString(leftContextOf(match, context)) {
		return true, 0.9
	}
	return false, 0
}

var structuredUENRe = regexp.MustCompile(`^[TS]\d{2}[A-Z]{2}\d{4}[A-Z]$`)

// aadhaarLabelRe / sgICLabelRe gate three more broad detectors the same way
// passportLabelRe/dobLabelRe (#2567) and sgPostalLabelRe/sgUENLabelRe (#2575) do:
// the label must IMMEDIATELY PRECEDE the value (anchored at the end of the left
// context). These three matched on shape alone with no real gate, and EvaluateAll
// has no confidence threshold, so under PII_ACTION=redact they masked benign IDs:
// any 12-digit number fired Aadhaar; any [STFGM]/[FG]+7digit+letter fired NRIC/FIN.
var aadhaarLabelRe = regexp.MustCompile(`(?i)\b(aadhaar|aadhar|uidai|uid|unique\s*id)\b\s*(?:number|no\.?|num|card|id)?\s*[:#=.\-]?\s*$`)

// aadhaarLabelInMatchRe matches when the Aadhaar label is the PREFIX of the
// matched span (the seed pattern's leftmost `aadhaar[:\s]+<digits>` /
// `UID[:\s]+<digits>` alternatives put the label inside the match). Anchored at
// the span start (^) so it only fires for a leading label — combined with the
// caller's word-boundary check on the left context, this rejects a label that the
// case-insensitive seed alt scraped out of the MIDDLE of a word (e.g. "liqUID
// 234..." → span "uid 234...") while accepting a genuine "aadhaar 234..." match.
var aadhaarLabelInMatchRe = regexp.MustCompile(`(?i)^\s*(aadhaar|aadhar|uidai|uid|unique\s*id)\b`)

// endsWithWordChar reports whether s ends in a word character ([A-Za-z0-9_]).
// Used to tell a real word-boundary label ("...customer aadhaar"|"") from one the
// regex scraped out of the middle of a longer word ("...the liq"+"uid").
func endsWithWordChar(s string) bool {
	rs := []rune(s)
	if len(rs) == 0 {
		return false
	}
	r := rs[len(rs)-1]
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

// sgICLabelRe: the unambiguous labels (nric, national registration, identity card,
// foreign identification) may appear bare; the bare token "fin" is an ordinary
// English word (fish fin, code fin), so it is accepted ONLY when followed by a
// qualifier (no/number/card) or a separator (:/#/=/-), i.e. "FIN: F…", "FIN no F…"
// — never "the fin S…". Bare-space "FIN F…" is out of scope (use a separator).
var sgICLabelRe = regexp.MustCompile(`(?i)(?:\b(?:nric|national\s*registration(?:\s*identity)?(?:\s*card)?|foreign\s*identification(?:\s*number)?|identity\s*card)\b\s*(?:number|no\.?|num)?\s*[:#=.\-]?|\bfin\b\s*(?:no\.?|number|num|card|[:#=.\-]))\s*$`)

// ValidateSingaporeNRIC gates sys_pii_singapore_nric. Its pattern `[STFGM]\d{7}[A-Z]`
// matches generic letter+7digit+letter ids (asset tags, SKUs, order refs), and the
// pii-singapore category default validator is nil (accept-all). Validity therefore
// REQUIRES an NRIC/identity-card label immediately preceding the value.
//
// Coverage limit (documented, not a regression): the NRIC checksum (the trailing
// check letter) is Enterprise-only (Issue #1076); the OSS path never validated it,
// so a bare unlabelled NRIC is not governed here — the safe direction versus masking
// arbitrary alphanumeric ids.
func ValidateSingaporeNRIC(match string, context string) (bool, float64) {
	if sgICLabelRe.MatchString(leftContextOf(match, context)) {
		return true, 0.9
	}
	return false, 0
}

// ValidateSingaporeFIN gates sys_pii_singapore_fin (`[FG]\d{7}[A-Z]`) — same broad
// shape and same nil-category-default as NRIC. Same adjacent-label gate.
func ValidateSingaporeFIN(match string, context string) (bool, float64) {
	if sgICLabelRe.MatchString(leftContextOf(match, context)) {
		return true, 0.9
	}
	return false, 0
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
	"passport":     ValidatePassport,
	"dob":          ValidateDOB,
	"sg_postal":    ValidateSingaporePostal,
	"sg_uen":       ValidateSingaporeUEN,
	"sg_nric":      ValidateSingaporeNRIC,
	"sg_fin":       ValidateSingaporeFIN,
}

// GetValidatorByType returns a validator by PII type name.
func GetValidatorByType(piiType string) ValidatorFunc {
	return ValidatorRegistry[strings.ToLower(piiType)]
}

// validatorTokenMappings maps PII-type tokens to ValidatorRegistry keys, in
// DETERMINISTIC, most-specific-first order. Used to select a validator from a
// policy ID by underscore-delimited segment match (so "sys_pii_email" → email).
//
// A slice (not a map) on purpose: map iteration order is random in Go, so the
// previous map-based segment matcher could non-deterministically pick the wrong
// validator when two tokens both matched. Specific multi-word tokens
// (credit_card, ip_address, bank_account) MUST precede their shorter aliases
// (ip, bank) so the alias never shadows the precise match.
var validatorTokenMappings = []struct{ token, regKey string }{
	{"credit_card", "credit_card"},
	{"bank_account", "bank_account"},
	{"ip_address", "ip_address"},
	{"ssn", "ssn"},
	{"iban", "iban"},
	{"aadhaar", "aadhaar"},
	{"pan", "pan"},
	{"email", "email"},
	{"phone", "phone"},
	{"passport", "passport"},
	{"dob", "dob"},
	{"postal", "sg_postal"},
	{"uen", "sg_uen"},
	{"nric", "sg_nric"},
	{"fin", "sg_fin"},
	{"ip", "ip_address"},
	{"bank", "bank_account"},
}

// ValidatorForPolicyID selects a validator by matching a known PII-type token as
// an underscore-delimited segment of the policy ID (e.g. "sys_pii_email" → the
// email validator). Returns nil when no token matches, so callers fall back to
// the category default.
//
// This realizes the "can be overridden per pattern" behavior that the seed
// comments describe but the exact-match ValidatorRegistry[policyID] lookup never
// delivered: a system policy ID like "sys_pii_email" never equals a bare type
// key ("email"), so every loaded policy silently fell through to its category
// default validator — which for pii-global is the credit-card validator, and that
// validator rejects every non-card string. Concretely this fix changes resolution
// for these DB-loaded policies:
//   - sys_pii_email, sys_pii_phone, sys_pii_ip_address: credit-card → the correct
//     validator (these were inert before — never matched anything).
//   - sys_pii_pan: ValidateAadhaar (pii-india default) → ValidatePAN (correct).
//   - sys_pii_indonesia_phone, sys_pii_singapore_phone: nil/accept-all (their
//     category default) → ValidatePhone (a slight narrowing; still governs real
//     numbers — see TestValidatorForPolicyID_LocalePhones).
//
// SSN/IBAN/Aadhaar were already correct only because their pii-us/eu/india
// category defaults happen to be the right validator. sys_pii_passport and
// sys_pii_dob now resolve to ValidatePassport/ValidateDOB (#2567) — both
// context-gated to avoid false-positive blocks/redactions on the broad
// passport/date patterns. sys_pii_booking_ref still has no token and no shared
// validator, so it keeps the pii-global credit-card default and remains
// validator-inert (intentional — a booking ref is not PII to redact).
//
// Single source of truth shared by the loader (PolicyLoader.getValidatorForPolicy,
// which pre-sets CompiledPolicy.Validator) and the evaluator (PatternEvaluator
// .getValidator, the in-memory fallback) so the two never diverge.
func ValidatorForPolicyID(policyID string) ValidatorFunc {
	segments := "_" + strings.ToLower(policyID) + "_"
	for _, m := range validatorTokenMappings {
		if strings.Contains(segments, "_"+m.token+"_") {
			return ValidatorRegistry[m.regKey]
		}
	}
	return nil
}
