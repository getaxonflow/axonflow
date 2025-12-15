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

// Package rbi provides India-specific PII detection for RBI compliance.
// This Community edition provides pattern-based detection for Aadhaar, PAN, UPI, and other Indian PII.
// Enterprise edition adds checksum validation (Verhoeff for Aadhaar) and advanced context analysis.
package rbi

import (
	"regexp"
	"strings"
	"unicode"
)

// IndiaPIIType represents different categories of India-specific PII
type IndiaPIIType string

const (
	IndiaPIITypeUPI            IndiaPIIType = "upi_id"
	IndiaPIITypeAadhaar        IndiaPIIType = "aadhaar"
	IndiaPIITypePAN            IndiaPIIType = "pan"
	IndiaPIITypeIFSC           IndiaPIIType = "ifsc"
	IndiaPIITypeBankAccount    IndiaPIIType = "bank_account_india"
	IndiaPIITypeGSTIN          IndiaPIIType = "gstin"
	IndiaPIITypeVoterID        IndiaPIIType = "voter_id"
	IndiaPIITypeDrivingLicense IndiaPIIType = "driving_license_india"
	IndiaPIITypePassport       IndiaPIIType = "passport_india"
	IndiaPIITypeRationCard     IndiaPIIType = "ration_card"
	IndiaPIITypeIndianPhone    IndiaPIIType = "phone_india"
	IndiaPIITypePincode        IndiaPIIType = "pincode"
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
	RBICategory string           `json:"rbi_category"`
}

// IndiaPIIDetectorConfig configures the India PII detector behavior
type IndiaPIIDetectorConfig struct {
	ContextWindow    int
	MinConfidence    float64
	EnableValidation bool // Ignored in Community - always pattern-only
	EnabledTypes     []IndiaPIIType
}

// indiaPIIPattern represents a compiled pattern for India PII detection
type indiaPIIPattern struct {
	Type        IndiaPIIType
	Pattern     *regexp.Regexp
	Severity    IndiaPIISeverity
	MinLength   int
	MaxLength   int
	RBICategory string
}

// IndiaPIIDetector provides India-specific PII detection.
// Community edition: Pattern-based detection only (no checksum validation).
// Enterprise edition: Full validation with Verhoeff checksums and context analysis.
type IndiaPIIDetector struct {
	patterns      []*indiaPIIPattern
	contextWindow int
	minConfidence float64
}

// DefaultIndiaPIIDetectorConfig returns sensible defaults for India PII detection.
func DefaultIndiaPIIDetectorConfig() IndiaPIIDetectorConfig {
	return IndiaPIIDetectorConfig{
		ContextWindow:    50,
		MinConfidence:    0.6,
		EnableValidation: false, // Community uses pattern-only
		EnabledTypes:     nil,   // All types enabled
	}
}

// NewIndiaPIIDetector creates a new India-specific PII detector.
// Community edition provides pattern-based detection without checksum validation.
func NewIndiaPIIDetector(config IndiaPIIDetectorConfig) *IndiaPIIDetector {
	detector := &IndiaPIIDetector{
		contextWindow: config.ContextWindow,
		minConfidence: config.MinConfidence,
	}
	detector.loadPatterns(config.EnabledTypes)
	return detector
}

// loadPatterns initializes India-specific PII detection patterns
func (d *IndiaPIIDetector) loadPatterns(enabledTypes []IndiaPIIType) {
	allPatterns := []*indiaPIIPattern{
		// UPI ID - username@provider format
		{
			Type:        IndiaPIITypeUPI,
			Pattern:     regexp.MustCompile(`\b[a-zA-Z0-9][a-zA-Z0-9._-]{2,255}@[a-zA-Z][a-zA-Z0-9]{2,49}\b`),
			Severity:    IndiaPIISeverityCritical,
			MinLength:   7,
			MaxLength:   256,
			RBICategory: "payment_identifier",
		},
		// Aadhaar - 12-digit unique identification number
		{
			Type:        IndiaPIITypeAadhaar,
			Pattern:     regexp.MustCompile(`\b[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b`),
			Severity:    IndiaPIISeverityCritical,
			MinLength:   12,
			MaxLength:   14,
			RBICategory: "national_identity",
		},
		// PAN - Permanent Account Number
		{
			Type:        IndiaPIITypePAN,
			Pattern:     regexp.MustCompile(`\b[A-Z]{5}[0-9]{4}[A-Z]\b`),
			Severity:    IndiaPIISeverityCritical,
			MinLength:   10,
			MaxLength:   10,
			RBICategory: "tax_identifier",
		},
		// IFSC Code - Indian Financial System Code
		{
			Type:        IndiaPIITypeIFSC,
			Pattern:     regexp.MustCompile(`\b[A-Z]{4}0[A-Z0-9]{6}\b`),
			Severity:    IndiaPIISeverityMedium,
			MinLength:   11,
			MaxLength:   11,
			RBICategory: "bank_identifier",
		},
		// GSTIN - Goods and Services Tax Identification Number
		{
			Type:        IndiaPIITypeGSTIN,
			Pattern:     regexp.MustCompile(`\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]\b`),
			Severity:    IndiaPIISeverityHigh,
			MinLength:   15,
			MaxLength:   15,
			RBICategory: "tax_identifier",
		},
		// Voter ID (EPIC) - 3 letters + 7 digits
		{
			Type:        IndiaPIITypeVoterID,
			Pattern:     regexp.MustCompile(`\b[A-Z]{3}[0-9]{7}\b`),
			Severity:    IndiaPIISeverityHigh,
			MinLength:   10,
			MaxLength:   10,
			RBICategory: "national_identity",
		},
		// Indian Passport - 1 letter + 7 digits
		{
			Type:        IndiaPIITypePassport,
			Pattern:     regexp.MustCompile(`\b[A-Z][0-9]{7}\b`),
			Severity:    IndiaPIISeverityHigh,
			MinLength:   8,
			MaxLength:   8,
			RBICategory: "travel_document",
		},
		// Indian Mobile Number
		{
			Type:        IndiaPIITypeIndianPhone,
			Pattern:     regexp.MustCompile(`(?:\+91[\s-]?|0)?[6-9][0-9]{9}\b`),
			Severity:    IndiaPIISeverityMedium,
			MinLength:   10,
			MaxLength:   14,
			RBICategory: "contact_info",
		},
		// Indian Pincode - 6 digits, first digit 1-9
		{
			Type:        IndiaPIITypePincode,
			Pattern:     regexp.MustCompile(`\b[1-9][0-9]{5}\b`),
			Severity:    IndiaPIISeverityLow,
			MinLength:   6,
			MaxLength:   6,
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

// DetectAll scans text for all types of India PII.
// Community edition: Pattern-based detection with 0.7 confidence (no checksum validation).
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
			cleanLen := len(strings.Map(func(r rune) rune {
				if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '@' || r == '.' || r == '-' || r == '_' {
					return r
				}
				return -1
			}, matchedText))
			if cleanLen < pattern.MinLength || cleanLen > pattern.MaxLength {
				continue
			}

			// Skip email addresses that match UPI pattern (Community edition basic filtering)
			if pattern.Type == IndiaPIITypeUPI && isLikelyEmail(matchedText) {
				continue
			}

			// Extract context
			context := d.extractContext(text, startIdx, endIdx)

			// Pattern-only confidence (Community edition)
			// Enterprise adds checksum validation for higher confidence
			confidence := 0.7

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

// DetectType scans text for a specific type of India PII.
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

			cleanLen := len(strings.Map(func(r rune) rune {
				if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '@' || r == '.' || r == '-' || r == '_' {
					return r
				}
				return -1
			}, matchedText))
			if cleanLen < pattern.MinLength || cleanLen > pattern.MaxLength {
				continue
			}

			// Skip email addresses that match UPI pattern (Community edition basic filtering)
			if pattern.Type == IndiaPIITypeUPI && isLikelyEmail(matchedText) {
				continue
			}

			context := d.extractContext(text, startIdx, endIdx)
			confidence := 0.7

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

// DetectUPIIDs is a convenience method to detect only UPI IDs.
func (d *IndiaPIIDetector) DetectUPIIDs(text string) []IndiaPIIDetectionResult {
	return d.DetectType(text, IndiaPIITypeUPI)
}

// DetectAadhaar is a convenience method to detect only Aadhaar numbers.
func (d *IndiaPIIDetector) DetectAadhaar(text string) []IndiaPIIDetectionResult {
	return d.DetectType(text, IndiaPIITypeAadhaar)
}

// DetectPAN is a convenience method to detect only PAN numbers.
func (d *IndiaPIIDetector) DetectPAN(text string) []IndiaPIIDetectionResult {
	return d.DetectType(text, IndiaPIITypePAN)
}

// HasIndiaPII quickly checks if text contains any India PII.
func (d *IndiaPIIDetector) HasIndiaPII(text string) bool {
	for _, pattern := range d.patterns {
		if pattern.Pattern.MatchString(text) {
			return true
		}
	}
	return false
}

// HasUPIID quickly checks if text contains any UPI ID.
func (d *IndiaPIIDetector) HasUPIID(text string) bool {
	for _, pattern := range d.patterns {
		if pattern.Type == IndiaPIITypeUPI && pattern.Pattern.MatchString(text) {
			// Basic email domain filtering for Community edition
			matches := pattern.Pattern.FindAllString(text, -1)
			for _, match := range matches {
				if !isLikelyEmail(match) {
					return true
				}
			}
		}
	}
	return false
}

// HasCriticalPII checks if text contains critical PII (Aadhaar, PAN, UPI, Bank Account).
func (d *IndiaPIIDetector) HasCriticalPII(text string) bool {
	criticalTypes := map[IndiaPIIType]bool{
		IndiaPIITypeUPI:         true,
		IndiaPIITypeAadhaar:     true,
		IndiaPIITypePAN:         true,
		IndiaPIITypeBankAccount: true,
	}

	for _, pattern := range d.patterns {
		if criticalTypes[pattern.Type] && pattern.Pattern.MatchString(text) {
			return true
		}
	}
	return false
}

// GetRBISensitiveData returns all detections categorized by RBI data category.
func (d *IndiaPIIDetector) GetRBISensitiveData(text string) map[string][]IndiaPIIDetectionResult {
	results := d.DetectAll(text)
	categorized := make(map[string][]IndiaPIIDetectionResult)

	for _, r := range results {
		categorized[r.RBICategory] = append(categorized[r.RBICategory], r)
	}

	return categorized
}

// GetPatternStats returns statistics about loaded patterns.
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
		"total_patterns":     len(d.patterns),
		"types":              typeCount,
		"severities":         severityCount,
		"rbi_categories":     categoryCount,
		"validation_enabled": false, // Community: pattern-only
		"edition":            "community",
		"min_confidence":     d.minConfidence,
		"context_window":     d.contextWindow,
	}
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

// FilterBySeverity filters results by minimum severity.
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

// FilterByConfidence filters results by minimum confidence.
func FilterIndiaPIIByConfidence(results []IndiaPIIDetectionResult, minConfidence float64) []IndiaPIIDetectionResult {
	var filtered []IndiaPIIDetectionResult
	for _, r := range results {
		if r.Confidence >= minConfidence {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// GetCriticalFinancialPII returns only critical financial PII (UPI, Aadhaar, PAN, Bank accounts).
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

// maskIndiaPII masks sensitive data for logging/display
func maskIndiaPII(value string, piiType IndiaPIIType) string {
	switch piiType {
	case IndiaPIITypeUPI:
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
		clean := strings.ReplaceAll(strings.ReplaceAll(value, " ", ""), "-", "")
		if len(clean) >= 4 {
			return "XXXX XXXX " + clean[len(clean)-4:]
		}
		return "XXXX XXXX XXXX"
	case IndiaPIITypePAN:
		if len(value) == 10 {
			return value[:2] + "******" + value[8:]
		}
		return "**********"
	case IndiaPIITypeIndianPhone:
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
		if len(value) >= 4 {
			return strings.Repeat("X", len(value)-4) + value[len(value)-4:]
		}
		return strings.Repeat("X", len(value))
	default:
		if len(value) <= 4 {
			return strings.Repeat("*", len(value))
		}
		return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
	}
}

// RBIPIICheckResult represents the result of a pre-check PII scan
type RBIPIICheckResult struct {
	HasPII           bool                      `json:"has_pii"`
	CriticalPII      bool                      `json:"critical_pii"`
	DetectedTypes    []IndiaPIIType            `json:"detected_types,omitempty"`
	Detections       []IndiaPIIDetectionResult `json:"detections,omitempty"`
	BlockRecommended bool                      `json:"block_recommended"`
	Reason           string                    `json:"reason,omitempty"`
}

// CheckRequestForPII scans a request for India-specific PII and returns a check result.
// This is the main entry point for pre-check integration.
func CheckRequestForPII(detector *IndiaPIIDetector, query string, blockOnCritical bool) *RBIPIICheckResult {
	if detector == nil {
		return &RBIPIICheckResult{
			HasPII:           false,
			CriticalPII:      false,
			BlockRecommended: false,
		}
	}

	detections := detector.DetectAll(query)

	if len(detections) == 0 {
		return &RBIPIICheckResult{
			HasPII:           false,
			CriticalPII:      false,
			BlockRecommended: false,
		}
	}

	// Collect detected types
	typeSet := make(map[IndiaPIIType]bool)
	hasCritical := false
	criticalTypes := map[IndiaPIIType]bool{
		IndiaPIITypeUPI:         true,
		IndiaPIITypeAadhaar:     true,
		IndiaPIITypePAN:         true,
		IndiaPIITypeBankAccount: true,
	}

	for _, d := range detections {
		typeSet[d.Type] = true
		if criticalTypes[d.Type] {
			hasCritical = true
		}
	}

	detectedTypes := make([]IndiaPIIType, 0, len(typeSet))
	for t := range typeSet {
		detectedTypes = append(detectedTypes, t)
	}

	result := &RBIPIICheckResult{
		HasPII:        true,
		CriticalPII:   hasCritical,
		DetectedTypes: detectedTypes,
		Detections:    detections,
	}

	if blockOnCritical && hasCritical {
		result.BlockRecommended = true
		result.Reason = "Critical India PII detected (Aadhaar, PAN, UPI, or Bank Account)"
	}

	return result
}

// IsEnabled returns whether India PII detection is enabled.
// Community edition: Returns true (pattern-based detection is available).
func IsEnabled() bool {
	return true
}

// isLikelyEmail checks if a UPI-like pattern is actually an email address.
// This provides basic false positive filtering for the Community edition.
// Note: The UPI regex may match partial email addresses (e.g., "john@gmail" from "john@gmail.com")
// so we check for common email provider names both with and without domain extensions.
func isLikelyEmail(match string) bool {
	parts := strings.Split(match, "@")
	if len(parts) != 2 {
		return false
	}

	handle := strings.ToLower(parts[1])

	// Common email provider names (regex may match partial: "john@gmail" from "john@gmail.com")
	emailProviders := []string{
		"gmail", "yahoo", "outlook", "hotmail", "rediffmail",
		"live", "msn", "aol", "icloud", "protonmail", "zoho",
		"mail", "email", "inbox",
	}

	for _, provider := range emailProviders {
		if handle == provider {
			return true
		}
	}

	// Full domain matches (for cases where the full email is matched)
	emailDomains := []string{
		"gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
		"rediffmail.com", "live.com", "msn.com", "aol.com",
		"icloud.com", "protonmail.com", "zoho.com",
	}

	for _, domain := range emailDomains {
		if handle == domain {
			return true
		}
	}

	// TLD suffixes
	emailTLDs := []string{".com", ".org", ".net", ".in", ".co.in", ".edu", ".gov"}
	for _, tld := range emailTLDs {
		if strings.HasSuffix(handle, tld) {
			return true
		}
	}

	return false
}
