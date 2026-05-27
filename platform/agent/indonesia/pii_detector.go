//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package indonesia

import (
	"regexp"
	"strconv"
	"strings"
)

// validProvinces is the full 34-province lookup table for NIK validation.
var validProvinces = map[int]string{
	11: "Aceh", 12: "North Sumatra", 13: "West Sumatra", 14: "Riau",
	15: "Jambi", 16: "South Sumatra", 17: "Bengkulu", 18: "Lampung",
	19: "Bangka Belitung", 21: "Riau Islands",
	31: "DKI Jakarta", 32: "West Java", 33: "Central Java",
	34: "DI Yogyakarta", 35: "East Java", 36: "Banten",
	51: "Bali", 52: "West Nusa Tenggara", 53: "East Nusa Tenggara",
	61: "West Kalimantan", 62: "Central Kalimantan", 63: "South Kalimantan",
	64: "East Kalimantan", 65: "North Kalimantan",
	71: "North Sulawesi", 72: "Central Sulawesi", 73: "South Sulawesi",
	74: "Southeast Sulawesi", 75: "Gorontalo", 76: "West Sulawesi",
	81: "Maluku", 82: "North Maluku",
	91: "Papua", 92: "West Papua", 93: "South Papua", 94: "Central Papua",
}

// DefaultIndonesiaPIIDetectorConfig returns sensible defaults for Indonesia PII detection.
func DefaultIndonesiaPIIDetectorConfig() IndonesiaPIIDetectorConfig {
	return IndonesiaPIIDetectorConfig{
		ContextWindow:    50,
		MinConfidence:    0.6,
		EnableValidation: true,
		EnabledTypes:     nil,
	}
}

// NewIndonesiaPIIDetector creates an Indonesia PII detector with full enterprise validation.
func NewIndonesiaPIIDetector(config IndonesiaPIIDetectorConfig) *IndonesiaPIIDetector {
	detector := &IndonesiaPIIDetector{
		contextWindow: config.ContextWindow,
		minConfidence: config.MinConfidence,
	}

	enabledSet := make(map[IndonesiaPIIType]bool)
	for _, t := range config.EnabledTypes {
		enabledSet[t] = true
	}
	allEnabled := len(enabledSet) == 0

	allPatterns := enterprisePatterns()
	for _, p := range allPatterns {
		if allEnabled || enabledSet[p.Type] {
			detector.patterns = append(detector.patterns, p)
		}
	}

	return detector
}

func enterprisePatterns() []*indonesiaPIIPattern {
	return communityPatterns()
}

func communityPatterns() []*indonesiaPIIPattern {
	return []*indonesiaPIIPattern{
		{
			Type: IndonesiaPIITypeNIK,
			Pattern: regexp.MustCompile(
				`\b(?:` +
					`1[1-9]|21|` +
					`3[1-6]|` +
					`5[1-3]|` +
					`6[1-5]|` +
					`7[1-6]|` +
					`8[12]|` +
					`9[1-4]` +
					`)` +
					`\d{4}` +
					`(?:0[1-9]|[12]\d|3[01]|4[1-9]|[56]\d|7[01])` +
					`(?:0[1-9]|1[0-2])` +
					`\d{2}` +
					`\d{4}\b`),
			Severity:    IndonesiaPIISeverityCritical,
			MinLength:   16,
			MaxLength:   16,
			OJKCategory: "national_identity",
		},
		{
			Type:        IndonesiaPIITypeNPWPLegacy,
			Pattern:     regexp.MustCompile(`\b\d{2}\.\d{3}\.\d{3}\.\d{1}-\d{3}\.\d{3}\b`),
			Severity:    IndonesiaPIISeverityCritical,
			MinLength:   20,
			MaxLength:   20,
			OJKCategory: "tax_identifier",
		},
		{
			Type:        IndonesiaPIITypeNPWPNew,
			Pattern:     regexp.MustCompile(`(?i)(?:NPWP|npwp|tax[\s_-]*(?:id|number|no)|nomor[\s_-]*pokok)[:\s]+(\d{16})\b`),
			Severity:    IndonesiaPIISeverityCritical,
			MinLength:   16,
			MaxLength:   50,
			OJKCategory: "tax_identifier",
		},
		{
			Type:        IndonesiaPIITypePhone,
			Pattern:     regexp.MustCompile(`\b(?:\+?62|0)8[1-9]\d{6,10}\b`),
			Severity:    IndonesiaPIISeverityMedium,
			MinLength:   10,
			MaxLength:   15,
			OJKCategory: "contact_information",
		},
		{
			Type:        IndonesiaPIITypeBCA,
			Pattern:     regexp.MustCompile(`(?i)(?:BCA|bank[\s_-]*central[\s_-]*asia|rek(?:ening)?)[:\s]+(\d{10})\b`),
			Severity:    IndonesiaPIISeverityHigh,
			MinLength:   10,
			MaxLength:   40,
			OJKCategory: "financial_account",
		},
		{
			Type:        IndonesiaPIITypeMandiri,
			Pattern:     regexp.MustCompile(`(?i)(?:mandiri|bank[\s_-]*mandiri|rek(?:ening)?[\s_-]*mandiri)[:\s]+(\d{13})\b`),
			Severity:    IndonesiaPIISeverityHigh,
			MinLength:   13,
			MaxLength:   50,
			OJKCategory: "financial_account",
		},
		{
			Type:        IndonesiaPIITypeBRI,
			Pattern:     regexp.MustCompile(`(?i)(?:BRI|bank[\s_-]*rakyat[\s_-]*indonesia|rek(?:ening)?[\s_-]*BRI)[:\s]+(\d{15})\b`),
			Severity:    IndonesiaPIISeverityHigh,
			MinLength:   15,
			MaxLength:   50,
			OJKCategory: "financial_account",
		},
		{
			Type:        IndonesiaPIITypeBNI,
			Pattern:     regexp.MustCompile(`(?i)(?:BNI|bank[\s_-]*negara[\s_-]*indonesia|rek(?:ening)?[\s_-]*BNI)[:\s]+(\d{10})\b`),
			Severity:    IndonesiaPIISeverityHigh,
			MinLength:   10,
			MaxLength:   40,
			OJKCategory: "financial_account",
		},
	}
}

// DetectAll scans text for all Indonesia-specific PII types with enterprise validation.
func (d *IndonesiaPIIDetector) DetectAll(text string) []IndonesiaPIIDetectionResult {
	if text == "" {
		return nil
	}

	var results []IndonesiaPIIDetectionResult
	for _, p := range d.patterns {
		matches := p.Pattern.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			matchText := text[loc[0]:loc[1]]

			if p.Type == IndonesiaPIITypeNIK && isLikelyCreditCardOrTimestamp(text, loc[0], loc[1]) {
				continue
			}

			confidence := 0.7

			switch p.Type {
			case IndonesiaPIITypeNIK:
				if validateNIKEnterprise(matchText) {
					confidence = 0.95
				} else {
					continue
				}
			case IndonesiaPIITypeNPWPLegacy:
				if validateNPWPLegacy(matchText) {
					confidence = 0.92
				}
			case IndonesiaPIITypeNPWPNew:
				digits := extractDigits(matchText)
				if len(digits) == 16 && validateNPWPNew(digits) {
					confidence = 0.93
				}
			case IndonesiaPIITypePhone:
				confidence = 0.85
			default:
				confidence = 0.85
			}

			if confidence < d.minConfidence {
				continue
			}

			result := IndonesiaPIIDetectionResult{
				Type:        p.Type,
				Value:       matchText,
				MaskedValue: maskIndonesiaPII(matchText, p.Type),
				Severity:    p.Severity,
				Confidence:  confidence,
				StartIndex:  loc[0],
				EndIndex:    loc[1],
				OJKCategory: p.OJKCategory,
			}

			if d.contextWindow > 0 {
				start := loc[0] - d.contextWindow
				if start < 0 {
					start = 0
				}
				end := loc[1] + d.contextWindow
				if end > len(text) {
					end = len(text)
				}
				result.Context = text[start:end]
			}

			results = append(results, result)
		}
	}
	return results
}

// DetectType scans text for a specific Indonesia PII type.
func (d *IndonesiaPIIDetector) DetectType(text string, piiType IndonesiaPIIType) []IndonesiaPIIDetectionResult {
	var results []IndonesiaPIIDetectionResult
	all := d.DetectAll(text)
	for _, r := range all {
		if r.Type == piiType {
			results = append(results, r)
		}
	}
	return results
}

// HasIndonesiaPII returns true if the text contains any Indonesia-specific PII.
func (d *IndonesiaPIIDetector) HasIndonesiaPII(text string) bool {
	return len(d.DetectAll(text)) > 0
}

// CheckRequestForPII scans a request for Indonesia-specific PII and returns a check result.
func CheckRequestForPII(detector *IndonesiaPIIDetector, query string, blockOnCritical bool) *IndonesiaPIICheckResult {
	if detector == nil {
		return &IndonesiaPIICheckResult{
			HasPII:           false,
			CriticalPII:      false,
			BlockRecommended: false,
		}
	}

	detections := detector.DetectAll(query)
	if len(detections) == 0 {
		return &IndonesiaPIICheckResult{
			HasPII:           false,
			CriticalPII:      false,
			BlockRecommended: false,
		}
	}

	typeSet := make(map[IndonesiaPIIType]bool)
	hasCritical := false
	criticalTypes := map[IndonesiaPIIType]bool{
		IndonesiaPIITypeNIK:        true,
		IndonesiaPIITypeNPWPLegacy: true,
		IndonesiaPIITypeNPWPNew:    true,
	}

	for _, det := range detections {
		typeSet[det.Type] = true
		if criticalTypes[det.Type] {
			hasCritical = true
		}
	}

	detectedTypes := make([]IndonesiaPIIType, 0, len(typeSet))
	for t := range typeSet {
		detectedTypes = append(detectedTypes, t)
	}

	result := &IndonesiaPIICheckResult{
		HasPII:        true,
		CriticalPII:   hasCritical,
		DetectedTypes: detectedTypes,
		Detections:    detections,
	}

	if blockOnCritical && hasCritical {
		result.BlockRecommended = true
		result.Reason = "Critical Indonesia PII detected (NIK or NPWP)"
	}

	return result
}

// IsEnabled returns whether Indonesia PII detection is enabled.
func IsEnabled() bool {
	return true
}

func maskIndonesiaPII(value string, piiType IndonesiaPIIType) string {
	if len(value) < 4 {
		return strings.Repeat("*", len(value))
	}
	switch piiType {
	case IndonesiaPIITypeNIK:
		if len(value) >= 16 {
			return value[:2] + strings.Repeat("*", 10) + value[12:]
		}
		return strings.Repeat("*", len(value))
	case IndonesiaPIITypeNPWPLegacy, IndonesiaPIITypeNPWPNew:
		return strings.Repeat("*", len(value))
	case IndonesiaPIITypePhone:
		if len(value) > 6 {
			return value[:3] + strings.Repeat("*", len(value)-7) + value[len(value)-4:]
		}
		return strings.Repeat("*", len(value))
	default:
		if len(value) > 4 {
			return strings.Repeat("*", len(value)-4) + value[len(value)-4:]
		}
		return strings.Repeat("*", len(value))
	}
}

func isLikelyCreditCardOrTimestamp(text string, matchStart, matchEnd int) bool {
	if matchStart > 0 {
		prev := text[matchStart-1]
		if prev >= '0' && prev <= '9' {
			return true
		}
		if prev == '-' && matchStart > 1 && text[matchStart-2] >= '0' && text[matchStart-2] <= '9' {
			return true
		}
	}
	if matchEnd < len(text) {
		next := text[matchEnd]
		if next >= '0' && next <= '9' {
			return true
		}
	}
	return false
}

func validateNIKEnterprise(nik string) bool {
	digitsOnly := extractDigits(nik)
	if len(digitsOnly) != 16 {
		return false
	}

	provinceCode, err := strconv.Atoi(digitsOnly[:2])
	if err != nil {
		return false
	}
	if _, ok := validProvinces[provinceCode]; !ok {
		return false
	}

	dd, err := strconv.Atoi(digitsOnly[6:8])
	if err != nil {
		return false
	}
	if dd > 40 {
		dd -= 40
	}
	if dd < 1 || dd > 31 {
		return false
	}

	mm, err := strconv.Atoi(digitsOnly[8:10])
	if err != nil {
		return false
	}
	if mm < 1 || mm > 12 {
		return false
	}

	return true
}

func validateNPWPLegacy(npwp string) bool {
	digits := extractDigits(npwp)
	if len(digits) != 15 {
		return false
	}
	prefix, err := strconv.Atoi(digits[:2])
	if err != nil || prefix == 0 {
		return false
	}
	return true
}

func validateNPWPNew(digits string) bool {
	if len(digits) != 16 {
		return false
	}
	allZero := true
	for _, c := range digits {
		if c != '0' {
			allZero = false
			break
		}
	}
	return !allZero
}

func extractDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
