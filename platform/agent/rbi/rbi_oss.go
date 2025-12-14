//go:build !enterprise

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

// Package rbi provides RBI FREE-AI Framework compliance for India-specific PII detection.
// This is the OSS stub - RBI compliance features are disabled in OSS mode.
// Enterprise builds overlay this with full PII detection for Aadhaar, PAN, UPI, etc.
package rbi

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
	EnableValidation bool
	EnabledTypes     []IndiaPIIType
}

// IndiaPIIDetector provides India-specific PII detection for RBI compliance.
// OSS stub: No-op implementation - India PII detection is disabled in OSS mode.
type IndiaPIIDetector struct {
	// No fields needed for OSS stub
}

// DefaultIndiaPIIDetectorConfig returns sensible defaults for RBI compliance.
// OSS stub: Returns empty config.
func DefaultIndiaPIIDetectorConfig() IndiaPIIDetectorConfig {
	return IndiaPIIDetectorConfig{
		ContextWindow:    50,
		MinConfidence:    0.6,
		EnableValidation: true,
		EnabledTypes:     nil,
	}
}

// NewIndiaPIIDetector creates a new India-specific PII detector.
// OSS stub: Returns a no-op detector.
func NewIndiaPIIDetector(config IndiaPIIDetectorConfig) *IndiaPIIDetector {
	return &IndiaPIIDetector{}
}

// DetectAll scans text for all types of India PII.
// OSS stub: Always returns empty slice (no detection in OSS mode).
func (d *IndiaPIIDetector) DetectAll(text string) []IndiaPIIDetectionResult {
	return nil
}

// DetectType scans text for a specific type of India PII.
// OSS stub: Always returns empty slice (no detection in OSS mode).
func (d *IndiaPIIDetector) DetectType(text string, piiType IndiaPIIType) []IndiaPIIDetectionResult {
	return nil
}

// HasIndiaPII quickly checks if text contains any India PII.
// OSS stub: Always returns false (no detection in OSS mode).
func (d *IndiaPIIDetector) HasIndiaPII(text string) bool {
	return false
}

// HasCriticalPII checks if text contains critical PII (Aadhaar, PAN, UPI, Bank Account).
// OSS stub: Always returns false (no detection in OSS mode).
func (d *IndiaPIIDetector) HasCriticalPII(text string) bool {
	return false
}

// GetRBISensitiveData returns all detections categorized by RBI data category.
// OSS stub: Always returns empty map (no detection in OSS mode).
func (d *IndiaPIIDetector) GetRBISensitiveData(text string) map[string][]IndiaPIIDetectionResult {
	return make(map[string][]IndiaPIIDetectionResult)
}

// GetPatternStats returns statistics about loaded patterns.
// OSS stub: Returns minimal stats indicating OSS mode.
func (d *IndiaPIIDetector) GetPatternStats() map[string]interface{} {
	return map[string]interface{}{
		"total_patterns": 0,
		"oss_mode":       true,
		"enterprise":     false,
	}
}

// FilterBySeverity filters results by minimum severity.
// OSS stub: Returns empty slice.
func FilterIndiaPIIBySeverity(results []IndiaPIIDetectionResult, minSeverity IndiaPIISeverity) []IndiaPIIDetectionResult {
	return nil
}

// FilterByConfidence filters results by minimum confidence.
// OSS stub: Returns empty slice.
func FilterIndiaPIIByConfidence(results []IndiaPIIDetectionResult, minConfidence float64) []IndiaPIIDetectionResult {
	return nil
}

// GetCriticalFinancialPII returns only critical financial PII (UPI, Aadhaar, PAN, Bank accounts).
// OSS stub: Returns empty slice.
func GetCriticalFinancialPII(results []IndiaPIIDetectionResult) []IndiaPIIDetectionResult {
	return nil
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
// OSS stub: Returns no PII found.
func CheckRequestForPII(detector *IndiaPIIDetector, query string, blockOnCritical bool) *RBIPIICheckResult {
	return &RBIPIICheckResult{
		HasPII:           false,
		CriticalPII:      false,
		DetectedTypes:    nil,
		Detections:       nil,
		BlockRecommended: false,
		Reason:           "",
	}
}

// IsEnabled returns whether RBI PII detection is enabled.
// OSS stub: Always returns false.
func IsEnabled() bool {
	return false
}
