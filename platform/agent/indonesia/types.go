// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package indonesia

import "regexp"

// IndonesiaPIIType represents categories of Indonesia-specific PII.
type IndonesiaPIIType string

const (
	IndonesiaPIITypeNIK         IndonesiaPIIType = "nik"
	IndonesiaPIITypeNPWPLegacy  IndonesiaPIIType = "npwp_legacy"
	IndonesiaPIITypeNPWPNew     IndonesiaPIIType = "npwp_new"
	IndonesiaPIITypePhone       IndonesiaPIIType = "phone_indonesia"
	IndonesiaPIITypeBCA         IndonesiaPIIType = "bank_bca"
	IndonesiaPIITypeMandiri     IndonesiaPIIType = "bank_mandiri"
	IndonesiaPIITypeBRI         IndonesiaPIIType = "bank_bri"
	IndonesiaPIITypeBNI         IndonesiaPIIType = "bank_bni"
)

// IndonesiaPIISeverity represents the risk level of detected Indonesia PII.
type IndonesiaPIISeverity string

const (
	IndonesiaPIISeverityLow      IndonesiaPIISeverity = "low"
	IndonesiaPIISeverityMedium   IndonesiaPIISeverity = "medium"
	IndonesiaPIISeverityHigh     IndonesiaPIISeverity = "high"
	IndonesiaPIISeverityCritical IndonesiaPIISeverity = "critical"
)

// IndonesiaPIIDetectionResult represents a single Indonesia PII detection.
type IndonesiaPIIDetectionResult struct {
	Type        IndonesiaPIIType     `json:"type"`
	Value       string               `json:"value"`
	MaskedValue string               `json:"masked_value"`
	Severity    IndonesiaPIISeverity `json:"severity"`
	Confidence  float64              `json:"confidence"`
	StartIndex  int                  `json:"start_index"`
	EndIndex    int                  `json:"end_index"`
	Context     string               `json:"context,omitempty"`
	OJKCategory string               `json:"ojk_category"`
}

// IndonesiaPIIDetectorConfig configures the Indonesia PII detector behavior.
type IndonesiaPIIDetectorConfig struct {
	ContextWindow    int
	MinConfidence    float64
	EnableValidation bool
	EnabledTypes     []IndonesiaPIIType
}

type indonesiaPIIPattern struct {
	Type        IndonesiaPIIType
	Pattern     *regexp.Regexp
	Severity    IndonesiaPIISeverity
	MinLength   int
	MaxLength   int
	OJKCategory string
}

// IndonesiaPIIDetector provides Indonesia-specific PII detection.
type IndonesiaPIIDetector struct {
	patterns      []*indonesiaPIIPattern
	contextWindow int
	minConfidence float64
}

// IndonesiaPIICheckResult represents the result of a pre-check PII scan.
type IndonesiaPIICheckResult struct {
	HasPII           bool                          `json:"has_pii"`
	CriticalPII      bool                          `json:"critical_pii"`
	DetectedTypes    []IndonesiaPIIType            `json:"detected_types,omitempty"`
	Detections       []IndonesiaPIIDetectionResult `json:"detections,omitempty"`
	BlockRecommended bool                          `json:"block_recommended"`
	Reason           string                        `json:"reason,omitempty"`
}
