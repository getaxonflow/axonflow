// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package media

import (
	"context"
)

// analyzerTierRequirement maps analyzer types to their minimum required tier.
// Community-available analyzers require no license.
// Enterprise analyzers require at least Professional tier.
var analyzerTierRequirement = map[MediaAnalyzerType]string{
	// Community analyzers - available without license
	AnalyzerTypeLocalOCR: "community",

	// Enterprise analyzers - require license
	AnalyzerTypeAWSRekognition: "enterprise",
	AnalyzerTypeGoogleVision:   "enterprise",
	AnalyzerTypeAzureVision:    "enterprise",
	AnalyzerTypeCustom:         "enterprise",
}

// AnalyzerLicenseValidator defines the interface for license validation.
type AnalyzerLicenseValidator interface {
	// IsAnalyzerAllowed checks if an analyzer type is allowed by the current license.
	IsAnalyzerAllowed(ctx context.Context, analyzerType MediaAnalyzerType) bool

	// GetMaxAnalyzers returns the maximum number of analyzers allowed.
	// Returns -1 for unlimited.
	GetMaxAnalyzers(ctx context.Context) int

	// GetEnforcementStrategy returns the enforcement strategy for the current tier.
	GetEnforcementStrategy(ctx context.Context) EnforcementStrategy
}

// CommunityAnalyzerValidator is the default validator for Community builds.
// It allows only the local OCR analyzer and enforces fail-open mode.
type CommunityAnalyzerValidator struct{}

// IsAnalyzerAllowed checks if an analyzer is allowed in Community mode.
func (v *CommunityAnalyzerValidator) IsAnalyzerAllowed(ctx context.Context, analyzerType MediaAnalyzerType) bool {
	req, exists := analyzerTierRequirement[analyzerType]
	if !exists {
		return false
	}
	return req == "community"
}

// GetMaxAnalyzers returns the Community limit of 2 analyzers.
func (v *CommunityAnalyzerValidator) GetMaxAnalyzers(ctx context.Context) int {
	return 2
}

// GetEnforcementStrategy returns fail-open for Community tier.
func (v *CommunityAnalyzerValidator) GetEnforcementStrategy(ctx context.Context) EnforcementStrategy {
	return EnforcementFailOpen
}

// DefaultAnalyzerValidator is the global analyzer license validator instance.
// In Community builds, this is a CommunityAnalyzerValidator.
// In Enterprise builds, this is replaced with EnterpriseAnalyzerValidator.
var DefaultAnalyzerValidator AnalyzerLicenseValidator = &CommunityAnalyzerValidator{}

// SetDefaultAnalyzerValidator allows replacing the default validator.
func SetDefaultAnalyzerValidator(v AnalyzerLicenseValidator) {
	DefaultAnalyzerValidator = v
}

// IsCommunityAnalyzer returns true if the analyzer is available in Community mode.
func IsCommunityAnalyzer(analyzerType MediaAnalyzerType) bool {
	req, exists := analyzerTierRequirement[analyzerType]
	if !exists {
		return false
	}
	return req == "community"
}

// GetCommunityAnalyzers returns a list of analyzers available in Community mode.
func GetCommunityAnalyzers() []MediaAnalyzerType {
	var analyzers []MediaAnalyzerType
	for at, req := range analyzerTierRequirement {
		if req == "community" {
			analyzers = append(analyzers, at)
		}
	}
	return analyzers
}

// GetEnterpriseAnalyzers returns a list of analyzers that require a license.
func GetEnterpriseAnalyzers() []MediaAnalyzerType {
	var analyzers []MediaAnalyzerType
	for at, req := range analyzerTierRequirement {
		if req != "community" {
			analyzers = append(analyzers, at)
		}
	}
	return analyzers
}
