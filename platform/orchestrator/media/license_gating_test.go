// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package media

import (
	"context"
	"testing"
)

func TestCommunityAnalyzerValidator_IsAnalyzerAllowed(t *testing.T) {
	v := &CommunityAnalyzerValidator{}
	ctx := context.Background()

	tests := []struct {
		name         string
		analyzerType MediaAnalyzerType
		expected     bool
	}{
		{"local-ocr is allowed", AnalyzerTypeLocalOCR, true},
		{"aws-rekognition is not allowed", AnalyzerTypeAWSRekognition, false},
		{"google-vision is not allowed", AnalyzerTypeGoogleVision, false},
		{"azure-vision is not allowed", AnalyzerTypeAzureVision, false},
		{"custom is not allowed", AnalyzerTypeCustom, false},
		{"unknown type is not allowed", MediaAnalyzerType("unknown-type"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.IsAnalyzerAllowed(ctx, tt.analyzerType)
			if got != tt.expected {
				t.Errorf("IsAnalyzerAllowed(%q) = %v, want %v", tt.analyzerType, got, tt.expected)
			}
		})
	}
}

func TestCommunityAnalyzerValidator_GetMaxAnalyzers(t *testing.T) {
	v := &CommunityAnalyzerValidator{}
	ctx := context.Background()

	max := v.GetMaxAnalyzers(ctx)
	if max != 2 {
		t.Errorf("expected GetMaxAnalyzers = 2, got %d", max)
	}
}

func TestCommunityAnalyzerValidator_GetEnforcementStrategy(t *testing.T) {
	v := &CommunityAnalyzerValidator{}
	ctx := context.Background()

	strategy := v.GetEnforcementStrategy(ctx)
	if strategy != EnforcementFailOpen {
		t.Errorf("expected EnforcementFailOpen, got %q", strategy)
	}
}

func TestIsCommunityAnalyzer(t *testing.T) {
	tests := []struct {
		name         string
		analyzerType MediaAnalyzerType
		expected     bool
	}{
		{"local-ocr is community", AnalyzerTypeLocalOCR, true},
		{"aws-rekognition is not community", AnalyzerTypeAWSRekognition, false},
		{"google-vision is not community", AnalyzerTypeGoogleVision, false},
		{"azure-vision is not community", AnalyzerTypeAzureVision, false},
		{"custom is not community", AnalyzerTypeCustom, false},
		{"unknown is not community", MediaAnalyzerType("nonexistent"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsCommunityAnalyzer(tt.analyzerType)
			if got != tt.expected {
				t.Errorf("IsCommunityAnalyzer(%q) = %v, want %v", tt.analyzerType, got, tt.expected)
			}
		})
	}
}

func TestGetCommunityAnalyzers(t *testing.T) {
	analyzers := GetCommunityAnalyzers()

	if len(analyzers) == 0 {
		t.Fatal("expected at least one community analyzer")
	}

	found := false
	for _, a := range analyzers {
		if a == AnalyzerTypeLocalOCR {
			found = true
		}
	}
	if !found {
		t.Error("expected GetCommunityAnalyzers to contain local-ocr")
	}
}

func TestGetEnterpriseAnalyzers(t *testing.T) {
	analyzers := GetEnterpriseAnalyzers()

	expectedTypes := map[MediaAnalyzerType]bool{
		AnalyzerTypeAWSRekognition: false,
		AnalyzerTypeGoogleVision:   false,
		AnalyzerTypeAzureVision:    false,
		AnalyzerTypeCustom:         false,
	}

	for _, a := range analyzers {
		if _, ok := expectedTypes[a]; ok {
			expectedTypes[a] = true
		}
		// Ensure no community analyzer leaked in.
		if a == AnalyzerTypeLocalOCR {
			t.Error("GetEnterpriseAnalyzers should not contain local-ocr")
		}
	}

	for at, found := range expectedTypes {
		if !found {
			t.Errorf("expected GetEnterpriseAnalyzers to contain %q", at)
		}
	}
}

func TestSetDefaultAnalyzerValidator(t *testing.T) {
	// Save the original to restore after the test.
	original := DefaultAnalyzerValidator
	defer SetDefaultAnalyzerValidator(original)

	// Create a mock validator.
	mock := &mockAnalyzerValidator{maxAnalyzers: 99}
	SetDefaultAnalyzerValidator(mock)

	if DefaultAnalyzerValidator != mock {
		t.Error("expected DefaultAnalyzerValidator to be the mock")
	}

	ctx := context.Background()
	if DefaultAnalyzerValidator.GetMaxAnalyzers(ctx) != 99 {
		t.Errorf("expected GetMaxAnalyzers = 99, got %d", DefaultAnalyzerValidator.GetMaxAnalyzers(ctx))
	}
}

func TestDefaultAnalyzerValidator_IsCommunityByDefault(t *testing.T) {
	// Save the original to restore after the test.
	original := DefaultAnalyzerValidator
	defer SetDefaultAnalyzerValidator(original)

	// Reset to default.
	SetDefaultAnalyzerValidator(&CommunityAnalyzerValidator{})

	ctx := context.Background()

	if !DefaultAnalyzerValidator.IsAnalyzerAllowed(ctx, AnalyzerTypeLocalOCR) {
		t.Error("default validator should allow local-ocr")
	}
	if DefaultAnalyzerValidator.IsAnalyzerAllowed(ctx, AnalyzerTypeAWSRekognition) {
		t.Error("default validator should not allow aws-rekognition")
	}
	if DefaultAnalyzerValidator.GetMaxAnalyzers(ctx) != 2 {
		t.Errorf("default validator GetMaxAnalyzers = %d, want 2", DefaultAnalyzerValidator.GetMaxAnalyzers(ctx))
	}
	if DefaultAnalyzerValidator.GetEnforcementStrategy(ctx) != EnforcementFailOpen {
		t.Errorf("default validator GetEnforcementStrategy = %q, want %q",
			DefaultAnalyzerValidator.GetEnforcementStrategy(ctx), EnforcementFailOpen)
	}
}

// mockAnalyzerValidator is a test double for AnalyzerLicenseValidator.
type mockAnalyzerValidator struct {
	maxAnalyzers int
}

func (m *mockAnalyzerValidator) IsAnalyzerAllowed(_ context.Context, _ MediaAnalyzerType) bool {
	return true
}

func (m *mockAnalyzerValidator) GetMaxAnalyzers(_ context.Context) int {
	return m.maxAnalyzers
}

func (m *mockAnalyzerValidator) GetEnforcementStrategy(_ context.Context) EnforcementStrategy {
	return EnforcementFailClosed
}
