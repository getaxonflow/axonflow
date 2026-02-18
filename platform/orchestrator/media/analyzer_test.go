// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package media

import (
	"context"
	"testing"
)

// MockMediaAnalyzer is a test double that implements the MediaAnalyzer interface.
type MockMediaAnalyzer struct {
	name         string
	analyzerType MediaAnalyzerType
	caps         []MediaAnalyzerCapability
	analyzeFunc  func(ctx context.Context, media MediaContent) (*MediaAnalysisResult, error)
	healthErr    error
}

func (m *MockMediaAnalyzer) Name() string {
	return m.name
}

func (m *MockMediaAnalyzer) Type() MediaAnalyzerType {
	return m.analyzerType
}

func (m *MockMediaAnalyzer) Analyze(ctx context.Context, media MediaContent) (*MediaAnalysisResult, error) {
	if m.analyzeFunc != nil {
		return m.analyzeFunc(ctx, media)
	}
	return &MediaAnalysisResult{
		AnalyzerName: m.name,
		AnalyzerType: m.analyzerType,
	}, nil
}

func (m *MockMediaAnalyzer) HealthCheck(ctx context.Context) error {
	return m.healthErr
}

func (m *MockMediaAnalyzer) Capabilities() []MediaAnalyzerCapability {
	return m.caps
}

// Compile-time interface check.
var _ MediaAnalyzer = (*MockMediaAnalyzer)(nil)

func TestHasCapability(t *testing.T) {
	analyzer := &MockMediaAnalyzer{
		name:         "test-analyzer",
		analyzerType: AnalyzerTypeLocalOCR,
		caps: []MediaAnalyzerCapability{
			CapabilityOCR,
			CapabilityPIIDetection,
			CapabilityContentSafety,
		},
	}

	tests := []struct {
		name string
		cap  MediaAnalyzerCapability
		want bool
	}{
		{
			name: "matching capability OCR",
			cap:  CapabilityOCR,
			want: true,
		},
		{
			name: "matching capability PII detection",
			cap:  CapabilityPIIDetection,
			want: true,
		},
		{
			name: "matching capability content safety",
			cap:  CapabilityContentSafety,
			want: true,
		},
		{
			name: "non-matching capability face detection",
			cap:  CapabilityFaceDetection,
			want: false,
		},
		{
			name: "non-matching capability label detection",
			cap:  CapabilityLabelDetection,
			want: false,
		},
		{
			name: "non-matching capability document classification",
			cap:  CapabilityDocumentClassification,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasCapability(analyzer, tt.cap)
			if got != tt.want {
				t.Errorf("HasCapability(%q) = %v, want %v", tt.cap, got, tt.want)
			}
		})
	}
}

func TestHasCapabilityEmptyCapabilities(t *testing.T) {
	analyzer := &MockMediaAnalyzer{
		name:         "empty-caps-analyzer",
		analyzerType: AnalyzerTypeCustom,
		caps:         []MediaAnalyzerCapability{},
	}

	capabilities := []MediaAnalyzerCapability{
		CapabilityOCR,
		CapabilityFaceDetection,
		CapabilityContentSafety,
		CapabilityDocumentClassification,
		CapabilityLabelDetection,
		CapabilityPIIDetection,
	}

	for _, cap := range capabilities {
		if HasCapability(analyzer, cap) {
			t.Errorf("HasCapability(%q) = true for analyzer with empty capabilities, want false", cap)
		}
	}

	// Also test with nil capabilities slice.
	analyzerNilCaps := &MockMediaAnalyzer{
		name:         "nil-caps-analyzer",
		analyzerType: AnalyzerTypeCustom,
		caps:         nil,
	}

	for _, cap := range capabilities {
		if HasCapability(analyzerNilCaps, cap) {
			t.Errorf("HasCapability(%q) = true for analyzer with nil capabilities, want false", cap)
		}
	}
}
