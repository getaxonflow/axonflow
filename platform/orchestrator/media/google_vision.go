// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//go:build enterprise

package media

import (
	"context"
	"fmt"
	"time"
)

// GoogleVisionAnalyzer uses Google Cloud Vision for image analysis.
// Supports text detection, face detection, safe search detection, and label detection.
// Enterprise tier only.
type GoogleVisionAnalyzer struct {
	name   string
	apiKey string
}

// NewGoogleVisionAnalyzer creates a new Google Vision analyzer.
func NewGoogleVisionAnalyzer(name string, apiKey string) *GoogleVisionAnalyzer {
	return &GoogleVisionAnalyzer{
		name:   name,
		apiKey: apiKey,
	}
}

// Name returns the analyzer name.
func (a *GoogleVisionAnalyzer) Name() string {
	return a.name
}

// Type returns the analyzer type.
func (a *GoogleVisionAnalyzer) Type() MediaAnalyzerType {
	return AnalyzerTypeGoogleVision
}

// Capabilities returns the capabilities of this analyzer.
func (a *GoogleVisionAnalyzer) Capabilities() []MediaAnalyzerCapability {
	return []MediaAnalyzerCapability{
		CapabilityOCR,
		CapabilityFaceDetection,
		CapabilityContentSafety,
		CapabilityLabelDetection,
		CapabilityDocumentClassification,
	}
}

// HealthCheck verifies Google Vision API connectivity.
func (a *GoogleVisionAnalyzer) HealthCheck(ctx context.Context) error {
	// TODO: Implement Google Vision health check
	return nil
}

// Analyze performs image analysis using Google Cloud Vision.
func (a *GoogleVisionAnalyzer) Analyze(ctx context.Context, media MediaContent) (*MediaAnalysisResult, error) {
	start := time.Now()

	result := &MediaAnalysisResult{
		AnalyzerName:     a.name,
		AnalyzerType:     AnalyzerTypeGoogleVision,
		EstimatedCostUSD: EstimateAnalyzerCost(AnalyzerTypeGoogleVision),
	}

	rawData, err := media.GetRawData()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw data: %w", err)
	}

	// TODO: Implement Google Cloud Vision API calls:
	// 1. TEXT_DETECTION — OCR
	// 2. FACE_DETECTION — Face detection
	// 3. SAFE_SEARCH_DETECTION — Content safety
	// 4. LABEL_DETECTION — Label detection
	_ = rawData

	result.AnalysisTimeMs = time.Since(start).Milliseconds()
	return result, nil
}

// init registers the Google Vision factory.
func init() {
	RegisterAnalyzerFactory(AnalyzerTypeGoogleVision, func(config AnalyzerConfig) (MediaAnalyzer, error) {
		if config.APIKey == "" && config.APIKeySecretARN == "" {
			return nil, &FactoryError{
				AnalyzerType: AnalyzerTypeGoogleVision,
				Code:         ErrFactoryInvalidConfig,
				Message:      "API key or secret ARN is required for Google Vision",
			}
		}
		return NewGoogleVisionAnalyzer(config.Name, config.APIKey), nil
	})
}
