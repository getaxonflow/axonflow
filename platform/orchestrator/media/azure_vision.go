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

// AzureVisionAnalyzer uses Azure Computer Vision for image analysis.
// Supports OCR (Read), face detection, and content safety analysis.
// Enterprise tier only.
type AzureVisionAnalyzer struct {
	name     string
	endpoint string
	apiKey   string
}

// NewAzureVisionAnalyzer creates a new Azure Vision analyzer.
func NewAzureVisionAnalyzer(name string, endpoint string, apiKey string) *AzureVisionAnalyzer {
	return &AzureVisionAnalyzer{
		name:     name,
		endpoint: endpoint,
		apiKey:   apiKey,
	}
}

// Name returns the analyzer name.
func (a *AzureVisionAnalyzer) Name() string {
	return a.name
}

// Type returns the analyzer type.
func (a *AzureVisionAnalyzer) Type() MediaAnalyzerType {
	return AnalyzerTypeAzureVision
}

// Capabilities returns the capabilities of this analyzer.
func (a *AzureVisionAnalyzer) Capabilities() []MediaAnalyzerCapability {
	return []MediaAnalyzerCapability{
		CapabilityOCR,
		CapabilityFaceDetection,
		CapabilityContentSafety,
		CapabilityLabelDetection,
	}
}

// HealthCheck verifies Azure Vision API connectivity.
func (a *AzureVisionAnalyzer) HealthCheck(ctx context.Context) error {
	// TODO: Implement Azure Vision health check
	return nil
}

// Analyze performs image analysis using Azure Computer Vision.
func (a *AzureVisionAnalyzer) Analyze(ctx context.Context, media MediaContent) (*MediaAnalysisResult, error) {
	start := time.Now()

	result := &MediaAnalysisResult{
		AnalyzerName:     a.name,
		AnalyzerType:     AnalyzerTypeAzureVision,
		EstimatedCostUSD: EstimateAnalyzerCost(AnalyzerTypeAzureVision),
	}

	rawData, err := media.GetRawData()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw data: %w", err)
	}

	// TODO: Implement Azure Computer Vision API calls:
	// 1. Read (OCR) — Text extraction
	// 2. Detect (faces) — Face detection
	// 3. Analyze (content safety) — Content moderation
	_ = rawData

	result.AnalysisTimeMs = time.Since(start).Milliseconds()
	return result, nil
}

// init registers the Azure Vision factory.
func init() {
	RegisterAnalyzerFactory(AnalyzerTypeAzureVision, func(config AnalyzerConfig) (MediaAnalyzer, error) {
		if config.Endpoint == "" {
			return nil, &FactoryError{
				AnalyzerType: AnalyzerTypeAzureVision,
				Code:         ErrFactoryInvalidConfig,
				Message:      "endpoint is required for Azure Vision",
			}
		}
		if config.APIKey == "" && config.APIKeySecretARN == "" {
			return nil, &FactoryError{
				AnalyzerType: AnalyzerTypeAzureVision,
				Code:         ErrFactoryInvalidConfig,
				Message:      "API key or secret ARN is required for Azure Vision",
			}
		}
		return NewAzureVisionAnalyzer(config.Name, config.Endpoint, config.APIKey), nil
	})
}
