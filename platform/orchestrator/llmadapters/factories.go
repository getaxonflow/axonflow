//go:build enterprise

// Copyright 2025 AxonFlow
// Licensed under the Elastic License 2.0 (ELv2)
// Enterprise features - not available in Community distribution

// Package llmadapters provides enterprise LLM provider adapters.
//
// This package contains adapters for enterprise-only LLM providers like
// AWS Bedrock. These adapters implement the unified llm.Provider interface
// and are automatically registered as factories when the enterprise build
// is used.
package llmadapters

import (
	"axonflow/platform/shared/llmdefaults"
	"fmt"

	"axonflow/platform/orchestrator/llm"
)

// init registers enterprise provider factories.
// This is called automatically when the package is imported in enterprise builds.
func init() {
	llm.RegisterFactory(llm.ProviderTypeBedrock, NewBedrockProviderFactory)
}

// NewBedrockProviderFactory creates a BedrockAdapter from configuration.
// This factory is registered for the "bedrock" provider type in enterprise builds.
func NewBedrockProviderFactory(config llm.ProviderConfig) (llm.Provider, error) {
	// Bedrock requires region configuration
	region := config.Region
	if region == "" && config.Settings != nil {
		// Try to extract from settings map
		if r, ok := config.Settings["region"].(string); ok && r != "" {
			region = r
		}
	}

	if region == "" {
		return nil, &llm.FactoryError{
			ProviderType: llm.ProviderTypeBedrock,
			Code:         llm.ErrFactoryInvalidConfig,
			Message:      "AWS region is required for Bedrock provider",
		}
	}

	// Get model from config
	model := config.Model
	if model == "" && config.Settings != nil {
		if m, ok := config.Settings["model"].(string); ok && m != "" {
			model = m
		}
	}

	// Default model if not specified
	if model == "" {
		model = llmdefaults.BedrockModel
	}

	// Get optional model family override
	modelFamily := ""
	if config.Settings != nil {
		if mf, ok := config.Settings["model_family"].(string); ok {
			modelFamily = mf
		}
	}

	// Create the adapter
	adapter, err := NewBedrockAdapter(BedrockAdapterConfig{
		Name:        config.Name,
		Region:      region,
		Model:       model,
		ModelFamily: modelFamily,
		RateLimit:   config.RateLimit,
	})
	if err != nil {
		return nil, &llm.FactoryError{
			ProviderType: llm.ProviderTypeBedrock,
			Code:         llm.ErrFactoryCreationFailed,
			Message:      fmt.Sprintf("failed to create Bedrock adapter: %v", err),
			Cause:        err,
		}
	}

	return adapter, nil
}
