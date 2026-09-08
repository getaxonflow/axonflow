// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

/*
Package llm provides a unified interface and types for LLM (Large Language Model) providers.

# Overview

This package defines the common abstractions used across all LLM integrations in AxonFlow.
It enables pluggable provider implementations that work consistently in both Community and
Enterprise editions.

# Provider Interface

The Provider interface is the core abstraction that all LLM providers must implement:

	type Provider interface {
		Name() string
		Type() ProviderType
		Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
		HealthCheck(ctx context.Context) (*HealthCheckResult, error)
		Capabilities() []Capability
		SupportsStreaming() bool
		EstimateCost(req CompletionRequest) *CostEstimate
	}

# Supported Providers

AxonFlow supports the following LLM providers out of the box:

  - OpenAI (GPT-4, GPT-3.5)
  - Anthropic (Claude 4, Claude 3.5, Claude 3)
  - AWS Bedrock (Claude, Titan, Llama, Mistral)
  - Ollama (self-hosted models)
  - Google Gemini (coming soon)

# Custom Providers

To create a custom provider, implement the Provider interface:

	type MyProvider struct {
		name   string
		config ProviderConfig
	}

	func (p *MyProvider) Name() string {
		return p.name
	}

	func (p *MyProvider) Type() ProviderType {
		return ProviderTypeCustom
	}

	func (p *MyProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
		// Your implementation here
	}

	// ... implement remaining methods

Then register the provider factory:

	registry.RegisterFactory(ProviderTypeCustom, func(cfg ProviderConfig) (Provider, error) {
		return &MyProvider{name: cfg.Name, config: cfg}, nil
	})

# Streaming Support

Providers that support streaming should implement StreamingProvider:

	type StreamingProvider interface {
		Provider
		CompleteStream(ctx context.Context, req CompletionRequest, handler StreamHandler) (*CompletionResponse, error)
	}

# Error Handling

Provider errors are wrapped in ProviderError with error codes for categorization:

	resp, err := provider.Complete(ctx, req)
	if err != nil {
		var provErr *ProviderError
		if errors.As(err, &provErr) {
			switch provErr.Code {
			case ErrCodeRateLimit:
				// Handle rate limiting
			case ErrCodeAuth:
				// Handle auth failure
			}
		}
	}

# Thread Safety

All provider implementations must be safe for concurrent use. The registry and
router implementations use sync.RWMutex for thread-safe operations.
*/
package llm
