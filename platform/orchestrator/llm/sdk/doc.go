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

/*
Package sdk provides a fluent builder API for creating custom LLM providers.

The SDK follows the same patterns as the MCP Connector SDK for consistency,
making it easy for developers familiar with AxonFlow connectors to also
create custom LLM providers.

# Quick Start

Create a custom provider using the fluent builder:

	provider := sdk.NewProviderBuilder("my-provider", llm.ProviderTypeCustom).
		WithModel("my-model-v1").
		WithEndpoint("https://api.myprovider.com/v1").
		WithAuth(sdk.NewAPIKeyAuth(os.Getenv("MY_API_KEY"))).
		WithRateLimiter(sdk.NewRateLimiter(100, 100)).
		WithRetry(sdk.DefaultRetryConfig()).
		WithCompleteFunc(myCompletionHandler).
		Build()

# Authentication

The SDK supports multiple authentication methods:

	// API Key in Authorization header (Bearer token)
	auth := sdk.NewAPIKeyAuth("sk-xxx")

	// API Key in custom header
	auth := sdk.NewAPIKeyAuthWithHeader("sk-xxx", "X-API-Key")

	// API Key as query parameter
	auth := sdk.NewAPIKeyAuthWithQuery("sk-xxx", "api_key")

	// Basic authentication
	auth := sdk.NewBasicAuth("username", "password")

	// Bearer token
	auth := sdk.NewBearerTokenAuth("token")

	// Chain multiple auth providers
	auth := sdk.NewChainedAuth(auth1, auth2)

# Rate Limiting

Token bucket rate limiting to respect API quotas:

	// 100 requests per second with burst of 100
	limiter := sdk.NewRateLimiter(100, 100)

	// Wait for permission (blocks until available)
	if err := limiter.Wait(ctx); err != nil {
		return err
	}

	// Try without blocking
	if !limiter.TryAcquire() {
		return errors.New("rate limited")
	}

For multi-tenant applications:

	mtLimiter := sdk.NewMultiTenantRateLimiter(func() *sdk.RateLimiter {
		return sdk.NewRateLimiter(10, 10)
	})
	mtLimiter.Wait(ctx, "tenant-123")

# Retry with Exponential Backoff

Automatic retry with configurable backoff:

	config := sdk.RetryConfig{
		MaxRetries:     5,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     30 * time.Second,
		BackoffFactor:  2.0,
		Jitter:         0.1,
		RetryIf:        sdk.DefaultRetryable,
	}

	result, err := sdk.RetryWithBackoff(ctx, config, func(ctx context.Context) (*Response, error) {
		return callAPI(ctx)
	})

# Circuit Breaker

Prevent cascading failures:

	cb := sdk.NewCircuitBreaker(5, 30*time.Second)

	if cb.Allow() {
		resp, err := callAPI()
		if err != nil {
			cb.RecordFailure()
		} else {
			cb.RecordSuccess()
		}
	}

# Implementing a Custom Provider

For complex providers, implement the llm.Provider interface directly:

	type MyProvider struct {
		name       string
		client     *http.Client
		auth       sdk.AuthProvider
		limiter    *sdk.RateLimiter
	}

	func (p *MyProvider) Name() string { return p.name }
	func (p *MyProvider) Type() llm.ProviderType { return llm.ProviderTypeCustom }

	func (p *MyProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
		// Apply rate limiting
		if err := p.limiter.Wait(ctx); err != nil {
			return nil, err
		}

		// Build request
		httpReq, _ := http.NewRequestWithContext(ctx, "POST", endpoint, body)
		p.auth.Apply(httpReq)

		// Execute with retry
		return sdk.RetryWithBackoff(ctx, *sdk.DefaultRetryConfig(), func(ctx context.Context) (*llm.CompletionResponse, error) {
			resp, err := p.client.Do(httpReq)
			// ... parse response
		})
	}

# Registering Custom Providers

Register your provider with the factory system:

	llm.RegisterFactory(llm.ProviderTypeCustom, func(config llm.ProviderConfig) (llm.Provider, error) {
		return sdk.NewProviderBuilder(config.Name, llm.ProviderTypeCustom).
			WithModel(config.Model).
			WithEndpoint(config.Endpoint).
			WithAuth(sdk.NewAPIKeyAuth(config.APIKey)).
			WithCompleteFunc(myHandler).
			Build(), nil
	})

# Configuration

Providers can be configured via YAML file with environment variable expansion:

	llm_providers:
		my_custom_provider:
			enabled: true
			display_name: "My Custom LLM"
			config:
				model: "my-model-v1"
				endpoint: "https://api.myprovider.com/v1"
				max_tokens: 4096
			credentials:
				api_key: ${MY_PROVIDER_API_KEY}
			priority: 10
			weight: 0.5

See the LLM Provider Configuration Guide for more details.
*/
package sdk
