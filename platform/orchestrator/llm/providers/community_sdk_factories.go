// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package providers registers SDK-backed factories for community LLM providers.
//
// These factories intentionally live outside the llm package to avoid import cycles
// (llm/sdk depends on llm). The orchestrator imports this package for side effects.
package providers

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"axonflow/platform/orchestrator/llm"
	"axonflow/platform/orchestrator/llm/anthropic"
	"axonflow/platform/orchestrator/llm/azure"
	"axonflow/platform/orchestrator/llm/gemini"
	llmsdk "axonflow/platform/orchestrator/llm/sdk"
)

const (
	anthropicInputCostPer1K    = 0.003
	anthropicOutputCostPer1K   = 0.015
	geminiInputCostPer1K       = 0.00125
	geminiOutputCostPer1K      = 0.005
	azureOpenAIInputCostPer1K  = 0.0025
	azureOpenAIOutputCostPer1K = 0.01
)

func init() {
	llm.RegisterFactory(llm.ProviderTypeAnthropic, NewAnthropicProviderFactory)
	llm.RegisterFactory(llm.ProviderTypeGemini, NewGeminiProviderFactory)
	llm.RegisterFactory(llm.ProviderTypeAzureOpenAI, NewAzureOpenAIProviderFactory)
	llm.RegisterFactory(llm.ProviderTypeOllama, NewOllamaProviderFactory)
}

func providerNameOrDefault(name, fallback string) string {
	if strings.TrimSpace(name) != "" {
		return name
	}
	return fallback
}

func buildSDKRateLimiter(rateLimitPerMinute int) *llmsdk.RateLimiter {
	if rateLimitPerMinute <= 0 {
		return nil
	}
	ratePerSecond := float64(rateLimitPerMinute) / 60.0
	burst := math.Max(1, ratePerSecond)
	return llmsdk.NewRateLimiter(ratePerSecond, burst)
}

func estimateTokens(req llm.CompletionRequest) (inputTokens, outputTokens int) {
	inputTokens = utf8.RuneCountInString(req.Prompt) / 4
	if req.SystemPrompt != "" {
		inputTokens += utf8.RuneCountInString(req.SystemPrompt) / 4
	}
	if inputTokens == 0 {
		inputTokens = 1
	}

	outputTokens = req.MaxTokens
	if outputTokens == 0 {
		outputTokens = 1000
	}

	return inputTokens, outputTokens
}

func calculateCost(inputTokens, outputTokens int, inputCostPer1K, outputCostPer1K float64) float64 {
	return (float64(inputTokens)/1000)*inputCostPer1K +
		(float64(outputTokens)/1000)*outputCostPer1K
}

func NewAnthropicProviderFactory(config llm.ProviderConfig) (llm.Provider, error) {
	if config.APIKey == "" && config.APIKeySecretARN == "" {
		return nil, &llm.FactoryError{
			ProviderType: llm.ProviderTypeAnthropic,
			Code:         llm.ErrFactoryInvalidConfig,
			Message:      "API key is required for Anthropic provider",
		}
	}

	model := config.Model
	if model == "" {
		model = anthropic.DefaultModel
	}
	timeout := 120 * time.Second
	if config.TimeoutSeconds > 0 {
		timeout = time.Duration(config.TimeoutSeconds) * time.Second
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = anthropic.DefaultBaseURL
	}

	provider, err := anthropic.NewProvider(anthropic.Config{
		APIKey:  config.APIKey,
		BaseURL: endpoint,
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, &llm.FactoryError{
			ProviderType: llm.ProviderTypeAnthropic,
			Code:         llm.ErrFactoryCreationFailed,
			Message:      fmt.Sprintf("failed to create Anthropic provider: %v", err),
			Cause:        err,
		}
	}

	adapter := &AnthropicProviderAdapter{
		provider: provider,
		name:     providerNameOrDefault(config.Name, "anthropic"),
		config:   config,
	}
	adapter.authProvider = llmsdk.NewAPIKeyAuth(config.APIKey)
	adapter.rateLimiter = buildSDKRateLimiter(config.RateLimit)

	builder := llmsdk.NewProviderBuilder(adapter.name, llm.ProviderTypeAnthropic).
		WithModel(model).
		WithEndpoint(endpoint).
		WithAuth(adapter.authProvider).
		WithTimeout(timeout).
		WithCapabilities(adapter.Capabilities()...).
		WithStreaming(true).
		WithCompleteFunc(adapter.completeRequest)
	if adapter.rateLimiter != nil {
		builder.WithRateLimiter(adapter.rateLimiter)
	}
	adapter.base = builder.Build()

	return adapter, nil
}

type AnthropicProviderAdapter struct {
	provider     *anthropic.Provider
	name         string
	config       llm.ProviderConfig
	base         *llmsdk.CustomProvider
	authProvider llmsdk.AuthProvider
	rateLimiter  *llmsdk.RateLimiter
}

func (a *AnthropicProviderAdapter) Name() string { return a.name }

func (a *AnthropicProviderAdapter) Type() llm.ProviderType { return llm.ProviderTypeAnthropic }

func (a *AnthropicProviderAdapter) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	if a.base != nil {
		return a.base.Complete(ctx, req)
	}
	return a.completeRequest(ctx, req)
}

func (a *AnthropicProviderAdapter) completeRequest(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	anthropicReq := anthropic.CompletionRequest{
		Prompt:        req.Prompt,
		SystemPrompt:  req.SystemPrompt,
		MaxTokens:     req.MaxTokens,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		TopK:          req.TopK,
		Model:         req.Model,
		StopSequences: req.StopSequences,
		Stream:        req.Stream,
	}

	resp, err := a.provider.Complete(ctx, anthropicReq)
	if err != nil {
		return nil, err
	}

	return &llm.CompletionResponse{
		Content: resp.Content,
		Model:   resp.Model,
		Usage: llm.UsageStats{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		},
		Latency:      resp.Latency,
		FinishReason: resp.StopReason,
		Metadata: map[string]any{
			"provider": "anthropic",
		},
	}, nil
}

func (a *AnthropicProviderAdapter) HealthCheck(ctx context.Context) (*llm.HealthCheckResult, error) {
	start := time.Now()
	healthy := a.provider.IsHealthy()

	status := llm.HealthStatusUnhealthy
	message := "provider reports unhealthy"
	if healthy {
		status = llm.HealthStatusHealthy
		message = "provider is operational"
	}

	return &llm.HealthCheckResult{
		Status:      status,
		Latency:     time.Since(start),
		Message:     message,
		LastChecked: time.Now(),
	}, nil
}

func (a *AnthropicProviderAdapter) Capabilities() []llm.Capability {
	return []llm.Capability{
		llm.CapabilityChat,
		llm.CapabilityCompletion,
		llm.CapabilityStreaming,
		llm.CapabilityVision,
		llm.CapabilityCodeGeneration,
		llm.CapabilityLongContext,
	}
}

func (a *AnthropicProviderAdapter) SupportsStreaming() bool { return a.provider.SupportsStreaming() }

func (a *AnthropicProviderAdapter) EstimateCost(req llm.CompletionRequest) *llm.CostEstimate {
	estimatedInputTokens, estimatedOutputTokens := estimateTokens(req)
	totalEstimate := calculateCost(estimatedInputTokens, estimatedOutputTokens,
		anthropicInputCostPer1K, anthropicOutputCostPer1K)

	return &llm.CostEstimate{
		InputCostPer1K:        anthropicInputCostPer1K,
		OutputCostPer1K:       anthropicOutputCostPer1K,
		EstimatedInputTokens:  estimatedInputTokens,
		EstimatedOutputTokens: estimatedOutputTokens,
		TotalEstimate:         totalEstimate,
		Currency:              "USD",
	}
}

func NewGeminiProviderFactory(config llm.ProviderConfig) (llm.Provider, error) {
	if config.APIKey == "" && config.APIKeySecretARN == "" {
		return nil, &llm.FactoryError{
			ProviderType: llm.ProviderTypeGemini,
			Code:         llm.ErrFactoryInvalidConfig,
			Message:      "API key is required for Gemini provider",
		}
	}

	model := config.Model
	if model == "" {
		model = gemini.DefaultModel
	}
	timeout := gemini.DefaultTimeout
	if config.TimeoutSeconds > 0 {
		timeout = time.Duration(config.TimeoutSeconds) * time.Second
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = gemini.DefaultBaseURL
	}

	provider, err := gemini.NewProvider(gemini.Config{
		APIKey:  config.APIKey,
		BaseURL: endpoint,
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, &llm.FactoryError{
			ProviderType: llm.ProviderTypeGemini,
			Code:         llm.ErrFactoryCreationFailed,
			Message:      fmt.Sprintf("failed to create Gemini provider: %v", err),
			Cause:        err,
		}
	}

	adapter := &GeminiProviderAdapter{
		provider: provider,
		name:     providerNameOrDefault(config.Name, "gemini"),
		config:   config,
	}
	adapter.authProvider = llmsdk.NewAPIKeyAuth(config.APIKey)
	adapter.rateLimiter = buildSDKRateLimiter(config.RateLimit)

	builder := llmsdk.NewProviderBuilder(adapter.name, llm.ProviderTypeGemini).
		WithModel(model).
		WithEndpoint(endpoint).
		WithAuth(adapter.authProvider).
		WithTimeout(timeout).
		WithCapabilities(adapter.Capabilities()...).
		WithStreaming(true).
		WithCompleteFunc(adapter.completeRequest)
	if adapter.rateLimiter != nil {
		builder.WithRateLimiter(adapter.rateLimiter)
	}
	adapter.base = builder.Build()

	return adapter, nil
}

type GeminiProviderAdapter struct {
	provider     *gemini.Provider
	name         string
	config       llm.ProviderConfig
	base         *llmsdk.CustomProvider
	authProvider llmsdk.AuthProvider
	rateLimiter  *llmsdk.RateLimiter
}

func (a *GeminiProviderAdapter) Name() string { return a.name }

func (a *GeminiProviderAdapter) Type() llm.ProviderType { return llm.ProviderTypeGemini }

func (a *GeminiProviderAdapter) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	if a.base != nil {
		return a.base.Complete(ctx, req)
	}
	return a.completeRequest(ctx, req)
}

func (a *GeminiProviderAdapter) completeRequest(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	geminiReq := gemini.CompletionRequest{
		Prompt:        req.Prompt,
		SystemPrompt:  req.SystemPrompt,
		MaxTokens:     req.MaxTokens,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		TopK:          req.TopK,
		Model:         req.Model,
		StopSequences: req.StopSequences,
		Stream:        req.Stream,
	}

	resp, err := a.provider.Complete(ctx, geminiReq)
	if err != nil {
		return nil, err
	}

	return &llm.CompletionResponse{
		Content: resp.Content,
		Model:   resp.Model,
		Usage: llm.UsageStats{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		},
		Latency:      resp.Latency,
		FinishReason: resp.StopReason,
		Metadata: map[string]any{
			"provider": "gemini",
		},
	}, nil
}

func (a *GeminiProviderAdapter) CompleteStream(ctx context.Context, req llm.CompletionRequest, handler llm.StreamHandler) (*llm.CompletionResponse, error) {
	geminiReq := gemini.CompletionRequest{
		Prompt:        req.Prompt,
		SystemPrompt:  req.SystemPrompt,
		MaxTokens:     req.MaxTokens,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		TopK:          req.TopK,
		Model:         req.Model,
		StopSequences: req.StopSequences,
		Stream:        true,
	}

	resp, err := a.provider.CompleteStream(ctx, geminiReq, func(chunk gemini.StreamChunk) error {
		if handler == nil {
			return nil
		}
		return handler(llm.StreamChunk{Type: chunk.Type, Content: chunk.Content, Done: chunk.Done})
	})
	if err != nil {
		return nil, err
	}

	return &llm.CompletionResponse{
		Content: resp.Content,
		Model:   resp.Model,
		Usage: llm.UsageStats{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		},
		Latency:      resp.Latency,
		FinishReason: resp.StopReason,
		Metadata: map[string]any{
			"provider": "gemini",
			"streamed": true,
		},
	}, nil
}

func (a *GeminiProviderAdapter) HealthCheck(ctx context.Context) (*llm.HealthCheckResult, error) {
	start := time.Now()
	healthy := a.provider.IsHealthy()

	status := llm.HealthStatusUnhealthy
	message := "provider reports unhealthy"
	if healthy {
		status = llm.HealthStatusHealthy
		message = "provider is operational"
	}

	return &llm.HealthCheckResult{
		Status:      status,
		Latency:     time.Since(start),
		Message:     message,
		LastChecked: time.Now(),
	}, nil
}

func (a *GeminiProviderAdapter) Capabilities() []llm.Capability {
	return []llm.Capability{
		llm.CapabilityChat,
		llm.CapabilityCompletion,
		llm.CapabilityStreaming,
		llm.CapabilityVision,
		llm.CapabilityFunctionCalling,
		llm.CapabilityCodeGeneration,
		llm.CapabilityLongContext,
	}
}

func (a *GeminiProviderAdapter) SupportsStreaming() bool { return a.provider.SupportsStreaming() }

func (a *GeminiProviderAdapter) EstimateCost(req llm.CompletionRequest) *llm.CostEstimate {
	estimatedInputTokens, estimatedOutputTokens := estimateTokens(req)
	totalEstimate := calculateCost(estimatedInputTokens, estimatedOutputTokens,
		geminiInputCostPer1K, geminiOutputCostPer1K)

	return &llm.CostEstimate{
		InputCostPer1K:        geminiInputCostPer1K,
		OutputCostPer1K:       geminiOutputCostPer1K,
		EstimatedInputTokens:  estimatedInputTokens,
		EstimatedOutputTokens: estimatedOutputTokens,
		TotalEstimate:         totalEstimate,
		Currency:              "USD",
	}
}

func NewAzureOpenAIProviderFactory(config llm.ProviderConfig) (llm.Provider, error) {
	if config.APIKey == "" && config.APIKeySecretARN == "" {
		return nil, &llm.FactoryError{
			ProviderType: llm.ProviderTypeAzureOpenAI,
			Code:         llm.ErrFactoryInvalidConfig,
			Message:      "API key is required for Azure OpenAI provider",
		}
	}
	if config.Endpoint == "" {
		return nil, &llm.FactoryError{
			ProviderType: llm.ProviderTypeAzureOpenAI,
			Code:         llm.ErrFactoryInvalidConfig,
			Message:      "endpoint is required for Azure OpenAI provider",
		}
	}

	deploymentName := config.Model
	if deploymentName == "" {
		return nil, &llm.FactoryError{
			ProviderType: llm.ProviderTypeAzureOpenAI,
			Code:         llm.ErrFactoryInvalidConfig,
			Message:      "deployment name (model) is required for Azure OpenAI provider",
		}
	}

	timeout := azure.DefaultTimeout
	if config.TimeoutSeconds > 0 {
		timeout = time.Duration(config.TimeoutSeconds) * time.Second
	}

	apiVersion := azure.DefaultAPIVersion
	if config.Settings != nil {
		if v, ok := config.Settings["api_version"].(string); ok && v != "" {
			apiVersion = v
		}
	}

	provider, err := azure.NewProvider(azure.Config{
		Endpoint:       config.Endpoint,
		APIKey:         config.APIKey,
		DeploymentName: deploymentName,
		APIVersion:     apiVersion,
		Timeout:        timeout,
	})
	if err != nil {
		return nil, &llm.FactoryError{
			ProviderType: llm.ProviderTypeAzureOpenAI,
			Code:         llm.ErrFactoryCreationFailed,
			Message:      fmt.Sprintf("failed to create Azure OpenAI provider: %v", err),
			Cause:        err,
		}
	}

	adapter := &AzureOpenAIProviderAdapter{
		provider: provider,
		name:     providerNameOrDefault(config.Name, "azure-openai"),
		config:   config,
	}
	adapter.authProvider = llmsdk.NewAPIKeyAuth(config.APIKey)
	adapter.rateLimiter = buildSDKRateLimiter(config.RateLimit)

	builder := llmsdk.NewProviderBuilder(adapter.name, llm.ProviderTypeAzureOpenAI).
		WithModel(deploymentName).
		WithEndpoint(config.Endpoint).
		WithAuth(adapter.authProvider).
		WithTimeout(timeout).
		WithCapabilities(adapter.Capabilities()...).
		WithStreaming(true).
		WithCompleteFunc(adapter.completeRequest)
	if adapter.rateLimiter != nil {
		builder.WithRateLimiter(adapter.rateLimiter)
	}
	adapter.base = builder.Build()

	return adapter, nil
}

type AzureOpenAIProviderAdapter struct {
	provider     *azure.Provider
	name         string
	config       llm.ProviderConfig
	base         *llmsdk.CustomProvider
	authProvider llmsdk.AuthProvider
	rateLimiter  *llmsdk.RateLimiter
}

func (a *AzureOpenAIProviderAdapter) Name() string { return a.name }

func (a *AzureOpenAIProviderAdapter) Type() llm.ProviderType { return llm.ProviderTypeAzureOpenAI }

func (a *AzureOpenAIProviderAdapter) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	if a.base != nil {
		return a.base.Complete(ctx, req)
	}
	return a.completeRequest(ctx, req)
}

func (a *AzureOpenAIProviderAdapter) completeRequest(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	azureReq := azure.CompletionRequest{
		Prompt:        req.Prompt,
		SystemPrompt:  req.SystemPrompt,
		MaxTokens:     req.MaxTokens,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		Model:         req.Model,
		StopSequences: req.StopSequences,
		Stream:        req.Stream,
	}

	resp, err := a.provider.Complete(ctx, azureReq)
	if err != nil {
		return nil, err
	}

	return &llm.CompletionResponse{
		Content: resp.Content,
		Model:   resp.Model,
		Usage: llm.UsageStats{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		},
		Latency:      resp.Latency,
		FinishReason: resp.StopReason,
		Metadata: map[string]any{
			"provider":  "azure-openai",
			"auth_type": string(a.provider.GetAuthType()),
		},
	}, nil
}

func (a *AzureOpenAIProviderAdapter) CompleteStream(ctx context.Context, req llm.CompletionRequest, handler llm.StreamHandler) (*llm.CompletionResponse, error) {
	azureReq := azure.CompletionRequest{
		Prompt:        req.Prompt,
		SystemPrompt:  req.SystemPrompt,
		MaxTokens:     req.MaxTokens,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		Model:         req.Model,
		StopSequences: req.StopSequences,
		Stream:        true,
	}

	resp, err := a.provider.CompleteStream(ctx, azureReq, func(chunk azure.StreamChunk) error {
		if handler == nil {
			return nil
		}
		return handler(llm.StreamChunk{Type: chunk.Type, Content: chunk.Content, Done: chunk.Done})
	})
	if err != nil {
		return nil, err
	}

	return &llm.CompletionResponse{
		Content: resp.Content,
		Model:   resp.Model,
		Usage: llm.UsageStats{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		},
		Latency:      resp.Latency,
		FinishReason: resp.StopReason,
		Metadata: map[string]any{
			"provider":  "azure-openai",
			"auth_type": string(a.provider.GetAuthType()),
			"streamed":  true,
		},
	}, nil
}

func (a *AzureOpenAIProviderAdapter) HealthCheck(ctx context.Context) (*llm.HealthCheckResult, error) {
	start := time.Now()
	healthy := a.provider.IsHealthy()

	status := llm.HealthStatusUnhealthy
	message := "provider reports unhealthy"
	if healthy {
		status = llm.HealthStatusHealthy
		message = fmt.Sprintf("provider is operational (auth: %s)", a.provider.GetAuthType())
	}

	return &llm.HealthCheckResult{
		Status:      status,
		Latency:     time.Since(start),
		Message:     message,
		LastChecked: time.Now(),
	}, nil
}

func (a *AzureOpenAIProviderAdapter) Capabilities() []llm.Capability {
	return []llm.Capability{
		llm.CapabilityChat,
		llm.CapabilityCompletion,
		llm.CapabilityStreaming,
		llm.CapabilityVision,
		llm.CapabilityFunctionCalling,
		llm.CapabilityCodeGeneration,
		llm.CapabilityEmbeddings,
	}
}

func (a *AzureOpenAIProviderAdapter) SupportsStreaming() bool { return a.provider.SupportsStreaming() }

func (a *AzureOpenAIProviderAdapter) EstimateCost(req llm.CompletionRequest) *llm.CostEstimate {
	estimatedInputTokens, estimatedOutputTokens := estimateTokens(req)
	totalEstimate := calculateCost(estimatedInputTokens, estimatedOutputTokens,
		azureOpenAIInputCostPer1K, azureOpenAIOutputCostPer1K)

	return &llm.CostEstimate{
		InputCostPer1K:        azureOpenAIInputCostPer1K,
		OutputCostPer1K:       azureOpenAIOutputCostPer1K,
		EstimatedInputTokens:  estimatedInputTokens,
		EstimatedOutputTokens: estimatedOutputTokens,
		TotalEstimate:         totalEstimate,
		Currency:              "USD",
	}
}

var (
	_ llm.Provider          = (*AnthropicProviderAdapter)(nil)
	_ llm.Provider          = (*GeminiProviderAdapter)(nil)
	_ llm.StreamingProvider = (*GeminiProviderAdapter)(nil)
	_ llm.Provider          = (*AzureOpenAIProviderAdapter)(nil)
	_ llm.StreamingProvider = (*AzureOpenAIProviderAdapter)(nil)
)

const (
	ollamaDefaultEndpoint = "http://localhost:11434"
	ollamaDefaultModel    = "llama3.2:latest"
	ollamaDefaultTimeout  = 300 * time.Second
)

type ollamaProvider struct {
	name        string
	endpoint    string
	model       string
	timeout     time.Duration
	client      *http.Client
	healthy     bool
	base        *llmsdk.CustomProvider
	inner       llm.Provider // cached underlying provider for request delegation
	rateLimiter *llmsdk.RateLimiter
	mu          sync.RWMutex
}

func NewOllamaProviderFactory(config llm.ProviderConfig) (llm.Provider, error) {
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = ollamaDefaultEndpoint
	}
	endpoint = strings.TrimRight(endpoint, "/")

	model := config.Model
	if model == "" {
		model = ollamaDefaultModel
	}

	timeout := ollamaDefaultTimeout
	if config.TimeoutSeconds > 0 {
		timeout = time.Duration(config.TimeoutSeconds) * time.Second
	}

	provider := &ollamaProvider{
		name:     providerNameOrDefault(config.Name, "ollama"),
		endpoint: endpoint,
		model:    model,
		timeout:  timeout,
		client:   &http.Client{Timeout: timeout},
		healthy:  true,
	}
	// Create the underlying non-SDK provider once for request delegation
	inner, err := llm.NewOllamaProviderFactory(llm.ProviderConfig{
		Name:           provider.name,
		Type:           llm.ProviderTypeOllama,
		Endpoint:       endpoint,
		Model:          model,
		TimeoutSeconds: int(timeout / time.Second),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create underlying ollama provider: %w", err)
	}
	provider.inner = inner
	provider.rateLimiter = buildSDKRateLimiter(config.RateLimit)

	builder := llmsdk.NewProviderBuilder(provider.name, llm.ProviderTypeOllama).
		WithModel(model).
		WithEndpoint(endpoint).
		WithHTTPClient(provider.client).
		WithTimeout(timeout).
		WithCapabilities(provider.Capabilities()...).
		WithStreaming(true).
		WithCompleteFunc(provider.completeRequest)
	if provider.rateLimiter != nil {
		builder.WithRateLimiter(provider.rateLimiter)
	}
	provider.base = builder.Build()

	return provider, nil
}

func (p *ollamaProvider) Name() string            { return p.name }
func (p *ollamaProvider) Type() llm.ProviderType  { return llm.ProviderTypeOllama }
func (p *ollamaProvider) SupportsStreaming() bool { return true }
func (p *ollamaProvider) Capabilities() []llm.Capability {
	return []llm.Capability{llm.CapabilityChat, llm.CapabilityCompletion, llm.CapabilityStreaming, llm.CapabilityCodeGeneration}
}
func (p *ollamaProvider) EstimateCost(req llm.CompletionRequest) *llm.CostEstimate {
	in, out := estimateTokens(req)
	return &llm.CostEstimate{InputCostPer1K: 0, OutputCostPer1K: 0, EstimatedInputTokens: in, EstimatedOutputTokens: out, TotalEstimate: 0, Currency: "USD"}
}

func (p *ollamaProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	if p.base != nil {
		return p.base.Complete(ctx, req)
	}
	return p.completeRequest(ctx, req)
}

func (p *ollamaProvider) completeRequest(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	resp, err := p.inner.Complete(ctx, req)
	p.setHealthy(err == nil)
	return resp, err
}

func (p *ollamaProvider) CompleteStream(ctx context.Context, req llm.CompletionRequest, handler llm.StreamHandler) (*llm.CompletionResponse, error) {
	streaming, ok := p.inner.(llm.StreamingProvider)
	if !ok {
		return nil, fmt.Errorf("ollama provider does not support streaming")
	}
	resp, err := streaming.CompleteStream(ctx, req, handler)
	p.setHealthy(err == nil)
	return resp, err
}

func (p *ollamaProvider) HealthCheck(ctx context.Context) (*llm.HealthCheckResult, error) {
	start := time.Now()
	httpReq, err := http.NewRequestWithContext(ctx, "GET", p.endpoint+"/api/tags", nil)
	if err != nil {
		return &llm.HealthCheckResult{Status: llm.HealthStatusUnhealthy, Latency: time.Since(start), Message: fmt.Sprintf("failed to create request: %v", err), LastChecked: time.Now()}, nil
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return &llm.HealthCheckResult{Status: llm.HealthStatusUnhealthy, Latency: time.Since(start), Message: fmt.Sprintf("connection failed: %v", err), LastChecked: time.Now()}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		p.setHealthy(false)
		return &llm.HealthCheckResult{Status: llm.HealthStatusUnhealthy, Latency: time.Since(start), Message: fmt.Sprintf("unhealthy status: %d", resp.StatusCode), LastChecked: time.Now()}, nil
	}

	p.setHealthy(true)
	return &llm.HealthCheckResult{Status: llm.HealthStatusHealthy, Latency: time.Since(start), Message: "Ollama server is operational", LastChecked: time.Now()}, nil
}

func (p *ollamaProvider) setHealthy(healthy bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthy = healthy
}

var (
	_ llm.Provider          = (*ollamaProvider)(nil)
	_ llm.StreamingProvider = (*ollamaProvider)(nil)
)
