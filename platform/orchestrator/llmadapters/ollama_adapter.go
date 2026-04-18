//go:build enterprise

// Copyright 2025 AxonFlow
// Licensed under the Elastic License 2.0 (ELv2)
// Enterprise features - not available in Community distribution

package llmadapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"axonflow/platform/orchestrator/llm"
)

// OllamaAdapter implements the unified llm.Provider interface for Ollama.
// This adapter provides direct integration with self-hosted Ollama instances.
type OllamaAdapter struct {
	httpClient *http.Client
	name       string
	endpoint   string
	model      string
}

// OllamaAdapterConfig contains configuration for creating an OllamaAdapter.
type OllamaAdapterConfig struct {
	// Name is the unique identifier for this provider instance.
	Name string

	// Endpoint is the Ollama API endpoint (e.g., "http://localhost:11434").
	Endpoint string

	// Model is the default model to use (e.g., "llama3", "llama3.2", "mistral").
	// Default: "llama3" (requires this model to be pulled in Ollama)
	Model string

	// HTTPClient is an optional custom HTTP client. If nil, a default client is used.
	HTTPClient *http.Client
}

// ollamaRequest represents the request body for Ollama API.
type ollamaRequest struct {
	Model       string  `json:"model"`
	Prompt      string  `json:"prompt"`
	Stream      bool    `json:"stream"`
	Options     *ollamaOptions `json:"options,omitempty"`
}

type ollamaOptions struct {
	Temperature float64 `json:"temperature,omitempty"`
	NumPredict  int     `json:"num_predict,omitempty"`
}

// ollamaResponse represents the response from Ollama API.
type ollamaResponse struct {
	Model              string `json:"model"`
	Response           string `json:"response"`
	Done               bool   `json:"done"`
	PromptEvalCount    int    `json:"prompt_eval_count"`
	EvalCount          int    `json:"eval_count"`
	TotalDuration      int64  `json:"total_duration"`
	LoadDuration       int64  `json:"load_duration"`
	PromptEvalDuration int64  `json:"prompt_eval_duration"`
	EvalDuration       int64  `json:"eval_duration"`
}

// NewOllamaAdapter creates a new OllamaAdapter.
func NewOllamaAdapter(cfg OllamaAdapterConfig) (*OllamaAdapter, error) {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "http://localhost:11434"
	}

	if cfg.Model == "" {
		cfg.Model = "llama3"
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 120 * time.Second,
		}
	}

	name := cfg.Name
	if name == "" {
		name = "ollama"
	}

	return &OllamaAdapter{
		httpClient: httpClient,
		name:       name,
		endpoint:   cfg.Endpoint,
		model:      cfg.Model,
	}, nil
}

// Name returns the unique identifier for this provider instance.
func (a *OllamaAdapter) Name() string {
	return a.name
}

// Type returns the provider type.
func (a *OllamaAdapter) Type() llm.ProviderType {
	return llm.ProviderTypeOllama
}

// Complete generates a completion using Ollama.
func (a *OllamaAdapter) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	start := time.Now()

	model := req.Model
	if model == "" {
		model = a.model
	}

	ollamaReq := ollamaRequest{
		Model:  model,
		Prompt: req.Prompt,
		Stream: false,
	}

	if req.Temperature > 0 || req.MaxTokens > 0 {
		ollamaReq.Options = &ollamaOptions{
			Temperature: req.Temperature,
			NumPredict:  req.MaxTokens,
		}
	}

	reqBody, err := json.Marshal(ollamaReq)
	if err != nil {
		return nil, &llm.ProviderError{
			Provider:  a.name,
			Code:      llm.ErrCodeInvalidRequest,
			Message:   fmt.Sprintf("failed to marshal request: %v", err),
			Retryable: false,
			Cause:     err,
		}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/api/generate", bytes.NewReader(reqBody))
	if err != nil {
		return nil, &llm.ProviderError{
			Provider:  a.name,
			Code:      llm.ErrCodeInvalidRequest,
			Message:   fmt.Sprintf("failed to create request: %v", err),
			Retryable: false,
			Cause:     err,
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &llm.ProviderError{
			Provider:  a.name,
			Code:      llm.ErrCodeUnavailable,
			Message:   fmt.Sprintf("request failed: %v", err),
			Retryable: true,
			Cause:     err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &llm.ProviderError{
			Provider:   a.name,
			Code:       llm.ErrCodeServerError,
			Message:    fmt.Sprintf("ollama returned status %d: %s", resp.StatusCode, string(body)),
			StatusCode: resp.StatusCode,
			Retryable:  resp.StatusCode >= 500,
		}
	}

	var ollamaResp ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return nil, &llm.ProviderError{
			Provider:  a.name,
			Code:      llm.ErrCodeServerError,
			Message:   fmt.Sprintf("failed to decode response: %v", err),
			Retryable: false,
			Cause:     err,
		}
	}

	return &llm.CompletionResponse{
		Content: ollamaResp.Response,
		Model:   ollamaResp.Model,
		Usage: llm.UsageStats{
			PromptTokens:     ollamaResp.PromptEvalCount,
			CompletionTokens: ollamaResp.EvalCount,
			TotalTokens:      ollamaResp.PromptEvalCount + ollamaResp.EvalCount,
		},
		Latency: time.Since(start),
	}, nil
}

// HealthCheck verifies the provider is operational.
func (a *OllamaAdapter) HealthCheck(ctx context.Context) (*llm.HealthCheckResult, error) {
	start := time.Now()

	// Check if Ollama is reachable via the tags endpoint (lightweight)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/api/tags", nil)
	if err != nil {
		return &llm.HealthCheckResult{
			Status:      llm.HealthStatusUnhealthy,
			Latency:     time.Since(start),
			Message:     fmt.Sprintf("failed to create request: %v", err),
			LastChecked: time.Now(),
		}, nil
	}

	resp, err := a.httpClient.Do(httpReq)
	latency := time.Since(start)

	if err != nil {
		return &llm.HealthCheckResult{
			Status:      llm.HealthStatusUnhealthy,
			Latency:     latency,
			Message:     fmt.Sprintf("connection failed: %v", err),
			LastChecked: time.Now(),
		}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &llm.HealthCheckResult{
			Status:      llm.HealthStatusUnhealthy,
			Latency:     latency,
			Message:     fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
			LastChecked: time.Now(),
		}, nil
	}

	return &llm.HealthCheckResult{
		Status:      llm.HealthStatusHealthy,
		Latency:     latency,
		Message:     "Ollama API is responsive",
		LastChecked: time.Now(),
	}, nil
}

// Capabilities returns the features supported by Ollama.
func (a *OllamaAdapter) Capabilities() []llm.Capability {
	return []llm.Capability{
		llm.CapabilityChat,
		llm.CapabilityCompletion,
		llm.CapabilityStreaming,
	}
}

// SupportsStreaming indicates Ollama supports streaming responses.
func (a *OllamaAdapter) SupportsStreaming() bool {
	return true
}

// EstimateCost provides cost estimation for Ollama requests.
// Ollama is self-hosted, so there's no per-request cost.
func (a *OllamaAdapter) EstimateCost(req llm.CompletionRequest) *llm.CostEstimate {
	inputTokens := len(req.Prompt) / 4
	if inputTokens < 1 {
		inputTokens = 1
	}

	outputTokens := req.MaxTokens
	if outputTokens == 0 {
		outputTokens = 1000
	}

	// Ollama is self-hosted - no per-token cost
	return &llm.CostEstimate{
		InputCostPer1K:        0,
		OutputCostPer1K:       0,
		EstimatedInputTokens:  inputTokens,
		EstimatedOutputTokens: outputTokens,
		TotalEstimate:         0,
		Currency:              "USD",
	}
}

// Compile-time interface compliance check
var _ llm.Provider = (*OllamaAdapter)(nil)
