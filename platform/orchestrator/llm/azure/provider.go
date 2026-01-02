// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package azure provides an LLM provider implementation for Azure OpenAI Service.
// It supports GPT-4, GPT-4o, GPT-4o-mini, and other Azure-hosted OpenAI models
// with both streaming and non-streaming completion modes.
package azure

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultAPIVersion is the default Azure OpenAI API version.
	DefaultAPIVersion = "2024-08-01-preview"

	// DefaultTimeout is the default HTTP timeout.
	DefaultTimeout = 120 * time.Second

	// DefaultMaxTokens is the default max output tokens for completions.
	DefaultMaxTokens = 4096

	// DefaultTemperature is the default temperature for completions.
	DefaultTemperature = 0.7
)

// Model constants for common Azure OpenAI deployments.
const (
	// GPT-4o models
	ModelGPT4o     = "gpt-4o"
	ModelGPT4oMini = "gpt-4o-mini"

	// GPT-4 models
	ModelGPT4       = "gpt-4"
	ModelGPT4Turbo  = "gpt-4-turbo"
	ModelGPT432K    = "gpt-4-32k"

	// GPT-3.5 models
	ModelGPT35Turbo    = "gpt-35-turbo"
	ModelGPT35Turbo16K = "gpt-35-turbo-16k"

	// Default model
	DefaultModel = ModelGPT4oMini
)

// HTTPClient is an interface for HTTP client operations (enables testing).
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// AuthType represents the authentication method for Azure OpenAI.
type AuthType string

const (
	// AuthTypeAPIKey uses the api-key header (Classic Azure OpenAI)
	AuthTypeAPIKey AuthType = "api-key"

	// AuthTypeBearer uses Authorization: Bearer header (Azure AI Foundry)
	AuthTypeBearer AuthType = "bearer"
)

// Provider implements the LLM provider interface for Azure OpenAI.
type Provider struct {
	endpoint       string // Azure OpenAI endpoint (e.g., https://myresource.openai.azure.com)
	apiKey         string
	deploymentName string // Azure deployment name
	apiVersion     string
	authType       AuthType // Authentication type (auto-detected from endpoint)
	timeout        time.Duration
	client         HTTPClient
	healthy        bool
	mu             sync.RWMutex
}

// Config contains configuration for the Azure OpenAI provider.
type Config struct {
	Endpoint       string        // Required: Azure OpenAI endpoint URL
	APIKey         string        // Required: Azure OpenAI API key or Bearer token
	DeploymentName string        // Required: Azure deployment name
	APIVersion     string        // Optional: API version (default: 2024-08-01-preview)
	AuthType       AuthType      // Optional: Auth type (auto-detected from endpoint if empty)
	Timeout        time.Duration // Optional: HTTP timeout (default: 120s)
}

// CompletionRequest represents a completion request to Azure OpenAI.
type CompletionRequest struct {
	Prompt        string   // The prompt/user message
	SystemPrompt  string   // Optional system instruction
	MaxTokens     int      // Maximum tokens to generate
	Temperature   float64  // Temperature (0.0-2.0)
	TopP          float64  // Top-p sampling (0.0-1.0)
	Model         string   // Model override (maps to deployment name in Azure)
	StopSequences []string // Stop sequences
	Stream        bool     // Enable streaming
}

// CompletionResponse represents a completion response from Azure OpenAI.
type CompletionResponse struct {
	Content      string
	Model        string
	StopReason   string
	Usage        UsageStats
	Latency      time.Duration
}

// UsageStats contains token usage statistics.
type UsageStats struct {
	InputTokens  int
	OutputTokens int
	TotalTokens  int
}

// StreamChunk represents a single chunk in a streaming response.
type StreamChunk struct {
	Type    string // "content", "done", "error"
	Content string // The text content
	Done    bool   // Whether this is the final chunk
}

// StreamHandler is a callback function for handling stream chunks.
type StreamHandler func(chunk StreamChunk) error

// NewProvider creates a new Azure OpenAI provider instance.
func NewProvider(cfg Config) (*Provider, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("azure OpenAI endpoint is required")
	}

	if cfg.APIKey == "" {
		return nil, fmt.Errorf("azure OpenAI API key is required")
	}

	if cfg.DeploymentName == "" {
		return nil, fmt.Errorf("azure OpenAI deployment name is required")
	}

	// Normalize endpoint (remove trailing slash)
	cfg.Endpoint = strings.TrimRight(cfg.Endpoint, "/")

	if cfg.APIVersion == "" {
		cfg.APIVersion = DefaultAPIVersion
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}

	// Auto-detect auth type from endpoint if not specified
	authType := cfg.AuthType
	if authType == "" {
		authType = detectAuthType(cfg.Endpoint)
	}

	return &Provider{
		endpoint:       cfg.Endpoint,
		apiKey:         cfg.APIKey,
		deploymentName: cfg.DeploymentName,
		apiVersion:     cfg.APIVersion,
		authType:       authType,
		timeout:        cfg.Timeout,
		client:         &http.Client{Timeout: cfg.Timeout},
		healthy:        true,
	}, nil
}

// detectAuthType auto-detects the authentication type based on the endpoint URL.
// - Classic Azure OpenAI (*.openai.azure.com) uses api-key header
// - Azure AI Foundry (*.cognitiveservices.azure.com) uses Bearer token
func detectAuthType(endpoint string) AuthType {
	endpoint = strings.ToLower(endpoint)
	if strings.Contains(endpoint, ".cognitiveservices.azure.com") {
		return AuthTypeBearer
	}
	// Default to api-key for *.openai.azure.com and other endpoints
	return AuthTypeAPIKey
}

// setAuthHeaders sets the appropriate authentication headers based on auth type.
func (p *Provider) setAuthHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	switch p.authType {
	case AuthTypeBearer:
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	default:
		req.Header.Set("api-key", p.apiKey)
	}
}

// GetAuthType returns the authentication type being used.
func (p *Provider) GetAuthType() AuthType {
	return p.authType
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return "azure-openai"
}

// SupportsStreaming indicates if the provider supports streaming.
func (p *Provider) SupportsStreaming() bool {
	return true
}

// GetCapabilities returns the provider's capabilities.
func (p *Provider) GetCapabilities() []string {
	return []string{
		"reasoning",
		"analysis",
		"writing",
		"code_generation",
		"vision",
		"streaming",
		"function_calling",
	}
}

// IsHealthy returns whether the provider is healthy.
func (p *Provider) IsHealthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.healthy && p.apiKey != ""
}

// setHealthy updates the provider health status.
func (p *Provider) setHealthy(healthy bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthy = healthy
}

// EstimateCost estimates the cost for a given number of tokens.
// Pricing based on GPT-4o: $2.50/1M input, $10/1M output.
// Using average estimate: $0.00000625 per token.
func (p *Provider) EstimateCost(tokens int) float64 {
	return float64(tokens) * 0.00000625
}

// buildURL constructs the Azure OpenAI API URL.
func (p *Provider) buildURL(deploymentName string, stream bool) string {
	// Azure OpenAI URL format:
	// https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions?api-version={version}
	return fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		p.endpoint, deploymentName, p.apiVersion)
}

// Complete generates a completion for the given request.
func (p *Provider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	start := time.Now()

	// Use deployment name from config, or override from request
	deploymentName := p.deploymentName
	if req.Model != "" {
		deploymentName = req.Model
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = DefaultMaxTokens
	}

	// Temperature: 0.0 is valid (deterministic), negative is invalid
	temperature := req.Temperature
	if temperature < 0 {
		temperature = DefaultTemperature
	}

	// Build messages
	messages := make([]map[string]string, 0, 2)
	if req.SystemPrompt != "" {
		messages = append(messages, map[string]string{
			"role":    "system",
			"content": req.SystemPrompt,
		})
	}
	messages = append(messages, map[string]string{
		"role":    "user",
		"content": req.Prompt,
	})

	// Build Azure OpenAI request (same format as OpenAI)
	apiReq := map[string]any{
		"messages":    messages,
		"max_tokens":  maxTokens,
		"temperature": temperature,
	}

	if req.TopP > 0 {
		apiReq["top_p"] = req.TopP
	}

	if len(req.StopSequences) > 0 {
		apiReq["stop"] = req.StopSequences
	}

	// Marshal request
	reqBody, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build URL
	url := p.buildURL(deploymentName, false)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication headers based on auth type
	p.setAuthHeaders(httpReq)

	// Execute request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return nil, fmt.Errorf("azure OpenAI API error: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 500 {
			p.setHealthy(false)
		}
		return nil, p.parseAPIError(resp.StatusCode, body)
	}

	p.setHealthy(true)

	// Parse response (same format as OpenAI)
	var apiResp openAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract content
	content := ""
	finishReason := "unknown"
	if len(apiResp.Choices) > 0 {
		content = apiResp.Choices[0].Message.Content
		finishReason = mapFinishReason(apiResp.Choices[0].FinishReason)
	}

	return &CompletionResponse{
		Content:    content,
		Model:      apiResp.Model,
		StopReason: finishReason,
		Usage: UsageStats{
			InputTokens:  apiResp.Usage.PromptTokens,
			OutputTokens: apiResp.Usage.CompletionTokens,
			TotalTokens:  apiResp.Usage.TotalTokens,
		},
		Latency: time.Since(start),
	}, nil
}

// CompleteStream generates a streaming completion for the given request.
func (p *Provider) CompleteStream(ctx context.Context, req CompletionRequest, handler StreamHandler) (*CompletionResponse, error) {
	start := time.Now()

	// Use deployment name from config, or override from request
	deploymentName := p.deploymentName
	if req.Model != "" {
		deploymentName = req.Model
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = DefaultMaxTokens
	}

	// Temperature: 0.0 is valid (deterministic), negative is invalid
	temperature := req.Temperature
	if temperature < 0 {
		temperature = DefaultTemperature
	}

	// Build messages
	messages := make([]map[string]string, 0, 2)
	if req.SystemPrompt != "" {
		messages = append(messages, map[string]string{
			"role":    "system",
			"content": req.SystemPrompt,
		})
	}
	messages = append(messages, map[string]string{
		"role":    "user",
		"content": req.Prompt,
	})

	// Build Azure OpenAI request with streaming enabled
	apiReq := map[string]any{
		"messages":    messages,
		"max_tokens":  maxTokens,
		"temperature": temperature,
		"stream":      true,
	}

	if req.TopP > 0 {
		apiReq["top_p"] = req.TopP
	}

	if len(req.StopSequences) > 0 {
		apiReq["stop"] = req.StopSequences
	}

	// Marshal request
	reqBody, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build URL
	url := p.buildURL(deploymentName, true)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication headers based on auth type
	p.setAuthHeaders(httpReq)
	httpReq.Header.Set("Accept", "text/event-stream")

	// Execute request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return nil, fmt.Errorf("azure OpenAI API error: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 500 {
			p.setHealthy(false)
		}
		return nil, p.parseAPIError(resp.StatusCode, body)
	}

	p.setHealthy(true)

	// Process SSE stream
	return p.processStream(resp.Body, handler, start, deploymentName)
}

// processStream processes the SSE stream from Azure OpenAI.
func (p *Provider) processStream(body io.Reader, handler StreamHandler, start time.Time, model string) (*CompletionResponse, error) {
	scanner := bufio.NewScanner(body)
	var contentBuilder strings.Builder
	var stopReason string
	var inputTokens, outputTokens int
	var responseModel string

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}

		// Parse SSE event
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		// Parse event data
		var chunk streamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue // Skip malformed events
		}

		if chunk.Model != "" {
			responseModel = chunk.Model
		}

		// Extract content from choices
		if len(chunk.Choices) > 0 {
			choice := chunk.Choices[0]

			// Extract text content
			if choice.Delta.Content != "" {
				contentBuilder.WriteString(choice.Delta.Content)
				if handler != nil {
					if err := handler(StreamChunk{
						Type:    "content",
						Content: choice.Delta.Content,
						Done:    false,
					}); err != nil {
						return nil, fmt.Errorf("handler error: %w", err)
					}
				}
			}

			// Check for finish reason
			if choice.FinishReason != "" {
				stopReason = mapFinishReason(choice.FinishReason)
			}
		}

		// Extract usage metadata (Azure may include this in final chunk)
		if chunk.Usage != nil {
			inputTokens = chunk.Usage.PromptTokens
			outputTokens = chunk.Usage.CompletionTokens
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("stream read error: %w", err)
	}

	// Send final done chunk
	if handler != nil {
		if err := handler(StreamChunk{Type: "done", Done: true}); err != nil {
			return nil, fmt.Errorf("handler error: %w", err)
		}
	}

	if responseModel == "" {
		responseModel = model
	}

	return &CompletionResponse{
		Content:    contentBuilder.String(),
		Model:      responseModel,
		StopReason: stopReason,
		Usage: UsageStats{
			InputTokens:  inputTokens,
			OutputTokens: outputTokens,
			TotalTokens:  inputTokens + outputTokens,
		},
		Latency: time.Since(start),
	}, nil
}

// parseAPIError parses an API error response.
func (p *Provider) parseAPIError(statusCode int, body []byte) error {
	var errResp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &errResp); err != nil {
		return fmt.Errorf("azure OpenAI API error (status %d): %s", statusCode, string(body))
	}

	return &APIError{
		StatusCode: statusCode,
		Code:       errResp.Error.Code,
		Type:       errResp.Error.Type,
		Message:    errResp.Error.Message,
	}
}

// mapFinishReason maps Azure OpenAI finish reasons to standard reasons.
func mapFinishReason(reason string) string {
	switch reason {
	case "stop":
		return "stop"
	case "length":
		return "max_tokens"
	case "content_filter":
		return "content_filter"
	default:
		return reason
	}
}

// APIError represents an Azure OpenAI API error.
type APIError struct {
	StatusCode int
	Code       string
	Type       string
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("azure OpenAI API error (status %d, code %s, type %s): %s",
		e.StatusCode, e.Code, e.Type, e.Message)
}

// IsRateLimitError returns true if this is a rate limit error.
func (e *APIError) IsRateLimitError() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.Code == "rate_limit_exceeded"
}

// IsAuthError returns true if this is an authentication error.
func (e *APIError) IsAuthError() bool {
	return e.StatusCode == http.StatusUnauthorized ||
		e.StatusCode == http.StatusForbidden ||
		e.Code == "invalid_api_key"
}

// IsQuotaExceededError returns true if this is a quota exceeded error.
func (e *APIError) IsQuotaExceededError() bool {
	return e.Code == "quota_exceeded" || e.Code == "insufficient_quota"
}

// Internal API types (OpenAI-compatible format)

type openAIResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int `json:"index"`
		Message      struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

type streamChunk struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role    string `json:"role,omitempty"`
			Content string `json:"content,omitempty"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason,omitempty"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage,omitempty"`
}

// GetSupportedModels returns a list of common Azure OpenAI model deployments.
func GetSupportedModels() []string {
	return []string{
		ModelGPT4o,
		ModelGPT4oMini,
		ModelGPT4,
		ModelGPT4Turbo,
		ModelGPT432K,
		ModelGPT35Turbo,
		ModelGPT35Turbo16K,
	}
}

// IsValidModel checks if the given model is a valid Azure OpenAI model.
// Note: In Azure, the "model" is actually the deployment name, so any name is valid.
func IsValidModel(model string) bool {
	// Any non-empty string is valid as a deployment name
	return model != ""
}

// SetHTTPClient sets a custom HTTP client for testing.
func (p *Provider) SetHTTPClient(client HTTPClient) {
	p.client = client
}
