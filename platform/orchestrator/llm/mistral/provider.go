// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package mistral provides an LLM provider implementation for Mistral AI models.
// It supports Mistral Small, Mistral Large, Codestral, and other Mistral models
// with both streaming and non-streaming completion modes via the OpenAI-compatible API.
package mistral

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
	// DefaultBaseURL is the default Mistral API endpoint.
	DefaultBaseURL = "https://api.mistral.ai"

	// DefaultTimeout is the default HTTP timeout.
	DefaultTimeout = 120 * time.Second

	// DefaultMaxTokens is the default max output tokens for completions.
	DefaultMaxTokens = 4096

	// DefaultTemperature is the default temperature for completions.
	DefaultTemperature = 0.7
)

// Model constants for supported Mistral models.
const (
	ModelMistralSmallLatest  = "mistral-small-latest"
	ModelMistralMediumLatest = "mistral-medium-latest"
	ModelMistralLargeLatest  = "mistral-large-latest"
	ModelCodestralLatest     = "codestral-latest"
	ModelOpenMistralNemo     = "open-mistral-nemo"
	ModelMinistral8BLatest   = "ministral-8b-latest"
	ModelPixtralLargeLatest  = "pixtral-large-latest"

	// Default model - use Mistral Small for best cost/performance ratio.
	DefaultModel = ModelMistralSmallLatest
)

// HTTPClient is an interface for HTTP client operations (enables testing).
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Provider implements the LLM provider interface for Mistral AI.
type Provider struct {
	apiKey  string
	baseURL string
	model   string
	timeout time.Duration
	client  HTTPClient
	healthy bool
	mu      sync.RWMutex
}

// Config contains configuration for the Mistral provider.
type Config struct {
	APIKey  string        // Required: Mistral API key
	BaseURL string        // Optional: API base URL (default: https://api.mistral.ai)
	Model   string        // Optional: Default model (default: mistral-small-latest)
	Timeout time.Duration // Optional: HTTP timeout (default: 120s)
}

// CompletionRequest represents a completion request to Mistral.
type CompletionRequest struct {
	Prompt        string   // The prompt/user message
	SystemPrompt  string   // Optional system instruction
	MaxTokens     int      // Maximum tokens to generate
	Temperature   float64  // Temperature (0.0-2.0)
	TopP          float64  // Top-p sampling (0.0-1.0)
	Model         string   // Model override
	StopSequences []string // Stop sequences
	Stream        bool     // Enable streaming
}

// CompletionResponse represents a completion response from Mistral.
type CompletionResponse struct {
	Content    string
	Model      string
	StopReason string
	Usage      UsageStats
	Latency    time.Duration
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

// NewProvider creates a new Mistral provider instance.
func NewProvider(cfg Config) (*Provider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("mistral API key is required")
	}

	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}

	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}

	return &Provider{
		apiKey:  cfg.APIKey,
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		model:   cfg.Model,
		timeout: cfg.Timeout,
		client:  &http.Client{Timeout: cfg.Timeout},
		healthy: true,
	}, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return "mistral"
}

// SupportsStreaming indicates if the provider supports streaming.
func (p *Provider) SupportsStreaming() bool {
	return true
}

// GetCapabilities returns the provider's capabilities.
// Note: function_calling and vision (Pixtral) require additional request/response
// fields (tools, tool_choice, image content blocks) that are not yet implemented.
// These will be added in a future release.
func (p *Provider) GetCapabilities() []string {
	return []string{
		"reasoning",
		"analysis",
		"writing",
		"code_generation",
		"streaming",
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
// Pricing based on Mistral Small: $0.10/1M input, $0.30/1M output.
// Using average estimate: $0.0000002 per token.
func (p *Provider) EstimateCost(tokens int) float64 {
	return float64(tokens) * 0.0000002
}

// Complete generates a completion for the given request.
func (p *Provider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	start := time.Now()

	model := req.Model
	if model == "" {
		model = p.model
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

	// Build API request body
	apiReq := p.buildAPIRequest(req.Prompt, req.SystemPrompt, model, maxTokens, temperature, req.TopP, req.StopSequences, false)

	// Marshal request
	reqBody, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build URL
	url := fmt.Sprintf("%s/v1/chat/completions", p.baseURL)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	// Execute request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return nil, fmt.Errorf("mistral API error: %w", err)
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

	// Parse response
	var apiResp chatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract content
	content := ""
	if len(apiResp.Choices) > 0 {
		content = apiResp.Choices[0].Message.Content
	}

	// Determine stop reason
	stopReason := "unknown"
	if len(apiResp.Choices) > 0 {
		stopReason = mapFinishReason(apiResp.Choices[0].FinishReason)
	}

	// Extract usage
	inputTokens := apiResp.Usage.PromptTokens
	outputTokens := apiResp.Usage.CompletionTokens

	return &CompletionResponse{
		Content:    content,
		Model:      apiResp.Model,
		StopReason: stopReason,
		Usage: UsageStats{
			InputTokens:  inputTokens,
			OutputTokens: outputTokens,
			TotalTokens:  inputTokens + outputTokens,
		},
		Latency: time.Since(start),
	}, nil
}

// CompleteStream generates a streaming completion for the given request.
func (p *Provider) CompleteStream(ctx context.Context, req CompletionRequest, handler StreamHandler) (*CompletionResponse, error) {
	start := time.Now()

	model := req.Model
	if model == "" {
		model = p.model
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

	// Build API request body with streaming enabled
	apiReq := p.buildAPIRequest(req.Prompt, req.SystemPrompt, model, maxTokens, temperature, req.TopP, req.StopSequences, true)

	// Marshal request
	reqBody, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build URL
	url := fmt.Sprintf("%s/v1/chat/completions", p.baseURL)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpReq.Header.Set("Accept", "text/event-stream")

	// Execute request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return nil, fmt.Errorf("mistral API error: %w", err)
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
	return p.processStream(resp.Body, handler, start, model)
}

// buildAPIRequest builds the Mistral chat completions API request body.
func (p *Provider) buildAPIRequest(prompt, systemPrompt, model string, maxTokens int, temperature, topP float64, stopSequences []string, stream bool) chatCompletionRequest {
	var messages []chatMessage

	// Add system message if provided
	if systemPrompt != "" {
		messages = append(messages, chatMessage{
			Role:    "system",
			Content: systemPrompt,
		})
	}

	// Add user message
	messages = append(messages, chatMessage{
		Role:    "user",
		Content: prompt,
	})

	apiReq := chatCompletionRequest{
		Model:       model,
		Messages:    messages,
		MaxTokens:   maxTokens,
		Temperature: temperature,
		Stream:      stream,
	}

	if topP > 0 {
		apiReq.TopP = &topP
	}

	if len(stopSequences) > 0 {
		apiReq.Stop = stopSequences
	}

	return apiReq
}

// processStream processes the SSE stream from Mistral.
func (p *Provider) processStream(body io.Reader, handler StreamHandler, start time.Time, model string) (*CompletionResponse, error) {
	scanner := bufio.NewScanner(body)
	var contentBuilder strings.Builder
	var stopReason string
	var inputTokens, outputTokens int
	var responseModel string

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines
		if line == "" {
			continue
		}

		// Parse SSE event
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")

		// Check for stream termination
		if data == "[DONE]" {
			break
		}

		// Parse event data
		var event chatCompletionStreamResponse
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue // Skip malformed events
		}

		if event.Model != "" {
			responseModel = event.Model
		}

		// Extract content from choices
		if len(event.Choices) > 0 {
			choice := event.Choices[0]

			// Extract delta content
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

		// Extract usage from final chunk (Mistral includes usage in the last event)
		if event.Usage != nil {
			inputTokens = event.Usage.PromptTokens
			outputTokens = event.Usage.CompletionTokens
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
		Object  string `json:"object"`
		Message string `json:"message"`
		Type    string `json:"type"`
		Param   string `json:"param"`
		Code    string `json:"code"`
	}

	if err := json.Unmarshal(body, &errResp); err != nil {
		return fmt.Errorf("mistral API error (status %d): %s", statusCode, string(body))
	}

	return &APIError{
		StatusCode: statusCode,
		Type:       errResp.Type,
		Code:       errResp.Code,
		Message:    errResp.Message,
	}
}

// mapFinishReason maps Mistral finish reasons to standard reasons.
func mapFinishReason(reason string) string {
	switch reason {
	case "stop":
		return "stop"
	case "length":
		return "max_tokens"
	case "model_length":
		return "max_tokens"
	case "content_filter":
		return "content_filter"
	default:
		return reason
	}
}

// APIError represents a Mistral API error.
type APIError struct {
	StatusCode int
	Type       string
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("mistral API error (status %d, type %s, code %s): %s",
		e.StatusCode, e.Type, e.Code, e.Message)
}

// IsRateLimitError returns true if this is a rate limit error.
func (e *APIError) IsRateLimitError() bool {
	return e.StatusCode == http.StatusTooManyRequests
}

// IsAuthError returns true if this is an authentication error.
func (e *APIError) IsAuthError() bool {
	return e.StatusCode == http.StatusUnauthorized ||
		e.StatusCode == http.StatusForbidden ||
		e.Type == "authentication_error"
}

// IsQuotaExceededError returns true if this is a quota exceeded error.
func (e *APIError) IsQuotaExceededError() bool {
	return e.StatusCode == http.StatusTooManyRequests && e.Type == "quota_exceeded"
}

// Internal API types (OpenAI-compatible)

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens"`
	Temperature float64       `json:"temperature"`
	TopP        *float64      `json:"top_p,omitempty"`
	Stream      bool          `json:"stream"`
	Stop        []string      `json:"stop,omitempty"`
}

type chatCompletionResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int         `json:"index"`
		Message      chatMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

type chatCompletionStreamResponse struct {
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

// GetSupportedModels returns a list of supported Mistral models.
func GetSupportedModels() []string {
	return []string{
		ModelMistralSmallLatest,
		ModelMistralMediumLatest,
		ModelMistralLargeLatest,
		ModelCodestralLatest,
		ModelOpenMistralNemo,
		ModelMinistral8BLatest,
		ModelPixtralLargeLatest,
	}
}

// IsValidModel checks if the given model is a valid Mistral model.
func IsValidModel(model string) bool {
	for _, m := range GetSupportedModels() {
		if m == model {
			return true
		}
	}
	// Also allow custom/future models starting with "mistral-", "codestral-", "open-mistral-", "ministral-", or "pixtral-"
	return strings.HasPrefix(model, "mistral-") ||
		strings.HasPrefix(model, "codestral-") ||
		strings.HasPrefix(model, "open-mistral-") ||
		strings.HasPrefix(model, "ministral-") ||
		strings.HasPrefix(model, "pixtral-")
}

// SetHTTPClient sets a custom HTTP client for testing.
func (p *Provider) SetHTTPClient(client HTTPClient) {
	p.client = client
}
