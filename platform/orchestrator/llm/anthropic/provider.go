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

// Package anthropic provides an LLM provider implementation for Anthropic's Claude models.
// It supports Claude 3.5 Sonnet, Claude 3 Opus, Claude 4, and other Claude models
// with both streaming and non-streaming completion modes.
package anthropic

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
	// DefaultBaseURL is the default Anthropic API endpoint
	DefaultBaseURL = "https://api.anthropic.com"

	// DefaultAPIVersion is the Anthropic API version
	DefaultAPIVersion = "2023-06-01"

	// DefaultTimeout is the default HTTP timeout
	DefaultTimeout = 120 * time.Second

	// DefaultMaxTokens is the default max tokens for completions
	DefaultMaxTokens = 4096

	// DefaultTemperature is the default temperature for completions
	DefaultTemperature = 0.7
)

// Model constants for supported Claude models
const (
	// Claude 4 models (Opus 4 and Sonnet 4)
	ModelClaude4Opus   = "claude-opus-4-20250514"
	ModelClaude4Sonnet = "claude-sonnet-4-20250514"

	// Claude 3.5 models
	ModelClaude35Sonnet    = "claude-3-5-sonnet-20241022"
	ModelClaude35SonnetOld = "claude-3-5-sonnet-20240620"
	ModelClaude35Haiku     = "claude-3-5-haiku-20241022"

	// Claude 3 models
	ModelClaude3Opus   = "claude-3-opus-20240229"
	ModelClaude3Sonnet = "claude-3-sonnet-20240229"
	ModelClaude3Haiku  = "claude-3-haiku-20240307"

	// Default model
	DefaultModel = ModelClaude35Sonnet
)

// HTTPClient is an interface for HTTP client operations (enables testing)
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Provider implements the LLM provider interface for Anthropic Claude
type Provider struct {
	apiKey     string
	baseURL    string
	apiVersion string
	model      string
	timeout    time.Duration
	client     HTTPClient
	healthy    bool
	mu         sync.RWMutex
}

// Config contains configuration for the Anthropic provider
type Config struct {
	APIKey     string        // Required: Anthropic API key
	BaseURL    string        // Optional: API base URL (default: https://api.anthropic.com)
	APIVersion string        // Optional: API version (default: 2023-06-01)
	Model      string        // Optional: Default model (default: claude-3-5-sonnet-20241022)
	Timeout    time.Duration // Optional: HTTP timeout (default: 120s)
}

// CompletionRequest represents a completion request to Anthropic
type CompletionRequest struct {
	Prompt       string   // The prompt/user message
	SystemPrompt string   // Optional system prompt
	MaxTokens    int      // Maximum tokens to generate
	Temperature  float64  // Temperature (0.0-1.0)
	TopP         float64  // Top-p sampling
	TopK         int      // Top-k sampling
	Model        string   // Model override
	StopSequences []string // Stop sequences
	Stream       bool     // Enable streaming
}

// CompletionResponse represents a completion response from Anthropic
type CompletionResponse struct {
	Content      string
	Model        string
	StopReason   string
	Usage        UsageStats
	Latency      time.Duration
}

// UsageStats contains token usage statistics
type UsageStats struct {
	InputTokens  int
	OutputTokens int
	TotalTokens  int
}

// StreamChunk represents a single chunk in a streaming response
type StreamChunk struct {
	Type    string // "content_block_delta", "message_delta", etc.
	Content string // The text content
	Done    bool   // Whether this is the final chunk
}

// StreamHandler is a callback function for handling stream chunks
type StreamHandler func(chunk StreamChunk) error

// NewProvider creates a new Anthropic provider instance
func NewProvider(cfg Config) (*Provider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("anthropic API key is required")
	}

	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}

	if cfg.APIVersion == "" {
		cfg.APIVersion = DefaultAPIVersion
	}

	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}

	return &Provider{
		apiKey:     cfg.APIKey,
		baseURL:    cfg.BaseURL,
		apiVersion: cfg.APIVersion,
		model:      cfg.Model,
		timeout:    cfg.Timeout,
		client:     &http.Client{Timeout: cfg.Timeout},
		healthy:    true,
	}, nil
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "anthropic"
}

// SupportsStreaming indicates if the provider supports streaming
func (p *Provider) SupportsStreaming() bool {
	return true
}

// GetCapabilities returns the provider's capabilities
func (p *Provider) GetCapabilities() []string {
	return []string{
		"reasoning",
		"analysis",
		"writing",
		"code_generation",
		"long_context",
		"vision",
		"streaming",
	}
}

// IsHealthy returns whether the provider is healthy
func (p *Provider) IsHealthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.healthy && p.apiKey != ""
}

// setHealthy updates the provider health status
func (p *Provider) setHealthy(healthy bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthy = healthy
}

// EstimateCost estimates the cost for a given number of tokens
// Pricing based on Claude 3.5 Sonnet: $3/1M input, $15/1M output
// Using average estimate: $0.000009 per token
func (p *Provider) EstimateCost(tokens int) float64 {
	return float64(tokens) * 0.000009
}

// Complete generates a completion for the given request
func (p *Provider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	start := time.Now()

	// Build request
	model := req.Model
	if model == "" {
		model = p.model
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = DefaultMaxTokens
	}

	// Temperature: 0.0 is valid (deterministic), negative is invalid
	// Only apply default if temperature is negative (unset/invalid)
	temperature := req.Temperature
	if temperature < 0 {
		temperature = DefaultTemperature
	}

	// Build API request body
	apiReq := anthropicRequest{
		Model:     model,
		MaxTokens: maxTokens,
		Messages: []anthropicMessage{
			{Role: "user", Content: req.Prompt},
		},
	}

	// Add temperature (0.0 is valid for deterministic outputs)
	if temperature >= 0 {
		apiReq.Temperature = &temperature
	}

	if req.TopP > 0 {
		apiReq.TopP = &req.TopP
	}

	if req.TopK > 0 {
		apiReq.TopK = &req.TopK
	}

	if req.SystemPrompt != "" {
		apiReq.System = req.SystemPrompt
	}

	if len(req.StopSequences) > 0 {
		apiReq.StopSequences = req.StopSequences
	}

	// Marshal request
	reqBody, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/v1/messages", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	p.setHeaders(httpReq)

	// Execute request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return nil, fmt.Errorf("anthropic API error: %w", err)
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
	var apiResp anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract content using strings.Builder for efficiency
	var contentBuilder strings.Builder
	for _, block := range apiResp.Content {
		if block.Type == "text" {
			contentBuilder.WriteString(block.Text)
		}
	}

	return &CompletionResponse{
		Content:    contentBuilder.String(),
		Model:      apiResp.Model,
		StopReason: apiResp.StopReason,
		Usage: UsageStats{
			InputTokens:  apiResp.Usage.InputTokens,
			OutputTokens: apiResp.Usage.OutputTokens,
			TotalTokens:  apiResp.Usage.InputTokens + apiResp.Usage.OutputTokens,
		},
		Latency: time.Since(start),
	}, nil
}

// CompleteStream generates a streaming completion for the given request
func (p *Provider) CompleteStream(ctx context.Context, req CompletionRequest, handler StreamHandler) (*CompletionResponse, error) {
	start := time.Now()

	// Build request
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
	apiReq := anthropicRequest{
		Model:     model,
		MaxTokens: maxTokens,
		Stream:    true,
		Messages: []anthropicMessage{
			{Role: "user", Content: req.Prompt},
		},
	}

	// Add temperature (0.0 is valid for deterministic outputs)
	if temperature >= 0 {
		apiReq.Temperature = &temperature
	}

	if req.TopP > 0 {
		apiReq.TopP = &req.TopP
	}

	if req.TopK > 0 {
		apiReq.TopK = &req.TopK
	}

	if req.SystemPrompt != "" {
		apiReq.System = req.SystemPrompt
	}

	if len(req.StopSequences) > 0 {
		apiReq.StopSequences = req.StopSequences
	}

	// Marshal request
	reqBody, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/v1/messages", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	p.setHeaders(httpReq)

	// Execute request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return nil, fmt.Errorf("anthropic API error: %w", err)
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

// processStream processes the SSE stream from Anthropic
func (p *Provider) processStream(body io.Reader, handler StreamHandler, start time.Time, model string) (*CompletionResponse, error) {
	scanner := bufio.NewScanner(body)
	var contentBuilder strings.Builder
	var usage UsageStats
	var stopReason string
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

		// Parse event data
		var event streamEvent
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue // Skip malformed events
		}

		switch event.Type {
		case "message_start":
			if event.Message != nil {
				responseModel = event.Message.Model
				if event.Message.Usage != nil {
					usage.InputTokens = event.Message.Usage.InputTokens
				}
			}

		case "content_block_delta":
			if event.Delta != nil && event.Delta.Type == "text_delta" {
				contentBuilder.WriteString(event.Delta.Text)
				if handler != nil {
					if err := handler(StreamChunk{
						Type:    "content_block_delta",
						Content: event.Delta.Text,
						Done:    false,
					}); err != nil {
						return nil, fmt.Errorf("handler error: %w", err)
					}
				}
			}

		case "message_delta":
			if event.Delta != nil {
				stopReason = event.Delta.StopReason
			}
			if event.Usage != nil {
				usage.OutputTokens = event.Usage.OutputTokens
			}

		case "message_stop":
			if handler != nil {
				if err := handler(StreamChunk{Type: "message_stop", Done: true}); err != nil {
					return nil, fmt.Errorf("handler error: %w", err)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("stream read error: %w", err)
	}

	if responseModel == "" {
		responseModel = model
	}

	usage.TotalTokens = usage.InputTokens + usage.OutputTokens

	return &CompletionResponse{
		Content:    contentBuilder.String(),
		Model:      responseModel,
		StopReason: stopReason,
		Usage:      usage,
		Latency:    time.Since(start),
	}, nil
}

// setHeaders sets the required headers for Anthropic API requests
func (p *Provider) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", p.apiVersion)
}

// parseAPIError parses an API error response
func (p *Provider) parseAPIError(statusCode int, body []byte) error {
	var errResp struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &errResp); err != nil {
		return fmt.Errorf("anthropic API error (status %d): %s", statusCode, string(body))
	}

	return &APIError{
		StatusCode: statusCode,
		Type:       errResp.Error.Type,
		Message:    errResp.Error.Message,
	}
}

// APIError represents an Anthropic API error
type APIError struct {
	StatusCode int
	Type       string
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("anthropic API error (status %d, type %s): %s", e.StatusCode, e.Type, e.Message)
}

// IsRateLimitError returns true if this is a rate limit error
func (e *APIError) IsRateLimitError() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.Type == "rate_limit_error"
}

// IsAuthError returns true if this is an authentication error
func (e *APIError) IsAuthError() bool {
	return e.StatusCode == http.StatusUnauthorized || e.Type == "authentication_error"
}

// IsOverloadedError returns true if the API is overloaded
func (e *APIError) IsOverloadedError() bool {
	return e.StatusCode == http.StatusServiceUnavailable || e.Type == "overloaded_error"
}

// Internal API types

type anthropicRequest struct {
	Model         string             `json:"model"`
	Messages      []anthropicMessage `json:"messages"`
	MaxTokens     int                `json:"max_tokens"`
	System        string             `json:"system,omitempty"`
	Temperature   *float64           `json:"temperature,omitempty"`
	TopP          *float64           `json:"top_p,omitempty"`
	TopK          *int               `json:"top_k,omitempty"`
	StopSequences []string           `json:"stop_sequences,omitempty"`
	Stream        bool               `json:"stream,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Role       string `json:"role"`
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Content    []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

type streamEvent struct {
	Type    string `json:"type"`
	Index   int    `json:"index,omitempty"`
	Message *struct {
		ID    string `json:"id"`
		Model string `json:"model"`
		Usage *struct {
			InputTokens int `json:"input_tokens"`
		} `json:"usage,omitempty"`
	} `json:"message,omitempty"`
	Delta *struct {
		Type       string `json:"type,omitempty"`
		Text       string `json:"text,omitempty"`
		StopReason string `json:"stop_reason,omitempty"`
	} `json:"delta,omitempty"`
	Usage *struct {
		OutputTokens int `json:"output_tokens"`
	} `json:"usage,omitempty"`
	ContentBlock *struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content_block,omitempty"`
}

// GetSupportedModels returns a list of supported Claude models
func GetSupportedModels() []string {
	return []string{
		ModelClaude4Opus,
		ModelClaude4Sonnet,
		ModelClaude35Sonnet,
		ModelClaude35SonnetOld,
		ModelClaude35Haiku,
		ModelClaude3Opus,
		ModelClaude3Sonnet,
		ModelClaude3Haiku,
	}
}

// IsValidModel checks if the given model is a valid Claude model
func IsValidModel(model string) bool {
	for _, m := range GetSupportedModels() {
		if m == model {
			return true
		}
	}
	// Also allow custom/future models starting with "claude-"
	return strings.HasPrefix(model, "claude-")
}
