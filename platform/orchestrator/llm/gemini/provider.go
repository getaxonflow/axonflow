// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package gemini provides an LLM provider implementation for Google's Gemini models.
// It supports Gemini 1.5 Pro, Gemini 1.5 Flash, and other Gemini models
// with both streaming and non-streaming completion modes.
package gemini

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
	// DefaultBaseURL is the default Gemini API endpoint.
	DefaultBaseURL = "https://generativelanguage.googleapis.com"

	// DefaultAPIVersion is the Gemini API version.
	DefaultAPIVersion = "v1beta"

	// DefaultTimeout is the default HTTP timeout.
	DefaultTimeout = 120 * time.Second

	// DefaultMaxTokens is the default max output tokens for completions.
	DefaultMaxTokens = 4096

	// DefaultTemperature is the default temperature for completions.
	DefaultTemperature = 0.7
)

// Model constants for supported Gemini models.
const (
	// Gemini 2.5 models (latest)
	ModelGemini25Flash = "gemini-2.5-flash"
	ModelGemini25Pro   = "gemini-2.5-pro"

	// Gemini 2.0 models
	ModelGemini2Flash     = "gemini-2.0-flash"
	ModelGemini2FlashLite = "gemini-2.0-flash-lite"

	// Gemini 1.5 models (legacy, may not be available in all regions)
	ModelGemini15Pro      = "gemini-1.5-pro"
	ModelGemini15Flash    = "gemini-1.5-flash"
	ModelGemini15Flash8B  = "gemini-1.5-flash-8b"

	// Gemini 1.0 models (legacy)
	ModelGemini10Pro = "gemini-1.0-pro"

	// Default model - use latest Flash for best availability
	DefaultModel = ModelGemini2Flash
)

// HTTPClient is an interface for HTTP client operations (enables testing).
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Provider implements the LLM provider interface for Google Gemini.
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

// Config contains configuration for the Gemini provider.
type Config struct {
	APIKey     string        // Required: Google API key
	BaseURL    string        // Optional: API base URL (default: https://generativelanguage.googleapis.com)
	APIVersion string        // Optional: API version (default: v1beta)
	Model      string        // Optional: Default model (default: gemini-1.5-pro)
	Timeout    time.Duration // Optional: HTTP timeout (default: 120s)
}

// CompletionRequest represents a completion request to Gemini.
type CompletionRequest struct {
	Prompt        string   // The prompt/user message
	SystemPrompt  string   // Optional system instruction
	MaxTokens     int      // Maximum tokens to generate
	Temperature   float64  // Temperature (0.0-2.0)
	TopP          float64  // Top-p sampling (0.0-1.0)
	TopK          int      // Top-k sampling
	Model         string   // Model override
	StopSequences []string // Stop sequences
	Stream        bool     // Enable streaming
}

// CompletionResponse represents a completion response from Gemini.
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

// NewProvider creates a new Gemini provider instance.
func NewProvider(cfg Config) (*Provider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("gemini API key is required")
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

// Name returns the provider name.
func (p *Provider) Name() string {
	return "gemini"
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
		"long_context",
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
// Pricing based on Gemini 1.5 Pro: $1.25/1M input, $5/1M output (up to 128K context).
// Using average estimate: $0.000003125 per token.
func (p *Provider) EstimateCost(tokens int) float64 {
	return float64(tokens) * 0.000003125
}

// Complete generates a completion for the given request.
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
	temperature := req.Temperature
	if temperature < 0 {
		temperature = DefaultTemperature
	}

	// Build API request body
	apiReq := p.buildAPIRequest(req.Prompt, req.SystemPrompt, maxTokens, temperature, req.TopP, req.TopK, req.StopSequences)

	// Marshal request
	reqBody, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build URL
	url := fmt.Sprintf("%s/%s/models/%s:generateContent?key=%s",
		p.baseURL, p.apiVersion, model, p.apiKey)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return nil, fmt.Errorf("gemini API error: %w", err)
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
	var apiResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract content
	content := ""
	if len(apiResp.Candidates) > 0 && len(apiResp.Candidates[0].Content.Parts) > 0 {
		content = apiResp.Candidates[0].Content.Parts[0].Text
	}

	// Determine stop reason
	stopReason := "unknown"
	if len(apiResp.Candidates) > 0 {
		stopReason = mapFinishReason(apiResp.Candidates[0].FinishReason)
	}

	// Extract usage
	inputTokens := 0
	outputTokens := 0
	if apiResp.UsageMetadata != nil {
		inputTokens = apiResp.UsageMetadata.PromptTokenCount
		outputTokens = apiResp.UsageMetadata.CandidatesTokenCount
	}

	return &CompletionResponse{
		Content:    content,
		Model:      model,
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

	// Build API request body
	apiReq := p.buildAPIRequest(req.Prompt, req.SystemPrompt, maxTokens, temperature, req.TopP, req.TopK, req.StopSequences)

	// Marshal request
	reqBody, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build URL for streaming endpoint
	url := fmt.Sprintf("%s/%s/models/%s:streamGenerateContent?alt=sse&key=%s",
		p.baseURL, p.apiVersion, model, p.apiKey)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	// Execute request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return nil, fmt.Errorf("gemini API error: %w", err)
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

// buildAPIRequest builds the Gemini API request body.
func (p *Provider) buildAPIRequest(prompt, systemPrompt string, maxTokens int, temperature, topP float64, topK int, stopSequences []string) map[string]any {
	// Build contents
	contents := []map[string]any{
		{
			"role": "user",
			"parts": []map[string]any{
				{"text": prompt},
			},
		},
	}

	// Build generation config
	generationConfig := map[string]any{
		"maxOutputTokens": maxTokens,
		"temperature":     temperature,
	}

	if topP > 0 {
		generationConfig["topP"] = topP
	}

	if topK > 0 {
		generationConfig["topK"] = topK
	}

	if len(stopSequences) > 0 {
		generationConfig["stopSequences"] = stopSequences
	}

	apiReq := map[string]any{
		"contents":         contents,
		"generationConfig": generationConfig,
	}

	// Add system instruction if provided
	if systemPrompt != "" {
		apiReq["systemInstruction"] = map[string]any{
			"parts": []map[string]any{
				{"text": systemPrompt},
			},
		}
	}

	return apiReq
}

// processStream processes the SSE stream from Gemini.
func (p *Provider) processStream(body io.Reader, handler StreamHandler, start time.Time, model string) (*CompletionResponse, error) {
	scanner := bufio.NewScanner(body)
	var contentBuilder strings.Builder
	var stopReason string
	var inputTokens, outputTokens int

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
		var event geminiResponse
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue // Skip malformed events
		}

		// Extract content from candidates
		if len(event.Candidates) > 0 {
			candidate := event.Candidates[0]

			// Extract text content
			if len(candidate.Content.Parts) > 0 {
				text := candidate.Content.Parts[0].Text
				if text != "" {
					contentBuilder.WriteString(text)
					if handler != nil {
						if err := handler(StreamChunk{
							Type:    "content",
							Content: text,
							Done:    false,
						}); err != nil {
							return nil, fmt.Errorf("handler error: %w", err)
						}
					}
				}
			}

			// Check for finish reason
			if candidate.FinishReason != "" {
				stopReason = mapFinishReason(candidate.FinishReason)
			}
		}

		// Extract usage metadata
		if event.UsageMetadata != nil {
			inputTokens = event.UsageMetadata.PromptTokenCount
			outputTokens = event.UsageMetadata.CandidatesTokenCount
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

	return &CompletionResponse{
		Content:    contentBuilder.String(),
		Model:      model,
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
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &errResp); err != nil {
		return fmt.Errorf("gemini API error (status %d): %s", statusCode, string(body))
	}

	return &APIError{
		StatusCode: statusCode,
		Code:       errResp.Error.Code,
		Status:     errResp.Error.Status,
		Message:    errResp.Error.Message,
	}
}

// mapFinishReason maps Gemini finish reasons to standard reasons.
func mapFinishReason(reason string) string {
	switch reason {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "max_tokens"
	case "SAFETY":
		return "content_filter"
	case "RECITATION":
		return "content_filter"
	case "OTHER":
		return "other"
	default:
		return reason
	}
}

// APIError represents a Gemini API error.
type APIError struct {
	StatusCode int
	Code       int
	Status     string
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("gemini API error (status %d, code %d, %s): %s",
		e.StatusCode, e.Code, e.Status, e.Message)
}

// IsRateLimitError returns true if this is a rate limit error.
func (e *APIError) IsRateLimitError() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.Status == "RESOURCE_EXHAUSTED"
}

// IsAuthError returns true if this is an authentication error.
func (e *APIError) IsAuthError() bool {
	return e.StatusCode == http.StatusUnauthorized ||
		e.StatusCode == http.StatusForbidden ||
		e.Status == "UNAUTHENTICATED" ||
		e.Status == "PERMISSION_DENIED"
}

// IsQuotaExceededError returns true if this is a quota exceeded error.
func (e *APIError) IsQuotaExceededError() bool {
	return e.Status == "RESOURCE_EXHAUSTED"
}

// Internal API types

type geminiResponse struct {
	Candidates    []geminiCandidate  `json:"candidates,omitempty"`
	UsageMetadata *geminiUsageMetadata `json:"usageMetadata,omitempty"`
	PromptFeedback *struct {
		BlockReason string `json:"blockReason,omitempty"`
	} `json:"promptFeedback,omitempty"`
}

type geminiCandidate struct {
	Content      geminiContent `json:"content"`
	FinishReason string        `json:"finishReason,omitempty"`
	Index        int           `json:"index"`
	SafetyRatings []struct {
		Category    string `json:"category"`
		Probability string `json:"probability"`
	} `json:"safetyRatings,omitempty"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
	Role  string       `json:"role"`
}

type geminiPart struct {
	Text string `json:"text,omitempty"`
}

type geminiUsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// GetSupportedModels returns a list of supported Gemini models.
func GetSupportedModels() []string {
	return []string{
		ModelGemini2Flash,
		ModelGemini2FlashLite,
		ModelGemini15Pro,
		ModelGemini15Flash,
		ModelGemini15Flash8B,
		ModelGemini10Pro,
	}
}

// IsValidModel checks if the given model is a valid Gemini model.
func IsValidModel(model string) bool {
	for _, m := range GetSupportedModels() {
		if m == model {
			return true
		}
	}
	// Also allow custom/future models starting with "gemini-"
	return strings.HasPrefix(model, "gemini-")
}

// SetHTTPClient sets a custom HTTP client for testing.
func (p *Provider) SetHTTPClient(client HTTPClient) {
	p.client = client
}
