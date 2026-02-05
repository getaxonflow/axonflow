// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package openai provides the OpenAI LLM provider implementation.
package openai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"axonflow/platform/orchestrator/llm"
	llmsdk "axonflow/platform/orchestrator/llm/sdk"
)

// OpenAI GPT-4o pricing per 1K tokens (as of 2025).
const (
	openAIInputCostPer1K  = 0.0025 // $2.50/1M input
	openAIOutputCostPer1K = 0.01   // $10/1M output
)

// Config contains configuration for the OpenAI provider.
type Config struct {
	Name        string
	APIKey      string
	Endpoint    string
	Model       string
	Timeout     time.Duration
	RateLimit   int // requests per minute
	RetryConfig *llmsdk.RetryConfig
	HTTPClient  *http.Client
	Auth        llmsdk.AuthProvider
}

// NewProviderFactory creates an OpenAI provider from the shared ProviderConfig.
func NewProviderFactory(config llm.ProviderConfig) (llm.Provider, error) {
	if config.APIKey == "" && config.APIKeySecretARN == "" {
		return nil, &llm.FactoryError{
			ProviderType: llm.ProviderTypeOpenAI,
			Code:         llm.ErrFactoryInvalidConfig,
			Message:      "API key is required for OpenAI provider",
		}
	}

	// Default model
	model := config.Model
	if model == "" {
		model = llm.OpenAIDefaultModel
	}

	// Default timeout
	timeout := llm.OpenAIDefaultTimeout
	if config.TimeoutSeconds > 0 {
		timeout = time.Duration(config.TimeoutSeconds) * time.Second
	}

	// Build endpoint
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = llm.OpenAIDefaultEndpoint
	}

	return NewProvider(Config{
		Name:      config.Name,
		APIKey:    config.APIKey,
		Endpoint:  endpoint,
		Model:     model,
		Timeout:   timeout,
		RateLimit: config.RateLimit,
	})
}

// init registers the OpenAI provider factory.
func init() {
	llm.RegisterFactory(llm.ProviderTypeOpenAI, NewProviderFactory)
}

// Provider implements llm.Provider for OpenAI's GPT models.
type Provider struct {
	name         string
	apiKey       string
	endpoint     string
	model        string
	timeout      time.Duration
	client       *http.Client
	healthy      bool
	base         *llmsdk.CustomProvider
	authProvider llmsdk.AuthProvider
	rateLimiter  *llmsdk.RateLimiter
	retryConfig  *llmsdk.RetryConfig
	mu           sync.RWMutex
}

// NewProvider creates a new OpenAI provider.
func NewProvider(config Config) (*Provider, error) {
	if config.Name == "" {
		config.Name = "openai"
	}

	if config.Endpoint == "" {
		config.Endpoint = llm.OpenAIDefaultEndpoint
	}
	if config.Model == "" {
		config.Model = llm.OpenAIDefaultModel
	}
	if config.Timeout == 0 {
		config.Timeout = llm.OpenAIDefaultTimeout
	}

	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: config.Timeout}
	}

	provider := &Provider{
		name:     config.Name,
		apiKey:   config.APIKey,
		endpoint: config.Endpoint,
		model:    config.Model,
		timeout:  config.Timeout,
		client:   client,
		healthy:  true,
	}

	if config.Auth != nil {
		provider.authProvider = config.Auth
	} else {
		provider.authProvider = llmsdk.NewAPIKeyAuth(config.APIKey)
	}

	if config.RateLimit > 0 {
		ratePerSecond := float64(config.RateLimit) / 60.0
		burst := math.Max(1, ratePerSecond)
		provider.rateLimiter = llmsdk.NewRateLimiter(ratePerSecond, burst)
	}

	if config.RetryConfig != nil {
		provider.retryConfig = config.RetryConfig
	}

	builder := llmsdk.NewProviderBuilder(provider.name, llm.ProviderTypeOpenAI).
		WithModel(provider.model).
		WithEndpoint(provider.endpoint).
		WithAuth(provider.authProvider).
		WithHTTPClient(provider.client).
		WithTimeout(provider.timeout).
		WithCapabilities(provider.Capabilities()...).
		WithStreaming(true).
		WithCompleteFunc(provider.completeRequest)

	if provider.rateLimiter != nil {
		builder.WithRateLimiter(provider.rateLimiter)
	}
	if provider.retryConfig != nil {
		builder.WithRetry(provider.retryConfig)
	}

	provider.base = builder.Build()

	return provider, nil
}

// Name returns the provider instance name.
func (p *Provider) Name() string {
	return p.name
}

// Type returns the provider type.
func (p *Provider) Type() llm.ProviderType {
	return llm.ProviderTypeOpenAI
}

// Model returns the default model.
func (p *Provider) Model() string {
	return p.model
}

// Endpoint returns the API endpoint.
func (p *Provider) Endpoint() string {
	return p.endpoint
}

// Complete generates a completion for the given request.
func (p *Provider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	if p.base != nil {
		return p.base.Complete(ctx, req)
	}
	return p.completeRequest(ctx, req)
}

func (p *Provider) completeRequest(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	start := time.Now()

	model := req.Model
	if model == "" {
		model = p.model
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 4096
	}

	temperature := req.Temperature
	if temperature < 0 {
		temperature = 0.7
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

	// Build OpenAI request
	openAIReq := map[string]any{
		"model":       model,
		"messages":    messages,
		"max_tokens":  maxTokens,
		"temperature": temperature,
	}

	if req.TopP > 0 {
		openAIReq["top_p"] = req.TopP
	}

	if len(req.StopSequences) > 0 {
		openAIReq["stop"] = req.StopSequences
	}

	reqBody, err := json.Marshal(openAIReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.endpoint+"/v1/chat/completions", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if p.authProvider != nil {
		if err := p.authProvider.Apply(httpReq); err != nil {
			return nil, fmt.Errorf("failed to apply auth: %w", err)
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return nil, fmt.Errorf("OpenAI API error: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 500 {
			p.setHealthy(false)
		}
		return nil, &llmsdk.APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("OpenAI API error (status %d): %s", resp.StatusCode, string(body)),
		}
	}

	p.setHealthy(true)

	var openAIResp struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Index   int `json:"index"`
			Message struct {
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

	if err := json.NewDecoder(resp.Body).Decode(&openAIResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	content := ""
	finishReason := ""
	if len(openAIResp.Choices) > 0 {
		content = openAIResp.Choices[0].Message.Content
		finishReason = openAIResp.Choices[0].FinishReason
	}

	return &llm.CompletionResponse{
		Content: content,
		Model:   openAIResp.Model,
		Usage: llm.UsageStats{
			PromptTokens:     openAIResp.Usage.PromptTokens,
			CompletionTokens: openAIResp.Usage.CompletionTokens,
			TotalTokens:      openAIResp.Usage.TotalTokens,
		},
		Latency:      time.Since(start),
		FinishReason: finishReason,
		Metadata: map[string]any{
			"provider":   "openai",
			"request_id": openAIResp.ID,
		},
	}, nil
}

// HealthCheck verifies the provider is operational.
func (p *Provider) HealthCheck(ctx context.Context) (*llm.HealthCheckResult, error) {
	p.mu.RLock()
	healthy := p.healthy && p.apiKey != ""
	p.mu.RUnlock()

	status := llm.HealthStatusUnhealthy
	message := "provider reports unhealthy"
	if healthy {
		status = llm.HealthStatusHealthy
		message = "provider is operational"
	}

	return &llm.HealthCheckResult{
		Status:      status,
		Latency:     0,
		Message:     message,
		LastChecked: time.Now(),
	}, nil
}

// Capabilities returns the list of features this provider supports.
func (p *Provider) Capabilities() []llm.Capability {
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

// SupportsStreaming indicates if the provider supports streaming responses.
func (p *Provider) SupportsStreaming() bool {
	return true
}

// CompleteStream generates a streaming completion for the given request.
func (p *Provider) CompleteStream(ctx context.Context, req llm.CompletionRequest, handler llm.StreamHandler) (*llm.CompletionResponse, error) {
	start := time.Now()

	if p.rateLimiter != nil {
		if err := p.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit exceeded: %w", err)
		}
	}

	model := req.Model
	if model == "" {
		model = p.model
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 4096
	}

	temperature := req.Temperature
	if temperature < 0 {
		temperature = 0.7
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

	// Build OpenAI request with streaming enabled
	openAIReq := map[string]any{
		"model":       model,
		"messages":    messages,
		"max_tokens":  maxTokens,
		"temperature": temperature,
		"stream":      true,
	}

	if req.TopP > 0 {
		openAIReq["top_p"] = req.TopP
	}

	if len(req.StopSequences) > 0 {
		openAIReq["stop"] = req.StopSequences
	}

	reqBody, err := json.Marshal(openAIReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.endpoint+"/v1/chat/completions", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if p.authProvider != nil {
		if err := p.authProvider.Apply(httpReq); err != nil {
			return nil, fmt.Errorf("failed to apply auth: %w", err)
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return nil, fmt.Errorf("OpenAI API error: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 500 {
			p.setHealthy(false)
		}
		return nil, &llmsdk.APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("OpenAI API error (status %d): %s", resp.StatusCode, string(body)),
		}
	}

	p.setHealthy(true)

	// Parse SSE stream
	var fullContent strings.Builder
	var finishReason string
	var usage llm.UsageStats
	var responseModel string

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}

		// Parse SSE data
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var chunk struct {
			ID      string `json:"id"`
			Model   string `json:"model"`
			Choices []struct {
				Index int `json:"index"`
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			} `json:"usage,omitempty"`
		}

		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue // Skip malformed chunks
		}

		if chunk.Model != "" {
			responseModel = chunk.Model
		}

		if len(chunk.Choices) > 0 {
			choice := chunk.Choices[0]
			if choice.Delta.Content != "" {
				fullContent.WriteString(choice.Delta.Content)

				// Call handler with chunk
				if handler != nil {
					if err := handler(llm.StreamChunk{
						Content: choice.Delta.Content,
						Done:    false,
					}); err != nil {
						return nil, fmt.Errorf("stream handler error: %w", err)
					}
				}
			}

			if choice.FinishReason != "" {
				finishReason = choice.FinishReason
			}
		}

		if chunk.Usage != nil {
			usage = llm.UsageStats{
				PromptTokens:     chunk.Usage.PromptTokens,
				CompletionTokens: chunk.Usage.CompletionTokens,
				TotalTokens:      chunk.Usage.TotalTokens,
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading stream: %w", err)
	}

	// Send final done chunk
	if handler != nil {
		if err := handler(llm.StreamChunk{
			Content: "",
			Done:    true,
		}); err != nil {
			return nil, fmt.Errorf("stream handler error: %w", err)
		}
	}

	return &llm.CompletionResponse{
		Content:      fullContent.String(),
		Model:        responseModel,
		Usage:        usage,
		Latency:      time.Since(start),
		FinishReason: finishReason,
		Metadata: map[string]any{
			"provider": "openai",
			"streamed": true,
		},
	}, nil
}

// EstimateCost provides a cost estimate for a given request.
func (p *Provider) EstimateCost(req llm.CompletionRequest) *llm.CostEstimate {
	estimatedInputTokens, estimatedOutputTokens := llm.EstimateTokens(req)
	totalEstimate := llm.CalculateCost(estimatedInputTokens, estimatedOutputTokens,
		openAIInputCostPer1K, openAIOutputCostPer1K)

	return &llm.CostEstimate{
		InputCostPer1K:        openAIInputCostPer1K,
		OutputCostPer1K:       openAIOutputCostPer1K,
		EstimatedInputTokens:  estimatedInputTokens,
		EstimatedOutputTokens: estimatedOutputTokens,
		TotalEstimate:         totalEstimate,
		Currency:              "USD",
	}
}

// setHealthy updates the provider health status.
func (p *Provider) setHealthy(healthy bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthy = healthy
}

// Verify interface compliance at compile time.
var _ llm.Provider = (*Provider)(nil)
var _ llm.StreamingProvider = (*Provider)(nil)
