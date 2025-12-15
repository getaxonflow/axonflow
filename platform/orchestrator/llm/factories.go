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

package llm

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

	"axonflow/platform/orchestrator/llm/anthropic"
)

// init registers all built-in provider factories.
// These are the OSS providers available without an enterprise license.
func init() {
	RegisterFactory(ProviderTypeAnthropic, NewAnthropicProviderFactory)
	RegisterFactory(ProviderTypeOpenAI, NewOpenAIProviderFactory)
	RegisterFactory(ProviderTypeOllama, NewOllamaProviderFactory)
}

// NewAnthropicProviderFactory creates an Anthropic provider from configuration.
func NewAnthropicProviderFactory(config ProviderConfig) (Provider, error) {
	if config.APIKey == "" && config.APIKeySecretARN == "" {
		return nil, &FactoryError{
			ProviderType: ProviderTypeAnthropic,
			Code:         ErrFactoryInvalidConfig,
			Message:      "API key is required for Anthropic provider",
		}
	}

	// Default model
	model := config.Model
	if model == "" {
		model = anthropic.DefaultModel
	}

	// Default timeout
	timeout := 120 * time.Second
	if config.TimeoutSeconds > 0 {
		timeout = time.Duration(config.TimeoutSeconds) * time.Second
	}

	// Build endpoint
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
		return nil, &FactoryError{
			ProviderType: ProviderTypeAnthropic,
			Code:         ErrFactoryCreationFailed,
			Message:      fmt.Sprintf("failed to create Anthropic provider: %v", err),
			Cause:        err,
		}
	}

	// Wrap in adapter that implements the unified Provider interface
	return &AnthropicProviderAdapter{
		provider: provider,
		name:     config.Name,
		config:   config,
	}, nil
}

// AnthropicProviderAdapter adapts the anthropic.Provider to the unified Provider interface.
type AnthropicProviderAdapter struct {
	provider *anthropic.Provider
	name     string
	config   ProviderConfig
}

// Name returns the provider instance name.
func (a *AnthropicProviderAdapter) Name() string {
	return a.name
}

// Type returns the provider type.
func (a *AnthropicProviderAdapter) Type() ProviderType {
	return ProviderTypeAnthropic
}

// Complete generates a completion for the given request.
func (a *AnthropicProviderAdapter) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	// Convert to anthropic-specific request
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

	return &CompletionResponse{
		Content: resp.Content,
		Model:   resp.Model,
		Usage: UsageStats{
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

// HealthCheck verifies the provider is operational.
func (a *AnthropicProviderAdapter) HealthCheck(ctx context.Context) (*HealthCheckResult, error) {
	start := time.Now()
	healthy := a.provider.IsHealthy()

	status := HealthStatusUnhealthy
	message := "provider reports unhealthy"
	if healthy {
		status = HealthStatusHealthy
		message = "provider is operational"
	}

	return &HealthCheckResult{
		Status:      status,
		Latency:     time.Since(start),
		Message:     message,
		LastChecked: time.Now(),
	}, nil
}

// Capabilities returns the list of features this provider supports.
func (a *AnthropicProviderAdapter) Capabilities() []Capability {
	return []Capability{
		CapabilityChat,
		CapabilityCompletion,
		CapabilityStreaming,
		CapabilityVision,
		CapabilityCodeGeneration,
		CapabilityLongContext,
	}
}

// SupportsStreaming indicates if the provider supports streaming responses.
func (a *AnthropicProviderAdapter) SupportsStreaming() bool {
	return a.provider.SupportsStreaming()
}

// EstimateCost provides a cost estimate for a given request.
func (a *AnthropicProviderAdapter) EstimateCost(req CompletionRequest) *CostEstimate {
	estimatedInputTokens, estimatedOutputTokens := estimateTokens(req)
	totalEstimate := calculateCost(estimatedInputTokens, estimatedOutputTokens,
		anthropicInputCostPer1K, anthropicOutputCostPer1K)

	return &CostEstimate{
		InputCostPer1K:        anthropicInputCostPer1K,
		OutputCostPer1K:       anthropicOutputCostPer1K,
		EstimatedInputTokens:  estimatedInputTokens,
		EstimatedOutputTokens: estimatedOutputTokens,
		TotalEstimate:         totalEstimate,
		Currency:              "USD",
	}
}

// Verify interface compliance at compile time.
var _ Provider = (*AnthropicProviderAdapter)(nil)

// OpenAI provider implementation

// OpenAI provider constants.
const (
	// OpenAIDefaultModel is the default OpenAI model.
	OpenAIDefaultModel = "gpt-4o"

	// OpenAIDefaultEndpoint is the default OpenAI API endpoint.
	OpenAIDefaultEndpoint = "https://api.openai.com"

	// OpenAIDefaultTimeout is the default timeout for OpenAI requests.
	OpenAIDefaultTimeout = 120 * time.Second

	// OpenAI GPT-4o pricing per 1K tokens (as of 2025).
	openAIInputCostPer1K  = 0.0025 // $2.50/1M input
	openAIOutputCostPer1K = 0.01   // $10/1M output
)

// Anthropic pricing constants per 1K tokens (Claude 3.5 Sonnet).
const (
	anthropicInputCostPer1K  = 0.003  // $3/1M input
	anthropicOutputCostPer1K = 0.015  // $15/1M output
)

// NewOpenAIProviderFactory creates an OpenAI provider from configuration.
func NewOpenAIProviderFactory(config ProviderConfig) (Provider, error) {
	if config.APIKey == "" && config.APIKeySecretARN == "" {
		return nil, &FactoryError{
			ProviderType: ProviderTypeOpenAI,
			Code:         ErrFactoryInvalidConfig,
			Message:      "API key is required for OpenAI provider",
		}
	}

	// Default model
	model := config.Model
	if model == "" {
		model = OpenAIDefaultModel
	}

	// Default timeout
	timeout := OpenAIDefaultTimeout
	if config.TimeoutSeconds > 0 {
		timeout = time.Duration(config.TimeoutSeconds) * time.Second
	}

	// Build endpoint
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = OpenAIDefaultEndpoint
	}

	return &OpenAIProvider{
		name:     config.Name,
		apiKey:   config.APIKey,
		endpoint: endpoint,
		model:    model,
		timeout:  timeout,
		client:   &http.Client{Timeout: timeout},
		healthy:  true,
	}, nil
}

// OpenAIProvider implements Provider for OpenAI's GPT models.
type OpenAIProvider struct {
	name     string
	apiKey   string
	endpoint string
	model    string
	timeout  time.Duration
	client   *http.Client
	healthy  bool
	mu       sync.RWMutex
}

// Name returns the provider instance name.
func (p *OpenAIProvider) Name() string {
	return p.name
}

// Type returns the provider type.
func (p *OpenAIProvider) Type() ProviderType {
	return ProviderTypeOpenAI
}

// Complete generates a completion for the given request.
func (p *OpenAIProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
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

	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
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
		return nil, fmt.Errorf("OpenAI API error (status %d): %s", resp.StatusCode, string(body))
	}

	p.setHealthy(true)

	var openAIResp struct {
		ID      string `json:"id"`
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

	if err := json.NewDecoder(resp.Body).Decode(&openAIResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	content := ""
	finishReason := ""
	if len(openAIResp.Choices) > 0 {
		content = openAIResp.Choices[0].Message.Content
		finishReason = openAIResp.Choices[0].FinishReason
	}

	return &CompletionResponse{
		Content: content,
		Model:   openAIResp.Model,
		Usage: UsageStats{
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
func (p *OpenAIProvider) HealthCheck(ctx context.Context) (*HealthCheckResult, error) {
	p.mu.RLock()
	healthy := p.healthy && p.apiKey != ""
	p.mu.RUnlock()

	status := HealthStatusUnhealthy
	message := "provider reports unhealthy"
	if healthy {
		status = HealthStatusHealthy
		message = "provider is operational"
	}

	return &HealthCheckResult{
		Status:      status,
		Latency:     0,
		Message:     message,
		LastChecked: time.Now(),
	}, nil
}

// Capabilities returns the list of features this provider supports.
func (p *OpenAIProvider) Capabilities() []Capability {
	return []Capability{
		CapabilityChat,
		CapabilityCompletion,
		CapabilityStreaming,
		CapabilityVision,
		CapabilityFunctionCalling,
		CapabilityCodeGeneration,
		CapabilityEmbeddings,
	}
}

// SupportsStreaming indicates if the provider supports streaming responses.
func (p *OpenAIProvider) SupportsStreaming() bool {
	return true
}

// CompleteStream generates a streaming completion for the given request.
func (p *OpenAIProvider) CompleteStream(ctx context.Context, req CompletionRequest, handler StreamHandler) (*CompletionResponse, error) {
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

	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
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
		return nil, fmt.Errorf("OpenAI API error (status %d): %s", resp.StatusCode, string(body))
	}

	p.setHealthy(true)

	// Parse SSE stream
	var fullContent strings.Builder
	var finishReason string
	var usage UsageStats
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
					if err := handler(StreamChunk{
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
			usage = UsageStats{
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
		if err := handler(StreamChunk{
			Content: "",
			Done:    true,
		}); err != nil {
			return nil, fmt.Errorf("stream handler error: %w", err)
		}
	}

	return &CompletionResponse{
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
func (p *OpenAIProvider) EstimateCost(req CompletionRequest) *CostEstimate {
	estimatedInputTokens, estimatedOutputTokens := estimateTokens(req)
	totalEstimate := calculateCost(estimatedInputTokens, estimatedOutputTokens,
		openAIInputCostPer1K, openAIOutputCostPer1K)

	return &CostEstimate{
		InputCostPer1K:        openAIInputCostPer1K,
		OutputCostPer1K:       openAIOutputCostPer1K,
		EstimatedInputTokens:  estimatedInputTokens,
		EstimatedOutputTokens: estimatedOutputTokens,
		TotalEstimate:         totalEstimate,
		Currency:              "USD",
	}
}

// setHealthy updates the provider health status.
func (p *OpenAIProvider) setHealthy(healthy bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthy = healthy
}

// Verify interface compliance at compile time.
var _ Provider = (*OpenAIProvider)(nil)
var _ StreamingProvider = (*OpenAIProvider)(nil)

// Ollama provider implementation

// OllamaDefaultEndpoint is the default Ollama API endpoint.
const OllamaDefaultEndpoint = "http://localhost:11434"

// OllamaDefaultModel is the default Ollama model.
const OllamaDefaultModel = "llama3.1:latest"

// OllamaDefaultTimeout is the default timeout for Ollama requests.
const OllamaDefaultTimeout = 300 * time.Second

// NewOllamaProviderFactory creates an Ollama provider from configuration.
func NewOllamaProviderFactory(config ProviderConfig) (Provider, error) {
	// Ollama doesn't require an API key (self-hosted)
	// But endpoint is important

	// Default endpoint
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = OllamaDefaultEndpoint
	}

	// Normalize endpoint (remove trailing slash)
	endpoint = strings.TrimRight(endpoint, "/")

	// Default model
	model := config.Model
	if model == "" {
		model = OllamaDefaultModel
	}

	// Default timeout (longer for local inference)
	timeout := OllamaDefaultTimeout
	if config.TimeoutSeconds > 0 {
		timeout = time.Duration(config.TimeoutSeconds) * time.Second
	}

	return &OllamaProvider{
		name:     config.Name,
		endpoint: endpoint,
		model:    model,
		timeout:  timeout,
		client:   &http.Client{Timeout: timeout},
		healthy:  true,
	}, nil
}

// OllamaProvider implements Provider for self-hosted Ollama models.
type OllamaProvider struct {
	name     string
	endpoint string
	model    string
	timeout  time.Duration
	client   *http.Client
	healthy  bool
	mu       sync.RWMutex
}

// Name returns the provider instance name.
func (p *OllamaProvider) Name() string {
	return p.name
}

// Type returns the provider type.
func (p *OllamaProvider) Type() ProviderType {
	return ProviderTypeOllama
}

// Complete generates a completion for the given request.
func (p *OllamaProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
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

	// Build prompt with system prompt if provided
	prompt := req.Prompt
	if req.SystemPrompt != "" {
		prompt = req.SystemPrompt + "\n\n" + req.Prompt
	}

	// Build Ollama request
	ollamaReq := map[string]any{
		"model":  model,
		"prompt": prompt,
		"stream": false,
		"options": map[string]any{
			"temperature": temperature,
			"num_predict": maxTokens,
		},
	}

	if req.TopP > 0 {
		ollamaReq["options"].(map[string]any)["top_p"] = req.TopP
	}

	if req.TopK > 0 {
		ollamaReq["options"].(map[string]any)["top_k"] = req.TopK
	}

	if len(req.StopSequences) > 0 {
		ollamaReq["options"].(map[string]any)["stop"] = req.StopSequences
	}

	reqBody, err := json.Marshal(ollamaReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.endpoint+"/api/generate", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return nil, fmt.Errorf("ollama API error: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 500 {
			p.setHealthy(false)
		}
		return nil, fmt.Errorf("ollama API error (status %d): %s", resp.StatusCode, string(body))
	}

	p.setHealthy(true)

	var ollamaResp struct {
		Model              string `json:"model"`
		Response           string `json:"response"`
		Done               bool   `json:"done"`
		TotalDuration      int64  `json:"total_duration"`
		LoadDuration       int64  `json:"load_duration"`
		PromptEvalCount    int    `json:"prompt_eval_count"`
		PromptEvalDuration int64  `json:"prompt_eval_duration"`
		EvalCount          int    `json:"eval_count"`
		EvalDuration       int64  `json:"eval_duration"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Map Ollama metrics to standard format
	promptTokens := ollamaResp.PromptEvalCount
	completionTokens := ollamaResp.EvalCount

	finishReason := "stop"
	if !ollamaResp.Done {
		finishReason = "length"
	}

	return &CompletionResponse{
		Content: ollamaResp.Response,
		Model:   ollamaResp.Model,
		Usage: UsageStats{
			PromptTokens:     promptTokens,
			CompletionTokens: completionTokens,
			TotalTokens:      promptTokens + completionTokens,
		},
		Latency:      time.Since(start),
		FinishReason: finishReason,
		Metadata: map[string]any{
			"provider":            "ollama",
			"total_duration_ns":   ollamaResp.TotalDuration,
			"load_duration_ns":    ollamaResp.LoadDuration,
			"eval_duration_ns":    ollamaResp.EvalDuration,
		},
	}, nil
}

// HealthCheck verifies the provider is operational.
func (p *OllamaProvider) HealthCheck(ctx context.Context) (*HealthCheckResult, error) {
	start := time.Now()

	// Try to list models as a health check
	httpReq, err := http.NewRequestWithContext(ctx, "GET", p.endpoint+"/api/tags", nil)
	if err != nil {
		return &HealthCheckResult{
			Status:      HealthStatusUnhealthy,
			Latency:     time.Since(start),
			Message:     fmt.Sprintf("failed to create request: %v", err),
			LastChecked: time.Now(),
		}, nil
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return &HealthCheckResult{
			Status:      HealthStatusUnhealthy,
			Latency:     time.Since(start),
			Message:     fmt.Sprintf("connection failed: %v", err),
			LastChecked: time.Now(),
		}, nil
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		p.setHealthy(false)
		return &HealthCheckResult{
			Status:      HealthStatusUnhealthy,
			Latency:     time.Since(start),
			Message:     fmt.Sprintf("unhealthy status: %d", resp.StatusCode),
			LastChecked: time.Now(),
		}, nil
	}

	p.setHealthy(true)
	return &HealthCheckResult{
		Status:      HealthStatusHealthy,
		Latency:     time.Since(start),
		Message:     "Ollama server is operational",
		LastChecked: time.Now(),
	}, nil
}

// Capabilities returns the list of features this provider supports.
func (p *OllamaProvider) Capabilities() []Capability {
	return []Capability{
		CapabilityChat,
		CapabilityCompletion,
		CapabilityStreaming,
		CapabilityCodeGeneration,
	}
}

// SupportsStreaming indicates if the provider supports streaming responses.
func (p *OllamaProvider) SupportsStreaming() bool {
	return true
}

// CompleteStream generates a streaming completion for the given request.
func (p *OllamaProvider) CompleteStream(ctx context.Context, req CompletionRequest, handler StreamHandler) (*CompletionResponse, error) {
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

	// Build prompt with system prompt if provided
	prompt := req.Prompt
	if req.SystemPrompt != "" {
		prompt = req.SystemPrompt + "\n\n" + req.Prompt
	}

	// Build Ollama request with streaming enabled
	ollamaReq := map[string]any{
		"model":  model,
		"prompt": prompt,
		"stream": true, // Enable streaming
		"options": map[string]any{
			"temperature": temperature,
			"num_predict": maxTokens,
		},
	}

	if req.TopP > 0 {
		ollamaReq["options"].(map[string]any)["top_p"] = req.TopP
	}

	if req.TopK > 0 {
		ollamaReq["options"].(map[string]any)["top_k"] = req.TopK
	}

	if len(req.StopSequences) > 0 {
		ollamaReq["options"].(map[string]any)["stop"] = req.StopSequences
	}

	reqBody, err := json.Marshal(ollamaReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.endpoint+"/api/generate", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.setHealthy(false)
		return nil, fmt.Errorf("ollama API error: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 500 {
			p.setHealthy(false)
		}
		return nil, fmt.Errorf("ollama API error (status %d): %s", resp.StatusCode, string(body))
	}

	p.setHealthy(true)

	// Parse streaming NDJSON response
	var fullContent strings.Builder
	var responseModel string
	var promptTokens, completionTokens int
	var done bool

	decoder := json.NewDecoder(resp.Body)
	for decoder.More() {
		var chunk struct {
			Model              string `json:"model"`
			Response           string `json:"response"`
			Done               bool   `json:"done"`
			PromptEvalCount    int    `json:"prompt_eval_count"`
			EvalCount          int    `json:"eval_count"`
		}

		if err := decoder.Decode(&chunk); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to decode chunk: %w", err)
		}

		if chunk.Model != "" {
			responseModel = chunk.Model
		}

		if chunk.Response != "" {
			fullContent.WriteString(chunk.Response)

			// Call handler with chunk
			if handler != nil {
				if err := handler(StreamChunk{
					Content: chunk.Response,
					Done:    false,
				}); err != nil {
					return nil, fmt.Errorf("stream handler error: %w", err)
				}
			}
		}

		if chunk.Done {
			done = true
			promptTokens = chunk.PromptEvalCount
			completionTokens = chunk.EvalCount
		}
	}

	// Send final done chunk
	if handler != nil {
		if err := handler(StreamChunk{
			Content: "",
			Done:    true,
		}); err != nil {
			return nil, fmt.Errorf("stream handler error: %w", err)
		}
	}

	finishReason := "stop"
	if !done {
		finishReason = "length"
	}

	return &CompletionResponse{
		Content: fullContent.String(),
		Model:   responseModel,
		Usage: UsageStats{
			PromptTokens:     promptTokens,
			CompletionTokens: completionTokens,
			TotalTokens:      promptTokens + completionTokens,
		},
		Latency:      time.Since(start),
		FinishReason: finishReason,
		Metadata: map[string]any{
			"provider": "ollama",
			"streamed": true,
		},
	}, nil
}

// EstimateCost provides a cost estimate for a given request.
// Ollama is self-hosted, so API costs are $0 (compute costs are external).
func (p *OllamaProvider) EstimateCost(req CompletionRequest) *CostEstimate {
	estimatedInputTokens, estimatedOutputTokens := estimateTokens(req)

	return &CostEstimate{
		InputCostPer1K:        0,
		OutputCostPer1K:       0,
		EstimatedInputTokens:  estimatedInputTokens,
		EstimatedOutputTokens: estimatedOutputTokens,
		TotalEstimate:         0,
		Currency:              "USD",
	}
}

// setHealthy updates the provider health status.
func (p *OllamaProvider) setHealthy(healthy bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthy = healthy
}

// Verify interface compliance at compile time.
var _ Provider = (*OllamaProvider)(nil)
var _ StreamingProvider = (*OllamaProvider)(nil)

// Helper functions for token estimation and cost calculation.

// estimateTokens provides rough token estimates for a completion request.
// This is a simple approximation; for accurate counts use a proper tokenizer.
func estimateTokens(req CompletionRequest) (inputTokens, outputTokens int) {
	// Rough estimate: ~4 characters per token for English text
	inputTokens = len(req.Prompt) / 4
	if req.SystemPrompt != "" {
		inputTokens += len(req.SystemPrompt) / 4
	}
	if inputTokens == 0 {
		inputTokens = 1
	}

	outputTokens = req.MaxTokens
	if outputTokens == 0 {
		outputTokens = 1000 // Default assumption
	}

	return inputTokens, outputTokens
}

// calculateCost computes the total cost estimate given token counts and pricing.
func calculateCost(inputTokens, outputTokens int, inputCostPer1K, outputCostPer1K float64) float64 {
	return (float64(inputTokens)/1000)*inputCostPer1K +
		(float64(outputTokens)/1000)*outputCostPer1K
}
