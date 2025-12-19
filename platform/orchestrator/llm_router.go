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

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"axonflow/platform/common/usage"
	"axonflow/platform/orchestrator/llm/anthropic"
	"axonflow/platform/orchestrator/llm/gemini"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

// LLMRouter handles intelligent routing to multiple LLM providers
type LLMRouter struct {
	providers      map[string]LLMProvider
	weights        map[string]float64
	healthChecker  *HealthChecker
	loadBalancer   *LoadBalancer
	metricsTracker *ProviderMetricsTracker
	mu             sync.RWMutex
}

// LLMProvider interface for different LLM implementations
type LLMProvider interface {
	Name() string
	Query(ctx context.Context, prompt string, options QueryOptions) (*LLMResponse, error)
	IsHealthy() bool
	GetCapabilities() []string
	EstimateCost(tokens int) float64
}

// LLMRouterConfig contains configuration for the router
type LLMRouterConfig struct {
	OpenAIKey       string
	AnthropicKey    string
	BedrockRegion   string
	BedrockModel    string
	OllamaEndpoint  string
	OllamaModel     string
	GeminiKey       string
	GeminiModel     string
	LocalEndpoint   string // Deprecated: use OllamaEndpoint
}

// QueryOptions contains options for LLM queries
type QueryOptions struct {
	MaxTokens    int     `json:"max_tokens"`
	Temperature  float64 `json:"temperature"`
	Model        string  `json:"model"`
	SystemPrompt string  `json:"system_prompt"`
}

// LLMResponse represents a response from an LLM provider
type LLMResponse struct {
	Content      string                 `json:"content"`
	Model        string                 `json:"model"`
	TokensUsed   int                    `json:"tokens_used"`
	Metadata     map[string]interface{} `json:"metadata"`
	ResponseTime time.Duration          `json:"response_time"`
}

// ProviderStatus represents the current status of a provider
type ProviderStatus struct {
	Name         string    `json:"name"`
	Healthy      bool      `json:"healthy"`
	Weight       float64   `json:"weight"`
	RequestCount int64     `json:"request_count"`
	ErrorCount   int64     `json:"error_count"`
	AvgLatency   float64   `json:"avg_latency_ms"`
	LastUsed     time.Time `json:"last_used"`
}

// NewLLMRouter creates a new LLM router instance
func NewLLMRouter(config LLMRouterConfig) *LLMRouter {
	router := &LLMRouter{
		providers:      make(map[string]LLMProvider),
		weights:        make(map[string]float64),
		healthChecker:  NewHealthChecker(),
		loadBalancer:   NewLoadBalancer(),
		metricsTracker: NewProviderMetricsTracker(),
	}

	// Initialize providers
	if config.OpenAIKey != "" {
		router.providers["openai"] = NewOpenAIProvider(config.OpenAIKey)
		router.weights["openai"] = 0.25
	}

	if config.AnthropicKey != "" {
		router.providers["anthropic"] = NewAnthropicProvider(config.AnthropicKey)
		router.weights["anthropic"] = 0.25
	}

	if config.BedrockRegion != "" {
		bedrockProvider, err := NewBedrockProvider(config.BedrockRegion, config.BedrockModel)
		if err != nil {
			log.Printf("[LLMRouter] ERROR: Failed to initialize Bedrock provider: %v", err)
			log.Printf("[LLMRouter] WARNING: Bedrock is configured (region=%s) but NOT available - LLM calls will fail", config.BedrockRegion)
		} else {
			router.providers["bedrock"] = bedrockProvider
			router.weights["bedrock"] = 0.25
		}
	}

	// Support Ollama endpoint (replaces legacy LocalEndpoint)
	ollamaEndpoint := config.OllamaEndpoint
	if ollamaEndpoint == "" && config.LocalEndpoint != "" {
		ollamaEndpoint = config.LocalEndpoint // Backward compatibility
	}

	if ollamaEndpoint != "" {
		router.providers["ollama"] = NewOllamaProvider(ollamaEndpoint, config.OllamaModel)
		router.weights["ollama"] = 0.25
	}

	if config.GeminiKey != "" {
		router.providers["gemini"] = NewGeminiProvider(config.GeminiKey, config.GeminiModel)
		router.weights["gemini"] = 0.25
	}

	// Log provider status summary at startup
	router.logProviderStatus(config)

	// Start health checking
	go router.healthCheckRoutine()

	return router
}

// logProviderStatus logs a summary of configured vs available providers at startup
func (r *LLMRouter) logProviderStatus(config LLMRouterConfig) {
	log.Printf("[LLMRouter] ========== LLM Provider Status ==========")

	// Log configured providers
	var configured []string
	var available []string
	var failed []string

	if config.OpenAIKey != "" {
		configured = append(configured, "openai")
		if _, ok := r.providers["openai"]; ok {
			available = append(available, "openai")
		} else {
			failed = append(failed, "openai")
		}
	}

	if config.AnthropicKey != "" {
		configured = append(configured, "anthropic")
		if _, ok := r.providers["anthropic"]; ok {
			available = append(available, "anthropic")
		} else {
			failed = append(failed, "anthropic")
		}
	}

	if config.BedrockRegion != "" {
		configured = append(configured, fmt.Sprintf("bedrock(%s)", config.BedrockRegion))
		if _, ok := r.providers["bedrock"]; ok {
			available = append(available, "bedrock")
		} else {
			failed = append(failed, "bedrock")
		}
	}

	if config.OllamaEndpoint != "" || config.LocalEndpoint != "" {
		configured = append(configured, "ollama")
		if _, ok := r.providers["ollama"]; ok {
			available = append(available, "ollama")
		} else {
			failed = append(failed, "ollama")
		}
	}

	if config.GeminiKey != "" {
		configured = append(configured, "gemini")
		if _, ok := r.providers["gemini"]; ok {
			available = append(available, "gemini")
		} else {
			failed = append(failed, "gemini")
		}
	}

	log.Printf("[LLMRouter] Configured: %v", configured)
	log.Printf("[LLMRouter] Available:  %v", available)
	if len(failed) > 0 {
		log.Printf("[LLMRouter] FAILED:     %v (check logs above for errors)", failed)
	}

	if len(available) == 0 {
		log.Printf("[LLMRouter] WARNING: No LLM providers available! All requests requiring LLM will fail.")
	}

	log.Printf("[LLMRouter] ==========================================")
}

// RouteRequest routes a request to the appropriate LLM provider
func (r *LLMRouter) RouteRequest(ctx context.Context, req OrchestratorRequest) (*LLMResponse, *ProviderInfo, error) {
	// Select provider based on request characteristics
	provider, err := r.selectProvider(req)
	if err != nil {
		return nil, nil, fmt.Errorf("provider selection failed: %w", err)
	}

	// Prepare query options with default max_tokens
	maxTokens := 1000

	// Check if max_tokens is specified in context (from workflow step)
	if req.Context != nil {
		if contextMaxTokens, ok := req.Context["max_tokens"].(int); ok && contextMaxTokens > 0 {
			maxTokens = contextMaxTokens
		}
	}

	options := QueryOptions{
		MaxTokens:   maxTokens,
		Temperature: 0.7,
		Model:       r.selectModel(provider.Name(), req),
	}
	
	// Build prompt
	prompt := r.buildPrompt(req)
	
	// Track start time
	startTime := time.Now()
	
	// Execute query
	response, err := provider.Query(ctx, prompt, options)
	if err != nil {
		// Track error
		r.metricsTracker.RecordError(provider.Name())
		
		// Try failover
		if fallbackProvider := r.getFallbackProvider(provider.Name()); fallbackProvider != nil {
			log.Printf("Failing over from %s to %s", provider.Name(), fallbackProvider.Name())
			// Update model for the fallback provider
			fallbackOptions := options
			fallbackOptions.Model = r.selectModel(fallbackProvider.Name(), req)
			response, err = fallbackProvider.Query(ctx, prompt, fallbackOptions)
			if err != nil {
				return nil, nil, fmt.Errorf("all providers failed: %w", err)
			}
			provider = fallbackProvider
		} else {
			return nil, nil, fmt.Errorf("primary provider failed and no fallback available: %w", err)
		}
	}
	
	// Track success
	responseTime := time.Since(startTime)
	r.metricsTracker.RecordSuccess(provider.Name(), responseTime)
	
	// Calculate cost
	cost := provider.EstimateCost(response.TokensUsed)
	
	// Build provider info
	providerInfo := &ProviderInfo{
		Provider:       provider.Name(),
		Model:          response.Model,
		ResponseTimeMs: responseTime.Milliseconds(),
		TokensUsed:     response.TokensUsed,
		Cost:           cost,
	}

	// Record LLM usage asynchronously (don't block response)
	// Extract org_id from request context
	orgID := ""
	if req.Client.OrgID != "" {
		orgID = req.Client.OrgID
	}

	if usageDB != nil && orgID != "" {
		go func() {
			recorder := usage.NewUsageRecorder(usageDB)
			instanceID := os.Getenv("HOSTNAME") // Docker container ID
			if instanceID == "" {
				instanceID = "orchestrator-unknown"
			}

			// For now, we only have total tokens, so we'll estimate 2/3 completion, 1/3 prompt
			// This is a reasonable approximation for most LLM interactions
			totalTokens := response.TokensUsed
			estimatedPromptTokens := totalTokens / 3
			estimatedCompletionTokens := totalTokens - estimatedPromptTokens

			err := recorder.RecordLLMRequest(usage.LLMRequestEvent{
				OrgID:            orgID,
				ClientID:         req.Client.ID,
				InstanceID:       instanceID,
				InstanceType:     "orchestrator",
				LLMProvider:      provider.Name(),
				LLMModel:         response.Model,
				PromptTokens:     estimatedPromptTokens,
				CompletionTokens: estimatedCompletionTokens,
				TotalTokens:      totalTokens,
				LatencyMs:        responseTime.Milliseconds(),
				HTTPStatusCode:   200, // Success if we got here
			})

			if err != nil {
				log.Printf("[USAGE] Failed to record LLM request: %v", err)
			}
		}()
	}

	return response, providerInfo, nil
}

// selectProvider selects the best provider for a request
func (r *LLMRouter) selectProvider(req OrchestratorRequest) (LLMProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	// Check if workflow explicitly requested a provider
	if providerName, exists := req.Context["provider"].(string); exists && providerName != "" {
		if provider, providerExists := r.providers[providerName]; providerExists && provider.IsHealthy() {
			return provider, nil
		}
		// If requested provider is not available, log warning and fall back to routing rules
		log.Printf("Warning: Requested provider '%s' not available, falling back to routing rules", providerName)
	}
	
	// Get healthy providers
	var healthyProviders []string
	for name, provider := range r.providers {
		if provider.IsHealthy() {
			healthyProviders = append(healthyProviders, name)
		}
	}
	
	if len(healthyProviders) == 0 {
		return nil, fmt.Errorf("no healthy providers available")
	}
	
	// Special routing rules
	if req.RequestType == "complex_analysis" {
		// Prefer more capable models for complex queries
		if provider, exists := r.providers["anthropic"]; exists && provider.IsHealthy() {
			return provider, nil
		}
		if provider, exists := r.providers["openai"]; exists && provider.IsHealthy() {
			return provider, nil
		}
	}
	
	if req.RequestType == "simple_query" && req.Context["allow_local"] == true {
		// Use local model for simple queries if allowed
		if provider, exists := r.providers["local"]; exists && provider.IsHealthy() {
			return provider, nil
		}
	}
	
	// Weighted random selection
	selected := r.loadBalancer.SelectProvider(healthyProviders, r.weights)
	return r.providers[selected], nil
}

// selectModel selects the appropriate model for a provider
func (r *LLMRouter) selectModel(providerName string, req OrchestratorRequest) string {
	switch providerName {
	case "openai":
		if req.RequestType == "code_generation" {
			return "gpt-4"
		}
		return "gpt-3.5-turbo"
	case "anthropic":
		// Use Claude 4 Sonnet for complex tasks, Claude 3.5 Sonnet for standard
		if req.RequestType == "complex_analysis" || req.RequestType == "code_generation" {
			return anthropic.ModelClaude4Sonnet
		}
		return anthropic.ModelClaude35Sonnet
	case "bedrock":
		// Return empty string to use provider's configured model
		// Bedrock model IDs must match format: provider.model-name-version
		// e.g., anthropic.claude-3-5-sonnet-20240620-v1:0
		return ""
	case "ollama":
		// Return empty string to use provider's configured model
		return ""
	case "local":
		return "llama2"
	default:
		return ""
	}
}

// buildPrompt builds the prompt for the LLM
func (r *LLMRouter) buildPrompt(req OrchestratorRequest) string {
	var prompt strings.Builder
	
	// Add context
	prompt.WriteString("You are an AI assistant helping with database queries.\n\n")
	
	// Add user context
	prompt.WriteString(fmt.Sprintf("User Role: %s\n", req.User.Role))
	prompt.WriteString(fmt.Sprintf("User Permissions: %v\n\n", req.User.Permissions))
	
	// Add the actual query
	prompt.WriteString("Query: ")
	prompt.WriteString(req.Query)
	
	return prompt.String()
}

// getFallbackProvider returns a fallback provider
func (r *LLMRouter) getFallbackProvider(failedProvider string) LLMProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	for name, provider := range r.providers {
		if name != failedProvider && provider.IsHealthy() {
			return provider
		}
	}
	return nil
}

// GetProviderStatus returns the status of all providers
func (r *LLMRouter) GetProviderStatus() map[string]ProviderStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	status := make(map[string]ProviderStatus)
	
	for name, provider := range r.providers {
		metrics := r.metricsTracker.GetMetrics(name)
		status[name] = ProviderStatus{
			Name:         name,
			Healthy:      provider.IsHealthy(),
			Weight:       r.weights[name],
			RequestCount: metrics.RequestCount,
			ErrorCount:   metrics.ErrorCount,
			AvgLatency:   metrics.AvgResponseTime,
			LastUsed:     time.Now(), // Using current time as placeholder
		}
	}
	
	return status
}

// UpdateProviderWeights updates the routing weights
func (r *LLMRouter) UpdateProviderWeights(weights map[string]float64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Validate weights
	total := 0.0
	for provider, weight := range weights {
		if _, exists := r.providers[provider]; !exists {
			return fmt.Errorf("unknown provider: %s", provider)
		}
		if weight < 0 || weight > 1 {
			return fmt.Errorf("invalid weight for %s: %f", provider, weight)
		}
		total += weight
	}
	
	if total > 1.01 || total < 0.99 { // Allow small floating point errors
		return fmt.Errorf("weights must sum to 1.0, got %f", total)
	}
	
	// Update weights
	for provider, weight := range weights {
		r.weights[provider] = weight
	}
	
	return nil
}

// IsHealthy checks if the router has any healthy providers
func (r *LLMRouter) IsHealthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	for _, provider := range r.providers {
		if provider.IsHealthy() {
			return true
		}
	}
	return false
}

// healthCheckRoutine periodically checks provider health
func (r *LLMRouter) healthCheckRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		r.mu.RLock()
		providers := make([]LLMProvider, 0, len(r.providers))
		for _, p := range r.providers {
			providers = append(providers, p)
		}
		r.mu.RUnlock()
		
		for _, provider := range providers {
			r.healthChecker.CheckProvider(provider)
		}
	}
}

// Provider implementations

// OpenAIProvider implements real OpenAI API calls
type OpenAIProvider struct {
	apiKey  string
	healthy bool
	client  *http.Client
}

func (p *OpenAIProvider) Name() string {
	return "openai"
}

func (p *OpenAIProvider) Query(ctx context.Context, prompt string, options QueryOptions) (*LLMResponse, error) {
	start := time.Now()
	
	// Build OpenAI request
	openAIReq := map[string]interface{}{
		"model": options.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens":  options.MaxTokens,
		"temperature": options.Temperature,
	}

	reqBody, err := json.Marshal(openAIReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OpenAI API error: %s", string(body))
	}

	var openAIResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&openAIResp); err != nil {
		return nil, err
	}

	content := ""
	if len(openAIResp.Choices) > 0 {
		content = openAIResp.Choices[0].Message.Content
	}

	return &LLMResponse{
		Content:      content,
		Model:        options.Model,
		TokensUsed:   openAIResp.Usage.TotalTokens,
		ResponseTime: time.Since(start),
		Metadata:     map[string]interface{}{"provider": "openai"},
	}, nil
}

func (p *OpenAIProvider) IsHealthy() bool {
	return p.healthy && p.apiKey != ""
}

func (p *OpenAIProvider) GetCapabilities() []string {
	return []string{"chat", "code", "embeddings"}
}

func (p *OpenAIProvider) EstimateCost(tokens int) float64 {
	return float64(tokens) * 0.00002 // $0.02 per 1K tokens
}

// AnthropicProvider implements real Anthropic API calls
type AnthropicProvider struct {
	apiKey  string
	healthy bool
	client  *http.Client
}

func (p *AnthropicProvider) Name() string {
	return "anthropic"
}

func (p *AnthropicProvider) Query(ctx context.Context, prompt string, options QueryOptions) (*LLMResponse, error) {
	start := time.Now()
	
	// Build Anthropic request
	anthropicReq := map[string]interface{}{
		"model": options.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens": options.MaxTokens,
		"temperature": options.Temperature,
	}

	reqBody, err := json.Marshal(anthropicReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("anthropic API error: %s", string(body))
	}

	var anthropicResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&anthropicResp); err != nil {
		return nil, err
	}

	content := ""
	if len(anthropicResp.Content) > 0 {
		content = anthropicResp.Content[0].Text
	}

	return &LLMResponse{
		Content:      content,
		Model:        options.Model,
		TokensUsed:   anthropicResp.Usage.InputTokens + anthropicResp.Usage.OutputTokens,
		ResponseTime: time.Since(start),
		Metadata:     map[string]interface{}{"provider": "anthropic"},
	}, nil
}

func (p *AnthropicProvider) IsHealthy() bool {
	return p.healthy && p.apiKey != ""
}

func (p *AnthropicProvider) GetCapabilities() []string {
	return []string{"reasoning", "analysis", "writing"}
}

func (p *AnthropicProvider) EstimateCost(tokens int) float64 {
	return float64(tokens) * 0.00003 // $0.03 per 1K tokens
}

// EnhancedAnthropicProvider wraps the new anthropic package provider
// with full support for Claude 3.5 Sonnet, Claude 3 Opus, Claude 4, and streaming.
type EnhancedAnthropicProvider struct {
	provider *anthropic.Provider
}

func (p *EnhancedAnthropicProvider) Name() string {
	return "anthropic"
}

func (p *EnhancedAnthropicProvider) Query(ctx context.Context, prompt string, options QueryOptions) (*LLMResponse, error) {
	// Use the model from options, or default to Claude 3.5 Sonnet
	model := options.Model
	if model == "" {
		model = anthropic.DefaultModel
	}

	req := anthropic.CompletionRequest{
		Prompt:       prompt,
		MaxTokens:    options.MaxTokens,
		Temperature:  options.Temperature,
		Model:        model,
		SystemPrompt: options.SystemPrompt,
	}

	resp, err := p.provider.Complete(ctx, req)
	if err != nil {
		return nil, err
	}

	return &LLMResponse{
		Content:      resp.Content,
		Model:        resp.Model,
		TokensUsed:   resp.Usage.TotalTokens,
		ResponseTime: resp.Latency, // Use latency from provider response
		Metadata: map[string]interface{}{
			"provider":      "anthropic",
			"stop_reason":   resp.StopReason,
			"input_tokens":  resp.Usage.InputTokens,
			"output_tokens": resp.Usage.OutputTokens,
		},
	}, nil
}

func (p *EnhancedAnthropicProvider) IsHealthy() bool {
	return p.provider.IsHealthy()
}

func (p *EnhancedAnthropicProvider) GetCapabilities() []string {
	return p.provider.GetCapabilities()
}

func (p *EnhancedAnthropicProvider) EstimateCost(tokens int) float64 {
	return p.provider.EstimateCost(tokens)
}

// QueryStream performs a streaming query using the enhanced provider
func (p *EnhancedAnthropicProvider) QueryStream(ctx context.Context, prompt string, options QueryOptions, handler func(chunk string) error) (*LLMResponse, error) {
	model := options.Model
	if model == "" {
		model = anthropic.DefaultModel
	}

	req := anthropic.CompletionRequest{
		Prompt:       prompt,
		MaxTokens:    options.MaxTokens,
		Temperature:  options.Temperature,
		Model:        model,
		SystemPrompt: options.SystemPrompt,
		Stream:       true,
	}

	resp, err := p.provider.CompleteStream(ctx, req, func(chunk anthropic.StreamChunk) error {
		if chunk.Content != "" {
			return handler(chunk.Content)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &LLMResponse{
		Content:      resp.Content,
		Model:        resp.Model,
		TokensUsed:   resp.Usage.TotalTokens,
		ResponseTime: resp.Latency, // Use latency from provider response
		Metadata: map[string]interface{}{
			"provider":      "anthropic",
			"stop_reason":   resp.StopReason,
			"input_tokens":  resp.Usage.InputTokens,
			"output_tokens": resp.Usage.OutputTokens,
			"streamed":      true,
		},
	}, nil
}

// EnhancedGeminiProvider wraps the gemini package provider
// with full support for Gemini 1.5 Pro, Gemini 1.5 Flash, and Gemini 2.0 Flash.
type EnhancedGeminiProvider struct {
	provider *gemini.Provider
}

func (p *EnhancedGeminiProvider) Name() string {
	return "gemini"
}

func (p *EnhancedGeminiProvider) Query(ctx context.Context, prompt string, options QueryOptions) (*LLMResponse, error) {
	// Use the model from options, or default to Gemini 1.5 Pro
	model := options.Model
	if model == "" {
		model = gemini.DefaultModel
	}

	req := gemini.CompletionRequest{
		Prompt:       prompt,
		MaxTokens:    options.MaxTokens,
		Temperature:  options.Temperature,
		Model:        model,
		SystemPrompt: options.SystemPrompt,
	}

	resp, err := p.provider.Complete(ctx, req)
	if err != nil {
		return nil, err
	}

	return &LLMResponse{
		Content:      resp.Content,
		Model:        resp.Model,
		TokensUsed:   resp.Usage.TotalTokens,
		ResponseTime: resp.Latency,
		Metadata: map[string]interface{}{
			"provider":      "gemini",
			"stop_reason":   resp.StopReason,
			"input_tokens":  resp.Usage.InputTokens,
			"output_tokens": resp.Usage.OutputTokens,
		},
	}, nil
}

func (p *EnhancedGeminiProvider) IsHealthy() bool {
	return p.provider.IsHealthy()
}

func (p *EnhancedGeminiProvider) GetCapabilities() []string {
	return p.provider.GetCapabilities()
}

func (p *EnhancedGeminiProvider) EstimateCost(tokens int) float64 {
	return p.provider.EstimateCost(tokens)
}

// QueryStream performs a streaming query using the Gemini provider
func (p *EnhancedGeminiProvider) QueryStream(ctx context.Context, prompt string, options QueryOptions, handler func(chunk string) error) (*LLMResponse, error) {
	model := options.Model
	if model == "" {
		model = gemini.DefaultModel
	}

	req := gemini.CompletionRequest{
		Prompt:       prompt,
		MaxTokens:    options.MaxTokens,
		Temperature:  options.Temperature,
		Model:        model,
		SystemPrompt: options.SystemPrompt,
		Stream:       true,
	}

	resp, err := p.provider.CompleteStream(ctx, req, func(chunk gemini.StreamChunk) error {
		if chunk.Content != "" {
			return handler(chunk.Content)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &LLMResponse{
		Content:      resp.Content,
		Model:        resp.Model,
		TokensUsed:   resp.Usage.TotalTokens,
		ResponseTime: resp.Latency,
		Metadata: map[string]interface{}{
			"provider":      "gemini",
			"stop_reason":   resp.StopReason,
			"input_tokens":  resp.Usage.InputTokens,
			"output_tokens": resp.Usage.OutputTokens,
			"streamed":      true,
		},
	}, nil
}

// BedrockProvider implements LLMProvider for AWS Bedrock using AWS SDK v2.
// This provides proper AWS Signature V4 authentication via IAM roles,
// enabling secure and compliant access to Bedrock models.
type BedrockProvider struct {
	client  *bedrockruntime.Client
	region  string
	model   string
	healthy bool
}

func (p *BedrockProvider) Name() string {
	return "bedrock"
}

func (p *BedrockProvider) Query(ctx context.Context, prompt string, options QueryOptions) (*LLMResponse, error) {
	start := time.Now()

	// Determine model to use
	model := options.Model
	if model == "" {
		model = p.model
	}

	// Build request body based on model family
	requestBody, err := p.buildRequestBody(prompt, options, model)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	// Marshal request to JSON
	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Invoke Bedrock model with AWS Signature V4 authentication
	output, err := p.client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(model),
		Body:        requestJSON,
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
	})
	if err != nil {
		p.healthy = false
		log.Printf("[Bedrock] API call failed: %v", err)
		return nil, fmt.Errorf("bedrock API error: %w", err)
	}

	p.healthy = true

	// Parse response based on model family
	response, err := p.parseResponseBody(output.Body, model)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	response.Model = model
	response.ResponseTime = time.Since(start)
	response.Metadata["provider"] = "bedrock"
	response.Metadata["region"] = p.region

	return response, nil
}

// buildRequestBody builds the request body based on model family
func (p *BedrockProvider) buildRequestBody(prompt string, options QueryOptions, model string) (map[string]interface{}, error) {
	family := detectBedrockModelFamily(model)

	switch family {
	case "anthropic":
		return map[string]interface{}{
			"anthropic_version": "bedrock-2023-05-31",
			"max_tokens":        options.MaxTokens,
			"temperature":       options.Temperature,
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		}, nil
	case "amazon":
		return map[string]interface{}{
			"inputText": prompt,
			"textGenerationConfig": map[string]interface{}{
				"maxTokenCount": options.MaxTokens,
				"temperature":   options.Temperature,
				"topP":          0.9,
			},
		}, nil
	case "meta":
		return map[string]interface{}{
			"prompt":      prompt,
			"max_gen_len": options.MaxTokens,
			"temperature": options.Temperature,
			"top_p":       0.9,
		}, nil
	case "mistral":
		return map[string]interface{}{
			"prompt":      prompt,
			"max_tokens":  options.MaxTokens,
			"temperature": options.Temperature,
			"top_p":       0.9,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported model family: %s", family)
	}
}

// parseResponseBody parses the response body based on model family
func (p *BedrockProvider) parseResponseBody(body []byte, model string) (*LLMResponse, error) {
	family := detectBedrockModelFamily(model)

	switch family {
	case "anthropic":
		return p.parseAnthropicResponse(body)
	case "amazon":
		return p.parseAmazonTitanResponse(body)
	case "meta":
		return p.parseMetaLlamaResponse(body)
	case "mistral":
		return p.parseMistralResponse(body)
	default:
		return nil, fmt.Errorf("unsupported model family: %s", family)
	}
}

// parseAnthropicResponse parses Anthropic Claude response
func (p *BedrockProvider) parseAnthropicResponse(body []byte) (*LLMResponse, error) {
	var resp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	content := ""
	if len(resp.Content) > 0 {
		content = resp.Content[0].Text
	}

	return &LLMResponse{
		Content:    content,
		TokensUsed: resp.Usage.InputTokens + resp.Usage.OutputTokens,
		Metadata: map[string]interface{}{
			"prompt_tokens":     resp.Usage.InputTokens,
			"completion_tokens": resp.Usage.OutputTokens,
		},
	}, nil
}

// parseAmazonTitanResponse parses Amazon Titan response
func (p *BedrockProvider) parseAmazonTitanResponse(body []byte) (*LLMResponse, error) {
	var resp struct {
		Results []struct {
			OutputText string `json:"outputText"`
			TokenCount int    `json:"tokenCount"`
		} `json:"results"`
		InputTextTokenCount int `json:"inputTextTokenCount"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	content := ""
	outputTokens := 0
	if len(resp.Results) > 0 {
		content = resp.Results[0].OutputText
		outputTokens = resp.Results[0].TokenCount
	}

	return &LLMResponse{
		Content:    content,
		TokensUsed: resp.InputTextTokenCount + outputTokens,
		Metadata: map[string]interface{}{
			"prompt_tokens":     resp.InputTextTokenCount,
			"completion_tokens": outputTokens,
		},
	}, nil
}

// parseMetaLlamaResponse parses Meta Llama response
func (p *BedrockProvider) parseMetaLlamaResponse(body []byte) (*LLMResponse, error) {
	var resp struct {
		Generation       string `json:"generation"`
		PromptTokenCount int    `json:"prompt_token_count"`
		GenTokenCount    int    `json:"generation_token_count"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &LLMResponse{
		Content:    resp.Generation,
		TokensUsed: resp.PromptTokenCount + resp.GenTokenCount,
		Metadata: map[string]interface{}{
			"prompt_tokens":     resp.PromptTokenCount,
			"completion_tokens": resp.GenTokenCount,
		},
	}, nil
}

// parseMistralResponse parses Mistral response
func (p *BedrockProvider) parseMistralResponse(body []byte) (*LLMResponse, error) {
	var resp struct {
		Outputs []struct {
			Text string `json:"text"`
		} `json:"outputs"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	content := ""
	if len(resp.Outputs) > 0 {
		content = resp.Outputs[0].Text
	}

	return &LLMResponse{
		Content:    content,
		TokensUsed: 0, // Mistral doesn't provide token counts
		Metadata:   map[string]interface{}{},
	}, nil
}

// inferenceProfilePrefixes are the known AWS Bedrock inference profile prefixes.
var inferenceProfilePrefixes = []string{"eu", "us", "apac", "global"}

// supportedBedrockFamilies are the model families that Bedrock supports.
var supportedBedrockFamilies = []string{"anthropic", "amazon", "meta", "mistral"}

// detectBedrockModelFamily detects the model family from model ID
func detectBedrockModelFamily(modelID string) string {
	// Model IDs follow pattern: provider.model-name-version
	// Examples:
	//   anthropic.claude-3-5-sonnet-20240620-v1:0
	//   amazon.titan-text-express-v1
	//   meta.llama3-70b-instruct-v1:0
	//   mistral.mistral-large-2402-v1:0
	//
	// Inference profile IDs have a regional prefix:
	//   eu.anthropic.claude-sonnet-4-5-20250929-v1:0
	//   us.anthropic.claude-sonnet-4-5-20250929-v1:0
	//   global.anthropic.claude-sonnet-4-5-20250929-v1:0
	//   apac.anthropic.claude-sonnet-4-5-20250929-v1:0

	if len(modelID) == 0 {
		return ""
	}

	// Split by dots
	segments := strings.Split(modelID, ".")
	if len(segments) < 2 {
		return ""
	}

	// Check if first segment is an inference profile prefix
	firstSegment := segments[0]
	for _, prefix := range inferenceProfilePrefixes {
		if firstSegment == prefix {
			// This is an inference profile ID - use second segment as model family
			if len(segments) > 1 {
				return validateBedrockFamily(segments[1])
			}
			return ""
		}
	}

	// Standard model ID - first segment is the model family
	return validateBedrockFamily(firstSegment)
}

// validateBedrockFamily returns the family if supported, empty string otherwise
func validateBedrockFamily(family string) string {
	for _, supported := range supportedBedrockFamilies {
		if family == supported {
			return family
		}
	}
	return ""
}

func (p *BedrockProvider) IsHealthy() bool {
	return p.healthy && p.region != ""
}

func (p *BedrockProvider) GetCapabilities() []string {
	return []string{"reasoning", "analysis", "writing", "hipaa_compliant"}
}

func (p *BedrockProvider) EstimateCost(tokens int) float64 {
	// Bedrock Claude pricing (similar to Anthropic)
	return float64(tokens) * 0.00003 // $0.03 per 1K tokens
}

// OllamaProvider implements local Ollama API calls
type OllamaProvider struct {
	endpoint string
	model    string
	healthy  bool
	client   *http.Client
}

func (p *OllamaProvider) Name() string {
	return "ollama"
}

func (p *OllamaProvider) Query(ctx context.Context, prompt string, options QueryOptions) (*LLMResponse, error) {
	start := time.Now()

	model := options.Model
	if model == "" {
		model = p.model
	}

	// Build Ollama request
	ollamaReq := map[string]interface{}{
		"model":  model,
		"prompt": prompt,
		"stream": false,
		"options": map[string]interface{}{
			"temperature": options.Temperature,
			"num_predict": options.MaxTokens,
		},
	}

	reqBody, err := json.Marshal(ollamaReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.endpoint+"/api/generate", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama API error: %s", string(body))
	}

	var ollamaResp struct {
		Response string `json:"response"`
		Model    string `json:"model"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return nil, err
	}

	return &LLMResponse{
		Content:      ollamaResp.Response,
		Model:        ollamaResp.Model,
		TokensUsed:   len(prompt) / 4, // Rough estimate
		ResponseTime: time.Since(start),
		Metadata:     map[string]interface{}{"provider": "ollama"},
	}, nil
}

func (p *OllamaProvider) IsHealthy() bool {
	return p.healthy && p.endpoint != ""
}

func (p *OllamaProvider) GetCapabilities() []string {
	return []string{"chat", "air_gapped", "self_hosted"}
}

func (p *OllamaProvider) EstimateCost(tokens int) float64 {
	return 0 // Free (self-hosted)
}

// MockProvider is a mock implementation for testing
type MockProvider struct {
	name    string
	healthy bool
	apiKey  string
}

func NewOpenAIProvider(apiKey string) LLMProvider {
	if apiKey == "" {
		// Return mock if no API key
		return &MockProvider{
			name:    "openai",
			healthy: true,
			apiKey:  apiKey,
		}
	}
	return &OpenAIProvider{
		apiKey:  apiKey,
		healthy: true,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func NewAnthropicProvider(apiKey string) LLMProvider {
	if apiKey == "" {
		// Return mock if no API key
		return &MockProvider{
			name:    "anthropic",
			healthy: true,
			apiKey:  apiKey,
		}
	}

	// Use the enhanced Anthropic provider from the anthropic package
	provider, err := anthropic.NewProvider(anthropic.Config{
		APIKey: apiKey,
	})
	if err != nil {
		log.Printf("[LLMRouter] ERROR: Failed to initialize Anthropic provider: %v", err)
		return &MockProvider{
			name:    "anthropic",
			healthy: false,
			apiKey:  apiKey,
		}
	}

	return &EnhancedAnthropicProvider{
		provider: provider,
	}
}

// NewBedrockProvider creates a new Bedrock provider using the AWS SDK v2.
// This properly handles AWS Signature V4 authentication via IAM roles.
// Returns an error if AWS config loading fails - callers should handle this
// rather than silently falling back to mock.
func NewBedrockProvider(region, model string) (LLMProvider, error) {
	if region == "" {
		region = "us-east-1" // Default region
	}
	if model == "" {
		model = "anthropic.claude-3-5-sonnet-20240620-v1:0" // Default model
	}

	// Load AWS configuration with the specified region
	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for Bedrock (region: %s): %w", region, err)
	}

	// Create Bedrock runtime client with AWS Signature V4 auth
	client := bedrockruntime.NewFromConfig(awsCfg)

	log.Printf("[Bedrock] Successfully initialized AWS SDK provider (region: %s, model: %s)", region, model)
	return &BedrockProvider{
		client:  client,
		region:  region,
		model:   model,
		healthy: true,
	}, nil
}

func NewOllamaProvider(endpoint, model string) LLMProvider {
	if endpoint == "" {
		endpoint = "http://ollama:11434" // Default endpoint
	}
	if model == "" {
		model = "llama3.1:70b" // Default model
	}
	return &OllamaProvider{
		endpoint: endpoint,
		model:    model,
		healthy:  true,
		client:   &http.Client{Timeout: 120 * time.Second},
	}
}

func NewLocalLLMProvider(endpoint string) LLMProvider {
	// Deprecated: use NewOllamaProvider instead
	return NewOllamaProvider(endpoint, "")
}

func NewGeminiProvider(apiKey, model string) LLMProvider {
	if apiKey == "" {
		// Return mock if no API key
		return &MockProvider{
			name:    "gemini",
			healthy: true,
			apiKey:  apiKey,
		}
	}

	// Use the Gemini provider from the gemini package
	provider, err := gemini.NewProvider(gemini.Config{
		APIKey: apiKey,
		Model:  model,
	})
	if err != nil {
		log.Printf("[LLMRouter] ERROR: Failed to initialize Gemini provider: %v", err)
		return &MockProvider{
			name:    "gemini",
			healthy: false,
			apiKey:  apiKey,
		}
	}

	return &EnhancedGeminiProvider{
		provider: provider,
	}
}

func (m *MockProvider) Name() string {
	return m.name
}

func (m *MockProvider) Query(ctx context.Context, prompt string, options QueryOptions) (*LLMResponse, error) {
	// Mock implementation
	time.Sleep(100 * time.Millisecond) // Simulate API call
	
	return &LLMResponse{
		Content:      fmt.Sprintf("Mock response from %s for: %s", m.name, prompt),
		Model:        options.Model,
		TokensUsed:   len(prompt) / 4, // Rough estimate
		ResponseTime: 100 * time.Millisecond,
	}, nil
}

func (m *MockProvider) IsHealthy() bool {
	return m.healthy
}

func (m *MockProvider) GetCapabilities() []string {
	switch m.name {
	case "openai":
		return []string{"chat", "code", "embeddings"}
	case "anthropic":
		return []string{"chat", "analysis", "long_context"}
	case "local":
		return []string{"chat", "basic_queries"}
	default:
		return []string{"chat"}
	}
}

func (m *MockProvider) EstimateCost(tokens int) float64 {
	switch m.name {
	case "openai":
		return float64(tokens) * 0.00002 // $0.02 per 1K tokens
	case "anthropic":
		return float64(tokens) * 0.00003 // $0.03 per 1K tokens
	case "local":
		return 0 // Free
	default:
		return 0
	}
}

// Supporting components

type HealthChecker struct{}

func NewHealthChecker() *HealthChecker {
	return &HealthChecker{}
}

func (h *HealthChecker) CheckProvider(provider LLMProvider) bool {
	// In production, this would make actual health check calls
	return provider.IsHealthy()
}

type LoadBalancer struct {
	random *rand.Rand
}

func NewLoadBalancer() *LoadBalancer {
	return &LoadBalancer{
		random: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (l *LoadBalancer) SelectProvider(providers []string, weights map[string]float64) string {
	// Weighted random selection
	totalWeight := 0.0
	for _, p := range providers {
		totalWeight += weights[p]
	}
	
	r := l.random.Float64() * totalWeight
	
	for _, p := range providers {
		r -= weights[p]
		if r <= 0 {
			return p
		}
	}
	
	return providers[0] // Fallback
}

type ProviderMetricsTracker struct {
	metrics map[string]*ProviderMetrics
	mu      sync.RWMutex
}


func NewProviderMetricsTracker() *ProviderMetricsTracker {
	return &ProviderMetricsTracker{
		metrics: make(map[string]*ProviderMetrics),
	}
}

func (t *ProviderMetricsTracker) RecordSuccess(provider string, latency time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	if _, exists := t.metrics[provider]; !exists {
		t.metrics[provider] = &ProviderMetrics{}
	}
	
	m := t.metrics[provider]
	m.RequestCount++
	// Update fields that exist in the ProviderMetrics from metrics_collector.go
	// Note: TotalLatency and LastUsed don't exist in the current struct
	// We'll update the existing fields instead
	if m.RequestCount > 0 {
		// Update the average response time calculation
		totalMs := float64(m.RequestCount) * m.AvgResponseTime
		totalMs += float64(latency.Milliseconds())
		m.AvgResponseTime = totalMs / float64(m.RequestCount)
	}
}

func (t *ProviderMetricsTracker) RecordError(provider string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	if _, exists := t.metrics[provider]; !exists {
		t.metrics[provider] = &ProviderMetrics{}
	}
	
	t.metrics[provider].ErrorCount++
}

func (t *ProviderMetricsTracker) GetMetrics(provider string) ProviderMetrics {
	t.mu.RLock()
	defer t.mu.RUnlock()
	
	if m, exists := t.metrics[provider]; exists {
		return *m
	}
	return ProviderMetrics{}
}