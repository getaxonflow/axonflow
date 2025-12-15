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

// Package sdk provides a fluent builder API for creating custom LLM providers.
// It follows the same pattern as the MCP connector SDK for consistency.
//
// Quick Start:
//
//	provider := sdk.NewProviderBuilder("my-provider", llm.ProviderTypeCustom).
//	    WithModel("my-model-v1").
//	    WithAuth(sdk.NewAPIKeyAuth(apiKey)).
//	    WithRateLimiter(sdk.NewRateLimiter(100, 100)).
//	    Build()
//
// For more complex providers, implement the llm.Provider interface directly
// and optionally embed BaseProvider for common functionality.
package sdk

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"axonflow/platform/orchestrator/llm"
)

// Version is the current SDK version
const Version = "1.0.0"

// ProviderBuilder provides a fluent interface for building LLM providers.
type ProviderBuilder struct {
	name           string
	providerType   llm.ProviderType
	model          string
	endpoint       string
	authProvider   AuthProvider
	rateLimiter    *RateLimiter
	retryConfig    *RetryConfig
	logger         *log.Logger
	capabilities   []llm.Capability
	httpClient     *http.Client
	timeout        time.Duration
	costEstimator  CostEstimator
	healthChecker  HealthChecker
	streamSupport  bool
	completeFunc   CompleteFunc
}

// CompleteFunc is a function type for custom completion logic.
type CompleteFunc func(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error)

// CostEstimator estimates costs for requests.
type CostEstimator interface {
	EstimateCost(req llm.CompletionRequest) *llm.CostEstimate
}

// HealthChecker performs health checks.
type HealthChecker interface {
	HealthCheck(ctx context.Context) (*llm.HealthCheckResult, error)
}

// NewProviderBuilder creates a new provider builder.
func NewProviderBuilder(name string, providerType llm.ProviderType) *ProviderBuilder {
	return &ProviderBuilder{
		name:         name,
		providerType: providerType,
		capabilities: []llm.Capability{llm.CapabilityChat, llm.CapabilityCompletion},
		logger:       log.New(os.Stdout, fmt.Sprintf("[LLM_%s] ", name), log.LstdFlags),
		timeout:      30 * time.Second,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}
}

// WithModel sets the default model.
func (b *ProviderBuilder) WithModel(model string) *ProviderBuilder {
	b.model = model
	return b
}

// WithEndpoint sets the API endpoint.
func (b *ProviderBuilder) WithEndpoint(endpoint string) *ProviderBuilder {
	b.endpoint = endpoint
	return b
}

// WithAuth sets the authentication provider.
func (b *ProviderBuilder) WithAuth(auth AuthProvider) *ProviderBuilder {
	b.authProvider = auth
	return b
}

// WithRateLimiter sets the rate limiter.
func (b *ProviderBuilder) WithRateLimiter(limiter *RateLimiter) *ProviderBuilder {
	b.rateLimiter = limiter
	return b
}

// WithRetry sets the retry configuration.
func (b *ProviderBuilder) WithRetry(config *RetryConfig) *ProviderBuilder {
	b.retryConfig = config
	return b
}

// WithLogger sets a custom logger.
func (b *ProviderBuilder) WithLogger(logger *log.Logger) *ProviderBuilder {
	b.logger = logger
	return b
}

// WithCapabilities sets the provider capabilities.
func (b *ProviderBuilder) WithCapabilities(caps ...llm.Capability) *ProviderBuilder {
	b.capabilities = caps
	return b
}

// WithHTTPClient sets a custom HTTP client.
func (b *ProviderBuilder) WithHTTPClient(client *http.Client) *ProviderBuilder {
	b.httpClient = client
	return b
}

// WithTimeout sets the request timeout.
func (b *ProviderBuilder) WithTimeout(timeout time.Duration) *ProviderBuilder {
	b.timeout = timeout
	b.httpClient.Timeout = timeout
	return b
}

// WithCostEstimator sets a custom cost estimator.
func (b *ProviderBuilder) WithCostEstimator(estimator CostEstimator) *ProviderBuilder {
	b.costEstimator = estimator
	return b
}

// WithHealthChecker sets a custom health checker.
func (b *ProviderBuilder) WithHealthChecker(checker HealthChecker) *ProviderBuilder {
	b.healthChecker = checker
	return b
}

// WithStreaming enables streaming support.
func (b *ProviderBuilder) WithStreaming(enabled bool) *ProviderBuilder {
	b.streamSupport = enabled
	if enabled && !containsCapability(b.capabilities, llm.CapabilityStreaming) {
		b.capabilities = append(b.capabilities, llm.CapabilityStreaming)
	}
	return b
}

// WithCompleteFunc sets a custom completion function.
// This is the core logic that actually calls the LLM API.
func (b *ProviderBuilder) WithCompleteFunc(fn CompleteFunc) *ProviderBuilder {
	b.completeFunc = fn
	return b
}

// Build creates a Provider with the configured options.
func (b *ProviderBuilder) Build() *CustomProvider {
	return &CustomProvider{
		name:          b.name,
		providerType:  b.providerType,
		model:         b.model,
		endpoint:      b.endpoint,
		authProvider:  b.authProvider,
		rateLimiter:   b.rateLimiter,
		retryConfig:   b.retryConfig,
		logger:        b.logger,
		capabilities:  b.capabilities,
		httpClient:    b.httpClient,
		timeout:       b.timeout,
		costEstimator: b.costEstimator,
		healthChecker: b.healthChecker,
		streamSupport: b.streamSupport,
		completeFunc:  b.completeFunc,
	}
}

// CustomProvider is a provider built using the SDK.
type CustomProvider struct {
	name          string
	providerType  llm.ProviderType
	model         string
	endpoint      string
	authProvider  AuthProvider
	rateLimiter   *RateLimiter
	retryConfig   *RetryConfig
	logger        *log.Logger
	capabilities  []llm.Capability
	httpClient    *http.Client
	timeout       time.Duration
	costEstimator CostEstimator
	healthChecker HealthChecker
	streamSupport bool
	completeFunc  CompleteFunc
}

// Name returns the provider name.
func (p *CustomProvider) Name() string {
	return p.name
}

// Type returns the provider type.
func (p *CustomProvider) Type() llm.ProviderType {
	return p.providerType
}

// Complete sends a completion request.
func (p *CustomProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	// Apply rate limiting
	if p.rateLimiter != nil {
		if err := p.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit exceeded: %w", err)
		}
	}

	// Use default model if not specified in request
	if req.Model == "" {
		req.Model = p.model
	}

	// Execute with retry if configured
	if p.retryConfig != nil && p.completeFunc != nil {
		return RetryWithBackoff(ctx, *p.retryConfig, func(ctx context.Context) (*llm.CompletionResponse, error) {
			return p.completeFunc(ctx, req)
		})
	}

	// Direct execution
	if p.completeFunc != nil {
		return p.completeFunc(ctx, req)
	}

	return nil, fmt.Errorf("no completion function configured - use WithCompleteFunc()")
}

// HealthCheck verifies the provider is operational.
func (p *CustomProvider) HealthCheck(ctx context.Context) (*llm.HealthCheckResult, error) {
	if p.healthChecker != nil {
		return p.healthChecker.HealthCheck(ctx)
	}

	// Default health check - try a simple completion
	start := time.Now()
	_, err := p.Complete(ctx, llm.CompletionRequest{
		Prompt:    "ping",
		MaxTokens: 1,
	})

	status := llm.HealthStatusHealthy
	message := "OK"
	if err != nil {
		status = llm.HealthStatusUnhealthy
		message = err.Error()
	}

	return &llm.HealthCheckResult{
		Status:      status,
		Latency:     time.Since(start),
		Message:     message,
		LastChecked: time.Now(),
	}, nil
}

// Capabilities returns the provider's capabilities.
func (p *CustomProvider) Capabilities() []llm.Capability {
	return p.capabilities
}

// SupportsStreaming returns true if streaming is supported.
func (p *CustomProvider) SupportsStreaming() bool {
	return p.streamSupport
}

// EstimateCost estimates the cost for a request.
func (p *CustomProvider) EstimateCost(req llm.CompletionRequest) *llm.CostEstimate {
	if p.costEstimator != nil {
		return p.costEstimator.EstimateCost(req)
	}

	// Default cost estimate (custom providers have unknown pricing)
	return &llm.CostEstimate{
		InputCostPer1K:        0,
		OutputCostPer1K:       0,
		EstimatedInputTokens:  len(req.Prompt) / 4,
		EstimatedOutputTokens: req.MaxTokens,
		TotalEstimate:         0,
		Currency:              "USD",
	}
}

// HTTPClient returns the HTTP client for making requests.
func (p *CustomProvider) HTTPClient() *http.Client {
	return p.httpClient
}

// AuthProvider returns the authentication provider.
func (p *CustomProvider) AuthProvider() AuthProvider {
	return p.authProvider
}

// Logger returns the logger.
func (p *CustomProvider) Logger() *log.Logger {
	return p.logger
}

// Endpoint returns the API endpoint.
func (p *CustomProvider) Endpoint() string {
	return p.endpoint
}

// Model returns the default model.
func (p *CustomProvider) Model() string {
	return p.model
}

// containsCapability checks if a capability is in the list.
func containsCapability(caps []llm.Capability, cap llm.Capability) bool {
	for _, c := range caps {
		if c == cap {
			return true
		}
	}
	return false
}

// Verify interface compliance at compile time.
var _ llm.Provider = (*CustomProvider)(nil)
