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
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"
)

// Router handles intelligent routing to multiple LLM providers.
// It uses the Registry for provider management and supports:
// - Weighted load balancing
// - Health-based routing
// - Automatic failover
// - Request-specific provider selection
type Router struct {
	registry       *Registry
	loadBalancer   *routerLoadBalancer
	metricsTracker *routerMetricsTracker
	logger         *log.Logger
	mu             sync.RWMutex

	// Default weights for load balancing (can be overridden per-request)
	defaultWeights map[string]float64

	// cancelHealthCheck cancels the background health check goroutine
	cancelHealthCheck context.CancelFunc
}

// RouterConfig configures the Router.
type RouterConfig struct {
	// Registry is the provider registry to use.
	// If nil, a new registry is created.
	Registry *Registry

	// DefaultWeights maps provider names to routing weights.
	// Weights should sum to 1.0.
	DefaultWeights map[string]float64

	// Logger is the logger to use. If nil, a default logger is created.
	Logger *log.Logger

	// HealthCheckInterval is how often to check provider health.
	// If 0, defaults to 30 seconds.
	HealthCheckInterval time.Duration
}

// RouterOption configures the Router.
type RouterOption func(*Router)

// WithRouterRegistry sets the registry for the router.
func WithRouterRegistry(r *Registry) RouterOption {
	return func(router *Router) {
		router.registry = r
	}
}

// WithRouterLogger sets the logger for the router.
func WithRouterLogger(l *log.Logger) RouterOption {
	return func(r *Router) {
		r.logger = l
	}
}

// WithDefaultWeights sets default routing weights.
func WithDefaultWeights(weights map[string]float64) RouterOption {
	return func(r *Router) {
		r.defaultWeights = weights
	}
}

// NewRouter creates a new Router with the given options.
func NewRouter(opts ...RouterOption) *Router {
	r := &Router{
		loadBalancer:   newRouterLoadBalancer(),
		metricsTracker: newRouterMetricsTracker(),
		defaultWeights: make(map[string]float64),
		logger:         log.New(os.Stdout, "[LLM_ROUTER] ", log.LstdFlags),
	}

	for _, opt := range opts {
		opt(r)
	}

	// Create default registry if not provided
	if r.registry == nil {
		r.registry = NewRegistry()
	}

	return r
}

// NewRouterFromConfig creates a router from configuration.
func NewRouterFromConfig(config RouterConfig) *Router {
	r := &Router{
		registry:       config.Registry,
		loadBalancer:   newRouterLoadBalancer(),
		metricsTracker: newRouterMetricsTracker(),
		defaultWeights: config.DefaultWeights,
		logger:         config.Logger,
	}

	if r.registry == nil {
		r.registry = NewRegistry()
	}

	if r.logger == nil {
		r.logger = log.New(os.Stdout, "[LLM_ROUTER] ", log.LstdFlags)
	}

	if r.defaultWeights == nil {
		r.defaultWeights = make(map[string]float64)
	}

	// Start health check routine with cancellable context
	healthInterval := config.HealthCheckInterval
	if healthInterval == 0 {
		healthInterval = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancelHealthCheck = cancel
	r.registry.StartPeriodicHealthCheck(ctx, healthInterval)

	return r
}

// RouteRequest routes a completion request to an appropriate provider.
func (r *Router) RouteRequest(ctx context.Context, req CompletionRequest, opts ...RouteOption) (*CompletionResponse, *RouteInfo, error) {
	// Apply route options
	routeOpts := &routeOptions{}
	for _, opt := range opts {
		opt(routeOpts)
	}

	// Select provider
	provider, err := r.selectProvider(ctx, req, routeOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("provider selection failed: %w", err)
	}

	// Track start time
	startTime := time.Now()

	// Execute request
	response, err := provider.Complete(ctx, req)
	if err != nil {
		// Track error
		r.metricsTracker.recordError(provider.Name())

		// Try failover if enabled
		if !routeOpts.disableFailover {
			fallback, fallbackErr := r.getFallbackProvider(ctx, provider.Name())
			if fallbackErr == nil && fallback != nil {
				r.logger.Printf("Failing over from %s to %s", provider.Name(), fallback.Name())
				response, err = fallback.Complete(ctx, req)
				if err != nil {
					r.metricsTracker.recordError(fallback.Name())
					return nil, nil, fmt.Errorf("all providers failed: %w", err)
				}
				provider = fallback
			} else {
				return nil, nil, fmt.Errorf("primary provider failed and no fallback: %w", err)
			}
		} else {
			return nil, nil, fmt.Errorf("provider failed: %w", err)
		}
	}

	// Track success
	responseTime := time.Since(startTime)
	r.metricsTracker.recordSuccess(provider.Name(), responseTime)

	// Build route info
	routeInfo := &RouteInfo{
		ProviderName:   provider.Name(),
		ProviderType:   provider.Type(),
		Model:          response.Model,
		ResponseTimeMs: responseTime.Milliseconds(),
		TokensUsed:     response.Usage.TotalTokens,
	}

	// Add cost estimate if available
	if estimate := provider.EstimateCost(req); estimate != nil {
		routeInfo.EstimatedCost = estimate.TotalEstimate
	}

	return response, routeInfo, nil
}

// selectProvider selects the best provider for a request.
func (r *Router) selectProvider(ctx context.Context, req CompletionRequest, opts *routeOptions) (Provider, error) {
	// If a specific provider was requested, use it
	if opts.preferredProvider != "" {
		provider, err := r.registry.Get(ctx, opts.preferredProvider)
		if err == nil {
			return provider, nil
		}
		r.logger.Printf("Requested provider %q not available: %v", opts.preferredProvider, err)
	}

	// Get healthy providers
	healthyNames := r.registry.GetHealthyProviders()
	if len(healthyNames) == 0 {
		// Fall back to all enabled providers
		healthyNames = r.registry.ListEnabled()
	}

	if len(healthyNames) == 0 {
		return nil, fmt.Errorf("no providers available")
	}

	// Get weights
	weights := r.getWeights(healthyNames, opts.weights)

	// Select using load balancer
	selected := r.loadBalancer.selectProvider(healthyNames, weights)

	return r.registry.Get(ctx, selected)
}

// getWeights returns weights for the given providers.
func (r *Router) getWeights(providers []string, overrides map[string]float64) map[string]float64 {
	weights := make(map[string]float64)

	// Start with equal weights
	equalWeight := 1.0 / float64(len(providers))
	for _, p := range providers {
		weights[p] = equalWeight
	}

	// Apply default weights
	r.mu.RLock()
	for p, w := range r.defaultWeights {
		if _, ok := weights[p]; ok {
			weights[p] = w
		}
	}
	r.mu.RUnlock()

	// Apply overrides
	for p, w := range overrides {
		if _, ok := weights[p]; ok {
			weights[p] = w
		}
	}

	// Normalize weights
	total := 0.0
	for _, w := range weights {
		total += w
	}
	if total > 0 {
		for p := range weights {
			weights[p] /= total
		}
	}

	return weights
}

// getFallbackProvider returns a fallback provider.
func (r *Router) getFallbackProvider(ctx context.Context, failedProvider string) (Provider, error) {
	healthyNames := r.registry.GetHealthyProviders()

	for _, name := range healthyNames {
		if name != failedProvider {
			return r.registry.Get(ctx, name)
		}
	}

	return nil, fmt.Errorf("no fallback provider available")
}

// SetDefaultWeights updates the default routing weights.
func (r *Router) SetDefaultWeights(weights map[string]float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultWeights = weights
}

// GetProviderStatus returns the status of all providers.
func (r *Router) GetProviderStatus(ctx context.Context) map[string]*ProviderStatus {
	status := make(map[string]*ProviderStatus)

	// Get all provider names
	names := r.registry.List()

	for _, name := range names {
		config, err := r.registry.GetConfig(name)
		if err != nil {
			continue
		}

		healthResult := r.registry.GetHealthResult(name)
		metrics := r.metricsTracker.getMetrics(name)

		ps := &ProviderStatus{
			Name:       name,
			Type:       config.Type,
			Enabled:    config.Enabled,
			Priority:   config.Priority,
			Weight:     config.Weight,
			RateLimit:  config.RateLimit,
			Metrics:    metrics,
		}

		if healthResult != nil {
			ps.Health = *healthResult
		}

		r.mu.RLock()
		if w, ok := r.defaultWeights[name]; ok {
			ps.RoutingWeight = w
		}
		r.mu.RUnlock()

		status[name] = ps
	}

	return status
}

// Registry returns the underlying registry.
func (r *Router) Registry() *Registry {
	return r.registry
}

// Close shuts down the router.
func (r *Router) Close() error {
	// Cancel the health check goroutine if running
	if r.cancelHealthCheck != nil {
		r.cancelHealthCheck()
	}
	return r.registry.Close()
}

// RouteInfo contains information about how a request was routed.
type RouteInfo struct {
	ProviderName   string       `json:"provider_name"`
	ProviderType   ProviderType `json:"provider_type"`
	Model          string       `json:"model"`
	ResponseTimeMs int64        `json:"response_time_ms"`
	TokensUsed     int          `json:"tokens_used"`
	EstimatedCost  float64      `json:"estimated_cost,omitempty"`
}

// ProviderStatus contains the current status of a provider.
type ProviderStatus struct {
	Name          string            `json:"name"`
	Type          ProviderType      `json:"type"`
	Enabled       bool              `json:"enabled"`
	Priority      int               `json:"priority"`
	Weight        int               `json:"weight"`
	RateLimit     int               `json:"rate_limit"`
	RoutingWeight float64           `json:"routing_weight"`
	Health        HealthCheckResult `json:"health"`
	Metrics       *RouteMetrics     `json:"metrics"`
}

// RouteMetrics contains routing metrics for a provider.
type RouteMetrics struct {
	RequestCount    int64   `json:"request_count"`
	ErrorCount      int64   `json:"error_count"`
	AvgResponseTime float64 `json:"avg_response_time_ms"`
}

// RouteOption configures a route request.
type RouteOption func(*routeOptions)

type routeOptions struct {
	preferredProvider string
	weights           map[string]float64
	disableFailover   bool
}

// WithPreferredProvider sets a preferred provider for the request.
func WithPreferredProvider(name string) RouteOption {
	return func(o *routeOptions) {
		o.preferredProvider = name
	}
}

// WithRouteWeights sets custom weights for this request.
func WithRouteWeights(weights map[string]float64) RouteOption {
	return func(o *routeOptions) {
		o.weights = weights
	}
}

// WithDisableFailover disables automatic failover.
func WithDisableFailover() RouteOption {
	return func(o *routeOptions) {
		o.disableFailover = true
	}
}

// routerLoadBalancer handles weighted random selection.
type routerLoadBalancer struct {
	random *rand.Rand
	mu     sync.Mutex
}

func newRouterLoadBalancer() *routerLoadBalancer {
	return &routerLoadBalancer{
		random: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (lb *routerLoadBalancer) selectProvider(providers []string, weights map[string]float64) string {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	totalWeight := 0.0
	for _, p := range providers {
		totalWeight += weights[p]
	}

	r := lb.random.Float64() * totalWeight

	for _, p := range providers {
		r -= weights[p]
		if r <= 0 {
			return p
		}
	}

	return providers[0]
}

// routerMetricsTracker tracks routing metrics.
type routerMetricsTracker struct {
	metrics map[string]*RouteMetrics
	mu      sync.RWMutex
}

func newRouterMetricsTracker() *routerMetricsTracker {
	return &routerMetricsTracker{
		metrics: make(map[string]*RouteMetrics),
	}
}

func (t *routerMetricsTracker) recordSuccess(provider string, latency time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.metrics[provider]; !exists {
		t.metrics[provider] = &RouteMetrics{}
	}

	m := t.metrics[provider]
	m.RequestCount++

	// Update average response time using incremental formula
	totalMs := float64(m.RequestCount-1) * m.AvgResponseTime
	totalMs += float64(latency.Milliseconds())
	m.AvgResponseTime = totalMs / float64(m.RequestCount)
}

func (t *routerMetricsTracker) recordError(provider string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.metrics[provider]; !exists {
		t.metrics[provider] = &RouteMetrics{}
	}

	t.metrics[provider].ErrorCount++
}

func (t *routerMetricsTracker) getMetrics(provider string) *RouteMetrics {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if m, exists := t.metrics[provider]; exists {
		copy := *m
		return &copy
	}
	return &RouteMetrics{}
}
