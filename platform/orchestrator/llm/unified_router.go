// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package llm

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// UnifiedRouter provides a unified interface for LLM routing that bridges
// the legacy LLMRouter API with the new Router implementation.
// This enables gradual migration without breaking existing code.
type UnifiedRouter struct {
	router         *Router
	routingConfig  RoutingConfig
	logger         *log.Logger
	mu             sync.RWMutex
}

// UnifiedRouterConfig configures the UnifiedRouter.
type UnifiedRouterConfig struct {
	// Registry is the provider registry to use.
	Registry *Registry

	// RoutingConfig is the routing configuration (strategy, weights, default provider).
	RoutingConfig RoutingConfig

	// Logger is the logger to use.
	Logger *log.Logger

	// HealthCheckInterval is how often to check provider health.
	HealthCheckInterval time.Duration
}

// NewUnifiedRouter creates a new UnifiedRouter.
func NewUnifiedRouter(config UnifiedRouterConfig) *UnifiedRouter {
	if config.Logger == nil {
		config.Logger = log.New(os.Stdout, "[UNIFIED_ROUTER] ", log.LstdFlags)
	}

	// Create the underlying new Router
	routerConfig := RouterConfig{
		Registry:            config.Registry,
		DefaultWeights:      config.RoutingConfig.ProviderWeights,
		RoutingStrategy:     config.RoutingConfig.Strategy,
		DefaultProvider:     config.RoutingConfig.DefaultProvider,
		Logger:              config.Logger,
		HealthCheckInterval: config.HealthCheckInterval,
	}

	router := NewRouterFromConfig(routerConfig)

	return &UnifiedRouter{
		router:        router,
		routingConfig: config.RoutingConfig,
		logger:        config.Logger,
	}
}

// NewUnifiedRouterFromEnv creates a UnifiedRouter with configuration from environment.
func NewUnifiedRouterFromEnv(registry *Registry) *UnifiedRouter {
	routingConfig := LoadRoutingConfigFromEnv()

	return NewUnifiedRouter(UnifiedRouterConfig{
		Registry:            registry,
		RoutingConfig:       routingConfig,
		HealthCheckInterval: 30 * time.Second,
	})
}

// RouteRequest routes a request using the legacy request format.
// This is the main compatibility method for existing code.
func (u *UnifiedRouter) RouteRequest(ctx context.Context, reqCtx RequestContext) (*LegacyLLMResponse, *LegacyProviderInfo, error) {
	// Convert legacy request context to new CompletionRequest
	req := RequestContextToCompletionRequest(reqCtx)

	// Build route options
	var opts []RouteOption
	if reqCtx.Provider != "" {
		opts = append(opts, WithPreferredProvider(reqCtx.Provider))
	}

	// Route using new router
	resp, routeInfo, err := u.router.RouteRequest(ctx, req, opts...)
	if err != nil {
		return nil, nil, err
	}

	// Convert response back to legacy format
	legacyResp := CompletionResponseToLegacyResponse(resp)
	legacyInfo := RouteInfoToLegacyProviderInfo(routeInfo)

	return legacyResp, legacyInfo, nil
}

// RouteCompletionRequest routes a request using the new request format.
// Use this for new code that has migrated to the new types.
func (u *UnifiedRouter) RouteCompletionRequest(ctx context.Context, req CompletionRequest, opts ...RouteOption) (*CompletionResponse, *RouteInfo, error) {
	return u.router.RouteRequest(ctx, req, opts...)
}

// GetProviderStatus returns the status of all providers.
func (u *UnifiedRouter) GetProviderStatus(ctx context.Context) map[string]*ProviderStatus {
	return u.router.GetProviderStatus(ctx)
}

// GetLegacyProviderStatus returns provider status in legacy format.
func (u *UnifiedRouter) GetLegacyProviderStatus() map[string]LegacyProviderStatus {
	ctx := context.Background()
	status := u.router.GetProviderStatus(ctx)

	legacy := make(map[string]LegacyProviderStatus)
	for name, ps := range status {
		legacy[name] = LegacyProviderStatus{
			Name:         ps.Name,
			Healthy:      ps.Health.Status == HealthStatusHealthy,
			Weight:       ps.RoutingWeight,
			RequestCount: ps.Metrics.RequestCount,
			ErrorCount:   ps.Metrics.ErrorCount,
			AvgLatency:   ps.Metrics.AvgResponseTime,
			LastUsed:     time.Now(), // Approximate
		}
	}
	return legacy
}

// LegacyProviderStatus is the legacy provider status format.
type LegacyProviderStatus struct {
	Name         string    `json:"name"`
	Healthy      bool      `json:"healthy"`
	Weight       float64   `json:"weight"`
	RequestCount int64     `json:"request_count"`
	ErrorCount   int64     `json:"error_count"`
	AvgLatency   float64   `json:"avg_latency_ms"`
	LastUsed     time.Time `json:"last_used"`
}

// UpdateProviderWeights updates routing weights at runtime.
func (u *UnifiedRouter) UpdateProviderWeights(weights map[string]float64) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if len(weights) == 0 {
		return fmt.Errorf("weights cannot be empty")
	}

	u.router.SetDefaultWeights(weights)
	u.routingConfig.ProviderWeights = weights
	u.logger.Printf("Updated provider weights: %v", weights)

	return nil
}

// GetRoutingStrategy returns the current routing strategy.
func (u *UnifiedRouter) GetRoutingStrategy() RoutingStrategy {
	return u.router.GetRoutingStrategy()
}

// SetRoutingStrategy updates the routing strategy at runtime.
func (u *UnifiedRouter) SetRoutingStrategy(strategy RoutingStrategy) {
	u.router.SetRoutingStrategy(strategy)
	u.logger.Printf("Updated routing strategy: %s", strategy)
}

// GetDefaultProvider returns the configured default provider.
func (u *UnifiedRouter) GetDefaultProvider() string {
	return u.router.GetDefaultProvider()
}

// SetDefaultProvider updates the default provider at runtime.
func (u *UnifiedRouter) SetDefaultProvider(provider string) {
	u.router.SetDefaultProvider(provider)
	u.logger.Printf("Updated default provider: %s", provider)
}

// IsHealthy returns true if at least one provider is healthy.
func (u *UnifiedRouter) IsHealthy() bool {
	healthy := u.router.Registry().GetHealthyProviders()
	return len(healthy) > 0
}

// Registry returns the underlying registry.
func (u *UnifiedRouter) Registry() *Registry {
	return u.router.Registry()
}

// Router returns the underlying new Router.
func (u *UnifiedRouter) Router() *Router {
	return u.router
}

// Close shuts down the router.
func (u *UnifiedRouter) Close() error {
	return u.router.Close()
}

// RegisterProvider registers a provider with the registry.
func (u *UnifiedRouter) RegisterProvider(config ProviderConfig) error {
	return u.router.Registry().Register(context.Background(), &config)
}

// EnableProvider enables a provider for routing.
func (u *UnifiedRouter) EnableProvider(name string) error {
	return u.router.Registry().Enable(name)
}

// DisableProvider disables a provider (removes from routing).
func (u *UnifiedRouter) DisableProvider(name string) error {
	return u.router.Registry().Disable(name)
}

// GetProvider returns a provider by name.
func (u *UnifiedRouter) GetProvider(ctx context.Context, name string) (Provider, error) {
	return u.router.Registry().Get(ctx, name)
}

// ListProviders returns all registered provider names.
func (u *UnifiedRouter) ListProviders() []string {
	return u.router.Registry().List()
}

// ListEnabledProviders returns names of enabled providers.
func (u *UnifiedRouter) ListEnabledProviders() []string {
	return u.router.Registry().ListEnabled()
}

// ListHealthyProviders returns names of healthy providers.
func (u *UnifiedRouter) ListHealthyProviders() []string {
	return u.router.Registry().GetHealthyProviders()
}
