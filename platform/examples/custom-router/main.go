// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Custom LLM Router Example
//
// This example demonstrates how to implement a custom LLM router using
// the LLMRouterInterface. Custom routers enable advanced routing logic,
// custom caching strategies, or integration with proprietary LLM systems.
//
// Use cases:
//   - Custom load balancing across LLM providers
//   - Request caching and deduplication
//   - Custom rate limiting logic
//   - Integration with internal LLM deployments
package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"axonflow/platform/orchestrator"
)

// CachingRouter implements LLMRouterInterface with response caching.
// This demonstrates a custom router that adds caching on top of
// another router implementation.
type CachingRouter struct {
	upstream orchestrator.LLMRouterInterface
	cache    sync.Map // map[string]*cachedResponse
	hits     int64
	misses   int64
	ttl      time.Duration
}

type cachedResponse struct {
	response  *orchestrator.LLMResponse
	info      *orchestrator.ProviderInfo
	expiresAt time.Time
}

// NewCachingRouter creates a caching wrapper around an existing router.
func NewCachingRouter(upstream orchestrator.LLMRouterInterface, ttl time.Duration) *CachingRouter {
	return &CachingRouter{
		upstream: upstream,
		ttl:      ttl,
	}
}

// RouteRequest implements LLMRouterInterface with caching logic.
func (r *CachingRouter) RouteRequest(ctx context.Context, req orchestrator.OrchestratorRequest) (*orchestrator.LLMResponse, *orchestrator.ProviderInfo, error) {
	// Generate cache key from query (in production, include more fields)
	cacheKey := req.Query

	// Check cache
	if cached, ok := r.cache.Load(cacheKey); ok {
		entry := cached.(*cachedResponse)
		if time.Now().Before(entry.expiresAt) {
			atomic.AddInt64(&r.hits, 1)
			log.Printf("[CachingRouter] Cache hit for query: %s", truncate(req.Query, 50))
			return entry.response, entry.info, nil
		}
		// Expired - remove from cache
		r.cache.Delete(cacheKey)
	}

	atomic.AddInt64(&r.misses, 1)
	log.Printf("[CachingRouter] Cache miss for query: %s", truncate(req.Query, 50))

	// Forward to upstream router
	response, info, err := r.upstream.RouteRequest(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	// Cache the response
	r.cache.Store(cacheKey, &cachedResponse{
		response:  response,
		info:      info,
		expiresAt: time.Now().Add(r.ttl),
	})

	return response, info, nil
}

// IsHealthy returns true if the upstream router is healthy.
func (r *CachingRouter) IsHealthy() bool {
	return r.upstream.IsHealthy()
}

// GetProviderStatus returns provider status from the upstream router.
func (r *CachingRouter) GetProviderStatus() map[string]orchestrator.ProviderStatus {
	return r.upstream.GetProviderStatus()
}

// UpdateProviderWeights updates weights on the upstream router.
func (r *CachingRouter) UpdateProviderWeights(weights map[string]float64) error {
	return r.upstream.UpdateProviderWeights(weights)
}

// GetCacheStats returns cache hit/miss statistics.
func (r *CachingRouter) GetCacheStats() (hits, misses int64) {
	return atomic.LoadInt64(&r.hits), atomic.LoadInt64(&r.misses)
}

// Compile-time check that CachingRouter implements LLMRouterInterface
var _ orchestrator.LLMRouterInterface = (*CachingRouter)(nil)

// MockProvider implements a simple mock for demonstration.
type MockProvider struct {
	name         string
	healthy      bool
	requestCount int64
}

// MockRouter demonstrates a simple LLMRouterInterface implementation.
type MockRouter struct {
	providers map[string]*MockProvider
	mu        sync.RWMutex
}

// NewMockRouter creates a mock router for demonstration purposes.
func NewMockRouter() *MockRouter {
	return &MockRouter{
		providers: map[string]*MockProvider{
			"openai": {
				name:    "openai",
				healthy: true,
			},
			"anthropic": {
				name:    "anthropic",
				healthy: true,
			},
		},
	}
}

// RouteRequest implements LLMRouterInterface.
func (r *MockRouter) RouteRequest(ctx context.Context, req orchestrator.OrchestratorRequest) (*orchestrator.LLMResponse, *orchestrator.ProviderInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Select first healthy provider
	var selectedProvider *MockProvider
	for _, p := range r.providers {
		if p.healthy {
			selectedProvider = p
			break
		}
	}

	if selectedProvider == nil {
		return nil, nil, fmt.Errorf("no healthy providers available")
	}

	atomic.AddInt64(&selectedProvider.requestCount, 1)

	// Simulate LLM response
	return &orchestrator.LLMResponse{
		Content:      fmt.Sprintf("Mock response for: %s", truncate(req.Query, 30)),
		Model:        "mock-model-v1",
		TokensUsed:   100,
		ResponseTime: 50 * time.Millisecond,
	}, &orchestrator.ProviderInfo{
		Provider:       selectedProvider.name,
		Model:          "mock-model-v1",
		ResponseTimeMs: 50,
		TokensUsed:     100,
	}, nil
}

// IsHealthy returns true if any provider is healthy.
func (r *MockRouter) IsHealthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.providers {
		if p.healthy {
			return true
		}
	}
	return false
}

// GetProviderStatus returns status for all providers.
func (r *MockRouter) GetProviderStatus() map[string]orchestrator.ProviderStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	status := make(map[string]orchestrator.ProviderStatus)
	for name, p := range r.providers {
		status[name] = orchestrator.ProviderStatus{
			Name:         p.name,
			Healthy:      p.healthy,
			Weight:       0.5,
			RequestCount: p.requestCount,
			ErrorCount:   0,
			AvgLatency:   50,
			LastUsed:     time.Now(),
		}
	}
	return status
}

// UpdateProviderWeights is a no-op for the mock router.
func (r *MockRouter) UpdateProviderWeights(weights map[string]float64) error {
	log.Printf("[MockRouter] UpdateProviderWeights called with: %v", weights)
	return nil
}

// Compile-time check that MockRouter implements LLMRouterInterface
var _ orchestrator.LLMRouterInterface = (*MockRouter)(nil)

func main() {
	fmt.Println("=== Custom LLM Router Example ===")
	fmt.Println()

	// Create the base mock router
	mockRouter := NewMockRouter()
	fmt.Println("1. Created MockRouter implementing LLMRouterInterface")
	fmt.Printf("   Health: %v\n", mockRouter.IsHealthy())
	fmt.Printf("   Providers: %d\n", len(mockRouter.GetProviderStatus()))
	fmt.Println()

	// Wrap with caching router
	cachingRouter := NewCachingRouter(mockRouter, 5*time.Minute)
	fmt.Println("2. Created CachingRouter wrapper")
	fmt.Println()

	// Demonstrate routing
	ctx := context.Background()
	fmt.Println("3. Making requests through CachingRouter:")

	queries := []string{
		"What is the weather today?",
		"How does machine learning work?",
		"What is the weather today?", // Duplicate - should be cached
		"Explain quantum computing",
		"What is the weather today?", // Another duplicate
	}

	for i, query := range queries {
		req := orchestrator.OrchestratorRequest{
			RequestID: fmt.Sprintf("req-%d", i),
			Query:     query,
		}

		response, info, err := cachingRouter.RouteRequest(ctx, req)
		if err != nil {
			log.Printf("   [%d] Error: %v", i, err)
			continue
		}

		fmt.Printf("   [%d] Query: %s\n", i, truncate(query, 30))
		fmt.Printf("       Provider: %s, Response: %s\n",
			info.Provider, truncate(response.Content, 50))
	}
	fmt.Println()

	// Show cache statistics
	hits, misses := cachingRouter.GetCacheStats()
	fmt.Println("4. Cache Statistics:")
	fmt.Printf("   Hits: %d, Misses: %d\n", hits, misses)
	fmt.Printf("   Hit Rate: %.1f%%\n", float64(hits)/float64(hits+misses)*100)
	fmt.Println()

	// Show provider status
	fmt.Println("5. Provider Status:")
	for name, status := range cachingRouter.GetProviderStatus() {
		fmt.Printf("   %s: healthy=%v, requests=%d\n",
			name, status.Healthy, status.RequestCount)
	}
	fmt.Println()

	fmt.Println("=== Example Complete ===")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
