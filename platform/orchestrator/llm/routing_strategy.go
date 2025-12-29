// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package llm

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RoutingStrategy defines how the LLM router selects providers.
type RoutingStrategy string

const (
	// RoutingStrategyWeighted selects providers based on configured weights (default).
	// Weights are normalized to sum to 1.0.
	RoutingStrategyWeighted RoutingStrategy = "weighted"

	// RoutingStrategyRoundRobin cycles through healthy providers equally.
	// Ignores weight configuration.
	RoutingStrategyRoundRobin RoutingStrategy = "round_robin"

	// RoutingStrategyFailover uses primary provider, falls back on failure.
	// Primary is determined by DEFAULT_LLM_PROVIDER or highest weight.
	RoutingStrategyFailover RoutingStrategy = "failover"
)

// ValidRoutingStrategies contains all valid routing strategy values.
var ValidRoutingStrategies = []RoutingStrategy{
	RoutingStrategyWeighted,
	RoutingStrategyRoundRobin,
	RoutingStrategyFailover,
}

// IsValidRoutingStrategy checks if a string is a valid routing strategy.
func IsValidRoutingStrategy(s string) bool {
	for _, valid := range ValidRoutingStrategies {
		if RoutingStrategy(s) == valid {
			return true
		}
	}
	return false
}

// RoutingConfig holds the routing configuration.
type RoutingConfig struct {
	// Strategy is the routing algorithm to use.
	Strategy RoutingStrategy

	// ProviderWeights maps provider names to their routing weights (normalized to sum to 1.0).
	ProviderWeights map[string]float64

	// DefaultProvider is the fallback provider for failover strategy.
	DefaultProvider string
}

// LoadRoutingConfigFromEnv loads routing configuration from environment variables.
//
// Environment variables:
//   - LLM_ROUTING_STRATEGY: "weighted" (default), "round_robin", or "failover"
//   - PROVIDER_WEIGHTS: "openai:50,anthropic:30,bedrock:20" or "bedrock:100"
//   - DEFAULT_LLM_PROVIDER: fallback provider when primary selection fails
func LoadRoutingConfigFromEnv() RoutingConfig {
	config := RoutingConfig{
		Strategy:        RoutingStrategyWeighted,
		ProviderWeights: make(map[string]float64),
		DefaultProvider: "",
	}

	// Load routing strategy
	strategyStr := os.Getenv("LLM_ROUTING_STRATEGY")
	if strategyStr != "" {
		if IsValidRoutingStrategy(strategyStr) {
			config.Strategy = RoutingStrategy(strategyStr)
			log.Printf("[LLM Routing] Strategy: %s", config.Strategy)
		} else {
			log.Printf("[LLM Routing] WARNING: Invalid LLM_ROUTING_STRATEGY '%s', using default 'weighted'", strategyStr)
			log.Printf("[LLM Routing] Valid strategies: %v", ValidRoutingStrategies)
		}
	}

	// Load provider weights
	weightsStr := os.Getenv("PROVIDER_WEIGHTS")
	if weightsStr != "" {
		weights, err := ParseProviderWeights(weightsStr)
		if err != nil {
			log.Printf("[LLM Routing] WARNING: Failed to parse PROVIDER_WEIGHTS '%s': %v", weightsStr, err)
		} else {
			config.ProviderWeights = weights
			log.Printf("[LLM Routing] Provider weights: %v", weights)
		}
	}

	// Load default provider
	config.DefaultProvider = os.Getenv("DEFAULT_LLM_PROVIDER")
	if config.DefaultProvider != "" {
		log.Printf("[LLM Routing] Default provider: %s", config.DefaultProvider)
	}

	return config
}

// ParseProviderWeights parses a weights string into a map.
// Format: "provider1:weight1,provider2:weight2" (e.g., "openai:50,anthropic:30,bedrock:20")
// Weights are normalized to sum to 1.0.
func ParseProviderWeights(weightsStr string) (map[string]float64, error) {
	weights := make(map[string]float64)

	if weightsStr == "" {
		return weights, nil
	}

	parts := strings.Split(weightsStr, ",")
	totalWeight := 0.0

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		kv := strings.Split(part, ":")
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid weight format '%s', expected 'provider:weight'", part)
		}

		provider := strings.TrimSpace(kv[0])
		weightStr := strings.TrimSpace(kv[1])

		weight, err := strconv.ParseFloat(weightStr, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid weight value '%s' for provider '%s': %w", weightStr, provider, err)
		}

		if weight < 0 {
			return nil, fmt.Errorf("negative weight %f for provider '%s'", weight, provider)
		}

		weights[provider] = weight
		totalWeight += weight
	}

	// Normalize weights to sum to 1.0
	if totalWeight > 0 {
		for provider := range weights {
			weights[provider] = weights[provider] / totalWeight
		}
	}

	return weights, nil
}

// ProviderSelector handles provider selection based on routing strategy.
type ProviderSelector struct {
	strategy        RoutingStrategy
	defaultProvider string
	roundRobinIndex uint64 // Atomic counter for round-robin
	random          *rand.Rand
	mu              sync.Mutex
}

// NewProviderSelector creates a new provider selector with the given strategy.
func NewProviderSelector(strategy RoutingStrategy, defaultProvider string) *ProviderSelector {
	return &ProviderSelector{
		strategy:        strategy,
		defaultProvider: defaultProvider,
		roundRobinIndex: 0,
		random:          rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// SelectProvider selects a provider based on the configured strategy.
// Parameters:
//   - healthyProviders: list of currently healthy provider names
//   - weights: map of provider name to weight (normalized)
//
// Returns the selected provider name, or empty string if no providers available.
func (s *ProviderSelector) SelectProvider(healthyProviders []string, weights map[string]float64) string {
	if len(healthyProviders) == 0 {
		return ""
	}

	switch s.strategy {
	case RoutingStrategyRoundRobin:
		return s.selectRoundRobin(healthyProviders)
	case RoutingStrategyFailover:
		return s.selectFailover(healthyProviders, weights)
	case RoutingStrategyWeighted:
		fallthrough
	default:
		return s.selectWeighted(healthyProviders, weights)
	}
}

// selectWeighted performs weighted random selection.
func (s *ProviderSelector) selectWeighted(healthyProviders []string, weights map[string]float64) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Calculate total weight for healthy providers
	totalWeight := 0.0
	for _, p := range healthyProviders {
		if w, ok := weights[p]; ok {
			totalWeight += w
		} else {
			// Default weight of 1.0 for unweighted providers
			totalWeight += 1.0
		}
	}

	if totalWeight == 0 {
		// Fall back to random selection
		return healthyProviders[s.random.Intn(len(healthyProviders))]
	}

	// Random weighted selection
	r := s.random.Float64() * totalWeight
	for _, p := range healthyProviders {
		w := 1.0
		if weight, ok := weights[p]; ok {
			w = weight
		}
		r -= w
		if r <= 0 {
			return p
		}
	}

	// Fallback to first provider
	return healthyProviders[0]
}

// selectRoundRobin cycles through providers equally.
func (s *ProviderSelector) selectRoundRobin(healthyProviders []string) string {
	index := atomic.AddUint64(&s.roundRobinIndex, 1) - 1
	return healthyProviders[int(index)%len(healthyProviders)]
}

// selectFailover uses the primary (default/first weighted) provider, falls back to others.
func (s *ProviderSelector) selectFailover(healthyProviders []string, weights map[string]float64) string {
	// Check if default provider is healthy
	if s.defaultProvider != "" {
		for _, p := range healthyProviders {
			if p == s.defaultProvider {
				return p
			}
		}
	}

	// Fall back to highest weighted provider that's healthy
	var highestWeight float64
	var highestProvider string

	for _, p := range healthyProviders {
		if w, ok := weights[p]; ok && w > highestWeight {
			highestWeight = w
			highestProvider = p
		}
	}

	if highestProvider != "" {
		return highestProvider
	}

	// Last resort: first healthy provider
	return healthyProviders[0]
}

// GetStrategy returns the current routing strategy.
func (s *ProviderSelector) GetStrategy() RoutingStrategy {
	return s.strategy
}

// GetDefaultProvider returns the configured default provider.
func (s *ProviderSelector) GetDefaultProvider() string {
	return s.defaultProvider
}

// SetStrategy updates the routing strategy at runtime.
func (s *ProviderSelector) SetStrategy(strategy RoutingStrategy) {
	s.strategy = strategy
}

// SetDefaultProvider updates the default provider at runtime.
func (s *ProviderSelector) SetDefaultProvider(provider string) {
	s.defaultProvider = provider
}
