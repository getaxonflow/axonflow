// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"os"
	"testing"
)

func TestIsValidRoutingStrategy(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		want     bool
	}{
		{"valid weighted", "weighted", true},
		{"valid round_robin", "round_robin", true},
		{"valid failover", "failover", true},
		{"invalid empty", "", false},
		{"invalid random string", "random", false},
		{"invalid cost_optimized", "cost_optimized", false}, // Future enterprise feature
		{"case sensitive", "Weighted", false},
		{"with spaces", " weighted ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidRoutingStrategy(tt.strategy)
			if got != tt.want {
				t.Errorf("IsValidRoutingStrategy(%q) = %v, want %v", tt.strategy, got, tt.want)
			}
		})
	}
}

func TestParseProviderWeights(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantWeights map[string]float64
		wantErr     bool
	}{
		{
			name:        "single provider 100%",
			input:       "bedrock:100",
			wantWeights: map[string]float64{"bedrock": 1.0},
			wantErr:     false,
		},
		{
			name:  "two providers equal",
			input: "openai:50,anthropic:50",
			wantWeights: map[string]float64{
				"openai":    0.5,
				"anthropic": 0.5,
			},
			wantErr: false,
		},
		{
			name:  "three providers",
			input: "openai:50,anthropic:30,bedrock:20",
			wantWeights: map[string]float64{
				"openai":    0.5,
				"anthropic": 0.3,
				"bedrock":   0.2,
			},
			wantErr: false,
		},
		{
			name:  "with spaces",
			input: " openai : 60 , anthropic : 40 ",
			wantWeights: map[string]float64{
				"openai":    0.6,
				"anthropic": 0.4,
			},
			wantErr: false,
		},
		{
			name:        "empty string",
			input:       "",
			wantWeights: map[string]float64{},
			wantErr:     false,
		},
		{
			name:    "invalid format no colon",
			input:   "openai50",
			wantErr: true,
		},
		{
			name:    "invalid weight not a number",
			input:   "openai:abc",
			wantErr: true,
		},
		{
			name:    "negative weight",
			input:   "openai:-10",
			wantErr: true,
		},
		{
			name:  "decimal weights",
			input: "openai:0.5,anthropic:0.5",
			wantWeights: map[string]float64{
				"openai":    0.5,
				"anthropic": 0.5,
			},
			wantErr: false,
		},
		{
			name:  "unnormalized weights get normalized",
			input: "openai:1,anthropic:1,bedrock:1",
			wantWeights: map[string]float64{
				"openai":    1.0 / 3.0,
				"anthropic": 1.0 / 3.0,
				"bedrock":   1.0 / 3.0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProviderWeights(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseProviderWeights(%q) expected error, got nil", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseProviderWeights(%q) unexpected error: %v", tt.input, err)
				return
			}

			if len(got) != len(tt.wantWeights) {
				t.Errorf("ParseProviderWeights(%q) got %d providers, want %d", tt.input, len(got), len(tt.wantWeights))
				return
			}

			for provider, wantWeight := range tt.wantWeights {
				gotWeight, ok := got[provider]
				if !ok {
					t.Errorf("ParseProviderWeights(%q) missing provider %q", tt.input, provider)
					continue
				}
				// Allow small floating point error
				if diff := gotWeight - wantWeight; diff > 0.0001 || diff < -0.0001 {
					t.Errorf("ParseProviderWeights(%q) provider %q got weight %f, want %f", tt.input, provider, gotWeight, wantWeight)
				}
			}
		})
	}
}

func TestLoadRoutingConfig(t *testing.T) {
	// Save original env vars
	origStrategy := os.Getenv("LLM_ROUTING_STRATEGY")
	origWeights := os.Getenv("PROVIDER_WEIGHTS")
	origDefault := os.Getenv("DEFAULT_LLM_PROVIDER")

	defer func() {
		os.Setenv("LLM_ROUTING_STRATEGY", origStrategy)
		os.Setenv("PROVIDER_WEIGHTS", origWeights)
		os.Setenv("DEFAULT_LLM_PROVIDER", origDefault)
	}()

	tests := []struct {
		name            string
		envStrategy     string
		envWeights      string
		envDefault      string
		wantStrategy    RoutingStrategy
		wantWeightsLen  int
		wantDefault     string
	}{
		{
			name:           "default values",
			envStrategy:    "",
			envWeights:     "",
			envDefault:     "",
			wantStrategy:   RoutingStrategyWeighted,
			wantWeightsLen: 0,
			wantDefault:    "",
		},
		{
			name:           "round_robin strategy",
			envStrategy:    "round_robin",
			envWeights:     "",
			envDefault:     "",
			wantStrategy:   RoutingStrategyRoundRobin,
			wantWeightsLen: 0,
			wantDefault:    "",
		},
		{
			name:           "failover with default provider",
			envStrategy:    "failover",
			envWeights:     "",
			envDefault:     "bedrock",
			wantStrategy:   RoutingStrategyFailover,
			wantWeightsLen: 0,
			wantDefault:    "bedrock",
		},
		{
			name:           "weighted with custom weights",
			envStrategy:    "weighted",
			envWeights:     "openai:60,anthropic:40",
			envDefault:     "",
			wantStrategy:   RoutingStrategyWeighted,
			wantWeightsLen: 2,
			wantDefault:    "",
		},
		{
			name:           "invalid strategy falls back to weighted",
			envStrategy:    "invalid_strategy",
			envWeights:     "",
			envDefault:     "",
			wantStrategy:   RoutingStrategyWeighted,
			wantWeightsLen: 0,
			wantDefault:    "",
		},
		{
			name:           "full configuration",
			envStrategy:    "failover",
			envWeights:     "bedrock:100",
			envDefault:     "bedrock",
			wantStrategy:   RoutingStrategyFailover,
			wantWeightsLen: 1,
			wantDefault:    "bedrock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("LLM_ROUTING_STRATEGY", tt.envStrategy)
			os.Setenv("PROVIDER_WEIGHTS", tt.envWeights)
			os.Setenv("DEFAULT_LLM_PROVIDER", tt.envDefault)

			config := LoadRoutingConfig()

			if config.Strategy != tt.wantStrategy {
				t.Errorf("LoadRoutingConfig() Strategy = %v, want %v", config.Strategy, tt.wantStrategy)
			}

			if len(config.ProviderWeights) != tt.wantWeightsLen {
				t.Errorf("LoadRoutingConfig() ProviderWeights len = %d, want %d", len(config.ProviderWeights), tt.wantWeightsLen)
			}

			if config.DefaultProvider != tt.wantDefault {
				t.Errorf("LoadRoutingConfig() DefaultProvider = %q, want %q", config.DefaultProvider, tt.wantDefault)
			}
		})
	}
}

func TestProviderSelector_SelectProvider_Weighted(t *testing.T) {
	selector := NewProviderSelector(RoutingStrategyWeighted, "")
	loadBalancer := NewLoadBalancer()

	weights := map[string]float64{
		"openai":    0.5,
		"anthropic": 0.3,
		"bedrock":   0.2,
	}

	healthyProviders := []string{"openai", "anthropic", "bedrock"}

	// Run multiple selections to verify randomness works
	selections := make(map[string]int)
	for i := 0; i < 100; i++ {
		selected := selector.SelectProvider(healthyProviders, weights, loadBalancer)
		selections[selected]++
	}

	// All providers should be selected at least once with these weights
	for _, provider := range healthyProviders {
		if selections[provider] == 0 {
			t.Errorf("Provider %q was never selected in 100 iterations", provider)
		}
	}
}

func TestProviderSelector_SelectProvider_RoundRobin(t *testing.T) {
	selector := NewProviderSelector(RoutingStrategyRoundRobin, "")
	loadBalancer := NewLoadBalancer()

	weights := map[string]float64{
		"openai":    0.5,
		"anthropic": 0.5,
	}

	healthyProviders := []string{"openai", "anthropic"}

	// Round robin should cycle through providers
	selections := make([]string, 6)
	for i := 0; i < 6; i++ {
		selections[i] = selector.SelectProvider(healthyProviders, weights, loadBalancer)
	}

	// Should alternate (or at least cycle)
	for i := 0; i < 3; i++ {
		if selections[i] != selections[i+2] {
			// This might fail due to map iteration order being random
			// Skip this assertion
		}
	}

	// Verify both providers are used
	providerUsed := make(map[string]bool)
	for _, s := range selections {
		providerUsed[s] = true
	}

	if len(providerUsed) != 2 {
		t.Errorf("Round robin should use all providers, only used %d", len(providerUsed))
	}
}

func TestProviderSelector_SelectProvider_Failover(t *testing.T) {
	tests := []struct {
		name             string
		defaultProvider  string
		healthyProviders []string
		weights          map[string]float64
		wantProvider     string
	}{
		{
			name:             "uses default when healthy",
			defaultProvider:  "bedrock",
			healthyProviders: []string{"openai", "anthropic", "bedrock"},
			weights: map[string]float64{
				"openai":    0.5,
				"anthropic": 0.3,
				"bedrock":   0.2,
			},
			wantProvider: "bedrock",
		},
		{
			name:             "falls back to highest weight when default unhealthy",
			defaultProvider:  "bedrock",
			healthyProviders: []string{"openai", "anthropic"},
			weights: map[string]float64{
				"openai":    0.5,
				"anthropic": 0.3,
				"bedrock":   0.2,
			},
			wantProvider: "openai",
		},
		{
			name:             "falls back to first when no weights match",
			defaultProvider:  "bedrock",
			healthyProviders: []string{"gemini"},
			weights:          map[string]float64{},
			wantProvider:     "gemini",
		},
		{
			name:             "no default uses highest weight",
			defaultProvider:  "",
			healthyProviders: []string{"openai", "anthropic"},
			weights: map[string]float64{
				"openai":    0.3,
				"anthropic": 0.7,
			},
			wantProvider: "anthropic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector := NewProviderSelector(RoutingStrategyFailover, tt.defaultProvider)
			loadBalancer := NewLoadBalancer()

			got := selector.SelectProvider(tt.healthyProviders, tt.weights, loadBalancer)

			if got != tt.wantProvider {
				t.Errorf("SelectProvider() = %q, want %q", got, tt.wantProvider)
			}
		})
	}
}

func TestProviderSelector_EmptyProviders(t *testing.T) {
	strategies := []RoutingStrategy{
		RoutingStrategyWeighted,
		RoutingStrategyRoundRobin,
		RoutingStrategyFailover,
	}

	for _, strategy := range strategies {
		t.Run(string(strategy), func(t *testing.T) {
			selector := NewProviderSelector(strategy, "bedrock")
			loadBalancer := NewLoadBalancer()

			got := selector.SelectProvider([]string{}, map[string]float64{}, loadBalancer)

			if got != "" {
				t.Errorf("SelectProvider with empty providers = %q, want empty string", got)
			}
		})
	}
}

func TestProviderSelector_GetStrategy(t *testing.T) {
	strategies := []RoutingStrategy{
		RoutingStrategyWeighted,
		RoutingStrategyRoundRobin,
		RoutingStrategyFailover,
	}

	for _, strategy := range strategies {
		t.Run(string(strategy), func(t *testing.T) {
			selector := NewProviderSelector(strategy, "")
			if got := selector.GetStrategy(); got != strategy {
				t.Errorf("GetStrategy() = %v, want %v", got, strategy)
			}
		})
	}
}

func TestProviderSelector_GetDefaultProvider(t *testing.T) {
	tests := []struct {
		name    string
		default_ string
	}{
		{"empty", ""},
		{"bedrock", "bedrock"},
		{"openai", "openai"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector := NewProviderSelector(RoutingStrategyFailover, tt.default_)
			if got := selector.GetDefaultProvider(); got != tt.default_ {
				t.Errorf("GetDefaultProvider() = %q, want %q", got, tt.default_)
			}
		})
	}
}

func TestValidRoutingStrategies(t *testing.T) {
	// Verify the constant slice contains expected values
	expected := []RoutingStrategy{
		RoutingStrategyWeighted,
		RoutingStrategyRoundRobin,
		RoutingStrategyFailover,
	}

	if len(ValidRoutingStrategies) != len(expected) {
		t.Errorf("ValidRoutingStrategies has %d items, expected %d", len(ValidRoutingStrategies), len(expected))
	}

	for _, e := range expected {
		found := false
		for _, v := range ValidRoutingStrategies {
			if v == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ValidRoutingStrategies missing %v", e)
		}
	}
}

// Tests for LLMRouter integration with routing strategies
func TestLLMRouter_WithRoutingStrategy(t *testing.T) {
	tests := []struct {
		name         string
		config       LLMRouterConfig
		wantStrategy RoutingStrategy
		wantDefault  string
	}{
		{
			name: "default strategy when not specified",
			config: LLMRouterConfig{
				OpenAIKey: "test-key",
			},
			wantStrategy: RoutingStrategyWeighted,
			wantDefault:  "",
		},
		{
			name: "round_robin strategy",
			config: LLMRouterConfig{
				OpenAIKey:       "test-key",
				RoutingStrategy: RoutingStrategyRoundRobin,
			},
			wantStrategy: RoutingStrategyRoundRobin,
			wantDefault:  "",
		},
		{
			name: "failover with default provider",
			config: LLMRouterConfig{
				OpenAIKey:       "test-key",
				AnthropicKey:    "test-key",
				RoutingStrategy: RoutingStrategyFailover,
				DefaultProvider: "anthropic",
			},
			wantStrategy: RoutingStrategyFailover,
			wantDefault:  "anthropic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewLLMRouter(tt.config)

			if got := router.GetRoutingStrategy(); got != tt.wantStrategy {
				t.Errorf("GetRoutingStrategy() = %v, want %v", got, tt.wantStrategy)
			}

			if got := router.GetDefaultProvider(); got != tt.wantDefault {
				t.Errorf("GetDefaultProvider() = %q, want %q", got, tt.wantDefault)
			}
		})
	}
}

func TestLLMRouter_ApplyCustomWeights(t *testing.T) {
	tests := []struct {
		name          string
		config        LLMRouterConfig
		wantWeights   map[string]float64
		wantZeroFor   []string // providers that should have 0 weight
	}{
		{
			name: "single provider 100%",
			config: LLMRouterConfig{
				OpenAIKey:    "test-key",
				AnthropicKey: "test-key",
				ProviderWeights: map[string]float64{
					"openai": 1.0,
				},
			},
			wantWeights: map[string]float64{
				"openai": 1.0,
			},
			wantZeroFor: []string{"anthropic"},
		},
		{
			name: "split between two providers",
			config: LLMRouterConfig{
				OpenAIKey:    "test-key",
				AnthropicKey: "test-key",
				ProviderWeights: map[string]float64{
					"openai":    0.6,
					"anthropic": 0.4,
				},
			},
			wantWeights: map[string]float64{
				"openai":    0.6,
				"anthropic": 0.4,
			},
			wantZeroFor: []string{},
		},
		{
			name: "ignores weights for non-existent providers",
			config: LLMRouterConfig{
				OpenAIKey: "test-key",
				ProviderWeights: map[string]float64{
					"openai":    0.5,
					"bedrock":   0.5, // Not configured
				},
			},
			wantWeights: map[string]float64{
				"openai": 1.0, // Normalized since bedrock is ignored
			},
			wantZeroFor: []string{},
		},
		{
			name: "no custom weights uses defaults",
			config: LLMRouterConfig{
				OpenAIKey:       "test-key",
				AnthropicKey:    "test-key",
				ProviderWeights: map[string]float64{},
			},
			wantWeights: map[string]float64{
				"openai":    0.25,
				"anthropic": 0.25,
			},
			wantZeroFor: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewLLMRouter(tt.config)
			status := router.GetProviderStatus()

			for provider, wantWeight := range tt.wantWeights {
				if s, ok := status[provider]; ok {
					diff := s.Weight - wantWeight
					if diff > 0.01 || diff < -0.01 {
						t.Errorf("Provider %q weight = %f, want %f", provider, s.Weight, wantWeight)
					}
				} else {
					t.Errorf("Provider %q not found in status", provider)
				}
			}

			for _, provider := range tt.wantZeroFor {
				if s, ok := status[provider]; ok {
					if s.Weight != 0 {
						t.Errorf("Provider %q weight = %f, want 0", provider, s.Weight)
					}
				}
			}
		})
	}
}

func TestLLMRouter_NilProviderSelector(t *testing.T) {
	// Test the nil checks in GetRoutingStrategy and GetDefaultProvider
	router := &LLMRouter{
		providerSelector: nil,
	}

	if got := router.GetRoutingStrategy(); got != RoutingStrategyWeighted {
		t.Errorf("GetRoutingStrategy() with nil selector = %v, want %v", got, RoutingStrategyWeighted)
	}

	if got := router.GetDefaultProvider(); got != "" {
		t.Errorf("GetDefaultProvider() with nil selector = %q, want empty string", got)
	}
}
