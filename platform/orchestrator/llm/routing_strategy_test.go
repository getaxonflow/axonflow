// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package llm

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
		{"weighted is valid", "weighted", true},
		{"round_robin is valid", "round_robin", true},
		{"failover is valid", "failover", true},
		{"empty is invalid", "", false},
		{"random is invalid", "random", false},
		// Note: cost_optimized is valid in enterprise builds, invalid in community builds
		// This is tested separately in routing_strategy_enterprise_test.go
		{"WEIGHTED uppercase is invalid", "WEIGHTED", false},
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
		name      string
		input     string
		wantErr   bool
		checkFunc func(t *testing.T, weights map[string]float64)
	}{
		{
			name:    "empty string",
			input:   "",
			wantErr: false,
			checkFunc: func(t *testing.T, weights map[string]float64) {
				if len(weights) != 0 {
					t.Errorf("expected empty map, got %v", weights)
				}
			},
		},
		{
			name:    "single provider",
			input:   "openai:100",
			wantErr: false,
			checkFunc: func(t *testing.T, weights map[string]float64) {
				if weights["openai"] != 1.0 {
					t.Errorf("expected openai weight 1.0, got %f", weights["openai"])
				}
			},
		},
		{
			name:    "multiple providers",
			input:   "openai:50,anthropic:30,bedrock:20",
			wantErr: false,
			checkFunc: func(t *testing.T, weights map[string]float64) {
				// Should be normalized to sum to 1.0
				if weights["openai"] != 0.5 {
					t.Errorf("expected openai weight 0.5, got %f", weights["openai"])
				}
				if weights["anthropic"] != 0.3 {
					t.Errorf("expected anthropic weight 0.3, got %f", weights["anthropic"])
				}
				if weights["bedrock"] != 0.2 {
					t.Errorf("expected bedrock weight 0.2, got %f", weights["bedrock"])
				}
			},
		},
		{
			name:    "with spaces",
			input:   " openai : 60 , anthropic : 40 ",
			wantErr: false,
			checkFunc: func(t *testing.T, weights map[string]float64) {
				if weights["openai"] != 0.6 {
					t.Errorf("expected openai weight 0.6, got %f", weights["openai"])
				}
			},
		},
		{
			name:    "decimal weights",
			input:   "openai:0.7,anthropic:0.3",
			wantErr: false,
			checkFunc: func(t *testing.T, weights map[string]float64) {
				if weights["openai"] != 0.7 {
					t.Errorf("expected openai weight 0.7, got %f", weights["openai"])
				}
			},
		},
		{
			name:    "invalid format - no colon",
			input:   "openai50",
			wantErr: true,
		},
		{
			name:    "invalid format - multiple colons",
			input:   "openai:50:extra",
			wantErr: true,
		},
		{
			name:    "invalid weight - not a number",
			input:   "openai:abc",
			wantErr: true,
		},
		{
			name:    "invalid weight - negative",
			input:   "openai:-50",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProviderWeights(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseProviderWeights(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if tt.checkFunc != nil && err == nil {
				tt.checkFunc(t, got)
			}
		})
	}
}

func TestLoadRoutingConfigFromEnv(t *testing.T) {
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
		strategy        string
		weights         string
		defaultProvider string
		checkFunc       func(t *testing.T, config RoutingConfig)
	}{
		{
			name: "defaults when env not set",
			checkFunc: func(t *testing.T, config RoutingConfig) {
				if config.Strategy != RoutingStrategyWeighted {
					t.Errorf("expected default strategy weighted, got %s", config.Strategy)
				}
			},
		},
		{
			name:     "round_robin strategy",
			strategy: "round_robin",
			checkFunc: func(t *testing.T, config RoutingConfig) {
				if config.Strategy != RoutingStrategyRoundRobin {
					t.Errorf("expected round_robin, got %s", config.Strategy)
				}
			},
		},
		{
			name:     "failover strategy with default provider",
			strategy: "failover",
			weights:  "bedrock:100",
			defaultProvider: "bedrock",
			checkFunc: func(t *testing.T, config RoutingConfig) {
				if config.Strategy != RoutingStrategyFailover {
					t.Errorf("expected failover, got %s", config.Strategy)
				}
				if config.DefaultProvider != "bedrock" {
					t.Errorf("expected default provider bedrock, got %s", config.DefaultProvider)
				}
				if config.ProviderWeights["bedrock"] != 1.0 {
					t.Errorf("expected bedrock weight 1.0, got %f", config.ProviderWeights["bedrock"])
				}
			},
		},
		{
			name:     "invalid strategy falls back to weighted",
			strategy: "invalid",
			checkFunc: func(t *testing.T, config RoutingConfig) {
				if config.Strategy != RoutingStrategyWeighted {
					t.Errorf("expected weighted on invalid, got %s", config.Strategy)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("LLM_ROUTING_STRATEGY", tt.strategy)
			os.Setenv("PROVIDER_WEIGHTS", tt.weights)
			os.Setenv("DEFAULT_LLM_PROVIDER", tt.defaultProvider)

			config := LoadRoutingConfigFromEnv()
			if tt.checkFunc != nil {
				tt.checkFunc(t, config)
			}
		})
	}
}

func TestProviderSelector_SelectProvider_Weighted(t *testing.T) {
	selector := NewProviderSelector(RoutingStrategyWeighted, "")
	providers := []string{"openai", "anthropic", "bedrock"}
	weights := map[string]float64{
		"openai":    0.6,
		"anthropic": 0.3,
		"bedrock":   0.1,
	}

	// Run multiple selections to verify distribution
	counts := make(map[string]int)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		selected := selector.SelectProvider(providers, weights)
		counts[selected]++
	}

	// Verify all providers are selected at least once
	for _, p := range providers {
		if counts[p] == 0 {
			t.Errorf("provider %s was never selected", p)
		}
	}

	// Verify rough distribution (allowing for randomness)
	openaiPct := float64(counts["openai"]) / float64(iterations)
	if openaiPct < 0.4 || openaiPct > 0.8 {
		t.Errorf("openai selection rate %f outside expected range 0.4-0.8", openaiPct)
	}
}

func TestProviderSelector_SelectProvider_RoundRobin(t *testing.T) {
	selector := NewProviderSelector(RoutingStrategyRoundRobin, "")
	providers := []string{"openai", "anthropic", "bedrock"}
	weights := map[string]float64{} // Should be ignored

	// Verify cycling through providers
	for cycle := 0; cycle < 3; cycle++ {
		for i, expected := range providers {
			selected := selector.SelectProvider(providers, weights)
			if selected != expected {
				t.Errorf("cycle %d, index %d: expected %s, got %s", cycle, i, expected, selected)
			}
		}
	}
}

func TestProviderSelector_SelectProvider_Failover(t *testing.T) {
	tests := []struct {
		name            string
		defaultProvider string
		providers       []string
		weights         map[string]float64
		want            string
	}{
		{
			name:            "uses default provider when healthy",
			defaultProvider: "bedrock",
			providers:       []string{"openai", "bedrock", "anthropic"},
			weights:         map[string]float64{"openai": 0.5, "bedrock": 0.3, "anthropic": 0.2},
			want:            "bedrock",
		},
		{
			name:            "falls back to highest weight when default unhealthy",
			defaultProvider: "bedrock",
			providers:       []string{"openai", "anthropic"}, // bedrock not in healthy list
			weights:         map[string]float64{"openai": 0.6, "anthropic": 0.4},
			want:            "openai",
		},
		{
			name:            "uses first provider when no weights",
			defaultProvider: "bedrock",
			providers:       []string{"openai", "anthropic"},
			weights:         map[string]float64{},
			want:            "openai",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector := NewProviderSelector(RoutingStrategyFailover, tt.defaultProvider)
			got := selector.SelectProvider(tt.providers, tt.weights)
			if got != tt.want {
				t.Errorf("SelectProvider() = %s, want %s", got, tt.want)
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
			selector := NewProviderSelector(strategy, "default")
			got := selector.SelectProvider([]string{}, map[string]float64{})
			if got != "" {
				t.Errorf("expected empty string for empty providers, got %s", got)
			}
		})
	}
}

func TestProviderSelector_Getters(t *testing.T) {
	selector := NewProviderSelector(RoutingStrategyFailover, "bedrock")

	if selector.GetStrategy() != RoutingStrategyFailover {
		t.Errorf("GetStrategy() = %s, want failover", selector.GetStrategy())
	}

	if selector.GetDefaultProvider() != "bedrock" {
		t.Errorf("GetDefaultProvider() = %s, want bedrock", selector.GetDefaultProvider())
	}
}

func TestProviderSelector_Setters(t *testing.T) {
	selector := NewProviderSelector(RoutingStrategyWeighted, "")

	selector.SetStrategy(RoutingStrategyRoundRobin)
	if selector.GetStrategy() != RoutingStrategyRoundRobin {
		t.Errorf("after SetStrategy, GetStrategy() = %s, want round_robin", selector.GetStrategy())
	}

	selector.SetDefaultProvider("anthropic")
	if selector.GetDefaultProvider() != "anthropic" {
		t.Errorf("after SetDefaultProvider, GetDefaultProvider() = %s, want anthropic", selector.GetDefaultProvider())
	}
}

func TestValidRoutingStrategies(t *testing.T) {
	// Core strategies that must be present in both community and enterprise builds
	coreStrategies := []RoutingStrategy{
		RoutingStrategyWeighted,
		RoutingStrategyRoundRobin,
		RoutingStrategyFailover,
	}

	// At minimum, core strategies must be present (enterprise adds cost_optimized)
	if len(ValidRoutingStrategies) < len(coreStrategies) {
		t.Errorf("ValidRoutingStrategies has %d elements, want at least %d", len(ValidRoutingStrategies), len(coreStrategies))
	}

	// Verify core strategies are present and in correct order
	for i, s := range coreStrategies {
		if i >= len(ValidRoutingStrategies) || ValidRoutingStrategies[i] != s {
			t.Errorf("ValidRoutingStrategies[%d] = %v, want %s", i,
				func() string {
					if i < len(ValidRoutingStrategies) {
						return string(ValidRoutingStrategies[i])
					}
					return "<missing>"
				}(), s)
		}
	}
}

func TestProviderSelector_SelectWeighted_NoWeights(t *testing.T) {
	selector := NewProviderSelector(RoutingStrategyWeighted, "")
	providers := []string{"openai", "anthropic"}
	weights := map[string]float64{} // Empty weights

	// Should fall back to random selection
	counts := make(map[string]int)
	for i := 0; i < 100; i++ {
		selected := selector.SelectProvider(providers, weights)
		counts[selected]++
	}

	// Both should be selected at least once
	if counts["openai"] == 0 {
		t.Error("openai never selected with empty weights")
	}
	if counts["anthropic"] == 0 {
		t.Error("anthropic never selected with empty weights")
	}
}
