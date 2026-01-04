// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"os"
	"testing"
)

func TestNewPricingConfig(t *testing.T) {
	pricing := NewPricingConfig()

	if pricing == nil {
		t.Fatal("expected non-nil pricing config")
	}

	if len(pricing.Providers) == 0 {
		t.Fatal("expected providers to be populated")
	}
}

func TestCalculateCost(t *testing.T) {
	pricing := NewPricingConfig()

	tests := []struct {
		name      string
		provider  string
		model     string
		tokensIn  int
		tokensOut int
		wantMin   float64
		wantMax   float64
	}{
		{
			name:      "anthropic claude-sonnet-4",
			provider:  "anthropic",
			model:     "claude-sonnet-4",
			tokensIn:  1000,
			tokensOut: 500,
			wantMin:   0.01,
			wantMax:   0.02,
		},
		{
			name:      "openai gpt-4o",
			provider:  "openai",
			model:     "gpt-4o",
			tokensIn:  1000,
			tokensOut: 1000,
			wantMin:   0.005,
			wantMax:   0.02,
		},
		{
			name:      "google gemini-pro",
			provider:  "google",
			model:     "gemini-pro",
			tokensIn:  2000,
			tokensOut: 1000,
			wantMin:   0.001,
			wantMax:   0.01,
		},
		{
			name:      "ollama local model",
			provider:  "ollama",
			model:     "llama3",
			tokensIn:  5000,
			tokensOut: 2000,
			wantMin:   0.0,
			wantMax:   0.001,
		},
		{
			name:      "unknown provider uses default",
			provider:  "unknown-provider",
			model:     "unknown-model",
			tokensIn:  1000,
			tokensOut: 1000,
			wantMin:   0.0,
			wantMax:   0.1,
		},
		{
			name:      "zero tokens",
			provider:  "anthropic",
			model:     "claude-sonnet-4",
			tokensIn:  0,
			tokensOut: 0,
			wantMin:   0.0,
			wantMax:   0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := pricing.CalculateCost(tt.provider, tt.model, tt.tokensIn, tt.tokensOut)

			if cost < tt.wantMin || cost > tt.wantMax {
				t.Errorf("cost = %v, want between %v and %v", cost, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestGetModelPricing(t *testing.T) {
	pricing := NewPricingConfig()

	tests := []struct {
		name     string
		provider string
		model    string
		wantOK   bool
	}{
		{
			name:     "existing model",
			provider: "anthropic",
			model:    "claude-sonnet-4",
			wantOK:   true,
		},
		{
			name:     "wildcard fallback",
			provider: "anthropic",
			model:    "claude-3-opus-20240229-variant",
			wantOK:   true, // Should fallback to wildcard
		},
		{
			name:     "unknown provider",
			provider: "nonexistent",
			model:    "model",
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := pricing.GetModelPricing(tt.provider, tt.model)
			if ok != tt.wantOK {
				t.Errorf("GetModelPricing() ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestListProviders(t *testing.T) {
	pricing := NewPricingConfig()

	providers := pricing.ListProviders()

	if len(providers) == 0 {
		t.Fatal("expected providers list to be non-empty")
	}

	// Check for expected providers
	expectedProviders := []string{"anthropic", "openai", "google", "azure", "ollama"}
	for _, expected := range expectedProviders {
		found := false
		for _, p := range providers {
			if p == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected provider %s not found in list", expected)
		}
	}
}

func TestListModels(t *testing.T) {
	pricing := NewPricingConfig()

	tests := []struct {
		name     string
		provider string
		wantMin  int
	}{
		{
			name:     "anthropic models",
			provider: "anthropic",
			wantMin:  3, // At least a few Claude models
		},
		{
			name:     "openai models",
			provider: "openai",
			wantMin:  3, // At least a few GPT models
		},
		{
			name:     "unknown provider",
			provider: "nonexistent",
			wantMin:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			models := pricing.ListModels(tt.provider)
			if len(models) < tt.wantMin {
				t.Errorf("ListModels() returned %d models, want at least %d", len(models), tt.wantMin)
			}
		})
	}
}

func TestLoadPricingFromEnv(t *testing.T) {
	// Save original env
	origProvider := os.Getenv("LLM_PRICING_PROVIDER")
	origModel := os.Getenv("LLM_PRICING_MODEL")
	origInput := os.Getenv("LLM_PRICING_INPUT")
	origOutput := os.Getenv("LLM_PRICING_OUTPUT")

	defer func() {
		os.Setenv("LLM_PRICING_PROVIDER", origProvider)
		os.Setenv("LLM_PRICING_MODEL", origModel)
		os.Setenv("LLM_PRICING_INPUT", origInput)
		os.Setenv("LLM_PRICING_OUTPUT", origOutput)
	}()

	// Test loading with no env vars set
	pricing := LoadPricingFromEnv()
	if pricing == nil {
		t.Fatal("expected non-nil pricing config")
	}

	// Test with custom pricing via env
	os.Setenv("LLM_PRICING_PROVIDER", "custom")
	os.Setenv("LLM_PRICING_MODEL", "custom-model")
	os.Setenv("LLM_PRICING_INPUT", "0.01")
	os.Setenv("LLM_PRICING_OUTPUT", "0.02")

	pricing = LoadPricingFromEnv()
	if pricing == nil {
		t.Fatal("expected non-nil pricing config with custom values")
	}
}

func TestDefaultPricing(t *testing.T) {
	if DefaultPricing == nil {
		t.Fatal("DefaultPricing should not be nil")
	}

	// Verify it has the expected structure
	if DefaultPricing.Providers == nil {
		t.Fatal("DefaultPricing.Providers should not be nil")
	}

	// Check for anthropic pricing
	if _, ok := DefaultPricing.Providers["anthropic"]; !ok {
		t.Error("DefaultPricing should have anthropic provider")
	}
}

func TestWildcardPricing(t *testing.T) {
	pricing := NewPricingConfig()

	// Add a provider with wildcard
	pricing.Providers["test-provider"] = map[string]ModelPricing{
		"*": {InputPer1K: 0.001, OutputPer1K: 0.002},
	}

	// Request a model not explicitly defined
	cost := pricing.CalculateCost("test-provider", "any-model", 1000, 1000)

	// Should use wildcard pricing: 0.001 + 0.002 = 0.003
	expected := 0.003
	if cost != expected {
		t.Errorf("wildcard cost = %v, want %v", cost, expected)
	}
}

func TestCostCalculationPrecision(t *testing.T) {
	pricing := NewPricingConfig()

	// Test with exact values to verify precision
	pricing.Providers["precise"] = map[string]ModelPricing{
		"model": {InputPer1K: 0.001, OutputPer1K: 0.002},
	}

	// 2500 input tokens at $0.001/1K = $0.0025
	// 3500 output tokens at $0.002/1K = $0.007
	// Total = $0.0095
	cost := pricing.CalculateCost("precise", "model", 2500, 3500)

	expected := 0.0095
	if cost != expected {
		t.Errorf("cost = %v, want %v", cost, expected)
	}
}
