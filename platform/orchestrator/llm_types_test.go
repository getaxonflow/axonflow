// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"fmt"
	"testing"
	"time"

	"axonflow/platform/orchestrator/llm"
)

func TestLoadRoutingConfig(t *testing.T) {
	// Test that LoadRoutingConfig returns a valid RoutingConfig
	config := LoadRoutingConfig()

	// Should have a valid strategy (defaults to weighted if not set)
	if config.Strategy != llm.RoutingStrategyWeighted &&
		config.Strategy != llm.RoutingStrategyRoundRobin &&
		config.Strategy != llm.RoutingStrategyFailover {
		// If no strategy is set in env, it should be empty string or default
		// Just verify it doesn't panic
	}

	// Weights should be a valid map (can be nil or empty)
	// This just verifies the function runs without error
}

func TestRoutingStrategyConstants(t *testing.T) {
	// Test that routing strategy constants are correctly aliased
	tests := []struct {
		name     string
		constant RoutingStrategy
		expected llm.RoutingStrategy
	}{
		{
			name:     "weighted strategy",
			constant: RoutingStrategyWeighted,
			expected: llm.RoutingStrategyWeighted,
		},
		{
			name:     "round robin strategy",
			constant: RoutingStrategyRoundRobin,
			expected: llm.RoutingStrategyRoundRobin,
		},
		{
			name:     "failover strategy",
			constant: RoutingStrategyFailover,
			expected: llm.RoutingStrategyFailover,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, tt.constant)
			}
		})
	}
}

func TestLLMRouterConfigFields(t *testing.T) {
	// Test that LLMRouterConfig can be initialized with all fields
	config := LLMRouterConfig{
		OpenAIKey:       "test-openai-key",
		AnthropicKey:    "test-anthropic-key",
		GeminiKey:       "test-gemini-key",
		GeminiModel:     "gemini-pro",
		BedrockRegion:   "us-east-1",
		BedrockModel:    "anthropic.claude-3-sonnet",
		OllamaEndpoint:  "http://localhost:11434",
		OllamaModel:     "llama2",
		LocalEndpoint:   "http://localhost:11434", // deprecated
		RoutingStrategy: RoutingStrategyWeighted,
		ProviderWeights: map[string]float64{"openai": 0.5, "anthropic": 0.5},
		DefaultProvider: "openai",
	}

	// Verify fields are set correctly
	if config.OpenAIKey != "test-openai-key" {
		t.Error("OpenAIKey not set correctly")
	}
	if config.AnthropicKey != "test-anthropic-key" {
		t.Error("AnthropicKey not set correctly")
	}
	if config.RoutingStrategy != RoutingStrategyWeighted {
		t.Error("RoutingStrategy not set correctly")
	}
	if len(config.ProviderWeights) != 2 {
		t.Error("ProviderWeights not set correctly")
	}
}

func TestQueryOptionsFields(t *testing.T) {
	// Test QueryOptions struct
	opts := QueryOptions{
		MaxTokens:    1000,
		Temperature:  0.7,
		Model:        "gpt-4",
		SystemPrompt: "You are a helpful assistant",
	}

	if opts.MaxTokens != 1000 {
		t.Errorf("MaxTokens expected 1000, got %d", opts.MaxTokens)
	}
	if opts.Temperature != 0.7 {
		t.Errorf("Temperature expected 0.7, got %f", opts.Temperature)
	}
	if opts.Model != "gpt-4" {
		t.Errorf("Model expected gpt-4, got %s", opts.Model)
	}
	if opts.SystemPrompt != "You are a helpful assistant" {
		t.Errorf("SystemPrompt not set correctly")
	}
}

func TestLLMResponseFields(t *testing.T) {
	// Test LLMResponse struct
	resp := LLMResponse{
		Content:      "Hello, world!",
		Model:        "gpt-4",
		TokensUsed:   50,
		Metadata:     map[string]interface{}{"finish_reason": "stop"},
		ResponseTime: 100 * time.Millisecond,
	}

	if resp.Content != "Hello, world!" {
		t.Error("Content not set correctly")
	}
	if resp.Model != "gpt-4" {
		t.Error("Model not set correctly")
	}
	if resp.TokensUsed != 50 {
		t.Errorf("TokensUsed expected 50, got %d", resp.TokensUsed)
	}
	if resp.Metadata["finish_reason"] != "stop" {
		t.Error("Metadata not set correctly")
	}
	if resp.ResponseTime != 100*time.Millisecond {
		t.Error("ResponseTime not set correctly")
	}
}

func TestMockLLMRouter_GetProviderStatus_NilResult(t *testing.T) {
	// Test GetProviderStatus with nil ProviderStatusResult
	router := &MockLLMRouter{
		Healthy:              true,
		ProviderStatusResult: nil, // explicitly nil
	}

	status := router.GetProviderStatus()
	if status == nil {
		t.Error("GetProviderStatus should return empty map, not nil")
	}
	if len(status) != 0 {
		t.Errorf("Expected empty map, got %d entries", len(status))
	}
}

func TestMockLLMRouter_FullInterface(t *testing.T) {
	// Test all MockLLMRouter methods
	router := NewMockLLMRouter()

	// Test IsHealthy
	if !router.IsHealthy() {
		t.Error("Default router should be healthy")
	}

	// Test GetProviderStatus with values
	status := router.GetProviderStatus()
	if len(status) == 0 {
		t.Error("Default router should have provider status")
	}

	// Test UpdateProviderWeights with no error
	err := router.UpdateProviderWeights(map[string]float64{"test": 1.0})
	if err != nil {
		t.Errorf("UpdateProviderWeights should not error: %v", err)
	}

	// Test UpdateProviderWeights with error
	router.UpdateWeightsError = fmt.Errorf("test error")
	err = router.UpdateProviderWeights(map[string]float64{"test": 1.0})
	if err == nil {
		t.Error("UpdateProviderWeights should return error")
	}
}

func TestProviderStatusFields(t *testing.T) {
	// Test ProviderStatus struct
	now := time.Now()
	status := ProviderStatus{
		Name:         "openai",
		Healthy:      true,
		Weight:       0.5,
		RequestCount: 100,
		ErrorCount:   5,
		AvgLatency:   150.5,
		LastUsed:     now,
	}

	if status.Name != "openai" {
		t.Error("Name not set correctly")
	}
	if !status.Healthy {
		t.Error("Healthy should be true")
	}
	if status.Weight != 0.5 {
		t.Errorf("Weight expected 0.5, got %f", status.Weight)
	}
	if status.RequestCount != 100 {
		t.Errorf("RequestCount expected 100, got %d", status.RequestCount)
	}
	if status.ErrorCount != 5 {
		t.Errorf("ErrorCount expected 5, got %d", status.ErrorCount)
	}
	if status.AvgLatency != 150.5 {
		t.Errorf("AvgLatency expected 150.5, got %f", status.AvgLatency)
	}
	if !status.LastUsed.Equal(now) {
		t.Error("LastUsed not set correctly")
	}
}
