// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
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
	"testing"
)

// mockLegacyProvider implements LegacyProvider for testing.
type mockLegacyProvider struct {
	name         string
	healthy      bool
	capabilities []string
	queryResp    *LegacyResponse
	queryErr     error
}

func (m *mockLegacyProvider) Name() string {
	return m.name
}

func (m *mockLegacyProvider) Query(ctx context.Context, prompt string, options LegacyQueryOptions) (*LegacyResponse, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	if m.queryResp != nil {
		return m.queryResp, nil
	}
	return &LegacyResponse{
		Content:    "mock response",
		Model:      options.Model,
		TokensUsed: 100,
	}, nil
}

func (m *mockLegacyProvider) IsHealthy() bool {
	return m.healthy
}

func (m *mockLegacyProvider) GetCapabilities() []string {
	return m.capabilities
}

func (m *mockLegacyProvider) EstimateCost(tokens int) float64 {
	return float64(tokens) * 0.00002
}

func TestProviderAdapter(t *testing.T) {
	ctx := context.Background()

	t.Run("Name", func(t *testing.T) {
		provider := NewMockProvider("test-provider", ProviderTypeOpenAI)
		adapter := NewProviderAdapter(provider)

		if adapter.Name() != "test-provider" {
			t.Errorf("Name() = %q, want %q", adapter.Name(), "test-provider")
		}
	})

	t.Run("Query", func(t *testing.T) {
		provider := NewMockProvider("test-provider", ProviderTypeOpenAI)
		adapter := NewProviderAdapter(provider)

		options := LegacyQueryOptions{
			MaxTokens:   100,
			Temperature: 0.7,
			Model:       "gpt-4",
		}

		resp, err := adapter.Query(ctx, "Hello", options)
		if err != nil {
			t.Fatalf("Query error: %v", err)
		}
		if resp == nil {
			t.Fatal("response should not be nil")
		}
		if resp.Content == "" {
			t.Error("content should not be empty")
		}
	})

	t.Run("IsHealthy", func(t *testing.T) {
		provider := NewMockProvider("test-provider", ProviderTypeOpenAI)
		provider.healthStatus = HealthStatusHealthy
		adapter := NewProviderAdapter(provider)

		if !adapter.IsHealthy() {
			t.Error("IsHealthy() should return true")
		}

		provider.healthStatus = HealthStatusUnhealthy
		if adapter.IsHealthy() {
			t.Error("IsHealthy() should return false when unhealthy")
		}
	})

	t.Run("GetCapabilities", func(t *testing.T) {
		provider := NewMockProvider("test-provider", ProviderTypeOpenAI)
		provider.capabilities = []Capability{CapabilityChat, CapabilityStreaming}
		adapter := NewProviderAdapter(provider)

		caps := adapter.GetCapabilities()
		if len(caps) != 2 {
			t.Errorf("len(capabilities) = %d, want 2", len(caps))
		}
	})

	t.Run("EstimateCost", func(t *testing.T) {
		provider := NewMockProvider("test-provider", ProviderTypeOpenAI)
		provider.costEstimate = &CostEstimate{
			InputCostPer1K:  0.003,
			OutputCostPer1K: 0.015,
			TotalEstimate:   0.009,
		}
		adapter := NewProviderAdapter(provider)

		cost := adapter.EstimateCost(1000)
		if cost <= 0 {
			t.Error("cost should be positive")
		}
	})

	t.Run("Provider", func(t *testing.T) {
		provider := NewMockProvider("test-provider", ProviderTypeOpenAI)
		adapter := NewProviderAdapter(provider)

		if adapter.Provider() != provider {
			t.Error("Provider() should return the underlying provider")
		}
	})
}

func TestLegacyAdapter(t *testing.T) {
	ctx := context.Background()

	t.Run("Name", func(t *testing.T) {
		legacy := &mockLegacyProvider{name: "legacy-provider"}
		adapter := NewLegacyAdapter(legacy, ProviderTypeOpenAI)

		if adapter.Name() != "legacy-provider" {
			t.Errorf("Name() = %q, want %q", adapter.Name(), "legacy-provider")
		}
	})

	t.Run("Type", func(t *testing.T) {
		legacy := &mockLegacyProvider{name: "legacy-provider"}
		adapter := NewLegacyAdapter(legacy, ProviderTypeAnthropic)

		if adapter.Type() != ProviderTypeAnthropic {
			t.Errorf("Type() = %q, want %q", adapter.Type(), ProviderTypeAnthropic)
		}
	})

	t.Run("Complete", func(t *testing.T) {
		legacy := &mockLegacyProvider{
			name:    "legacy-provider",
			healthy: true,
			queryResp: &LegacyResponse{
				Content:    "legacy response",
				Model:      "test-model",
				TokensUsed: 150,
			},
		}
		adapter := NewLegacyAdapter(legacy, ProviderTypeOpenAI)

		req := CompletionRequest{
			Prompt:    "Hello",
			MaxTokens: 100,
			Model:     "test-model",
		}

		resp, err := adapter.Complete(ctx, req)
		if err != nil {
			t.Fatalf("Complete error: %v", err)
		}
		if resp.Content != "legacy response" {
			t.Errorf("Content = %q, want %q", resp.Content, "legacy response")
		}
		if resp.Model != "test-model" {
			t.Errorf("Model = %q, want %q", resp.Model, "test-model")
		}
		if resp.Usage.TotalTokens != 150 {
			t.Errorf("TotalTokens = %d, want 150", resp.Usage.TotalTokens)
		}
	})

	t.Run("HealthCheck", func(t *testing.T) {
		legacy := &mockLegacyProvider{name: "legacy-provider", healthy: true}
		adapter := NewLegacyAdapter(legacy, ProviderTypeOpenAI)

		result, err := adapter.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("HealthCheck error: %v", err)
		}
		if result.Status != HealthStatusHealthy {
			t.Errorf("Status = %v, want %v", result.Status, HealthStatusHealthy)
		}

		legacy.healthy = false
		result, _ = adapter.HealthCheck(ctx)
		if result.Status != HealthStatusUnhealthy {
			t.Errorf("Status = %v, want %v", result.Status, HealthStatusUnhealthy)
		}
	})

	t.Run("HealthCheck_ContextCancelled", func(t *testing.T) {
		legacy := &mockLegacyProvider{name: "legacy-provider", healthy: true}
		adapter := NewLegacyAdapter(legacy, ProviderTypeOpenAI)

		// Create a cancelled context
		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := adapter.HealthCheck(cancelledCtx)
		if err == nil {
			t.Error("HealthCheck should return error for cancelled context")
		}
		if err != context.Canceled {
			t.Errorf("error = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("Capabilities", func(t *testing.T) {
		legacy := &mockLegacyProvider{
			name:         "legacy-provider",
			capabilities: []string{"chat", "streaming", "vision"},
		}
		adapter := NewLegacyAdapter(legacy, ProviderTypeOpenAI)

		caps := adapter.Capabilities()
		if len(caps) != 3 {
			t.Errorf("len(capabilities) = %d, want 3", len(caps))
		}
	})

	t.Run("SupportsStreaming", func(t *testing.T) {
		legacy := &mockLegacyProvider{name: "legacy-provider"}
		adapter := NewLegacyAdapter(legacy, ProviderTypeOpenAI)

		// Legacy providers don't support streaming
		if adapter.SupportsStreaming() {
			t.Error("SupportsStreaming() should return false for legacy providers")
		}
	})

	t.Run("EstimateCost", func(t *testing.T) {
		legacy := &mockLegacyProvider{name: "legacy-provider"}
		adapter := NewLegacyAdapter(legacy, ProviderTypeOpenAI)

		req := CompletionRequest{
			Prompt:    "Hello world",
			MaxTokens: 100,
		}

		estimate := adapter.EstimateCost(req)
		if estimate == nil {
			t.Fatal("estimate should not be nil")
		}
		if estimate.Currency != "USD" {
			t.Errorf("Currency = %q, want %q", estimate.Currency, "USD")
		}
	})

	t.Run("EstimateCost_EmptyPrompt", func(t *testing.T) {
		// Test that empty prompt doesn't cause division by zero
		legacy := &mockLegacyProvider{name: "legacy-provider"}
		adapter := NewLegacyAdapter(legacy, ProviderTypeOpenAI)

		req := CompletionRequest{
			Prompt:    "", // Empty prompt
			MaxTokens: 0,  // Zero max tokens
		}

		// This should not panic
		estimate := adapter.EstimateCost(req)
		if estimate == nil {
			t.Fatal("estimate should not be nil")
		}
		// Should use default values
		if estimate.EstimatedInputTokens < 1 {
			t.Errorf("EstimatedInputTokens = %d, want >= 1", estimate.EstimatedInputTokens)
		}
		if estimate.EstimatedOutputTokens < 1 {
			t.Errorf("EstimatedOutputTokens = %d, want >= 1", estimate.EstimatedOutputTokens)
		}
	})
}

func TestAdapterInterfaceCompliance(t *testing.T) {
	// These are compile-time checks already, but let's verify at runtime too
	var _ LegacyProvider = (*ProviderAdapter)(nil)
	var _ Provider = (*LegacyAdapter)(nil)
}
