// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"strings"
	"time"
)

// stringContains is a helper function for test cases that checks if s contains substr.
// This replaces the legacy helper from llm_router.go.
func stringContains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// MockLLMRouter implements LLMRouterInterface for testing.
// It provides configurable behavior for all interface methods.
type MockLLMRouter struct {
	// Health configuration
	Healthy bool

	// Provider status configuration
	ProviderStatusResult map[string]ProviderStatus

	// Route request configuration
	RouteResponse *LLMResponse
	RouteInfo     *ProviderInfo
	RouteError    error

	// Weight update configuration
	UpdateWeightsError error

	// Tracking
	RouteRequestCalls int
}

// NewMockLLMRouter creates a new mock router with sensible defaults.
func NewMockLLMRouter() *MockLLMRouter {
	return &MockLLMRouter{
		Healthy: true,
		ProviderStatusResult: map[string]ProviderStatus{
			"mock": {
				Name:         "mock",
				Healthy:      true,
				Weight:       1.0,
				RequestCount: 0,
				ErrorCount:   0,
				AvgLatency:   50,
				LastUsed:     time.Now(),
			},
		},
		RouteResponse: &LLMResponse{
			Content:      "Mock response",
			Model:        "mock-model",
			TokensUsed:   100,
			ResponseTime: 50 * time.Millisecond,
		},
		RouteInfo: &ProviderInfo{
			Provider:       "mock",
			Model:          "mock-model",
			ResponseTimeMs: 50,
			TokensUsed:     100,
		},
	}
}

// RouteRequest implements LLMRouterInterface.
func (m *MockLLMRouter) RouteRequest(ctx context.Context, req OrchestratorRequest) (*LLMResponse, *ProviderInfo, error) {
	m.RouteRequestCalls++
	if m.RouteError != nil {
		return nil, nil, m.RouteError
	}
	return m.RouteResponse, m.RouteInfo, nil
}

// IsHealthy implements LLMRouterInterface.
func (m *MockLLMRouter) IsHealthy() bool {
	return m.Healthy
}

// GetProviderStatus implements LLMRouterInterface.
func (m *MockLLMRouter) GetProviderStatus() map[string]ProviderStatus {
	if m.ProviderStatusResult == nil {
		return make(map[string]ProviderStatus)
	}
	return m.ProviderStatusResult
}

// UpdateProviderWeights implements LLMRouterInterface.
func (m *MockLLMRouter) UpdateProviderWeights(weights map[string]float64) error {
	return m.UpdateWeightsError
}

// Compile-time check that MockLLMRouter implements LLMRouterInterface.
var _ LLMRouterInterface = (*MockLLMRouter)(nil)
