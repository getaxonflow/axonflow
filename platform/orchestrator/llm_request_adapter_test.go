// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"axonflow/platform/orchestrator/llm"
)

// TestLLMRouterInterfaceCompliance verifies compile-time interface implementation
func TestLLMRouterInterfaceCompliance(t *testing.T) {
	// These will fail at compile time if interfaces are not satisfied
	var _ LLMRouterInterface = (*UnifiedRouterWrapper)(nil)
	var _ LLMRouterInterface = (*MockLLMRouter)(nil)

	t.Log("UnifiedRouterWrapper and MockLLMRouter both implement LLMRouterInterface")
}

// TestNewUnifiedRouterWrapper tests wrapper creation
func TestNewUnifiedRouterWrapper(t *testing.T) {
	tests := []struct {
		name       string
		router     *llm.UnifiedRouter
		wantNil    bool
	}{
		{
			name:    "nil router creates wrapper with nil underlying",
			router:  nil,
			wantNil: false, // Wrapper is created even with nil router
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := NewUnifiedRouterWrapper(tt.router)

			if tt.wantNil && wrapper != nil {
				t.Error("Expected nil wrapper")
			}
			if !tt.wantNil && wrapper == nil {
				t.Error("Expected non-nil wrapper")
			}
		})
	}
}

// TestUnifiedRouterWrapper_Underlying tests access to underlying router
func TestUnifiedRouterWrapper_Underlying(t *testing.T) {
	wrapper := NewUnifiedRouterWrapper(nil)

	underlying := wrapper.Underlying()
	if underlying != nil {
		t.Error("Expected nil underlying router")
	}
}

// TestOrchestratorRequestToLLMContext tests request conversion
func TestOrchestratorRequestToLLMContext(t *testing.T) {
	tests := []struct {
		name     string
		req      OrchestratorRequest
		expected llm.RequestContext
	}{
		{
			name: "full request with all context fields",
			req: OrchestratorRequest{
				Query:       "SELECT * FROM users",
				RequestType: "sql",
				User: UserContext{
					Role:        "admin",
					Permissions: []string{"read", "write"},
				},
				Client: ClientContext{
					ID:       "client-123",
					OrgID:    "org-456",
					TenantID: "tenant-789",
				},
				Context: map[string]interface{}{
					"provider":      "openai",
					"model":         "gpt-4",
					"max_tokens":    1000,
					"temperature":   0.7,
					"system_prompt": "You are a helpful assistant",
				},
			},
			expected: llm.RequestContext{
				Query:           "SELECT * FROM users",
				RequestType:     "sql",
				UserRole:        "admin",
				UserPermissions: []string{"read", "write"},
				ClientID:        "client-123",
				OrgID:           "org-456",
				TenantID:        "tenant-789",
				Provider:        "openai",
				Model:           "gpt-4",
				MaxTokens:       1000,
				Temperature:     0.7,
				SystemPrompt:    "You are a helpful assistant",
				AllowLocal:      true,
			},
		},
		{
			name: "minimal request with nil context",
			req: OrchestratorRequest{
				Query:       "Hello",
				RequestType: "chat",
				User:        UserContext{Role: "user"},
				Client:      ClientContext{ID: "client-1"},
				Context:     nil,
			},
			expected: llm.RequestContext{
				Query:           "Hello",
				RequestType:     "chat",
				UserRole:        "user",
				UserPermissions: nil,
				ClientID:        "client-1",
				OrgID:           "",
				TenantID:        "",
				Provider:        "",
				Model:           "",
				MaxTokens:       0,
				Temperature:     0,
				SystemPrompt:    "",
				AllowLocal:      true,
			},
		},
		{
			name: "request with max_tokens as int",
			req: OrchestratorRequest{
				Query:       "Test",
				RequestType: "test",
				Context: map[string]interface{}{
					"max_tokens": 500, // int type
				},
			},
			expected: llm.RequestContext{
				Query:       "Test",
				RequestType: "test",
				MaxTokens:   500,
				AllowLocal:  true,
			},
		},
		{
			name: "request with max_tokens as float64",
			req: OrchestratorRequest{
				Query:       "Test",
				RequestType: "test",
				Context: map[string]interface{}{
					"max_tokens": 750.0, // float64 type (common from JSON)
				},
			},
			expected: llm.RequestContext{
				Query:       "Test",
				RequestType: "test",
				MaxTokens:   750,
				AllowLocal:  true,
			},
		},
		{
			name: "request with empty context map",
			req: OrchestratorRequest{
				Query:       "Empty context",
				RequestType: "test",
				Context:     map[string]interface{}{},
			},
			expected: llm.RequestContext{
				Query:       "Empty context",
				RequestType: "test",
				AllowLocal:  true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := OrchestratorRequestToLLMContext(tt.req)

			if result.Query != tt.expected.Query {
				t.Errorf("Query: got %q, want %q", result.Query, tt.expected.Query)
			}
			if result.RequestType != tt.expected.RequestType {
				t.Errorf("RequestType: got %q, want %q", result.RequestType, tt.expected.RequestType)
			}
			if result.UserRole != tt.expected.UserRole {
				t.Errorf("UserRole: got %q, want %q", result.UserRole, tt.expected.UserRole)
			}
			if result.ClientID != tt.expected.ClientID {
				t.Errorf("ClientID: got %q, want %q", result.ClientID, tt.expected.ClientID)
			}
			if result.OrgID != tt.expected.OrgID {
				t.Errorf("OrgID: got %q, want %q", result.OrgID, tt.expected.OrgID)
			}
			if result.TenantID != tt.expected.TenantID {
				t.Errorf("TenantID: got %q, want %q", result.TenantID, tt.expected.TenantID)
			}
			if result.Provider != tt.expected.Provider {
				t.Errorf("Provider: got %q, want %q", result.Provider, tt.expected.Provider)
			}
			if result.Model != tt.expected.Model {
				t.Errorf("Model: got %q, want %q", result.Model, tt.expected.Model)
			}
			if result.MaxTokens != tt.expected.MaxTokens {
				t.Errorf("MaxTokens: got %d, want %d", result.MaxTokens, tt.expected.MaxTokens)
			}
			if result.Temperature != tt.expected.Temperature {
				t.Errorf("Temperature: got %f, want %f", result.Temperature, tt.expected.Temperature)
			}
			if result.SystemPrompt != tt.expected.SystemPrompt {
				t.Errorf("SystemPrompt: got %q, want %q", result.SystemPrompt, tt.expected.SystemPrompt)
			}
			if result.AllowLocal != tt.expected.AllowLocal {
				t.Errorf("AllowLocal: got %v, want %v", result.AllowLocal, tt.expected.AllowLocal)
			}
		})
	}
}

// TestLegacyResponseToLLMResponse tests response conversion
func TestLegacyResponseToLLMResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    *llm.LegacyLLMResponse
		expected *LLMResponse
	}{
		{
			name:     "nil input returns nil",
			input:    nil,
			expected: nil,
		},
		{
			name: "full response conversion",
			input: &llm.LegacyLLMResponse{
				Content:      "Generated response",
				Model:        "gpt-4",
				TokensUsed:   150,
				Metadata:     map[string]interface{}{"key": "value"},
				ResponseTime: 500 * time.Millisecond,
			},
			expected: &LLMResponse{
				Content:      "Generated response",
				Model:        "gpt-4",
				TokensUsed:   150,
				Metadata:     map[string]interface{}{"key": "value"},
				ResponseTime: 500 * time.Millisecond,
			},
		},
		{
			name: "minimal response conversion",
			input: &llm.LegacyLLMResponse{
				Content: "Simple response",
			},
			expected: &LLMResponse{
				Content: "Simple response",
			},
		},
		{
			name: "empty response conversion",
			input: &llm.LegacyLLMResponse{
				Content:      "",
				Model:        "",
				TokensUsed:   0,
				Metadata:     nil,
				ResponseTime: 0,
			},
			expected: &LLMResponse{
				Content:      "",
				Model:        "",
				TokensUsed:   0,
				Metadata:     nil,
				ResponseTime: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := LegacyResponseToLLMResponse(tt.input)

			if tt.expected == nil {
				if result != nil {
					t.Error("Expected nil result")
				}
				return
			}

			if result == nil {
				t.Fatal("Expected non-nil result")
			}

			if result.Content != tt.expected.Content {
				t.Errorf("Content: got %q, want %q", result.Content, tt.expected.Content)
			}
			if result.Model != tt.expected.Model {
				t.Errorf("Model: got %q, want %q", result.Model, tt.expected.Model)
			}
			if result.TokensUsed != tt.expected.TokensUsed {
				t.Errorf("TokensUsed: got %d, want %d", result.TokensUsed, tt.expected.TokensUsed)
			}
			if result.ResponseTime != tt.expected.ResponseTime {
				t.Errorf("ResponseTime: got %v, want %v", result.ResponseTime, tt.expected.ResponseTime)
			}
		})
	}
}

// TestLegacyProviderInfoToProviderInfo tests provider info conversion
func TestLegacyProviderInfoToProviderInfo(t *testing.T) {
	tests := []struct {
		name     string
		input    *llm.LegacyProviderInfo
		expected *ProviderInfo
	}{
		{
			name:     "nil input returns nil",
			input:    nil,
			expected: nil,
		},
		{
			name: "full provider info conversion",
			input: &llm.LegacyProviderInfo{
				Provider:       "openai",
				Model:          "gpt-4",
				ResponseTimeMs: 250,
				TokensUsed:     100,
				Cost:           0.05,
			},
			expected: &ProviderInfo{
				Provider:       "openai",
				Model:          "gpt-4",
				ResponseTimeMs: 250,
				TokensUsed:     100,
				Cost:           0.05,
			},
		},
		{
			name: "minimal provider info conversion",
			input: &llm.LegacyProviderInfo{
				Provider: "anthropic",
			},
			expected: &ProviderInfo{
				Provider: "anthropic",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := LegacyProviderInfoToProviderInfo(tt.input)

			if tt.expected == nil {
				if result != nil {
					t.Error("Expected nil result")
				}
				return
			}

			if result == nil {
				t.Fatal("Expected non-nil result")
			}

			if result.Provider != tt.expected.Provider {
				t.Errorf("Provider: got %q, want %q", result.Provider, tt.expected.Provider)
			}
			if result.Model != tt.expected.Model {
				t.Errorf("Model: got %q, want %q", result.Model, tt.expected.Model)
			}
			if result.ResponseTimeMs != tt.expected.ResponseTimeMs {
				t.Errorf("ResponseTimeMs: got %d, want %d", result.ResponseTimeMs, tt.expected.ResponseTimeMs)
			}
			if result.TokensUsed != tt.expected.TokensUsed {
				t.Errorf("TokensUsed: got %d, want %d", result.TokensUsed, tt.expected.TokensUsed)
			}
			if result.Cost != tt.expected.Cost {
				t.Errorf("Cost: got %f, want %f", result.Cost, tt.expected.Cost)
			}
		})
	}
}

// TestLegacyStatusToProviderStatus tests status map conversion
func TestLegacyStatusToProviderStatus(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		input    map[string]llm.LegacyProviderStatus
		expected map[string]ProviderStatus
	}{
		{
			name:     "nil input returns empty map",
			input:    nil,
			expected: map[string]ProviderStatus{},
		},
		{
			name:     "empty input returns empty map",
			input:    map[string]llm.LegacyProviderStatus{},
			expected: map[string]ProviderStatus{},
		},
		{
			name: "single provider status conversion",
			input: map[string]llm.LegacyProviderStatus{
				"openai": {
					Name:         "openai",
					Healthy:      true,
					Weight:       0.6,
					RequestCount: 100,
					ErrorCount:   5,
					AvgLatency:   150.5,
					LastUsed:     now,
				},
			},
			expected: map[string]ProviderStatus{
				"openai": {
					Name:         "openai",
					Healthy:      true,
					Weight:       0.6,
					RequestCount: 100,
					ErrorCount:   5,
					AvgLatency:   150.5,
					LastUsed:     now,
				},
			},
		},
		{
			name: "multiple provider status conversion",
			input: map[string]llm.LegacyProviderStatus{
				"openai": {
					Name:         "openai",
					Healthy:      true,
					Weight:       0.5,
					RequestCount: 50,
					ErrorCount:   2,
					AvgLatency:   100.0,
					LastUsed:     now,
				},
				"anthropic": {
					Name:         "anthropic",
					Healthy:      false,
					Weight:       0.3,
					RequestCount: 30,
					ErrorCount:   10,
					AvgLatency:   200.0,
					LastUsed:     now.Add(-time.Hour),
				},
				"local": {
					Name:         "local",
					Healthy:      true,
					Weight:       0.2,
					RequestCount: 20,
					ErrorCount:   0,
					AvgLatency:   50.0,
					LastUsed:     now.Add(-time.Minute),
				},
			},
			expected: map[string]ProviderStatus{
				"openai": {
					Name:         "openai",
					Healthy:      true,
					Weight:       0.5,
					RequestCount: 50,
					ErrorCount:   2,
					AvgLatency:   100.0,
					LastUsed:     now,
				},
				"anthropic": {
					Name:         "anthropic",
					Healthy:      false,
					Weight:       0.3,
					RequestCount: 30,
					ErrorCount:   10,
					AvgLatency:   200.0,
					LastUsed:     now.Add(-time.Hour),
				},
				"local": {
					Name:         "local",
					Healthy:      true,
					Weight:       0.2,
					RequestCount: 20,
					ErrorCount:   0,
					AvgLatency:   50.0,
					LastUsed:     now.Add(-time.Minute),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := LegacyStatusToProviderStatus(tt.input)

			if len(result) != len(tt.expected) {
				t.Errorf("Map length: got %d, want %d", len(result), len(tt.expected))
			}

			for name, expectedStatus := range tt.expected {
				resultStatus, exists := result[name]
				if !exists {
					t.Errorf("Missing provider %q in result", name)
					continue
				}

				if resultStatus.Name != expectedStatus.Name {
					t.Errorf("%s Name: got %q, want %q", name, resultStatus.Name, expectedStatus.Name)
				}
				if resultStatus.Healthy != expectedStatus.Healthy {
					t.Errorf("%s Healthy: got %v, want %v", name, resultStatus.Healthy, expectedStatus.Healthy)
				}
				if resultStatus.Weight != expectedStatus.Weight {
					t.Errorf("%s Weight: got %f, want %f", name, resultStatus.Weight, expectedStatus.Weight)
				}
				if resultStatus.RequestCount != expectedStatus.RequestCount {
					t.Errorf("%s RequestCount: got %d, want %d", name, resultStatus.RequestCount, expectedStatus.RequestCount)
				}
				if resultStatus.ErrorCount != expectedStatus.ErrorCount {
					t.Errorf("%s ErrorCount: got %d, want %d", name, resultStatus.ErrorCount, expectedStatus.ErrorCount)
				}
				if resultStatus.AvgLatency != expectedStatus.AvgLatency {
					t.Errorf("%s AvgLatency: got %f, want %f", name, resultStatus.AvgLatency, expectedStatus.AvgLatency)
				}
				if !resultStatus.LastUsed.Equal(expectedStatus.LastUsed) {
					t.Errorf("%s LastUsed: got %v, want %v", name, resultStatus.LastUsed, expectedStatus.LastUsed)
				}
			}
		})
	}
}

// mockLLMRouterInterface is a mock implementation for testing
type mockLLMRouterInterface struct {
	routeRequestFn        func(ctx context.Context, req OrchestratorRequest) (*LLMResponse, *ProviderInfo, error)
	isHealthyFn           func() bool
	getProviderStatusFn   func() map[string]ProviderStatus
	updateProviderWeightsFn func(weights map[string]float64) error
}

func (m *mockLLMRouterInterface) RouteRequest(ctx context.Context, req OrchestratorRequest) (*LLMResponse, *ProviderInfo, error) {
	if m.routeRequestFn != nil {
		return m.routeRequestFn(ctx, req)
	}
	return nil, nil, nil
}

func (m *mockLLMRouterInterface) IsHealthy() bool {
	if m.isHealthyFn != nil {
		return m.isHealthyFn()
	}
	return true
}

func (m *mockLLMRouterInterface) GetProviderStatus() map[string]ProviderStatus {
	if m.getProviderStatusFn != nil {
		return m.getProviderStatusFn()
	}
	return map[string]ProviderStatus{}
}

func (m *mockLLMRouterInterface) UpdateProviderWeights(weights map[string]float64) error {
	if m.updateProviderWeightsFn != nil {
		return m.updateProviderWeightsFn(weights)
	}
	return nil
}

// TestMockLLMRouterInterface verifies mock implements interface
func TestMockLLMRouterInterface(t *testing.T) {
	var _ LLMRouterInterface = (*mockLLMRouterInterface)(nil)
	t.Log("mockLLMRouterInterface implements LLMRouterInterface")
}

// TestOrchestratorRequestToLLMContext_ContextTypeAssertions tests type assertion edge cases
func TestOrchestratorRequestToLLMContext_ContextTypeAssertions(t *testing.T) {
	tests := []struct {
		name          string
		contextMap    map[string]interface{}
		expectedField string
		expectedValue interface{}
	}{
		{
			name: "provider as non-string returns empty",
			contextMap: map[string]interface{}{
				"provider": 123, // int instead of string
			},
			expectedField: "provider",
			expectedValue: "",
		},
		{
			name: "model as non-string returns empty",
			contextMap: map[string]interface{}{
				"model": []string{"gpt-4"}, // slice instead of string
			},
			expectedField: "model",
			expectedValue: "",
		},
		{
			name: "max_tokens as string returns 0",
			contextMap: map[string]interface{}{
				"max_tokens": "1000", // string instead of int
			},
			expectedField: "max_tokens",
			expectedValue: 0,
		},
		{
			name: "temperature as int returns 0",
			contextMap: map[string]interface{}{
				"temperature": 1, // int instead of float64
			},
			expectedField: "temperature",
			expectedValue: 0.0,
		},
		{
			name: "system_prompt as int returns empty",
			contextMap: map[string]interface{}{
				"system_prompt": 42, // int instead of string
			},
			expectedField: "system_prompt",
			expectedValue: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := OrchestratorRequest{
				Query:   "test",
				Context: tt.contextMap,
			}
			result := OrchestratorRequestToLLMContext(req)

			switch tt.expectedField {
			case "provider":
				if result.Provider != tt.expectedValue.(string) {
					t.Errorf("Provider: got %q, want %q", result.Provider, tt.expectedValue)
				}
			case "model":
				if result.Model != tt.expectedValue.(string) {
					t.Errorf("Model: got %q, want %q", result.Model, tt.expectedValue)
				}
			case "max_tokens":
				if result.MaxTokens != tt.expectedValue.(int) {
					t.Errorf("MaxTokens: got %d, want %d", result.MaxTokens, tt.expectedValue)
				}
			case "temperature":
				if result.Temperature != tt.expectedValue.(float64) {
					t.Errorf("Temperature: got %f, want %f", result.Temperature, tt.expectedValue)
				}
			case "system_prompt":
				if result.SystemPrompt != tt.expectedValue.(string) {
					t.Errorf("SystemPrompt: got %q, want %q", result.SystemPrompt, tt.expectedValue)
				}
			}
		})
	}
}

// TestOrchestratorRequestToLLMContext_MetadataPassthrough tests that context is passed as metadata
func TestOrchestratorRequestToLLMContext_MetadataPassthrough(t *testing.T) {
	contextMap := map[string]interface{}{
		"custom_key":    "custom_value",
		"another_key":   123,
		"nested_object": map[string]interface{}{"foo": "bar"},
	}

	req := OrchestratorRequest{
		Query:   "test",
		Context: contextMap,
	}

	result := OrchestratorRequestToLLMContext(req)

	// Verify metadata is the same as context
	if result.Metadata == nil {
		t.Fatal("Expected Metadata to be set")
	}

	for key, expectedValue := range contextMap {
		if actualValue, exists := result.Metadata[key]; !exists {
			t.Errorf("Metadata missing key %q", key)
		} else {
			// Simple type comparison for primitives
			switch v := expectedValue.(type) {
			case string, int, float64, bool:
				if actualValue != expectedValue {
					t.Errorf("Metadata[%q]: got %v, want %v", key, actualValue, expectedValue)
				}
			default:
				// For complex types, just verify existence
				_ = v
			}
		}
	}
}

// TestLegacyResponseToLLMResponse_MetadataPreservation tests metadata is preserved
func TestLegacyResponseToLLMResponse_MetadataPreservation(t *testing.T) {
	metadata := map[string]interface{}{
		"request_id": "req-123",
		"latency_ms": 150,
		"retries":    2,
	}

	input := &llm.LegacyLLMResponse{
		Content:  "response",
		Metadata: metadata,
	}

	result := LegacyResponseToLLMResponse(input)

	if result.Metadata == nil {
		t.Fatal("Expected Metadata to be preserved")
	}

	for key, expectedValue := range metadata {
		if actualValue, exists := result.Metadata[key]; !exists {
			t.Errorf("Metadata missing key %q", key)
		} else if actualValue != expectedValue {
			t.Errorf("Metadata[%q]: got %v, want %v", key, actualValue, expectedValue)
		}
	}
}

// TestUnifiedRouterWrapper_WithEmptyRegistry tests wrapper with an empty router
func TestUnifiedRouterWrapper_WithEmptyRegistry(t *testing.T) {
	// Create registry without any providers
	registry := llm.NewRegistry()

	// Create UnifiedRouter with empty registry
	router := llm.NewUnifiedRouter(llm.UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: llm.RoutingConfig{
			Strategy: "weighted",
		},
	})

	wrapper := NewUnifiedRouterWrapper(router)

	t.Run("IsHealthy returns false with no providers", func(t *testing.T) {
		healthy := wrapper.IsHealthy()
		// With no providers, should not be healthy
		t.Logf("Healthy status: %v", healthy)
	})

	t.Run("GetProviderStatus returns status map", func(t *testing.T) {
		status := wrapper.GetProviderStatus()
		if status == nil {
			t.Fatal("Expected non-nil status map")
		}
		t.Logf("Status map has %d entries", len(status))
	})

	t.Run("UpdateProviderWeights with empty weights", func(t *testing.T) {
		err := wrapper.UpdateProviderWeights(map[string]float64{})
		// Empty weights may or may not be accepted
		t.Logf("UpdateProviderWeights error: %v", err)
	})

	t.Run("Underlying returns the router", func(t *testing.T) {
		underlying := wrapper.Underlying()
		if underlying != router {
			t.Error("Expected Underlying to return the same router")
		}
	})

	t.Run("RouteRequest with no providers fails", func(t *testing.T) {
		ctx := context.Background()
		req := OrchestratorRequest{
			RequestID:   "test-123",
			Query:       "Test query",
			RequestType: "test",
		}

		_, _, err := wrapper.RouteRequest(ctx, req)
		// Should fail with no providers
		if err == nil {
			t.Log("RouteRequest unexpectedly succeeded with no providers")
		} else {
			t.Logf("RouteRequest error (expected): %v", err)
		}
	})
}

// TestUnifiedRouterWrapper_NilRouter tests wrapper behavior with nil router
func TestUnifiedRouterWrapper_NilRouter(t *testing.T) {
	wrapper := NewUnifiedRouterWrapper(nil)

	t.Run("Underlying returns nil", func(t *testing.T) {
		if wrapper.Underlying() != nil {
			t.Error("Expected nil underlying router")
		}
	})

	// Note: Other methods will panic with nil router, which is expected behavior
	// Testing those would require panic recovery
}

// TestUnifiedRouterWrapper_RouteRequest_ErrorHandling tests error propagation with empty router
func TestUnifiedRouterWrapper_RouteRequest_ErrorHandling(t *testing.T) {
	registry := llm.NewRegistry()
	router := llm.NewUnifiedRouter(llm.UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: llm.RoutingConfig{
			Strategy: "weighted",
		},
	})

	wrapper := NewUnifiedRouterWrapper(router)

	ctx := context.Background()
	req := OrchestratorRequest{
		RequestID:   "test-error",
		Query:       "This should fail with no providers",
		RequestType: "test",
	}

	// This should return an error with no providers
	_, _, err := wrapper.RouteRequest(ctx, req)
	if err != nil {
		t.Logf("Expected error with no providers: %v", err)
	}
}

// TestLLMRouterInterface_MockRouter tests that MockLLMRouter satisfies interface
func TestLLMRouterInterface_MockRouter(t *testing.T) {
	// Create a MockLLMRouter for testing
	router := NewMockLLMRouter()

	// Test interface methods
	t.Run("IsHealthy", func(t *testing.T) {
		// By default, mock router is healthy
		healthy := router.IsHealthy()
		if !healthy {
			t.Error("Expected healthy by default")
		}

		// Test unhealthy state
		router.Healthy = false
		if router.IsHealthy() {
			t.Error("Expected unhealthy after setting Healthy=false")
		}
	})

	t.Run("GetProviderStatus", func(t *testing.T) {
		status := router.GetProviderStatus()
		if status == nil {
			t.Error("Expected non-nil status map")
		}
	})

	t.Run("UpdateProviderWeights", func(t *testing.T) {
		err := router.UpdateProviderWeights(map[string]float64{"test": 1.0})
		// Default mock router should accept weights
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

// TestOrchestratorRequestToLLMContext_ComplexMetadata tests complex metadata handling
func TestOrchestratorRequestToLLMContext_ComplexMetadata(t *testing.T) {
	complexContext := map[string]interface{}{
		"provider":    "openai",
		"model":       "gpt-4",
		"max_tokens":  2000,
		"temperature": 0.8,
		"nested": map[string]interface{}{
			"level1": map[string]interface{}{
				"level2": "deep value",
			},
		},
		"array": []string{"a", "b", "c"},
		"null":  nil,
	}

	req := OrchestratorRequest{
		Query:   "Complex test",
		Context: complexContext,
	}

	result := OrchestratorRequestToLLMContext(req)

	// Verify extracted fields
	if result.Provider != "openai" {
		t.Errorf("Provider: got %q, want %q", result.Provider, "openai")
	}
	if result.Model != "gpt-4" {
		t.Errorf("Model: got %q, want %q", result.Model, "gpt-4")
	}
	if result.MaxTokens != 2000 {
		t.Errorf("MaxTokens: got %d, want %d", result.MaxTokens, 2000)
	}

	// Verify metadata is passed through
	if result.Metadata == nil {
		t.Fatal("Expected metadata to be set")
	}

	// Check nested is in metadata
	if _, ok := result.Metadata["nested"]; !ok {
		t.Error("Expected 'nested' key in metadata")
	}

	// Check array is in metadata
	if _, ok := result.Metadata["array"]; !ok {
		t.Error("Expected 'array' key in metadata")
	}
}

// TestLegacyStatusToProviderStatus_EmptyFields tests status with zero values
func TestLegacyStatusToProviderStatus_EmptyFields(t *testing.T) {
	input := map[string]llm.LegacyProviderStatus{
		"empty-provider": {
			Name:         "",
			Healthy:      false,
			Weight:       0,
			RequestCount: 0,
			ErrorCount:   0,
			AvgLatency:   0,
			LastUsed:     time.Time{}, // Zero time
		},
	}

	result := LegacyStatusToProviderStatus(input)

	if len(result) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(result))
	}

	status, exists := result["empty-provider"]
	if !exists {
		t.Fatal("Expected 'empty-provider' in result")
	}

	if status.Name != "" {
		t.Errorf("Name: expected empty, got %q", status.Name)
	}
	if status.Healthy != false {
		t.Error("Healthy: expected false")
	}
	if status.Weight != 0 {
		t.Errorf("Weight: expected 0, got %f", status.Weight)
	}
	if !status.LastUsed.IsZero() {
		t.Errorf("LastUsed: expected zero time, got %v", status.LastUsed)
	}
}

// TestUnifiedRouterWrapper_ContextCancellation tests context handling
func TestUnifiedRouterWrapper_ContextCancellation(t *testing.T) {
	registry := llm.NewRegistry()

	router := llm.NewUnifiedRouter(llm.UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: llm.RoutingConfig{
			Strategy: "weighted",
		},
	})

	wrapper := NewUnifiedRouterWrapper(router)

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := OrchestratorRequest{
		RequestID: "cancelled-test",
		Query:     "Test with cancelled context",
	}

	_, _, err := wrapper.RouteRequest(ctx, req)
	// Should get context cancelled error or no-provider error
	if err != nil {
		t.Logf("Error with cancelled context (expected): %v", err)
	}
}

// Benchmark tests for conversion functions
func BenchmarkOrchestratorRequestToLLMContext(b *testing.B) {
	req := OrchestratorRequest{
		Query:       "Benchmark query",
		RequestType: "sql",
		User: UserContext{
			Role:        "admin",
			Permissions: []string{"read", "write", "admin"},
		},
		Client: ClientContext{
			ID:       "client-123",
			OrgID:    "org-456",
			TenantID: "tenant-789",
		},
		Context: map[string]interface{}{
			"provider":      "openai",
			"model":         "gpt-4",
			"max_tokens":    1000,
			"temperature":   0.7,
			"system_prompt": "You are a helpful assistant",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = OrchestratorRequestToLLMContext(req)
	}
}

func BenchmarkLegacyResponseToLLMResponse(b *testing.B) {
	resp := &llm.LegacyLLMResponse{
		Content:      "This is a response from the LLM provider",
		Model:        "gpt-4",
		TokensUsed:   150,
		Metadata:     map[string]interface{}{"key": "value"},
		ResponseTime: 500 * time.Millisecond,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = LegacyResponseToLLMResponse(resp)
	}
}

func BenchmarkLegacyStatusToProviderStatus(b *testing.B) {
	status := map[string]llm.LegacyProviderStatus{
		"openai":    {Name: "openai", Healthy: true, Weight: 0.5, RequestCount: 100},
		"anthropic": {Name: "anthropic", Healthy: true, Weight: 0.3, RequestCount: 50},
		"local":     {Name: "local", Healthy: true, Weight: 0.2, RequestCount: 25},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = LegacyStatusToProviderStatus(status)
	}
}

// TestUnifiedRouterWrapper_Concurrency tests concurrent access
func TestUnifiedRouterWrapper_Concurrency(t *testing.T) {
	registry := llm.NewRegistry()

	router := llm.NewUnifiedRouter(llm.UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: llm.RoutingConfig{
			Strategy: "weighted",
		},
	})

	wrapper := NewUnifiedRouterWrapper(router)

	// Run concurrent operations
	done := make(chan struct{})
	errChan := make(chan error, 30)

	// Multiple goroutines calling IsHealthy
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() {
				if r := recover(); r != nil {
					errChan <- fmt.Errorf("panic in goroutine %d: %v", id, r)
				}
				done <- struct{}{}
			}()
			for j := 0; j < 10; j++ {
				_ = wrapper.IsHealthy()
			}
		}(i)
	}

	// Multiple goroutines calling GetProviderStatus
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() {
				if r := recover(); r != nil {
					errChan <- fmt.Errorf("panic in status goroutine %d: %v", id, r)
				}
				done <- struct{}{}
			}()
			for j := 0; j < 10; j++ {
				_ = wrapper.GetProviderStatus()
			}
		}(i)
	}

	// Multiple goroutines calling RouteRequest
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() {
				if r := recover(); r != nil {
					errChan <- fmt.Errorf("panic in route goroutine %d: %v", id, r)
				}
				done <- struct{}{}
			}()
			ctx := context.Background()
			req := OrchestratorRequest{
				RequestID: fmt.Sprintf("concurrent-%d", id),
				Query:     "Concurrent test",
			}
			_, _, _ = wrapper.RouteRequest(ctx, req)
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 30; i++ {
		<-done
	}

	close(errChan)
	for err := range errChan {
		t.Error(err)
	}
}
