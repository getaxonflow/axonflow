// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package llm

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewUnifiedRouter(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()

	// Register a mock provider
	err := registry.Register(ctx, &ProviderConfig{
		Name:    "test-provider",
		Type:    ProviderTypeOllama,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("failed to register config: %v", err)
	}

	config := UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
			ProviderWeights: map[string]float64{
				"test-provider": 1.0,
			},
		},
		HealthCheckInterval: 1 * time.Hour, // Long interval for tests
	}

	router := NewUnifiedRouter(config)
	defer router.Close()

	if router == nil {
		t.Fatal("expected non-nil router")
	}

	if router.GetRoutingStrategy() != RoutingStrategyWeighted {
		t.Errorf("expected weighted strategy, got %s", router.GetRoutingStrategy())
	}
}

func TestNewUnifiedRouterFromEnv(t *testing.T) {
	registry := NewRegistry()
	router := NewUnifiedRouterFromEnv(registry)
	defer router.Close()

	if router == nil {
		t.Fatal("expected non-nil router")
	}

	// Default strategy should be weighted
	if router.GetRoutingStrategy() != RoutingStrategyWeighted {
		t.Errorf("expected weighted strategy, got %s", router.GetRoutingStrategy())
	}
}

func TestUnifiedRouter_RouteRequest(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()

	// Register a mock provider
	registry.Register(ctx, &ProviderConfig{
		Name:    "test-openai",
		Type:    ProviderTypeOpenAI,
		APIKey:  "test-key",
		Enabled: true,
	})

	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
		},
	})
	defer router.Close()

	// This will fail because the mock provider doesn't have real API access
	// but we can verify the request flow works
	_, _, err := router.RouteRequest(context.Background(), RequestContext{
		Query:       "Hello",
		RequestType: "test",
		UserRole:    "admin",
	})

	// Expect an error because no real provider is available
	if err == nil {
		t.Log("Warning: RouteRequest succeeded unexpectedly (mock provider may be responding)")
	}
}

func TestUnifiedRouter_GetProviderStatus(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()

	registry.Register(ctx, &ProviderConfig{
		Name:    "test-provider",
		Type:    ProviderTypeOllama,
		Enabled: true,
	})

	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
		},
	})
	defer router.Close()

	status := router.GetProviderStatus(ctx)

	if len(status) == 0 {
		t.Error("expected at least one provider in status")
	}

	if _, ok := status["test-provider"]; !ok {
		t.Error("expected test-provider in status")
	}
}

func TestUnifiedRouter_GetLegacyProviderStatus(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()

	registry.Register(ctx, &ProviderConfig{
		Name:    "test-provider",
		Type:    ProviderTypeOllama,
		Enabled: true,
	})

	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
		},
	})
	defer router.Close()

	status := router.GetLegacyProviderStatus()

	if len(status) == 0 {
		t.Error("expected at least one provider in status")
	}

	if ps, ok := status["test-provider"]; ok {
		if ps.Name != "test-provider" {
			t.Errorf("expected name test-provider, got %s", ps.Name)
		}
	} else {
		t.Error("expected test-provider in status")
	}
}

func TestUnifiedRouter_UpdateProviderWeights(t *testing.T) {
	registry := NewRegistry()
	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
		},
	})
	defer router.Close()

	// Test empty weights error
	err := router.UpdateProviderWeights(map[string]float64{})
	if err == nil {
		t.Error("expected error for empty weights")
	}

	// Test valid weights
	err = router.UpdateProviderWeights(map[string]float64{
		"openai":    0.6,
		"anthropic": 0.4,
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUnifiedRouter_RoutingStrategy(t *testing.T) {
	registry := NewRegistry()
	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
		},
	})
	defer router.Close()

	// Test getter
	if router.GetRoutingStrategy() != RoutingStrategyWeighted {
		t.Errorf("expected weighted, got %s", router.GetRoutingStrategy())
	}

	// Test setter
	router.SetRoutingStrategy(RoutingStrategyRoundRobin)
	if router.GetRoutingStrategy() != RoutingStrategyRoundRobin {
		t.Errorf("expected round_robin, got %s", router.GetRoutingStrategy())
	}
}

func TestUnifiedRouter_DefaultProvider(t *testing.T) {
	registry := NewRegistry()
	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy:        RoutingStrategyFailover,
			DefaultProvider: "bedrock",
		},
	})
	defer router.Close()

	// Test getter
	if router.GetDefaultProvider() != "bedrock" {
		t.Errorf("expected bedrock, got %s", router.GetDefaultProvider())
	}

	// Test setter
	router.SetDefaultProvider("anthropic")
	if router.GetDefaultProvider() != "anthropic" {
		t.Errorf("expected anthropic, got %s", router.GetDefaultProvider())
	}
}

func TestUnifiedRouter_IsHealthy(t *testing.T) {
	registry := NewRegistry()
	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
		},
	})
	defer router.Close()

	// No providers registered, should be unhealthy
	if router.IsHealthy() {
		t.Error("expected unhealthy with no providers")
	}
}

func TestUnifiedRouter_ProviderManagement(t *testing.T) {
	registry := NewRegistry()
	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
		},
	})
	defer router.Close()

	// Register a provider
	err := router.RegisterProvider(ProviderConfig{
		Name:    "new-provider",
		Type:    ProviderTypeOllama,
		Enabled: true,
	})
	if err != nil {
		t.Errorf("failed to register provider: %v", err)
	}

	// List providers
	providers := router.ListProviders()
	if len(providers) != 1 {
		t.Errorf("expected 1 provider, got %d", len(providers))
	}

	// List enabled
	enabled := router.ListEnabledProviders()
	if len(enabled) != 1 {
		t.Errorf("expected 1 enabled provider, got %d", len(enabled))
	}

	// Disable provider
	err = router.DisableProvider("new-provider")
	if err != nil {
		t.Errorf("failed to disable provider: %v", err)
	}

	enabled = router.ListEnabledProviders()
	if len(enabled) != 0 {
		t.Errorf("expected 0 enabled providers, got %d", len(enabled))
	}

	// Enable provider
	err = router.EnableProvider("new-provider")
	if err != nil {
		t.Errorf("failed to enable provider: %v", err)
	}

	enabled = router.ListEnabledProviders()
	if len(enabled) != 1 {
		t.Errorf("expected 1 enabled provider, got %d", len(enabled))
	}
}

func TestUnifiedRouter_Registry(t *testing.T) {
	registry := NewRegistry()
	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
		},
	})
	defer router.Close()

	if router.Registry() != registry {
		t.Error("expected same registry instance")
	}
}

func TestUnifiedRouter_Router(t *testing.T) {
	registry := NewRegistry()
	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
		},
	})
	defer router.Close()

	if router.Router() == nil {
		t.Error("expected non-nil underlying router")
	}
}

func TestUnifiedRouter_RouteCompletionRequest(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()

	registry.Register(ctx, &ProviderConfig{
		Name:    "test-openai",
		Type:    ProviderTypeOpenAI,
		APIKey:  "test-key",
		Enabled: true,
	})

	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
		},
	})
	defer router.Close()

	// Test RouteCompletionRequest - this will fail with real API but tests the code path
	req := CompletionRequest{
		Prompt: "Hello",
	}
	_, _, err := router.RouteCompletionRequest(ctx, req)
	// Expected to fail since we're not hitting real API
	if err == nil {
		t.Log("Warning: RouteCompletionRequest succeeded unexpectedly")
	}
}

func TestUnifiedRouter_GetProvider(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()

	// Register a pre-instantiated mock provider to avoid factory issues
	testProvider := NewMockProvider("test-provider", ProviderTypeOpenAI)
	registry.RegisterProvider("test-provider", testProvider, &ProviderConfig{
		Name:    "test-provider",
		Type:    ProviderTypeOpenAI,
		Enabled: true,
	})

	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
		},
	})
	defer router.Close()

	// Get existing provider
	provider, err := router.GetProvider(ctx, "test-provider")
	if err != nil {
		t.Fatalf("GetProvider error: %v", err)
	}
	if provider == nil {
		t.Error("expected non-nil provider")
	}

	// Get non-existent provider
	_, err = router.GetProvider(ctx, "non-existent")
	if err == nil {
		t.Error("expected error for non-existent provider")
	}
}

func TestUnifiedRouter_ListHealthyProviders(t *testing.T) {
	registry := NewRegistry()

	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
		},
	})
	defer router.Close()

	// No providers registered, should be empty
	healthy := router.ListHealthyProviders()
	if len(healthy) != 0 {
		t.Errorf("expected 0 healthy providers, got %d", len(healthy))
	}
}

func TestUnifiedRouter_StrictProviderSemantics(t *testing.T) {
	ctx := context.Background()
	registry := NewRegistry()

	failing := NewMockProvider("preferred-provider", ProviderTypeOpenAI)
	failing.completeErr = NewProviderError("preferred-provider", ErrCodeRateLimit, "simulated failure")
	fallback := NewMockProvider("fallback-provider", ProviderTypeAnthropic)

	if err := registry.RegisterProvider("preferred-provider", failing, &ProviderConfig{
		Name:    "preferred-provider",
		Type:    ProviderTypeOpenAI,
		Enabled: true,
	}); err != nil {
		t.Fatalf("failed to register preferred provider: %v", err)
	}
	if err := registry.RegisterProvider("fallback-provider", fallback, &ProviderConfig{
		Name:    "fallback-provider",
		Type:    ProviderTypeAnthropic,
		Enabled: true,
	}); err != nil {
		t.Fatalf("failed to register fallback provider: %v", err)
	}

	// Seed healthy provider cache used by fallback selection.
	registry.HealthCheck(ctx, GlobalTenant)

	router := NewUnifiedRouter(UnifiedRouterConfig{
		Registry: registry,
		RoutingConfig: RoutingConfig{
			Strategy: RoutingStrategyWeighted,
		},
		HealthCheckInterval: 1 * time.Hour,
	})
	defer router.Close()

	t.Run("provider preference allows fallback by default", func(t *testing.T) {
		resp, info, err := router.RouteRequest(ctx, RequestContext{
			Query:       "hello",
			RequestType: "chat",
			Provider:    "preferred-provider",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || info == nil {
			t.Fatalf("expected response and provider info")
		}
		if info.Provider != "fallback-provider" {
			t.Fatalf("expected fallback-provider, got %q", info.Provider)
		}
	})

	t.Run("strict provider disables fallback", func(t *testing.T) {
		_, _, err := router.RouteRequest(ctx, RequestContext{
			Query:          "hello",
			RequestType:    "chat",
			Provider:       "preferred-provider",
			StrictProvider: true,
		})
		if err == nil {
			t.Fatalf("expected strict provider error")
		}
		if !strings.Contains(err.Error(), "provider failed") {
			t.Fatalf("expected provider failure error, got: %v", err)
		}
	})

	t.Run("policy allowed providers remain strict", func(t *testing.T) {
		_, _, err := router.RouteRequest(ctx, RequestContext{
			Query:                  "hello",
			RequestType:            "chat",
			PolicyAllowedProviders: []string{"preferred-provider"},
		})
		if err == nil {
			t.Fatalf("expected policy strict error")
		}
		if !strings.Contains(err.Error(), "compliant") && !strings.Contains(err.Error(), "allowed") {
			t.Fatalf("expected compliant/allowed error, got: %v", err)
		}
	})
}
