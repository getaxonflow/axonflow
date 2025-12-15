// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
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
	"log"
	"os"
	"testing"
	"time"
)

func setupTestRouter(t *testing.T) *Router {
	t.Helper()

	// Create registry with mock factory
	fm := NewFactoryManager()
	fm.Register(ProviderTypeOpenAI, func(config ProviderConfig) (Provider, error) {
		mock := NewMockProvider(config.Name, config.Type)
		mock.healthStatus = HealthStatusHealthy
		return mock, nil
	})
	fm.Register(ProviderTypeAnthropic, func(config ProviderConfig) (Provider, error) {
		mock := NewMockProvider(config.Name, config.Type)
		mock.healthStatus = HealthStatusHealthy
		return mock, nil
	})
	fm.Register(ProviderTypeOllama, func(config ProviderConfig) (Provider, error) {
		mock := NewMockProvider(config.Name, config.Type)
		mock.healthStatus = HealthStatusHealthy
		return mock, nil
	})

	registry := NewRegistry(WithFactoryManager(fm))
	return NewRouter(WithRouterRegistry(registry))
}

func TestNewRouter(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		router := NewRouter()
		if router == nil {
			t.Fatal("NewRouter returned nil")
		}
		if router.registry == nil {
			t.Error("registry should not be nil")
		}
		if router.loadBalancer == nil {
			t.Error("loadBalancer should not be nil")
		}
	})

	t.Run("with registry", func(t *testing.T) {
		registry := NewRegistry()
		router := NewRouter(WithRouterRegistry(registry))
		if router.registry != registry {
			t.Error("registry should be the provided one")
		}
	})

	t.Run("with default weights", func(t *testing.T) {
		weights := map[string]float64{"provider-a": 0.7, "provider-b": 0.3}
		router := NewRouter(WithDefaultWeights(weights))
		if router.defaultWeights["provider-a"] != 0.7 {
			t.Error("default weights should be set")
		}
	})
}

func TestNewRouterFromConfig(t *testing.T) {
	t.Run("with defaults", func(t *testing.T) {
		config := RouterConfig{}
		router := NewRouterFromConfig(config)
		if router == nil {
			t.Fatal("NewRouterFromConfig returned nil")
		}
		if router.registry == nil {
			t.Error("registry should not be nil")
		}
		if router.logger == nil {
			t.Error("logger should not be nil")
		}
		if router.defaultWeights == nil {
			t.Error("defaultWeights should not be nil")
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		registry := NewRegistry()
		weights := map[string]float64{"a": 0.5}
		config := RouterConfig{
			Registry:            registry,
			DefaultWeights:      weights,
			HealthCheckInterval: 1 * time.Minute,
		}
		router := NewRouterFromConfig(config)
		if router.registry != registry {
			t.Error("registry should be the provided one")
		}
		if router.defaultWeights["a"] != 0.5 {
			t.Error("default weights should be set")
		}
	})
}

func TestRouter_RouteRequest(t *testing.T) {
	ctx := context.Background()
	router := setupTestRouter(t)

	// Register some providers
	_ = router.registry.Register(ctx, &ProviderConfig{
		Name:    "openai-test",
		Type:    ProviderTypeOpenAI,
		APIKey:  "test",
		Enabled: true,
	})
	_ = router.registry.Register(ctx, &ProviderConfig{
		Name:    "anthropic-test",
		Type:    ProviderTypeAnthropic,
		APIKey:  "test",
		Enabled: true,
	})

	// Trigger lazy instantiation and health check
	_, _ = router.registry.Get(ctx, "openai-test")
	_, _ = router.registry.Get(ctx, "anthropic-test")
	router.registry.HealthCheck(ctx)

	t.Run("basic routing", func(t *testing.T) {
		req := CompletionRequest{
			Prompt:    "Hello",
			MaxTokens: 100,
		}

		resp, info, err := router.RouteRequest(ctx, req)
		if err != nil {
			t.Fatalf("RouteRequest error: %v", err)
		}
		if resp == nil {
			t.Fatal("response should not be nil")
		}
		if info == nil {
			t.Fatal("info should not be nil")
		}
		if info.ProviderName == "" {
			t.Error("provider name should be set")
		}
	})

	t.Run("with preferred provider", func(t *testing.T) {
		req := CompletionRequest{
			Prompt:    "Hello",
			MaxTokens: 100,
		}

		_, info, err := router.RouteRequest(ctx, req, WithPreferredProvider("anthropic-test"))
		if err != nil {
			t.Fatalf("RouteRequest error: %v", err)
		}
		if info.ProviderName != "anthropic-test" {
			t.Errorf("provider = %q, want %q", info.ProviderName, "anthropic-test")
		}
	})
}

func TestRouter_RouteRequest_NoProviders(t *testing.T) {
	ctx := context.Background()
	router := NewRouter()

	req := CompletionRequest{
		Prompt: "Hello",
	}

	_, _, err := router.RouteRequest(ctx, req)
	if err == nil {
		t.Fatal("expected error with no providers")
	}
}

func TestRouter_WithRouterLogger(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)
	router := NewRouter(WithRouterLogger(logger))
	if router.logger != logger {
		t.Error("logger should be the provided one")
	}
}

func TestRouter_SetDefaultWeights(t *testing.T) {
	router := NewRouter()

	weights := map[string]float64{
		"provider-a": 0.6,
		"provider-b": 0.4,
	}

	router.SetDefaultWeights(weights)

	router.mu.RLock()
	defer router.mu.RUnlock()

	if router.defaultWeights["provider-a"] != 0.6 {
		t.Errorf("weight = %f, want 0.6", router.defaultWeights["provider-a"])
	}
}

func TestRouter_GetProviderStatus(t *testing.T) {
	ctx := context.Background()
	router := setupTestRouter(t)

	// Register providers
	_ = router.registry.Register(ctx, &ProviderConfig{
		Name:     "test-provider",
		Type:     ProviderTypeOllama,
		Enabled:  true,
		Priority: 100,
	})

	// Get and check health
	_, _ = router.registry.Get(ctx, "test-provider")
	router.registry.HealthCheck(ctx)

	status := router.GetProviderStatus(ctx)
	if len(status) != 1 {
		t.Errorf("status count = %d, want 1", len(status))
	}

	ps := status["test-provider"]
	if ps == nil {
		t.Fatal("status should exist for test-provider")
	}
	if ps.Name != "test-provider" {
		t.Errorf("name = %q, want %q", ps.Name, "test-provider")
	}
	if ps.Priority != 100 {
		t.Errorf("priority = %d, want 100", ps.Priority)
	}
}

func TestRouter_Registry(t *testing.T) {
	registry := NewRegistry()
	router := NewRouter(WithRouterRegistry(registry))

	if router.Registry() != registry {
		t.Error("Registry() should return the configured registry")
	}
}

func TestRouter_Close(t *testing.T) {
	t.Run("close router without health check", func(t *testing.T) {
		router := NewRouter()
		err := router.Close()
		if err != nil {
			t.Errorf("Close error: %v", err)
		}
	})

	t.Run("close router from config cancels health check", func(t *testing.T) {
		// NewRouterFromConfig starts a health check goroutine
		config := RouterConfig{
			HealthCheckInterval: 1 * time.Hour, // Long interval so we don't wait
		}
		router := NewRouterFromConfig(config)

		// Verify cancelHealthCheck is set
		if router.cancelHealthCheck == nil {
			t.Fatal("cancelHealthCheck should be set for router from config")
		}

		// Close should cancel the health check goroutine
		err := router.Close()
		if err != nil {
			t.Errorf("Close error: %v", err)
		}
	})
}

func TestRouterLoadBalancer(t *testing.T) {
	lb := newRouterLoadBalancer()

	providers := []string{"a", "b", "c"}
	weights := map[string]float64{
		"a": 0.5,
		"b": 0.3,
		"c": 0.2,
	}

	// Run multiple selections
	counts := make(map[string]int)
	for i := 0; i < 1000; i++ {
		selected := lb.selectProvider(providers, weights)
		counts[selected]++
	}

	// Verify all providers were selected at least once
	for _, p := range providers {
		if counts[p] == 0 {
			t.Errorf("provider %q was never selected", p)
		}
	}

	// Verify rough distribution (with some tolerance)
	// Provider "a" with 50% weight should be selected more than "c" with 20%
	if counts["a"] < counts["c"] {
		t.Logf("Warning: distribution may be off - a=%d, c=%d", counts["a"], counts["c"])
	}
}

func TestRouterMetricsTracker(t *testing.T) {
	tracker := newRouterMetricsTracker()

	t.Run("record success", func(t *testing.T) {
		tracker.recordSuccess("provider-a", 100*time.Millisecond)
		tracker.recordSuccess("provider-a", 200*time.Millisecond)

		metrics := tracker.getMetrics("provider-a")
		if metrics.RequestCount != 2 {
			t.Errorf("RequestCount = %d, want 2", metrics.RequestCount)
		}
		// Average should be 150ms
		if metrics.AvgResponseTime < 100 || metrics.AvgResponseTime > 200 {
			t.Errorf("AvgResponseTime = %f, want ~150", metrics.AvgResponseTime)
		}
	})

	t.Run("record error", func(t *testing.T) {
		tracker.recordError("provider-b")
		tracker.recordError("provider-b")
		tracker.recordError("provider-b")

		metrics := tracker.getMetrics("provider-b")
		if metrics.ErrorCount != 3 {
			t.Errorf("ErrorCount = %d, want 3", metrics.ErrorCount)
		}
	})

	t.Run("nonexistent provider", func(t *testing.T) {
		metrics := tracker.getMetrics("nonexistent")
		if metrics.RequestCount != 0 {
			t.Error("expected zero metrics for nonexistent provider")
		}
	})
}

func TestRouteOptions(t *testing.T) {
	t.Run("WithPreferredProvider", func(t *testing.T) {
		opts := &routeOptions{}
		WithPreferredProvider("test-provider")(opts)
		if opts.preferredProvider != "test-provider" {
			t.Error("preferredProvider should be set")
		}
	})

	t.Run("WithRouteWeights", func(t *testing.T) {
		opts := &routeOptions{}
		weights := map[string]float64{"a": 0.5}
		WithRouteWeights(weights)(opts)
		if opts.weights["a"] != 0.5 {
			t.Error("weights should be set")
		}
	})

	t.Run("WithDisableFailover", func(t *testing.T) {
		opts := &routeOptions{}
		WithDisableFailover()(opts)
		if !opts.disableFailover {
			t.Error("disableFailover should be true")
		}
	})
}
