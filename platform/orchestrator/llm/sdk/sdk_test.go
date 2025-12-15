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

package sdk

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"axonflow/platform/orchestrator/llm"
)

func TestProviderBuilder(t *testing.T) {
	t.Run("basic build", func(t *testing.T) {
		provider := NewProviderBuilder("test-provider", llm.ProviderTypeCustom).Build()

		if provider.Name() != "test-provider" {
			t.Errorf("Name() = %q, want %q", provider.Name(), "test-provider")
		}
		if provider.Type() != llm.ProviderTypeCustom {
			t.Errorf("Type() = %q, want %q", provider.Type(), llm.ProviderTypeCustom)
		}
	})

	t.Run("with model", func(t *testing.T) {
		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).
			WithModel("gpt-4").
			Build()

		if provider.Model() != "gpt-4" {
			t.Errorf("Model() = %q, want %q", provider.Model(), "gpt-4")
		}
	})

	t.Run("with endpoint", func(t *testing.T) {
		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).
			WithEndpoint("https://api.example.com").
			Build()

		if provider.Endpoint() != "https://api.example.com" {
			t.Errorf("Endpoint() = %q, want %q", provider.Endpoint(), "https://api.example.com")
		}
	})

	t.Run("with auth", func(t *testing.T) {
		auth := NewAPIKeyAuth("test-key")
		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).
			WithAuth(auth).
			Build()

		if provider.AuthProvider() == nil {
			t.Error("AuthProvider() should not be nil")
		}
	})

	t.Run("with rate limiter", func(t *testing.T) {
		limiter := NewRateLimiter(100, 100)
		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).
			WithRateLimiter(limiter).
			Build()

		// Provider should be created
		if provider == nil {
			t.Error("Build() should not return nil")
		}
	})

	t.Run("with capabilities", func(t *testing.T) {
		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).
			WithCapabilities(llm.CapabilityChat, llm.CapabilityVision).
			Build()

		caps := provider.Capabilities()
		if len(caps) != 2 {
			t.Errorf("len(Capabilities()) = %d, want 2", len(caps))
		}
	})

	t.Run("with streaming", func(t *testing.T) {
		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).
			WithStreaming(true).
			Build()

		if !provider.SupportsStreaming() {
			t.Error("SupportsStreaming() should return true")
		}
	})

	t.Run("with timeout", func(t *testing.T) {
		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).
			WithTimeout(60 * time.Second).
			Build()

		if provider.HTTPClient().Timeout != 60*time.Second {
			t.Errorf("HTTPClient().Timeout = %v, want %v", provider.HTTPClient().Timeout, 60*time.Second)
		}
	})
}

func TestCustomProvider_Complete(t *testing.T) {
	t.Run("successful completion", func(t *testing.T) {
		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).
			WithCompleteFunc(func(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
				return &llm.CompletionResponse{
					Content: "Hello, world!",
					Model:   req.Model,
					Usage: llm.UsageStats{
						PromptTokens:     10,
						CompletionTokens: 5,
						TotalTokens:      15,
					},
				}, nil
			}).
			Build()

		ctx := context.Background()
		resp, err := provider.Complete(ctx, llm.CompletionRequest{
			Prompt:    "Hello",
			Model:     "test-model",
			MaxTokens: 100,
		})

		if err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if resp.Content != "Hello, world!" {
			t.Errorf("Content = %q, want %q", resp.Content, "Hello, world!")
		}
	})

	t.Run("no completion function", func(t *testing.T) {
		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).Build()

		ctx := context.Background()
		_, err := provider.Complete(ctx, llm.CompletionRequest{Prompt: "Hello"})

		if err == nil {
			t.Error("Complete() should return error when no function configured")
		}
	})

	t.Run("with rate limiting", func(t *testing.T) {
		callCount := 0
		limiter := NewRateLimiter(1000, 1000) // High rate to not block

		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).
			WithRateLimiter(limiter).
			WithCompleteFunc(func(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
				callCount++
				return &llm.CompletionResponse{Content: "OK"}, nil
			}).
			Build()

		ctx := context.Background()
		_, err := provider.Complete(ctx, llm.CompletionRequest{Prompt: "Hello"})

		if err != nil {
			t.Errorf("Complete() error = %v", err)
		}
		if callCount != 1 {
			t.Errorf("callCount = %d, want 1", callCount)
		}
	})

	t.Run("default model", func(t *testing.T) {
		var receivedModel string

		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).
			WithModel("default-model").
			WithCompleteFunc(func(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
				receivedModel = req.Model
				return &llm.CompletionResponse{Content: "OK", Model: req.Model}, nil
			}).
			Build()

		ctx := context.Background()
		provider.Complete(ctx, llm.CompletionRequest{Prompt: "Hello"}) // No model specified

		if receivedModel != "default-model" {
			t.Errorf("receivedModel = %q, want %q", receivedModel, "default-model")
		}
	})
}

func TestCustomProvider_HealthCheck(t *testing.T) {
	t.Run("default health check", func(t *testing.T) {
		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).
			WithCompleteFunc(func(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
				return &llm.CompletionResponse{Content: "OK"}, nil
			}).
			Build()

		ctx := context.Background()
		result, err := provider.HealthCheck(ctx)

		if err != nil {
			t.Errorf("HealthCheck() error = %v", err)
		}
		if result.Status != llm.HealthStatusHealthy {
			t.Errorf("Status = %v, want %v", result.Status, llm.HealthStatusHealthy)
		}
	})

	t.Run("unhealthy when completion fails", func(t *testing.T) {
		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).
			WithCompleteFunc(func(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
				return nil, errors.New("API error")
			}).
			Build()

		ctx := context.Background()
		result, err := provider.HealthCheck(ctx)

		if err != nil {
			t.Errorf("HealthCheck() error = %v", err)
		}
		if result.Status != llm.HealthStatusUnhealthy {
			t.Errorf("Status = %v, want %v", result.Status, llm.HealthStatusUnhealthy)
		}
	})
}

func TestCustomProvider_EstimateCost(t *testing.T) {
	t.Run("default cost estimator", func(t *testing.T) {
		provider := NewProviderBuilder("test", llm.ProviderTypeCustom).Build()

		estimate := provider.EstimateCost(llm.CompletionRequest{
			Prompt:    "Hello, world!",
			MaxTokens: 100,
		})

		if estimate == nil {
			t.Fatal("EstimateCost() should not return nil")
		}
		if estimate.Currency != "USD" {
			t.Errorf("Currency = %q, want %q", estimate.Currency, "USD")
		}
	})
}

func TestCustomProvider_InterfaceCompliance(t *testing.T) {
	// Verify CustomProvider implements llm.Provider
	var _ llm.Provider = (*CustomProvider)(nil)
}

func TestContainsCapability(t *testing.T) {
	caps := []llm.Capability{llm.CapabilityChat, llm.CapabilityCompletion}

	if !containsCapability(caps, llm.CapabilityChat) {
		t.Error("containsCapability should return true for Chat")
	}

	if containsCapability(caps, llm.CapabilityVision) {
		t.Error("containsCapability should return false for Vision")
	}
}

func TestAuthApply(t *testing.T) {
	t.Run("API key auth", func(t *testing.T) {
		auth := NewAPIKeyAuth("test-key")
		req, _ := http.NewRequest("GET", "http://example.com", nil)

		auth.Apply(req)

		if req.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("Authorization = %q, want %q", req.Header.Get("Authorization"), "Bearer test-key")
		}
	})

	t.Run("custom header auth", func(t *testing.T) {
		auth := NewAPIKeyAuthWithHeader("test-key", "X-API-Key")
		req, _ := http.NewRequest("GET", "http://example.com", nil)

		auth.Apply(req)

		if req.Header.Get("X-API-Key") != "test-key" {
			t.Errorf("X-API-Key = %q, want %q", req.Header.Get("X-API-Key"), "test-key")
		}
	})

	t.Run("query param auth", func(t *testing.T) {
		auth := NewAPIKeyAuthWithQuery("test-key", "api_key")
		req, _ := http.NewRequest("GET", "http://example.com", nil)

		auth.Apply(req)

		if req.URL.Query().Get("api_key") != "test-key" {
			t.Errorf("api_key param = %q, want %q", req.URL.Query().Get("api_key"), "test-key")
		}
	})

	t.Run("bearer token auth", func(t *testing.T) {
		auth := NewBearerTokenAuth("my-token")
		req, _ := http.NewRequest("GET", "http://example.com", nil)

		auth.Apply(req)

		if req.Header.Get("Authorization") != "Bearer my-token" {
			t.Errorf("Authorization = %q, want %q", req.Header.Get("Authorization"), "Bearer my-token")
		}
	})

	t.Run("basic auth", func(t *testing.T) {
		auth := NewBasicAuth("user", "pass")
		req, _ := http.NewRequest("GET", "http://example.com", nil)

		auth.Apply(req)

		authHeader := req.Header.Get("Authorization")
		if authHeader == "" {
			t.Error("Authorization header should be set")
		}
		if len(authHeader) < 10 {
			t.Error("Authorization header seems too short")
		}
	})

	t.Run("no auth", func(t *testing.T) {
		auth := NewNoAuth()
		req, _ := http.NewRequest("GET", "http://example.com", nil)

		auth.Apply(req)

		if req.Header.Get("Authorization") != "" {
			t.Error("NoAuth should not set Authorization header")
		}
	})

	t.Run("chained auth", func(t *testing.T) {
		auth := NewChainedAuth(
			NewAPIKeyAuthWithHeader("key1", "X-API-Key-1"),
			NewAPIKeyAuthWithHeader("key2", "X-API-Key-2"),
		)
		req, _ := http.NewRequest("GET", "http://example.com", nil)

		auth.Apply(req)

		if req.Header.Get("X-API-Key-1") != "key1" {
			t.Error("First auth should be applied")
		}
		if req.Header.Get("X-API-Key-2") != "key2" {
			t.Error("Second auth should be applied")
		}
	})
}

func TestRateLimiter(t *testing.T) {
	t.Run("basic rate limiting", func(t *testing.T) {
		limiter := NewRateLimiter(1000, 10)

		// Should be able to acquire tokens up to burst
		for i := 0; i < 10; i++ {
			if !limiter.TryAcquire() {
				t.Errorf("TryAcquire() should succeed on attempt %d", i)
			}
		}
	})

	t.Run("wait for token", func(t *testing.T) {
		limiter := NewRateLimiter(1000, 1)
		limiter.TryAcquire() // Use the one available token

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// Should eventually get a token due to high refill rate
		err := limiter.Wait(ctx)
		if err != nil {
			t.Errorf("Wait() error = %v", err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		limiter := NewRateLimiter(0.001, 1) // Very slow refill
		limiter.TryAcquire()                // Use the one available token

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		err := limiter.Wait(ctx)
		if err == nil {
			t.Error("Wait() should return error on context cancellation")
		}
	})

	t.Run("available tokens", func(t *testing.T) {
		limiter := NewRateLimiter(100, 10)

		available := limiter.Available()
		if available != 10 {
			t.Errorf("Available() = %f, want 10", available)
		}
	})
}

func TestMultiTenantRateLimiter(t *testing.T) {
	t.Run("per-tenant limiting", func(t *testing.T) {
		mtLimiter := NewMultiTenantRateLimiter(func() *RateLimiter {
			return NewRateLimiter(1000, 5)
		})

		// Each tenant should have their own pool
		for i := 0; i < 5; i++ {
			if !mtLimiter.TryAcquire("tenant-a") {
				t.Errorf("TryAcquire for tenant-a should succeed on attempt %d", i)
			}
			if !mtLimiter.TryAcquire("tenant-b") {
				t.Errorf("TryAcquire for tenant-b should succeed on attempt %d", i)
			}
		}
	})

	t.Run("tenant count", func(t *testing.T) {
		mtLimiter := NewMultiTenantRateLimiter(func() *RateLimiter {
			return NewRateLimiter(100, 10)
		})

		mtLimiter.TryAcquire("tenant-a")
		mtLimiter.TryAcquire("tenant-b")
		mtLimiter.TryAcquire("tenant-c")

		if mtLimiter.TenantCount() != 3 {
			t.Errorf("TenantCount() = %d, want 3", mtLimiter.TenantCount())
		}
	})

	t.Run("remove tenant", func(t *testing.T) {
		mtLimiter := NewMultiTenantRateLimiter(func() *RateLimiter {
			return NewRateLimiter(100, 10)
		})

		mtLimiter.TryAcquire("tenant-a")
		mtLimiter.TryAcquire("tenant-b")
		mtLimiter.RemoveTenant("tenant-a")

		if mtLimiter.TenantCount() != 1 {
			t.Errorf("TenantCount() = %d, want 1", mtLimiter.TenantCount())
		}
	})
}

func TestRetryWithBackoff(t *testing.T) {
	t.Run("success on first try", func(t *testing.T) {
		attempts := 0
		result, err := RetryWithBackoff(context.Background(), *DefaultRetryConfig(), func(ctx context.Context) (string, error) {
			attempts++
			return "success", nil
		})

		if err != nil {
			t.Errorf("RetryWithBackoff() error = %v", err)
		}
		if result != "success" {
			t.Errorf("result = %q, want %q", result, "success")
		}
		if attempts != 1 {
			t.Errorf("attempts = %d, want 1", attempts)
		}
	})

	t.Run("success after retries", func(t *testing.T) {
		attempts := 0
		result, err := RetryWithBackoff(context.Background(), RetryConfig{
			MaxRetries:     3,
			InitialBackoff: 1 * time.Millisecond,
			BackoffFactor:  1.5,
			RetryIf:        func(err error) bool { return true },
		}, func(ctx context.Context) (string, error) {
			attempts++
			if attempts < 3 {
				return "", errors.New("temporary error")
			}
			return "success", nil
		})

		if err != nil {
			t.Errorf("RetryWithBackoff() error = %v", err)
		}
		if result != "success" {
			t.Errorf("result = %q, want %q", result, "success")
		}
		if attempts != 3 {
			t.Errorf("attempts = %d, want 3", attempts)
		}
	})

	t.Run("non-retryable error", func(t *testing.T) {
		attempts := 0
		_, err := RetryWithBackoff(context.Background(), RetryConfig{
			MaxRetries: 3,
			RetryIf:    func(err error) bool { return false },
		}, func(ctx context.Context) (string, error) {
			attempts++
			return "", errors.New("non-retryable")
		})

		if err == nil {
			t.Error("RetryWithBackoff() should return error")
		}
		if attempts != 1 {
			t.Errorf("attempts = %d, want 1", attempts)
		}
	})
}

func TestCircuitBreaker(t *testing.T) {
	t.Run("closed state", func(t *testing.T) {
		cb := NewCircuitBreaker(5, 30*time.Second)

		if !cb.Allow() {
			t.Error("Allow() should return true when closed")
		}
		if cb.State() != CircuitClosed {
			t.Errorf("State() = %v, want CircuitClosed", cb.State())
		}
	})

	t.Run("opens after threshold", func(t *testing.T) {
		cb := NewCircuitBreaker(3, 30*time.Second)

		cb.RecordFailure()
		cb.RecordFailure()
		cb.RecordFailure()

		if cb.State() != CircuitOpen {
			t.Errorf("State() = %v, want CircuitOpen", cb.State())
		}
		if cb.Allow() {
			t.Error("Allow() should return false when open")
		}
	})

	t.Run("success resets failures", func(t *testing.T) {
		cb := NewCircuitBreaker(3, 30*time.Second)

		cb.RecordFailure()
		cb.RecordFailure()
		cb.RecordSuccess()

		if cb.State() != CircuitClosed {
			t.Errorf("State() = %v, want CircuitClosed", cb.State())
		}
	})

	t.Run("half-open after timeout", func(t *testing.T) {
		cb := NewCircuitBreaker(1, 10*time.Millisecond)
		cb.RecordFailure()

		time.Sleep(20 * time.Millisecond)

		if !cb.Allow() {
			t.Error("Allow() should return true after timeout (half-open)")
		}
		if cb.State() != CircuitHalfOpen {
			t.Errorf("State() = %v, want CircuitHalfOpen", cb.State())
		}
	})

	t.Run("reset", func(t *testing.T) {
		cb := NewCircuitBreaker(1, 30*time.Second)
		cb.RecordFailure()
		cb.Reset()

		if cb.State() != CircuitClosed {
			t.Errorf("State() = %v, want CircuitClosed", cb.State())
		}
	})
}

func TestAPIError(t *testing.T) {
	t.Run("rate limit is retryable", func(t *testing.T) {
		err := &APIError{StatusCode: 429, Message: "rate limited"}
		if !err.IsRetryable() {
			t.Error("429 should be retryable")
		}
	})

	t.Run("server error is retryable", func(t *testing.T) {
		err := &APIError{StatusCode: 500, Message: "server error"}
		if !err.IsRetryable() {
			t.Error("500 should be retryable")
		}
	})

	t.Run("client error is not retryable", func(t *testing.T) {
		err := &APIError{StatusCode: 400, Message: "bad request"}
		if err.IsRetryable() {
			t.Error("400 should not be retryable")
		}
	})

	t.Run("error message", func(t *testing.T) {
		err := &APIError{StatusCode: 500, Message: "internal error"}
		if err.Error() != "internal error" {
			t.Errorf("Error() = %q, want %q", err.Error(), "internal error")
		}
	})
}
