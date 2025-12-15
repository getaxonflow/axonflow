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
	"fmt"
	"testing"
	"time"
)

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	if config.MaxRetries != 3 {
		t.Errorf("expected max retries 3, got %d", config.MaxRetries)
	}

	if config.InitialInterval != 100*time.Millisecond {
		t.Errorf("expected initial interval 100ms, got %v", config.InitialInterval)
	}

	if config.MaxInterval != 30*time.Second {
		t.Errorf("expected max interval 30s, got %v", config.MaxInterval)
	}

	if config.Multiplier != 2.0 {
		t.Errorf("expected multiplier 2.0, got %f", config.Multiplier)
	}
}

func TestDefaultRetryCondition(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"context canceled", context.Canceled, false},
		{"context deadline", context.DeadlineExceeded, false},
		{"connection refused", fmt.Errorf("connection refused"), true},
		{"connection reset", fmt.Errorf("connection reset by peer"), true},
		{"service unavailable", fmt.Errorf("service unavailable"), true},
		{"rate limit", fmt.Errorf("rate limit exceeded"), true},
		{"429 status", fmt.Errorf("got status 429"), true},
		{"503 status", fmt.Errorf("got status 503"), true},
		{"504 status", fmt.Errorf("got status 504"), true},
		{"random error", fmt.Errorf("some random error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DefaultRetryCondition(tt.err)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRetryableError(t *testing.T) {
	originalErr := fmt.Errorf("original error")
	retryableErr := &RetryableError{
		Err:        originalErr,
		RetryAfter: 5 * time.Second,
	}

	if retryableErr.Error() != originalErr.Error() {
		t.Error("error message should match wrapped error")
	}

	if !errors.Is(retryableErr, originalErr) {
		t.Error("should unwrap to original error")
	}

	if !IsRetryable(retryableErr) {
		t.Error("should be identified as retryable")
	}

	if GetRetryAfter(retryableErr) != 5*time.Second {
		t.Error("should return retry-after duration")
	}
}

func TestNonRetryableError(t *testing.T) {
	originalErr := fmt.Errorf("permanent error")
	nonRetryable := &NonRetryableError{Err: originalErr}

	if nonRetryable.Error() != originalErr.Error() {
		t.Error("error message should match wrapped error")
	}

	if !IsNonRetryable(nonRetryable) {
		t.Error("should be identified as non-retryable")
	}

	if IsRetryable(nonRetryable) {
		t.Error("should not be retryable")
	}
}

func TestRetryWithBackoff(t *testing.T) {
	t.Run("success on first try", func(t *testing.T) {
		ctx := context.Background()
		attempts := 0

		result, err := RetryWithBackoff(ctx, nil, func() (string, error) {
			attempts++
			return "success", nil
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result != "success" {
			t.Errorf("expected success, got %s", result)
		}

		if attempts != 1 {
			t.Errorf("expected 1 attempt, got %d", attempts)
		}
	})

	t.Run("success after retries", func(t *testing.T) {
		ctx := context.Background()
		attempts := 0

		config := &RetryConfig{
			MaxRetries:      3,
			InitialInterval: time.Millisecond,
			MaxInterval:     10 * time.Millisecond,
			Multiplier:      2,
			Jitter:          0,
			RetryIf:         func(error) bool { return true },
		}

		result, err := RetryWithBackoff(ctx, config, func() (string, error) {
			attempts++
			if attempts < 3 {
				return "", fmt.Errorf("temporary error")
			}
			return "success", nil
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result != "success" {
			t.Errorf("expected success, got %s", result)
		}

		if attempts != 3 {
			t.Errorf("expected 3 attempts, got %d", attempts)
		}
	})

	t.Run("max retries exceeded", func(t *testing.T) {
		ctx := context.Background()
		attempts := 0

		config := &RetryConfig{
			MaxRetries:      2,
			InitialInterval: time.Millisecond,
			MaxInterval:     10 * time.Millisecond,
			Multiplier:      2,
			Jitter:          0,
			RetryIf:         func(error) bool { return true },
		}

		_, err := RetryWithBackoff(ctx, config, func() (string, error) {
			attempts++
			return "", fmt.Errorf("always fails")
		})

		if err == nil {
			t.Fatal("expected error")
		}

		var retryErr *RetryError
		if !errors.As(err, &retryErr) {
			t.Error("expected RetryError")
		}

		if attempts != 3 { // Initial + 2 retries
			t.Errorf("expected 3 attempts, got %d", attempts)
		}
	})

	t.Run("non-retryable error stops immediately", func(t *testing.T) {
		ctx := context.Background()
		attempts := 0

		config := DefaultRetryConfig()

		_, err := RetryWithBackoff(ctx, config, func() (string, error) {
			attempts++
			return "", &NonRetryableError{Err: fmt.Errorf("permanent")}
		})

		if err == nil {
			t.Fatal("expected error")
		}

		if attempts != 1 {
			t.Errorf("expected 1 attempt for non-retryable, got %d", attempts)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		attempts := 0

		config := &RetryConfig{
			MaxRetries:      10,
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     time.Second,
			Multiplier:      2,
			Jitter:          0,
			RetryIf:         func(error) bool { return true },
		}

		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		_, err := RetryWithBackoff(ctx, config, func() (string, error) {
			attempts++
			return "", fmt.Errorf("error")
		})

		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})

	t.Run("retry-after hint", func(t *testing.T) {
		ctx := context.Background()
		attempts := 0
		start := time.Now()

		config := &RetryConfig{
			MaxRetries:      2,
			InitialInterval: time.Millisecond,
			MaxInterval:     time.Second,
			Multiplier:      2,
			Jitter:          0,
			RetryIf:         func(error) bool { return true },
		}

		_, err := RetryWithBackoff(ctx, config, func() (string, error) {
			attempts++
			if attempts == 1 {
				return "", &RetryableError{
					Err:        fmt.Errorf("retry"),
					RetryAfter: 50 * time.Millisecond,
				}
			}
			return "success", nil
		})

		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if elapsed < 45*time.Millisecond {
			t.Errorf("expected at least 50ms delay, got %v", elapsed)
		}
	})
}

func TestRetry(t *testing.T) {
	ctx := context.Background()
	attempts := 0

	result, err := Retry(ctx, func() (int, error) {
		attempts++
		return 42, nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
}

func TestRetryVoid(t *testing.T) {
	ctx := context.Background()
	attempts := 0

	config := &RetryConfig{
		MaxRetries:      3,
		InitialInterval: time.Millisecond,
		MaxInterval:     10 * time.Millisecond,
		Multiplier:      2,
		Jitter:          0,
		RetryIf:         func(error) bool { return true },
	}

	err := RetryVoid(ctx, config, func() error {
		attempts++
		if attempts < 2 {
			return fmt.Errorf("retry")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestCircuitBreaker(t *testing.T) {
	t.Run("closed state allows calls", func(t *testing.T) {
		cb := NewCircuitBreaker("test", 3, time.Second)

		ctx := context.Background()
		err := cb.Execute(ctx, func() error {
			return nil
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cb.State() != "closed" {
			t.Errorf("expected closed state, got %s", cb.State())
		}
	})

	t.Run("opens after failures", func(t *testing.T) {
		cb := NewCircuitBreaker("test", 3, time.Second)
		ctx := context.Background()

		// Fail 3 times
		for i := 0; i < 3; i++ {
			cb.Execute(ctx, func() error {
				return fmt.Errorf("failure")
			})
		}

		if cb.State() != "open" {
			t.Errorf("expected open state, got %s", cb.State())
		}

		// Next call should fail immediately
		err := cb.Execute(ctx, func() error {
			return nil
		})

		var cbErr *CircuitBreakerOpenError
		if !errors.As(err, &cbErr) {
			t.Error("expected CircuitBreakerOpenError")
		}
	})

	t.Run("transitions to half-open after timeout", func(t *testing.T) {
		cb := NewCircuitBreaker("test", 2, 50*time.Millisecond)
		ctx := context.Background()

		// Open the circuit
		for i := 0; i < 2; i++ {
			cb.Execute(ctx, func() error {
				return fmt.Errorf("failure")
			})
		}

		if cb.State() != "open" {
			t.Errorf("expected open state, got %s", cb.State())
		}

		// Wait for reset timeout
		time.Sleep(60 * time.Millisecond)

		// Next call should succeed and move to half-open
		err := cb.Execute(ctx, func() error {
			return nil
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// After successful calls, should close
		for i := 0; i < 3; i++ {
			cb.Execute(ctx, func() error { return nil })
		}

		if cb.State() != "closed" {
			t.Errorf("expected closed state after successes, got %s", cb.State())
		}
	})

	t.Run("reset", func(t *testing.T) {
		cb := NewCircuitBreaker("test", 2, time.Second)
		ctx := context.Background()

		// Open the circuit
		for i := 0; i < 2; i++ {
			cb.Execute(ctx, func() error {
				return fmt.Errorf("failure")
			})
		}

		cb.Reset()

		if cb.State() != "closed" {
			t.Errorf("expected closed state after reset, got %s", cb.State())
		}

		// Should allow calls again
		err := cb.Execute(ctx, func() error {
			return nil
		})

		if err != nil {
			t.Fatalf("unexpected error after reset: %v", err)
		}
	})
}

func TestBackoff(t *testing.T) {
	t.Run("exponential increase", func(t *testing.T) {
		backoff := NewBackoff(
			10*time.Millisecond,
			1*time.Second,
			2.0,
			0, // no jitter for predictable tests
		)

		first := backoff.Next()
		if first != 10*time.Millisecond {
			t.Errorf("expected 10ms, got %v", first)
		}

		second := backoff.Next()
		if second < 15*time.Millisecond || second > 25*time.Millisecond {
			t.Errorf("expected ~20ms, got %v", second)
		}

		third := backoff.Next()
		if third < 35*time.Millisecond || third > 45*time.Millisecond {
			t.Errorf("expected ~40ms, got %v", third)
		}
	})

	t.Run("respects max interval", func(t *testing.T) {
		backoff := NewBackoff(
			100*time.Millisecond,
			200*time.Millisecond,
			10.0,
			0,
		)

		// First call
		backoff.Next()
		// Second would be 1s without cap
		second := backoff.Next()
		if second > 200*time.Millisecond {
			t.Errorf("expected max 200ms, got %v", second)
		}
	})

	t.Run("reset", func(t *testing.T) {
		backoff := NewBackoff(10*time.Millisecond, time.Second, 2.0, 0)

		backoff.Next()
		backoff.Next()

		if backoff.Attempt() != 2 {
			t.Errorf("expected 2 attempts, got %d", backoff.Attempt())
		}

		backoff.Reset()

		if backoff.Attempt() != 0 {
			t.Errorf("expected 0 attempts after reset, got %d", backoff.Attempt())
		}
	})

	t.Run("with jitter", func(t *testing.T) {
		backoff := NewBackoff(100*time.Millisecond, time.Second, 2.0, 0.5)

		// Get multiple values and verify they're not all the same
		values := make(map[time.Duration]bool)
		backoff.Next() // First is always initial

		for i := 0; i < 10; i++ {
			backoff.Reset()
			backoff.Next() // Skip initial
			values[backoff.Next()] = true
		}

		// With jitter, we should see some variation
		if len(values) < 2 {
			t.Error("expected some variation with jitter")
		}
	})
}

func TestRetryError(t *testing.T) {
	originalErr := fmt.Errorf("underlying error")
	retryErr := &RetryError{
		Err:      originalErr,
		Attempts: 5,
	}

	errStr := retryErr.Error()
	if errStr == "" {
		t.Error("expected non-empty error string")
	}

	if !errors.Is(retryErr, originalErr) {
		t.Error("should unwrap to original error")
	}
}

func TestCircuitBreakerOpenError(t *testing.T) {
	err := &CircuitBreakerOpenError{Name: "my-circuit"}

	expected := "circuit breaker 'my-circuit' is open"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}
