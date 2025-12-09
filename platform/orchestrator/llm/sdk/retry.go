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

package sdk

import (
	"context"
	"math/rand"
	"net/http"
	"time"
)

// RetryConfig configures retry behavior.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts.
	MaxRetries int

	// InitialBackoff is the initial wait time before the first retry.
	InitialBackoff time.Duration

	// MaxBackoff is the maximum wait time between retries.
	MaxBackoff time.Duration

	// BackoffFactor is the multiplier for exponential backoff.
	BackoffFactor float64

	// Jitter adds randomness to avoid thundering herd (0.0-1.0).
	Jitter float64

	// RetryIf determines if an error should be retried.
	RetryIf func(err error) bool
}

// DefaultRetryConfig returns a sensible default retry configuration.
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     30 * time.Second,
		BackoffFactor:  2.0,
		Jitter:         0.1,
		RetryIf:        DefaultRetryable,
	}
}

// DefaultRetryable determines if an error is retryable by default.
// It returns true for rate limit errors, server errors, and timeouts.
func DefaultRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific error types
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.IsRetryable()
	}

	// Retry context deadline exceeded (timeouts)
	if err == context.DeadlineExceeded {
		return true
	}

	return false
}

// RetryWithBackoff executes a function with exponential backoff retry.
func RetryWithBackoff[T any](ctx context.Context, config RetryConfig, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	var lastErr error

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		result, err := fn(ctx)
		if err == nil {
			return result, nil
		}

		lastErr = err

		// Check if we should retry
		if config.RetryIf != nil && !config.RetryIf(err) {
			return zero, err
		}

		// Don't wait after the last attempt
		if attempt >= config.MaxRetries {
			break
		}

		// Calculate backoff duration
		backoff := config.InitialBackoff * time.Duration(pow(config.BackoffFactor, float64(attempt)))
		if backoff > config.MaxBackoff {
			backoff = config.MaxBackoff
		}

		// Add jitter
		if config.Jitter > 0 {
			jitterDelta := float64(backoff) * config.Jitter
			jitter := (rand.Float64() * 2 * jitterDelta) - jitterDelta
			backoff = time.Duration(float64(backoff) + jitter)
		}

		// Wait with context cancellation
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(backoff):
			continue
		}
	}

	return zero, lastErr
}

// pow calculates base^exp for floats.
func pow(base, exp float64) float64 {
	result := 1.0
	for exp > 0 {
		if int(exp)%2 == 1 {
			result *= base
		}
		exp = float64(int(exp) / 2)
		base *= base
	}
	return result
}

// APIError represents an API error with retry information.
type APIError struct {
	StatusCode int
	Message    string
	Type       string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	return e.Message
}

// IsRetryable returns true if the error is retryable.
func (e *APIError) IsRetryable() bool {
	// Rate limit errors are retryable
	if e.StatusCode == http.StatusTooManyRequests {
		return true
	}

	// Server errors (5xx) are retryable
	if e.StatusCode >= 500 && e.StatusCode < 600 {
		return true
	}

	// Check error type
	switch e.Type {
	case "rate_limit_error", "server_error", "overloaded_error":
		return true
	}

	return false
}

// CircuitBreaker prevents cascading failures by stopping requests to unhealthy services.
type CircuitBreaker struct {
	failures         int
	threshold        int
	resetTimeout     time.Duration
	lastFailureTime  time.Time
	state            CircuitState
}

// CircuitState represents the state of a circuit breaker.
type CircuitState int

const (
	// CircuitClosed allows requests through.
	CircuitClosed CircuitState = iota
	// CircuitOpen blocks requests.
	CircuitOpen
	// CircuitHalfOpen allows a test request through.
	CircuitHalfOpen
)

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(threshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold:    threshold,
		resetTimeout: resetTimeout,
		state:        CircuitClosed,
	}
}

// Allow checks if a request should be allowed through.
func (cb *CircuitBreaker) Allow() bool {
	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(cb.lastFailureTime) >= cb.resetTimeout {
			cb.state = CircuitHalfOpen
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	}
	return false
}

// RecordSuccess records a successful request.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.failures = 0
	cb.state = CircuitClosed
}

// RecordFailure records a failed request.
func (cb *CircuitBreaker) RecordFailure() {
	cb.failures++
	cb.lastFailureTime = time.Now()

	if cb.failures >= cb.threshold {
		cb.state = CircuitOpen
	}
}

// State returns the current circuit state.
func (cb *CircuitBreaker) State() CircuitState {
	return cb.state
}

// Reset resets the circuit breaker.
func (cb *CircuitBreaker) Reset() {
	cb.failures = 0
	cb.state = CircuitClosed
}
