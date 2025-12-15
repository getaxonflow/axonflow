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
	"math"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// RetryConfig configures retry behavior
type RetryConfig struct {
	MaxRetries      int           // Maximum number of retry attempts
	InitialInterval time.Duration // Initial wait interval
	MaxInterval     time.Duration // Maximum wait interval
	Multiplier      float64       // Backoff multiplier
	Jitter          float64       // Jitter factor (0-1)
	RetryIf         func(error) bool // Custom retry condition
}

// DefaultRetryConfig returns a sensible default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:      3,
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
		Jitter:          0.1,
		RetryIf:         DefaultRetryCondition,
	}
}

// DefaultRetryCondition returns true for transient errors
func DefaultRetryCondition(err error) bool {
	if err == nil {
		return false
	}

	// Check for context errors
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Check for network errors (timeout only, Temporary() is deprecated)
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}

	// Check for specific error messages
	errMsg := strings.ToLower(err.Error())
	transientPatterns := []string{
		"connection refused",
		"connection reset",
		"connection timed out",
		"temporary failure",
		"service unavailable",
		"too many requests",
		"rate limit",
		"429",
		"503",
		"504",
	}

	for _, pattern := range transientPatterns {
		if strings.Contains(errMsg, pattern) {
			return true
		}
	}

	return false
}

// RetryableError wraps an error to indicate it should be retried
type RetryableError struct {
	Err        error
	RetryAfter time.Duration
}

func (e *RetryableError) Error() string {
	return e.Err.Error()
}

func (e *RetryableError) Unwrap() error {
	return e.Err
}

// IsRetryable checks if an error is marked as retryable
func IsRetryable(err error) bool {
	var retryable *RetryableError
	return errors.As(err, &retryable)
}

// GetRetryAfter returns the retry-after duration if specified
func GetRetryAfter(err error) time.Duration {
	var retryable *RetryableError
	if errors.As(err, &retryable) {
		return retryable.RetryAfter
	}
	return 0
}

// NonRetryableError wraps an error to indicate it should not be retried
type NonRetryableError struct {
	Err error
}

func (e *NonRetryableError) Error() string {
	return e.Err.Error()
}

func (e *NonRetryableError) Unwrap() error {
	return e.Err
}

// IsNonRetryable checks if an error is marked as non-retryable
func IsNonRetryable(err error) bool {
	var nonRetryable *NonRetryableError
	return errors.As(err, &nonRetryable)
}

// RetryFunc is the function type that can be retried
type RetryFunc[T any] func() (T, error)

// RetryWithBackoff executes a function with exponential backoff retry
func RetryWithBackoff[T any](ctx context.Context, config *RetryConfig, fn RetryFunc[T]) (T, error) {
	var zero T

	if config == nil {
		config = DefaultRetryConfig()
	}

	var lastErr error
	interval := config.InitialInterval

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		// Check context before each attempt
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}

		result, err := fn()
		if err == nil {
			return result, nil
		}

		lastErr = err

		// Check if we should retry
		if IsNonRetryable(err) {
			return zero, err
		}

		// Check custom retry condition if not explicitly retryable
		if !IsRetryable(err) && config.RetryIf != nil && !config.RetryIf(err) {
			return zero, err
		}

		// Check if this was the last attempt
		if attempt >= config.MaxRetries {
			break
		}

		// Calculate wait time
		waitTime := interval

		// Check for retry-after header
		if retryAfter := GetRetryAfter(err); retryAfter > 0 {
			waitTime = retryAfter
		}

		// Apply jitter
		if config.Jitter > 0 {
			jitter := waitTime.Seconds() * config.Jitter * (rand.Float64()*2 - 1)
			waitTime += time.Duration(jitter * float64(time.Second))
		}

		// Cap at max interval
		if waitTime > config.MaxInterval {
			waitTime = config.MaxInterval
		}

		// Wait with context
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(waitTime):
			// Continue to next attempt
		}

		// Update interval for next iteration
		interval = time.Duration(float64(interval) * config.Multiplier)
		if interval > config.MaxInterval {
			interval = config.MaxInterval
		}
	}

	return zero, &RetryError{
		Err:      lastErr,
		Attempts: config.MaxRetries + 1,
	}
}

// Retry executes a function with default retry configuration
func Retry[T any](ctx context.Context, fn RetryFunc[T]) (T, error) {
	return RetryWithBackoff(ctx, DefaultRetryConfig(), fn)
}

// RetryVoid executes a void function with retry
func RetryVoid(ctx context.Context, config *RetryConfig, fn func() error) error {
	_, err := RetryWithBackoff(ctx, config, func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}

// RetryError indicates all retry attempts failed
type RetryError struct {
	Err      error
	Attempts int
}

func (e *RetryError) Error() string {
	return fmt.Sprintf("operation failed after %d attempts: %v", e.Attempts, e.Err)
}

func (e *RetryError) Unwrap() error {
	return e.Err
}

// RetryWithBackoffSimple is a simplified retry for functions that don't return a value
func RetryWithBackoffSimple(ctx context.Context, config *RetryConfig, fn func() error) error {
	return RetryVoid(ctx, config, fn)
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	name            string
	maxFailures     int
	resetTimeout    time.Duration
	halfOpenMax     int
	failures        int
	state           circuitState
	lastFailureTime time.Time
	halfOpenSuccess int
	mu              sync.Mutex
}

type circuitState int

const (
	circuitClosed circuitState = iota
	circuitOpen
	circuitHalfOpen
)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(name string, maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		name:         name,
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		halfOpenMax:  3, // Number of successful calls to close circuit
		state:        circuitClosed,
	}
}

// Execute runs the function through the circuit breaker
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() error) error {
	cb.mu.Lock()

	// Check if circuit should transition from open to half-open
	if cb.state == circuitOpen {
		if time.Since(cb.lastFailureTime) > cb.resetTimeout {
			cb.state = circuitHalfOpen
			cb.halfOpenSuccess = 0
		} else {
			cb.mu.Unlock()
			return &CircuitBreakerOpenError{Name: cb.name}
		}
	}

	cb.mu.Unlock()

	// Execute the function
	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.recordFailure()
		return err
	}

	cb.recordSuccess()
	return nil
}

func (cb *CircuitBreaker) recordFailure() {
	cb.failures++
	cb.lastFailureTime = time.Now()

	if cb.state == circuitHalfOpen || cb.failures >= cb.maxFailures {
		cb.state = circuitOpen
	}
}

func (cb *CircuitBreaker) recordSuccess() {
	if cb.state == circuitHalfOpen {
		cb.halfOpenSuccess++
		if cb.halfOpenSuccess >= cb.halfOpenMax {
			cb.state = circuitClosed
			cb.failures = 0
		}
	} else {
		cb.failures = 0
	}
}

// State returns the current circuit state as a string
func (cb *CircuitBreaker) State() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case circuitClosed:
		return "closed"
	case circuitOpen:
		return "open"
	case circuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = circuitClosed
	cb.failures = 0
	cb.halfOpenSuccess = 0
}

// CircuitBreakerOpenError indicates the circuit is open
type CircuitBreakerOpenError struct {
	Name string
}

func (e *CircuitBreakerOpenError) Error() string {
	return fmt.Sprintf("circuit breaker '%s' is open", e.Name)
}

// Backoff calculates exponential backoff with optional jitter
type Backoff struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
	Jitter          float64
	attempt         int
}

// NewBackoff creates a new backoff calculator
func NewBackoff(initial, max time.Duration, multiplier, jitter float64) *Backoff {
	return &Backoff{
		InitialInterval: initial,
		MaxInterval:     max,
		Multiplier:      multiplier,
		Jitter:          jitter,
	}
}

// Next returns the next backoff duration
func (b *Backoff) Next() time.Duration {
	if b.attempt == 0 {
		b.attempt++
		return b.InitialInterval
	}

	interval := float64(b.InitialInterval) * math.Pow(b.Multiplier, float64(b.attempt))
	if interval > float64(b.MaxInterval) {
		interval = float64(b.MaxInterval)
	}

	// Apply jitter
	if b.Jitter > 0 {
		jitter := interval * b.Jitter * (rand.Float64()*2 - 1)
		interval += jitter
	}

	b.attempt++
	return time.Duration(interval)
}

// Reset resets the backoff to initial state
func (b *Backoff) Reset() {
	b.attempt = 0
}

// Attempt returns the current attempt number
func (b *Backoff) Attempt() int {
	return b.attempt
}
