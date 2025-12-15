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
	"fmt"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	rate       float64   // tokens per second
	burst      int       // maximum burst size
	tokens     float64   // current tokens available
	lastUpdate time.Time // last time tokens were updated
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter
// rate: number of requests allowed per second
// burst: maximum number of requests allowed in a burst
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

// Wait blocks until a token is available or the context is cancelled
func (r *RateLimiter) Wait(ctx context.Context) error {
	for {
		r.mu.Lock()

		// Update tokens based on time elapsed
		now := time.Now()
		elapsed := now.Sub(r.lastUpdate).Seconds()
		r.tokens = min(float64(r.burst), r.tokens+elapsed*r.rate)
		r.lastUpdate = now

		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return nil
		}

		// Calculate wait time
		waitTime := time.Duration((1-r.tokens)/r.rate*1000) * time.Millisecond
		r.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
			// Continue loop to try again
		}
	}
}

// TryAcquire attempts to acquire a token without blocking
// Returns true if a token was acquired, false otherwise
func (r *RateLimiter) TryAcquire() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Update tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(r.lastUpdate).Seconds()
	r.tokens = min(float64(r.burst), r.tokens+elapsed*r.rate)
	r.lastUpdate = now

	if r.tokens >= 1 {
		r.tokens--
		return true
	}
	return false
}

// Reserve reserves n tokens and returns the time to wait
// Returns 0 if tokens are immediately available
func (r *RateLimiter) Reserve(n int) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Update tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(r.lastUpdate).Seconds()
	r.tokens = min(float64(r.burst), r.tokens+elapsed*r.rate)
	r.lastUpdate = now

	needed := float64(n)
	if r.tokens >= needed {
		r.tokens -= needed
		return 0
	}

	// Calculate wait time
	deficit := needed - r.tokens
	waitTime := time.Duration(deficit/r.rate*1000) * time.Millisecond
	r.tokens = 0

	return waitTime
}

// Available returns the number of tokens currently available
func (r *RateLimiter) Available() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Update tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(r.lastUpdate).Seconds()
	r.tokens = min(float64(r.burst), r.tokens+elapsed*r.rate)
	r.lastUpdate = now

	return int(r.tokens)
}

// Reset resets the rate limiter to full capacity
func (r *RateLimiter) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens = float64(r.burst)
	r.lastUpdate = time.Now()
}

// SetRate updates the rate limit dynamically
func (r *RateLimiter) SetRate(rate float64, burst int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rate = rate
	r.burst = burst
	if r.tokens > float64(burst) {
		r.tokens = float64(burst)
	}
}

// AdaptiveRateLimiter adjusts rate limits based on response patterns
type AdaptiveRateLimiter struct {
	*RateLimiter
	minRate      float64
	maxRate      float64
	targetRate   float64
	windowSize   int
	errorCount   int
	successCount int
	mu           sync.Mutex
}

// NewAdaptiveRateLimiter creates a rate limiter that adapts to server responses
func NewAdaptiveRateLimiter(minRate, maxRate float64, burst int) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		RateLimiter: NewRateLimiter(maxRate, burst),
		minRate:     minRate,
		maxRate:     maxRate,
		targetRate:  maxRate,
		windowSize:  100,
	}
}

// RecordSuccess records a successful request
func (a *AdaptiveRateLimiter) RecordSuccess() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.successCount++
	a.checkAndAdjust()
}

// RecordError records a failed request (rate limited)
func (a *AdaptiveRateLimiter) RecordError() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.errorCount++
	a.checkAndAdjust()
}

// RecordRateLimited records a 429 Too Many Requests response
// This significantly reduces the rate
func (a *AdaptiveRateLimiter) RecordRateLimited() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Immediately reduce rate by 50%
	a.targetRate = max(a.minRate, a.targetRate*0.5)
	a.SetRate(a.targetRate, a.burst)
	a.errorCount = 0
	a.successCount = 0
}

func (a *AdaptiveRateLimiter) checkAndAdjust() {
	total := a.errorCount + a.successCount
	if total < a.windowSize {
		return
	}

	errorRate := float64(a.errorCount) / float64(total)

	if errorRate > 0.1 {
		// Too many errors, reduce rate
		a.targetRate = max(a.minRate, a.targetRate*0.8)
	} else if errorRate < 0.01 && a.targetRate < a.maxRate {
		// Very few errors, gradually increase rate
		a.targetRate = min(a.maxRate, a.targetRate*1.1)
	}

	a.SetRate(a.targetRate, a.burst)
	a.errorCount = 0
	a.successCount = 0
}

// GetCurrentRate returns the current rate limit
func (a *AdaptiveRateLimiter) GetCurrentRate() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.targetRate
}

// SlidingWindowRateLimiter implements a sliding window rate limiter
type SlidingWindowRateLimiter struct {
	windowSize time.Duration
	maxRequests int
	requests    []time.Time
	mu          sync.Mutex
}

// NewSlidingWindowRateLimiter creates a sliding window rate limiter
func NewSlidingWindowRateLimiter(windowSize time.Duration, maxRequests int) *SlidingWindowRateLimiter {
	return &SlidingWindowRateLimiter{
		windowSize:  windowSize,
		maxRequests: maxRequests,
		requests:    make([]time.Time, 0, maxRequests),
	}
}

// Wait blocks until a request is allowed
func (s *SlidingWindowRateLimiter) Wait(ctx context.Context) error {
	for {
		s.mu.Lock()
		s.cleanup()

		if len(s.requests) < s.maxRequests {
			s.requests = append(s.requests, time.Now())
			s.mu.Unlock()
			return nil
		}

		// Calculate wait time
		oldestRequest := s.requests[0]
		waitTime := s.windowSize - time.Since(oldestRequest)
		s.mu.Unlock()

		if waitTime <= 0 {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
			// Continue and try again
		}
	}
}

// TryAcquire attempts to acquire a slot without blocking
func (s *SlidingWindowRateLimiter) TryAcquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanup()

	if len(s.requests) < s.maxRequests {
		s.requests = append(s.requests, time.Now())
		return true
	}
	return false
}

// cleanup removes expired requests
func (s *SlidingWindowRateLimiter) cleanup() {
	cutoff := time.Now().Add(-s.windowSize)
	i := 0
	for i < len(s.requests) && s.requests[i].Before(cutoff) {
		i++
	}
	s.requests = s.requests[i:]
}

// Available returns the number of requests available in the current window
func (s *SlidingWindowRateLimiter) Available() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanup()
	return s.maxRequests - len(s.requests)
}

// MultiTenantRateLimiter provides per-tenant rate limiting
type MultiTenantRateLimiter struct {
	limiters    map[string]*RateLimiter
	defaultRate float64
	defaultBurst int
	mu          sync.RWMutex
}

// NewMultiTenantRateLimiter creates a rate limiter that supports multiple tenants
func NewMultiTenantRateLimiter(defaultRate float64, defaultBurst int) *MultiTenantRateLimiter {
	return &MultiTenantRateLimiter{
		limiters:     make(map[string]*RateLimiter),
		defaultRate:  defaultRate,
		defaultBurst: defaultBurst,
	}
}

// Wait blocks until a token is available for the given tenant
func (m *MultiTenantRateLimiter) Wait(ctx context.Context, tenantID string) error {
	limiter := m.getLimiter(tenantID)
	return limiter.Wait(ctx)
}

// TryAcquire attempts to acquire a token for the given tenant without blocking
func (m *MultiTenantRateLimiter) TryAcquire(tenantID string) bool {
	limiter := m.getLimiter(tenantID)
	return limiter.TryAcquire()
}

// SetTenantLimit sets custom rate limits for a specific tenant
func (m *MultiTenantRateLimiter) SetTenantLimit(tenantID string, rate float64, burst int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if limiter, exists := m.limiters[tenantID]; exists {
		limiter.SetRate(rate, burst)
	} else {
		m.limiters[tenantID] = NewRateLimiter(rate, burst)
	}
}

// RemoveTenant removes a tenant's rate limiter
func (m *MultiTenantRateLimiter) RemoveTenant(tenantID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.limiters, tenantID)
}

func (m *MultiTenantRateLimiter) getLimiter(tenantID string) *RateLimiter {
	m.mu.RLock()
	limiter, exists := m.limiters[tenantID]
	m.mu.RUnlock()

	if exists {
		return limiter
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists = m.limiters[tenantID]; exists {
		return limiter
	}

	limiter = NewRateLimiter(m.defaultRate, m.defaultBurst)
	m.limiters[tenantID] = limiter
	return limiter
}

// RateLimitError represents a rate limit error with metadata
type RateLimitError struct {
	Message    string
	RetryAfter time.Duration
	Limit      int
	Remaining  int
	Reset      time.Time
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%s (retry after %v)", e.Message, e.RetryAfter)
}

// NewRateLimitError creates a new rate limit error
func NewRateLimitError(retryAfter time.Duration) *RateLimitError {
	return &RateLimitError{
		Message:    "rate limit exceeded",
		RetryAfter: retryAfter,
	}
}
