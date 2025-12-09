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
	"sync"
	"time"
)

// RateLimiter implements token bucket rate limiting for LLM API calls.
type RateLimiter struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter.
// rate: requests per second
// burst: maximum burst size (bucket capacity)
func NewRateLimiter(rate, burst float64) *RateLimiter {
	return &RateLimiter{
		tokens:     burst,
		maxTokens:  burst,
		refillRate: rate,
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available or the context is cancelled.
func (r *RateLimiter) Wait(ctx context.Context) error {
	for {
		if r.TryAcquire() {
			return nil
		}

		// Wait for the next refill
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond * 10):
			continue
		}
	}
}

// TryAcquire attempts to acquire a token without blocking.
// Returns true if a token was acquired.
func (r *RateLimiter) TryAcquire() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.refill()

	if r.tokens >= 1 {
		r.tokens--
		return true
	}
	return false
}

// refill adds tokens based on elapsed time.
func (r *RateLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.tokens += elapsed * r.refillRate
	if r.tokens > r.maxTokens {
		r.tokens = r.maxTokens
	}
	r.lastRefill = now
}

// Available returns the current number of available tokens.
func (r *RateLimiter) Available() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refill()
	return r.tokens
}

// SetRate dynamically updates the rate limit.
func (r *RateLimiter) SetRate(rate float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refillRate = rate
}

// SetBurst dynamically updates the burst capacity.
func (r *RateLimiter) SetBurst(burst float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maxTokens = burst
}

// MultiTenantRateLimiter provides per-tenant rate limiting.
type MultiTenantRateLimiter struct {
	limiters map[string]*RateLimiter
	factory  func() *RateLimiter
	mu       sync.RWMutex
}

// NewMultiTenantRateLimiter creates a multi-tenant rate limiter.
// The factory function creates a new limiter for each tenant.
func NewMultiTenantRateLimiter(factory func() *RateLimiter) *MultiTenantRateLimiter {
	return &MultiTenantRateLimiter{
		limiters: make(map[string]*RateLimiter),
		factory:  factory,
	}
}

// Wait blocks until a token is available for the given tenant.
func (m *MultiTenantRateLimiter) Wait(ctx context.Context, tenantID string) error {
	limiter := m.getLimiter(tenantID)
	return limiter.Wait(ctx)
}

// TryAcquire attempts to acquire a token for the given tenant.
func (m *MultiTenantRateLimiter) TryAcquire(tenantID string) bool {
	limiter := m.getLimiter(tenantID)
	return limiter.TryAcquire()
}

// getLimiter returns the rate limiter for a tenant, creating one if needed.
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

	limiter = m.factory()
	m.limiters[tenantID] = limiter
	return limiter
}

// RemoveTenant removes a tenant's rate limiter.
func (m *MultiTenantRateLimiter) RemoveTenant(tenantID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.limiters, tenantID)
}

// TenantCount returns the number of tracked tenants.
func (m *MultiTenantRateLimiter) TenantCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.limiters)
}
