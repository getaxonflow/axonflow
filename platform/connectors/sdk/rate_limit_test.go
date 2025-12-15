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
	"sync"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	t.Run("basic rate limiting", func(t *testing.T) {
		limiter := NewRateLimiter(10, 10) // 10 requests per second, burst of 10

		ctx := context.Background()

		// Should immediately allow burst
		for i := 0; i < 10; i++ {
			if err := limiter.Wait(ctx); err != nil {
				t.Fatalf("unexpected error on request %d: %v", i, err)
			}
		}
	})

	t.Run("try acquire", func(t *testing.T) {
		limiter := NewRateLimiter(10, 2)

		// First two should succeed
		if !limiter.TryAcquire() {
			t.Error("expected first acquire to succeed")
		}
		if !limiter.TryAcquire() {
			t.Error("expected second acquire to succeed")
		}

		// Third should fail (burst exhausted)
		if limiter.TryAcquire() {
			t.Error("expected third acquire to fail")
		}
	})

	t.Run("reserve tokens", func(t *testing.T) {
		limiter := NewRateLimiter(10, 5)

		// Reserve 3 tokens
		wait := limiter.Reserve(3)
		if wait != 0 {
			t.Errorf("expected immediate availability, got wait %v", wait)
		}

		// Available should be 2
		if available := limiter.Available(); available != 2 {
			t.Errorf("expected 2 available, got %d", available)
		}

		// Reserve more than available
		wait = limiter.Reserve(5)
		if wait == 0 {
			t.Error("expected wait time for over-reserve")
		}
	})

	t.Run("reset", func(t *testing.T) {
		limiter := NewRateLimiter(1, 5)

		// Exhaust all tokens
		for i := 0; i < 5; i++ {
			limiter.TryAcquire()
		}

		if limiter.Available() != 0 {
			t.Error("expected no tokens available")
		}

		// Reset
		limiter.Reset()

		if limiter.Available() != 5 {
			t.Errorf("expected 5 tokens after reset, got %d", limiter.Available())
		}
	})

	t.Run("set rate", func(t *testing.T) {
		limiter := NewRateLimiter(10, 5)

		// Update rate
		limiter.SetRate(20, 10)

		// Now should have capacity of 10
		limiter.Reset()
		if available := limiter.Available(); available != 10 {
			t.Errorf("expected 10 available after rate change, got %d", available)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		limiter := NewRateLimiter(0.1, 1) // Very slow rate

		// Exhaust the burst
		limiter.TryAcquire()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		err := limiter.Wait(ctx)
		if err == nil {
			t.Error("expected context error")
		}
	})

	t.Run("token replenishment", func(t *testing.T) {
		limiter := NewRateLimiter(100, 2) // 100 per second

		// Exhaust burst
		limiter.TryAcquire()
		limiter.TryAcquire()

		// Wait for replenishment
		time.Sleep(30 * time.Millisecond)

		// Should have some tokens now
		if limiter.Available() < 1 {
			t.Error("expected token replenishment")
		}
	})
}

func TestAdaptiveRateLimiter(t *testing.T) {
	t.Run("success recording", func(t *testing.T) {
		limiter := NewAdaptiveRateLimiter(1, 100, 10)

		initialRate := limiter.GetCurrentRate()

		// Record many successes
		for i := 0; i < 150; i++ {
			limiter.RecordSuccess()
		}

		// Rate might increase or stay the same
		newRate := limiter.GetCurrentRate()
		if newRate < initialRate {
			t.Error("rate should not decrease with all successes")
		}
	})

	t.Run("error recording", func(t *testing.T) {
		limiter := NewAdaptiveRateLimiter(1, 100, 10)

		// Record many errors
		for i := 0; i < 100; i++ {
			limiter.RecordError()
		}

		// Rate should decrease
		if limiter.GetCurrentRate() >= 100 {
			t.Error("rate should decrease with errors")
		}
	})

	t.Run("rate limit response", func(t *testing.T) {
		limiter := NewAdaptiveRateLimiter(1, 100, 10)

		initialRate := limiter.GetCurrentRate()
		limiter.RecordRateLimited()

		// Rate should drop by 50%
		if limiter.GetCurrentRate() > initialRate*0.6 {
			t.Error("rate should drop significantly on rate limit")
		}
	})

	t.Run("respects minimum rate", func(t *testing.T) {
		limiter := NewAdaptiveRateLimiter(5, 100, 10)

		// Keep hitting rate limits
		for i := 0; i < 20; i++ {
			limiter.RecordRateLimited()
		}

		// Should not go below minimum
		if limiter.GetCurrentRate() < 5 {
			t.Errorf("rate %f below minimum 5", limiter.GetCurrentRate())
		}
	})
}

func TestSlidingWindowRateLimiter(t *testing.T) {
	t.Run("basic sliding window", func(t *testing.T) {
		limiter := NewSlidingWindowRateLimiter(time.Second, 5)

		// Should allow 5 requests
		for i := 0; i < 5; i++ {
			if !limiter.TryAcquire() {
				t.Errorf("expected request %d to succeed", i)
			}
		}

		// 6th should fail
		if limiter.TryAcquire() {
			t.Error("expected 6th request to fail")
		}
	})

	t.Run("window expiration", func(t *testing.T) {
		limiter := NewSlidingWindowRateLimiter(50*time.Millisecond, 2)

		// Use up quota
		limiter.TryAcquire()
		limiter.TryAcquire()

		if limiter.TryAcquire() {
			t.Error("expected failure after quota exhausted")
		}

		// Wait for window to slide
		time.Sleep(60 * time.Millisecond)

		// Should allow requests again
		if !limiter.TryAcquire() {
			t.Error("expected success after window slide")
		}
	})

	t.Run("available count", func(t *testing.T) {
		limiter := NewSlidingWindowRateLimiter(time.Second, 10)

		if available := limiter.Available(); available != 10 {
			t.Errorf("expected 10 available, got %d", available)
		}

		for i := 0; i < 3; i++ {
			limiter.TryAcquire()
		}

		if available := limiter.Available(); available != 7 {
			t.Errorf("expected 7 available, got %d", available)
		}
	})

	t.Run("wait with context", func(t *testing.T) {
		limiter := NewSlidingWindowRateLimiter(time.Second, 1)

		ctx := context.Background()
		if err := limiter.Wait(ctx); err != nil {
			t.Fatalf("first wait failed: %v", err)
		}

		// Second wait should block until window expires or context cancels
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		err := limiter.Wait(ctx)
		if err == nil {
			t.Error("expected context error")
		}
	})
}

func TestMultiTenantRateLimiter(t *testing.T) {
	t.Run("per-tenant limiting", func(t *testing.T) {
		limiter := NewMultiTenantRateLimiter(10, 5)

		ctx := context.Background()

		// Tenant A uses quota
		for i := 0; i < 5; i++ {
			if err := limiter.Wait(ctx, "tenant-a"); err != nil {
				t.Fatalf("tenant-a wait %d failed: %v", i, err)
			}
		}

		// Tenant A exhausted
		if limiter.TryAcquire("tenant-a") {
			t.Error("expected tenant-a to be exhausted")
		}

		// Tenant B should still work
		if !limiter.TryAcquire("tenant-b") {
			t.Error("expected tenant-b to succeed")
		}
	})

	t.Run("custom tenant limits", func(t *testing.T) {
		limiter := NewMultiTenantRateLimiter(10, 5)

		// Give tenant-premium higher limits
		limiter.SetTenantLimit("tenant-premium", 100, 50)

		// Premium tenant should have higher burst
		for i := 0; i < 50; i++ {
			if !limiter.TryAcquire("tenant-premium") {
				t.Errorf("expected premium request %d to succeed", i)
			}
		}
	})

	t.Run("remove tenant", func(t *testing.T) {
		limiter := NewMultiTenantRateLimiter(10, 5)

		// Use some quota
		limiter.TryAcquire("tenant-temp")

		// Remove tenant
		limiter.RemoveTenant("tenant-temp")

		// New requests get fresh limiter
		for i := 0; i < 5; i++ {
			if !limiter.TryAcquire("tenant-temp") {
				t.Errorf("expected fresh quota for request %d", i)
			}
		}
	})
}

func TestRateLimitError(t *testing.T) {
	err := NewRateLimitError(5 * time.Second)

	if err.Message != "rate limit exceeded" {
		t.Errorf("expected default message, got %s", err.Message)
	}

	errStr := err.Error()
	if errStr == "" {
		t.Error("expected non-empty error string")
	}
}

func TestConcurrentRateLimiting(t *testing.T) {
	limiter := NewRateLimiter(1000, 100)
	ctx := context.Background()

	var wg sync.WaitGroup
	errors := make(chan error, 1000)

	// Launch many concurrent goroutines
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if err := limiter.Wait(ctx); err != nil {
					errors <- err
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent error: %v", err)
	}
}
