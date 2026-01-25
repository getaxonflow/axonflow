// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// TestInitPolicyRedis tests Redis initialization
func TestInitPolicyRedis(t *testing.T) {
	// Reset state before each test
	policyRedisClient = nil

	tests := []struct {
		name      string
		redisURL  string
		wantErr   bool
		wantNil   bool
		setupMock func() (string, func())
	}{
		{
			name:     "empty URL returns nil (fallback mode)",
			redisURL: "",
			wantErr:  false,
			wantNil:  true,
		},
		{
			name:     "invalid URL format returns error",
			redisURL: "not-a-valid-url",
			wantErr:  true,
			wantNil:  true,
		},
		{
			name:     "connection refused returns error",
			redisURL: "redis://localhost:59999", // unlikely to be running
			wantErr:  true,
			wantNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset state
			policyRedisClient = nil

			err := InitPolicyRedis(tt.redisURL)

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantNil && policyRedisClient != nil {
				t.Error("expected nil client, got non-nil")
			}
		})
	}
}

// TestInitPolicyRedis_WithMiniredis tests successful Redis initialization with miniredis
func TestInitPolicyRedis_WithMiniredis(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	// Reset state
	policyRedisClient = nil

	err = InitPolicyRedis(fmt.Sprintf("redis://%s", mr.Addr()))
	if err != nil {
		t.Fatalf("InitPolicyRedis failed: %v", err)
	}

	if policyRedisClient == nil {
		t.Error("expected non-nil client after successful init")
	}

	// Cleanup
	_ = ClosePolicyRedis()
}

// TestClosePolicyRedis tests Redis cleanup
func TestClosePolicyRedis(t *testing.T) {
	t.Run("nil client returns nil error", func(t *testing.T) {
		policyRedisClient = nil
		err := ClosePolicyRedis()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("connected client closes successfully", func(t *testing.T) {
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("failed to start miniredis: %v", err)
		}
		defer mr.Close()

		policyRedisClient = nil
		err = InitPolicyRedis(fmt.Sprintf("redis://%s", mr.Addr()))
		if err != nil {
			t.Fatalf("InitPolicyRedis failed: %v", err)
		}

		err = ClosePolicyRedis()
		if err != nil {
			t.Errorf("ClosePolicyRedis failed: %v", err)
		}
	})
}

// TestIsPolicyRedisAvailable tests availability check
func TestIsPolicyRedisAvailable(t *testing.T) {
	t.Run("returns false when not initialized", func(t *testing.T) {
		policyRedisClient = nil
		if IsPolicyRedisAvailable() {
			t.Error("expected false when client is nil")
		}
	})

	t.Run("returns true when initialized", func(t *testing.T) {
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("failed to start miniredis: %v", err)
		}
		defer mr.Close()

		policyRedisClient = nil
		err = InitPolicyRedis(fmt.Sprintf("redis://%s", mr.Addr()))
		if err != nil {
			t.Fatalf("InitPolicyRedis failed: %v", err)
		}
		defer ClosePolicyRedis()

		if !IsPolicyRedisAvailable() {
			t.Error("expected true when client is initialized")
		}
	})
}

// TestCheckRateLimitRedis tests Redis rate limiting
func TestCheckRateLimitRedis(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	policyRedisClient = nil
	err = InitPolicyRedis(fmt.Sprintf("redis://%s", mr.Addr()))
	if err != nil {
		t.Fatalf("InitPolicyRedis failed: %v", err)
	}
	defer ClosePolicyRedis()

	ctx := context.Background()

	t.Run("allows requests under limit", func(t *testing.T) {
		key := "test:ratelimit:under"
		maxRequests := 5
		windowSeconds := 60

		for i := 0; i < maxRequests; i++ {
			matched, allowed, reason := checkRateLimitRedis(ctx, key, maxRequests, windowSeconds)
			if !matched {
				t.Errorf("request %d: expected matched=true", i)
			}
			if !allowed {
				t.Errorf("request %d: expected allowed=true, reason=%s", i, reason)
			}
		}
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		key := "test:ratelimit:over"
		maxRequests := 2
		windowSeconds := 60

		// First two should be allowed
		for i := 0; i < maxRequests; i++ {
			_, allowed, _ := checkRateLimitRedis(ctx, key, maxRequests, windowSeconds)
			if !allowed {
				t.Errorf("request %d should be allowed", i)
			}
		}

		// Third should be blocked
		matched, allowed, reason := checkRateLimitRedis(ctx, key, maxRequests, windowSeconds)
		if !matched {
			t.Error("expected matched=true for blocked request")
		}
		if allowed {
			t.Error("expected allowed=false for request over limit")
		}
		if reason == "" {
			t.Error("expected non-empty block reason")
		}
	})

	t.Run("returns false matched when Redis unavailable", func(t *testing.T) {
		// Close Redis
		_ = ClosePolicyRedis()

		matched, allowed, _ := checkRateLimitRedis(ctx, "test:key", 10, 60)
		if matched {
			t.Error("expected matched=false when Redis unavailable")
		}
		if !allowed {
			t.Error("expected allowed=true (fail open) when Redis unavailable")
		}
	})
}

// TestCheckBudgetRedis tests Redis budget tracking
func TestCheckBudgetRedis(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	policyRedisClient = nil
	err = InitPolicyRedis(fmt.Sprintf("redis://%s", mr.Addr()))
	if err != nil {
		t.Fatalf("InitPolicyRedis failed: %v", err)
	}
	defer ClosePolicyRedis()

	ctx := context.Background()

	t.Run("allows requests under budget", func(t *testing.T) {
		key := "test:budget:under"
		maxBudget := 10.0
		costPerRequest := 1.0
		periodDays := 30

		for i := 0; i < 5; i++ {
			matched, allowed, reason := checkBudgetRedis(ctx, key, maxBudget, costPerRequest, periodDays)
			if !matched {
				t.Errorf("request %d: expected matched=true", i)
			}
			if !allowed {
				t.Errorf("request %d: expected allowed=true, reason=%s", i, reason)
			}
		}
	})

	t.Run("blocks requests over budget", func(t *testing.T) {
		key := "test:budget:over"
		maxBudget := 2.0
		costPerRequest := 1.0
		periodDays := 30

		// First two should be allowed ($0 -> $1, $1 -> $2)
		for i := 0; i < 2; i++ {
			_, allowed, _ := checkBudgetRedis(ctx, key, maxBudget, costPerRequest, periodDays)
			if !allowed {
				t.Errorf("request %d should be allowed", i)
			}
		}

		// Third should be blocked ($2 + $1 > $2 limit)
		matched, allowed, reason := checkBudgetRedis(ctx, key, maxBudget, costPerRequest, periodDays)
		if !matched {
			t.Error("expected matched=true for blocked request")
		}
		if allowed {
			t.Error("expected allowed=false for request over budget")
		}
		if reason == "" {
			t.Error("expected non-empty block reason")
		}
	})

	t.Run("returns false matched when Redis unavailable", func(t *testing.T) {
		// Close Redis
		_ = ClosePolicyRedis()

		matched, allowed, _ := checkBudgetRedis(ctx, "test:key", 10.0, 0.01, 30)
		if matched {
			t.Error("expected matched=false when Redis unavailable")
		}
		if !allowed {
			t.Error("expected allowed=true (fail open) when Redis unavailable")
		}
	})
}

// TestCheckBudgetRedis_PeriodReset tests budget period reset
func TestCheckBudgetRedis_PeriodReset(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	policyRedisClient = nil
	err = InitPolicyRedis(fmt.Sprintf("redis://%s", mr.Addr()))
	if err != nil {
		t.Fatalf("InitPolicyRedis failed: %v", err)
	}
	defer ClosePolicyRedis()

	ctx := context.Background()

	// First request establishes period
	key := "test:budget:period"
	maxBudget := 1.0
	costPerRequest := 0.5
	periodDays := 1

	// Use 50% of budget
	matched, allowed, _ := checkBudgetRedis(ctx, key, maxBudget, costPerRequest, periodDays)
	if !matched || !allowed {
		t.Error("first request should be allowed")
	}

	// Use remaining 50%
	matched, allowed, _ = checkBudgetRedis(ctx, key, maxBudget, costPerRequest, periodDays)
	if !matched || !allowed {
		t.Error("second request should be allowed")
	}

	// Budget exhausted
	matched, allowed, _ = checkBudgetRedis(ctx, key, maxBudget, costPerRequest, periodDays)
	if !matched {
		t.Error("expected matched=true")
	}
	if allowed {
		t.Error("third request should be blocked (over budget)")
	}
}

// TestResetRateLimitRedis tests rate limit reset
func TestResetRateLimitRedis(t *testing.T) {
	t.Run("returns error when Redis not initialized", func(t *testing.T) {
		policyRedisClient = nil
		err := ResetRateLimitRedis(context.Background(), "tenant", "user", "connector")
		if err == nil {
			t.Error("expected error when Redis not initialized")
		}
	})

	t.Run("successfully resets rate limit", func(t *testing.T) {
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("failed to start miniredis: %v", err)
		}
		defer mr.Close()

		policyRedisClient = nil
		err = InitPolicyRedis(fmt.Sprintf("redis://%s", mr.Addr()))
		if err != nil {
			t.Fatalf("InitPolicyRedis failed: %v", err)
		}
		defer ClosePolicyRedis()

		err = ResetRateLimitRedis(context.Background(), "tenant1", "user1", "connector1")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestResetBudgetRedis tests budget reset
func TestResetBudgetRedis(t *testing.T) {
	t.Run("returns error when Redis not initialized", func(t *testing.T) {
		policyRedisClient = nil
		err := ResetBudgetRedis(context.Background(), "tenant", "user")
		if err == nil {
			t.Error("expected error when Redis not initialized")
		}
	})

	t.Run("successfully resets budget", func(t *testing.T) {
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("failed to start miniredis: %v", err)
		}
		defer mr.Close()

		policyRedisClient = nil
		err = InitPolicyRedis(fmt.Sprintf("redis://%s", mr.Addr()))
		if err != nil {
			t.Fatalf("InitPolicyRedis failed: %v", err)
		}
		defer ClosePolicyRedis()

		err = ResetBudgetRedis(context.Background(), "tenant1", "user1")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestGetRateLimitStatusRedis tests rate limit status retrieval
func TestGetRateLimitStatusRedis(t *testing.T) {
	t.Run("returns error when Redis not initialized", func(t *testing.T) {
		policyRedisClient = nil
		_, err := GetRateLimitStatusRedis(context.Background(), "tenant", "user", "connector", 60)
		if err == nil {
			t.Error("expected error when Redis not initialized")
		}
	})

	t.Run("returns count of requests in window", func(t *testing.T) {
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("failed to start miniredis: %v", err)
		}
		defer mr.Close()

		policyRedisClient = nil
		err = InitPolicyRedis(fmt.Sprintf("redis://%s", mr.Addr()))
		if err != nil {
			t.Fatalf("InitPolicyRedis failed: %v", err)
		}
		defer ClosePolicyRedis()

		ctx := context.Background()

		// Make some requests
		key := "ratelimit:tenant1:user1:connector1"
		checkRateLimitRedis(ctx, key, 100, 60)
		checkRateLimitRedis(ctx, key, 100, 60)
		checkRateLimitRedis(ctx, key, 100, 60)

		count, err := GetRateLimitStatusRedis(ctx, "tenant1", "user1", "connector1", 60)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if count != 3 {
			t.Errorf("expected count=3, got %d", count)
		}
	})
}

// TestGetBudgetStatusRedis tests budget status retrieval
func TestGetBudgetStatusRedis(t *testing.T) {
	t.Run("returns error when Redis not initialized", func(t *testing.T) {
		policyRedisClient = nil
		_, _, err := GetBudgetStatusRedis(context.Background(), "tenant", "user")
		if err == nil {
			t.Error("expected error when Redis not initialized")
		}
	})

	t.Run("returns budget usage", func(t *testing.T) {
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("failed to start miniredis: %v", err)
		}
		defer mr.Close()

		policyRedisClient = nil
		err = InitPolicyRedis(fmt.Sprintf("redis://%s", mr.Addr()))
		if err != nil {
			t.Fatalf("InitPolicyRedis failed: %v", err)
		}
		defer ClosePolicyRedis()

		ctx := context.Background()

		// Make some requests
		key := "budget:tenant1:user1"
		checkBudgetRedis(ctx, key, 100.0, 0.5, 30)
		checkBudgetRedis(ctx, key, 100.0, 0.5, 30)

		used, periodEnd, err := GetBudgetStatusRedis(ctx, "tenant1", "user1")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if used < 0.9 || used > 1.1 { // Allow some floating point variance
			t.Errorf("expected used ~1.0, got %f", used)
		}
		if periodEnd.Before(time.Now()) {
			t.Error("expected periodEnd to be in the future")
		}
	})
}
