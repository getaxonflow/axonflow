// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
)

// policyRedisClient is the Redis client for distributed rate limiting and budget tracking.
// When nil, the system falls back to in-memory storage.
var policyRedisClient *redis.Client

// InitPolicyRedis initializes the Redis connection for distributed policy enforcement.
// If Redis is unavailable, the system falls back to in-memory storage.
func InitPolicyRedis(redisURL string) error {
	if redisURL == "" {
		log.Println("ℹ️  REDIS_URL not set - using in-memory policy storage (rate limiting, budget tracking)")
		return nil
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	policyRedisClient = redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := policyRedisClient.Ping(ctx).Err(); err != nil {
		policyRedisClient = nil
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}

	log.Printf("✅ Redis connected for policy enforcement: %s", redisURL)
	return nil
}

// ClosePolicyRedis closes the Redis connection (call on shutdown).
func ClosePolicyRedis() error {
	if policyRedisClient != nil {
		return policyRedisClient.Close()
	}
	return nil
}

// IsPolicyRedisAvailable returns true if Redis is configured and connected.
func IsPolicyRedisAvailable() bool {
	return policyRedisClient != nil
}

// checkRateLimitRedis checks rate limit using Redis with sliding window algorithm.
// Returns (matched, allowed, blockReason).
func checkRateLimitRedis(ctx context.Context, key string, maxRequests, windowSeconds int) (bool, bool, string) {
	if policyRedisClient == nil {
		return false, true, "" // Not matched - fallback to in-memory
	}

	now := time.Now()
	redisKey := fmt.Sprintf("mcp:ratelimit:%s", key)

	// Use Redis pipeline for atomic operations
	pipe := policyRedisClient.Pipeline()

	// Remove timestamps older than the window (sliding window)
	minScore := now.Add(-time.Duration(windowSeconds) * time.Second).Unix()
	pipe.ZRemRangeByScore(ctx, redisKey, "0", fmt.Sprintf("%d", minScore))

	// Count requests in current window
	pipe.ZCard(ctx, redisKey)

	// Add current request timestamp
	pipe.ZAdd(ctx, redisKey, &redis.Z{
		Score:  float64(now.Unix()),
		Member: fmt.Sprintf("%d", now.UnixNano()),
	})

	// Set expiration (cleanup old keys)
	pipe.Expire(ctx, redisKey, time.Duration(windowSeconds*2)*time.Second)

	// Execute pipeline
	cmds, err := pipe.Exec(ctx)
	if err != nil {
		// On Redis error, fail open (allow request) and log
		log.Printf("[MCPDynamicPolicy] Redis rate limit check failed: %v (failing open)", err)
		return false, true, "" // Not matched - allow and let in-memory handle
	}

	// Get count from ZCARD result (index 1)
	count := cmds[1].(*redis.IntCmd).Val()

	if count >= int64(maxRequests) {
		return true, false, fmt.Sprintf("Rate limit exceeded: %d requests per %d seconds", maxRequests, windowSeconds)
	}

	return true, true, ""
}

// checkBudgetRedis checks budget using Redis with period-based tracking.
// Returns (matched, allowed, blockReason).
func checkBudgetRedis(ctx context.Context, key string, maxBudget, costPerRequest float64, periodDays int) (bool, bool, string) {
	if policyRedisClient == nil {
		return false, true, "" // Not matched - fallback to in-memory
	}

	redisKey := fmt.Sprintf("mcp:budget:%s", key)

	// Get current usage and period end
	pipe := policyRedisClient.Pipeline()
	usedCmd := pipe.HGet(ctx, redisKey, "used")
	periodEndCmd := pipe.HGet(ctx, redisKey, "period_end")
	_, _ = pipe.Exec(ctx)

	now := time.Now()
	var currentUsed float64
	var periodEnd time.Time

	// Parse current usage
	usedStr, err := usedCmd.Result()
	if err == nil {
		currentUsed, _ = strconv.ParseFloat(usedStr, 64)
	}

	// Parse period end
	periodEndStr, err := periodEndCmd.Result()
	if err == nil {
		periodEndUnix, _ := strconv.ParseInt(periodEndStr, 10, 64)
		periodEnd = time.Unix(periodEndUnix, 0)
	}

	// Check if period has expired
	if periodEnd.IsZero() || now.After(periodEnd) {
		// New period - reset usage
		newPeriodEnd := now.AddDate(0, 0, periodDays)
		pipe := policyRedisClient.Pipeline()
		pipe.HSet(ctx, redisKey, "used", fmt.Sprintf("%.6f", costPerRequest))
		pipe.HSet(ctx, redisKey, "period_end", fmt.Sprintf("%d", newPeriodEnd.Unix()))
		pipe.Expire(ctx, redisKey, time.Duration(periodDays+1)*24*time.Hour)
		if _, err := pipe.Exec(ctx); err != nil {
			log.Printf("[MCPDynamicPolicy] Redis budget reset failed: %v (failing open)", err)
			return false, true, ""
		}
		return true, true, ""
	}

	// Check if adding this request would exceed budget
	if currentUsed+costPerRequest > maxBudget {
		return true, false, fmt.Sprintf("Budget exceeded: $%.2f used of $%.2f limit", currentUsed, maxBudget)
	}

	// Increment usage
	if _, err := policyRedisClient.HIncrByFloat(ctx, redisKey, "used", costPerRequest).Result(); err != nil {
		log.Printf("[MCPDynamicPolicy] Redis budget increment failed: %v (failing open)", err)
		return false, true, ""
	}

	return true, true, ""
}

// ResetRateLimitRedis resets rate limit data for a key (admin operation).
func ResetRateLimitRedis(ctx context.Context, tenantID, userID, connectorName string) error {
	if policyRedisClient == nil {
		return fmt.Errorf("redis not initialized")
	}

	key := fmt.Sprintf("mcp:ratelimit:ratelimit:%s:%s:%s", tenantID, userID, connectorName)
	return policyRedisClient.Del(ctx, key).Err()
}

// ResetBudgetRedis resets budget data for a key (admin operation).
func ResetBudgetRedis(ctx context.Context, tenantID, userID string) error {
	if policyRedisClient == nil {
		return fmt.Errorf("redis not initialized")
	}

	key := fmt.Sprintf("mcp:budget:budget:%s:%s", tenantID, userID)
	return policyRedisClient.Del(ctx, key).Err()
}

// GetRateLimitStatusRedis returns current rate limit status from Redis.
func GetRateLimitStatusRedis(ctx context.Context, tenantID, userID, connectorName string, windowSeconds int) (int64, error) {
	if policyRedisClient == nil {
		return 0, fmt.Errorf("redis not initialized")
	}

	key := fmt.Sprintf("mcp:ratelimit:ratelimit:%s:%s:%s", tenantID, userID, connectorName)
	now := time.Now()
	minScore := now.Add(-time.Duration(windowSeconds) * time.Second).Unix()

	count, err := policyRedisClient.ZCount(ctx, key, fmt.Sprintf("%d", minScore), "+inf").Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get rate limit status: %w", err)
	}

	return count, nil
}

// GetBudgetStatusRedis returns current budget usage from Redis.
func GetBudgetStatusRedis(ctx context.Context, tenantID, userID string) (float64, time.Time, error) {
	if policyRedisClient == nil {
		return 0, time.Time{}, fmt.Errorf("redis not initialized")
	}

	key := fmt.Sprintf("mcp:budget:budget:%s:%s", tenantID, userID)

	pipe := policyRedisClient.Pipeline()
	usedCmd := pipe.HGet(ctx, key, "used")
	periodEndCmd := pipe.HGet(ctx, key, "period_end")
	_, _ = pipe.Exec(ctx)

	usedStr, _ := usedCmd.Result()
	used, _ := strconv.ParseFloat(usedStr, 64)

	periodEndStr, _ := periodEndCmd.Result()
	periodEndUnix, _ := strconv.ParseInt(periodEndStr, 10, 64)
	periodEnd := time.Unix(periodEndUnix, 0)

	return used, periodEnd, nil
}
