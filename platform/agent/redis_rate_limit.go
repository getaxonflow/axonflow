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

package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// ============================================================
// Redis-Backed Distributed Rate Limiting (Option 3)
// ============================================================

var redisClient *redis.Client

// initRedis initializes the Redis connection pool
func initRedis(redisURL string) error {
	// Parse Redis URL (format: redis://host:port or redis://host:port/db)
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	// Create Redis client with connection pool
	redisClient = redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}

	fmt.Printf("✅ Redis connected: %s\n", redisURL)
	return nil
}

// checkRateLimitRedis checks rate limit using Redis with sliding window algorithm
// Returns error if rate limit exceeded, nil if within limit
func checkRateLimitRedis(ctx context.Context, customerID string, limitPerMinute int) error {
	if redisClient == nil {
		// Fallback to in-memory rate limiting if Redis unavailable
		return checkRateLimit(customerID, limitPerMinute)
	}

	now := time.Now()
	key := fmt.Sprintf("ratelimit:%s", customerID)

	// Use Redis pipeline for atomic operations
	pipe := redisClient.Pipeline()

	// Remove timestamps older than 1 minute (sliding window)
	minScore := now.Add(-time.Minute).Unix()
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", minScore))

	// Count requests in current window
	pipe.ZCard(ctx, key)

	// Add current request timestamp
	pipe.ZAdd(ctx, key, &redis.Z{
		Score:  float64(now.Unix()),
		Member: fmt.Sprintf("%d", now.UnixNano()),
	})

	// Set expiration (cleanup old keys)
	pipe.Expire(ctx, key, 2*time.Minute)

	// Execute pipeline
	cmds, err := pipe.Exec(ctx)
	if err != nil {
		// On Redis error, fail open (allow request) and log
		fmt.Printf("Warning: Redis rate limit check failed for %s: %v (failing open)\n", customerID, err)
		return nil
	}

	// Get count from ZCARD result (index 1)
	count := cmds[1].(*redis.IntCmd).Val()

	if count > int64(limitPerMinute) {
		return fmt.Errorf("rate limit exceeded: %d requests/minute (limit: %d)", count, limitPerMinute)
	}

	return nil
}

// getRateLimitStatusRedis returns current rate limit status from Redis
func getRateLimitStatusRedis(ctx context.Context, customerID string) (int, time.Time, error) {
	if redisClient == nil {
		count, _, resetTime := getRateLimitStatus(customerID)
		return count, resetTime, nil
	}

	key := fmt.Sprintf("ratelimit:%s", customerID)
	now := time.Now()

	// Count requests in current window
	minScore := now.Add(-time.Minute).Unix()
	count, err := redisClient.ZCount(ctx, key, fmt.Sprintf("%d", minScore), "+inf").Result()
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("failed to get rate limit status: %w", err)
	}

	// Rate limit resets at the start of next minute
	resetTime := now.Truncate(time.Minute).Add(time.Minute)

	return int(count), resetTime, nil
}

// getRateLimitStatsRedis retrieves detailed rate limit statistics for monitoring
func getRateLimitStatsRedis(ctx context.Context, customerID string, duration time.Duration) (*RateLimitStats, error) {
	if redisClient == nil {
		return nil, fmt.Errorf("redis not initialized")
	}

	key := fmt.Sprintf("ratelimit:%s", customerID)
	now := time.Now()
	startTime := now.Add(-duration)

	// Get all timestamps in the duration window
	timestamps, err := redisClient.ZRangeByScore(ctx, key, &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", startTime.Unix()),
		Max: "+inf",
	}).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to get rate limit stats: %w", err)
	}

	return &RateLimitStats{
		CustomerID:   customerID,
		RequestCount: len(timestamps),
		WindowStart:  startTime,
		WindowEnd:    now,
		Duration:     duration,
	}, nil
}

// RateLimitStats represents rate limit statistics
type RateLimitStats struct {
	CustomerID   string
	RequestCount int
	WindowStart  time.Time
	WindowEnd    time.Time
	Duration     time.Duration
}

// flushRateLimitRedis removes all rate limit data for a customer (admin operation)
func flushRateLimitRedis(ctx context.Context, customerID string) error {
	if redisClient == nil {
		return fmt.Errorf("redis not initialized")
	}

	key := fmt.Sprintf("ratelimit:%s", customerID)
	if err := redisClient.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to flush rate limit data: %w", err)
	}

	return nil
}

// closeRedis closes the Redis connection (cleanup on shutdown)
func closeRedis() error {
	if redisClient != nil {
		return redisClient.Close()
	}
	return nil
}
