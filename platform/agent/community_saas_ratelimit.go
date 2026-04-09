// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

// ErrDailyLimitExceeded is returned when a tenant exceeds their daily request cap.
var ErrDailyLimitExceeded = errors.New("daily request limit exceeded")

// checkCommunityDailyLimit checks and increments the daily request counter for a tenant.
// Returns nil if under cap, ErrDailyLimitExceeded if the daily limit is reached.
//
// Primary path: Redis INCR with 25-hour expiry (avoids midnight window race).
// Fallback path: PostgreSQL atomic increment via increment_csaas_daily() function.
func checkCommunityDailyLimit(ctx context.Context, tenantID string, dailyCap int, db *sql.DB) error {
	// Try Redis first (fast path)
	if redisClient != nil {
		count, err := checkDailyLimitRedis(ctx, tenantID, dailyCap)
		if err == nil {
			if count > dailyCap {
				return ErrDailyLimitExceeded
			}
			return nil
		}
		// Redis failed — fall through to DB
		log.Printf("[CSAAS-RATELIMIT] Redis daily limit check failed, falling back to DB: %v", err)
	}

	// DB fallback path
	return checkDailyLimitDB(ctx, tenantID, dailyCap, db)
}

// checkDailyLimitRedis increments the daily counter in Redis and returns the new count.
// Key format: csaas:daily:{tenantID}:{YYYYMMDD_UTC}
// Expiry: 25 hours (avoids midnight race condition where key could expire mid-day
// if created late in the previous day due to timezone edge cases).
func checkDailyLimitRedis(ctx context.Context, tenantID string, dailyCap int) (int, error) {
	if redisClient == nil {
		return 0, fmt.Errorf("redis client not initialized")
	}

	dayKey := time.Now().UTC().Format("20060102")
	key := fmt.Sprintf("csaas:daily:%s:%s", tenantID, dayKey)

	// Atomic increment
	count, err := redisClient.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("redis INCR failed: %w", err)
	}

	// Set expiry on first increment (count == 1 means key was just created)
	if count == 1 {
		// 25 hours = 90000 seconds — ensures key outlives the UTC day boundary
		redisClient.Expire(ctx, key, 25*time.Hour)
	}

	return int(count), nil
}

// checkDailyLimitDB increments the daily counter in PostgreSQL and checks against the cap.
// Uses the increment_csaas_daily() function from migration 068 for atomic upsert.
func checkDailyLimitDB(ctx context.Context, tenantID string, dailyCap int, db *sql.DB) error {
	if db == nil {
		return ErrDatabaseUnavailable
	}

	var count int
	err := db.QueryRowContext(ctx,
		"SELECT increment_csaas_daily($1, CURRENT_DATE)", tenantID).Scan(&count)
	if err != nil {
		return fmt.Errorf("daily limit DB check failed: %w", err)
	}

	if count > dailyCap {
		return ErrDailyLimitExceeded
	}
	return nil
}

// getEnvInt reads an integer from an environment variable, returning defaultVal
// if the variable is unset or cannot be parsed.
func getEnvInt(key string, defaultVal int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	parsed, err := strconv.Atoi(val)
	if err != nil {
		log.Printf("[CONFIG] Invalid integer for %s=%q, using default %d", key, val, defaultVal)
		return defaultVal
	}
	return parsed
}
