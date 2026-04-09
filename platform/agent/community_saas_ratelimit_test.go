// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"os"
	"testing"
)

func TestCheckCommunityDailyLimit_NilDBAndRedis(t *testing.T) {
	// With both Redis and DB nil, should return ErrDatabaseUnavailable
	oldRedis := redisClient
	redisClient = nil
	defer func() { redisClient = oldRedis }()

	err := checkCommunityDailyLimit(context.Background(), "test-tenant", 500, nil)
	if err != ErrDatabaseUnavailable {
		t.Errorf("Expected ErrDatabaseUnavailable, got %v", err)
	}
}

func TestCheckDailyLimitDB_NilDB(t *testing.T) {
	err := checkDailyLimitDB(context.Background(), "test-tenant", 500, nil)
	if err != ErrDatabaseUnavailable {
		t.Errorf("Expected ErrDatabaseUnavailable, got %v", err)
	}
}

func TestCheckDailyLimitRedis_NilClient(t *testing.T) {
	oldRedis := redisClient
	redisClient = nil
	defer func() { redisClient = oldRedis }()

	_, err := checkDailyLimitRedis(context.Background(), "test-tenant", 500)
	if err == nil {
		t.Error("Expected error for nil redis client")
	}
}

func TestGetEnvInt_Default(t *testing.T) {
	os.Unsetenv("TEST_CSAAS_INT")
	got := getEnvInt("TEST_CSAAS_INT", 42)
	if got != 42 {
		t.Errorf("Expected default 42, got %d", got)
	}
}

func TestGetEnvInt_Override(t *testing.T) {
	os.Setenv("TEST_CSAAS_INT", "100")
	defer os.Unsetenv("TEST_CSAAS_INT")

	got := getEnvInt("TEST_CSAAS_INT", 42)
	if got != 100 {
		t.Errorf("Expected 100, got %d", got)
	}
}

func TestGetEnvInt_Invalid(t *testing.T) {
	os.Setenv("TEST_CSAAS_INT", "not-a-number")
	defer os.Unsetenv("TEST_CSAAS_INT")

	got := getEnvInt("TEST_CSAAS_INT", 42)
	if got != 42 {
		t.Errorf("Expected default 42 for invalid input, got %d", got)
	}
}

func TestGetEnvInt_Empty(t *testing.T) {
	os.Setenv("TEST_CSAAS_INT", "")
	defer os.Unsetenv("TEST_CSAAS_INT")

	got := getEnvInt("TEST_CSAAS_INT", 42)
	if got != 42 {
		t.Errorf("Expected default 42 for empty input, got %d", got)
	}
}

func TestGetEnvInt_Zero(t *testing.T) {
	os.Setenv("TEST_CSAAS_INT", "0")
	defer os.Unsetenv("TEST_CSAAS_INT")

	got := getEnvInt("TEST_CSAAS_INT", 42)
	if got != 0 {
		t.Errorf("Expected 0 (explicit zero), got %d", got)
	}
}

func TestGetEnvInt_Negative(t *testing.T) {
	os.Setenv("TEST_CSAAS_INT", "-5")
	defer os.Unsetenv("TEST_CSAAS_INT")

	got := getEnvInt("TEST_CSAAS_INT", 42)
	if got != -5 {
		t.Errorf("Expected -5, got %d", got)
	}
}
