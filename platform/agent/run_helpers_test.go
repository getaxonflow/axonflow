// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"testing"
)

// TestGetEnv covers the env helper used throughout startup configuration.
func TestGetEnv_RunHelpers(t *testing.T) {
	t.Run("returns env value when set", func(t *testing.T) {
		os.Setenv("AGENT_TEST_GETENV", "from-env")
		defer os.Unsetenv("AGENT_TEST_GETENV")
		got := getEnv("AGENT_TEST_GETENV", "default-value")
		if got != "from-env" {
			t.Errorf("Expected env value, got %q", got)
		}
	})

	t.Run("returns default when env unset", func(t *testing.T) {
		os.Unsetenv("AGENT_TEST_GETENV_UNSET")
		got := getEnv("AGENT_TEST_GETENV_UNSET", "the-default")
		if got != "the-default" {
			t.Errorf("Expected default value, got %q", got)
		}
	})

	t.Run("returns default when env empty string", func(t *testing.T) {
		os.Setenv("AGENT_TEST_GETENV_EMPTY", "")
		defer os.Unsetenv("AGENT_TEST_GETENV_EMPTY")
		got := getEnv("AGENT_TEST_GETENV_EMPTY", "fallback")
		if got != "fallback" {
			t.Errorf("Expected fallback for empty env, got %q", got)
		}
	})
}
