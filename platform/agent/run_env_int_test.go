// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"testing"
)

// TestEnvIntDefault covers the parser used by circuit-breaker threshold
// overrides + future numeric env knobs. Three paths:
//
//  1. unset → default
//  2. set + valid int → parsed value
//  3. set + invalid int → default (with warning), NOT zero
//
// The third path is the load-bearing one — a typo in
// AXONFLOW_CB_POLICY_VIOLATION_THRESHOLD shouldn't silently drop the breaker
// to "trip on the first violation" (effectively zero). Validate the fallback.
func TestEnvIntDefault(t *testing.T) {
	const key = "AXONFLOW_TEST_ENV_INT_DEFAULT"

	t.Run("unset_returns_default", func(t *testing.T) {
		os.Unsetenv(key)
		if got := envIntDefault(key, 42); got != 42 {
			t.Errorf("unset: got %d, want default 42", got)
		}
	})

	t.Run("valid_int_parsed", func(t *testing.T) {
		os.Setenv(key, "1000")
		t.Cleanup(func() { os.Unsetenv(key) })
		if got := envIntDefault(key, 42); got != 1000 {
			t.Errorf("valid: got %d, want 1000", got)
		}
	})

	t.Run("zero_is_honored", func(t *testing.T) {
		os.Setenv(key, "0")
		t.Cleanup(func() { os.Unsetenv(key) })
		if got := envIntDefault(key, 42); got != 0 {
			t.Errorf("zero: got %d, want 0", got)
		}
	})

	t.Run("negative_is_honored", func(t *testing.T) {
		os.Setenv(key, "-5")
		t.Cleanup(func() { os.Unsetenv(key) })
		if got := envIntDefault(key, 42); got != -5 {
			t.Errorf("negative: got %d, want -5", got)
		}
	})

	t.Run("invalid_falls_back_to_default", func(t *testing.T) {
		os.Setenv(key, "not-a-number")
		t.Cleanup(func() { os.Unsetenv(key) })
		if got := envIntDefault(key, 42); got != 42 {
			t.Errorf("invalid: got %d, want default 42 (typo must NOT silently drop to zero)", got)
		}
	})

	t.Run("empty_string_returns_default", func(t *testing.T) {
		os.Setenv(key, "")
		t.Cleanup(func() { os.Unsetenv(key) })
		if got := envIntDefault(key, 42); got != 42 {
			t.Errorf("empty: got %d, want default 42", got)
		}
	})
}
