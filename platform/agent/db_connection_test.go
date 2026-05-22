// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// v9 Phase 8 — unit tests for the env-gated DB connection helpers.
// No DB connection required; these test pure env-var parsing logic.

import (
	"database/sql"
	"os"
	"testing"
)

// v9.0.0 (Brief 11.5 PR G): default flipped from false to true.
// Empty + unset both mean "true." Explicit "false"/"FALSE"/"0" disables.
func TestUseAppRoleEnabled(t *testing.T) {
	tests := []struct {
		envValue string
		want     bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", true},
		{"false", false},
		{"FALSE", false},
		{"False", false},
		{"0", false},
		{"", true},    // v9.0.0 default: empty → true
		{"yes", true}, // anything truthy-or-unknown → true (only explicit false-set disables)
		{"y", true},
		{"on", true},
	}
	for _, tc := range tests {
		t.Run("env="+tc.envValue, func(t *testing.T) {
			t.Setenv(EnvUseAppRole, tc.envValue)
			if got := UseAppRoleEnabled(); got != tc.want {
				t.Errorf("UseAppRoleEnabled() with %s=%q = %v, want %v", EnvUseAppRole, tc.envValue, got, tc.want)
			}
		})
	}

	// Explicit test for the unset (post-flip default) case — unset env var
	// returns "true" so v9.0.0 fresh deploys get app_role without any
	// configuration. Operators must explicitly opt OUT during transition.
	t.Run("unset_returns_true_v9_default", func(t *testing.T) {
		if err := os.Unsetenv(EnvUseAppRole); err != nil {
			t.Fatalf("unsetenv: %v", err)
		}
		if got := UseAppRoleEnabled(); !got {
			t.Errorf("UseAppRoleEnabled() with %s unset = %v, want true (v9.0.0 default)", EnvUseAppRole, got)
		}
	})
}

func TestResolveAppRoleDSN(t *testing.T) {
	const fallback = "postgres://master@localhost/db"
	const appRoleDSN = "postgres://app@localhost/db"

	// Gate OFF — always returns fallback.
	t.Run("gate_off_returns_fallback", func(t *testing.T) {
		t.Setenv(EnvUseAppRole, "false")
		t.Setenv(EnvAppRoleURL, appRoleDSN)
		if got := ResolveAppRoleDSN(fallback); got != fallback {
			t.Errorf("expected fallback %q, got %q", fallback, got)
		}
	})

	// Gate ON, app role DSN set — returns app role DSN.
	t.Run("gate_on_uses_app_role_dsn", func(t *testing.T) {
		t.Setenv(EnvUseAppRole, "true")
		t.Setenv(EnvAppRoleURL, appRoleDSN)
		if got := ResolveAppRoleDSN(fallback); got != appRoleDSN {
			t.Errorf("expected %q, got %q", appRoleDSN, got)
		}
	})

	// Gate ON, app role DSN UNSET — falls back to the supplied DSN.
	// Covers Docker-compose dev where the master == app role.
	t.Run("gate_on_no_dsn_falls_back", func(t *testing.T) {
		t.Setenv(EnvUseAppRole, "true")
		// Clear the env var explicitly.
		if err := os.Unsetenv(EnvAppRoleURL); err != nil {
			t.Fatalf("unsetenv: %v", err)
		}
		if got := ResolveAppRoleDSN(fallback); got != fallback {
			t.Errorf("expected fallback %q, got %q", fallback, got)
		}
	})
}

func TestResolvePlatformAdminDSN(t *testing.T) {
	const dsn = "postgres://admin@localhost/db"

	t.Run("returns_env_value", func(t *testing.T) {
		t.Setenv(EnvPlatformAdminURL, dsn)
		if got := ResolvePlatformAdminDSN(); got != dsn {
			t.Errorf("expected %q, got %q", dsn, got)
		}
	})

	t.Run("returns_empty_when_unset", func(t *testing.T) {
		if err := os.Unsetenv(EnvPlatformAdminURL); err != nil {
			t.Fatalf("unsetenv: %v", err)
		}
		if got := ResolvePlatformAdminDSN(); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})
}

// TestWithOrgScope_NilDB asserts nil-db is rejected before any work happens.
func TestWithOrgScope_NilDB(t *testing.T) {
	err := WithOrgScope(t.Context(), nil, "any-org", func(tx *sql.Tx) error { return nil })
	if err == nil {
		t.Fatal("expected error for nil db, got nil")
	}
}

// TestWithOrgScope_EmptyOrgID asserts the cross-org-by-accident guard fires.
func TestWithOrgScope_EmptyOrgID(t *testing.T) {
	err := WithOrgScope(t.Context(), &sql.DB{}, "", func(tx *sql.Tx) error { return nil })
	if err == nil {
		t.Fatal("expected error for empty orgID, got nil")
	}
}

// v9 Brief 11.5 PR E coverage shim: pins the env-unset branch of
// OpenPlatformAdminConnection, which is the deterministic path
// (returns nil, nil — falls back to caller's regular DB).
func TestOpenPlatformAdminConnection_UnsetReturnsNil(t *testing.T) {
	if err := os.Unsetenv(EnvPlatformAdminURL); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	db, err := OpenPlatformAdminConnection(t.Context(), 1)
	if err != nil {
		t.Errorf("expected nil err when env unset, got %v", err)
	}
	if db != nil {
		t.Errorf("expected nil db when env unset, got non-nil")
		_ = db.Close()
	}
}

// TestOpenPlatformAdminConnection_InvalidDSN exercises the connect-failure
// path: a malformed DSN should produce an error after maxRetries attempts.
// Coverage-focused — no real PG required.
func TestOpenPlatformAdminConnection_InvalidDSN(t *testing.T) {
	t.Setenv(EnvPlatformAdminURL, "postgres://nonexistent-host-12345.invalid:5432/db?connect_timeout=1&sslmode=disable")
	db, err := OpenPlatformAdminConnection(t.Context(), 1)
	if err == nil {
		t.Error("expected error for unreachable DSN, got nil")
		if db != nil {
			_ = db.Close()
		}
	}
	if db != nil {
		t.Error("expected nil db on connect failure")
		_ = db.Close()
	}
}
