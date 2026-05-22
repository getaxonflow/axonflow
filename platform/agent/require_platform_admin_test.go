// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Tests for the RequirePlatformAdminOrFatal boot guard.
//
// The guard exists to close the silent-fallback class of bug observed on
// csaas-prod 2026-05-21: when AXONFLOW_DB_USE_APP_ROLE=true (v9.0.0
// default) AND AXONFLOW_DB_PLATFORM_ADMIN_URL is unset, every worker that
// opens a cross-org admin pool silently falls back to a non-BYPASSRLS db
// handle. Under FORCE RLS that's metering/sweep/recovery/monitoring
// quietly returning 0 rows — undercounts, missed alerts, missed billing.

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestPlatformAdminGuardShouldFire covers the pure decision logic across
// the three input combinations.
func TestPlatformAdminGuardShouldFire(t *testing.T) {
	cases := []struct {
		name          string
		useAppRole    string
		platformAdmin string
		wantFire      bool
		wantMsgFrag   string
	}{
		{
			name:          "gate_off_never_fires",
			useAppRole:    "false",
			platformAdmin: "",
			wantFire:      false,
		},
		{
			name:          "gate_off_with_admin_dsn_set_also_no_op",
			useAppRole:    "false",
			platformAdmin: "postgres://admin@localhost/db",
			wantFire:      false,
		},
		{
			name:          "gate_on_with_admin_dsn_set_no_op",
			useAppRole:    "true",
			platformAdmin: "postgres://admin@localhost/db",
			wantFire:      false,
		},
		{
			name:          "gate_on_with_admin_dsn_unset_fires",
			useAppRole:    "true",
			platformAdmin: "",
			wantFire:      true,
			wantMsgFrag:   "AXONFLOW_DB_PLATFORM_ADMIN_URL is required",
		},
		{
			// Unset USE_APP_ROLE means true (v9.0.0 default). Operator who
			// simply does not set USE_APP_ROLE OR PLATFORM_ADMIN_URL must
			// hit the guard — that's the exact misconfiguration we want to
			// catch.
			name:          "gate_unset_v9_default_with_admin_unset_fires",
			useAppRole:    "__UNSET__",
			platformAdmin: "",
			wantFire:      true,
			wantMsgFrag:   "AXONFLOW_DB_PLATFORM_ADMIN_URL is required",
		},
		{
			// Whitespace-only DSN (typo in CFN params or a YAML quoting
			// accident — `AXONFLOW_DB_PLATFORM_ADMIN_URL: " "`). Without
			// the TrimSpace guard the binary would boot and then crash
			// later inside pq.URL parsing with an opaque error. The guard
			// must treat whitespace-only as unset.
			name:          "gate_on_with_whitespace_admin_dsn_fires",
			useAppRole:    "true",
			platformAdmin: "   ",
			wantFire:      true,
			wantMsgFrag:   "AXONFLOW_DB_PLATFORM_ADMIN_URL is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.useAppRole == "__UNSET__" {
				if err := os.Unsetenv(EnvUseAppRole); err != nil {
					t.Fatalf("unsetenv USE_APP_ROLE: %v", err)
				}
			} else {
				t.Setenv(EnvUseAppRole, tc.useAppRole)
			}
			if tc.platformAdmin == "" {
				if err := os.Unsetenv(EnvPlatformAdminURL); err != nil {
					t.Fatalf("unsetenv PLATFORM_ADMIN_URL: %v", err)
				}
			} else {
				t.Setenv(EnvPlatformAdminURL, tc.platformAdmin)
			}

			fire, msg := platformAdminGuardShouldFire("TestCaller")
			if fire != tc.wantFire {
				t.Errorf("platformAdminGuardShouldFire: fire=%v want=%v (msg=%q)", fire, tc.wantFire, msg)
			}
			if tc.wantFire {
				if !strings.Contains(msg, tc.wantMsgFrag) {
					t.Errorf("expected msg to contain %q, got %q", tc.wantMsgFrag, msg)
				}
				if !strings.Contains(msg, "[TestCaller]") {
					t.Errorf("expected msg to contain [TestCaller] prefix, got %q", msg)
				}
				if !strings.Contains(msg, "AXONFLOW_DB_USE_APP_ROLE=true") {
					t.Errorf("expected msg to name the toggling env var with =true semantics, got %q", msg)
				}
			}
		})
	}
}

// TestRequirePlatformAdminOrFatal_FiresFatal verifies the wrapper hands a
// formatted message to the fatalfFn. By swapping fatalfFn in the test we
// observe the FATAL invocation without terminating the test process.
//
// This is the mutation-gate test: if a future change makes
// RequirePlatformAdminOrFatal a no-op (e.g. someone deletes the body, or
// inverts the if), this test fails because fatalfFn is never called.
func TestRequirePlatformAdminOrFatal_FiresFatal(t *testing.T) {
	t.Setenv(EnvUseAppRole, "true")
	if err := os.Unsetenv(EnvPlatformAdminURL); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}

	var fatalCalled bool
	var fatalMsg string
	prev := fatalfFn
	fatalfFn = func(format string, args ...any) {
		fatalCalled = true
		fatalMsg = fmt.Sprintf(format, args...)
	}
	defer func() { fatalfFn = prev }()

	RequirePlatformAdminOrFatal("Marketplace")

	if !fatalCalled {
		t.Fatal("expected fatalfFn to be invoked when USE_APP_ROLE=true + PLATFORM_ADMIN_URL unset, but it was not (refuse-to-boot guard is broken or removed)")
	}
	if !strings.Contains(fatalMsg, "[Marketplace] FATAL:") {
		t.Errorf("expected FATAL message to include the caller prefix, got %q", fatalMsg)
	}
	if !strings.Contains(fatalMsg, EnvPlatformAdminURL) {
		t.Errorf("expected FATAL message to name the missing env var (%s), got %q", EnvPlatformAdminURL, fatalMsg)
	}
	if !strings.Contains(fatalMsg, EnvUseAppRole+"=true") {
		t.Errorf("expected FATAL message to name the gate env var (%s=true), got %q", EnvUseAppRole, fatalMsg)
	}
}

// TestRequirePlatformAdminOrFatal_NoOpUnderLegacyPosture covers the
// must-not-fire branch. Operators who explicitly opt out of the v9.0.0
// default (AXONFLOW_DB_USE_APP_ROLE=false) MUST NOT be blocked by the
// guard, even when the admin DSN is unset — that's the legacy v8.x
// posture where the master role bypasses RLS.
func TestRequirePlatformAdminOrFatal_NoOpUnderLegacyPosture(t *testing.T) {
	t.Setenv(EnvUseAppRole, "false")
	if err := os.Unsetenv(EnvPlatformAdminURL); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}

	var fatalCalled bool
	prev := fatalfFn
	fatalfFn = func(format string, args ...any) {
		fatalCalled = true
	}
	defer func() { fatalfFn = prev }()

	RequirePlatformAdminOrFatal("CSAAS-SWEEP")

	if fatalCalled {
		t.Fatal("FATAL fired under AXONFLOW_DB_USE_APP_ROLE=false — guard must be a no-op under the legacy posture (community-mode docker-compose runs this way)")
	}
}

// TestRequirePlatformAdminOrFatal_NoOpWhenAdminDsnSet covers the green-path
// branch: gate on AND admin DSN set is the production happy path; the
// guard must not fire.
func TestRequirePlatformAdminOrFatal_NoOpWhenAdminDsnSet(t *testing.T) {
	t.Setenv(EnvUseAppRole, "true")
	t.Setenv(EnvPlatformAdminURL, "postgres://admin@localhost/db")

	var fatalCalled bool
	prev := fatalfFn
	fatalfFn = func(format string, args ...any) {
		fatalCalled = true
	}
	defer func() { fatalfFn = prev }()

	RequirePlatformAdminOrFatal("CSAAS-RECOVERY")

	if fatalCalled {
		t.Fatal("FATAL fired when both USE_APP_ROLE=true and PLATFORM_ADMIN_URL is set — green-path production wiring must boot cleanly")
	}
}
