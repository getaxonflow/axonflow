// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3159 — tests for the SECOND half of the app-role admin-pool boot guard.
//
// RequirePlatformAdminOrFatal (the first half, tested in
// require_platform_admin_test.go) asks only "is AXONFLOW_DB_PLATFORM_ADMIN_URL
// a non-blank string?". It never asks whether that string produced a pool. So
// the guard passes, OpenPlatformAdminConnection fails, the caller degrades the
// failure to a WARNING, and the process boots green with every cross-org and
// pre-auth read routed onto a NOBYPASSRLS pool that returns zero rows instead
// of an error. On the portal that means every SCIM bearer token and every
// pre-auth API-key lookup resolves nothing, which the handlers report as an
// authentication failure — so the operator rotates a credential that was never
// wrong.
//
// The three ways in, none of which involve a forgotten variable:
//   - the DSN authenticates as the master/owner role, not
//     axonflow_platform_admin. assertConnectedRole correctly refuses it and the
//     refusal is swallowed;
//   - a brief database outage inside this three-attempt boot window;
//   - a rotated password that has not propagated to the secret yet.
//
// The load-bearing distinction under test is between an UNSET DSN — a
// deliberate single-role/dev posture that must keep booting — and a CONFIGURED
// DSN that yielded nothing, which is a misconfiguration and is fatal.

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nonNilPool returns a usable-looking *sql.DB without touching a database.
// sql.Open does not connect; it only validates the driver name. That is
// exactly the "a pool came back" input the guard takes.
func nonNilPool(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", "postgres://unused@127.0.0.1:1/none?sslmode=disable")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestPlatformAdminPoolGuardShouldFire covers the pure decision logic over the
// full cross-product of (gate, DSN configured, opener outcome).
func TestPlatformAdminPoolGuardShouldFire(t *testing.T) {
	openErr := errors.New("OpenPlatformAdminConnection: role assertion failed: expected current_user=\"axonflow_platform_admin\", got \"postgres\"")

	cases := []struct {
		name string
		// useAppRole "__UNSET__" exercises the v9.0.0 default (true).
		useAppRole    string
		platformAdmin string
		// pool is built by nonNilPool when true; nil otherwise.
		pool     bool
		openErr  error
		wantFire bool
		why      string
	}{
		{
			name:          "gate_off_never_fires_even_when_the_pool_failed",
			useAppRole:    "false",
			platformAdmin: "postgres://admin@localhost/db",
			pool:          false,
			openErr:       openErr,
			wantFire:      false,
			why:           "legacy v8.x posture: the master role bypasses RLS, so the admin pool is not required for correctness",
		},
		{
			name:          "dsn_unset_never_fires_this_is_the_documented_fallback",
			useAppRole:    "true",
			platformAdmin: "",
			pool:          false,
			openErr:       nil,
			wantFire:      false,
			why:           "(nil, nil) is OpenPlatformAdminConnection's documented 'caller must fall back' contract — a single-role dev portal and every unit test constructing an engine under app-role fixtures runs this way on purpose",
		},
		{
			name:          "dsn_whitespace_only_never_fires_agrees_with_the_sibling_guard",
			useAppRole:    "true",
			platformAdmin: "   ",
			pool:          false,
			openErr:       nil,
			wantFire:      false,
			why:           "whitespace-only is 'unset' to platformAdminGuardShouldFire, which already fires on it; the two halves must agree on what 'configured' means so no DSN falls between them",
		},
		{
			name:          "dsn_set_and_pool_obtained_is_the_green_path",
			useAppRole:    "true",
			platformAdmin: "postgres://admin@localhost/db",
			pool:          true,
			openErr:       nil,
			wantFire:      false,
			why:           "production happy path",
		},
		{
			// THE #3159 DEFECT. assertConnectedRole rejected a DSN pointing at
			// the wrong role; before this guard the rejection became a WARNING.
			name:          "dsn_set_but_open_failed_fires",
			useAppRole:    "true",
			platformAdmin: "postgres://admin@localhost/db",
			pool:          false,
			openErr:       openErr,
			wantFire:      true,
			why:           "the operator asked for an admin pool and did not get one",
		},
		{
			// Defensive: the opener should not return (nil, nil) once the DSN
			// is non-blank, but if it ever did, silently continuing is the
			// exact failure this guard exists to stop.
			name:          "dsn_set_but_nil_pool_with_no_error_fires",
			useAppRole:    "true",
			platformAdmin: "postgres://admin@localhost/db",
			pool:          false,
			openErr:       nil,
			wantFire:      true,
			why:           "a nil pool is unusable regardless of whether an error accompanied it",
		},
		{
			// The v9.0.0 default is app-role ON. An operator who never sets
			// USE_APP_ROLE is in the posture this guard protects.
			name:          "gate_unset_v9_default_dsn_set_open_failed_fires",
			useAppRole:    "__UNSET__",
			platformAdmin: "postgres://admin@localhost/db",
			pool:          false,
			openErr:       openErr,
			wantFire:      true,
			why:           "unset USE_APP_ROLE means true since v9.0.0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.useAppRole == "__UNSET__" {
				t.Setenv(EnvUseAppRole, "") // restore on cleanup; see note above
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

			var pool *sql.DB
			if tc.pool {
				pool = nonNilPool(t)
			}

			fire, msg := platformAdminPoolGuardShouldFire("TestCaller", pool, tc.openErr)
			if fire != tc.wantFire {
				t.Fatalf("platformAdminPoolGuardShouldFire: fire=%v want=%v — %s (msg=%q)",
					fire, tc.wantFire, tc.why, msg)
			}
			if !tc.wantFire {
				if msg != "" {
					t.Errorf("expected an empty message when the guard does not fire, got %q", msg)
				}
				return
			}

			if !strings.Contains(msg, "[TestCaller] FATAL:") {
				t.Errorf("expected the caller prefix so operators can grep which guard fired, got %q", msg)
			}
			if !strings.Contains(msg, EnvPlatformAdminURL) {
				t.Errorf("expected the message to name %s, got %q", EnvPlatformAdminURL, msg)
			}
			if !strings.Contains(msg, EnvUseAppRole) {
				t.Errorf("expected the message to name the gate variable %s so the operator has an opt-out, got %q", EnvUseAppRole, msg)
			}
			// The underlying failure must be reported verbatim, not summarised
			// away. "role assertion failed" is the difference between "fix your
			// DSN's credentials" and "your database was down for a moment".
			if tc.openErr != nil && !strings.Contains(msg, tc.openErr.Error()) {
				t.Errorf("expected the message to carry the opener's own error verbatim, got %q", msg)
			}
		})
	}
}

// TestRequirePlatformAdminPoolOrFatal_FiresFatal is the mutation gate: if a
// future change empties the wrapper body or inverts its condition, fatalfFn is
// never invoked and this fails.
func TestRequirePlatformAdminPoolOrFatal_FiresFatal(t *testing.T) {
	t.Setenv(EnvUseAppRole, "true")
	t.Setenv(EnvPlatformAdminURL, "postgres://admin@localhost/db")

	var fatalCalled bool
	var fatalMsg string
	prev := fatalfFn
	fatalfFn = func(format string, args ...any) {
		fatalCalled = true
		fatalMsg = fmt.Sprintf(format, args...)
	}
	defer func() { fatalfFn = prev }()

	RequirePlatformAdminPoolOrFatal("customer-portal", nil,
		errors.New("OpenPlatformAdminConnection: failed after 3 attempts: dial tcp: connect: connection refused"))

	if !fatalCalled {
		t.Fatal("expected fatalfFn to be invoked when the configured admin DSN yielded no pool under app-role — " +
			"without it the portal boots green, every SetAdminDB is skipped, and the pre-auth SCIM and API-key " +
			"lookups silently resolve nothing (#3159)")
	}
	if !strings.Contains(fatalMsg, "[customer-portal] FATAL:") {
		t.Errorf("expected the caller prefix in the FATAL message, got %q", fatalMsg)
	}
	if !strings.Contains(fatalMsg, "connection refused") {
		t.Errorf("expected the opener's error to survive into the FATAL message, got %q", fatalMsg)
	}
}

// TestRequirePlatformAdminPoolOrFatal_SingleRoleDevPortalStillBoots is the
// availability half of the contract, and the reason the guard keys on "DSN
// configured" rather than on "pool is nil".
//
// A single-role or owner-connected portal runs with no admin DSN at all and
// must keep booting exactly as it does today: the tables in question are
// ENABLE, not FORCE, RLS, and the owner bypasses ENABLE. Making a nil pool
// fatal unconditionally would refuse to start every dev compose stack and
// every unit test that builds an engine under app-role fixtures.
func TestRequirePlatformAdminPoolOrFatal_SingleRoleDevPortalStillBoots(t *testing.T) {
	t.Setenv(EnvUseAppRole, "true")
	if err := os.Unsetenv(EnvPlatformAdminURL); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}

	var fatalCalled bool
	prev := fatalfFn
	fatalfFn = func(format string, args ...any) { fatalCalled = true }
	defer func() { fatalfFn = prev }()

	// Exactly what OpenPlatformAdminConnection returns for an unset DSN.
	RequirePlatformAdminPoolOrFatal("customer-portal", nil, nil)

	if fatalCalled {
		t.Fatal("FATAL fired with no admin DSN configured — a single-role/dev portal must still boot; " +
			"the unset-DSN case belongs to RequirePlatformAdminOrFatal, not to this guard")
	}
}

// TestRequirePlatformAdminPoolOrFatal_LegacyPostureStillBoots covers the
// explicit v8.x opt-out: under AXONFLOW_DB_USE_APP_ROLE=false the connection is
// the table owner, RLS is dormant, and a failed admin pool is not a
// correctness problem.
func TestRequirePlatformAdminPoolOrFatal_LegacyPostureStillBoots(t *testing.T) {
	t.Setenv(EnvUseAppRole, "false")
	t.Setenv(EnvPlatformAdminURL, "postgres://admin@localhost/db")

	var fatalCalled bool
	prev := fatalfFn
	fatalfFn = func(format string, args ...any) { fatalCalled = true }
	defer func() { fatalfFn = prev }()

	RequirePlatformAdminPoolOrFatal("CSAAS-SWEEP", nil, errors.New("boom"))

	if fatalCalled {
		t.Fatal("FATAL fired under AXONFLOW_DB_USE_APP_ROLE=false — the legacy posture must remain unaffected")
	}
}

// TestRequirePlatformAdminPoolOrFatal_GreenPathBoots covers the production
// happy path: gate on, DSN set, pool obtained.
func TestRequirePlatformAdminPoolOrFatal_GreenPathBoots(t *testing.T) {
	t.Setenv(EnvUseAppRole, "true")
	t.Setenv(EnvPlatformAdminURL, "postgres://admin@localhost/db")

	var fatalCalled bool
	prev := fatalfFn
	fatalfFn = func(format string, args ...any) { fatalCalled = true }
	defer func() { fatalfFn = prev }()

	RequirePlatformAdminPoolOrFatal("customer-portal", nonNilPool(t), nil)

	if fatalCalled {
		t.Fatal("FATAL fired on the green path (gate on, DSN set, pool obtained)")
	}
}

// TestPlatformAdminGuards_CoverDisjointCases pins the relationship between the
// two halves, which is the whole point of #3159: neither is sufficient alone.
//
// Without this, someone reading either guard in isolation can reasonably
// conclude it already covers the other's case — which is precisely the reading
// that left the hole for five releases.
func TestPlatformAdminGuards_CoverDisjointCases(t *testing.T) {
	t.Setenv(EnvUseAppRole, "true")

	t.Run("dsn_unset_only_the_string_guard_fires", func(t *testing.T) {
		// t.Setenv first so the ORIGINAL value is restored at test end; a bare
		// os.Unsetenv leaks the unset state into every later test in this
		// package, which for an env-gated guard is a silent cross-test coupling.
		t.Setenv(EnvPlatformAdminURL, "")
		if err := os.Unsetenv(EnvPlatformAdminURL); err != nil {
			t.Fatalf("unsetenv: %v", err)
		}
		strFire, _ := platformAdminGuardShouldFire("X")
		poolFire, _ := platformAdminPoolGuardShouldFire("X", nil, nil)
		if !strFire {
			t.Error("the string guard must fire for an unset DSN under app-role")
		}
		if poolFire {
			t.Error("the pool guard must NOT fire for an unset DSN — that would break single-role deployments")
		}
	})

	t.Run("dsn_set_but_unusable_only_the_pool_guard_fires", func(t *testing.T) {
		t.Setenv(EnvPlatformAdminURL, "postgres://admin@localhost/db")
		strFire, _ := platformAdminGuardShouldFire("X")
		poolFire, _ := platformAdminPoolGuardShouldFire("X", nil, errors.New("role assertion failed"))
		if strFire {
			t.Error("the string guard must NOT fire when the DSN is set — this is exactly why it missed #3159")
		}
		if !poolFire {
			t.Error("the pool guard must fire when a configured DSN yields no pool")
		}
	})
}

// TestPlatformAdminPoolGuardIsWiredAtEveryBootPathSite is the census pin.
//
// #3159 R3 round 2. The first attempt at this pinned exactly ONE of the twelve
// call sites — the customer portal's, in that module's own source-scan test —
// and R3 proved the rest were unpinned by deleting the agent's Idempotency and
// HITL guards and watching this whole package stay green. Fixing the enumerated
// instance and not the class is the defect; this covers the class.
//
// Why a source scan rather than behaviour: each call site is a single
// non-behavioural line whose absence changes nothing observable until a
// misconfigured admin DSN reaches production, which is exactly what makes it
// deletable without any test noticing. The guard's own decision logic is
// covered by the tests above; what this adds is that the decision is actually
// CONSULTED, and where.
func TestPlatformAdminPoolGuardIsWiredAtEveryBootPathSite(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}

	// caller name -> file it must be wired in. The caller string is the guard's
	// log prefix, so a mismatch here is also what an operator greps for.
	want := map[string][]string{
		filepath.Join(repoRoot, "platform", "agent", "run.go"): {
			"Marketplace", "NodeMonitor", "CSAAS-SWEEP", "Idempotency",
			"HITL", "CSAAS-RECOVERY", "CSAAS-DELETE",
		},
		filepath.Join(repoRoot, "platform", "orchestrator", "run.go"): {
			"Idempotency", "NodeMonitor", "AuditRetention", "RLS-3039-ReadPool",
		},
	}

	total := 0
	for file, callers := range want {
		src, readErr := os.ReadFile(file)
		if readErr != nil {
			t.Fatalf("read %s: %v", file, readErr)
		}
		body := string(src)
		for _, caller := range callers {
			needle := "RequirePlatformAdminPoolOrFatal(\"" + caller + "\""
			if !strings.Contains(body, needle) {
				t.Errorf("%s: missing RequirePlatformAdminPoolOrFatal for %q — #3159 regression. Without it "+
					"a CONFIGURED but unusable admin DSN is degraded to a WARNING and this worker runs on a "+
					"NOBYPASSRLS pool that returns zero rows instead of an error.", filepath.Base(file), caller)
			}
			total++
		}
	}

	// The three sites that deliberately do NOT carry the guard, pinned in the
	// negative so re-adding one is a conscious act. Each is reachable while the
	// orchestrator is booting with an unreachable database, where a fatal turns
	// a degraded-but-serving governance plane into a crash-loop.
	for _, rel := range []string{
		filepath.Join("platform", "orchestrator", "connector_marketplace_handlers.go"),
		filepath.Join("platform", "orchestrator", "db_dynamic_policies.go"),
		filepath.Join("platform", "orchestrator", "dynamic_policy_engine.go"),
	} {
		src, readErr := os.ReadFile(filepath.Join(repoRoot, rel))
		if readErr != nil {
			t.Fatalf("read %s: %v", rel, readErr)
		}
		if strings.Contains(string(src), "RequirePlatformAdminPoolOrFatal(") {
			t.Errorf("%s: carries RequirePlatformAdminPoolOrFatal, which was deliberately removed. This site "+
				"is reachable while the orchestrator boots with an unreachable database (it gates on "+
				"DATABASE_URL being set, or is a constructor with test callers), so a fatal here converts a "+
				"database failover into a crash-loop — and zero orchestrator tasks is itself the fail-open "+
				"shape. If this is intentional, update the rationale at the site and here together.", rel)
		}
	}

	// The portal's own site is pinned in its module's source-scan test, which
	// cannot be read from here (separate Go module).
	if total != 11 {
		t.Errorf("expected to check 11 call sites outside the portal, checked %d — update this census "+
			"deliberately, not by adjusting the number", total)
	}
}
