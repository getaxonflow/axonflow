// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// v9 Phase 8 RLS — DB connection acquisition with role gating.
//
// Two new env vars opt the agent into the RLS-enforcing connection roles
// created by migration 098_v9_rls_roles.sql:
//
//   AXONFLOW_DB_USE_APP_ROLE=true (DEFAULT in v9.0.0)
//     - Normal request traffic uses axonflow_app_role (no BYPASSRLS).
//     - DSN is read from AXONFLOW_DB_APP_ROLE_URL (separate Secrets Manager entry).
//     - Falls back to DATABASE_URL if AXONFLOW_DB_APP_ROLE_URL is not set, so
//       Docker-compose dev where the master == app role works without two env
//       vars. (Production must set both.)
//
//   AXONFLOW_DB_USE_APP_ROLE=false (legacy v8.x default; explicit override only)
//     - Connects as the table owner / RDS master. FORCE RLS effectively
//       dormant because the master role bypasses RLS.
//     - v9.0.0 flipped the default to true (Brief 11.5). Operators
//       upgrading from v8.x MUST verify cross-org workers route through
//       axonflow_platform_admin (via AXONFLOW_DB_PLATFORM_ADMIN_URL)
//       BEFORE the upgrade; the sweep + recovery + node-monitor workers
//       silently return 0 rows on cross-org queries without it.
//     - Set explicitly to "false" to override the v9.0.0 default during
//       a phased rollout.
//
// Cross-org workers (sweep, mirror, bridge, aggregators) use:
//
//   AXONFLOW_DB_PLATFORM_ADMIN_URL=<dsn>
//     - Workers that genuinely iterate across orgs open a SECOND connection
//       to this DSN, which authenticates as axonflow_platform_admin (BYPASSRLS).
//     - This env is consumed by the worker code paths individually; the agent's
//       main authDB/usageDB DO NOT pick this up automatically.

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const (
	// EnvUseAppRole gates whether the agent opens its main DB connection as
	// the non-BYPASSRLS axonflow_app_role. Default TRUE in v9.0.0 (Brief 11.5);
	// was false in v8.x. Set explicitly to "false" to override for phased rollout.
	EnvUseAppRole = "AXONFLOW_DB_USE_APP_ROLE"

	// EnvAppRoleURL holds the DSN that authenticates as axonflow_app_role.
	// Falls back to DATABASE_URL when unset.
	EnvAppRoleURL = "AXONFLOW_DB_APP_ROLE_URL"

	// EnvPlatformAdminURL holds the DSN that authenticates as
	// axonflow_platform_admin (BYPASSRLS). Cross-org workers open a SEPARATE
	// connection to this DSN. The main agent process does not consume this.
	EnvPlatformAdminURL = "AXONFLOW_DB_PLATFORM_ADMIN_URL"
)

// UseAppRoleEnabled returns true when AXONFLOW_DB_USE_APP_ROLE is set to
// any truthy value OR is unset (v9.0.0 default).
//
// v9.0.0 (Brief 11.5 PR G): flipped the default from false to true. Empty
// string + unset both mean "use app role" now. Set explicitly to "false"
// (or "0", "FALSE") to override during a phased v8.x→v9.0.0 rollout.
//
// Implementation note: the previous v8.x logic was "default false, any
// truthy value enables." The new v9.0.0 logic is "default true, any
// explicit falsy value disables." This is a controlled behavior change
// captured in CHANGELOG [9.0.0].
func UseAppRoleEnabled() bool {
	switch os.Getenv(EnvUseAppRole) {
	case "false", "FALSE", "False", "0":
		return false
	}
	return true
}

// ResolveAppRoleDSN returns the DSN to use for the main request-traffic
// connection. When UseAppRoleEnabled() is true, it prefers
// AXONFLOW_DB_APP_ROLE_URL; otherwise it returns the supplied fallback (the
// existing dbURL the agent already resolved from DATABASE_URL + parts).
//
// When the gate is on but no explicit app-role DSN is set, we fall back to the
// supplied URL. This keeps Docker-compose dev workable, where the master role
// IS the app role for testing convenience. Production must always set the
// dedicated env.
func ResolveAppRoleDSN(fallback string) string {
	if !UseAppRoleEnabled() {
		return fallback
	}
	if appURL := os.Getenv(EnvAppRoleURL); appURL != "" {
		return appURL
	}
	return fallback
}

// ResolvePlatformAdminDSN returns the DSN for the cross-org admin connection.
// Workers call this directly; the main agent does not.
//
// Returns the empty string when AXONFLOW_DB_PLATFORM_ADMIN_URL is unset.
// Workers MUST treat empty as "fall back to single-role behavior" (i.e., the
// worker still connects as the regular role and hopes SET LOCAL is wired);
// production deployments running under FORCE RLS for any worker-touched table
// MUST set this env var.
func ResolvePlatformAdminDSN() string {
	return os.Getenv(EnvPlatformAdminURL)
}

// fatalfFn is overridable so tests can capture the FATAL invocation without
// terminating the test process. Production uses log.Fatalf, which calls
// os.Exit(1) after logging.
var fatalfFn = log.Fatalf

// platformAdminGuardShouldFire returns (true, message) when boot must abort
// because AXONFLOW_DB_USE_APP_ROLE=true (v9.0.0 default) AND
// AXONFLOW_DB_PLATFORM_ADMIN_URL is unset — the combination would silently
// degrade cross-org workers to a non-BYPASSRLS pool. Returns (false, "")
// when the guard is a no-op (gate off OR admin DSN present).
//
// Split out from RequirePlatformAdminOrFatal so the decision logic is unit
// testable without subprocess gymnastics.
//
// SCOPE (#3159): this half tests only that the DSN is a non-blank STRING. It
// deliberately says nothing about whether that string yields a usable pool —
// that is platformAdminPoolGuardShouldFire's job, and it must be called too.
// Neither half is sufficient alone: this one passes for a DSN pointing at the
// wrong role, that one no-ops when the DSN is absent.
func platformAdminGuardShouldFire(caller string) (bool, string) {
	if !UseAppRoleEnabled() {
		return false, ""
	}
	// TrimSpace catches whitespace-only DSNs (typo in CFN params, YAML quoting
	// accident). Otherwise the binary would boot only to fail later inside
	// OpenPlatformAdminConnection with an opaque pq.URL parse error instead of
	// this guard's actionable FATAL message.
	if strings.TrimSpace(os.Getenv(EnvPlatformAdminURL)) != "" {
		return false, ""
	}
	msg := fmt.Sprintf("[%s] FATAL: %s is required when %s=true (silent fallback to a non-BYPASSRLS pool would defeat FORCE RLS — cross-org metering/sweep/recovery/monitoring would silently return 0 rows or undercount). Set %s to a DSN authenticating as axonflow_platform_admin, or set %s=false to opt out of the v9.0.0 default and run under the legacy v8.x posture.",
		caller, EnvPlatformAdminURL, EnvUseAppRole, EnvPlatformAdminURL, EnvUseAppRole)
	return true, msg
}

// platformAdminPoolGuardShouldFire is the SECOND half of the app-role admin-pool
// boot guard, and it closes the hole platformAdminGuardShouldFire leaves open:
// that one tests only that AXONFLOW_DB_PLATFORM_ADMIN_URL is a non-blank
// STRING, never that a pool was actually obtained from it (#3159).
//
// The gap is not theoretical, and none of the ways in involve a forgotten
// variable — the operator set it, so the first guard passes:
//
//   - the DSN authenticates as the master/owner role rather than
//     axonflow_platform_admin. OpenPlatformAdminConnection's assertConnectedRole
//     correctly refuses it, and the refusal is then swallowed by the caller's
//     "log a WARNING and carry on with the RLS-blind pool" branch;
//   - a brief database outage inside this three-attempt boot window, while the
//     main pool's five attempts succeed;
//   - a rotated password that has not propagated to this secret yet.
//
// In every one of them the process boots green and every cross-org / pre-auth
// read it was supposed to route through BYPASSRLS silently runs on a
// NOBYPASSRLS pool instead — returning zero rows rather than an error. That is
// the same silent corruption RequirePlatformAdminOrFatal exists to prevent, so
// it gets the same answer: refuse to boot.
//
// Returns (true, message) ONLY when all three hold:
//
//	AXONFLOW_DB_USE_APP_ROLE is on (the v9.0.0 default), AND
//	AXONFLOW_DB_PLATFORM_ADMIN_URL is non-blank, AND
//	no usable pool came back (adminErr != nil, or a nil pool).
//
// The non-blank DSN condition is what keeps this narrow. An UNSET DSN is a
// deliberate posture, not a failure: OpenPlatformAdminConnection documents
// (nil, nil) as "caller must fall back", a single-role dev portal and an
// owner-connected deployment run that way on purpose, and unit tests build
// engines under app-role fixtures with no admin DSN at all. That case is
// untouched — owned by RequirePlatformAdminOrFatal at the sites that mandate
// the DSN, and a warning everywhere else.
//
// WHERE THIS IS AND IS NOT CALLED, precisely. An earlier revision of this
// comment claimed the guard "adds no new fatal to any topology that boots
// today". That was too strong, and R3 falsified it: the orchestrator is
// designed to boot with an unreachable database (run.go degrades usageDB to
// nil and continues), so a fatal on a site reachable in that state converts an
// RDS failover into a crash-loop — and zero orchestrator tasks is itself the
// #3048/#3049 fail-open shape.
//
// So the guard is applied only where a failed admin pool cannot make things
// worse than the process already is:
//
//   - the customer portal, which already log.Fatalf's if its MAIN pool fails;
//   - the agent's worker pools, all of which sit past a log.Fatal that refuses
//     to start without DATABASE_URL at all;
//   - the four orchestrator sites inside `if usageDB != nil`, i.e. skipped
//     entirely in the degraded-database state.
//
// It is deliberately NOT applied to initializeConnectorRegistry (gates on
// DATABASE_URL being set rather than on the pool being usable, so it IS
// reachable while degraded), nor to the two dynamic-policy engine
// constructors, whose own comments forbid a fatal because their 16 test call
// sites would os.Exit the test binary. Those residual gaps are stated at each
// site rather than papered over.
//
// What remains true: this fires only where the operator asked for an admin
// pool and did not get one.
//
// Split out from RequirePlatformAdminPoolOrFatal so the decision logic is unit
// testable without subprocess gymnastics, mirroring platformAdminGuardShouldFire.
func platformAdminPoolGuardShouldFire(caller string, adminDB *sql.DB, adminErr error) (bool, string) {
	if !UseAppRoleEnabled() {
		return false, ""
	}
	// An unset (or whitespace-only) DSN is the documented fall-back contract,
	// not a failed pool. Same TrimSpace as the sibling guard so the two agree
	// on what "configured" means and no DSN falls between them.
	if strings.TrimSpace(os.Getenv(EnvPlatformAdminURL)) == "" {
		return false, ""
	}
	if adminErr == nil && adminDB != nil {
		return false, ""
	}

	// Report the observed failure and no more. This guard can see that the
	// gate is on, that the DSN is non-blank, and what the opener returned; it
	// cannot see WHICH of the causes above applies, so they are offered as
	// candidates rather than asserted.
	detail := "OpenPlatformAdminConnection returned a nil pool with no error"
	if adminErr != nil {
		detail = adminErr.Error()
	}
	msg := fmt.Sprintf("[%s] FATAL: %s is set but no usable axonflow_platform_admin pool was obtained (%s). Booting on would silently route cross-org and pre-auth reads through a NOBYPASSRLS pool, which returns 0 rows instead of an error. Check, in order: the DSN authenticates as axonflow_platform_admin (not the master/owner role); the database was reachable during startup; the credential in the secret is current. Set %s=false to opt out of the v9.0.0 app-role posture, or unset %s to run single-role deliberately.",
		caller, EnvPlatformAdminURL, detail, EnvUseAppRole, EnvPlatformAdminURL)
	return true, msg
}

// RequirePlatformAdminPoolOrFatal aborts boot when the configured admin DSN did
// not yield a usable BYPASSRLS pool under the app-role posture (#3159).
//
// Call it immediately after OpenPlatformAdminConnection and BEFORE the caller's
// own "fall back to the ordinary pool" branch — that branch is the defect, and
// this makes it unreachable in the posture where it corrupts. caller is the
// same human-readable worker name RequirePlatformAdminOrFatal takes, so a
// single grep finds either half of the guard.
//
// No-op when the gate is off, when the DSN is unset, or when a pool was
// obtained. See platformAdminPoolGuardShouldFire for why an unset DSN is
// deliberately excluded.
func RequirePlatformAdminPoolOrFatal(caller string, adminDB *sql.DB, adminErr error) {
	if fire, msg := platformAdminPoolGuardShouldFire(caller, adminDB, adminErr); fire {
		fatalfFn("%s", msg)
	}
}

// RequirePlatformAdminOrFatal is the boot-time guard that closes the silent
// master-role fallback in worker pools. When AXONFLOW_DB_USE_APP_ROLE=true
// (the v9.0.0 default) AND AXONFLOW_DB_PLATFORM_ADMIN_URL is unset, any
// caller of OpenPlatformAdminConnection would silently fall back to the
// supplied (master/app-role) db pool; under FORCE RLS that pool either
// bypasses the policy entirely (master) or returns 0 rows on cross-org
// queries (app-role). Both outcomes are silent corruption of cross-org
// metering/sweep/recovery/monitoring.
//
// Callers invoke this at startup BEFORE OpenPlatformAdminConnection so the
// process refuses to boot with a loud FATAL log naming the missing env var,
// rather than degrading into the silent-fallback state. caller is the
// human-readable name of the worker (e.g. "Marketplace", "CSAAS-SWEEP")
// used as the log prefix so operators can grep which guard fired.
//
// No-op when AXONFLOW_DB_USE_APP_ROLE=false (legacy v8.x posture where the
// master role bypasses RLS, so the admin pool is not required for
// correctness).
func RequirePlatformAdminOrFatal(caller string) {
	if fire, msg := platformAdminGuardShouldFire(caller); fire {
		fatalfFn("%s", msg)
	}
}

// OpenAppRoleConnection opens a *sql.DB using the resolved app-role DSN. This
// is a thin wrapper around sql.Open + Ping with a retry loop, suitable for
// agent startup. Callers are responsible for closing the returned handle.
//
// On success, also asserts the connected role: if AXONFLOW_DB_USE_APP_ROLE=true
// AND the current_user is not axonflow_app_role, returns an error so we don't
// silently fall back to the master role and miss the RLS gate.
func OpenAppRoleConnection(ctx context.Context, fallbackDSN string, maxRetries int) (*sql.DB, error) {
	dsn := ResolveAppRoleDSN(fallbackDSN)
	if dsn == "" {
		return nil, fmt.Errorf("OpenAppRoleConnection: no DSN available (set DATABASE_URL or %s)", EnvAppRoleURL)
	}

	var db *sql.DB
	var err error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		db, err = sql.Open("postgres", dsn)
		if err == nil {
			pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = db.PingContext(pingCtx)
			cancel()
			if err == nil {
				break
			}
			_ = db.Close()
		}
		if attempt < maxRetries {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("OpenAppRoleConnection: failed after %d attempts: %w", maxRetries, err)
	}

	// When the gate is enabled, assert the connected role is what we expected.
	// Catches misconfigured DSNs that silently fall back to the master.
	if UseAppRoleEnabled() {
		if err := assertConnectedRole(ctx, db, "axonflow_app_role"); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("OpenAppRoleConnection: role assertion failed: %w", err)
		}
	}

	return db, nil
}

// OpenPlatformAdminConnection opens a *sql.DB authenticated as
// axonflow_platform_admin (BYPASSRLS). Cross-org workers (sweep, recovery,
// node enforcement aggregators) MUST use this connection — under FORCE RLS
// on agent_heartbeats / community_saas_registrations / etc. (mig 105+107),
// axonflow_app_role queries that need to iterate across orgs silently
// return 0 rows.
//
// Returns nil + nil error when AXONFLOW_DB_PLATFORM_ADMIN_URL is unset —
// callers MUST treat nil-with-nil-err as "fall back to the supplied db
// pool." Production deployments running under FORCE RLS for any
// worker-touched table MUST set the env var so the fallback never fires.
//
// On success, asserts the connected role IS axonflow_platform_admin so we
// don't silently fall back to the master and lose the abstraction.
//
// v9 Phase 8 (#2305 Brief 11.5, Item 2): paired with the
// AXONFLOW_DB_USE_APP_ROLE=true default flip.
func OpenPlatformAdminConnection(ctx context.Context, maxRetries int) (*sql.DB, error) {
	dsn := ResolvePlatformAdminDSN()
	if dsn == "" {
		// Caller must fall back. Not an error.
		return nil, nil
	}

	var db *sql.DB
	var err error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		db, err = sql.Open("postgres", dsn)
		if err == nil {
			pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = db.PingContext(pingCtx)
			cancel()
			if err == nil {
				break
			}
			_ = db.Close()
		}
		if attempt < maxRetries {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("OpenPlatformAdminConnection: failed after %d attempts: %w", maxRetries, err)
	}

	if err := assertConnectedRole(ctx, db, "axonflow_platform_admin"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("OpenPlatformAdminConnection: role assertion failed: %w", err)
	}
	return db, nil
}

// assertConnectedRole verifies the open connection is authenticated as the
// expected role. Used as a defensive check that the env-gated DSN actually
// landed on the role we wanted.
func assertConnectedRole(ctx context.Context, db *sql.DB, expected string) error {
	var current string
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := db.QueryRowContext(checkCtx, "SELECT current_user").Scan(&current); err != nil {
		return fmt.Errorf("could not query current_user: %w", err)
	}
	if current != expected {
		return fmt.Errorf("expected current_user=%q, got %q (check %s and DSN credentials)", expected, current, EnvAppRoleURL)
	}
	return nil
}
