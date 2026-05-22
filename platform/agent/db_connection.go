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
