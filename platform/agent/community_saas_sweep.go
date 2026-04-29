// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lib/pq"

	logutil "axonflow/platform/shared/logger"
)

// Community-SaaS inactivity sweep — daily background goroutine that terminates
// tenants inactive for >3 months or past the 1-year hard cap and cascade-deletes
// their tenant-scoped data. Tombstone rows stay in community_saas_registrations
// indefinitely so the tenant_id PK slot is never reused (ADR-048).
//
// Multi-instance correctness: pg_try_advisory_lock at the top of each tick.
// First instance to acquire wins; others skip cleanly. The lock is released on
// tick exit. Lock id derived from a constant hash so all instances target the
// same lock.
//
// Operational controls:
//   - COMMUNITY_SAAS_SWEEP_ENABLED (default false on first deploy, flip to true
//     after a successful dry-run soak): hard kill switch. When false the
//     goroutine doesn't even start.
//   - COMMUNITY_SAAS_SWEEP_DRYRUN (default true on first enable): when true,
//     the sweep runs all SELECT queries, logs what WOULD be terminated and
//     cascade-deleted, but never executes the UPDATEs/DELETEs. Lets us soak
//     for 24h before flipping the switch.

const (
	// communitySaasSweepEnabledEnv: hard switch. Goroutine does not start when
	// the env var is not literal "true". Default off so the sweep is opt-in
	// per deploy.
	communitySaasSweepEnabledEnv = "COMMUNITY_SAAS_SWEEP_ENABLED"

	// communitySaasSweepDryRunEnv: when "true", every UPDATE/DELETE is replaced
	// with a SELECT that counts how many rows would have been affected, and
	// the result is logged. Useful for the first 24h after enabling.
	communitySaasSweepDryRunEnv = "COMMUNITY_SAAS_SWEEP_DRYRUN"

	// communitySaasSweepInterval: how often the goroutine wakes up. Hourly
	// rather than daily because the ticks are cheap when no tenants need
	// terminating, and shortening the window makes the sweep responsive
	// without risking long backlogs after agent restarts.
	communitySaasSweepInterval = 1 * time.Hour

	// communitySaasInactivityWindow: the "3-month idle" predicate. After this
	// many hours since last_seen_at, with no other activity, the tenant is
	// terminated.
	communitySaasInactivityWindow = "3 months"

	// communitySaasHardCap: the "1-year cap" predicate. After this many hours
	// since created_at, regardless of activity, the tenant is terminated.
	communitySaasHardCap = "1 year"

	// communitySaasSweepLockID: stable advisory lock id. All instances target
	// the same number. Picked deterministically from "community_saas_sweep"
	// (md5 of the literal, take first 8 hex chars, parse as int64). Encoded
	// here as the resulting integer so the lock id is greppable in logs.
	communitySaasSweepLockID int64 = 0x07ECC10A55EE7E5

	// minSafeCascadeTables: refuse to run the sweep if information_schema
	// reflection finds fewer than this many cascade tables. The set should
	// only ever grow; a sudden shrink suggests a migration regression and
	// not running is safer than partial cascade.
	minSafeCascadeTables = 8
)

// validIdentifier matches Postgres identifiers we'll accept from
// information_schema reflection. Defense-in-depth against any future bug
// upstream that lets a non-identifier slip into pg_class.
var validIdentifier = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// communitySaasSweepNonCascadeTables lists tables that have a tenant_id column
// but MUST NOT be cascade-deleted on tenant termination:
//
//   - community_saas_registrations: the tombstone itself; sweep updates the row
//     in place rather than deleting it
//   - tenants: canonical tenant tracking; we keep the row (analog tombstone)
//   - static_policies: rows are mostly tenant_id='global' system policies; only
//     tenant-specific overrides should match `tenant_id = $terminated_id` and
//     deleting those is correct, but they're tier-gated and Community-SaaS
//     tenants don't create them, so skip
//   - license_keys: Community-SaaS tenants don't have license keys
//   - schema_migrations / community_saas_daily_usage: rate-limit / migration
//     metadata, retained per ops convention
var communitySaasSweepNonCascadeTables = map[string]struct{}{
	"community_saas_registrations": {},
	"tenants":                      {},
	"static_policies":              {},
	"license_keys":                 {},
	"schema_migrations":            {},
	"community_saas_daily_usage":   {},
}

// communitySaasSweepMetrics is incremented by the sweep on each tick. Read by
// /metrics for Prometheus scrape and used in tests to assert behavior.
type communitySaasSweepMetrics struct {
	TerminationsByInactivity atomic.Int64
	TerminationsByHardCap    atomic.Int64
	TickFailures             atomic.Int64
	LockAcquisitionSkips     atomic.Int64
	CascadeRowsDeleted       atomic.Int64
}

var communitySaasSweepCounters communitySaasSweepMetrics

// GetCommunitySaasSweepMetrics returns a snapshot of sweep counters. Used by
// the metrics endpoint and by tests to assert sweep behavior.
func GetCommunitySaasSweepMetrics() (inactivity, hardCap, failures, lockSkips, cascadeRows int64) {
	return communitySaasSweepCounters.TerminationsByInactivity.Load(),
		communitySaasSweepCounters.TerminationsByHardCap.Load(),
		communitySaasSweepCounters.TickFailures.Load(),
		communitySaasSweepCounters.LockAcquisitionSkips.Load(),
		communitySaasSweepCounters.CascadeRowsDeleted.Load()
}

// StartCommunitySaasSweep starts the daily inactivity sweep goroutine. No-op
// when COMMUNITY_SAAS_SWEEP_ENABLED is not "true" (default off — sweep is
// opt-in per deploy). Returns immediately after spawning; the goroutine runs
// for the lifetime of ctx.
//
// Per the ADR-048 sequencing, this is called from run.go startup AFTER the
// auth path's terminated_at predicate is in place, so the sweep cannot leave
// a window where a row is terminated but auth still admits it.
func StartCommunitySaasSweep(ctx context.Context, db *sql.DB) {
	if os.Getenv(communitySaasSweepEnabledEnv) != "true" {
		log.Printf("[CSAAS-SWEEP] disabled via %s; not starting goroutine", communitySaasSweepEnabledEnv)
		return
	}
	if db == nil {
		log.Printf("[CSAAS-SWEEP] db handle nil; not starting (community-saas mode requires a database)")
		return
	}
	dryRun := os.Getenv(communitySaasSweepDryRunEnv) == "true"

	tables, err := discoverCommunitySaasCascadeTables(ctx, db)
	if err != nil {
		log.Printf("[CSAAS-SWEEP] failed to discover cascade tables: %v; not starting goroutine", err)
		return
	}
	if len(tables) < minSafeCascadeTables {
		log.Printf("[CSAAS-SWEEP] cascade table count %d < safety threshold %d; not starting (suspected migration regression)",
			len(tables), minSafeCascadeTables)
		return
	}
	log.Printf("[CSAAS-SWEEP] starting (interval=%s dry_run=%v cascade_tables=%d)",
		communitySaasSweepInterval, dryRun, len(tables))
	log.Printf("[CSAAS-SWEEP] cascade tables: %s", strings.Join(tables, ", "))

	go func() {
		// First tick fires immediately so operators can verify the loop is
		// running without waiting an hour. Subsequent ticks follow the interval.
		runCommunitySaasSweepTick(ctx, db, tables, dryRun)
		ticker := time.NewTicker(communitySaasSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Printf("[CSAAS-SWEEP] context done, exiting")
				return
			case <-ticker.C:
				runCommunitySaasSweepTick(ctx, db, tables, dryRun)
			}
		}
	}()
}

// runCommunitySaasSweepTick is one iteration of the sweep loop. Pins a single
// connection from the pool, acquires the session-scoped advisory lock on it,
// runs the two terminations + cascade in a single transaction on the SAME
// connection, releases the lock, and returns the connection to the pool.
// Errors are logged and the tick fails closed (no partial terminations).
//
// Why a pinned *sql.Conn: pg_try_advisory_lock and pg_advisory_unlock are
// session-scoped — the lock is held by the Postgres backend session, not by
// the calling logical operation. *sql.DB is a connection pool, so a naive
// implementation can acquire on connection A and release on connection B,
// at which point the unlock returns false and the lock leaks on A in the
// pool. Future ticks then keep skipping forever because the leaked lock is
// still held. By pulling a *sql.Conn at the top of the tick and using that
// same connection for acquire / tx / release, we guarantee one Postgres
// session for the whole tick.
func runCommunitySaasSweepTick(ctx context.Context, db *sql.DB, cascadeTables []string, dryRun bool) {
	// Bound the tick — even on a slow DB we want to release the advisory lock
	// rather than hang forever.
	tickCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	conn, err := db.Conn(tickCtx)
	if err != nil {
		log.Printf("[CSAAS-SWEEP] failed to pin a connection: %v", err)
		communitySaasSweepCounters.TickFailures.Add(1)
		return
	}
	// IMPORTANT: conn.Close returns the connection to the pool. We MUST release
	// the advisory lock first, or the lock leaks on this session in the pool.
	// The defer order below enforces release-then-close because deferred
	// statements run LIFO. Close error is intentionally not checked: the
	// connection is being returned to a pool whose health is the pool's concern,
	// not ours, and bubbling a close error here would mask the real tick error.
	defer func() {
		_ = conn.Close()
	}()

	acquired, err := acquireCommunitySaasSweepLock(tickCtx, conn)
	if err != nil {
		log.Printf("[CSAAS-SWEEP] lock acquisition failed: %v", err)
		communitySaasSweepCounters.TickFailures.Add(1)
		return
	}
	if !acquired {
		// Another instance is running the sweep this tick; skip cleanly.
		communitySaasSweepCounters.LockAcquisitionSkips.Add(1)
		return
	}
	defer func() {
		if err := releaseCommunitySaasSweepLock(tickCtx, conn); err != nil {
			log.Printf("[CSAAS-SWEEP] lock release failed: %v", err)
		}
	}()

	if dryRun {
		runCommunitySaasSweepDryRun(tickCtx, conn)
		return
	}

	tx, err := conn.BeginTx(tickCtx, nil)
	if err != nil {
		log.Printf("[CSAAS-SWEEP] BeginTx failed: %v", err)
		communitySaasSweepCounters.TickFailures.Add(1)
		return
	}
	rolledBack := false
	defer func() {
		if !rolledBack {
			_ = tx.Rollback() // no-op after Commit; safety net on early returns
		}
	}()

	inactivityIDs, err := terminateInactiveCommunitySaasTenants(tickCtx, tx)
	if err != nil {
		log.Printf("[CSAAS-SWEEP] inactivity termination failed, rolling back tick: %v", err)
		_ = tx.Rollback()
		rolledBack = true
		communitySaasSweepCounters.TickFailures.Add(1)
		return
	}

	hardCapIDs, err := terminateHardCappedCommunitySaasTenants(tickCtx, tx)
	if err != nil {
		log.Printf("[CSAAS-SWEEP] hard-cap termination failed, rolling back tick: %v", err)
		_ = tx.Rollback()
		rolledBack = true
		communitySaasSweepCounters.TickFailures.Add(1)
		return
	}

	// Cascade is keyed on the EXACT tenant_ids returned by the two UPDATEs
	// above, not on a wall-clock cutoff. Using app-side time.Now() vs
	// Postgres NOW() introduces clock skew that can cause rows terminated in
	// this tick to fall outside a `terminated_at >= $1` filter, leaving the
	// registration tombstoned but the tenant-scoped data orphaned.
	terminatedIDs := append(inactivityIDs, hardCapIDs...)

	cascadeRows, err := cascadeDeleteCommunitySaasTenantData(tickCtx, tx, cascadeTables, terminatedIDs)
	if err != nil {
		log.Printf("[CSAAS-SWEEP] cascade delete failed, rolling back tick: %v", err)
		_ = tx.Rollback()
		rolledBack = true
		communitySaasSweepCounters.TickFailures.Add(1)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[CSAAS-SWEEP] commit failed: %v", err)
		communitySaasSweepCounters.TickFailures.Add(1)
		return
	}
	rolledBack = true // suppress the deferred rollback no-op

	communitySaasSweepCounters.TerminationsByInactivity.Add(int64(len(inactivityIDs)))
	communitySaasSweepCounters.TerminationsByHardCap.Add(int64(len(hardCapIDs)))
	communitySaasSweepCounters.CascadeRowsDeleted.Add(int64(cascadeRows))
	if len(inactivityIDs) > 0 || len(hardCapIDs) > 0 {
		log.Printf("[CSAAS-SWEEP] tick complete: inactivity=%d hard_cap=%d cascade_rows=%d",
			len(inactivityIDs), len(hardCapIDs), cascadeRows)
	}
}

// runCommunitySaasSweepDryRun mirrors the real tick but uses SELECT-only
// queries so we can sanity-check the predicate counts before flipping
// COMMUNITY_SAAS_SWEEP_DRYRUN to false. Runs on the same pinned connection
// the caller acquired so it sees the same session state as a real tick.
func runCommunitySaasSweepDryRun(ctx context.Context, conn *sql.Conn) {
	var inactivityCount, hardCapCount int
	err := conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM community_saas_registrations
		 WHERE last_seen_at IS NOT NULL
		   AND last_seen_at < NOW() - INTERVAL '`+communitySaasInactivityWindow+`'
		   AND terminated_at IS NULL`).Scan(&inactivityCount)
	if err != nil {
		log.Printf("[CSAAS-SWEEP][DRYRUN] inactivity count query failed: %v", err)
		communitySaasSweepCounters.TickFailures.Add(1)
		return
	}
	err = conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM community_saas_registrations
		 WHERE created_at < NOW() - INTERVAL '`+communitySaasHardCap+`'
		   AND terminated_at IS NULL`).Scan(&hardCapCount)
	if err != nil {
		log.Printf("[CSAAS-SWEEP][DRYRUN] hard-cap count query failed: %v", err)
		communitySaasSweepCounters.TickFailures.Add(1)
		return
	}
	if inactivityCount > 0 || hardCapCount > 0 {
		log.Printf("[CSAAS-SWEEP][DRYRUN] would terminate inactivity=%d hard_cap=%d (no rows actually changed; flip %s=false to enable)",
			inactivityCount, hardCapCount, communitySaasSweepDryRunEnv)
	}
}

// terminateInactiveCommunitySaasTenants marks tenants whose last_seen_at is
// older than 3 months as terminated. Returns the tenant_ids of every row the
// UPDATE actually changed (via RETURNING). Emits a structured audit log line
// per terminated tenant.
//
// The caller cascades on these exact tenant_ids — not on a wall-clock cutoff
// — so any clock skew between the application process and the database is
// irrelevant.
func terminateInactiveCommunitySaasTenants(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx,
		`UPDATE community_saas_registrations
		 SET terminated_at = NOW(), secret_hash = ''
		 WHERE last_seen_at IS NOT NULL
		   AND last_seen_at < NOW() - INTERVAL '`+communitySaasInactivityWindow+`'
		   AND terminated_at IS NULL
		 RETURNING tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("inactivity update: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return ids, fmt.Errorf("inactivity scan: %w", err)
		}
		ids = append(ids, tenantID)
		log.Printf("[CSAAS-SWEEP][AUDIT] terminated tenant=%s reason=3mo-inactivity",
			logutil.Sanitize(tenantID))
	}
	if err := rows.Err(); err != nil {
		return ids, fmt.Errorf("inactivity rows iteration: %w", err)
	}
	return ids, nil
}

// terminateHardCappedCommunitySaasTenants marks tenants past the 1-year hard
// cap as terminated, regardless of recent activity. Returns the tenant_ids
// of every row the UPDATE actually changed.
func terminateHardCappedCommunitySaasTenants(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx,
		`UPDATE community_saas_registrations
		 SET terminated_at = NOW(), secret_hash = ''
		 WHERE created_at < NOW() - INTERVAL '`+communitySaasHardCap+`'
		   AND terminated_at IS NULL
		 RETURNING tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("hard-cap update: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return ids, fmt.Errorf("hard-cap scan: %w", err)
		}
		ids = append(ids, tenantID)
		log.Printf("[CSAAS-SWEEP][AUDIT] terminated tenant=%s reason=1yr-cap",
			logutil.Sanitize(tenantID))
	}
	if err := rows.Err(); err != nil {
		return ids, fmt.Errorf("hard-cap rows iteration: %w", err)
	}
	return ids, nil
}

// cascadeDeleteCommunitySaasTenantData deletes tenant-scoped rows belonging to
// the supplied list of tenant_ids — typically the union of the IDs returned
// from the two terminate UPDATEs in the same transaction. Runs one DELETE per
// table in cascadeTables; returns the total number of rows deleted.
//
// Why we use exact tenant_ids rather than `terminated_at >= $cutoff`: the
// terminate UPDATEs write `terminated_at = NOW()` (server-side), but a wall-
// clock cutoff would have to come from the app process (`time.Now()` in Go).
// Any clock skew between app and DB — even a few milliseconds — can cause
// rows just terminated in this transaction to fall outside the cutoff,
// orphaning their tenant-scoped data. Driving cascade off the explicit list
// of returned IDs eliminates the skew dependency entirely.
//
// Table names came from information_schema reflection at startup and were
// validated against `validIdentifier` in discoverCommunitySaasCascadeTables.
// We re-validate here to guard against any in-memory mutation between calls.
func cascadeDeleteCommunitySaasTenantData(ctx context.Context, tx *sql.Tx, cascadeTables []string, tenantIDs []string) (int64, error) {
	var total int64
	if len(tenantIDs) == 0 {
		// No tenants terminated this tick — cascade is a no-op
		return 0, nil
	}
	for _, table := range cascadeTables {
		if !validIdentifier.MatchString(table) {
			return total, fmt.Errorf("table name %q failed identifier check; refusing to interpolate into DELETE", table)
		}
		// Identifier is bound at this site (validated above); the WHERE clause
		// uses a parameterized array binding for the tenant ids — no string
		// interpolation of values, no clock skew dependency.
		query := fmt.Sprintf(`DELETE FROM %s WHERE tenant_id = ANY($1)`, table)
		res, err := tx.ExecContext(ctx, query, pq.Array(tenantIDs))
		if err != nil {
			return total, fmt.Errorf("cascade delete from %s: %w", table, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("cascade delete from %s: rows-affected: %w", table, err)
		}
		total += n
		if n > 0 {
			log.Printf("[CSAAS-SWEEP][AUDIT] cascade-deleted %d rows from %s", n, table)
		}
	}
	return total, nil
}

// discoverCommunitySaasCascadeTables queries information_schema for tables in
// the public schema with a `tenant_id` column of a string type, then filters
// out the non-cascade allowlist (tombstone, structural, system policies). The
// resulting list is what cascadeDeleteCommunitySaasTenantData will DELETE
// from on each tick.
//
// CRITICAL: this query joins against information_schema.tables and restricts
// to `table_type = 'BASE TABLE'`. Without that filter, views with a tenant_id
// column (e.g. `code_governance_metrics`) get picked up as cascade targets,
// and the per-table DELETE fails with `cannot delete from view`, rolling the
// entire sweep transaction back and silently undoing the terminations.
//
// Called once at sweep startup; the list is stable for the agent process
// lifetime. New tables added by future migrations are picked up on the next
// agent restart.
func discoverCommunitySaasCascadeTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT c.table_name
		FROM information_schema.columns c
		JOIN information_schema.tables t
		  ON c.table_schema = t.table_schema AND c.table_name = t.table_name
		WHERE c.column_name = 'tenant_id'
		  AND c.table_schema = 'public'
		  AND c.data_type IN ('character varying', 'text', 'character')
		  AND t.table_type = 'BASE TABLE'
		ORDER BY c.table_name
	`)
	if err != nil {
		return nil, fmt.Errorf("information_schema query: %w", err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan table name: %w", err)
		}
		if !validIdentifier.MatchString(name) {
			log.Printf("[CSAAS-SWEEP] skipping table with invalid identifier: %q", name)
			continue
		}
		if _, skip := communitySaasSweepNonCascadeTables[name]; skip {
			continue
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("information_schema iteration: %w", err)
	}
	return tables, nil
}

// acquireCommunitySaasSweepLock attempts to take the advisory lock on the
// supplied connection. Returns (true, nil) if the caller now holds it,
// (false, nil) if another instance holds it, (_, err) on database error.
//
// Caller MUST pass the same *sql.Conn that will later release the lock.
// pg_try_advisory_lock is session-scoped — acquiring on connection A and
// releasing on connection B leaks the lock on A in the pool.
func acquireCommunitySaasSweepLock(ctx context.Context, conn *sql.Conn) (bool, error) {
	var got bool
	err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, communitySaasSweepLockID).Scan(&got)
	if err != nil {
		return false, fmt.Errorf("pg_try_advisory_lock: %w", err)
	}
	return got, nil
}

// releaseCommunitySaasSweepLock releases the advisory lock on the supplied
// connection — MUST be the same *sql.Conn that acquired it. Logged on
// failure because a leaked lock means subsequent instances skip the sweep
// until the session ends.
func releaseCommunitySaasSweepLock(ctx context.Context, conn *sql.Conn) error {
	var released bool
	err := conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, communitySaasSweepLockID).Scan(&released)
	if err != nil {
		return fmt.Errorf("pg_advisory_unlock: %w", err)
	}
	if !released {
		return fmt.Errorf("pg_advisory_unlock returned false (lock was not held by this session)")
	}
	return nil
}

// communitySaasSweepShouldStart decides whether the sweep is appropriate for
// the current deployment mode. The sweep operates on the
// community_saas_registrations table which is only meaningfully populated
// in community-saas mode, so we refuse to start the goroutine in any other
// deployment shape — same binary ships everywhere, but only one mode runs
// the sweep.
//
// Uses the canonical isCommunitySaasMode() helper from run.go (per the
// repo's DEPLOYMENT_MODE lint rule, Issue #1133) rather than reading the env
// var directly here.
func communitySaasSweepShouldStart() bool {
	if !isCommunitySaasMode() {
		return false
	}
	// Belt and braces: if the agent is running with a non-community license
	// captured at validation time, refuse to start the sweep regardless of
	// DEPLOYMENT_MODE. License is ground truth; env vars can be misconfigured.
	tier := currentLicenseTier()
	if tier != "" && tier != "community" && tier != "Community" {
		return false
	}
	return true
}
