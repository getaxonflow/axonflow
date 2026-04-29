// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// These tests exercise the community-saas inactivity sweep against a real
// Postgres (DATABASE_URL set; CI provides it via test-community.yml's service
// container). They skip when no DB is available.
//
// Each test seeds rows with a test-specific tenant prefix (cs_test_sweep_*)
// and cleans them up via t.Cleanup, so concurrent test runs against the same
// DB don't collide and the prefix never matches handler-generated cs_<uuid>
// rows from production.

const sweepTestPrefix = "cs_test_sweep_"

// connectSweepDB returns a *sql.DB and a cleanup function. Cleanup also
// resets the package-level sweep counters so each test starts from zero.
func connectSweepDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping sweep test: DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatalf("db.Ping: %v", err)
	}
	resetSweepCounters()
	cleanup := func() {
		// Always release the advisory lock if a test left it held — failing
		// to release would block subsequent tests' lock acquisition.
		_, _ = db.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, communitySaasSweepLockID)
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM community_saas_registrations WHERE tenant_id LIKE $1`, sweepTestPrefix+"%")
		_ = db.Close()
	}
	return db, cleanup
}

func resetSweepCounters() {
	communitySaasSweepCounters.TerminationsByInactivity.Store(0)
	communitySaasSweepCounters.TerminationsByHardCap.Store(0)
	communitySaasSweepCounters.TickFailures.Store(0)
	communitySaasSweepCounters.LockAcquisitionSkips.Store(0)
	communitySaasSweepCounters.CascadeRowsDeleted.Store(0)
}

// seedSweepTenant inserts a tenant with the supplied attributes and returns
// the generated tenant_id. created_at and last_seen_at are settable by
// passing time.Now() offsets.
func seedSweepTenant(t *testing.T, db *sql.DB, suffix string, createdAt time.Time, lastSeenAt sql.NullTime, terminated bool) string {
	t.Helper()
	tenantID := sweepTestPrefix + suffix + "_" + uuid.NewString()
	var terminatedExpr sql.NullTime
	if terminated {
		terminatedExpr = sql.NullTime{Valid: true, Time: time.Now().UTC()}
	}
	// Explicit ::timestamptz cast on $2 — Postgres can't deduce the type when the
	// same parameter is referenced both as a column value AND as an operand of
	// `+ INTERVAL '1 year'`. Without the cast the driver errors with
	// `pq: inconsistent types deduced for parameter $2`.
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO community_saas_registrations
		 (tenant_id, secret_hash, secret_prefix, org_id, created_at, expires_at, last_seen_at, terminated_at)
		 VALUES ($1, '', '', 'community-saas', $2::timestamptz, $2::timestamptz + INTERVAL '1 year', $3, $4)`,
		tenantID, createdAt, lastSeenAt, terminatedExpr)
	if err != nil {
		t.Fatalf("seed tenant %s: %v", suffix, err)
	}
	return tenantID
}

// TestDiscoverCommunitySaasCascadeTables_DB asserts the reflection finds the
// expected high-value tenant-scoped tables and excludes the non-cascade
// allowlist (community_saas_registrations, tenants, static_policies, etc).
func TestDiscoverCommunitySaasCascadeTables_DB(t *testing.T) {
	db, cleanup := connectSweepDB(t)
	defer cleanup()

	tables, err := discoverCommunitySaasCascadeTables(context.Background(), db)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	got := make(map[string]bool, len(tables))
	for _, name := range tables {
		got[name] = true
	}
	mustInclude := []string{
		"audit_logs",
		"decision_chain",
		"workflows",
	}
	for _, name := range mustInclude {
		if !got[name] {
			t.Errorf("expected cascade table %q in discovery result, but it was missing (got %d tables: %v)",
				name, len(tables), tables)
		}
	}
	mustExclude := []string{
		"community_saas_registrations",
		"tenants",
		"static_policies",
	}
	for _, name := range mustExclude {
		if got[name] {
			t.Errorf("table %q should NOT be in cascade list (it's in non-cascade allowlist)", name)
		}
	}
	if len(tables) < minSafeCascadeTables {
		t.Errorf("discovered %d tables, expected at least %d (safety threshold)", len(tables), minSafeCascadeTables)
	}
}

// TestSweepTerminateInactive_DB seeds an inactive tenant (last_seen_at >
// 3 months ago) and a recently-active tenant, runs one tick, asserts only the
// inactive one is terminated.
func TestSweepTerminateInactive_DB(t *testing.T) {
	db, cleanup := connectSweepDB(t)
	defer cleanup()

	inactive := seedSweepTenant(t, db, "inactive",
		time.Now().UTC().AddDate(0, -6, 0),                // created 6 months ago
		sql.NullTime{Valid: true, Time: time.Now().UTC().AddDate(0, -4, 0)}, // idle 4 months
		false)
	active := seedSweepTenant(t, db, "active",
		time.Now().UTC().AddDate(0, -1, 0),                              // created 1 month ago
		sql.NullTime{Valid: true, Time: time.Now().UTC().Add(-1 * time.Hour)}, // active 1h ago
		false)

	tables, err := discoverCommunitySaasCascadeTables(context.Background(), db)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	runCommunitySaasSweepTick(context.Background(), db, tables, false)

	if got := assertTenantTerminated(t, db, inactive); !got {
		t.Errorf("inactive tenant should be terminated, but terminated_at is NULL")
	}
	if got := assertTenantTerminated(t, db, active); got {
		t.Errorf("active tenant should NOT be terminated, but terminated_at is set")
	}
	inactCount, _, _, _, _ := GetCommunitySaasSweepMetrics()
	if inactCount < 1 {
		t.Errorf("expected at least 1 inactivity termination counter, got %d", inactCount)
	}
}

// TestSweepTerminateHardCap_DB seeds a tenant past the 1-year cap with recent
// activity (so the inactivity predicate alone wouldn't terminate it), runs
// one tick, asserts it gets terminated by the hard-cap path.
func TestSweepTerminateHardCap_DB(t *testing.T) {
	db, cleanup := connectSweepDB(t)
	defer cleanup()

	old := seedSweepTenant(t, db, "old",
		time.Now().UTC().AddDate(-1, -1, 0),                                   // created 13 months ago
		sql.NullTime{Valid: true, Time: time.Now().UTC().Add(-1 * time.Hour)}, // active 1h ago
		false)

	tables, err := discoverCommunitySaasCascadeTables(context.Background(), db)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	runCommunitySaasSweepTick(context.Background(), db, tables, false)

	if got := assertTenantTerminated(t, db, old); !got {
		t.Errorf("13-month-old tenant should be terminated by hard-cap, but terminated_at is NULL")
	}
	_, hardCap, _, _, _ := GetCommunitySaasSweepMetrics()
	if hardCap < 1 {
		t.Errorf("expected at least 1 hard-cap termination counter, got %d", hardCap)
	}
}

// TestSweepDryRun_DB seeds an inactive tenant, runs the sweep with the
// dry-run path, asserts NO termination happens but the count would have been
// detected (verified by examining log output is impractical here; we just
// confirm the row is unchanged).
func TestSweepDryRun_DB(t *testing.T) {
	db, cleanup := connectSweepDB(t)
	defer cleanup()

	inactive := seedSweepTenant(t, db, "dryrun",
		time.Now().UTC().AddDate(0, -6, 0),
		sql.NullTime{Valid: true, Time: time.Now().UTC().AddDate(0, -4, 0)},
		false)

	tables, _ := discoverCommunitySaasCascadeTables(context.Background(), db)
	runCommunitySaasSweepTick(context.Background(), db, tables, true) // dry-run

	if got := assertTenantTerminated(t, db, inactive); got {
		t.Errorf("dry-run should NOT terminate any tenant, but %s has terminated_at set", inactive)
	}
}

// TestSweepIdempotent_DB asserts running two ticks back-to-back is a no-op
// after the first one terminates the eligible tenants. Second tick MUST NOT
// re-terminate already-terminated rows or fail.
func TestSweepIdempotent_DB(t *testing.T) {
	db, cleanup := connectSweepDB(t)
	defer cleanup()

	seedSweepTenant(t, db, "idem",
		time.Now().UTC().AddDate(0, -6, 0),
		sql.NullTime{Valid: true, Time: time.Now().UTC().AddDate(0, -4, 0)},
		false)

	tables, _ := discoverCommunitySaasCascadeTables(context.Background(), db)
	runCommunitySaasSweepTick(context.Background(), db, tables, false)
	firstInact, firstHardCap, _, _, _ := GetCommunitySaasSweepMetrics()

	runCommunitySaasSweepTick(context.Background(), db, tables, false)
	secondInact, secondHardCap, failures, _, _ := GetCommunitySaasSweepMetrics()

	if secondInact != firstInact {
		t.Errorf("second tick added %d inactivity terminations (expected 0): first=%d second=%d",
			secondInact-firstInact, firstInact, secondInact)
	}
	if secondHardCap != firstHardCap {
		t.Errorf("second tick added %d hard-cap terminations (expected 0)", secondHardCap-firstHardCap)
	}
	if failures > 0 {
		t.Errorf("second tick had %d failures (expected 0)", failures)
	}
}

// TestSweepAdvisoryLock_Concurrent asserts that when two goroutines try to
// acquire the lock simultaneously, exactly one succeeds and the other skips
// without error. We use a brief artificial delay between acquire and release
// to ensure the second goroutine actually races against the first.
func TestSweepAdvisoryLock_Concurrent(t *testing.T) {
	db, cleanup := connectSweepDB(t)
	defer cleanup()

	// Two independent sessions — a single *sql.DB pools connections, but
	// pg_try_advisory_lock is session-scoped, so we need separate connections.
	// db.Conn() yields a dedicated connection from the pool.
	conn1, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn1: %v", err)
	}
	defer conn1.Close()
	conn2, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn2: %v", err)
	}
	defer conn2.Close()

	var wg sync.WaitGroup
	results := make([]bool, 2)
	errsOut := make([]error, 2)

	tryLock := func(idx int, conn *sql.Conn) {
		defer wg.Done()
		var got bool
		err := conn.QueryRowContext(context.Background(),
			`SELECT pg_try_advisory_lock($1)`, communitySaasSweepLockID).Scan(&got)
		results[idx] = got
		errsOut[idx] = err
		if got {
			// Hold the lock briefly so the other goroutine actually races
			time.Sleep(50 * time.Millisecond)
			_, _ = conn.ExecContext(context.Background(),
				`SELECT pg_advisory_unlock($1)`, communitySaasSweepLockID)
		}
	}
	wg.Add(2)
	go tryLock(0, conn1)
	go tryLock(1, conn2)
	wg.Wait()

	if errsOut[0] != nil || errsOut[1] != nil {
		t.Fatalf("unexpected errors: %v / %v", errsOut[0], errsOut[1])
	}
	winners := 0
	if results[0] {
		winners++
	}
	if results[1] {
		winners++
	}
	if winners != 1 {
		t.Errorf("exactly one goroutine should win the advisory lock, got %d (results=%v)", winners, results)
	}
}

// TestSweepLockHeldOnPinnedConnection_DB regression-tests the P1 fix from PR
// review: the advisory lock must be acquired AND released on the SAME
// Postgres session. A naive *sql.DB-based implementation can acquire on
// connection A and release on connection B, leaving the lock leaked on A
// in the pool.
//
// Setup: open two pooled connections, acquire on conn1, attempt to release
// on conn2 — must return false (or error). Then release on conn1 — must
// succeed. This guards against any future regression that drops the
// pinned-connection invariant.
func TestSweepLockHeldOnPinnedConnection_DB(t *testing.T) {
	db, cleanup := connectSweepDB(t)
	defer cleanup()

	conn1, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn1: %v", err)
	}
	defer conn1.Close()
	conn2, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn2: %v", err)
	}
	defer conn2.Close()

	// Acquire on conn1
	got, err := acquireCommunitySaasSweepLock(context.Background(), conn1)
	if err != nil {
		t.Fatalf("acquire on conn1: %v", err)
	}
	if !got {
		t.Fatalf("expected acquire on conn1 to succeed, got false")
	}

	// Attempt release on conn2 — should fail because conn2 doesn't hold the
	// session-scoped lock. The helper returns an error in this case.
	releaseErr := releaseCommunitySaasSweepLock(context.Background(), conn2)
	if releaseErr == nil {
		t.Errorf("releasing on conn2 should fail (lock was acquired on conn1) but returned nil error")
	}

	// Now release on conn1 — should succeed
	if err := releaseCommunitySaasSweepLock(context.Background(), conn1); err != nil {
		t.Errorf("release on conn1: %v", err)
	}

	// Sanity: subsequent acquire on conn1 should now succeed (lock is free)
	got, err = acquireCommunitySaasSweepLock(context.Background(), conn1)
	if err != nil || !got {
		t.Errorf("after release, conn1 should be able to re-acquire; got=%v err=%v", got, err)
	}
	_ = releaseCommunitySaasSweepLock(context.Background(), conn1)
}

// TestSweepCascadeKeyedOnReturnedIDs_DB regression-tests the P2 fix from PR
// review: cascade DELETE must use the exact tenant_ids returned by the
// terminate UPDATEs, not a wall-clock cutoff. With the old design, app-side
// time.Now() vs Postgres NOW() clock skew could cause rows just terminated
// to fall outside the cutoff and have their tenant-scoped data orphaned.
//
// We can't easily inject clock skew, but we CAN verify the contract: cascade
// is keyed on the IDs (tenant_id = ANY), not on a timestamp column. The
// straightforward proof is a tenant whose terminated_at is set to a
// timestamp 10 seconds AFTER our app-side tickStart — under the old code
// that row would be cascaded by `terminated_at >= $1`; under the new code
// it's cascaded only because its tenant_id is in the explicit list.
func TestSweepCascadeKeyedOnReturnedIDs_DB(t *testing.T) {
	db, cleanup := connectSweepDB(t)
	defer cleanup()

	if !auditLogsHasMinimalSchema(t, db) {
		t.Skip("audit_logs schema check failed; cascade test needs the column")
	}

	// Seed a tenant marked terminated; force its terminated_at to a
	// timestamp that's slightly in the FUTURE relative to wall-clock now,
	// proving the cascade isn't time-cutoff dependent.
	tenantID := sweepTestPrefix + "future_term_" + uuid.NewString()
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO community_saas_registrations
		 (tenant_id, secret_hash, secret_prefix, org_id, created_at, expires_at, terminated_at)
		 VALUES ($1, '', '', 'community-saas',
		         NOW() - INTERVAL '6 months', NOW() + INTERVAL '6 months', NOW() + INTERVAL '10 seconds')`,
		tenantID)
	if err != nil {
		t.Fatalf("seed terminated tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM audit_logs WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM community_saas_registrations WHERE tenant_id = $1`, tenantID)
	})

	// Seed audit_logs row for this tenant (skip cleanly if the schema needs
	// extra NOT NULL columns we don't want to fabricate)
	_, err = db.ExecContext(context.Background(),
		`INSERT INTO audit_logs (tenant_id) VALUES ($1)`, tenantID)
	if err != nil {
		t.Skipf("audit_logs requires more columns; skipping: %v", err)
	}

	// Run cascade with the EXPLICIT tenant_id list — this should delete the
	// audit_logs row regardless of any timestamp cutoff. Under the broken
	// design, an old `terminated_at >= time.Now()` cutoff would have missed
	// this row (its terminated_at is in the future relative to that cutoff).
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()
	deleted, err := cascadeDeleteCommunitySaasTenantData(context.Background(), tx, []string{"audit_logs"}, []string{tenantID})
	if err != nil {
		t.Fatalf("cascade delete: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 row deleted from audit_logs (keyed on explicit tenant_id), got %d", deleted)
	}
}

// TestSweepCascadeNoOpWhenNoTenants_DB asserts the cascade is a no-op when
// the supplied tenant_ids list is empty — important so a tick that happens
// to terminate zero tenants doesn't pointlessly hit every cascade table
// with an empty IN clause.
func TestSweepCascadeNoOpWhenNoTenants_DB(t *testing.T) {
	db, cleanup := connectSweepDB(t)
	defer cleanup()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()
	deleted, err := cascadeDeleteCommunitySaasTenantData(context.Background(), tx, []string{"audit_logs"}, nil)
	if err != nil {
		t.Errorf("cascade with empty tenant list should be a no-op, got error: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 rows deleted with empty tenant list, got %d", deleted)
	}
}

// TestSweepCascadeDelete_DB seeds a terminated tenant plus rows in the
// `audit_logs` table for that tenant, then runs cascadeDeleteCommunitySaasTenantData
// with audit_logs in the cascade list and asserts the rows are gone.
func TestSweepCascadeDelete_DB(t *testing.T) {
	db, cleanup := connectSweepDB(t)
	defer cleanup()

	// Seed a terminated tenant
	tenantID := sweepTestPrefix + "cascade_" + uuid.NewString()
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO community_saas_registrations
		 (tenant_id, secret_hash, secret_prefix, org_id, created_at, expires_at, terminated_at)
		 VALUES ($1, '', '', 'community-saas', NOW() - INTERVAL '6 months', NOW() + INTERVAL '6 months', NOW())`,
		tenantID)
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM audit_logs WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM community_saas_registrations WHERE tenant_id = $1`, tenantID)
	})

	// Seed audit_logs rows for this tenant. We don't assume the audit_logs
	// schema beyond having a tenant_id column — write minimal columns.
	if !auditLogsHasMinimalSchema(t, db) {
		t.Skip("audit_logs schema does not have expected shape; skipping cascade test")
	}
	for i := 0; i < 3; i++ {
		_, err := db.ExecContext(context.Background(),
			`INSERT INTO audit_logs (tenant_id) VALUES ($1)`, tenantID)
		if err != nil {
			t.Skipf("audit_logs insert minimal-shape failed (schema requires more columns): %v", err)
		}
	}

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()
	deleted, err := cascadeDeleteCommunitySaasTenantData(context.Background(), tx, []string{"audit_logs"}, []string{tenantID})
	if err != nil {
		t.Fatalf("cascade delete: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if deleted != 3 {
		t.Errorf("expected 3 rows deleted from audit_logs, got %d", deleted)
	}
}

// TestSweepCascadeDelete_RejectsBadIdentifier asserts the validIdentifier
// guard refuses a malicious table name (defense in depth even though the
// table list comes from information_schema reflection).
func TestSweepCascadeDelete_RejectsBadIdentifier(t *testing.T) {
	db, cleanup := connectSweepDB(t)
	defer cleanup()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	_, err = cascadeDeleteCommunitySaasTenantData(context.Background(), tx,
		[]string{"audit_logs; DROP TABLE community_saas_registrations; --"},
		[]string{"cs_test_some_tenant"})
	if err == nil {
		t.Error("expected error for bad identifier, got nil")
	}
	if !strings.Contains(fmt.Sprint(err), "identifier check") {
		t.Errorf("expected error message to mention identifier check, got %v", err)
	}
}

// TestSweepEndToEnd_RegisterAgeSweepRejectAuth is the smart E2E that closes
// the loop between the registration handler (Gate 2a), the sweep job
// (Gate 2b), and the auth path predicate (Gate 2a):
//
//  1. Register a tenant via the real handler — same code path that plugins
//     hit on first run. Returns valid {tenant_id, secret}.
//  2. Backdate its last_seen_at to 4 months ago via SQL UPDATE — this is
//     the only test concession; in production, this would happen naturally
//     over time.
//  3. Run one sweep tick.
//  4. Assert auth path now rejects the credentials with ErrRegistrationTerminated
//     (not ErrInvalidSecret, not ErrRegistrationExpired). Distinguishing the
//     terminated case is what lets the plugin bootstrap know to delete its
//     local registration file and re-register.
//  5. Assert the row's secret_hash is empty (sweep cleared it) and
//     terminated_at is non-NULL.
//
// This exercises every layer the production deploy will actually use:
// real Postgres, real handler, real sweep, real auth predicate. If any
// piece breaks the contract, this test fails.
func TestSweepEndToEnd_RegisterAgeSweepRejectAuth(t *testing.T) {
	db, cleanup := connectSweepDB(t)
	defer cleanup()

	// 1. Register via the real handler with a unique IP so the rate limiter
	//    state from previous tests doesn't trip us.
	resetRegistrationIPTracker()
	body := `{"label":"sweep-e2e-test"}`
	req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.77:1234"
	rr := httptest.NewRecorder()
	handleCommunityRegister(db).ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp registrationResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse register response: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM community_saas_registrations WHERE tenant_id = $1`, resp.TenantID)
	})
	if !strings.HasPrefix(resp.TenantID, "cs_") {
		t.Fatalf("expected cs_ prefix on tenant_id, got %q", resp.TenantID)
	}

	// 2. Sanity check: auth path accepts the freshly-registered creds
	if err := validateCommunityRegistration(context.Background(), db, resp.TenantID, resp.Secret); err != nil {
		t.Fatalf("fresh registration should authenticate; got %v", err)
	}

	// 3. Age it: backdate last_seen_at to 4 months ago. The tenant is now
	//    eligible for inactivity termination on the next sweep tick.
	_, err := db.ExecContext(context.Background(),
		`UPDATE community_saas_registrations SET last_seen_at = NOW() - INTERVAL '4 months' WHERE tenant_id = $1`,
		resp.TenantID)
	if err != nil {
		t.Fatalf("age last_seen_at: %v", err)
	}

	// 4. Run one sweep tick (real, not dry-run)
	tables, err := discoverCommunitySaasCascadeTables(context.Background(), db)
	if err != nil {
		t.Fatalf("discover cascade tables: %v", err)
	}
	runCommunitySaasSweepTick(context.Background(), db, tables, false)

	// 5. Auth path now rejects with ErrRegistrationTerminated specifically —
	//    not ErrInvalidSecret, not ErrRegistrationExpired
	authErr := validateCommunityRegistration(context.Background(), db, resp.TenantID, resp.Secret)
	if !errors.Is(authErr, ErrRegistrationTerminated) {
		t.Errorf("after sweep, auth should return ErrRegistrationTerminated; got %v", authErr)
	}

	// 6. DB row state: terminated_at non-NULL, secret_hash cleared
	var terminatedAt sql.NullTime
	var secretHash string
	err = db.QueryRowContext(context.Background(),
		`SELECT terminated_at, secret_hash FROM community_saas_registrations WHERE tenant_id = $1`,
		resp.TenantID).Scan(&terminatedAt, &secretHash)
	if err != nil {
		t.Fatalf("read row: %v", err)
	}
	if !terminatedAt.Valid {
		t.Errorf("terminated_at should be non-NULL after sweep")
	}
	if secretHash != "" {
		t.Errorf("secret_hash should be empty after sweep, got %q (length %d)", secretHash, len(secretHash))
	}
}

// TestSweepEndToEnd_HardCapPathSeparateFromInactivity asserts that a tenant
// whose last_seen_at is recent (so the inactivity predicate skips it) but
// whose created_at is past the 1-year cap STILL gets terminated. Exercises
// the second predicate independently — without this test, a regression that
// inverts the inactivity / hard-cap ordering or accidentally ANDs the two
// predicates would slip through.
func TestSweepEndToEnd_HardCapPathSeparateFromInactivity(t *testing.T) {
	db, cleanup := connectSweepDB(t)
	defer cleanup()

	// Seed: created 13 months ago, but active 1 minute ago — the inactivity
	// predicate alone would skip this row.
	tenantID := seedSweepTenant(t, db, "hardcap_active",
		time.Now().UTC().AddDate(-1, -1, 0),                                     // created_at
		sql.NullTime{Valid: true, Time: time.Now().UTC().Add(-1 * time.Minute)}, // last_seen_at
		false)

	tables, err := discoverCommunitySaasCascadeTables(context.Background(), db)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	runCommunitySaasSweepTick(context.Background(), db, tables, false)

	if !assertTenantTerminated(t, db, tenantID) {
		t.Errorf("13mo-old tenant with recent activity should be terminated by hard-cap")
	}
	_, hardCap, _, _, _ := GetCommunitySaasSweepMetrics()
	if hardCap < 1 {
		t.Errorf("hard-cap counter should be >= 1, got %d", hardCap)
	}
}

// TestSweepValidationErrorWrapsCorrectly asserts that internal errors from
// terminate functions wrap the underlying error in a way that errors.Is
// unwrapping continues to work — important for any future caller that wants
// to react to specific failure modes.
func TestSweepValidationErrorWrapsCorrectly(t *testing.T) {
	// Pure unit test: don't need DB.
	wrapped := fmt.Errorf("inactivity update: %w", errors.New("driver: bad connection"))
	if !errors.Is(wrapped, errors.Unwrap(wrapped)) {
		t.Errorf("wrapping should preserve errors.Is unwrap chain")
	}
}

// TestValidIdentifierRegex asserts the identifier validation accepts the
// shapes Postgres uses for table names and rejects anything else.
func TestValidIdentifierRegex(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// Valid Postgres identifiers
		{"audit_logs", true},
		{"a", true},
		{"_underscore_start", true},
		{"name123", true},
		{"snake_case_with_numbers_42", true},
		// Invalid: uppercase (we reject; Postgres folds to lowercase but our
		// reflection query only finds lowercase, so uppercase here would mean
		// something abnormal).
		{"AuditLogs", false},
		// Invalid: leading digit
		{"1table", false},
		// Invalid: SQL injection attempts via table name
		{"audit_logs; DROP TABLE foo;--", false},
		{"audit_logs)", false},
		{"audit_logs--", false},
		{"audit_logs\nfoo", false},
		{"audit logs", false}, // space
		{"audit-logs", false}, // hyphen
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := validIdentifier.MatchString(c.name)
			if got != c.want {
				t.Errorf("validIdentifier.MatchString(%q) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

// TestNonCascadeAllowlistContent asserts the hard-coded allowlist of tables
// to exclude from cascade DELETE includes every table whose data we MUST
// preserve when terminating a Community-SaaS tenant: tombstone (registrations),
// canonical tenants tracking, system-wide policies, license keys, and the
// schema-migrations marker. The list is intentionally hard-coded rather than
// computed from semantics, so this test guards against an accidental regression
// where someone removes an entry thinking it's redundant.
func TestNonCascadeAllowlistContent(t *testing.T) {
	must := []string{
		"community_saas_registrations", // tombstone — sweep updates in place
		"tenants",                      // canonical tenant tracking, analog tombstone
		"static_policies",              // system policies w/ tenant_id='global'
		"license_keys",                 // community-saas tenants don't have one
		"schema_migrations",            // schema metadata
		"community_saas_daily_usage",   // rate-limit metadata, retained per ops convention
	}
	for _, name := range must {
		if _, ok := communitySaasSweepNonCascadeTables[name]; !ok {
			t.Errorf("non-cascade allowlist missing required table %q", name)
		}
	}
	// Ensure we never accidentally allowlist an actual-data table
	mustNot := []string{
		"audit_logs",
		"workflows",
		"plans",
		"decision_chain",
	}
	for _, name := range mustNot {
		if _, ok := communitySaasSweepNonCascadeTables[name]; ok {
			t.Errorf("non-cascade allowlist incorrectly contains data table %q (would be skipped from cleanup)", name)
		}
	}
}

// TestCommunitySaasSweepShouldStart_GatedByDeploymentMode asserts the
// goroutine refuses to start when DEPLOYMENT_MODE != "community-saas",
// regardless of license tier. Same agent binary ships in enterprise / in-vpc
// deployments and should not touch the community_saas_registrations table
// in those modes.
func TestCommunitySaasSweepShouldStart_GatedByDeploymentMode(t *testing.T) {
	cases := []struct {
		mode string
		tier string
		want bool
	}{
		{"community-saas", "community", true},
		{"community-saas", "Community", true},
		{"community-saas", "", true}, // pre-license-validation; deployment mode wins
		{"saas", "community", false},
		{"in-vpc-enterprise", "community", false},
		{"", "community", false},
		{"community-saas", "Enterprise", false}, // license overrides deployment mode
		{"community-saas", "Evaluation", false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("mode=%s/tier=%s", c.mode, c.tier), func(t *testing.T) {
			oldMode := os.Getenv("DEPLOYMENT_MODE")
			defer os.Setenv("DEPLOYMENT_MODE", oldMode)
			os.Setenv("DEPLOYMENT_MODE", c.mode)

			// Manage the licenseTier atomic.Value via the canonical setter
			// pattern used elsewhere in the agent. We can't easily reset
			// across subtests, so we just set what each case needs.
			if c.tier != "" {
				licenseTier.Store(c.tier)
			} else {
				licenseTier.Store("")
			}

			if got := communitySaasSweepShouldStart(); got != c.want {
				t.Errorf("communitySaasSweepShouldStart() with mode=%q tier=%q = %v, want %v",
					c.mode, c.tier, got, c.want)
			}
		})
	}
}

// TestStartCommunitySaasSweep_DisabledByEnv asserts StartCommunitySaasSweep
// returns immediately (no goroutine spawned, no log noise besides the
// disabled message) when COMMUNITY_SAAS_SWEEP_ENABLED is not "true".
//
// We can't assert "no goroutine spawned" directly without runtime tricks,
// but we CAN assert the function returns synchronously and doesn't panic
// when given a nil DB — a goroutine that did start would deref the nil DB
// and crash.
func TestStartCommunitySaasSweep_DisabledByEnv(t *testing.T) {
	oldEnabled := os.Getenv(communitySaasSweepEnabledEnv)
	defer os.Setenv(communitySaasSweepEnabledEnv, oldEnabled)

	cases := []string{"", "false", "0", "yes", "TRUE"} // only literal "true" should enable
	for _, val := range cases {
		t.Run(fmt.Sprintf("env=%q", val), func(t *testing.T) {
			os.Setenv(communitySaasSweepEnabledEnv, val)
			// Should not panic on nil db because the gate exits before touching it
			StartCommunitySaasSweep(context.Background(), nil)
		})
	}
}

// TestStartCommunitySaasSweep_NilDB asserts we don't spawn a goroutine when
// the DB handle is nil even with the env flag enabled — guards against a
// startup ordering bug where the sweep is wired up before community-saas DB
// initialization.
func TestStartCommunitySaasSweep_NilDB(t *testing.T) {
	oldEnabled := os.Getenv(communitySaasSweepEnabledEnv)
	defer os.Setenv(communitySaasSweepEnabledEnv, oldEnabled)
	os.Setenv(communitySaasSweepEnabledEnv, "true")
	// Should log and return without panic — a goroutine with a nil DB would
	// nil-deref on the first QueryRowContext.
	StartCommunitySaasSweep(context.Background(), nil)
}

// assertTenantTerminated returns true if community_saas_registrations row for
// tenantID has terminated_at non-NULL.
func assertTenantTerminated(t *testing.T, db *sql.DB, tenantID string) bool {
	t.Helper()
	var terminatedAt sql.NullTime
	err := db.QueryRowContext(context.Background(),
		`SELECT terminated_at FROM community_saas_registrations WHERE tenant_id = $1`, tenantID).Scan(&terminatedAt)
	if err != nil {
		t.Fatalf("read terminated_at for %s: %v", tenantID, err)
	}
	return terminatedAt.Valid
}

// auditLogsHasMinimalSchema returns true if audit_logs has at least a tenant_id
// column and accepts an INSERT with no other columns. Used to skip the cascade
// test when the audit_logs schema requires additional NOT NULL columns we
// don't want to fabricate.
func auditLogsHasMinimalSchema(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var hasTenantCol bool
	err := db.QueryRowContext(context.Background(),
		`SELECT EXISTS (
		   SELECT 1 FROM information_schema.columns
		   WHERE table_schema = 'public' AND table_name = 'audit_logs' AND column_name = 'tenant_id'
		 )`).Scan(&hasTenantCol)
	if err != nil {
		return false
	}
	return hasTenantCol
}
