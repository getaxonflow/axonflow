// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package queue

// Real-Postgres proof for #3520 item 2: THE UNSCOPED SWEEP MATCHES NOTHING AND
// REPORTS SUCCESS.
//
// The claim is not that the old statement was wrong SQL - it was correct SQL.
// The claim is that under FORCE ROW LEVEL SECURITY, as a non-owner role with no
// `app.current_org_id` set, it updates ZERO ROWS and returns no error. That is
// the #3048 shape, and it is why the Evaluation-tier 24h auto-expiry has done
// nothing on every app-role deployment since v9 while its log line said nothing
// at all.
//
// Nothing but a real Postgres can show this. sqlmock returns whatever the test
// tells it to; a unit test asserting "the code passes an admin pool" asserts the
// fix's SHAPE rather than its EFFECT, which is the cheaper signal the behaviour
// usually produces.
//
// Skips cleanly when Docker is unavailable (CI unit lane).

import (
	"context"
	"database/sql"
	"net/url"
	"testing"

	"axonflow/platform/testutil"
)

// appRoleDSN rewrites the container's owner DSN to log in as a different role.
//
// Local to this test rather than added to platform/testutil: exactly one test
// needs it, and a shared helper with one caller is a guess about the second.
func appRoleDSN(t *testing.T, ownerURL, role, password string) string {
	t.Helper()
	u, err := url.Parse(ownerURL)
	if err != nil {
		t.Fatalf("parse container DSN: %v", err)
	}
	u.User = url.UserPassword(role, password)
	return u.String()
}

// hitlQueueRLSDDL is migration core/025's shape for this table, reduced to what
// the sweep touches, PLUS the RLS posture v9 turned on.
//
// FORCE ROW LEVEL SECURITY is the load-bearing line and it is not in migration
// 025 itself - migration 098/101 add it. Without FORCE, the TABLE OWNER bypasses
// RLS and the whole distinction this test measures disappears: both arms would
// return the same rows and the test would pass while proving nothing.
const hitlQueueRLSDDL = `
CREATE TABLE IF NOT EXISTS hitl_approval_queue (
    id BIGSERIAL PRIMARY KEY,
    request_id UUID NOT NULL UNIQUE,
    org_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    original_query TEXT NOT NULL,
    request_context JSONB DEFAULT '{}'::jsonb,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION get_current_org_id() RETURNS TEXT AS $$
    SELECT current_setting('app.current_org_id', true);
$$ LANGUAGE SQL STABLE;

ALTER TABLE hitl_approval_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE hitl_approval_queue FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS hitl_queue_tenant_isolation ON hitl_approval_queue;
CREATE POLICY hitl_queue_tenant_isolation ON hitl_approval_queue
    USING (org_id = get_current_org_id())
    WITH CHECK (org_id = get_current_org_id());

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        CREATE ROLE axonflow_app_role LOGIN PASSWORD 'apppass';
    END IF;
END
$$;
GRANT USAGE ON SCHEMA public TO axonflow_app_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON hitl_approval_queue TO axonflow_app_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO axonflow_app_role;
`

// unscopedExpireSQL is the statement expireEvalApprovals ran before #3520,
// verbatim from origin/main.
//
// Written out here rather than derived from ExpireDueReturningSQL on purpose: a
// fixture built by mutating the FIXED statement inherits whatever the fix does
// and cannot express the defect. This is the defect.
const unscopedExpireSQL = `UPDATE hitl_approval_queue
		 SET status = 'expired', updated_at = NOW()
		 WHERE status = 'pending' AND expires_at < NOW()
		 RETURNING request_id, tenant_id, original_query, request_context`

func seedExpiredApprovals(t *testing.T, db *sql.DB, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := db.Exec(`
			INSERT INTO hitl_approval_queue (request_id, org_id, tenant_id, original_query, status, expires_at)
			VALUES (gen_random_uuid(), $1, 'tenant-1', 'held request', 'pending', NOW() - INTERVAL '1 hour')`,
			"org-"+string(rune('a'+i%3))); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
}

func countPendingApprovals(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM hitl_approval_queue WHERE status = 'pending'`).Scan(&n); err != nil {
		t.Fatalf("count pending: %v", err)
	}
	return n
}

func TestUnscopedExpirySweepMatchesNothingUnderAppRole_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, hitlQueueRLSDDL)

	ctx := context.Background()
	seedExpiredApprovals(t, pg.DB, 6)

	// The APP-ROLE connection: a non-owner login with no app.current_org_id set,
	// which is exactly what an orchestrator running with
	// AXONFLOW_DB_USE_APP_ROLE=true hands InitializeWCPHITL.
	appDSN := appRoleDSN(t, pg.URL, "axonflow_app_role", "apppass")
	appDB, err := sql.Open("postgres", appDSN)
	if err != nil {
		t.Fatalf("open app-role connection: %v", err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	appDB.SetMaxOpenConns(1)

	var role string
	if err := appDB.QueryRow("SELECT current_user").Scan(&role); err != nil {
		t.Fatalf("probe current_user: %v", err)
	}
	if role != "axonflow_app_role" {
		t.Fatalf("connected as %q, not axonflow_app_role; this test would then be measuring the "+
			"OWNER, which bypasses nothing and would pass for the wrong reason", role)
	}

	// --- THE DEFECT -------------------------------------------------------
	rows, err := appDB.QueryContext(ctx, unscopedExpireSQL)
	if err != nil {
		t.Fatalf("the unscoped sweep ERRORED (%v). The point of #3520 is that it does NOT: "+
			"an error would have been noticed years ago.", err)
	}
	matched := 0
	for rows.Next() {
		matched++
	}
	_ = rows.Close()

	if matched != 0 {
		t.Fatalf("the unscoped sweep matched %d rows under axonflow_app_role. Either FORCE RLS is "+
			"not in effect in this fixture or the policy is not applying - and then the fix below "+
			"proves nothing, because there was nothing to fix.", matched)
	}
	if got := countPendingApprovals(t, pg.DB); got != 6 {
		t.Fatalf("after the unscoped sweep %d of 6 rows are still pending, want 6", got)
	}
	t.Log("the unscoped sweep updated 0 of 6 expired approvals and returned NO ERROR - " +
		"the #3048 shape, and the reason the Evaluation-tier auto-expiry has been inert " +
		"on every app-role deployment (#3520)")

	// --- THE FIX ----------------------------------------------------------
	// ExpireDueReturning on the cross-tenant pool. pg.DB is the owner, which is
	// what a BYPASSRLS platform-admin pool is on a real deployment: it is not
	// subject to the policy.
	fixed, err := ExpireDueReturning(ctx, pg.DB, 100)
	if err != nil {
		t.Fatalf("ExpireDueReturning on the cross-tenant pool: %v", err)
	}
	expired := 0
	for fixed.Next() {
		expired++
	}
	_ = fixed.Close()

	if expired != 6 {
		t.Errorf("the fixed sweep expired %d of 6 approvals, want 6", expired)
	}
	if got := countPendingApprovals(t, pg.DB); got != 0 {
		t.Errorf("%d approvals are still pending after the fixed sweep, want 0", got)
	}
}

// TestExpireDueReturningBatchBoundIsRealAndDrains_RealPostgres.
//
// The batch bound is the blast-radius control for the FIRST tick after a
// deployment upgrades onto a working sweeper: without it, every approval that
// has sat falsely pending since that deployment moved to app_role is expired in
// one transaction and its workflow aborted with it.
//
// Two properties, and the second is why the first is not enough: the bound must
// HOLD (a tick expires at most N) and the sweep must DRAIN (successive ticks
// finish the backlog). A bound that held but never drained would swap a silent
// no-op for a silent partial one.
func TestExpireDueReturningBatchBoundIsRealAndDrains_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, hitlQueueRLSDDL)

	ctx := context.Background()
	seedExpiredApprovals(t, pg.DB, 7)

	rows, err := ExpireDueReturning(ctx, pg.DB, 3)
	if err != nil {
		t.Fatalf("tick 1: %v", err)
	}
	first := 0
	for rows.Next() {
		first++
	}
	_ = rows.Close()
	if first != 3 {
		t.Fatalf("tick 1 expired %d, want exactly the batch bound of 3", first)
	}
	if got := countPendingApprovals(t, pg.DB); got != 4 {
		t.Fatalf("after tick 1, %d pending, want 4", got)
	}

	total := first
	for tick := 2; tick <= 5 && countPendingApprovals(t, pg.DB) > 0; tick++ {
		r, err := ExpireDueReturning(ctx, pg.DB, 3)
		if err != nil {
			t.Fatalf("tick %d: %v", tick, err)
		}
		for r.Next() {
			total++
		}
		_ = r.Close()
	}
	if total != 7 {
		t.Errorf("successive ticks expired %d of 7; the backlog does not drain", total)
	}
	if got := countPendingApprovals(t, pg.DB); got != 0 {
		t.Errorf("%d approvals still pending after draining, want 0", got)
	}
}

// TestExpireDueReturningRefusesAnUnusablePool.
//
// A nil pool and a non-positive limit are both refused rather than treated as
// "no pool, use the default" and "no limit, take everything". The first is the
// #3520 fail-open direction; the second is the blast radius the bound exists to
// stop, reintroduced by a caller that passes 0.
func TestExpireDueReturningRefusesAnUnusablePool(t *testing.T) {
	if _, err := ExpireDueReturning(context.Background(), nil, 10); err == nil {
		t.Error("a nil pool was accepted; on an app-role deployment a sweep with no cross-tenant " +
			"pool matches nothing and reports success")
	}
	for _, limit := range []int{0, -1} {
		if _, err := ExpireDueReturning(context.Background(), &sql.DB{}, limit); err == nil {
			t.Errorf("a limit of %d was accepted; an unbounded first tick is what the bound exists "+
				"to prevent", limit)
		}
	}
}
