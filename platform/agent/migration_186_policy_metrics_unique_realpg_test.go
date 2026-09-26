// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres proof for migration 186 (#4249): policy_metrics gets the
// (org_id, policy_id, date) unique index the agent's metrics UPSERT names.
//
//	Pin 1 - over a table seeded at 185 with two rows sharing one key, another
//	        organization's row for the same policy and day, and two
//	        orchestrator rows with no policy_id, 186 applies: the pair collapses
//	        into one row carrying the summed counts, and every other row is
//	        untouched.
//	Pin 2 - after 186, written by the APPLICATION ROLE through the agent's own
//	        flushMetricsBatch: two entries for one organization, policy and day
//	        are one row (hit_count 2, block_count 1), and a second flush for that
//	        key conflicts and adds to it (hit_count 3); another organization's
//	        entry for the same policy and day is its own row; the orchestrator's
//	        per-evaluation INSERT (no policy_id) still succeeds twice.
//	Pin 3 - the index is load-bearing: with 186's down applied the same flush
//	        writes nothing (42P10, counted as metrics_write_failed); 186
//	        re-applies over the rows Pin 2's shape leaves.
//	Pin 4 - a database initialized by the retired init-rds.sh carries
//	        UNIQUE(policy_id, date): 186 drops it, and two organizations' rows
//	        for one policy and day then both land.
//
// Gated on TEST_PG_INTEGRATION=1 through approletest.

import (
	"context"
	"database/sql"
	"testing"

	"axonflow/platform/agent/approletest"
)

const (
	mig186Path     = "../../migrations/core/186_policy_metrics_org_policy_date_unique.sql"
	mig186DownPath = "../../migrations/core/186_policy_metrics_org_policy_date_unique_down.sql"
)

// mig186Rows reads policy_metrics as the master role (row-level security off
// for the owner), one "org|policy|hit|block|n" string per key, sorted.
func mig186Rows(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT COALESCE(org_id, '<null>') || '|' || COALESCE(policy_id, '<null>') || '|' ||
		       SUM(COALESCE(hit_count, 0)) || '|' || SUM(COALESCE(block_count, 0)) || '|' || COUNT(*)
		  FROM policy_metrics
		 GROUP BY org_id, policy_id
		 ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func mig186Equal(t *testing.T, step string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: policy_metrics reads %q, want %q", step, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s: policy_metrics reads %q, want %q", step, got, want)
		}
	}
}

// mig186OrchestratorInsert is db_dynamic_policies.go's per-evaluation row, in
// its column shape, under its organization scope.
func mig186OrchestratorInsert(db *sql.DB, org string) error {
	return WithOrgScope(context.Background(), db, org, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO policy_metrics (policy_name, execution_time_ms, success, tenant_id, org_id)
			VALUES ('evaluation', 3, true, 'tenant', $1)`, org)
		return err
	})
}

func mig186Flush(t *testing.T, db *sql.DB, entries []AuditEntry) {
	t.Helper()
	aq := unstartedQueue(t, AuditModePerformance, 10)
	aq.db = db
	aq.flushMetricsBatch(entries)
}

func TestMigration186_CollapsesDuplicateKeysAndLeavesEveryOtherRow(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.SetupAtVersion(t, "../../migrations/core", 185)
	master := mig178Open(t, env.MasterDSN)

	if _, err := master.Exec(`
		INSERT INTO policy_metrics (org_id, policy_id, policy_type, hit_count, block_count, allow_count, date) VALUES
			('org-a', 'sys_pii_ssn', 'static', 2, 1, 0, CURRENT_DATE),
			('org-a', 'sys_pii_ssn', 'static', 3, 0, 4, CURRENT_DATE),
			('org-b', 'sys_pii_ssn', 'static', 7, 2, 0, CURRENT_DATE);
		INSERT INTO policy_metrics (org_id, policy_name, execution_time_ms, success, tenant_id) VALUES
			('org-a', 'evaluation', 5, true, 't'),
			('org-a', 'evaluation', 6, false, 't');`); err != nil {
		t.Fatalf("seeding at 185: %v", err)
	}
	if _, err := master.Exec(mig181SQL(t, mig186Path)); err != nil {
		t.Fatalf("186 did not apply over a table holding a duplicate key: %v", err)
	}
	mig186Equal(t, "after 186", mig186Rows(t, master), []string{
		"org-a|<null>|0|0|2",
		"org-a|sys_pii_ssn|5|1|1",
		"org-b|sys_pii_ssn|7|2|1",
	})
	var allow int
	if err := master.QueryRow(`SELECT allow_count FROM policy_metrics WHERE org_id = 'org-a' AND policy_id = 'sys_pii_ssn'`).Scan(&allow); err != nil || allow != 4 {
		t.Fatalf("the collapsed row's allow_count is %d (%v), want the sum 4", allow, err)
	}
}

func TestMigration186_TheAgentsUpsertLandsPerOrganizationAndTheOrchestratorsInsertStillSucceeds(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	master := mig178Open(t, env.MasterDSN)
	app := mig178Open(t, env.AppRoleDSN)

	before := droppedAt(auditDropMetricsWriteFailed)
	mig186Flush(t, app, []AuditEntry{
		{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "sys_pii_ssn", "blocked": true}},
		{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "sys_pii_ssn", "blocked": false}},
		{OrgID: "org-b", Details: map[string]interface{}{"policy_id": "sys_pii_ssn", "blocked": true}},
	})
	if got := droppedAt(auditDropMetricsWriteFailed) - before; got != 0 {
		t.Fatalf("%v metrics writes failed under the application role; want every entry written", got)
	}
	// A SECOND FLUSH for the same organization, policy and day conflicts with
	// the row the first wrote: DO UPDATE adds EXCLUDED's counts under the
	// application role's RLS UPDATE policy, through the partial index.
	mig186Flush(t, app, []AuditEntry{
		{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "sys_pii_ssn", "blocked": false}},
	})
	if got := droppedAt(auditDropMetricsWriteFailed) - before; got != 0 {
		t.Fatalf("the conflicting second flush failed under the application role (%v entries)", got)
	}
	for i := 0; i < 2; i++ {
		if err := mig186OrchestratorInsert(app, "org-a"); err != nil {
			t.Fatalf("the orchestrator's per-evaluation INSERT failed after 186 (attempt %d): %v", i+1, err)
		}
	}
	mig186Equal(t, "after the writes", mig186Rows(t, master), []string{
		"org-a|<null>|0|0|2",
		"org-a|sys_pii_ssn|3|1|1",
		"org-b|sys_pii_ssn|1|1|1",
	})
}

func TestMigration186_TheIndexIsWhatTheUpsertNeedsAndItReapplies(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	master := mig178Open(t, env.MasterDSN)
	app := mig178Open(t, env.AppRoleDSN)

	if _, err := master.Exec(mig181SQL(t, mig186DownPath)); err != nil {
		t.Fatalf("186 down: %v", err)
	}
	before := droppedAt(auditDropMetricsWriteFailed)
	mig186Flush(t, app, []AuditEntry{{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "sys_pii_ssn", "blocked": true}}})
	if got := droppedAt(auditDropMetricsWriteFailed) - before; got != 1 {
		t.Fatalf("without the index the UPSERT failed %v times, want 1 (42P10, counted)", got)
	}
	mig186Equal(t, "without the index", mig186Rows(t, master), nil)

	if _, err := master.Exec(mig181SQL(t, mig186Path)); err != nil {
		t.Fatalf("186 did not re-apply: %v", err)
	}
	if _, err := master.Exec(mig181SQL(t, mig186Path)); err != nil {
		t.Fatalf("186 is not idempotent: %v", err)
	}
	mig186Flush(t, app, []AuditEntry{{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "sys_pii_ssn", "blocked": true}}})
	mig186Equal(t, "after re-applying 186", mig186Rows(t, master), []string{"org-a|sys_pii_ssn|1|1|1"})
}

func TestMigration186_DropsALegacyPolicyDateUniqueConstraint(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.SetupAtVersion(t, "../../migrations/core", 185)
	master := mig178Open(t, env.MasterDSN)
	app := mig178Open(t, env.AppRoleDSN)

	if _, err := master.Exec(`ALTER TABLE policy_metrics ADD CONSTRAINT policy_metrics_policy_id_date_key UNIQUE (policy_id, date)`); err != nil {
		t.Fatalf("PREMISE: adding the legacy constraint: %v", err)
	}
	// And a standalone legacy unique INDEX on the same columns (in the other
	// order), which the DO block's second loop must find.
	if _, err := master.Exec(`CREATE UNIQUE INDEX policy_metrics_legacy_date_policy ON policy_metrics (date, policy_id)`); err != nil {
		t.Fatalf("PREMISE: adding the legacy index: %v", err)
	}
	if _, err := master.Exec(mig181SQL(t, mig186Path)); err != nil {
		t.Fatalf("186 did not apply over the legacy constraint: %v", err)
	}
	var legacy int
	if err := master.QueryRow(`SELECT count(*) FROM pg_constraint WHERE conrelid = 'policy_metrics'::regclass AND conname = 'policy_metrics_policy_id_date_key'`).Scan(&legacy); err != nil || legacy != 0 {
		t.Fatalf("the legacy constraint is still present (%d, %v)", legacy, err)
	}
	if err := master.QueryRow(`SELECT count(*) FROM pg_class WHERE relname = 'policy_metrics_legacy_date_policy'`).Scan(&legacy); err != nil || legacy != 0 {
		t.Fatalf("the legacy unique index is still present (%d, %v)", legacy, err)
	}
	before := droppedAt(auditDropMetricsWriteFailed)
	mig186Flush(t, app, []AuditEntry{
		{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "sys_pii_ssn", "blocked": true}},
		{OrgID: "org-b", Details: map[string]interface{}{"policy_id": "sys_pii_ssn", "blocked": false}},
	})
	if got := droppedAt(auditDropMetricsWriteFailed) - before; got != 0 {
		t.Fatalf("%v metrics writes failed after 186 dropped the legacy constraint", got)
	}
	mig186Equal(t, "two organizations, one policy and day", mig186Rows(t, master), []string{
		"org-a|sys_pii_ssn|1|1|1",
		"org-b|sys_pii_ssn|1|0|1",
	})
}
