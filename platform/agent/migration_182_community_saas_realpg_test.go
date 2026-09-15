// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real Postgres proof of migrations/community-saas/182 (#4017), the deploy-time
// backfill that gives every Community SaaS organization registered before the
// registration began recording it the same sqli=block override and
// DETECTION_POSTURE_SET admin_audit_log row a new registration gets.
//
// It proves, on the real chain (approletest.Setup applies every core
// migration; community-saas/088 and 182 are applied here as the runner applies
// them, one batch each):
//   - the dry run: the file inside a transaction that is rolled back records
//     nothing, which is what scripts/migrations/dry-run-community-saas-182.sh
//     relies on;
//   - WHO: every live cs_ organization, and not a terminated one, nor a live
//     registration outside the cs_ fence;
//   - WHAT: one override per organization, updated_by the migration's actor,
//     and one audit row for each row it inserted - and an organization that
//     already recorded a sqli action keeps it, with no row;
//   - it is idempotent, and leaves no function behind;
//   - its down withdraws only the overrides the backfill recorded and nobody
//     changed since, recording each withdrawal.
//
// Gating: TEST_PG_INTEGRATION=1 + docker (approletest.SkipUnlessEnabled).
// Wired into .github/workflows/migrations-gate.yml.

import (
	"database/sql"
	"os"
	"testing"

	"axonflow/platform/agent/approletest"
)

const migration182Actor = "system:community-saas/182"

func applyMigrationFile(t *testing.T, db interface {
	Exec(string, ...any) (sql.Result, error)
}, path string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("apply %s: %v", path, err)
	}
}

func TestCommunitySaasMigration182RecordsSQLInjectionBlockOnceForEveryLiveOrganization_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	db, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	defer func() { _ = db.Close() }()
	applyMigrationFile(t, db, "../../migrations/community-saas/088_admin_audit_log.sql")

	const (
		live      = "cs_182_live"
		chose     = "cs_182_chose_warn"
		gone      = "cs_182_terminated"
		canary    = "axonflow-internal-canary-182"
		upPath    = "../../migrations/community-saas/182_sqli_block_backfill.sql"
		downPath  = "../../migrations/community-saas/182_sqli_block_backfill_down.sql"
		operator  = "admin@chose.example"
		recording = "DETECTION_POSTURE_SET"
	)
	for _, reg := range []struct {
		org        string
		terminated bool
	}{{live, false}, {chose, false}, {gone, true}, {canary, false}} {
		if _, err := db.Exec(`INSERT INTO community_saas_registrations
			  (tenant_id, client_id, secret_hash, secret_prefix, org_id, label, expires_at, terminated_at)
			VALUES ($1, $1, 'x', 'x', $1, '182', NOW() + INTERVAL '1 year', CASE WHEN $2 THEN NOW() END)`,
			reg.org, reg.terminated); err != nil {
			t.Fatalf("seed registration %s: %v", reg.org, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO detection_action_overrides (org_id, category, action, updated_by)
		VALUES ($1, 'sqli', 'warn', $2)`, chose, operator); err != nil {
		t.Fatalf("seed %s's own choice: %v", chose, err)
	}

	override := func(org string) (action, by string, ok bool) {
		t.Helper()
		err := db.QueryRow(`SELECT action, updated_by FROM detection_action_overrides WHERE org_id = $1 AND category = 'sqli'`, org).Scan(&action, &by)
		if err == sql.ErrNoRows {
			return "", "", false
		}
		if err != nil {
			t.Fatalf("read %s's override: %v", org, err)
		}
		return action, by, true
	}
	audits := func(org, action string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM admin_audit_log
			 WHERE org_id = $1 AND action = $2 AND admin_identifier = $3 AND success
			   AND details->>'category' = 'sqli'`, org, action, migration182Actor).Scan(&n); err != nil {
			t.Fatalf("count %s's audit rows: %v", org, err)
		}
		return n
	}

	t.Run("the dry run records nothing", func(t *testing.T) {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		applyMigrationFile(t, tx, upPath)
		if err := tx.Rollback(); err != nil {
			t.Fatalf("roll the dry run back: %v (a COMMIT inside the file would have ended the transaction early)", err)
		}
		if _, _, ok := override(live); ok {
			t.Fatal("the rolled-back run left an override: the file commits on its own, so its dry run would record")
		}
		if n := audits(live, recording); n != 0 {
			t.Fatalf("the rolled-back run left %d audit row(s)", n)
		}
	})

	t.Run("every live cs_ organization gets sqli=block and one audit row; nobody else changes", func(t *testing.T) {
		applyMigrationFile(t, db, upPath)
		if action, by, ok := override(live); !ok || action != "block" || by != migration182Actor {
			t.Fatalf("%s: override = %q by %q (present %v), want block by %s", live, action, by, ok, migration182Actor)
		}
		if n := audits(live, recording); n != 1 {
			t.Fatalf("%s: %d DETECTION_POSTURE_SET row(s), want 1", live, n)
		}
		if action, by, _ := override(chose); action != "warn" || by != operator {
			t.Fatalf("%s: override = %q by %q, want its own warn by %s kept", chose, action, by, operator)
		}
		if n := audits(chose, recording); n != 0 {
			t.Fatalf("%s: the backfill audited a change it did not make (%d row(s))", chose, n)
		}
		for _, untouched := range []string{gone, canary} {
			if _, _, ok := override(untouched); ok {
				t.Fatalf("%s got an override: the backfill is for live cs_ organizations only", untouched)
			}
		}
		var left int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pg_proc WHERE proname LIKE 'csaas_backfill_4017%'`).Scan(&left); err != nil || left != 0 {
			t.Fatalf("the backfill left %d function(s) behind (err %v)", left, err)
		}
	})

	t.Run("a second run changes nothing", func(t *testing.T) {
		applyMigrationFile(t, db, upPath)
		if n := audits(live, recording); n != 1 {
			t.Fatalf("%s: %d DETECTION_POSTURE_SET row(s) after a second run, want still 1", live, n)
		}
	})

	t.Run("the down withdraws only what the backfill recorded, and records it", func(t *testing.T) {
		applyMigrationFile(t, db, downPath)
		if _, _, ok := override(live); ok {
			t.Fatalf("%s: the backfill's override survived its down", live)
		}
		if n := audits(live, "DETECTION_POSTURE_DELETE"); n != 1 {
			t.Fatalf("%s: %d DETECTION_POSTURE_DELETE row(s), want 1", live, n)
		}
		if n := audits(live, recording); n != 1 {
			t.Fatalf("%s: the down erased the up's audit row (%d left), want the history kept", live, n)
		}
		if action, by, _ := override(chose); action != "warn" || by != operator {
			t.Fatalf("%s: the down touched an override the backfill never wrote: %q by %q", chose, action, by)
		}
	})
}
