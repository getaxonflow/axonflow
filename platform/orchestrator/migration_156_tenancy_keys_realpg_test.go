//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Real-Postgres proof for migration core/156 (#3065) against a PRE-UPGRADE
// fixture.
//
// The migrations CI gate applies the whole chain to a FRESH database, where
// `UPDATE ... WHERE col IS NULL OR btrim(col) = <empty>` stamps zero rows. That
// exercises none of what 156 is for: the backfill branch, the DROP DEFAULT on
// webhook_subscriptions (mig 048 declared it NOT NULL with an empty-string
// DEFAULT, so the
// constraint existed and the default recreated the exploit value), and
// constraining a table that actually has offenders.
//
// So this test reproduces the shape a real deployment has at upgrade time —
// nullable/defaulted tenancy columns holding NULLs and empty strings — applies
// the REAL migration file, and asserts on the outcome.
package orchestrator

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
)

const migration156Sentinel = "__axonflow_unowned__"

func applyMigration156File(t *testing.T, db *sql.DB, name string) {
	t.Helper()
	sqlBytes, err := os.ReadFile(filepath.Join("..", "..", "migrations", "core", name))
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	if _, err := db.Exec(string(sqlBytes)); err != nil {
		t.Fatalf("apply migration %s: %v", name, err)
	}
}

// seedPreUpgradeShape builds the four tables as they exist BEFORE 156: tenancy
// columns nullable (plans / workflows / workflow_checkpoints /
// execution_summaries) or NOT NULL with an empty-string DEFAULT
// (webhook_subscriptions, per mig 048), and seeds both an owned row and an
// unowned one in each.
func seedPreUpgradeShape(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		`CREATE TABLE plans (
			plan_id   VARCHAR(255) PRIMARY KEY,
			org_id    VARCHAR(255),
			tenant_id VARCHAR(255))`,
		`CREATE TABLE workflows (
			workflow_id VARCHAR(255) PRIMARY KEY,
			org_id      VARCHAR(255),
			tenant_id   VARCHAR(255))`,
		`CREATE TABLE workflow_checkpoints (
			id        BIGSERIAL PRIMARY KEY,
			org_id    VARCHAR(255),
			tenant_id VARCHAR(255))`,
		`CREATE TABLE execution_summaries (
			request_id VARCHAR(255) PRIMARY KEY,
			org_id     VARCHAR(255),
			tenant_id  VARCHAR(255))`,
		// The real mig-048 shape: the NOT NULL was already there and did
		// nothing, because the DEFAULT supplies the exploit value.
		`CREATE TABLE webhook_subscriptions (
			id        TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL DEFAULT '',
			org_id    TEXT NOT NULL DEFAULT '')`,

		`INSERT INTO plans VALUES ('owned', 'org-a', 'tenant-a'), ('orphan-null', NULL, NULL), ('orphan-empty', '', '')`,
		`INSERT INTO workflows VALUES ('owned', 'org-a', 'tenant-a'), ('orphan-null', NULL, NULL)`,
		`INSERT INTO workflow_checkpoints (org_id, tenant_id) VALUES ('org-a', 'tenant-a'), (NULL, NULL)`,
		`INSERT INTO execution_summaries VALUES ('owned', 'org-a', 'tenant-a'), ('orphan-empty', '   ', '')`,
		// Omits both columns entirely — the DEFAULT '' path, which is how
		// unowned webhook rows were actually created.
		`INSERT INTO webhook_subscriptions (id) VALUES ('orphan-default')`,
		`INSERT INTO webhook_subscriptions (id, tenant_id, org_id) VALUES ('owned', 'tenant-a', 'org-a')`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed %.60s: %v", s, err)
		}
	}
}

func TestMigration156_BackfillsOrphansAndConstrains_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pc.DB

	seedPreUpgradeShape(t, db)

	// Precondition — the fixture must actually QUALIFY for the backfill loop,
	// otherwise this test passes vacuously exactly like the fresh-DB CI gate.
	var offenders int
	if err := db.QueryRow(
		`SELECT count(*) FROM plans WHERE org_id IS NULL OR btrim(org_id) = ''`).Scan(&offenders); err != nil {
		t.Fatalf("precondition query: %v", err)
	}
	if offenders != 2 {
		t.Fatalf("fixture precondition: expected 2 unowned plans before the migration, got %d — the backfill branch would not run", offenders)
	}

	applyMigration156File(t, db, "156_tenancy_keys_not_null.sql")

	t.Run("orphans are stamped with the sentinel, owned rows untouched", func(t *testing.T) {
		for _, tc := range []struct{ table, key, id, wantOrg, wantTenant string }{
			{"plans", "plan_id", "owned", "org-a", "tenant-a"},
			{"plans", "plan_id", "orphan-null", migration156Sentinel, migration156Sentinel},
			{"plans", "plan_id", "orphan-empty", migration156Sentinel, migration156Sentinel},
			{"workflows", "workflow_id", "owned", "org-a", "tenant-a"},
			{"workflows", "workflow_id", "orphan-null", migration156Sentinel, migration156Sentinel},
			{"execution_summaries", "request_id", "owned", "org-a", "tenant-a"},
			// Whitespace-only counts as unowned — btrim, not = ''.
			{"execution_summaries", "request_id", "orphan-empty", migration156Sentinel, migration156Sentinel},
			{"webhook_subscriptions", "id", "owned", "org-a", "tenant-a"},
			{"webhook_subscriptions", "id", "orphan-default", migration156Sentinel, migration156Sentinel},
		} {
			var org, tenant string
			q := `SELECT org_id, tenant_id FROM ` + tc.table + ` WHERE ` + tc.key + ` = $1`
			if err := db.QueryRow(q, tc.id).Scan(&org, &tenant); err != nil {
				t.Fatalf("%s/%s: %v", tc.table, tc.id, err)
			}
			if org != tc.wantOrg || tenant != tc.wantTenant {
				t.Errorf("%s/%s = (%q,%q), want (%q,%q)", tc.table, tc.id, org, tenant, tc.wantOrg, tc.wantTenant)
			}
		}
	})

	t.Run("the empty value stops being writable", func(t *testing.T) {
		// NULL is refused by NOT NULL...
		if _, err := db.Exec(`INSERT INTO plans VALUES ('new-null', NULL, NULL)`); err == nil {
			t.Error("a NULL tenancy key must be refused after 156")
		}
		// ...and the empty string by the CHECK, which is the value the
		// exploit actually used.
		if _, err := db.Exec(`INSERT INTO plans VALUES ('new-empty', '', '')`); err == nil {
			t.Error("an empty-string tenancy key must be refused after 156")
		}
		if _, err := db.Exec(`INSERT INTO plans VALUES ('new-space', '  ', '  ')`); err == nil {
			t.Error("a whitespace-only tenancy key must be refused after 156")
		}
		// The DEFAULT '' is gone, so omitting the columns no longer silently
		// produces an unowned row — it fails.
		if _, err := db.Exec(`INSERT INTO webhook_subscriptions (id) VALUES ('new-default')`); err == nil {
			t.Error("webhook_subscriptions must no longer default its tenancy columns to the empty string")
		}
		// Positive control: a properly-keyed row still inserts.
		if _, err := db.Exec(`INSERT INTO plans VALUES ('new-owned', 'org-b', 'tenant-b')`); err != nil {
			t.Errorf("a fully-keyed insert must still succeed: %v", err)
		}
	})

	t.Run("idempotent re-run", func(t *testing.T) {
		applyMigration156File(t, db, "156_tenancy_keys_not_null.sql")
	})

	t.Run("down migration relaxes what 156 constrained, and re-applying works", func(t *testing.T) {
		applyMigration156File(t, db, "156_tenancy_keys_not_null_down.sql")

		var checks int
		if err := db.QueryRow(
			`SELECT count(*) FROM pg_constraint WHERE conname LIKE '%_not_empty'`).Scan(&checks); err != nil {
			t.Fatalf("constraint count: %v", err)
		}
		if checks != 0 {
			t.Errorf("down migration left %d non-empty CHECK constraints", checks)
		}

		// webhook_subscriptions was ALREADY NOT NULL before 156 (mig 048), so
		// the rollback must not relax it — that would leave the schema in a
		// state the pre-156 code never saw.
		var nullable string
		if err := db.QueryRow(`SELECT is_nullable FROM information_schema.columns
			WHERE table_name = 'webhook_subscriptions' AND column_name = 'org_id'`).Scan(&nullable); err != nil {
			t.Fatalf("nullability query: %v", err)
		}
		if nullable != "NO" {
			t.Errorf("webhook_subscriptions.org_id is_nullable = %q, want NO — it predates 156", nullable)
		}

		// The sentinel stamps stay: reverting them would restore rows every
		// tenant could reach, and a rollback must not reopen the hole.
		var org string
		if err := db.QueryRow(`SELECT org_id FROM plans WHERE plan_id = 'orphan-null'`).Scan(&org); err != nil {
			t.Fatalf("post-rollback read: %v", err)
		}
		if org != migration156Sentinel {
			t.Errorf("rollback un-stamped an orphan row (org_id = %q) — that restores a row every tenant can reach", org)
		}

		applyMigration156File(t, db, "156_tenancy_keys_not_null.sql")
	})
}

// TestMigration156_ToleratesAbsentTables covers the community-mirror /
// partial-schema case: the loops are guarded on table AND column existence, so
// a schema missing one of the five must not RAISE — a migration that aborts is
// a boot loop, because the runner calls log.Fatalf.
func TestMigration156_ToleratesAbsentTables_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pc.DB

	// Only one of the five tables exists, and one legacy table lacks the
	// tenant_id column entirely.
	if _, err := db.Exec(`CREATE TABLE plans (plan_id VARCHAR(255) PRIMARY KEY, org_id VARCHAR(255))`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO plans VALUES ('orphan', NULL)`); err != nil {
		t.Fatalf("seed row: %v", err)
	}

	applyMigration156File(t, db, "156_tenancy_keys_not_null.sql")

	var org string
	if err := db.QueryRow(`SELECT org_id FROM plans WHERE plan_id = 'orphan'`).Scan(&org); err != nil {
		t.Fatalf("read: %v", err)
	}
	if org != migration156Sentinel {
		t.Errorf("org_id = %q, want the sentinel — the column that DOES exist must still be processed", org)
	}
}
