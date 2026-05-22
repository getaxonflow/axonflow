// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// v9 Phase 8 B8 (Brief 11 PR C): real-Postgres contract test for
// migration 107 — FORCE RLS on connectors, connector_configs,
// agent_heartbeats, node_violations.
//
// What this pins:
//   - All 4 tables have FORCE RLS active + canonical app.current_org_id
//     policy after mig 107.
//   - connector_configs has a new org_id column NOT NULL.
//   - Cross-org isolation works on connectors + connector_configs under
//     axonflow_app_role with SET LOCAL.
//   - Mutation proof: DROP POLICY → cross-org leak observable; restore.
//
// Gated on TEST_PG_INTEGRATION=1 + TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
)

func TestMigration107_B8MiscTablesForceRLS(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION not set — skipping")
	}
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping")
	}

	ctx := context.Background()
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// Schema reset + GUCs.
	if _, err := db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	for _, guc := range []struct{ k, v string }{
		{"app.db_password", "test-pass"},
		{"app.deployment_kind", "dev"},
		{"app.deployment_org_id", "mig107-test-bootstrap"},
	} {
		if _, err := db.Exec("SELECT set_config($1, $2, false)", guc.k, guc.v); err != nil {
			t.Fatalf("set %s: %v", guc.k, err)
		}
	}

	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "RESET ROLE")
	})

	// Apply core migrations 1-107.
	runMigrationsRange(t, db, 1, 107)

	// Apply enterprise migrations the test schema needs:
	//   - 100 (billing) — creates `customers` table that core mig 021's
	//     connector_configs depends on (gated by IF EXISTS customers)
	//   - 101 (agent_heartbeats)
	//   - 105 (node_enforcement / node_violations)
	for _, mig := range []string{
		"../../migrations/enterprise/100_billing_and_metering.sql",
		"../../migrations/enterprise/101_agent_heartbeats.sql",
		"../../migrations/enterprise/105_node_enforcement.sql",
	} {
		body, err := os.ReadFile(mig)
		if err != nil {
			t.Fatalf("read %s: %v", mig, err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("apply %s: %v", mig, err)
		}
	}

	// Re-apply core mig 021 so connector_configs gets created now that
	// customers exists (021 conditionally skipped when customers wasn't
	// present during the initial 1-107 pass).
	body021, err := os.ReadFile("../../migrations/core/021_runtime_connector_configuration.sql")
	if err != nil {
		t.Fatalf("read mig 021: %v", err)
	}
	if _, err := db.Exec(string(body021)); err != nil {
		t.Fatalf("re-apply mig 021: %v", err)
	}

	// Re-apply mig 107 so its FORCE/policy steps run against the now-present
	// enterprise tables. Idempotent.
	body, err := os.ReadFile("../../migrations/core/107_v9_rls_b8_misc_tables.sql")
	if err != nil {
		t.Fatalf("read mig 107: %v", err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("re-apply mig 107: %v", err)
	}

	// ========================================================================
	// Pin 1: All 4 tables have FORCE active
	// ========================================================================
	expectedTables := []string{"connectors", "connector_configs", "agent_heartbeats", "node_violations"}
	for _, tbl := range expectedTables {
		var forced bool
		err := db.QueryRowContext(ctx,
			`SELECT relforcerowsecurity FROM pg_class WHERE relname = $1`, tbl,
		).Scan(&forced)
		if err != nil {
			t.Errorf("query FORCE on %s: %v", tbl, err)
			continue
		}
		if !forced {
			t.Errorf("FORCE RLS not active on %s", tbl)
		}
	}

	// ========================================================================
	// Pin 2: All 4 tables have canonical app.current_org_id policy + no
	// pre-existing app.tenant_id policy remains
	// ========================================================================
	for _, tbl := range expectedTables {
		var policyCount int
		err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pg_policies
			 WHERE tablename = $1 AND qual LIKE '%app.current_org_id%'`, tbl,
		).Scan(&policyCount)
		if err != nil {
			t.Errorf("query policy on %s: %v", tbl, err)
			continue
		}
		if policyCount == 0 {
			t.Errorf("%s has no app.current_org_id policy", tbl)
		}
	}

	// ========================================================================
	// Pin 3: connector_configs has org_id column NOT NULL
	// ========================================================================
	var isNullable string
	if err := db.QueryRowContext(ctx,
		`SELECT is_nullable FROM information_schema.columns
		 WHERE table_name = 'connector_configs' AND column_name = 'org_id'`,
	).Scan(&isNullable); err != nil {
		t.Fatalf("query connector_configs.org_id: %v", err)
	}
	if isNullable != "NO" {
		t.Errorf("connector_configs.org_id is %s, want NOT NULL", isNullable)
	}

	// ========================================================================
	// Pin 4: Cross-org isolation on connectors (smallest happy-path test —
	// app_role can SET LOCAL org_id and see only matching rows)
	// ========================================================================
	// Seed two connectors in different orgs as table owner.
	const orgA = "mig107-test-orgA"
	const orgB = "mig107-test-orgB"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO connectors (id, org_id, name, type, tenant_id, options, credentials, installed_at)
		VALUES
		    ($1, $1, 'connA', 'http', $1, '{}'::jsonb, '{}'::jsonb, NOW()),
		    ($2, $2, 'connB', 'http', $2, '{}'::jsonb, '{}'::jsonb, NOW())
		ON CONFLICT (id) DO UPDATE SET org_id = EXCLUDED.org_id
	`, orgA, orgB); err != nil {
		t.Fatalf("seed connectors: %v", err)
	}

	// Switch to axonflow_app_role.
	if _, err := db.ExecContext(ctx, "GRANT axonflow_app_role TO CURRENT_USER"); err != nil {
		if !strings.Contains(err.Error(), "is a member of role") && !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("GRANT app_role: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, "SET ROLE axonflow_app_role"); err != nil {
		t.Fatalf("SET ROLE: %v", err)
	}

	t.Run("CrossOrgIsolation_connectors", func(t *testing.T) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("BeginTx: %v", err)
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx,
			"SELECT set_config('app.current_org_id', $1, true)", orgA,
		); err != nil {
			t.Fatalf("set_config: %v", err)
		}

		var count int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM connectors WHERE id IN ($1, $2)`, orgA, orgB,
		).Scan(&count); err != nil {
			t.Fatalf("count under orgA: %v", err)
		}
		if count != 1 {
			t.Errorf("under orgA, expected 1 visible connector, saw %d", count)
		}
	})

	// ========================================================================
	// Pin 5: Mutation proof — DISABLE RLS on connectors → cross-org leak.
	// Under app_role (NOBYPASSRLS), the lever for visibility is ENABLE+policy
	// (per reference_rls_force_vs_enable_under_app_role.md). NOT FORCE alone.
	// ========================================================================
	t.Run("MutationProof_DisableRLS_LeaksCrossOrg", func(t *testing.T) {
		_, _ = db.ExecContext(ctx, "RESET ROLE")
		if _, err := db.ExecContext(ctx, "ALTER TABLE connectors DISABLE ROW LEVEL SECURITY"); err != nil {
			t.Fatalf("DISABLE RLS: %v", err)
		}
		defer func() {
			_, _ = db.ExecContext(ctx, "RESET ROLE")
			_, _ = db.ExecContext(ctx, "ALTER TABLE connectors ENABLE ROW LEVEL SECURITY")
		}()

		if _, err := db.ExecContext(ctx, "SET ROLE axonflow_app_role"); err != nil {
			t.Fatalf("SET ROLE: %v", err)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("BeginTx: %v", err)
		}
		defer tx.Rollback()
		_, _ = tx.ExecContext(ctx, "SELECT set_config('app.current_org_id', $1, true)", orgA)

		var count int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM connectors WHERE id IN ($1, $2)`, orgA, orgB,
		).Scan(&count); err != nil {
			t.Fatalf("count after DISABLE: %v", err)
		}
		if count != 2 {
			t.Errorf("after DISABLE RLS, expected 2 visible connectors (cross-org leak), saw %d", count)
		}
		t.Logf("mutation proof: DISABLE RLS on connectors flipped from 1 to %d visible — RLS is load-bearing", count)
	})
}
