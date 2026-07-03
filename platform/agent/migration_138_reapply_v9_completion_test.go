// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"os"
	"testing"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration138_ReapplyV9Completion_RealPostgres proves migration 138
// against a REAL Postgres in the exact FRESH-enterprise-deploy state that
// shipped #2782: the migration runner sorts all directories by numeric
// version, so core/106 (sso_* org_id + RLS) and core/107 (connector_configs
// org_id + RLS) run BEFORE enterprise/108 and enterprise/120 create those
// tables — their IF EXISTS guards no-op, and the tables come up without
// org_id (portal create handlers 500) and without any org RLS.
//
// The test seeds the tables in that post-108/120, pre-completion shape, runs
// the real 138 file, and asserts the user-visible outcomes: the portal
// INSERT shape works, RLS is FORCEd with the canonical app.current_org_id
// policy, and a 'redact' action override (offered by the UI, canonical in
// ValidOverrideActions) now satisfies the rebuilt CHECK (#2808 E-9).
func TestMigration138_ReapplyV9Completion_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pc.DB

	// Fresh-deploy shape: tables exactly as enterprise/108 + enterprise/120
	// create them (no org_id, mig-108's tenant_id policies on sso_*, no RLS
	// at all on connector_configs), plus the core/070-shape policy_overrides
	// CHECK without 'redact', plus the tenants lookup table the backfill
	// joins against (customers is NOT seeded — it doesn't exist on community
	// deploys, and mig 138 must backfill from tenants, not customers).
	preDDL := `
		CREATE TABLE tenants (tenant_id varchar(255) PRIMARY KEY, org_id varchar(255));
		CREATE TABLE organizations (org_id varchar(255) PRIMARY KEY, status varchar(20));

		CREATE TABLE sso_configurations (
			id varchar(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
			tenant_id varchar(255) NOT NULL,
			provider varchar(50) NOT NULL,
			enabled boolean DEFAULT false,
			enforce_sso boolean DEFAULT false
		);
		CREATE TABLE sso_sessions (
			id varchar(255) PRIMARY KEY,
			tenant_id varchar(255) NOT NULL
		);
		CREATE TABLE sso_login_attempts (
			id serial PRIMARY KEY,
			tenant_id varchar(255) NOT NULL
		);
		ALTER TABLE sso_configurations ENABLE ROW LEVEL SECURITY;
		CREATE POLICY sso_configurations_tenant_isolation ON sso_configurations
			USING (tenant_id = current_setting('app.tenant_id', true));

		CREATE TABLE connector_configs (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id varchar(100) NOT NULL,
			connector_name varchar(100) NOT NULL,
			connector_type varchar(50) NOT NULL,
			display_name varchar(255),
			description text,
			enabled boolean DEFAULT true
		);

		CREATE TABLE policy_overrides (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			policy_id uuid,
			action_override varchar(20),
			org_id varchar(255),
			CONSTRAINT policy_overrides_action_override_check CHECK (
				action_override IN ('block', 'warn', 'log', 'allow', 'deny', 'require_approval', 'log_only')
			)
		);
	`
	pc.RunMigration(t, preDDL)

	// Pre-138 regression proof #1: the portal connector INSERT shape fails
	// (this is the exact "Failed to create connector" 500).
	_, err := db.Exec(`INSERT INTO connector_configs (tenant_id, org_id, connector_name, connector_type)
		VALUES ('acme-eval', 'acme-eval', 'pg-main', 'postgres')`)
	require.Error(t, err, "pre-138 connector insert with org_id must fail (column missing)")
	assert.Contains(t, err.Error(), `column "org_id"`)

	// Pre-138 regression proof #2: a redact override violates the CHECK.
	_, err = db.Exec(`INSERT INTO policy_overrides (action_override, org_id) VALUES ('redact', 'acme-eval')`)
	require.Error(t, err, "pre-138 redact override must violate the CHECK")
	assert.Contains(t, err.Error(), "policy_overrides_action_override_check")

	// Backfill fixtures: existing rows (an upgraded-deploy shape would have
	// them) so the org_id backfill + NOT NULL tighten is exercised on data.
	pc.RunMigration(t, `
		INSERT INTO tenants (tenant_id, org_id) VALUES ('acme-eval', 'acme-eval');
		INSERT INTO sso_configurations (tenant_id, provider) VALUES ('acme-eval', 'okta');
		INSERT INTO connector_configs (tenant_id, connector_name, connector_type) VALUES ('acme-eval', 'pg-legacy', 'postgres');
	`)

	// Apply migration 138 (the real file, not a hand-rolled copy).
	upSQL, err := os.ReadFile("../../migrations/core/138_reapply_v9_completion_enterprise_created_tables.sql")
	require.NoError(t, err)
	pc.RunMigration(t, string(upSQL))

	// org_id present + NOT NULL + backfilled from tenant_id on all 4 tables.
	for _, tbl := range []string{"sso_configurations", "sso_sessions", "sso_login_attempts", "connector_configs"} {
		var nullable string
		require.NoError(t, db.QueryRow(
			`SELECT is_nullable FROM information_schema.columns
			 WHERE table_name = $1 AND column_name = 'org_id'`, tbl).Scan(&nullable),
			"%s must have org_id after 138", tbl)
		assert.Equal(t, "NO", nullable, "%s.org_id must be NOT NULL", tbl)
	}
	var backfilled string
	require.NoError(t, db.QueryRow(
		`SELECT org_id FROM connector_configs WHERE connector_name = 'pg-legacy'`).Scan(&backfilled))
	assert.Equal(t, "acme-eval", backfilled, "legacy connector row must be backfilled from tenants")

	// FORCE RLS + canonical app.current_org_id policy on every table; the
	// legacy app.tenant_id policy replaced on sso_configurations.
	for _, tbl := range []string{"sso_configurations", "sso_sessions", "sso_login_attempts", "connector_configs"} {
		var forced bool
		require.NoError(t, db.QueryRow(
			`SELECT relforcerowsecurity FROM pg_class WHERE relname = $1`, tbl).Scan(&forced))
		assert.True(t, forced, "%s must be FORCE RLS after 138", tbl)

		var nPolicies int
		require.NoError(t, db.QueryRow(
			`SELECT count(*) FROM pg_policies WHERE tablename = $1 AND qual LIKE '%app.current_org_id%'`, tbl).Scan(&nPolicies))
		assert.Equal(t, 1, nPolicies, "%s must carry the canonical org_id policy", tbl)
	}
	var legacyPolicies int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM pg_policies WHERE tablename = 'sso_configurations' AND qual LIKE '%app.tenant_id%'`).Scan(&legacyPolicies))
	assert.Equal(t, 0, legacyPolicies, "mig-108 tenant_id policy must be replaced")

	// THE user-visible regressions, post-138:
	// #1 — the portal connector INSERT shape succeeds.
	_, err = db.Exec(`INSERT INTO connector_configs (tenant_id, org_id, connector_name, connector_type)
		VALUES ('acme-eval', 'acme-eval', 'pg-main', 'postgres')`)
	require.NoError(t, err, "post-138 connector insert must succeed")

	// #2 — a redact override satisfies the rebuilt CHECK; garbage still rejected.
	_, err = db.Exec(`INSERT INTO policy_overrides (action_override, org_id) VALUES ('redact', 'acme-eval')`)
	require.NoError(t, err, "post-138 redact override must satisfy the CHECK")
	_, err = db.Exec(`INSERT INTO policy_overrides (action_override, org_id) VALUES ('nonsense', 'acme-eval')`)
	require.Error(t, err, "post-138 CHECK must still reject unknown actions")

	// RLS actually isolates: under a non-superuser role with the org GUC set
	// to a different org, the acme-eval rows are invisible.
	assertOrgIsolation(t, db)

	// Idempotency: a second run of the full file is clean (the exact
	// situation on an upgraded deploy where 106/107 already completed).
	pc.RunMigration(t, string(upSQL))

	// Down migration: restores the narrower CHECK only when no redact rows
	// remain; keeps it (with a NOTICE) while they exist.
	downSQL, err := os.ReadFile("../../migrations/core/138_reapply_v9_completion_enterprise_created_tables_down.sql")
	require.NoError(t, err)
	pc.RunMigration(t, string(downSQL))
	_, err = db.Exec(`INSERT INTO policy_overrides (action_override, org_id) VALUES ('redact', 'other-org')`)
	require.NoError(t, err, "down migration must keep the widened CHECK while redact rows exist")

	pc.RunMigration(t, `DELETE FROM policy_overrides WHERE action_override = 'redact';`)
	pc.RunMigration(t, string(downSQL))
	_, err = db.Exec(`INSERT INTO policy_overrides (action_override, org_id) VALUES ('redact', 'other-org')`)
	require.Error(t, err, "after down with no redact rows, the pre-138 CHECK must reject redact again")
}

// TestMigration138_CommunityTopology_RealPostgres proves 138 applies cleanly
// on the REAL pure-community shape: no `customers` (enterprise/100), no sso_*
// tables (enterprise/108), and — the master-R3 round-2 correction — NO
// `connector_configs` either: core/021 is customers-gated ("OSS mode.
// Skipping."), so on community the table never exists and 138's Steps 7/8
// must skip via their IF EXISTS guards. The only 138 effect on community is
// the policy_overrides redact-CHECK widening (policy_overrides IS core,
// mig 030). An earlier draft of this test seeded connector_configs — a
// hybrid shape that does not occur on any real deploy — so it never
// exercised the actual community boot path.
func TestMigration138_CommunityTopology_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pc.DB

	// Pure community shape: tenants + policy_overrides only. NO customers,
	// NO sso_configurations, NO connector_configs.
	pc.RunMigration(t, `
		CREATE TABLE tenants (tenant_id varchar(255) PRIMARY KEY, org_id varchar(255));
		CREATE TABLE policy_overrides (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			action_override varchar(20),
			org_id varchar(255),
			CONSTRAINT policy_overrides_action_override_check CHECK (
				action_override IN ('block', 'warn', 'log', 'allow', 'deny', 'require_approval', 'log_only')
			)
		);
		INSERT INTO tenants (tenant_id, org_id) VALUES ('acme', 'acme');
	`)

	upSQL, err := os.ReadFile("../../migrations/core/138_reapply_v9_completion_enterprise_created_tables.sql")
	require.NoError(t, err)
	// The whole point: with the enterprise-created tables entirely absent,
	// every guarded step must skip and the migration must COMMIT cleanly —
	// this is the community agent-boot path.
	pc.RunMigration(t, string(upSQL))

	// Nothing was created that shouldn't be...
	var exists bool
	require.NoError(t, db.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connector_configs')`).Scan(&exists))
	assert.False(t, exists, "138 must not CREATE connector_configs on community")

	// ...and the one community-relevant effect landed: redact CHECK widened.
	_, err = db.Exec(`INSERT INTO policy_overrides (action_override, org_id) VALUES ('redact', 'acme')`)
	require.NoError(t, err, "community deploy must accept redact after 138")

	// Idempotent re-run stays clean on this shape too.
	pc.RunMigration(t, string(upSQL))
}

// assertOrgIsolation proves the canonical policy actually scopes reads by
// app.current_org_id. The testcontainer connection is a SUPERUSER (which
// bypasses RLS entirely, FORCE or not), so the probe runs under a dedicated
// non-superuser role — the same posture as the axonflow_app_role runtime.
func assertOrgIsolation(t *testing.T, db *sql.DB) {
	t.Helper()

	_, err := db.Exec(`
		DO $$ BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rls_probe') THEN
				CREATE ROLE rls_probe NOLOGIN;
			END IF;
		END $$;
		GRANT SELECT ON connector_configs TO rls_probe;`)
	require.NoError(t, err)

	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`SET LOCAL ROLE rls_probe`)
	require.NoError(t, err)

	_, err = tx.Exec(`SET LOCAL app.current_org_id = 'some-other-org'`)
	require.NoError(t, err)
	var visible int
	require.NoError(t, tx.QueryRow(`SELECT count(*) FROM connector_configs`).Scan(&visible))
	assert.Equal(t, 0, visible, "foreign org must see zero connector rows under FORCE RLS")

	_, err = tx.Exec(`SET LOCAL app.current_org_id = 'acme-eval'`)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(`SELECT count(*) FROM connector_configs`).Scan(&visible))
	assert.Equal(t, 2, visible, "own org must see its connector rows")
}

var _ = sql.ErrNoRows // keep database/sql imported alongside testutil helpers
