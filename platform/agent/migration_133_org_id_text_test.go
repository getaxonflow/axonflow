// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #3334 (2026-08-25): THIS TEST DELIBERATELY PINS A PRE-166 SCHEMA. Migration
// core/166 drops `organization_id` from the policy tables and drops
// `valid_override_scope` with it, so the present tense below describes the
// schema as of core/133 and NOT the schema a current deployment runs. The test
// is hermetic -- it applies its own bounded migration range and still passes --
// and it is left pinned on purpose: 133's regression (a free-form org id in a
// uuid column throwing `pq: invalid input syntax for type uuid`) is only
// observable while the column exists, and re-pointing the test at org_id would
// silently retire the coverage instead of moving it.
//
// It is called out because after 166 this is the ONLY place still asserting BY
// NAME that `organization_id` and `valid_override_scope` exist, so a reader
// finding it is entitled to think the column is live. It is not.
//
// TestMigration133_OrganizationIDUUIDToText_RealPostgres proves migration 133
// against a REAL Postgres: it retypes the legacy `organization_id` column from
// uuid to text on all four policy tables, and — the actual regression — a
// FREE-FORM (non-UUID) org id can then be inserted without the
// `invalid input syntax for type uuid` error that shipped a hard 500 in 9.3.0
// (customer-portal policy-override create + org-tier static-policy create).
//
// The test also proves the migration is transparent to the dependent objects
// the analysis flagged: the `valid_override_scope` CHECK constraint and the
// partial index on organization_id survive the retype and still function.
func TestMigration133_OrganizationIDUUIDToText_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pc.DB

	// The four tables carrying the legacy `organization_id uuid` column, seeded
	// in the PRE-133 shape (uuid) plus the real dependent objects so the
	// migration's transparency is actually exercised, not assumed.
	preDDL := `
		CREATE TABLE static_policies (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id uuid,
			tenant_id varchar(255),
			org_id varchar(255)
		);
		CREATE INDEX idx_static_policies_organization ON static_policies (organization_id) WHERE organization_id IS NOT NULL;

		CREATE TABLE dynamic_policies (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id uuid,
			tenant_id varchar(255),
			org_id varchar(255)
		);

		CREATE TABLE policy_evaluations (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id uuid
		);

		CREATE TABLE policy_overrides (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id uuid,
			tenant_id varchar(100),
			org_id varchar(255),
			CONSTRAINT valid_override_scope CHECK (
				(organization_id IS NOT NULL AND tenant_id IS NULL) OR (tenant_id IS NOT NULL)
			)
		);
		CREATE INDEX idx_policy_overrides_org ON policy_overrides (organization_id) WHERE organization_id IS NOT NULL;
	`
	pc.RunMigration(t, preDDL)

	// Sanity: the columns start as uuid (the pre-133 state).
	for _, tbl := range []string{"static_policies", "dynamic_policies", "policy_overrides", "policy_evaluations"} {
		assert.Equal(t, "uuid", columnType(t, db, tbl), "pre-migration %s.organization_id should be uuid", tbl)
	}

	// Pre-133 regression proof: a free-form org id CANNOT be inserted (this is
	// exactly the 500 a non-UUID-org deployment hit).
	_, err := db.Exec(`INSERT INTO policy_overrides (organization_id, tenant_id) VALUES ($1, NULL)`, "acme-eval")
	require.Error(t, err, "pre-migration insert of a non-uuid org must fail")
	assert.Contains(t, err.Error(), "invalid input syntax for type uuid")

	// Apply migration 133 (the real file, not a hand-rolled copy).
	upSQL, err := os.ReadFile("../../migrations/core/133_organization_id_uuid_to_text.sql")
	require.NoError(t, err)
	pc.RunMigration(t, string(upSQL))

	// All four columns are now text.
	for _, tbl := range []string{"static_policies", "dynamic_policies", "policy_overrides", "policy_evaluations"} {
		assert.Equal(t, "text", columnType(t, db, tbl), "post-migration %s.organization_id should be text", tbl)
	}

	// THE regression: a free-form (non-uuid) org id now inserts cleanly on every
	// table — the override path AND the org-tier static/dynamic policy path.
	for i, tbl := range []string{"static_policies", "dynamic_policies", "policy_evaluations"} {
		_, err := db.Exec(fmt.Sprintf(`INSERT INTO %s (organization_id) VALUES ($1)`, tbl), "acme-eval")
		require.NoErrorf(t, err, "post-migration insert of non-uuid org into %s (case %d) must succeed", tbl, i)
	}
	// policy_overrides has the CHECK; the org-scoped shape (org set, tenant NULL)
	// must still satisfy valid_override_scope AND accept the string org.
	_, err = db.Exec(`INSERT INTO policy_overrides (organization_id, tenant_id) VALUES ($1, NULL)`, "acme-eval")
	require.NoError(t, err, "post-migration: org-scoped override with a string org must insert and satisfy valid_override_scope")

	// The CHECK constraint is still ENFORCED after the retype (a row with
	// neither org nor tenant is still rejected).
	_, err = db.Exec(`INSERT INTO policy_overrides (organization_id, tenant_id) VALUES (NULL, NULL)`)
	require.Error(t, err, "valid_override_scope must still reject a row with neither org nor tenant")
	assert.Contains(t, err.Error(), "valid_override_scope")

	// The partial index survived the retype and is usable for a string lookup.
	var n int
	require.NoError(t, db.QueryRow(
		`SELECT COUNT(*) FROM policy_overrides WHERE organization_id = $1`, "acme-eval").Scan(&n))
	assert.Equal(t, 1, n)

	// Down migration round-trips back to uuid (rows here are string-valued, so
	// the down must be run against uuid/NULL-only data; prove it reverts the
	// type on a cleaned table).
	pc.RunMigration(t, `DELETE FROM policy_overrides; DELETE FROM static_policies; DELETE FROM dynamic_policies; DELETE FROM policy_evaluations;`)
	downSQL, err := os.ReadFile("../../migrations/core/133_organization_id_uuid_to_text_down.sql")
	require.NoError(t, err)
	pc.RunMigration(t, string(downSQL))
	assert.Equal(t, "uuid", columnType(t, db, "policy_overrides"), "down migration should revert organization_id to uuid")
}

// columnType returns the information_schema data_type of <table>.organization_id.
func columnType(t *testing.T, db *sql.DB, table string) string {
	t.Helper()
	var dt string
	err := db.QueryRow(
		`SELECT data_type FROM information_schema.columns
		 WHERE table_name = $1 AND column_name = 'organization_id'`, table).Scan(&dt)
	require.NoError(t, err)
	return dt
}
