// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// v9 Phase 8 B6 — cross-org RLS isolation contract test for the in-VPC
// enterprise auth tables (Epic #2230 Brief B):
//
//   - api_keys
//   - customers
//
// Migration 108 ships the SECURITY DEFINER auth_lookup_api_key + auth_touch_api_key
// helpers AND ENABLEs + FORCEs RLS on these tables. Without the SECURITY DEFINER
// helpers, validateClientCredentialsDB → validateViaAPIKeys (db_auth.go:101) would
// return zero rows for every auth attempt under axonflow_app_role once FORCE RLS
// lands (the JOIN runs BEFORE app.current_org_id can be set — same chicken-and-
// egg shape as the SaaS path which PR #2341 closed via auth_lookup_org).
//
// Test scenarios (under one top-level test):
//
//   Visibility (4 scenarios × 2 tables = 8 subtests):
//     A — axonflow_app_role + SET LOCAL app.current_org_id = orgA → sees A's row
//     B — axonflow_app_role + SET LOCAL app.current_org_id = orgB → sees B's row
//     C — axonflow_app_role with NO SET LOCAL          → sees zero rows
//     D — axonflow_platform_admin (BYPASSRLS)          → sees BOTH rows
//
//   WITH CHECK enforcement (2 subtests, one per table):
//     under orgA's context, INSERT a row with org_id=orgB → RLS violation
//
//   SECURITY DEFINER load-bearing mutation proof (1 subtest):
//     re-CREATE auth_lookup_api_key WITHOUT the SECURITY DEFINER keyword
//     (i.e., as SECURITY INVOKER, the default), call it as axonflow_app_role
//     with NO app.current_org_id set, confirm it returns 0 rows. Restore the
//     SECURITY DEFINER version in defer. This proves the SECURITY DEFINER
//     keyword is the load-bearing piece — without it, the auth-bootstrap
//     lookup fails the moment FORCE RLS lands on api_keys/customers.
//
//   RLS-package load-bearing mutation proof (2 subtests, one per table):
//     temporarily DISABLE RLS on the table, re-run scenario A, assert count
//     flips 1 → 2 (cross-org leak observable). Restore ENABLE + FORCE in
//     defer. Mirrors rls_phase6_isolation_test.go's mutation pattern.
//
// Gating: TEST_PG_INTEGRATION=1. Without it, the test skips.
//
// SET LOCAL ROLE gotcha (reference_force_rls_test_superuser_gotcha.md):
// every read/write subtest below runs through runAsAppRoleWithOrg /
// runAsAppRoleNoOrg / runAsPlatformAdmin which SET LOCAL ROLE inside the
// transaction. Without this, the docker postgres container's default
// `postgres` user is a superuser and bypasses RLS, making every assertion
// trivially pass.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"testing"
)

const (
	b6OrgA = "rls-b6-test-org-A"
	b6OrgB = "rls-b6-test-org-B"

	// Distinct content markers per cohort (defeats "matched by accident"
	// tautology class — assertion checks both org_id AND content).
	b6LabelA = "b6-customer-A-uniqmarker-44a91"
	b6LabelB = "b6-customer-B-uniqmarker-7c2e8"

	// Synthetic license_key_hash values to seed api_keys per org.
	b6HashA = "b6-test-license-hash-A-7311aa"
	b6HashB = "b6-test-license-hash-B-9924bb"

	// Synthetic API key UUIDs. api_keys.api_key_id is UUID in the production
	// 006_option3 schema; the test schema mirrors this. These literals are
	// passed through auth_touch_api_key($1) in the touch-path subtest to
	// exercise the WHERE-clause cast against the real Postgres operator
	// resolver (the R3 regression guard against HIGH-1).
	b6ApiKeyIDA = "11111111-1111-1111-1111-111111111111"
	b6ApiKeyIDB = "22222222-2222-2222-2222-222222222222"
)

// b6TestTable describes one table under test with its content column.
type b6TestTable struct {
	name       string
	contentCol string
}

var b6Tables = []b6TestTable{
	{name: "api_keys", contentCol: "key_name"},
	{name: "customers", contentCol: "organization_name"},
}

// rlsB6TestSetup brings up an isolated postgres testcontainer, runs core
// migrations 1-107, manually applies the in-VPC enterprise schema (mimicking
// `migrations/enterprise/100_billing_and_metering.sql` + the operator-applied
// `platform/database/migrations/006_option3_auth_system.sql` api_keys
// extension), runs migration 108 to install the SECURITY DEFINER helpers +
// FORCE RLS, and seeds two cohorts.
//
// Returns the DB handle and a cleanup func.
func rlsB6TestSetup(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("set TEST_PG_INTEGRATION=1 to run real-PG integration tests (requires docker)")
	}

	pgURL, containerCleanup := startPostgresContainer(t)

	db, err := sql.Open("postgres", pgURL)
	if err != nil {
		containerCleanup()
		t.Fatalf("sql.Open: %v", err)
	}
	// Pin pool to 1 so the GRANTs + SET LOCAL we issue land on the same backend.
	db.SetMaxOpenConns(1)

	// app.db_password satisfies mig 028's dblink template. Same shape as
	// rls_phase6_isolation_test.go's setup.
	if _, err := db.Exec(`SELECT set_config('app.db_password', 'test-pass', false)`); err != nil {
		_ = db.Close()
		containerCleanup()
		t.Fatalf("set app.db_password: %v", err)
	}
	// app.deployment_org_id satisfies mig 094's precondition.
	if _, err := db.Exec(`SELECT set_config('app.deployment_org_id', 'local-dev-org', false)`); err != nil {
		_ = db.Close()
		containerCleanup()
		t.Fatalf("set app.deployment_org_id: %v", err)
	}

	// Run core migrations 1-107 (everything except our new 108).
	runMigrationsRange(t, db, 1, 107)

	// Apply the in-VPC enterprise schema that migration 108 expects. In a real
	// deployed environment, this comes from migrations/enterprise/100 +
	// platform/database/migrations/006_option3_auth_system.sql (operator-
	// applied via apply-migration-remote.sh). The community-mode core/
	// migration path doesn't carry these; we replicate them inline so the
	// FORCE branch of migration 108 has the schema it gates on.
	applyB6InVPCEnterpriseSchema(t, db)

	// Now run migration 108. Its IF EXISTS guards will detect the schema we
	// just applied and ship the FORCE RLS branch.
	runMigrationsRange(t, db, 108, 108)

	// Grant role memberships so SET LOCAL ROLE works inside test transactions.
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "GRANT axonflow_app_role TO CURRENT_USER"); err != nil {
		_ = db.Close()
		containerCleanup()
		t.Fatalf("GRANT axonflow_app_role: %v", err)
	}
	if _, err := db.ExecContext(ctx, "GRANT axonflow_platform_admin TO CURRENT_USER"); err != nil {
		_ = db.Close()
		containerCleanup()
		t.Fatalf("GRANT axonflow_platform_admin: %v", err)
	}

	seedB6Rows(t, db)

	cleanup := func() {
		_ = db.Close()
		containerCleanup()
	}
	return db, cleanup
}

// applyB6InVPCEnterpriseSchema applies the in-VPC enterprise schema that
// migration 108's FORCE RLS branch gates on. Source-of-truth:
//
//   - `customers` table: migrations/enterprise/100_billing_and_metering.sql
//   - `pricing_tiers` table: migrations/enterprise/100_billing_and_metering.sql
//   - `api_keys` extension (api_key_id, customer_id, license_key,
//     license_key_hash, etc.): platform/database/migrations/006_option3_auth_system.sql
//
// We replicate only the column-level minimum that migration 108's body +
// validateViaAPIKeys SELECT touch. Anything beyond that (FK constraints, full
// CHECK constraints, indexes) is intentionally elided — the test exercises
// RLS contract, not enterprise/100's full surface area.
//
// The augmented api_keys table after this function returns carries BOTH the
// migration-002 columns (id, org_id, key_hash, key_prefix, name, scopes, ...)
// AND the 006_option3 columns (api_key_id, customer_id, license_key,
// license_key_hash, key_name, key_type, ...) — exactly mirroring how a
// deployed in-VPC enterprise environment ends up. Mig 108's guard predicate
// checks for `license_key_hash` presence, so this drift between the two
// schemas is what triggers the FORCE branch.
func applyB6InVPCEnterpriseSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		// pricing_tiers — deployment-scope; cross-org-readable via SECURITY
		// DEFINER. INTENTIONALLY UNFORCED per mig 108 header.
		`CREATE TABLE IF NOT EXISTS pricing_tiers (
			tier                VARCHAR(20)  NOT NULL,
			deployment_mode     VARCHAR(20)  NOT NULL,
			requests_per_minute INTEGER      NOT NULL,
			PRIMARY KEY (tier, deployment_mode)
		)`,
		`INSERT INTO pricing_tiers (tier, deployment_mode, requests_per_minute)
		 VALUES ('Enterprise', 'in-vpc', 30000)
		 ON CONFLICT (tier, deployment_mode) DO NOTHING`,
		`INSERT INTO pricing_tiers (tier, deployment_mode, requests_per_minute)
		 VALUES ('Enterprise', 'saas', 30000)
		 ON CONFLICT (tier, deployment_mode) DO NOTHING`,

		// customers — mig 108 gates on customers.org_id presence.
		`CREATE TABLE IF NOT EXISTS customers (
			customer_id        VARCHAR(255) PRIMARY KEY,
			organization_name  VARCHAR(255) NOT NULL,
			organization_id    VARCHAR(100) NOT NULL UNIQUE,
			org_id             VARCHAR(255),
			deployment_mode    VARCHAR(20)  NOT NULL,
			tier               VARCHAR(20)  NOT NULL,
			tenant_id          VARCHAR(100) NOT NULL UNIQUE,
			status             VARCHAR(20)  NOT NULL DEFAULT 'active',
			enabled            BOOLEAN      NOT NULL DEFAULT true,
			created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
			updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
		)`,

		// api_keys extension — add the 006_option3 columns alongside the
		// existing mig 002 schema. mig 108 gates on license_key_hash presence.
		//
		// api_key_id is UUID in production (006_option3 line 90:
		// `api_key_id UUID PRIMARY KEY DEFAULT gen_random_uuid()`). The
		// test schema MUST mirror this so the auth_touch_api_key WHERE
		// cast (`api_key_id::TEXT = p_api_key_id::TEXT`) gets exercised
		// against the same operator-type combination production sees.
		// Previously this was VARCHAR(255), which masked the UUID-vs-
		// VARCHAR mismatch bug surfaced by R3 round 1 (HIGH-1).
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS api_key_id        UUID DEFAULT gen_random_uuid()`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS customer_id       VARCHAR(255)`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS license_key       VARCHAR(200)`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS license_key_hash  VARCHAR(64)`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_name          VARCHAR(100)`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_type          VARCHAR(20) DEFAULT 'production'`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS grace_period_days INTEGER     DEFAULT 7`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS permissions       JSONB       DEFAULT '["query","llm"]'`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS custom_rate_limit INTEGER`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS enabled           BOOLEAN     DEFAULT true`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS revoked_at        TIMESTAMPTZ`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS total_requests    BIGINT      DEFAULT 0`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
		// Mig 002 already added api_keys.expires_at, last_used_at, org_id +
		// the legacy mig 002 NOT NULL columns (key_hash, key_prefix, name).
		// Provide defaults for those so the seed INSERTs don't have to
		// populate them.
		`ALTER TABLE api_keys ALTER COLUMN key_hash   DROP NOT NULL`,
		`ALTER TABLE api_keys ALTER COLUMN key_prefix DROP NOT NULL`,
		`ALTER TABLE api_keys ALTER COLUMN name       DROP NOT NULL`,
		`ALTER TABLE api_keys ALTER COLUMN org_id     DROP NOT NULL`,
		// 006_option3 schema declares expires_at/last_used_at/revoked_at as
		// TIMESTAMPTZ. Mig 002 declared them as plain TIMESTAMP. The
		// auth_lookup_api_key RETURN TABLE matches the 006_option3 types
		// (TIMESTAMPTZ); without this realignment, the function's RETURN
		// QUERY raises "structure of query does not match function result
		// type" at INVOCATION. The real deployed in-VPC schema (post-
		// operator-applied 006_option3) carries TIMESTAMPTZ, so the test
		// realignment here mirrors deployed reality, not test artifice.
		`ALTER TABLE api_keys ALTER COLUMN expires_at   TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC'`,
		`ALTER TABLE api_keys ALTER COLUMN last_used_at TYPE TIMESTAMPTZ USING last_used_at AT TIME ZONE 'UTC'`,
		`ALTER TABLE api_keys ALTER COLUMN revoked_at   TYPE TIMESTAMPTZ USING revoked_at AT TIME ZONE 'UTC'`,
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			t.Fatalf("apply B6 in-VPC enterprise schema: %v\n(stmt: %s)", err, s)
		}
	}
}

// seedB6Rows inserts one row per orgA / orgB into customers + api_keys.
// Inserts run as the table owner (superuser) which bypasses RLS at INSERT
// time, but FORCE RLS is already on at this point so we explicitly DISABLE
// momentarily, seed, then re-enable. Why: under FORCE RLS, even the owner
// gets WITH CHECK enforcement, and we have no GUC set during seed.
//
// FK ordering: organizations → customers → api_keys (customers FKs to
// pricing_tiers but not to organizations in this schema; api_keys has no
// FK in this minimal test schema).
func seedB6Rows(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()

	// Temporarily DISABLE RLS so the seed INSERTs aren't blocked by WITH CHECK
	// (we haven't set a GUC during seed, and we need to insert BOTH org
	// cohorts up front).
	for _, tbl := range b6Tables {
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s DISABLE ROW LEVEL SECURITY", tbl.name)); err != nil {
			t.Fatalf("disable RLS for seed on %s: %v", tbl.name, err)
		}
	}
	// Re-enable + FORCE on defer'd cleanup at function return.
	defer func() {
		for _, tbl := range b6Tables {
			if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY", tbl.name)); err != nil {
				t.Errorf("restore ENABLE on %s post-seed: %v", tbl.name, err)
			}
			if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s FORCE ROW LEVEL SECURITY", tbl.name)); err != nil {
				t.Errorf("restore FORCE on %s post-seed: %v", tbl.name, err)
			}
		}
	}()

	// Pre-clean any leftovers (paranoid; testcontainer is fresh).
	_, _ = db.ExecContext(ctx, "DELETE FROM api_keys  WHERE org_id IN ($1, $2)", b6OrgA, b6OrgB)
	_, _ = db.ExecContext(ctx, "DELETE FROM customers WHERE org_id IN ($1, $2)", b6OrgA, b6OrgB)
	_, _ = db.ExecContext(ctx, "DELETE FROM organizations WHERE org_id IN ($1, $2)", b6OrgA, b6OrgB)

	// organizations — must come first because api_keys.org_id FKs to it
	// (added by mig 002 line 232's ALTER TABLE ADD CONSTRAINT).
	for _, orgID := range []string{b6OrgA, b6OrgB} {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO organizations (org_id, name, license_key, tier, created_at)
			VALUES ($1, $1, $2, 'Enterprise', NOW())
		`, orgID, "b6-license-"+orgID); err != nil {
			t.Fatalf("seed organizations(%s): %v", orgID, err)
		}
	}

	cohorts := []struct {
		orgID    string
		label    string
		hash     string
		apiKeyID string // UUID literal — see b6ApiKeyID{A,B} comment
	}{
		{b6OrgA, b6LabelA, b6HashA, b6ApiKeyIDA},
		{b6OrgB, b6LabelB, b6HashB, b6ApiKeyIDB},
	}

	for _, c := range cohorts {
		// customers — populate both organization_id (the natural surrogate)
		// and org_id (the RLS isolation key, equal here per mig 108's
		// canonical backfill rule).
		if _, err := db.ExecContext(ctx, `
			INSERT INTO customers
			    (customer_id, organization_name, organization_id, org_id,
			     deployment_mode, tier, tenant_id, status, enabled)
			VALUES ($1, $2, $3, $4, 'in-vpc', 'Enterprise', $5, 'active', true)
		`, "cust-"+c.orgID, c.label, c.orgID, c.orgID, "tenant-"+c.orgID); err != nil {
			t.Fatalf("seed customers(%s): %v", c.orgID, err)
		}

		// api_keys — populate the 006_option3 columns + the RLS org_id.
		// api_key_id is passed as a string literal; Postgres parses it as
		// UUID per the column type. Mirrors production's TEXT-bound caller.
		if _, err := db.ExecContext(ctx, `
			INSERT INTO api_keys
			    (api_key_id, customer_id, license_key, license_key_hash,
			     key_name, key_type, expires_at, grace_period_days,
			     permissions, enabled, total_requests, org_id, updated_at)
			VALUES ($1::uuid, $2, $3, $4, $5, 'production', NOW() + INTERVAL '365 days', 30,
			        '["query","llm"]'::jsonb, true, 0, $6, NOW())
		`, c.apiKeyID, "cust-"+c.orgID,
			"axon-test-"+c.orgID, c.hash,
			c.label, c.orgID); err != nil {
			t.Fatalf("seed api_keys(%s): %v", c.orgID, err)
		}
	}
}

// b6Row is a (org_id, contentMarker) pair returned by SELECTs against api_keys
// or customers. Both fields checked — defeats "row leaked but happens to
// match" tautology class.
type b6Row struct {
	OrgID   string
	Content string
}

// selectVisibleB6Rows returns the (org_id, content) pairs visible from the
// given table inside the current tx, filtered to our two test orgs and
// sorted by org_id for stable assertion.
func selectVisibleB6Rows(ctx context.Context, tx *sql.Tx, tbl b6TestTable) ([]b6Row, error) {
	q := fmt.Sprintf(
		"SELECT org_id, %s FROM %s WHERE org_id IN ($1, $2) ORDER BY org_id",
		tbl.contentCol, tbl.name,
	)
	rows, err := tx.QueryContext(ctx, q, b6OrgA, b6OrgB)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []b6Row
	for rows.Next() {
		var r b6Row
		if err := rows.Scan(&r.OrgID, &r.Content); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OrgID < out[j].OrgID })
	return out, nil
}

// assertB6RowsEqual fails the test if got != want, including a clear
// diagnostic of which side carries which (org_id, content) pairs.
func assertB6RowsEqual(t *testing.T, table string, got, want []b6Row) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s visibility mismatch: got %d rows %+v, want %d rows %+v", table, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s row[%d] mismatch: got %+v, want %+v (full got=%+v, want=%+v)", table, i, got[i], want[i], got, want)
		}
	}
}

// =============================================================================
// TestRLSIsolation_B6 — top-level entry; runs the visibility + WITH CHECK +
// mutation-proof subtests against api_keys + customers.
// =============================================================================

func TestRLSIsolation_B6(t *testing.T) {
	db, cleanup := rlsB6TestSetup(t)
	defer cleanup()

	ctx := context.Background()

	// -------------------------------------------------------------------------
	// Scenario A: app_role + SET LOCAL app.current_org_id = orgA → sees only A
	// -------------------------------------------------------------------------
	for _, tbl := range b6Tables {
		tbl := tbl
		t.Run("A_OrgA_SeesOnlyOrgA/"+tbl.name, func(t *testing.T) {
			err := runAsAppRoleWithOrg(t, db, b6OrgA, func(tx *sql.Tx) error {
				rows, err := selectVisibleB6Rows(ctx, tx, tbl)
				if err != nil {
					return err
				}
				assertB6RowsEqual(t, tbl.name, rows, []b6Row{
					{OrgID: b6OrgA, Content: b6LabelA},
				})
				return nil
			})
			if err != nil {
				t.Fatalf("scenario A query: %v", err)
			}
		})
	}

	// -------------------------------------------------------------------------
	// Scenario B: app_role + SET LOCAL app.current_org_id = orgB → sees only B
	// -------------------------------------------------------------------------
	for _, tbl := range b6Tables {
		tbl := tbl
		t.Run("B_OrgB_SeesOnlyOrgB/"+tbl.name, func(t *testing.T) {
			err := runAsAppRoleWithOrg(t, db, b6OrgB, func(tx *sql.Tx) error {
				rows, err := selectVisibleB6Rows(ctx, tx, tbl)
				if err != nil {
					return err
				}
				assertB6RowsEqual(t, tbl.name, rows, []b6Row{
					{OrgID: b6OrgB, Content: b6LabelB},
				})
				return nil
			})
			if err != nil {
				t.Fatalf("scenario B query: %v", err)
			}
		})
	}

	// -------------------------------------------------------------------------
	// Scenario C: app_role with NO SET LOCAL → sees zero rows
	// -------------------------------------------------------------------------
	for _, tbl := range b6Tables {
		tbl := tbl
		t.Run("C_NoOrgContext_ZeroRows/"+tbl.name, func(t *testing.T) {
			err := runAsAppRoleNoOrg(t, db, func(tx *sql.Tx) error {
				var orgGUC string
				if err := tx.QueryRowContext(ctx, "SELECT current_setting('app.current_org_id', true)").Scan(&orgGUC); err != nil {
					return fmt.Errorf("check entry GUC: %w", err)
				}
				if orgGUC != "" {
					return fmt.Errorf("expected app.current_org_id='' at tx entry, got %q (GUC leaked from prior subtest)", orgGUC)
				}
				rows, err := selectVisibleB6Rows(ctx, tx, tbl)
				if err != nil {
					return err
				}
				assertB6RowsEqual(t, tbl.name, rows, nil)
				return nil
			})
			if err != nil {
				t.Fatalf("scenario C query: %v", err)
			}
		})
	}

	// -------------------------------------------------------------------------
	// Scenario D: axonflow_platform_admin (BYPASSRLS) → sees both rows
	// -------------------------------------------------------------------------
	for _, tbl := range b6Tables {
		tbl := tbl
		t.Run("D_AdminBypass_SeesBothRows/"+tbl.name, func(t *testing.T) {
			err := runAsPlatformAdmin(t, db, func(tx *sql.Tx) error {
				rows, err := selectVisibleB6Rows(ctx, tx, tbl)
				if err != nil {
					return err
				}
				assertB6RowsEqual(t, tbl.name, rows, []b6Row{
					{OrgID: b6OrgA, Content: b6LabelA},
					{OrgID: b6OrgB, Content: b6LabelB},
				})
				return nil
			})
			if err != nil {
				t.Fatalf("scenario D query: %v", err)
			}
		})
	}

	// -------------------------------------------------------------------------
	// WITH CHECK enforcement: under orgA, INSERT a row with org_id=orgB →
	// expect SQLSTATE 42501 RLS policy violation.
	// -------------------------------------------------------------------------
	t.Run("WITH_CHECK_OrgA_RejectsOrgBInsert/customers", func(t *testing.T) {
		err := runAsAppRoleWithOrg(t, db, b6OrgA, func(tx *sql.Tx) error {
			_, ex := tx.ExecContext(ctx, `
				INSERT INTO customers
				    (customer_id, organization_name, organization_id, org_id,
				     deployment_mode, tier, tenant_id, status, enabled)
				VALUES ($1, $2, $3, $4, 'in-vpc', 'Enterprise', $5, 'active', true)
			`,
				"cust-b6-attack",
				"b6-attack-label",
				"b6-attack-org-id",
				b6OrgB, // mismatched org_id
				"tenant-b6-attack",
			)
			return mustBeRLSViolation(ex)
		})
		if err != nil {
			t.Fatalf("WITH CHECK customers: %v", err)
		}
	})

	t.Run("WITH_CHECK_OrgA_RejectsOrgBInsert/api_keys", func(t *testing.T) {
		err := runAsAppRoleWithOrg(t, db, b6OrgA, func(tx *sql.Tx) error {
			_, ex := tx.ExecContext(ctx, `
				INSERT INTO api_keys
				    (api_key_id, customer_id, license_key, license_key_hash,
				     key_name, key_type, expires_at, grace_period_days,
				     permissions, enabled, total_requests, org_id, updated_at)
				VALUES ($1::uuid, $2, $3, $4, $5, 'production', NOW() + INTERVAL '365 days', 30,
				        '["query","llm"]'::jsonb, true, 0, $6, NOW())
			`,
				"33333333-3333-3333-3333-333333333333", // synthetic attacker UUID
				"cust-"+b6OrgA,                         // existing customer (FK ok)
				"axon-test-b6-attack",
				"b6-attack-hash",
				"b6-attack-key-name",
				b6OrgB, // mismatched org_id
			)
			return mustBeRLSViolation(ex)
		})
		if err != nil {
			t.Fatalf("WITH CHECK api_keys: %v", err)
		}
	})

	// -------------------------------------------------------------------------
	// SECURITY DEFINER load-bearing mutation proof.
	//
	// Re-create auth_lookup_api_key WITHOUT the SECURITY DEFINER keyword
	// (i.e., as SECURITY INVOKER, the default). Then call it as
	// axonflow_app_role with NO app.current_org_id set. With FORCE RLS on
	// api_keys + customers and an unset GUC, the JOIN inside the function
	// runs under the caller's RLS context and returns 0 rows — proving the
	// SECURITY DEFINER keyword is the load-bearing piece. Restore the
	// SECURITY DEFINER variant in defer so subsequent subtests are unaffected.
	//
	// We use license_key_hash = b6HashA which IS present in the seed; the
	// SECURITY DEFINER version returns 1 row for this hash, the SECURITY
	// INVOKER (mutated) version returns 0 (RLS hides it).
	// -------------------------------------------------------------------------
	t.Run("MutationProof_SecurityDefinerRequired_AuthLookupApiKey", func(t *testing.T) {
		// Sanity-check the SECURITY DEFINER version returns 1 row for b6HashA
		// under app_role with NO GUC. This is the SECURITY DEFINER bypass
		// exercising itself — even with no GUC, the function runs as its
		// owner (superuser) so RLS is bypassed inside the function body.
		if err := runAsAppRoleNoOrg(t, db, func(tx *sql.Tx) error {
			var n int
			if err := tx.QueryRowContext(ctx,
				"SELECT COUNT(*) FROM auth_lookup_api_key($1)", b6HashA,
			).Scan(&n); err != nil {
				return fmt.Errorf("count via SECURITY DEFINER fn: %w", err)
			}
			if n != 1 {
				return fmt.Errorf("SECURITY DEFINER baseline: expected 1 row, got %d (function not bypassing RLS — fix the test setup)", n)
			}
			return nil
		}); err != nil {
			t.Fatalf("baseline failed: %v", err)
		}

		// Mutate: re-create as SECURITY INVOKER (default; we omit the
		// SECURITY DEFINER keyword). The body is otherwise identical.
		mutationSQL := `
CREATE OR REPLACE FUNCTION auth_lookup_api_key(p_license_key_hash TEXT)
    RETURNS TABLE(
        api_key_id          VARCHAR,
        customer_id         VARCHAR,
        license_key         VARCHAR,
        key_name            VARCHAR,
        key_type            VARCHAR,
        expires_at          TIMESTAMPTZ,
        grace_period_days   INTEGER,
        permissions         JSONB,
        custom_rate_limit   INTEGER,
        enabled             BOOLEAN,
        revoked_at          TIMESTAMPTZ,
        last_used_at        TIMESTAMPTZ,
        total_requests      BIGINT,
        c_customer_id       VARCHAR,
        organization_name   VARCHAR,
        organization_id     VARCHAR,
        deployment_mode     VARCHAR,
        tier                VARCHAR,
        tenant_id           VARCHAR,
        status              VARCHAR,
        c_enabled           BOOLEAN,
        requests_per_minute INTEGER
    )
    LANGUAGE plpgsql
    STABLE
    -- NOTE: SECURITY DEFINER keyword INTENTIONALLY OMITTED (mutation under test)
AS $body$
BEGIN
    RETURN QUERY
    SELECT k.api_key_id::VARCHAR, k.customer_id::VARCHAR, k.license_key::VARCHAR,
           k.key_name::VARCHAR, k.key_type::VARCHAR, k.expires_at,
           k.grace_period_days, k.permissions, k.custom_rate_limit, k.enabled,
           k.revoked_at, k.last_used_at, k.total_requests,
           c.customer_id::VARCHAR, c.organization_name, c.organization_id,
           c.deployment_mode, c.tier, c.tenant_id, c.status, c.enabled,
           pt.requests_per_minute
    FROM api_keys k
    JOIN customers c ON k.customer_id = c.customer_id
    JOIN pricing_tiers pt ON c.tier = pt.tier
                         AND c.deployment_mode = pt.deployment_mode
    WHERE k.license_key_hash = p_license_key_hash
      AND k.enabled = true
      AND c.enabled = true
      AND c.status  = 'active';
END;
$body$;
`
		if _, err := db.ExecContext(ctx, mutationSQL); err != nil {
			t.Fatalf("mutate auth_lookup_api_key to SECURITY INVOKER: %v", err)
		}

		// Restore in defer so subsequent runs see the canonical version.
		// Also ASSERT the restoration actually re-installed SECURITY DEFINER —
		// folded inline from R3 round 1 MEDIUM-4 (a regression that broke
		// the restore would leave subsequent subtests in a false-pass state).
		defer func() {
			// Restore by re-applying migration 108. Since CREATE OR REPLACE
			// replaces the function in place, re-running the migration is
			// the simplest restoration path.
			runMigrationsRange(t, db, 108, 108)

			// Post-restore confirmation: prosecdef=true via pg_proc, AND a
			// real call returns 1 row again (baseline equivalence). If
			// restoration silently fails, the next mutation subtest would
			// false-pass against a SECURITY INVOKER residue.
			var prosecdef bool
			if err := db.QueryRowContext(ctx,
				`SELECT prosecdef FROM pg_proc WHERE proname = 'auth_lookup_api_key' AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')`,
			).Scan(&prosecdef); err != nil {
				t.Errorf("post-restore prosecdef check: %v", err)
				return
			}
			if !prosecdef {
				t.Errorf("post-restore prosecdef=false (restoration via runMigrationsRange did NOT re-install SECURITY DEFINER variant); subsequent subtests would false-pass")
				return
			}
			if err := runAsAppRoleNoOrg(t, db, func(tx *sql.Tx) error {
				var n int
				if err := tx.QueryRowContext(ctx,
					"SELECT COUNT(*) FROM auth_lookup_api_key($1)", b6HashA,
				).Scan(&n); err != nil {
					return fmt.Errorf("post-restore baseline: %w", err)
				}
				if n != 1 {
					return fmt.Errorf("post-restore baseline FAILED: expected 1 row from SECURITY DEFINER variant, got %d", n)
				}
				return nil
			}); err != nil {
				t.Errorf("post-restore baseline assertion: %v", err)
			}
		}()

		// Now call the mutated function as app_role with NO GUC. The JOIN
		// inside the function body runs under the caller's RLS context;
		// FORCE RLS on api_keys + customers + empty GUC means the JOIN
		// produces 0 rows.
		if err := runAsAppRoleNoOrg(t, db, func(tx *sql.Tx) error {
			var n int
			if err := tx.QueryRowContext(ctx,
				"SELECT COUNT(*) FROM auth_lookup_api_key($1)", b6HashA,
			).Scan(&n); err != nil {
				return fmt.Errorf("count via SECURITY INVOKER mutation: %w", err)
			}
			if n != 0 {
				return fmt.Errorf("mutation proof FAILED: SECURITY INVOKER variant returned %d rows (expected 0); SECURITY DEFINER keyword is NOT load-bearing — auth lookup would still work without it. Either the function isn't actually running under app_role context, or the policy isn't being enforced on this code path.", n)
			}
			return nil
		}); err != nil {
			t.Fatalf("mutation proof query: %v", err)
		}
		t.Log("mutation proof verified: SECURITY DEFINER keyword is load-bearing. With it, the function bypasses RLS and returns 1 row; without it (SECURITY INVOKER), the JOIN under app_role's empty GUC returns 0 rows — auth would fail.")
	})

	// -------------------------------------------------------------------------
	// RLS-package load-bearing mutation proof: DISABLE RLS per table, re-run
	// scenario A, assert visible-count flips 1 → 2 (cross-org leak observable).
	// Restore ENABLE + FORCE in defer. Mirrors rls_phase6_isolation_test.go's
	// per-table mutation pattern.
	//
	// Why DISABLE (not NO FORCE): per
	// reference_rls_force_vs_enable_under_app_role.md, under
	// axonflow_app_role (NOBYPASSRLS per mig 098), FORCE is irrelevant —
	// Postgres only consults FORCE for table-owner roles. ENABLE + policy
	// together gate app_role's visibility. The mutation that observably
	// changes scenario A's count under app_role is therefore DISABLE.
	// -------------------------------------------------------------------------
	for _, tbl := range b6Tables {
		tbl := tbl
		t.Run("MutationProof_DisableRLS_LeaksCrossOrg/"+tbl.name, func(t *testing.T) {
			tblName := tbl.name
			if _, err := db.ExecContext(ctx,
				fmt.Sprintf("ALTER TABLE %s DISABLE ROW LEVEL SECURITY", tblName)); err != nil {
				t.Fatalf("disable RLS on %s: %v", tblName, err)
			}

			defer func() {
				if _, err := db.ExecContext(ctx,
					fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY", tblName)); err != nil {
					t.Errorf("restore ENABLE on %s: %v", tblName, err)
				}
				if _, err := db.ExecContext(ctx,
					fmt.Sprintf("ALTER TABLE %s FORCE ROW LEVEL SECURITY", tblName)); err != nil {
					t.Errorf("restore FORCE on %s: %v", tblName, err)
				}
			}()

			err := runAsAppRoleWithOrg(t, db, b6OrgA, func(tx *sql.Tx) error {
				rows, err := selectVisibleB6Rows(ctx, tx, tbl)
				if err != nil {
					return err
				}
				if len(rows) != 2 {
					return fmt.Errorf("mutation proof FAILED: with RLS DISABLED on %s, scenario A still sees %d rows %+v; expected 2 (cross-org leak should be observable). Assertion in scenario A is tautological — the test does not actually depend on RLS being active.",
						tblName, len(rows), rows)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("mutation proof query: %v", err)
			}
			t.Logf("mutation proof verified: disabling RLS on %s flipped scenario A from 1 visible row to 2 (cross-org leak observable, RLS package is load-bearing)", tblName)
		})
	}

	// -------------------------------------------------------------------------
	// Touch-path coverage (R3 round 1 HIGH-1 regression guard).
	//
	// auth_touch_api_key is invoked as a fire-and-forget goroutine after
	// validateViaAPIKeys returns success. It runs as axonflow_app_role on
	// a fresh connection with NO app.current_org_id set — and must succeed
	// (SECURITY DEFINER bypass) on the UUID-typed api_key_id column. Without
	// the explicit `WHERE api_key_id::TEXT = p_api_key_id::TEXT` cast in
	// the function body, Postgres errors with `operator does not exist:
	// uuid = character varying`.
	//
	// This subtest exercises the touch path end-to-end against the real DB
	// with the UUID column type that production uses (see the test schema's
	// `api_key_id UUID DEFAULT gen_random_uuid()` ALTER). Pre-state:
	// total_requests = 0. Post-state: total_requests = 1. last_used_at
	// transitions from NULL to a non-NULL timestamp.
	// -------------------------------------------------------------------------
	t.Run("TouchPath_NoGUC_UpdatesUUIDApiKeyId", func(t *testing.T) {
		// Self-managed tx + COMMIT (NOT the runAsAppRoleNoOrg helper, which
		// rollback-defers — the touch path's UPDATE would never persist for
		// the readback below to observe). Inside the tx: SET LOCAL ROLE
		// axonflow_app_role (no GUC set on app.current_org_id, mirroring
		// the fire-and-forget goroutine's runtime context).
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("BeginTx: %v", err)
		}
		if _, ex := tx.ExecContext(ctx, "SET LOCAL ROLE axonflow_app_role"); ex != nil {
			_ = tx.Rollback()
			t.Fatalf("SET LOCAL ROLE: %v", ex)
		}
		if _, ex := tx.ExecContext(ctx,
			"SELECT auth_touch_api_key($1)", b6ApiKeyIDA,
		); ex != nil {
			_ = tx.Rollback()
			t.Fatalf("auth_touch_api_key($1) call failed (UUID cast regression?): %v", ex)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}

		// Verify post-state under platform_admin (BYPASSRLS so we can read).
		if err := runAsPlatformAdmin(t, db, func(tx *sql.Tx) error {
			var totalRequests int64
			var lastUsedAt sql.NullTime
			if err := tx.QueryRowContext(ctx,
				`SELECT total_requests, last_used_at FROM api_keys WHERE api_key_id = $1::uuid`,
				b6ApiKeyIDA,
			).Scan(&totalRequests, &lastUsedAt); err != nil {
				return fmt.Errorf("post-touch readback: %w", err)
			}
			if totalRequests != 1 {
				return fmt.Errorf("post-touch total_requests=%d, expected 1 (auth_touch_api_key body did NOT increment — UUID cast regression?)", totalRequests)
			}
			if !lastUsedAt.Valid {
				return fmt.Errorf("post-touch last_used_at IS NULL, expected non-NULL (auth_touch_api_key body did NOT set the timestamp)")
			}
			return nil
		}); err != nil {
			t.Fatalf("touch-path post-state assertion: %v", err)
		}
		t.Log("touch-path verified: auth_touch_api_key updates total_requests + last_used_at under UUID-typed api_key_id without app.current_org_id (SECURITY DEFINER bypass works on the touch path).")
	})

	// -------------------------------------------------------------------------
	// Backfill coverage (R3 round 1 MEDIUM-1 regression guard).
	//
	// The main seedB6Rows pre-populates org_id explicitly, so migration 108's
	// backfill block (108_v9_b6_in_vpc_security_definer.sql lines 294-311)
	// matches zero rows during the main test setup. This subtest seeds a
	// fresh customer + api_key WITH org_id=NULL, then re-runs migration 108,
	// and asserts the backfill UPDATEs landed.
	//
	// Migration is idempotent (CREATE OR REPLACE + WHERE org_id IS NULL OR ''
	// guard), so re-running is safe. The backfill is deterministic:
	// customers.org_id ← organization_id; api_keys.org_id ← joined
	// customers.org_id.
	// -------------------------------------------------------------------------
	t.Run("Backfill_PopulatesEmptyOrgId", func(t *testing.T) {
		const backfillCustomerID = "cust-b6-backfill"
		const backfillOrgID = "rls-b6-backfill-org"
		const backfillTenantID = "tenant-b6-backfill"
		const backfillApiKeyID = "55555555-5555-5555-5555-555555555555"
		const backfillHash = "b6-backfill-hash"
		const backfillLabel = "b6-backfill-label"

		// Cleanup any residue from a prior run.
		_, _ = db.ExecContext(ctx, "DELETE FROM api_keys  WHERE customer_id = $1", backfillCustomerID)
		_, _ = db.ExecContext(ctx, "DELETE FROM customers WHERE customer_id = $1", backfillCustomerID)
		_, _ = db.ExecContext(ctx, "DELETE FROM organizations WHERE org_id = $1", backfillOrgID)

		// FORCE RLS is on at this point — temporarily DISABLE so we can
		// seed an UNbackfilled row (no GUC during seed). Same shape as
		// seedB6Rows.
		for _, tbl := range b6Tables {
			if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s DISABLE ROW LEVEL SECURITY", tbl.name)); err != nil {
				t.Fatalf("disable RLS for backfill seed on %s: %v", tbl.name, err)
			}
		}
		defer func() {
			for _, tbl := range b6Tables {
				_, _ = db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY", tbl.name))
				_, _ = db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s FORCE ROW LEVEL SECURITY", tbl.name))
			}
			// Cleanup the seeded backfill cohort.
			_, _ = db.ExecContext(ctx, "DELETE FROM api_keys  WHERE customer_id = $1", backfillCustomerID)
			_, _ = db.ExecContext(ctx, "DELETE FROM customers WHERE customer_id = $1", backfillCustomerID)
			_, _ = db.ExecContext(ctx, "DELETE FROM organizations WHERE org_id = $1", backfillOrgID)
		}()

		// organizations row first (api_keys.org_id FKs to it).
		if _, err := db.ExecContext(ctx, `
			INSERT INTO organizations (org_id, name, license_key, tier, created_at)
			VALUES ($1, $1, $2, 'Enterprise', NOW())
		`, backfillOrgID, "b6-backfill-license"); err != nil {
			t.Fatalf("seed backfill organizations: %v", err)
		}

		// customers row with org_id = NULL (the row migration 108's backfill
		// targets).
		if _, err := db.ExecContext(ctx, `
			INSERT INTO customers
			    (customer_id, organization_name, organization_id, org_id,
			     deployment_mode, tier, tenant_id, status, enabled)
			VALUES ($1, $2, $3, NULL, 'in-vpc', 'Enterprise', $4, 'active', true)
		`, backfillCustomerID, backfillLabel, backfillOrgID, backfillTenantID); err != nil {
			t.Fatalf("seed backfill customers: %v", err)
		}

		// api_keys row with org_id = NULL.
		if _, err := db.ExecContext(ctx, `
			INSERT INTO api_keys
			    (api_key_id, customer_id, license_key, license_key_hash,
			     key_name, key_type, expires_at, grace_period_days,
			     permissions, enabled, total_requests, org_id, updated_at)
			VALUES ($1::uuid, $2, $3, $4, $5, 'production', NOW() + INTERVAL '365 days', 30,
			        '["query","llm"]'::jsonb, true, 0, NULL, NOW())
		`, backfillApiKeyID, backfillCustomerID,
			"axon-test-backfill", backfillHash, backfillLabel); err != nil {
			t.Fatalf("seed backfill api_keys: %v", err)
		}

		// Re-run migration 108 — its backfill block should now match these
		// two rows (one in customers, one in api_keys).
		runMigrationsRange(t, db, 108, 108)

		// Assert backfill landed. Read under platform_admin (BYPASSRLS) so
		// we can see the rows regardless of org_id state.
		if err := runAsPlatformAdmin(t, db, func(tx *sql.Tx) error {
			var customerOrgID sql.NullString
			if err := tx.QueryRowContext(ctx,
				"SELECT org_id FROM customers WHERE customer_id = $1", backfillCustomerID,
			).Scan(&customerOrgID); err != nil {
				return fmt.Errorf("readback customers.org_id: %w", err)
			}
			if !customerOrgID.Valid || customerOrgID.String != backfillOrgID {
				return fmt.Errorf("customers.org_id post-backfill = %v, expected %q (backfill UPDATE on customers did NOT run or used wrong source column)", customerOrgID, backfillOrgID)
			}

			var apiKeyOrgID sql.NullString
			if err := tx.QueryRowContext(ctx,
				"SELECT org_id FROM api_keys WHERE api_key_id = $1::uuid", backfillApiKeyID,
			).Scan(&apiKeyOrgID); err != nil {
				return fmt.Errorf("readback api_keys.org_id: %w", err)
			}
			if !apiKeyOrgID.Valid || apiKeyOrgID.String != backfillOrgID {
				return fmt.Errorf("api_keys.org_id post-backfill = %v, expected %q (backfill UPDATE on api_keys did NOT run or JOIN was wrong)", apiKeyOrgID, backfillOrgID)
			}
			return nil
		}); err != nil {
			t.Fatalf("backfill assertion: %v", err)
		}
		t.Log("backfill verified: migration 108 populated customers.org_id from organization_id + api_keys.org_id via the customer_id JOIN.")
	})
}
