// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres tests for PolicyOverrideRepository (#3334).
//
// WHY THIS FILE EXISTS
//
// platform/agent/policy_override_repository_test.go is entirely sqlmock. sqlmock matches SQL text against regexes and returns canned rows;
// no statement is ever executed. As static_policy_repository_segment_realpg_test.go
// puts it for the sibling repository:
//
//	sqlmock ... cannot validate a real SQL WHERE clause - it returns whatever
//	rows it is told to, regardless of the query's actual filtering
//
// For policy_overrides that gap is wider than for most tables, because the
// three things most worth asserting are things sqlmock cannot reach AT ALL:
//
//  1. SCOPE SELECTION. Whether an override written for tenant A is visible to
//     tenant B is a property of the WHERE clause. Under sqlmock the canned row
//     comes back either way, so the existing suite goes green on a repository
//     that leaks across scopes.
//  2. The CHECK constraint on the table.
//  3. ROW-LEVEL SECURITY. Nothing in the sqlmock suite touches it, yet it is
//     what keeps one organization's overrides out of another's reads: under
//     app_role without app.current_org_id pinned, the USING predicate masks
//     rows.
//
// WHY THE ASSERTIONS GO THROUGH THE REPOSITORY API RATHER THAN NAMING COLUMNS
//
// This suite is deliberately written to be correct on BOTH sides of the
// #3334 organization_id retirement, because that retirement is in flight in a
// separate PR that also edits the sqlmock suite:
//
//   - Go-level: nothing here references PolicyOverride.OrganizationID. That
//     field is REMOVED by the retirement, so a test that sets it would stop
//     COMPILING the moment the retirement lands. Scope is expressed with
//     TenantID and OrgID only, which both survive.
//   - SQL-level: the minimal schema below carries BOTH organization_id and
//     org_id. Before the retirement the repository filters org-scoped reads on
//     organization_id; after it, on org_id. A schema carrying both satisfies
//     either query, and an unused nullable column is inert. The org-scoped
//     FIXTURE ROWS are therefore seeded with raw SQL that sets both columns to
//     the same value, which is what makes the org-selection assertions below
//     pass under either predicate.
//
// Every fixture row is seeded with raw SQL: the repository reads overrides and
// writes none (PRD v11 §1.5, W3-I item 9 removed its per-policy writers with the
// routes that called them), so coverage here is SELECTION and ISOLATION.
//
// Gated on Docker (testutil.SkipIfNoDocker) and building its own minimal
// schema rather than applying the migration chain, per
// static_policy_repository_segment_realpg_test.go.

import (
	"context"
	"database/sql"
	"net/url"
	"testing"
	"time"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
)

const (
	// Two tenants in two organizations, for the scoping and isolation cases.
	overrideTestTenant  = "acme-tenant"
	overrideTestTenantB = "globex-tenant"
	overrideTestOrg     = "acme-org"
	overrideTestOrgB    = "globex-org"

	// The password granted to the non-owner role used for the RLS cases.
	overrideAppRolePassword = "rls_probe_pw"
)

// newOverrideTestDB starts a container and builds the minimal schema the
// repository actually reads.
//
// The DDL is faithful to the shipped migrations in the ways that matter to
// these tests, and the deviations are deliberate:
//
//   - policy_overrides carries BOTH organization_id and org_id (see the file
//     header for why).
//   - RLS is ENABLEd but NOT FORCEd, exactly as migrations/core/030:103 leaves
//     it. This matters: with ENABLE alone the table OWNER bypasses RLS
//     entirely, so an RLS assertion made on this connection would pass no
//     matter what the policy said. That is why the RLS tests below open a
//     SECOND connection as a non-owner role instead of reusing pc.DB.
//   - The isolation policy is migration core/110's, verbatim in shape:
//     USING/WITH CHECK on org_id = current_setting('app.current_org_id', true).
func newOverrideTestDB(t *testing.T) *testutil.PostgresContainer {
	t.Helper()
	testutil.SkipIfNoDocker(t)

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pc.RunMigration(t, `
		CREATE TABLE static_policies (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			policy_id   varchar(255) UNIQUE,
			name        varchar(255),
			category    varchar(100),
			pattern     text,
			severity    varchar(50),
			description text,
			action      varchar(50),
			tier        varchar(50),
			priority    int,
			enabled     boolean,
			organization_id text,
			tenant_id   varchar(255),
			org_id      varchar(255),
			segment_id  varchar(255),
			tags        text,
			metadata    text,
			version     int,
			created_at  timestamptz DEFAULT now(),
			updated_at  timestamptz DEFAULT now(),
			created_by  varchar(255),
			updated_by  varchar(255),
			deleted_at  timestamptz
		);
		CREATE TABLE policy_overrides (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			policy_id       uuid NOT NULL,
			policy_type     varchar(50),
			organization_id text,
			tenant_id       varchar(100),
			org_id          varchar(255) NOT NULL,
			tool_signature  text,
			action_override varchar(50),
			enabled_override boolean,
			override_reason text,
			expires_at      timestamptz,
			created_by      varchar(255),
			created_at      timestamptz DEFAULT now(),
			updated_by      varchar(255),
			updated_at      timestamptz DEFAULT now(),
			revoked_at      timestamptz
		);
		ALTER TABLE policy_overrides ENABLE ROW LEVEL SECURITY;
		CREATE POLICY policy_overrides_org_id_isolation ON policy_overrides
			USING (org_id = current_setting('app.current_org_id', true))
			WITH CHECK (org_id = current_setting('app.current_org_id', true));
	`)

	return pc
}

// seedSystemPolicy inserts a tier='system' static policy (the tier a per-policy
// override named) and returns its UUID, which is what policy_overrides.policy_id
// stores.
func seedSystemPolicy(t *testing.T, db *sql.DB, policyID string) string {
	t.Helper()
	var id string
	err := db.QueryRow(`
		INSERT INTO static_policies
			(policy_id, name, category, pattern, severity, action, tier, priority, enabled, tenant_id, org_id, version)
		VALUES ($1, $1, 'pii-global', 'ssn', 'high', 'block', 'system', 50, true, $2, $3, 1)
		RETURNING id::text
	`, policyID, overrideTestTenant, overrideTestOrg).Scan(&id)
	if err != nil {
		t.Fatalf("seed system policy %q: %v", policyID, err)
	}
	return id
}

// seedTenantOverride inserts a TENANT-scoped override row, the shape the
// retired per-policy override route wrote, and returns its id.
func seedTenantOverride(t *testing.T, db *sql.DB, policyUUID, tenant, org string, expiresAt *time.Time) string {
	t.Helper()
	var id string
	err := db.QueryRow(`
		INSERT INTO policy_overrides
			(policy_id, policy_type, tenant_id, org_id,
			 action_override, override_reason, expires_at, created_by, updated_by)
		VALUES ($1, 'static', $2, $3, 'warn', 'approved by compliance, ticket AX-1', $4::timestamptz, 'seed', 'seed')
		RETURNING id::text
	`, policyUUID, tenant, org, expiresAt).Scan(&id)
	if err != nil {
		t.Fatalf("seed tenant override for %q: %v", tenant, err)
	}
	return id
}

// seedOrgScopedOverride inserts an ORG-scoped override row directly. It writes
// BOTH organization_id and org_id to the same value, so the row satisfies the
// org-scoped predicate whether the repository filters on the legacy column or
// on org_id. See the file header.
func seedOrgScopedOverride(t *testing.T, db *sql.DB, policyUUID, org string, expiresAt *time.Time) string {
	t.Helper()
	var id string
	err := db.QueryRow(`
		INSERT INTO policy_overrides
			(policy_id, policy_type, organization_id, tenant_id, org_id,
			 action_override, override_reason, expires_at, created_by, updated_by)
		VALUES ($1, 'static', $2::text, NULL, $2::text, 'warn', 'org scoped fixture', $3::timestamptz, 'seed', 'seed')
		RETURNING id::text
	`, policyUUID, org, expiresAt).Scan(&id)
	if err != nil {
		t.Fatalf("seed org-scoped override for %q: %v", org, err)
	}
	return id
}

// strptr is a local helper; the package has no shared one for *string literals.
func strptr(s string) *string { return &s }

// orgCtx returns a context carrying an authenticated caller org, as an
// authenticated request's does.
func orgCtx(org string) context.Context {
	return context.WithValue(context.Background(), ContextKeyOrgID, org)
}

// ────────────────────────────────────────────────────────────────────────────
// Selection and scoping - what sqlmock structurally cannot prove
// ────────────────────────────────────────────────────────────────────────────

// TestGetOverrideForPolicy_RealPG proves the WHERE clause actually scopes.
// Under sqlmock both halves of each pair return the canned row, so a
// repository that ignored tenant_id entirely would still pass the old suite.
func TestGetOverrideForPolicy_RealPG(t *testing.T) {
	pc := newOverrideTestDB(t)
	db := pc.DB
	ctx := orgCtx(overrideTestOrg)
	repo := NewPolicyOverrideRepository(db)

	pid := seedSystemPolicy(t, db, "sys_get_scope")
	seedTenantOverride(t, db, pid, overrideTestTenant, overrideTestOrg, nil)

	t.Run("found for its own tenant", func(t *testing.T) {
		got, err := repo.GetOverrideForPolicy(ctx, pid, strptr(overrideTestTenant), nil)
		if err != nil {
			t.Fatalf("GetOverrideForPolicy(own tenant): %v", err)
		}
		if got == nil || got.TenantID == nil || *got.TenantID != overrideTestTenant {
			t.Fatalf("got %+v, want the override for %q", got, overrideTestTenant)
		}
	})

	t.Run("NOT found for a different tenant", func(t *testing.T) {
		got, err := repo.GetOverrideForPolicy(ctx, pid, strptr(overrideTestTenantB), nil)
		if err != ErrOverrideNotFound {
			t.Fatalf("cross-tenant read returned (%+v, %v); want ErrOverrideNotFound", got, err)
		}
	})
}

// TestOverrideOrgScopeSelection_RealPG covers the org-scoped read path: an
// org-scoped override is selected for its own org and never for another.
//
// Fixtures are seeded with raw SQL setting organization_id AND org_id to the
// same value, so the assertions hold whichever column the repository's
// org-scoped predicate names. See the file header.
func TestOverrideOrgScopeSelection_RealPG(t *testing.T) {
	pc := newOverrideTestDB(t)
	db := pc.DB
	ctx := orgCtx(overrideTestOrg)
	repo := NewPolicyOverrideRepository(db)

	pid := seedSystemPolicy(t, db, "sys_org_scope")
	seedOrgScopedOverride(t, db, pid, overrideTestOrg, nil)

	t.Run("selected for its own org", func(t *testing.T) {
		got, err := repo.GetOverrideForPolicy(ctx, pid, nil, strptr(overrideTestOrg))
		if err != nil {
			t.Fatalf("org-scoped read for own org: %v", err)
		}
		if got == nil {
			t.Fatal("org-scoped read returned no override for its own org")
		}
		if got.TenantID != nil {
			t.Errorf("an org-scoped row must have a NULL tenant_id, got %v", got.TenantID)
		}
	})

	t.Run("no cross-org bleed", func(t *testing.T) {
		got, err := repo.GetOverrideForPolicy(ctx, pid, nil, strptr(overrideTestOrgB))
		if err != ErrOverrideNotFound {
			t.Fatalf("cross-org read returned (%+v, %v); want ErrOverrideNotFound", got, err)
		}
	})
}

// TestListOverridesForTenant_RealPG covers list scoping and the expiry
// predicate, both evaluated by the database.
func TestListOverridesForTenant_RealPG(t *testing.T) {
	pc := newOverrideTestDB(t)
	db := pc.DB
	ctx := orgCtx(overrideTestOrg)
	repo := NewPolicyOverrideRepository(db)

	pidA := seedSystemPolicy(t, db, "sys_list_a")
	pidB := seedSystemPolicy(t, db, "sys_list_b")
	seedTenantOverride(t, db, pidA, overrideTestTenant, overrideTestOrg, nil)
	seedTenantOverride(t, db, pidB, overrideTestTenantB, overrideTestOrgB, nil)

	t.Run("one tenant's overrides do not bleed into another's", func(t *testing.T) {
		got, err := repo.ListOverridesForTenant(ctx, overrideTestTenant, nil, true)
		if err != nil {
			t.Fatalf("ListOverridesForTenant: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d overrides for %q, want 1", len(got), overrideTestTenant)
		}
		if got[0].TenantID == nil || *got[0].TenantID != overrideTestTenant {
			t.Errorf("list returned a row for %v, want %q", got[0].TenantID, overrideTestTenant)
		}
	})

	t.Run("expiry is evaluated by the database, not a canned row", func(t *testing.T) {
		past := time.Now().UTC().Add(-1 * time.Hour)
		expired := seedTenantOverride(t, db, seedSystemPolicy(t, db, "sys_list_expired"), overrideTestTenant, overrideTestOrg, &past)

		active, err := repo.ListOverridesForTenant(ctx, overrideTestTenant, nil, false)
		if err != nil {
			t.Fatalf("list active: %v", err)
		}
		for _, o := range active {
			if o.ID == expired {
				t.Error("an expired override was returned with includeExpired=false")
			}
		}

		all, err := repo.ListOverridesForTenant(ctx, overrideTestTenant, nil, true)
		if err != nil {
			t.Fatalf("list all: %v", err)
		}
		var seen bool
		for _, o := range all {
			if o.ID == expired {
				seen = true
			}
		}
		if !seen {
			t.Error("the expired override was missing with includeExpired=true")
		}
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Row-level security - coverage with no sqlmock equivalent at all
// ────────────────────────────────────────────────────────────────────────────

// appRoleDB opens a SECOND connection as a non-owner role.
//
// This indirection is load-bearing. migrations/core/030:103 leaves
// policy_overrides with ENABLE ROW LEVEL SECURITY and NOT force, so the table
// OWNER - which is what pc.DB connects as - bypasses every policy. An RLS
// assertion made on pc.DB would therefore pass whatever the policy said, and
// would keep passing if the policy were deleted outright. Production connects
// as axonflow_app_role, a non-owner; these tests do the same.
//
// The connection is pinned to a single connection because the GUC is set with
// SET LOCAL semantics per transaction, and a pooled second connection would
// silently not carry it.
func appRoleDB(t *testing.T, pc *testutil.PostgresContainer) *sql.DB {
	t.Helper()

	pc.RunMigration(t, `
		DROP ROLE IF EXISTS axonflow_app_role_test;
		CREATE ROLE axonflow_app_role_test LOGIN PASSWORD '`+overrideAppRolePassword+`';
		GRANT SELECT, INSERT, UPDATE, DELETE ON policy_overrides TO axonflow_app_role_test;
		GRANT SELECT ON static_policies TO axonflow_app_role_test;
	`)

	u, err := url.Parse(pc.URL)
	if err != nil {
		t.Fatalf("parse container URL: %v", err)
	}
	u.User = url.UserPassword("axonflow_app_role_test", overrideAppRolePassword)

	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatalf("open app-role connection: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	if err := db.Ping(); err != nil {
		t.Fatalf("ping as app role: %v", err)
	}

	// Prove we are actually NOT the owner. Without this, a misconfigured DSN
	// would silently reconnect as the owner and every assertion below would
	// pass by bypassing RLS rather than by satisfying it.
	var who string
	if err := db.QueryRow(`SELECT current_user`).Scan(&who); err != nil {
		t.Fatalf("current_user: %v", err)
	}
	if who != "axonflow_app_role_test" {
		t.Fatalf("connected as %q, want axonflow_app_role_test - RLS would be bypassed", who)
	}
	return db
}

// TestPolicyOverridesRLS_RealPG covers the table's org isolation under the
// application role.
func TestPolicyOverridesRLS_RealPG(t *testing.T) {
	pc := newOverrideTestDB(t)
	ctx := orgCtx(overrideTestOrg)
	owner := pc.DB

	pid := seedSystemPolicy(t, owner, "sys_rls")
	seedTenantOverride(t, owner, pid, overrideTestTenant, overrideTestOrg, nil)

	appDB := appRoleDB(t, pc)

	t.Run("an unpinned read is masked to zero rows, not leaked", func(t *testing.T) {
		// Under app_role without app.current_org_id pinned, the USING
		// predicate masks rows.
		var n int
		if err := appDB.QueryRowContext(ctx,
			`SELECT count(*) FROM policy_overrides WHERE policy_id = $1`, pid).Scan(&n); err != nil {
			t.Fatalf("unpinned count: %v", err)
		}
		if n != 0 {
			t.Errorf("RLS not enforced: an unpinned app-role read saw %d row(s), want 0", n)
		}
	})

	t.Run("a read pinned to the owning org sees the row", func(t *testing.T) {
		// The other direction. Without this, the assertion above would be
		// satisfied just as well by a policy that hides EVERYTHING from the
		// app role, which is not isolation - it is a broken grant.
		err := WithOrgScope(ctx, appDB, overrideTestOrg, func(tx *sql.Tx) error {
			var n int
			if err := tx.QueryRowContext(ctx,
				`SELECT count(*) FROM policy_overrides WHERE policy_id = $1`, pid).Scan(&n); err != nil {
				return err
			}
			if n != 1 {
				t.Errorf("a read pinned to %q saw %d row(s), want 1", overrideTestOrg, n)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scoped read: %v", err)
		}
	})

	t.Run("a read pinned to a different org sees nothing", func(t *testing.T) {
		err := WithOrgScope(ctx, appDB, overrideTestOrgB, func(tx *sql.Tx) error {
			var n int
			if err := tx.QueryRowContext(ctx,
				`SELECT count(*) FROM policy_overrides WHERE policy_id = $1`, pid).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				t.Errorf("a read pinned to %q saw %d of another org's row(s), want 0", overrideTestOrgB, n)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("cross-org scoped read: %v", err)
		}
	})

	t.Run("an INSERT whose org_id contradicts the pinned scope is rejected by WITH CHECK", func(t *testing.T) {
		pidX := seedSystemPolicy(t, owner, "sys_rls_withcheck")
		err := WithOrgScope(ctx, appDB, overrideTestOrg, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO policy_overrides
					(policy_id, policy_type, tenant_id, org_id, override_reason, created_by, updated_by)
				VALUES ($1, 'static', $2, $3, 'smuggled', 'mallory', 'mallory')
			`, pidX, overrideTestTenantB, overrideTestOrgB)
			return exErr
		})
		if err == nil {
			t.Fatal("WITH CHECK did not reject an INSERT for a different org than the pinned scope")
		}

		// And nothing was written.
		var n int
		if qErr := owner.QueryRow(`SELECT count(*) FROM policy_overrides WHERE policy_id = $1`, pidX).Scan(&n); qErr != nil {
			t.Fatalf("count after rejected INSERT: %v", qErr)
		}
		if n != 0 {
			t.Errorf("the rejected INSERT persisted %d row(s), want 0", n)
		}
	})
}
