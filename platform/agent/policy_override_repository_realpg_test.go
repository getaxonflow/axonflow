// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres tests for PolicyOverrideRepository (#3334).
//
// WHY THIS FILE EXISTS
//
// platform/agent/policy_override_repository_test.go is 693 lines and entirely
// sqlmock. sqlmock matches SQL text against regexes and returns canned rows;
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
//  3. ROW-LEVEL SECURITY. Nothing in the sqlmock suite touches it, yet
//     policy_override_repository.go:116-155 documents behaviour that only RLS
//     produces - "under app_role without app.current_org_id pinned, the USING
//     predicate masks rows" - and that documented behaviour is what makes
//     Create wrap its existence check and its INSERT in ONE WithOrgScope txn.
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
// The one case that is NOT expressible on both sides is CREATING an org-scoped
// override through Create(): before the retirement Create writes the org key
// into organization_id (from the field that is about to be deleted), after it
// into org_id. Org-scoped rows are seeded directly instead, and org-scope
// coverage here is therefore about SELECTION and ISOLATION, not about the
// create path. See TestOverrideOrgScopeSelection_RealPG.
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
	// The seeded Enterprise client. Create() gates on an Enterprise licence
	// and resolves the licence key from TenantID, so every tenant used by a
	// Create() test needs a row in clients.
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
		CREATE TABLE clients (
			tenant_id    varchar(255) PRIMARY KEY,
			license_tier varchar(50),
			enabled      boolean NOT NULL DEFAULT true
		);
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

	pc.RunMigration(t, `
		INSERT INTO clients (tenant_id, license_tier, enabled) VALUES
			('`+overrideTestTenant+`',  'Enterprise', true),
			('`+overrideTestTenantB+`', 'Enterprise', true),
			('`+overrideTestOrg+`',     'Enterprise', true),
			('`+overrideTestOrgB+`',    'Enterprise', true),
			('community-tenant',        'Community',  true);
	`)

	return pc
}

// seedSystemPolicy inserts a tier='system' static policy (the only tier
// Create() will override) and returns its UUID, which is what
// policy_overrides.policy_id stores.
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

// seedTenantPolicy inserts a tier='tenant' policy, which Create() must refuse.
func seedTenantPolicy(t *testing.T, db *sql.DB, policyID string) string {
	t.Helper()
	var id string
	err := db.QueryRow(`
		INSERT INTO static_policies
			(policy_id, name, category, pattern, severity, action, tier, priority, enabled, tenant_id, org_id, version)
		VALUES ($1, $1, 'pii-global', 'ssn', 'high', 'block', 'tenant', 50, true, $2, $3, 1)
		RETURNING id::text
	`, policyID, overrideTestTenant, overrideTestOrg).Scan(&id)
	if err != nil {
		t.Fatalf("seed tenant policy %q: %v", policyID, err)
	}
	return id
}

// seedOrgScopedOverride inserts an ORG-scoped override row directly.
//
// Raw SQL rather than Create() on purpose: it writes BOTH organization_id and
// org_id to the same value, so the row satisfies the org-scoped predicate
// whether the repository filters on the legacy column or on org_id. See the
// file header. Create() cannot do this without touching the struct field that
// the #3334 retirement removes.
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

// orgCtx returns a context carrying an authenticated caller org.
//
// This is not boilerplate. GetByID refuses outright when the context carries
// no caller org - see policy_override_repository.go:336-353 (#3065 F7): an
// unknown caller org "is now a denial before any SQL runs", because on a
// legacy owner-pool deployment a bare by-id read bypasses RLS and would
// resolve ANY org's row, and Delete() then wraps its DELETE in
// WithOrgScope(existing.OrgID) - the victim's org. Tests that used a bare
// context.Background() got ErrOverrideNotFound from a row that was demonstrably
// present, which is the guard working, not a fixture bug.
func orgCtx(org string) context.Context {
	return context.WithValue(context.Background(), ContextKeyOrgID, org)
}

// newTenantOverride builds a tenant-scoped override. It deliberately sets only
// TenantID and OrgID - never OrganizationID, which #3334 removes.
func newTenantOverride(policyUUID, tenant, org string) *PolicyOverride {
	action := OverrideAction("warn")
	return &PolicyOverride{
		PolicyID:       policyUUID,
		TenantID:       strptr(tenant),
		OrgID:          org,
		ActionOverride: &action,
		OverrideReason: "approved by compliance, ticket AX-1",
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Create
// ────────────────────────────────────────────────────────────────────────────

// TestCreateOverride_RealPG covers the create path against a real database.
// The duplicate case is the one sqlmock cannot express honestly: it depends on
// overrideExistsTx running the real SELECT inside the same WithOrgScope txn as
// the INSERT.
func TestCreateOverride_RealPG(t *testing.T) {
	pc := newOverrideTestDB(t)
	db := pc.DB
	ctx := orgCtx(overrideTestOrg)
	repo := NewPolicyOverrideRepository(db)

	t.Run("tenant-scoped create persists a real row", func(t *testing.T) {
		pid := seedSystemPolicy(t, db, "sys_create_ok")
		ov := newTenantOverride(pid, overrideTestTenant, overrideTestOrg)

		if err := repo.Create(ctx, ov, "alice"); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if ov.ID == "" {
			t.Fatal("Create did not populate the override ID")
		}

		// Read it back through the repository, not through a hand-written
		// SELECT: a canned-row double would pass either way, a real row is
		// what makes this meaningful.
		got, err := repo.GetByID(ctx, ov.ID)
		if err != nil {
			t.Fatalf("GetByID after Create: %v", err)
		}
		if got.OverrideReason != ov.OverrideReason {
			t.Errorf("override_reason: got %q want %q", got.OverrideReason, ov.OverrideReason)
		}
		if got.OrgID != overrideTestOrg {
			t.Errorf("org_id: got %q want %q", got.OrgID, overrideTestOrg)
		}
		if got.TenantID == nil || *got.TenantID != overrideTestTenant {
			t.Errorf("tenant_id: got %v want %q", got.TenantID, overrideTestTenant)
		}
	})

	t.Run("empty OrgID is rejected before any write", func(t *testing.T) {
		// This is the scope invariant that SURVIVES #3334. The database-level
		// valid_override_scope CHECK is dropped along with the column it
		// referenced (migrations/core/166 asserts its absence), so this
		// application-level guard becomes the only thing preventing an
		// unscoped override row. Worth its own assertion for that reason.
		pid := seedSystemPolicy(t, db, "sys_create_no_org")
		ov := newTenantOverride(pid, overrideTestTenant, "")

		err := repo.Create(ctx, ov, "alice")
		if err == nil {
			t.Fatal("Create with empty OrgID succeeded; want an error")
		}

		var n int
		if qErr := db.QueryRow(`SELECT count(*) FROM policy_overrides WHERE policy_id = $1`, pid).Scan(&n); qErr != nil {
			t.Fatalf("count after rejected Create: %v", qErr)
		}
		if n != 0 {
			t.Errorf("a rejected Create left %d row(s) behind; want 0", n)
		}
	})

	t.Run("duplicate for the same scope tuple is rejected", func(t *testing.T) {
		pid := seedSystemPolicy(t, db, "sys_create_dup")

		if err := repo.Create(ctx, newTenantOverride(pid, overrideTestTenant, overrideTestOrg), "alice"); err != nil {
			t.Fatalf("first Create: %v", err)
		}
		err := repo.Create(ctx, newTenantOverride(pid, overrideTestTenant, overrideTestOrg), "alice")
		if err == nil {
			t.Fatal("duplicate Create succeeded; want ErrOverrideAlreadyExists")
		}

		// The count is the real assertion. #2384's R3 round 2 recorded that a
		// duplicate check run OUTSIDE the WithOrgScope txn returns false even
		// when a duplicate exists, persisting two rows. A canned-row double
		// cannot tell those apart; a COUNT can.
		var n int
		if qErr := db.QueryRow(`SELECT count(*) FROM policy_overrides WHERE policy_id = $1`, pid).Scan(&n); qErr != nil {
			t.Fatalf("count after duplicate Create: %v", qErr)
		}
		if n != 1 {
			t.Errorf("duplicate Create left %d rows; want exactly 1", n)
		}
	})

	t.Run("a non-system policy cannot be overridden", func(t *testing.T) {
		pid := seedTenantPolicy(t, db, "tenant_tier_policy")
		err := repo.Create(ctx, newTenantOverride(pid, overrideTestTenant, overrideTestOrg), "alice")
		if err != ErrOnlySystemPoliciesOverridable {
			t.Errorf("got %v, want ErrOnlySystemPoliciesOverridable", err)
		}
	})

	t.Run("a reason is mandatory", func(t *testing.T) {
		pid := seedSystemPolicy(t, db, "sys_create_no_reason")
		ov := newTenantOverride(pid, overrideTestTenant, overrideTestOrg)
		ov.OverrideReason = ""
		if err := repo.Create(ctx, ov, "alice"); err != ErrOverrideReasonRequired {
			t.Errorf("got %v, want ErrOverrideReasonRequired", err)
		}
	})

	t.Run("GetByID refuses when the context carries no caller org", func(t *testing.T) {
		// The #3065 F7 denial, which the sqlmock suite cannot reach: it is a
		// return before any SQL runs, so a canned-row double never exercises
		// it. Proven against a row that demonstrably EXISTS - otherwise this
		// assertion would be satisfied by the row simply being absent.
		pid := seedSystemPolicy(t, db, "sys_no_caller_org")
		ov := newTenantOverride(pid, overrideTestTenant, overrideTestOrg)
		if err := repo.Create(ctx, ov, "alice"); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := repo.GetByID(orgCtx(overrideTestOrg), ov.ID); err != nil {
			t.Fatalf("precondition: the row must be readable WITH a caller org: %v", err)
		}

		if _, err := repo.GetByID(context.Background(), ov.ID); err != ErrOverrideNotFound {
			t.Errorf("GetByID with no caller org returned %v; want ErrOverrideNotFound", err)
		}
		// And a caller from a different org must not see it either.
		if _, err := repo.GetByID(orgCtx(overrideTestOrgB), ov.ID); err != ErrOverrideNotFound {
			t.Errorf("GetByID from a foreign org returned %v; want ErrOverrideNotFound", err)
		}
	})

	t.Run("a Community tenant cannot create an override", func(t *testing.T) {
		// Resolved from the real clients row, not a canned licence answer.
		pid := seedSystemPolicy(t, db, "sys_create_community")
		ov := newTenantOverride(pid, "community-tenant", overrideTestOrg)
		if err := repo.Create(ctx, ov, "alice"); err != ErrOverrideRequiresEnterprise {
			t.Errorf("got %v, want ErrOverrideRequiresEnterprise", err)
		}
	})
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
	if err := repo.Create(ctx, newTenantOverride(pid, overrideTestTenant, overrideTestOrg), "alice"); err != nil {
		t.Fatalf("seed override: %v", err)
	}

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
	if err := repo.Create(ctx, newTenantOverride(pidA, overrideTestTenant, overrideTestOrg), "alice"); err != nil {
		t.Fatalf("seed A: %v", err)
	}
	if err := repo.Create(ctx, newTenantOverride(pidB, overrideTestTenantB, overrideTestOrgB), "bob"); err != nil {
		t.Fatalf("seed B: %v", err)
	}

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
		pidExp := seedSystemPolicy(t, db, "sys_list_expired")
		ov := newTenantOverride(pidExp, overrideTestTenant, overrideTestOrg)
		past := time.Now().UTC().Add(-1 * time.Hour)
		ov.ExpiresAt = &past
		if err := repo.Create(ctx, ov, "alice"); err != nil {
			t.Fatalf("seed expired: %v", err)
		}

		active, err := repo.ListOverridesForTenant(ctx, overrideTestTenant, nil, false)
		if err != nil {
			t.Fatalf("list active: %v", err)
		}
		for _, o := range active {
			if o.ID == ov.ID {
				t.Error("an expired override was returned with includeExpired=false")
			}
		}

		all, err := repo.ListOverridesForTenant(ctx, overrideTestTenant, nil, true)
		if err != nil {
			t.Fatalf("list all: %v", err)
		}
		var seen bool
		for _, o := range all {
			if o.ID == ov.ID {
				seen = true
			}
		}
		if !seen {
			t.Error("the expired override was missing with includeExpired=true")
		}
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Delete paths
// ────────────────────────────────────────────────────────────────────────────

func TestDeleteOverrideAndGetByID_RealPG(t *testing.T) {
	pc := newOverrideTestDB(t)
	db := pc.DB
	ctx := orgCtx(overrideTestOrg)
	repo := NewPolicyOverrideRepository(db)

	pid := seedSystemPolicy(t, db, "sys_delete_roundtrip")
	ov := newTenantOverride(pid, overrideTestTenant, overrideTestOrg)
	if err := repo.Create(ctx, ov, "alice"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := repo.GetByID(ctx, ov.ID); err != nil {
		t.Fatalf("GetByID before Delete: %v", err)
	}
	if err := repo.Delete(ctx, ov.ID, "alice"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// The row is really gone, not merely reported as gone.
	if _, err := repo.GetByID(ctx, ov.ID); err != ErrOverrideNotFound {
		t.Errorf("GetByID after Delete returned %v; want ErrOverrideNotFound", err)
	}
}

// TestDeleteByPolicyID_RealPG proves the delete predicate is scoped: deleting
// in one tenant leaves the other tenant's row intact. Under sqlmock this is a
// canned RowsAffected value and a repository that deleted everything would
// still pass.
func TestDeleteByPolicyID_RealPG(t *testing.T) {
	pc := newOverrideTestDB(t)
	db := pc.DB
	ctx := orgCtx(overrideTestOrg)
	repo := NewPolicyOverrideRepository(db)

	pid := seedSystemPolicy(t, db, "sys_delete_scoped")
	if err := repo.Create(ctx, newTenantOverride(pid, overrideTestTenant, overrideTestOrg), "alice"); err != nil {
		t.Fatalf("seed A: %v", err)
	}
	if err := repo.Create(ctx, newTenantOverride(pid, overrideTestTenantB, overrideTestOrgB), "bob"); err != nil {
		t.Fatalf("seed B: %v", err)
	}

	if err := repo.DeleteByPolicyID(ctx, overrideTestOrg, pid, strptr(overrideTestTenant), nil, "alice"); err != nil {
		t.Fatalf("DeleteByPolicyID: %v", err)
	}

	var remaining int
	if err := db.QueryRow(
		`SELECT count(*) FROM policy_overrides WHERE policy_id = $1 AND tenant_id = $2`,
		pid, overrideTestTenantB,
	).Scan(&remaining); err != nil {
		t.Fatalf("count survivor: %v", err)
	}
	if remaining != 1 {
		t.Errorf("the other tenant's override was collateral damage: %d rows remain, want 1", remaining)
	}

	var deleted int
	if err := db.QueryRow(
		`SELECT count(*) FROM policy_overrides WHERE policy_id = $1 AND tenant_id = $2`,
		pid, overrideTestTenant,
	).Scan(&deleted); err != nil {
		t.Fatalf("count deleted: %v", err)
	}
	if deleted != 0 {
		t.Errorf("the targeted override survived: %d rows remain, want 0", deleted)
	}

	t.Run("nothing to delete reports ErrOverrideNotFound", func(t *testing.T) {
		err := repo.DeleteByPolicyID(ctx, overrideTestOrg, pid, strptr("no-such-tenant"), nil, "alice")
		if err != ErrOverrideNotFound {
			t.Errorf("got %v, want ErrOverrideNotFound", err)
		}
	})

	t.Run("an empty rlsOrgID is refused", func(t *testing.T) {
		if err := repo.DeleteByPolicyID(ctx, "", pid, strptr(overrideTestTenantB), nil, "alice"); err == nil {
			t.Error("DeleteByPolicyID accepted an empty rlsOrgID; want an error")
		}
	})
}

// TestCleanupExpiredOverrides_RealPG exercises the real NOW() boundary.
func TestCleanupExpiredOverrides_RealPG(t *testing.T) {
	pc := newOverrideTestDB(t)
	db := pc.DB
	ctx := orgCtx(overrideTestOrg)
	repo := NewPolicyOverrideRepository(db)

	pidExpired := seedSystemPolicy(t, db, "sys_cleanup_expired")
	pidFuture := seedSystemPolicy(t, db, "sys_cleanup_future")
	pidNever := seedSystemPolicy(t, db, "sys_cleanup_never")

	past := time.Now().UTC().Add(-2 * time.Hour)
	future := time.Now().UTC().Add(2 * time.Hour)

	expired := newTenantOverride(pidExpired, overrideTestTenant, overrideTestOrg)
	expired.ExpiresAt = &past
	if err := repo.Create(ctx, expired, "alice"); err != nil {
		t.Fatalf("seed expired: %v", err)
	}
	notYet := newTenantOverride(pidFuture, overrideTestTenant, overrideTestOrg)
	notYet.ExpiresAt = &future
	if err := repo.Create(ctx, notYet, "alice"); err != nil {
		t.Fatalf("seed future: %v", err)
	}
	if err := repo.Create(ctx, newTenantOverride(pidNever, overrideTestTenant, overrideTestOrg), "alice"); err != nil {
		t.Fatalf("seed never-expiring: %v", err)
	}

	n, err := repo.CleanupExpiredOverrides(ctx)
	if err != nil {
		t.Fatalf("CleanupExpiredOverrides: %v", err)
	}
	if n != 1 {
		t.Errorf("CleanupExpiredOverrides removed %d rows, want 1", n)
	}

	// Assert on the surviving set, not only the returned count: a count is
	// consistent with having deleted the wrong row.
	for _, tc := range []struct {
		name string
		pid  string
		want int
	}{
		{"expired row is gone", pidExpired, 0},
		{"not-yet-expired row is kept", pidFuture, 1},
		{"never-expiring row is kept", pidNever, 1},
	} {
		var got int
		if qErr := db.QueryRow(`SELECT count(*) FROM policy_overrides WHERE policy_id = $1`, tc.pid).Scan(&got); qErr != nil {
			t.Fatalf("%s: count: %v", tc.name, qErr)
		}
		if got != tc.want {
			t.Errorf("%s: %d rows, want %d", tc.name, got, tc.want)
		}
	}
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
		GRANT SELECT ON static_policies, clients TO axonflow_app_role_test;
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

// TestPolicyOverridesRLS_RealPG covers behaviour documented at
// policy_override_repository.go:116-155 that nothing currently tests.
func TestPolicyOverridesRLS_RealPG(t *testing.T) {
	pc := newOverrideTestDB(t)
	ctx := orgCtx(overrideTestOrg)
	owner := pc.DB
	repo := NewPolicyOverrideRepository(owner)

	pid := seedSystemPolicy(t, owner, "sys_rls")
	if err := repo.Create(ctx, newTenantOverride(pid, overrideTestTenant, overrideTestOrg), "alice"); err != nil {
		t.Fatalf("seed override: %v", err)
	}

	appDB := appRoleDB(t, pc)

	t.Run("an unpinned read is masked to zero rows, not leaked", func(t *testing.T) {
		// The exact behaviour the repository comment relies on: "under
		// app_role without app.current_org_id pinned, the USING predicate
		// masks rows". This is why Create must run its existence check inside
		// the same txn as its INSERT.
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
