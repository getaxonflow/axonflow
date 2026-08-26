// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3048 R3 BLOCKER-1 unit tests: 'global'-wildcard baseline rows are
// READ-visible to every org (the GetByID exemption) but WRITABLE by none of
// them. Without the write guards, a tenant caller's Delete/Toggle/Update ran
// under WithOrgScope("global") — RLS passed and the shared baseline
// (drop_table_prevention, int_* policies, eu_ai_act_* templates) was mutable
// deployment-wide by any org admin.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// expectGlobalRowGetByID registers the scoped GetByID shape resolving a
// tier='tenant' row carrying the 'global' wildcard (the mig-010 seed shape:
// demoted to tier='tenant' by mig 031, org_id='global' via mig 153/154).
func expectGlobalRowGetByID(mock sqlmock.Sqlmock, callerOrg, policyID string, enabled bool) {
	cols := []string{
		"id", "policy_id", "name", "category", "tier", "pattern",
		"severity", "description", "action", "priority", "enabled",
		"tenant_id", "org_id", "tags", "metadata",
		"version", "created_at", "updated_at", "created_by", "updated_by", "deleted_at",
	}
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs(callerOrg).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT.*FROM static_policies WHERE`).
		WithArgs(policyID).
		WillReturnRows(sqlmock.NewRows(cols).AddRow(
			"uuid-"+policyID, policyID, "DROP TABLE Prevention", "dangerous_queries", "tenant", `drop\s+table`,
			"critical", "baseline", "block", 100, enabled,
			"global", "global", "[]", "{}",
			1, time.Now(), time.Now(), "system", "system", nil,
		))
	mock.ExpectCommit()
}

func TestGlobalBaselineRow_WritesRejected(t *testing.T) {
	callerCtx := context.WithValue(context.Background(), ContextKeyOrgID, "tenant-a")

	t.Run("Delete rejected", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		defer db.Close()
		// GetByID resolves the global row in the caller-org scope (owner-pool
		// shape) — then the guard must fire with NO write expectations.
		expectGlobalRowGetByID(mock, "tenant-a", "drop_table_prevention", true)

		repo := NewStaticPolicyRepository(db)
		err = repo.Delete(callerCtx, "drop_table_prevention", "attacker@tenant-a.example")
		if !errors.Is(err, ErrSystemPolicyDeletion) {
			t.Fatalf("SECURITY: tenant caller deleted a 'global' baseline row (err=%v) — deployment-wide protection removable by one org (#3048 R3 BLOCKER-1)", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("no write may have run: %v", err)
		}
	})

	t.Run("ToggleEnabled rejected both directions", func(t *testing.T) {
		for _, enable := range []bool{false, true} {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			expectGlobalRowGetByID(mock, "tenant-a", "drop_table_prevention", !enable)

			repo := NewStaticPolicyRepository(db)
			err = repo.ToggleEnabled(callerCtx, "drop_table_prevention", enable, "attacker@tenant-a.example")
			if !errors.Is(err, ErrSystemPolicyModification) {
				t.Fatalf("SECURITY: tenant caller toggled a 'global' baseline row to enabled=%v (err=%v)", enable, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("no write may have run (enable=%v): %v", enable, err)
			}
			_ = db.Close()
		}
	})

	t.Run("Update rejected", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		defer db.Close()
		expectGlobalRowGetByID(mock, "tenant-a", "drop_table_prevention", true)

		repo := NewStaticPolicyRepository(db)
		newPattern := "never_matches_anything"
		_, err = repo.Update(callerCtx, "drop_table_prevention",
			&UpdateStaticPolicyRequest{Pattern: &newPattern}, "attacker@tenant-a.example")
		if !errors.Is(err, ErrSystemPolicyModification) {
			t.Fatalf("SECURITY: tenant caller rewrote a 'global' baseline row's pattern (err=%v)", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("no write may have run: %v", err)
		}
	})

	t.Run("read stays visible (the exemption is read-only)", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		defer db.Close()
		expectGlobalRowGetByID(mock, "tenant-a", "drop_table_prevention", true)

		repo := NewStaticPolicyRepository(db)
		got, err := repo.GetByID(callerCtx, "drop_table_prevention")
		if err != nil {
			t.Fatalf("GetByID must still resolve the shared baseline for reads: %v", err)
		}
		if got.PolicyID != "drop_table_prevention" {
			t.Fatalf("wrong row: %s", got.PolicyID)
		}
	})
}

// TestGetVersions_OrgTierParentLeg (#3048 R3 MEDIUM-5): the parent-ownership
// predicate must admit ORGANIZATION-tier parents owned by the caller's org —
// the earlier predicate (`tier='system' OR tenant_id=$2`) dropped them, so an
// org admin could not read version history for their own org-tier policies.
//
// Decision 5 (#3490) satisfies the same requirement with ONE org leg instead
// of two: `tier='system' OR org_id=$2`. The org-tier leg it replaces keyed on
// the LEGACY organization_id column, which no shipped migration ever writes
// (0 of 101 rows, #3334), so the leg this test was written to pin could only
// ever have matched a row created through the Go create path. The assertion
// is now that the caller's ORG admits the parent - the property the test was
// really after - and it still fails if the non-system leg is dropped
// entirely.
func TestGetVersions_OrgTierParentLeg(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`SELECT license_tier FROM clients`).
		WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Enterprise"))

	// The version query MUST carry the org leg and bind the caller org as
	// $2 - the regexp fails the match if the leg is dropped, and the WithArgs
	// list fails if the caller TENANT is bound anywhere (it is no longer an
	// argument at all).
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`sp\.tier = 'system' OR sp\.org_id = \$2`).
		WithArgs("policy-org-tier", "org-1", 1000).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "policy_id", "version", "snapshot", "change_type",
			"change_summary", "changed_by", "changed_at",
		}).AddRow("v1", "policy-org-tier", 1, []byte(`{}`), "create", "created", "admin", time.Now()))
	mock.ExpectCommit()

	repo := NewStaticPolicyRepository(db)
	ctx := context.WithValue(context.Background(), ContextKeyOrgID, "org-1")
	versions, err := repo.GetVersions(ctx, "policy-org-tier", "tenant-1")
	if err != nil {
		t.Fatalf("GetVersions: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("expected the org-tier parent's version row, got %d", len(versions))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("org-tier leg missing from the parent predicate: %v", err)
	}
}
