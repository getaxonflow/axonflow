// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// Regression test for the SECOND half of #3367, which is invisible on a local
// developer stack.
//
// The visible defect was the SQL predicate: the portal's org-shaped
// X-Tenant-ID was ANDed against execution_history.tenant_id, which holds the
// EXECUTING CREDENTIAL's id. Dropping that predicate is enough to fix a stack
// whose pool is BYPASSRLS (docker compose runs as the superuser owner and mig
// 042 is ENABLE, not FORCE, row level security) - and it is NOT enough in
// production, because mig 042's USING predicate is
//
//	tenant_id IS NULL OR tenant_id = current_setting('app.current_tenant_id')
//
// and the only tenant value an org-bound caller has is the org id. Under
// axonflow_app_role the old dual-key wrap would therefore re-apply, in RLS,
// exactly the narrowing the handler had just dropped, and the tile would keep
// rendering 0 while every local test and every live check on a dev stack said
// the bug was fixed.
//
// So this test asserts the org-wide read on the REAL app-role connection, with
// identities that actually differ, and carries the pre-fix shape alongside it
// as a control.
//
// Gating: TEST_PG_INTEGRATION=1 + docker (see approletest.SkipUnlessEnabled).

import (
	"context"
	"testing"
	"time"

	"axonflow/platform/shared/execution"
)

func TestExecutionOrgWideListUnderAppRole_3367(t *testing.T) {
	f := setup3039Fixture(t)

	const org = "rls3367-exec-org"
	// The Basic-auth username the agent derives the scope from. It is NOT the
	// org, and that is the entire point: a fixture where org == tenant ==
	// client id is blind to this bug by construction.
	const runnerA = "rls3367-runner-app"
	const runnerB = "rls3367-second-app"
	const otherOrg = "rls3367-other-org"
	const otherRunner = "rls3367-other-runner"

	f.seedOrg(t, org)
	f.seedOrg(t, otherOrg)

	repo := execution.NewPostgresRepository(f.appRoleDB)
	repo.SetCrossOrgDB(f.adminDB)
	ctx := context.Background()
	now := time.Now().UTC()

	seed := func(id, tenant, execOrg string) {
		t.Helper()
		if err := repo.Create(ctx, &execution.ExecutionStatus{
			ExecutionID:   id,
			ExecutionType: execution.ExecutionTypeWCP,
			Name:          id + " workflow",
			Source:        "test",
			TenantID:      tenant,
			OrgID:         execOrg,
			Status:        execution.StatusRunning,
			TotalSteps:    1,
			StartedAt:     now,
			Steps:         []execution.StepStatus{},
			CreatedAt:     now,
			UpdatedAt:     now,
		}); err != nil {
			t.Fatalf("Create %s under app_role: %v", id, err)
		}
	}

	seed("wf_rls3367_a", runnerA, org)
	seed("wf_rls3367_b", runnerB, org)
	seed("wf_rls3367_other", otherRunner, otherOrg)

	// Vacuity control. If the fixture is not actually enforcing RLS against
	// this connection then every assertion below passes for the wrong reason,
	// and the production-only half of the bug goes unguarded again.
	if n := f.bareCount(t, "execution_history", "org_id = $1", org); n != 0 {
		t.Fatalf("fixture not faithful: bare app_role read sees %d execution_history rows (RLS not enforced)", n)
	}

	t.Run("pre_fix_shape_still_reads_zero", func(t *testing.T) {
		// This is the exact call the portal used to make: tenant = the org's
		// display default, org = the org. It matches nothing, and it must keep
		// matching nothing - the fix is not "the tenant filter stopped
		// working", it is "an org-bound caller stopped sending one".
		rows, total, err := repo.List(ctx, execution.ListExecutionsRequest{
			TenantID: org, OrgID: org, Limit: 10,
		})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if total != 0 || len(rows) != 0 {
			t.Fatalf("pre-fix shape returned %d rows / total %d, want 0/0; the control no longer models the bug", len(rows), total)
		}
	})

	t.Run("org_wide_read_returns_every_credentials_rows", func(t *testing.T) {
		rows, total, err := repo.List(ctx, execution.ListExecutionsRequest{OrgID: org, OrgWide: true, Limit: 10})
		if err != nil {
			t.Fatalf("List org-wide: %v", err)
		}
		if total != 2 || len(rows) != 2 {
			t.Fatalf("org-wide List = %d rows / total %d, want 2/2 - the 'Workflows Run' tile renders this number (#3367)", len(rows), total)
		}
		seen := map[string]bool{}
		for _, r := range rows {
			seen[r.TenantID] = true
		}
		if !seen[runnerA] || !seen[runnerB] {
			t.Fatalf("org-wide List returned tenants %v, want both %q and %q", seen, runnerA, runnerB)
		}
	})

	t.Run("org_wide_read_does_not_cross_orgs", func(t *testing.T) {
		// The org predicate is the entire tenancy boundary on this path, and
		// the path runs on a BYPASSRLS pool, so this is the assertion that the
		// SQL layer is really carrying the isolation RLS used to.
		rows, total, err := repo.List(ctx, execution.ListExecutionsRequest{OrgID: org, OrgWide: true, Limit: 100})
		if err != nil {
			t.Fatalf("List org-wide: %v", err)
		}
		for _, r := range rows {
			if r.OrgID != org {
				t.Fatalf("org-wide List leaked a row from org %q", r.OrgID)
			}
		}
		if total != 2 {
			t.Fatalf("org-wide total = %d, want 2 (a leak would inflate this)", total)
		}

		otherRows, otherTotal, err := repo.List(ctx, execution.ListExecutionsRequest{OrgID: otherOrg, OrgWide: true, Limit: 100})
		if err != nil {
			t.Fatalf("List other org: %v", err)
		}
		if otherTotal != 1 || len(otherRows) != 1 || otherRows[0].OrgID != otherOrg {
			t.Fatalf("other org read = %d rows / total %d, want exactly its own 1", len(otherRows), otherTotal)
		}
	})

	t.Run("credential_scoped_read_is_unchanged", func(t *testing.T) {
		// The agent path: tenant AND org, dual-key RLS wrap, one credential's
		// rows. #3367 must not have widened this.
		rows, total, err := repo.List(ctx, execution.ListExecutionsRequest{
			TenantID: runnerA, OrgID: org, Limit: 10,
		})
		if err != nil {
			t.Fatalf("List credential-scoped: %v", err)
		}
		if total != 1 || len(rows) != 1 || rows[0].TenantID != runnerA {
			t.Fatalf("credential-scoped List = %d rows / total %d (tenants may have widened)", len(rows), total)
		}
	})

	t.Run("org_only_filter_WITHOUT_the_authority_flag_keeps_the_rls_wrap", func(t *testing.T) {
		// R3 round 1. "Org set, tenant empty" is a shape any caller can produce
		// by omitting a header; it must NOT reach the BYPASSRLS pool. Under
		// app_role the old dual-key wrap pins app.current_tenant_id to the org,
		// which matches no credential row - so zero is the CORRECT answer here,
		// and getting rows back would mean the BYPASSRLS read had become
		// reachable without the caller's authority.
		rows, total, err := repo.List(ctx, execution.ListExecutionsRequest{OrgID: org, Limit: 10})
		if err != nil {
			t.Fatalf("List org-only without the flag: %v", err)
		}
		if total != 0 || len(rows) != 0 {
			t.Fatalf("org-only filter returned %d rows / total %d WITHOUT OrgWide; the BYPASSRLS read is "+
				"reachable by omitting X-Tenant-ID (guard-by-shape)", len(rows), total)
		}
	})

	t.Run("org_wide_and_tenant_scoped_at_once_is_refused", func(t *testing.T) {
		// Honouring one of the two silently would make the result depend on
		// which, and the caller could not tell which it got.
		if _, _, err := repo.List(ctx, execution.ListExecutionsRequest{
			OrgID: org, TenantID: runnerA, OrgWide: true, Limit: 10,
		}); err == nil {
			t.Fatal("List accepted a contradictory org-wide + tenant-scoped request")
		}
	})

	t.Run("org_wide_read_refuses_a_blank_org", func(t *testing.T) {
		// A BYPASSRLS pool means the SQL layer owns tenancy, so the org key is
		// VALIDATED rather than merely appended when non-empty. #3065's
		// fail-open was precisely a conditional org predicate.
		if _, _, err := repo.List(ctx, execution.ListExecutionsRequest{OrgID: "   ", OrgWide: true, Limit: 10}); err == nil {
			t.Fatal("org-wide List accepted a whitespace-only org; a blank tenancy key must fail closed, not list the deployment")
		}
	})
}
