// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"axonflow/platform/agent/approletest"
)

// TestCallerOrgOwnsStaticPolicy covers the pure decision logic of the
// tenant-isolation guard added for #2774: a static write is allowed only when
// the target policy's org matches the authenticated caller's org, with a
// deliberate fail-open on an unknown caller org or a policy that predates the
// org column (mirrors the WithOrgScope skip).
func TestCallerOrgOwnsStaticPolicy(t *testing.T) {
	cases := []struct {
		name      string
		callerOrg string
		policyOrg string
		want      bool
	}{
		{"same org → allow", "org-a", "org-a", true},
		{"different org → deny", "org-a", "org-b", false},
		{"unknown caller org → allow (single-tenant/community)", "", "org-b", true},
		{"policy predates org column → allow", "org-a", "", true},
		{"both empty → allow", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), ContextKeyOrgID, tc.callerOrg)
			got := callerOrgOwnsStaticPolicy(ctx, &StaticPolicy{OrgID: tc.policyOrg})
			if got != tc.want {
				t.Fatalf("callerOrgOwnsStaticPolicy(caller=%q, policy=%q) = %v, want %v",
					tc.callerOrg, tc.policyOrg, got, tc.want)
			}
		})
	}
}

// TestStaticPolicyWrite_TenantIsolation_RealPostgres proves the GetByID
// tenant-isolation guard end to end against a REAL Postgres on the superuser
// (BYPASSRLS) connection — the exact owner-connection scenario
// (AXONFLOW_DB_USE_APP_ROLE=false) where table RLS does NOT isolate rows. Without
// the guard, org A could read AND update/delete/toggle org B's static policy
// (confirmed live before the fix, #2774). With it: a cross-org READ (GetByID) and
// every cross-org WRITE return ErrPolicyNotFound; same-org access still succeeds;
// and the shared system-tier baseline stays readable across orgs.
func TestStaticPolicyWrite_TenantIsolation_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	db, err := sql.Open("postgres", env.MasterDSN) // superuser → BYPASSRLS
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	defer func() { _ = db.Close() }()

	repo := NewStaticPolicyRepository(db)

	const orgA, orgB = "org-a", "org-b"
	seed := func(id, policyID, org, tier string) {
		t.Helper()
		// #3334 / core/166: the legacy `organization_id` column is dropped. This
		// seed carried it as a literal NULL, so it never contributed a scope key
		// -- org scoping here has always come from org_id ($4). Naming a dropped
		// column in the column list is a hard INSERT error, so it is removed
		// rather than left NULL.
		_, err := db.Exec(`
			INSERT INTO static_policies
			  (id, policy_id, name, category, pattern, severity, description, action,
			   tier, priority, enabled, tenant_id, org_id,
			   version, created_at, updated_at, created_by, updated_by)
			VALUES ($1,$2,$3,'pii-global','X-[0-9]+','high','', 'block',
			        $5, 50, true, $4, $4,
			        1, now(), now(), $4, $4)`,
			id, policyID, "pol-"+org, org, tier)
		if err != nil {
			t.Fatalf("seed %s: %v", org, err)
		}
	}
	// Deterministic UUIDs so the test is self-contained.
	const idA = "11111111-1111-1111-1111-111111111111"
	const idB = "22222222-2222-2222-2222-222222222222"
	const idSys = "33333333-3333-3333-3333-333333333333"
	seed(idA, "pol_a", orgA, "tenant")
	seed(idB, "pol_b", orgB, "tenant")
	seed(idSys, "pol_sys", "org-system", "system") // shared baseline, org != caller

	ctxA := context.WithValue(context.Background(), ContextKeyOrgID, orgA)

	// --- Cross-org READ (GetByID) of B's tenant policy must be not-found ---
	if _, err := repo.GetByID(ctxA, idB); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("cross-org GetByID: err = %v, want ErrPolicyNotFound", err)
	}
	// A can read its OWN policy.
	if _, err := repo.GetByID(ctxA, idA); err != nil {
		t.Fatalf("same-org GetByID should succeed: %v", err)
	}
	// A can read a SYSTEM-tier policy even though its org differs (shared baseline).
	if _, err := repo.GetByID(ctxA, idSys); err != nil {
		t.Fatalf("system-tier GetByID must be readable cross-org: %v", err)
	}

	// --- Cross-org writes by A against B's policy must all be rejected ---
	newDesc := "HACKED BY A"
	if _, err := repo.Update(ctxA, idB, &UpdateStaticPolicyRequest{Description: &newDesc}, orgA); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("cross-org Update: err = %v, want ErrPolicyNotFound", err)
	}
	if err := repo.ToggleEnabled(ctxA, idB, false, orgA); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("cross-org ToggleEnabled: err = %v, want ErrPolicyNotFound", err)
	}
	if err := repo.Delete(ctxA, idB, orgA); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("cross-org Delete: err = %v, want ErrPolicyNotFound", err)
	}

	// B's policy must be untouched: still enabled, not soft-deleted, original desc.
	var enabled bool
	var deletedAt sql.NullTime
	var desc sql.NullString
	if err := db.QueryRow(`SELECT enabled, deleted_at, description FROM static_policies WHERE id=$1`, idB).
		Scan(&enabled, &deletedAt, &desc); err != nil {
		t.Fatalf("read B after attack: %v", err)
	}
	if !enabled || deletedAt.Valid || desc.String == newDesc {
		t.Fatalf("B's policy was mutated cross-tenant: enabled=%v deleted=%v desc=%q", enabled, deletedAt.Valid, desc.String)
	}

	// --- A can still fully manage its OWN policy (guard is not over-blocking) ---
	ownDesc := "legit update by A"
	if _, err := repo.Update(ctxA, idA, &UpdateStaticPolicyRequest{Description: &ownDesc}, orgA); err != nil {
		t.Fatalf("same-org Update should succeed: %v", err)
	}
	if err := repo.ToggleEnabled(ctxA, idA, false, orgA); err != nil {
		t.Fatalf("same-org ToggleEnabled should succeed: %v", err)
	}
	if err := repo.Delete(ctxA, idA, orgA); err != nil {
		t.Fatalf("same-org Delete should succeed: %v", err)
	}
	// Confirm the own-policy soft delete landed.
	if err := db.QueryRow(`SELECT deleted_at FROM static_policies WHERE id=$1`, idA).Scan(&deletedAt); err != nil {
		t.Fatalf("read A after own delete: %v", err)
	}
	if !deletedAt.Valid {
		t.Fatalf("A's own policy was not soft-deleted")
	}
}
