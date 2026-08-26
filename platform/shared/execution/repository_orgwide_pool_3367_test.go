// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package execution

// #3367 R3 round 2: a fast, ungated guard on WHICH POOL an org-wide list runs
// on, and on the refusals that make that choice safe.
//
// The sibling guard (orchestrator/execution_org_wide_list_3367_approle_test.go)
// proves the same property against a real axonflow_app_role connection, but it
// is gated on TEST_PG_INTEGRATION=1 + docker. Round 2's point stands: the
// round-1 defect - selecting the BYPASSRLS pool from the FILTER SHAPE
// "org set, tenant empty", which any caller can produce by omitting a header -
// would have been caught only in that heavier lane. This file catches it in
// the default `go test ./...` one.
//
// It needs no database. Both pools are opened against unroutable DSNs whose
// HOST NAMES differ, so the connection error names the pool that was chosen.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

const (
	poolProbeMain   = "main-pool-probe.invalid"
	poolProbeLookup = "lookup-pool-probe.invalid"
)

// newPoolProbeRepo builds a repository whose two pools are distinguishable by
// the hostname that appears in their connection errors.
func newPoolProbeRepo(t *testing.T) *PostgresRepository {
	t.Helper()
	open := func(host string) *sql.DB {
		db, err := sql.Open("postgres", "postgres://probe:probe@"+host+":5432/probe?sslmode=disable&connect_timeout=1")
		if err != nil {
			t.Fatalf("open probe pool %s: %v", host, err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	r := NewPostgresRepository(open(poolProbeMain))
	r.SetCrossOrgDB(open(poolProbeLookup))
	return r
}

// poolUsedBy runs a List that is guaranteed to fail at connect time and reports
// which pool's hostname the error names.
func poolUsedBy(t *testing.T, r *PostgresRepository, req ListExecutionsRequest) string {
	t.Helper()
	_, _, err := r.List(context.Background(), req)
	if err == nil {
		t.Fatal("List against unroutable pools returned no error; the probe cannot report a pool")
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, poolProbeLookup):
		return "lookup"
	case strings.Contains(msg, poolProbeMain):
		return "main"
	default:
		t.Fatalf("List error names neither probe pool, so this test cannot discriminate: %v", err)
		return ""
	}
}

func TestOrgWideListRunsOnTheAdminPool_3367(t *testing.T) {
	r := newPoolProbeRepo(t)

	if got := poolUsedBy(t, r, ListExecutionsRequest{OrgID: "acme-org", OrgWide: true, Limit: 5}); got != "lookup" {
		t.Fatalf("org-wide list ran on the %s pool, want lookup (BYPASSRLS). On axonflow_app_role the "+
			"main pool is filtered by mig 042's tenant-keyed RLS and the read returns zero rows (#3367)", got)
	}
}

func TestOrgOnlyFilterWithoutAuthorityStaysOnTheMainPool_3367(t *testing.T) {
	r := newPoolProbeRepo(t)

	// THE round-1 regression. "Org set, tenant empty" is producible by simply
	// omitting X-Tenant-ID; the authority behind it is not. If the pool choice
	// is inferred from that shape, this reports "lookup" and a caller with no
	// org-wide authority has silently been handed a BYPASSRLS read.
	if got := poolUsedBy(t, r, ListExecutionsRequest{OrgID: "acme-org", Limit: 5}); got != "main" {
		t.Fatalf("an org-only FILTER with no OrgWide authority ran on the %s pool, want main. The "+
			"BYPASSRLS read must be gated on the caller's authority, never on the shape of the "+
			"headers it happened to send", got)
	}
}

func TestCredentialScopedListStaysOnTheMainPool_3367(t *testing.T) {
	r := newPoolProbeRepo(t)

	if got := poolUsedBy(t, r, ListExecutionsRequest{OrgID: "acme-org", TenantID: "payments-app", Limit: 5}); got != "main" {
		t.Fatalf("the agent path ran on the %s pool, want main (RLS-scoped, unchanged by #3367)", got)
	}
}

func TestOrgWideListRefusalsHappenBeforeAnyQuery_3367(t *testing.T) {
	r := newPoolProbeRepo(t)

	cases := []struct {
		name string
		req  ListExecutionsRequest
	}{
		{
			// The org predicate is the entire tenancy boundary on a BYPASSRLS
			// read, so a blank key must refuse rather than list the deployment.
			// #3065's fail-open was exactly an org predicate that was
			// conditional on non-emptiness.
			name: "blank org",
			req:  ListExecutionsRequest{OrgWide: true, Limit: 5},
		},
		{
			name: "whitespace-only org",
			req:  ListExecutionsRequest{OrgID: "   ", OrgWide: true, Limit: 5},
		},
		{
			// The GUARD trims (tenantscope.usable) and the PREDICATE binds raw,
			// so an unnormalized key would clear the guard and match nothing:
			// a silent zero of exactly the class #3367 removes. Refused rather
			// than trimmed, because the writer stamps the key raw and a reader
			// that normalized on its own would be the second call site
			// normalizing one value differently.
			name: "unnormalized org key",
			req:  ListExecutionsRequest{OrgID: " acme-org ", OrgWide: true, Limit: 5},
		},
		{
			// Honouring one of the two silently would make the result depend on
			// which, and the caller could not tell which it got.
			name: "org-wide AND tenant-scoped",
			req:  ListExecutionsRequest{OrgID: "acme-org", TenantID: "payments-app", OrgWide: true, Limit: 5},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := r.List(context.Background(), tc.req)
			if err == nil {
				t.Fatal("List accepted an unsafe org-wide request")
			}
			// The refusal must precede the query. If it did not, the error
			// would be a connection failure naming a probe pool, and the test
			// would otherwise pass on the wrong error.
			if strings.Contains(err.Error(), poolProbeLookup) || strings.Contains(err.Error(), poolProbeMain) {
				t.Fatalf("refusal happened AFTER a query was attempted: %v", err)
			}
		})
	}
}

// R3 MAJOR-2. AXONFLOW_DB_USE_APP_ROLE=true with
// AXONFLOW_DB_PLATFORM_ADMIN_URL unset is a posture the orchestrator's
// RequirePlatformAdminOrFatal guard refuses to boot, so this test pins the
// repository's own defence in depth: the guard is one relaxation away from
// letting the shape through, and the refusal below it must hold on its own.
// Before this guard, an org-wide list in that posture ran
// on the app-role pool, mig 042's tenant-keyed RLS filtered it to nothing, and
// the handler answered 200 with an empty page: the confident zero this whole
// fix exists to remove, restored by a deployment gap. It must refuse instead.
func TestOrgWideListRefusesWhenAppRoleHasNoAdminPool_3367(t *testing.T) {
	r := newPoolProbeRepo(t)
	r.lookupDB = nil // the deployment gap: SetCrossOrgDB was never called
	r.SetAppRolePredicate(func() bool { return true })

	_, _, err := r.List(context.Background(), ListExecutionsRequest{OrgID: "acme-org", OrgWide: true, Limit: 5})
	if err == nil {
		t.Fatal("org-wide list with no admin pool under axonflow_app_role returned no error; " +
			"RLS would filter it to zero rows and the tile would read 0 again (#3367)")
	}
	if strings.Contains(err.Error(), poolProbeMain) {
		t.Fatalf("the refusal must precede the query, but the error names the main pool: %v", err)
	}
	if !strings.Contains(err.Error(), "AXONFLOW_DB_PLATFORM_ADMIN_URL") {
		t.Fatalf("the refusal must name the missing setting so an operator can act on it, got: %v", err)
	}
}

// The same posture on an owner or superuser pool is genuinely harmless (no RLS
// narrowing applies), so it must NOT refuse. A guard that fires in both cases
// would break every owner-pool deployment to fix an app-role one.
func TestOrgWideListStillServesOwnerPoolWithoutAdminPool_3367(t *testing.T) {
	r := newPoolProbeRepo(t)
	r.lookupDB = nil
	r.SetAppRolePredicate(func() bool { return false })

	if got := poolUsedBy(t, r, ListExecutionsRequest{OrgID: "acme-org", OrgWide: true, Limit: 5}); got != "main" {
		t.Fatalf("owner-pool fallback ran on the %s pool, want main", got)
	}
}
