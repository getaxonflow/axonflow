// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// Decision 5 (#3490) regression tests for the SELECTION PREDICATE on the
// shared engine's content plane.
//
// WHY THIS FILE EXISTS. A reviewer reverted loader.go's `AND org_id = $1` to
// `AND tenant_id = $1` -- the exact vulnerability this series closes, on the
// shared engine -- and it COMPILED and passed all 346 subtests in this
// package. Coverage lived only in runtime-e2e/3490, which needs a live stack,
// so nothing in the Go build could tell the two apart.
//
// The reason the existing loader tests cannot catch it is worth stating,
// because it is the trap to avoid when adding more: they register the read
// with `mock.ExpectQuery("SELECT")`, and sqlmock's default matcher treats
// that as a REGEXP searched anywhere in the statement. It matches the
// reverted query exactly as happily as the correct one. Asserting on
// GetPolicies' RETURN VALUE cannot discriminate either -- the mock replays
// whatever rows the test registered regardless of the predicate, so both
// variants return an identical policy set.
//
// So these tests assert on the two things a revert actually changes:
//
//  1. the SQL TEXT issued, captured verbatim through a recording QueryMatcher
//     and inspected in Go (kills the predicate revert);
//  2. the ARGUMENT bound to $1 and to the RLS GUC, with the caller's tenant
//     and the caller's org deliberately set to DIFFERENT strings so a
//     substitution cannot pass by coincidence (kills the scopeOrg-derivation
//     revert, and covers the second enforcement plane -- WithOrgScope's
//     `SET LOCAL app.current_org_id`, which on an app-role deployment is what
//     RLS itself keys on).
//
// Both passes are covered. The 'global' pass carries the same predicate and
// the same substitution risk as the caller's-org pass, and a revert that
// changed only one of them would still be a cross-tenant selection bug.

// recordingMatcher captures every statement sqlmock is asked to match, so a
// test can assert on the SQL the loader ACTUALLY issued rather than on a
// pattern the test itself supplied. Matching still delegates to sqlmock's
// regexp matcher so existing expectation semantics are unchanged.
type recordingMatcher struct {
	mu      sync.Mutex
	queries []string
}

func (m *recordingMatcher) Match(expectedSQL, actualSQL string) error {
	m.mu.Lock()
	m.queries = append(m.queries, actualSQL)
	m.mu.Unlock()
	return sqlmock.QueryMatcherRegexp.Match(expectedSQL, actualSQL)
}

// policyReads returns only the captured statements that read static_policies,
// discarding the set_config execs WithOrgScope issues around them.
func (m *recordingMatcher) policyReads() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, q := range m.queries {
		if strings.Contains(q, "FROM static_policies") {
			out = append(out, q)
		}
	}
	return out
}

// whereClause returns the text after the first WHERE, lowercased and with
// runs of whitespace collapsed. The predicate assertions must look ONLY here:
// `tenant_id` also appears in the SELECT column list (it is still read for
// row attribution), so a naive "does the statement mention tenant_id" check
// would fire on the correct query and prove nothing.
func whereClause(t *testing.T, query string) string {
	t.Helper()
	lower := strings.ToLower(query)
	i := strings.Index(lower, "where")
	if i < 0 {
		t.Fatalf("no WHERE clause in issued query:\n%s", query)
	}
	return strings.Join(strings.Fields(lower[i:]), " ")
}

// TestLoader_SelectionPredicateIsOrgID_BothPasses pins the predicate itself.
//
// Kills the mutant `AND org_id = $1` -> `AND tenant_id = $1` (the reviewer's
// exact revert), on BOTH scoped passes.
func TestLoader_SelectionPredicateIsOrgID_BothPasses(t *testing.T) {
	rec := &recordingMatcher{}
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(rec))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	const (
		callerTenant = "tenant-the-caller-named"
		callerOrg    = "org-from-the-licence"
	)

	// Two passes: the caller's org scope, then the 'global' scope.
	expectScopedLoadPass(mock, callerOrg,
		tenantRow(sqlmock.NewRows(loaderTestCols()), "org_row", callerTenant, 50))
	expectScopedLoadPass(mock, globalTenantSentinel,
		systemRow(sqlmock.NewRows(loaderTestCols()), "sys_row", 100))

	loader := NewPolicyLoader(db, NewPolicyCache(time.Minute, 10))
	org := callerOrg
	if _, err := loader.GetPolicies(context.Background(), callerTenant, &org, PhaseRequest); err != nil {
		t.Fatalf("GetPolicies: %v", err)
	}

	reads := rec.policyReads()
	if len(reads) != 2 {
		t.Fatalf("expected 2 static_policies reads (caller-org pass + global pass), got %d", len(reads))
	}

	for i, q := range reads {
		where := whereClause(t, q)

		// The org predicate must be present...
		if !strings.Contains(where, "org_id = $1") {
			t.Errorf("pass %d: selection is not keyed on org_id (#3490).\nWHERE: %s", i, where)
		}
		// ...and the tenant predicate must be ABSENT. This is the half that
		// fails on the revert. Checked against the WHERE clause only, since
		// tenant_id is legitimately in the SELECT list.
		if strings.Contains(where, "tenant_id = $1") {
			t.Errorf("pass %d: selection is keyed on tenant_id -- the caller-chosen "+
				"Basic-auth username decides which policies govern it (#3490).\nWHERE: %s", i, where)
		}
		// `org_id = $1` must not be satisfied by an `organization_id` match:
		// the legacy column is a different key with a different population,
		// and #3334 retires it. Guard the substring explicitly.
		if strings.Contains(where, "organization_id = $1") {
			t.Errorf("pass %d: selection reads the legacy organization_id column (#3334).\nWHERE: %s", i, where)
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestLoader_BindsOrgNotTenant_OnBothPlanes pins the VALUE bound to the
// predicate and to the RLS GUC.
//
// Kills the mutant that drops the `if orgID != nil` branch at loader.go's
// scopeOrg derivation, leaving `scopeOrg := tenantID`. That mutant keeps the
// `org_id = $1` text intact -- so the predicate test above still passes -- and
// simply feeds it the caller-chosen tenant, which is the same vulnerability
// wearing the correct column name.
//
// It also covers the SECOND enforcement plane: scopeOrg fills the
// `SET LOCAL app.current_org_id` GUC inside WithOrgScope, which is what RLS
// keys on for an app-role deployment. sqlmock's WithArgs on that Exec is the
// assertion.
func TestLoader_BindsOrgNotTenant_OnBothPlanes(t *testing.T) {
	rec := &recordingMatcher{}
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(rec))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Deliberately different strings. If either plane substitutes one for the
	// other, sqlmock reports an argument mismatch rather than silently
	// serving the same rows.
	const (
		callerTenant = "acme-tenant-alpha"
		callerOrg    = "acme-org"
	)

	// Pass 1: BOTH the GUC exec and the query must bind the ORG.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app\.current_org_id', \$1, true\)`).
		WithArgs(callerOrg).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM static_policies`).
		WithArgs(callerOrg).
		WillReturnRows(tenantRow(sqlmock.NewRows(loaderTestCols()), "org_row", callerTenant, 50))
	mock.ExpectCommit()

	// Pass 2: the global sentinel, on both planes.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app\.current_org_id', \$1, true\)`).
		WithArgs(globalTenantSentinel).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM static_policies`).
		WithArgs(globalTenantSentinel).
		WillReturnRows(systemRow(sqlmock.NewRows(loaderTestCols()), "sys_row", 100))
	mock.ExpectCommit()

	loader := NewPolicyLoader(db, NewPolicyCache(time.Minute, 10))
	org := callerOrg
	policies, err := loader.GetPolicies(context.Background(), callerTenant, &org, PhaseRequest)
	if err != nil {
		t.Fatalf("GetPolicies: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected the org row and the global row, got %d", len(policies))
	}

	// ExpectationsWereMet is the load-bearing assertion here: it is what
	// fails when a plane binds the tenant instead of the org.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a plane bound the wrong scope value (#3490): %v", err)
	}
}

// TestLoader_RowsSelectedAreKeyedByOrg is the behavioural companion: the rows
// the caller ends up governed by are the ones stored under its ORG, and a
// tenant-keyed read would select a DIFFERENT set.
//
// The mock is keyed by argument, so it models a database in which the org's
// policy and a same-named tenant's policy are different rows. A revert that
// binds the tenant asks for a scope this mock does not serve.
func TestLoader_RowsSelectedAreKeyedByOrg(t *testing.T) {
	rec := &recordingMatcher{}
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(rec))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	const (
		callerTenant = "evader"     // a tenant name no policy targets
		callerOrg    = "victim-org" // where the governing policy actually lives
	)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config`).WithArgs(callerOrg).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM static_policies`).WithArgs(callerOrg).
		WillReturnRows(tenantRow(sqlmock.NewRows(loaderTestCols()), "org_governing_policy", callerTenant, 50))
	mock.ExpectCommit()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config`).WithArgs(globalTenantSentinel).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM static_policies`).WithArgs(globalTenantSentinel).
		WillReturnRows(systemRow(sqlmock.NewRows(loaderTestCols()), "sys_row", 100))
	mock.ExpectCommit()

	loader := NewPolicyLoader(db, NewPolicyCache(time.Minute, 10))
	org := callerOrg
	policies, err := loader.GetPolicies(context.Background(), callerTenant, &org, PhaseRequest)
	if err != nil {
		t.Fatalf("GetPolicies: %v", err)
	}

	var found bool
	for _, p := range policies {
		if p.PolicyID == "org_governing_policy" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the org's governing policy was not selected; a caller naming an "+
			"untargeted tenant escaped it (#3490). got %d policies", len(policies))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
