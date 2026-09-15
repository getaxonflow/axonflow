// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"sort"
	"strconv"
	"strings"
	"testing"

	"axonflow/platform/agent/approletest"
)

// TestThePreflightListsEveryOverrideTheUpgradeImportCarries_RealPG holds the
// upgrade preflight's check 26 to the import it previews (PRD v11 §1.5,
// migrations/core/183).
//
// The import selects in two halves: typed_policy_import_candidates() in SQL,
// then buildImportRecord in Go. The preflight runs before the migration that
// creates the function, so check 26 repeats the join and the six terms of the
// Go filter that SQL can state: organization-wide, unrevoked, unexpired, not
// break-glass, naming a legacy policy, changing it. Its second list is the same
// with the first term reversed: the tenant-scoped rows the import drops.
// Against a migrated database seeded with rows that each take one path through
// the import, the first list must hold every row the import carries and none a
// term excludes, and beyond the carried rows exactly the rows the import's
// document validation skips - the superset the check says it prints. The
// second list must hold exactly the tenant-scoped rows that pass the other
// five terms. The counts and listings the verdict prints are run too, over the
// same rows.
func TestThePreflightListsEveryOverrideTheUpgradeImportCarries_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	q := preflightCheck26Queries(t)
	env := approletest.Setup(t, "../../migrations/core")
	ctx := context.Background()

	owner, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()

	idOf := func(query, policy string) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, query, policy).Scan(&id); err != nil {
			t.Fatalf("the shipped row %s: %v", policy, err)
		}
		return id
	}
	union := idOf(`SELECT id::text FROM static_policies WHERE policy_id = $1`, "sys_sqli_union_select")
	injection := idOf(`SELECT id::text FROM static_policies WHERE policy_id = $1`, "sys_dangerous_injection_override")
	dynamic := idOf(`SELECT id::text FROM dynamic_policies WHERE policy_id = $1`, "sys_dyn_expensive_query")

	override := func(org, policy, policyType string, tenant, action, enabled any) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO policy_overrides
			(policy_id, policy_type, org_id, tenant_id, action_override, enabled_override, override_reason, created_by)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, 'realpg', 'realpg') RETURNING id::text`,
			policy, policyType, org, tenant, action, enabled).Scan(&id); err != nil {
			t.Fatalf("seeding an override for %s: %v", org, err)
		}
		return id
	}
	set := func(id, assignment string) {
		t.Helper()
		if _, err := owner.ExecContext(ctx, `UPDATE policy_overrides SET `+assignment+` WHERE id = $1::uuid`, id); err != nil {
			t.Fatalf("setting %s on %s: %v", assignment, id, err)
		}
	}

	// The rows the import carries, each in an organization of its own where it
	// could otherwise meet another row on its control, with the change the check
	// must print for it. An enabled_override of false wins over an action, as
	// buildImportRecord's switch has it.
	wantCarried := map[string]string{}
	wantCarried[override("org-a", union, "static", nil, "block", nil)] = "action block"
	wantCarried[override("org-a", injection, "static", nil, nil, false)] = "disabled"
	until := override("org-d", union, "static", nil, "warn", nil)
	set(until, `expires_at = now() + interval '1 day'`)
	wantCarried[until] = "action warn"
	wantCarried[override("org-e", union, "static", nil, "log", true)] = "action log"
	wantCarried[override("org-f", union, "static", nil, "block", false)] = "disabled"

	// One row per SQL term, each excluded by that term alone; the import skips
	// each for the reason that term stands for.
	excluded := map[string]string{}
	tenantRow := override("org-a", union, "static", "tenant-1", "warn", nil)
	excluded[tenantRow] = "tenant-scoped"
	revoked := override("org-a", union, "static", nil, "warn", nil)
	set(revoked, `revoked_at = now()`)
	excluded[revoked] = "revoked"
	expired := override("org-a", union, "static", nil, "warn", nil)
	set(expired, `expires_at = now() - interval '1 hour'`)
	excluded[expired] = "expired"
	signed := override("org-a", injection, "static", nil, "block", nil)
	set(signed, `tool_signature = 'sig'`)
	excluded[signed] = "break-glass"
	excluded[override("org-a", injection, "static", nil, "allow", nil)] = "break-glass"
	excluded[override("org-a", union, "static", nil, nil, true)] = "changes nothing"
	excluded[override("org-a", injection, "static", nil, nil, nil)] = "changes nothing"
	excluded[override("org-a", "00000000-0000-4000-8000-00000000c026", "static", nil, "block", nil)] = "names no legacy policy"
	// A tenant-scoped row one of the other terms excludes: in neither list.
	tenantRevoked := override("org-a", union, "static", "tenant-2", "block", nil)
	set(tenantRevoked, `revoked_at = now()`)
	excluded[tenantRevoked] = "tenant-scoped"
	// Tenant-scoped break-glass rows, a tool signature and an 'allow': in
	// neither list, which holds only while the tenant list keeps those terms.
	tenantSigned := override("org-a", injection, "static", "tenant-3", "block", nil)
	set(tenantSigned, `tool_signature = 'sig'`)
	excluded[tenantSigned] = "tenant-scoped"
	excluded[override("org-a", injection, "static", "tenant-4", "allow", nil)] = "tenant-scoped"

	// Rows only the import's document validation skips: SQL cannot repeat it,
	// so the first list holds them and the check says it is a superset.
	validatorOnly := map[string]string{}
	validatorOnly[override("org-b", dynamic, "dynamic", nil, "block", nil)] = "SYSTEM_CONTROL_NOT_REACTIONABLE"
	validatorOnly[override("org-c", union, "static", nil, "block", nil)] = "disagrees with another override"
	validatorOnly[override("org-c", union, "static", nil, "warn", nil)] = "disagrees with another override"
	validatorOnly[override("org-g", union, "static", nil, "deny", nil)] = "SYSTEM_CONTROL_MALFORMED"

	// The import's half, read and decided exactly as the boot step does.
	byOrg, orgs, err := readImportCandidates(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	carried := map[string]bool{}
	skipped := map[string]importSkip{}
	for _, org := range orgs {
		rec, err := buildImportRecord(byOrg[org])
		if err != nil {
			t.Fatalf("building %s's import record: %v", org, err)
		}
		why := map[string]bool{}
		for _, s := range rec.Skipped {
			why[s.OverrideID] = true
			skipped[s.OverrideID] = s
		}
		for _, c := range byOrg[org] {
			if !why[c.OverrideID] {
				carried[c.OverrideID] = true
			}
		}
	}
	if got, want := preflightSortedIDs(carried), preflightSortedKeys(wantCarried); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("the import carries %v; the fixture was built so that it carries %v", got, want)
	}
	for id, reason := range excluded {
		if s, ok := skipped[id]; !ok || !strings.HasPrefix(s.Reason, reason) {
			t.Fatalf("the import's reason for override %s is %+v; the fixture excludes it as %q", id, s, reason)
		}
	}
	for id, reason := range validatorOnly {
		if s, ok := skipped[id]; !ok || (s.Code != reason && !strings.HasPrefix(s.Reason, reason)) {
			t.Fatalf("the import's reason for override %s is %+v; the fixture expects its document validation to skip it as %q", id, s, reason)
		}
	}

	// The preflight's half: the exact queries a preflight run sends.
	listed := preflightRows(ctx, t, owner, `SELECT override_id, change FROM (`+q["C26_CANDIDATES"]+`) c`)
	for id, change := range wantCarried {
		if got, ok := listed[id]; !ok {
			t.Errorf("the import carries override %s into the draft and check 26 does not list it", id)
		} else if got != change {
			t.Errorf("check 26 names override %s's change %q; want %q", id, got, change)
		}
	}
	for id, reason := range excluded {
		if _, ok := listed[id]; ok {
			t.Errorf("check 26's draft list holds override %s, which the import skips as %s before it reaches the document", id, reason)
		}
	}
	for id, reason := range validatorOnly {
		if _, ok := listed[id]; !ok {
			t.Errorf("check 26 does not list override %s, which only the import's document validation skips (%s)", id, reason)
		}
	}
	if want := len(wantCarried) + len(validatorOnly); len(listed) != want {
		t.Errorf("check 26's draft list holds %d row(s); want %d: the %d the import carries and the %d its document validation skips. Listed: %v",
			len(listed), want, len(wantCarried), len(validatorOnly), listed)
	}

	tenantListed := preflightRows(ctx, t, owner, `SELECT override_id, change FROM (`+q["C26_TENANT_ROWS"]+`) c`)
	if len(tenantListed) != 1 || tenantListed[tenantRow] != "action warn" {
		t.Errorf("check 26's tenant-scoped list is %v; want exactly the tenant row %s, which the import drops, as action warn", tenantListed, tenantRow)
	}

	// The count and the listing the verdict prints, over the same rows.
	listedOrgs := map[string]bool{}
	for _, org := range orgs {
		for _, c := range byOrg[org] {
			if _, ok := listed[c.OverrideID]; ok {
				listedOrgs[org] = true
			}
		}
	}
	preflightScalar := func(name string) string {
		t.Helper()
		var s string
		if err := owner.QueryRowContext(ctx, q[name]).Scan(&s); err != nil {
			t.Fatalf("running %s: %v", name, err)
		}
		return s
	}
	if got, want := preflightScalar("C26_COUNT_SQL"), strconv.Itoa(len(listed))+"|"+strconv.Itoa(len(listedOrgs)); got != want {
		t.Errorf("C26_COUNT_SQL answers %q; the draft list has %s", got, want)
	}
	if got := preflightScalar("C26_TENANT_COUNT_SQL"); got != "1|1" {
		t.Errorf("C26_TENANT_COUNT_SQL answers %q; the tenant-scoped list has 1|1", got)
	}
	listing := preflightScalar("C26_LIST_SQL")
	if n := len(strings.Split(listing, "; ")); n != len(listed) {
		t.Errorf("C26_LIST_SQL prints %d entr(ies); the draft list has %d: %q", n, len(listed), listing)
	}
	for id := range listed {
		if !strings.Contains(listing, "(override "+id+")") {
			t.Errorf("C26_LIST_SQL does not name override %s: %q", id, listing)
		}
	}
	if tl := preflightScalar("C26_TENANT_LIST_SQL"); tl != "org-a/tenant-1: sys_sqli_union_select action warn (override "+tenantRow+")" {
		t.Errorf("C26_TENANT_LIST_SQL prints %q; want the one tenant row, named by organization and tenant", tl)
	}
}

// preflightRows runs query and maps each row's first column to its second.
func preflightRows(ctx context.Context, t *testing.T, db *sql.DB, query string) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		t.Fatalf("running check 26's query: %v", err)
	}
	out := map[string]string{}
	for rows.Next() {
		var id, change string
		if err := rows.Scan(&id, &change); err != nil {
			t.Fatal(err)
		}
		out[id] = change
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading check 26's rows: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}

func preflightSortedIDs(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func preflightSortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
