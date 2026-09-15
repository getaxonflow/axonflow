// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// `GET /api/v1/overrides` returned an EMPTY LIST for every organisation, and
// nothing in the tree could see it (#3048's third site, found reviewing #3944).
//
// # The defect
//
// `usageDB` is the `axonflow_app_role` pool — `run.go` opens it through
// `agent.OpenAppRoleConnection` precisely so the orchestrator does not run as a
// superuser — and that role is NOT `BYPASSRLS`. `policy_overrides` carries
// migration 110's policy:
//
//	USING (org_id = current_setting('app.current_org_id', true))
//
// With the GUC unset, `current_setting(..., true)` is NULL, `org_id = NULL` is
// NULL, and the policy admits NO ROW. The list handler ran its query bare, so
// the endpoint answered `200 {"overrides":[],"count":0}` for every caller — a
// success, which reads to an operator as "this tenant has no overrides" rather
// than as a failure. That is the shape of defect that survives longest: the
// instrument and the honest answer are the same bytes.
//
// #3048 fixed exactly this on the two sibling paths — the by-id read and the
// revoke lookup both carry the comment *"the bare read matched 0 rows under
// axonflow_app_role"* — and did not fix the list.
//
// # Why no existing test could have caught it
//
// Every other test over this handler is sqlmock, which has no roles, no RLS and
// no GUC: the fixture decides what comes back. Five of them assert a status
// code and at most a `count`. So the endpoint was covered, green, and returning
// nothing.
//
// This test uses the PRODUCTION ROLE against the REAL migrations, which is the
// only configuration in which the question can be asked at all.

package orchestrator

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"axonflow/platform/agent/approletest"

	_ "github.com/lib/pq"
)

func TestOverridesListIsVisibleUnderTheAppRole(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, filepath.Join("..", "..", "migrations", "core"))

	appDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatalf("open app-role DSN: %v", err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	// The posture is the point: if this connection is not the app role, the
	// whole test measures a superuser and RLS never applies.
	approletest.AssertCurrentUser(t, appDB, "axonflow_app_role")

	const org = "org-3944"
	const tenant = "tenant-3944"
	// policy_overrides.id is a uuid column, so the fixture id is a uuid rather
	// than a readable label.
	const overrideID = "3944aaaa-0000-4000-8000-00000000ffff"

	// Seed through the MASTER connection: writing the fixture is not what is
	// under test, and doing it through the app role would need the same GUC
	// the read path is being tested for.
	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	t.Cleanup(func() { _ = masterDB.Close() })
	if _, err := masterDB.Exec(`
		INSERT INTO policy_overrides
			(id, policy_id, policy_type, tenant_id, org_id, action_override,
			 override_reason, created_by, created_at)
		VALUES ($1, gen_random_uuid(), 'static', $2, $3, 'allow',
			 'debugging a payment failure', 'dev@example.com', NOW())`,
		overrideID, tenant, org); err != nil {
		t.Fatalf("seed override: %v", err)
	}

	// PRECONDITION, and it is the anti-vacuity floor for everything below.
	// An assertion that the list is non-empty is worthless if the row is not
	// there; and one that a row is REACHABLE is worthless if the reader can
	// only ever return zero. So: the row exists (asked with RLS bypassed), and
	// the app-role pool WITHOUT the GUC sees none of it — which is the defect,
	// stated as a measurement rather than as a claim about migration 110.
	var seeded int
	if err := masterDB.QueryRow(`SELECT count(*) FROM policy_overrides WHERE id = $1`, overrideID).
		Scan(&seeded); err != nil {
		t.Fatalf("count via master: %v", err)
	}
	if seeded != 1 {
		t.Fatalf("fixture did not land: %d rows", seeded)
	}
	var blind int
	if err := appDB.QueryRow(`SELECT count(*) FROM policy_overrides WHERE id = $1`, overrideID).
		Scan(&blind); err != nil {
		t.Fatalf("count via app role: %v", err)
	}
	if blind != 0 {
		t.Fatalf("the app-role pool sees %d row(s) with NO org GUC set. This test's whole premise is "+
			"that it sees zero — if RLS is not applying here, the handler assertion below cannot "+
			"distinguish a scoped read from an unscoped one.", blind)
	}

	// Now the handler, on that same pool.
	prev := usageDB
	usageDB = appDB
	t.Cleanup(func() { usageDB = prev })

	// PIN THE READ SCOPE, or this test can pass its own precondition and then
	// measure nothing.
	//
	// listOverridesHandler consults resolveCallerReadScope, which grants
	// tenant-wide reads via isCommunityMode() or an explicit read-scope header.
	// With neither, a caller resolves to a per-user scope with no user email
	// and the handler returns an EMPTY LIST at its fail-closed branch -
	// WITHOUT RUNNING THE QUERY AT ALL. The assertion below would then fire and
	// blame RLS, migration 110 and the app role in a nine-line message about
	// something it never reached. R3 found this: the test's own failure text
	// was its most likely lie.
	//
	// Community mode is the posture that makes the read tenant-wide, and it is
	// also the honest one for this test: the RLS policy it is about applies in
	// every mode.
	t.Setenv("DEPLOYMENT_MODE", "community")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/overrides", nil)
	req.Header.Set("X-Tenant-ID", tenant)
	req.Header.Set("X-Org-ID", org)
	rr := httptest.NewRecorder()
	listOverridesHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Overrides []OverrideView `json:"overrides"`
		Count     int            `json:"count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The read scope must actually be tenant-wide, or the branch above returned
	// early and everything below is measuring the wrong thing. Asserted rather
	// than assumed, because that early return produces the SAME empty body the
	// RLS defect produces - the two failures are indistinguishable from the
	// response alone, which is the whole reason this test exists.
	if scope := resolveCallerReadScope(req); !scope.TenantWide {
		t.Fatalf("the read scope is not tenant-wide, so listOverridesHandler returned an empty list "+
			"WITHOUT RUNNING ITS QUERY and the assertion below would blame RLS for something it "+
			"never reached (scope = %+v)", scope)
	}

	if len(body.Overrides) != 1 || body.Count != 1 {
		t.Fatalf("the list returned %d override(s) (count=%d) for an organisation that has one.\n"+
			"    Before #3944 this endpoint answered 200 with an EMPTY list on every deployment "+
			"running migration 110, because the query ran outside WithOrgScope and the app role is "+
			"not BYPASSRLS. A 200 with nothing in it reads as \"no overrides exist\", which is why "+
			"this survived: the failure and the honest answer are the same bytes.\n    body = %s",
			len(body.Overrides), body.Count, rr.Body.String())
	}

	// And the projection this issue is actually about must be present on the
	// row that came back — otherwise the scoping fix would make an incomplete
	// view visible instead of a complete one.
	got := body.Overrides[0]
	if got.ActionOverride == nil || *got.ActionOverride != "allow" {
		t.Errorf("action_override = %v, want \"allow\" — this is what the override DOES and the "+
			"reason #3944 exists", got.ActionOverride)
	}
	if got.OrgID != org || got.OrganizationID != org {
		t.Errorf("org keys = %q/%q, want both %q", got.OrgID, got.OrganizationID, org)
	}
	if got.CreatedBy != "dev@example.com" {
		t.Errorf("created_by = %q", got.CreatedBy)
	}
	if got.OverrideReason == "" {
		t.Error("override_reason is empty")
	}
}
