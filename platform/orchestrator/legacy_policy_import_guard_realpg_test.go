// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/shared/legacyfreeze"
)

// TestLegacyImportAgainstTheRealRevoke_RealPG is #4237 against core/172's
// real revoke, on the two connections a deployment can hold (PRD v11 §5 item
// 5):
//
//   - axonflow_app_role, from which core/172 revoked the write: every import
//     route, and create and update, refuses with the freeze before reading the
//     body, a malformed row included, and no row is written;
//   - the owner, whose writes core/172 does not refuse: the write proceeds, a
//     malformed row is the 400 it always should have been, and a realistic row
//     is written.
//
// The unit tests drive the guard through a stub probe. This is where the
// probe's query meets Postgres, so legacyfreeze.MayWrite's overload resolution
// and its answer for each role are measured rather than modelled.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (approletest.SkipUnlessEnabled).
func TestLegacyImportAgainstTheRealRevoke_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	open := func(dsn, label string) *sql.DB {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatalf("open %s: %v", label, err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	owner := open(env.MasterDSN, "owner")
	app := open(env.AppRoleDSN, "app role")
	approletest.AssertCurrentUser(t, app, "axonflow_app_role")
	ctx := context.Background()

	t.Run("the probe answers for the connection held", func(t *testing.T) {
		for _, table := range []string{"dynamic_policies", "static_policies"} {
			if may, err := legacyfreeze.MayWrite(ctx, app, table); err != nil || may {
				t.Errorf("MayWrite(app role, %s) = %v, %v; want false, nil - core/172 revoked it", table, may, err)
			}
			if may, err := legacyfreeze.MayWrite(ctx, owner, table); err != nil || !may {
				t.Errorf("MayWrite(owner, %s) = %v, %v; want true, nil - core/172 does not refuse the owner", table, may, err)
			}
		}
	})

	const org = "w3x-4237-org"
	headers := map[string]string{"X-Tenant-ID": org, "X-Org-ID": org}
	send := func(t *testing.T, db *sql.DB, method, path, body string) (int, codedError) {
		t.Helper()
		router := legacyImportRouter(t, NewPolicyService(NewPolicyRepository(db), nil))
		rr, _ := legacyImport(t, router, method, path, body, headers)
		var out codedError
		if rr.Code >= 300 {
			out = decodeCoded(t, rr)
		}
		return rr.Code, out
	}
	row := func(name, typeKey string) string {
		return `{"name":"` + name + `","` + typeKey + `":"content","category":"dynamic-compliance",` +
			`"conditions":[{"field":"query","operator":"contains","value":"x"}],"actions":[{"type":"block"}],"priority":10,"enabled":true}`
	}
	importOf := func(name, typeKey string) string { return `{"policies":[` + row(name, typeKey) + `]}` }
	countNamed := func(t *testing.T, name string) int {
		t.Helper()
		var n int
		if err := owner.QueryRow(`SELECT count(*) FROM dynamic_policies WHERE name = $1`, name).Scan(&n); err != nil {
			t.Fatalf("count %q as the owner: %v", name, err)
		}
		return n
	}
	refused := func(t *testing.T, code int, out codedError) {
		t.Helper()
		if code != http.StatusConflict || out.Error.Code != legacyfreeze.ErrCode {
			t.Fatalf("status=%d code=%q, want 409 %s - the real revoke did not reach the answer",
				code, out.Error.Code, legacyfreeze.ErrCode)
		}
		if !strings.Contains(out.Error.Message, TypedAuthoringRoutePrefix) {
			t.Fatalf("the refusal does not name the typed authoring route: %q", out.Error.Message)
		}
	}

	for i, path := range legacyImportRoutes {
		for _, typeKey := range []string{"type", "policy_type"} {
			name := fmt.Sprintf("w3x-4237-app-%d-%s", i, typeKey)
			t.Run("app role import "+path+" "+typeKey, func(t *testing.T) {
				code, out := send(t, app, http.MethodPost, path, importOf(name, typeKey))
				refused(t, code, out)
				if n := countNamed(t, name); n != 0 {
					t.Fatalf("the refused import left %d row(s)", n)
				}
			})
		}
	}
	for i, path := range []string{"/api/v1/policies", "/api/v1/dynamic-policies", "/api/v1/tenant-policies"} {
		for _, typeKey := range []string{"type", "policy_type"} {
			name := fmt.Sprintf("w3x-4237-app-create-%d-%s", i, typeKey)
			t.Run("app role create "+path+" "+typeKey, func(t *testing.T) {
				code, out := send(t, app, http.MethodPost, path, row(name, typeKey))
				refused(t, code, out)
				if n := countNamed(t, name); n != 0 {
					t.Fatalf("the refused create left %d row(s)", n)
				}
			})
		}
	}
	t.Run("app role update is refused before any lookup", func(t *testing.T) {
		// A policy that does not exist: without the guard this is a 404 (or a
		// 400 for the malformed body); with it, the freeze, because no update
		// can succeed on this connection either way.
		code, out := send(t, app, http.MethodPut, "/api/v1/policies/"+uuid.NewString(), `{"name":"x","priority":-1}`)
		refused(t, code, out)
	})

	t.Run("the owner still writes: a malformed row is a 400 and a realistic row is written", func(t *testing.T) {
		const malformed, realistic, created = "w3x-4237-owner-malformed", "w3x-4237-owner-realistic", "w3x-4237-owner-created"
		if code, out := send(t, owner, http.MethodPost, "/api/v1/policies/import", importOf(malformed, "policy_type")); code != http.StatusBadRequest || out.Error.Code != "VALIDATION_ERROR" {
			t.Fatalf("malformed import as the owner: status=%d code=%q, want 400 VALIDATION_ERROR", code, out.Error.Code)
		}
		if code, out := send(t, owner, http.MethodPost, "/api/v1/policies", row(malformed, "policy_type")); code != http.StatusBadRequest || out.Error.Code != "VALIDATION_ERROR" {
			t.Fatalf("malformed create as the owner: status=%d code=%q, want 400 VALIDATION_ERROR", code, out.Error.Code)
		}
		if n := countNamed(t, malformed); n != 0 {
			t.Fatalf("the refused malformed rows left %d row(s)", n)
		}
		if code, out := send(t, owner, http.MethodPost, "/api/v1/dynamic-policies/import", importOf(realistic, "type")); code != http.StatusOK {
			t.Fatalf("realistic import as the owner: status=%d (%+v), want 200 - an owner-role deployment still writes", code, out)
		}
		if code, out := send(t, owner, http.MethodPost, "/api/v1/dynamic-policies", row(created, "type")); code != http.StatusCreated {
			t.Fatalf("realistic create as the owner: status=%d (%+v), want 201", code, out)
		}
		for _, name := range []string{realistic, created} {
			if n := countNamed(t, name); n != 1 {
				t.Fatalf("the owner's write of %q left %d row(s), want 1", name, n)
			}
		}
	})
}
