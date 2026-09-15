// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// The system-policy write routes against the REAL core/172 revoke (#4084).
//
// static_policy_write_freeze_test.go proves the handler answers a SIMULATED
// 42501 correctly. This proves the other two things a simulation cannot:
// that the error a really revoked table raises, through the real repository
// and WithOrgScope, is the one the classifier recognises - and that a
// deployment connecting as the owner still writes, so the fix is a
// classification and not a static refusal that would pass every freeze
// assertion while breaking owner-pool deployments.
//
// Gating: TEST_PG_INTEGRATION=1 + docker (approletest.SkipUnlessEnabled).
// Runs in the `Unit Tests: Enterprise-Tagged + Real-PG` lane, which sets that
// variable for the whole platform module. That lane never runs on the PR
// board (its if: excludes pull_request): it runs in the merge queue, in the
// nightly test.yml dispatch on main, and on release tags.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/shared/legacyfreeze"
)

func TestSystemPolicyWritesAgainstTheRealRevoke_RealPG(t *testing.T) {
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
	// The license check reads this; unset, it falls back to the clients table,
	// which is the path a community-licensed caller takes.
	t.Setenv("AXONFLOW_LICENSE_KEY", "")

	const org = "w3f-4084-org"

	// THE FIXTURE IS SEEDED AS THE OWNER, because creating it through the API
	// is exactly what the freeze refuses. It is organization-owned - a
	// 'global' row is refused 403 by the baseline guard before any write is
	// attempted, which would make the verbs below assert against the wrong
	// refusal - disabled, and its pattern matches nothing. created_by and
	// updated_by are set because every API-created row carries them and
	// Update's RETURNING scans both into plain strings.
	seed := func(t *testing.T, policyID string) {
		t.Helper()
		if _, err := owner.Exec(`INSERT INTO static_policies
			(policy_id, name, category, pattern, action, severity, tier, tenant_id, org_id, enabled, created_by, updated_by)
			VALUES ($1, 'W3F seeded fixture', 'security-sqli', 'w3f-never-matches-[0-9]{40}', 'block', 'low', 'tenant', $2, $2, false, 'w3f-fixture', 'w3f-fixture')`,
			policyID, org); err != nil {
			t.Fatalf("seed %s as the owner: %v", policyID, err)
		}
	}
	type rowState struct {
		name    string
		enabled bool
		deleted bool
		pattern string
		version int
	}
	stateOf := func(t *testing.T, policyID string) rowState {
		t.Helper()
		var s rowState
		if err := owner.QueryRow(`SELECT name, enabled, deleted_at IS NOT NULL, pattern, version FROM static_policies WHERE policy_id = $1`,
			policyID).Scan(&s.name, &s.enabled, &s.deleted, &s.pattern, &s.version); err != nil {
			t.Fatalf("read %s as the owner: %v", policyID, err)
		}
		return s
	}
	countNamed := func(t *testing.T, name string) int {
		t.Helper()
		var n int
		if err := owner.QueryRow(`SELECT count(*) FROM static_policies WHERE name = $1`, name).Scan(&n); err != nil {
			t.Fatalf("count %q as the owner: %v", name, err)
		}
		return n
	}

	type verb struct {
		name   string
		method string
		body   string
		serve  func(*StaticPolicyAPIHandler) http.HandlerFunc
		// ok is the status the owner gets for the same request.
		ok int
	}
	verbs := []verb{
		{"create", http.MethodPost, `{"name":"W3F created","pattern":"w3f-never-matches-[0-9]{40}","category":"security-sqli","action":"block","tier":"tenant"}`,
			func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleCreateStaticPolicy }, http.StatusCreated},
		{"update", http.MethodPut, `{"name":"W3F renamed"}`,
			func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleUpdateStaticPolicy }, http.StatusOK},
		{"toggle", http.MethodPatch, `{"enabled":true}`,
			func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleTogglePolicy }, http.StatusOK},
		{"delete", http.MethodDelete, ``,
			func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleDeleteStaticPolicy }, http.StatusNoContent},
	}
	call := func(db *sql.DB, v verb, policyID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(v.method, "/api/v1/system-policies/"+policyID, bytes.NewReader([]byte(v.body)))
		req.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(req.Context(), ContextKeyTenantID, org)
		ctx = context.WithValue(ctx, ContextKeyOrgID, org)
		req = mux.SetURLVars(req.WithContext(ctx), map[string]string{"id": policyID})
		rr := httptest.NewRecorder()
		v.serve(NewStaticPolicyAPIHandler(db))(rr, req)
		return rr
	}

	t.Run("the application role is refused with the freeze's answer, and nothing is written", func(t *testing.T) {
		const id = "w3f_4084_app_role"
		seed(t, id)
		before := stateOf(t, id)
		for _, v := range verbs {
			rr := call(app, v, id)
			if rr.Code != http.StatusConflict {
				t.Fatalf("%s as axonflow_app_role: status %d, want 409 - the real revoke did not reach the answer. body=%s",
					v.name, rr.Code, rr.Body.String())
			}
			var out struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.Error.Code != legacyfreeze.ErrCode {
				t.Fatalf("%s: code %q (decode err %v), want %q. body=%s", v.name, out.Error.Code, err, legacyfreeze.ErrCode, rr.Body.String())
			}
		}
		// A REFUSAL LEAVES NO TRACE: the seeded row is exactly as it was, and
		// the refused create made no row.
		if after := stateOf(t, id); after != before {
			t.Fatalf("the refused writes changed the row: before %+v, after %+v", before, after)
		}
		if n := countNamed(t, "W3F created"); n != 0 {
			t.Fatalf("the refused create left %d row(s)", n)
		}
	})

	// #4237 follow-up: the create refuses before reading its body, so a body
	// missing its required fields is the freeze on the application role - it
	// was a 400 - and still the create's own 400 for the owner.
	t.Run("a create missing its required fields is the freeze on the application role and a 400 for the owner", func(t *testing.T) {
		bad := verb{"create", http.MethodPost, `{"name":"W3X malformed create"}`,
			func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleCreateStaticPolicy }, http.StatusBadRequest}
		rr := call(app, bad, "")
		var out struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); rr.Code != http.StatusConflict || err != nil ||
			out.Error.Code != legacyfreeze.ErrCode || out.Error.Message != legacyfreeze.Message {
			t.Fatalf("app role: status %d code %q (decode err %v), want 409 %s with legacyfreeze.Message. body=%s",
				rr.Code, out.Error.Code, err, legacyfreeze.ErrCode, rr.Body.String())
		}
		if rr := call(owner, bad, ""); rr.Code != http.StatusBadRequest {
			t.Fatalf("owner: status %d, want the create's own 400. body=%s", rr.Code, rr.Body.String())
		}
		if n := countNamed(t, "W3X malformed create"); n != 0 {
			t.Fatalf("the refused create left %d row(s)", n)
		}
	})

	// #4237 follow-up (master's ruling on R3 round 1's H1): update and toggle
	// refuse before the body and the lookup, so the answers the repository gave
	// before its write - an invalid pattern (400), a body that changes nothing
	// (200) and a toggle's invalid JSON (400) - are the freeze on the
	// application role, and still those answers for the owner. Nothing changes.
	t.Run("update and toggle answer the freeze before their own checks on the application role, and those checks still answer the owner", func(t *testing.T) {
		const id = "w3x_4237_update"
		seed(t, id)
		before := stateOf(t, id)
		update := func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleUpdateStaticPolicy }
		toggle := func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleTogglePolicy }
		for _, c := range []struct {
			name string
			v    verb
		}{
			{"an update with an invalid pattern", verb{"update", http.MethodPut, `{"pattern":"("}`, update, http.StatusBadRequest}},
			{"an update that changes nothing", verb{"update", http.MethodPut, `{}`, update, http.StatusOK}},
			{"a toggle with invalid JSON", verb{"toggle", http.MethodPatch, `{`, toggle, http.StatusBadRequest}},
		} {
			rr := call(app, c.v, id)
			var out struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &out); rr.Code != http.StatusConflict || err != nil ||
				out.Error.Code != legacyfreeze.ErrCode || out.Error.Message != legacyfreeze.Message {
				t.Fatalf("%s as the app role: status %d code %q (decode err %v), want 409 %s with legacyfreeze.Message. body=%s",
					c.name, rr.Code, out.Error.Code, err, legacyfreeze.ErrCode, rr.Body.String())
			}
			if rr := call(owner, c.v, id); rr.Code != c.v.ok {
				t.Fatalf("%s as the owner: status %d, want %d. body=%s", c.name, rr.Code, c.v.ok, rr.Body.String())
			}
		}
		if after := stateOf(t, id); after != before {
			t.Fatalf("the requests changed the row: before %+v, after %+v", before, after)
		}
	})

	t.Run("the owner still writes - the fix is a classification, not a static refusal", func(t *testing.T) {
		const id = "w3f_4084_owner"
		seed(t, id)
		for _, v := range verbs {
			if rr := call(owner, v, id); rr.Code != v.ok {
				t.Fatalf("%s as the owner: status %d, want %d. body=%s", v.name, rr.Code, v.ok, rr.Body.String())
			}
		}
		if n := countNamed(t, "W3F created"); n != 1 {
			t.Fatalf("the owner's create left %d row(s), want 1", n)
		}
		if after := stateOf(t, id); after.name != "W3F renamed" || !after.enabled || !after.deleted {
			t.Fatalf("the owner's update, toggle and delete did not all land: %+v", after)
		}
	})
}
