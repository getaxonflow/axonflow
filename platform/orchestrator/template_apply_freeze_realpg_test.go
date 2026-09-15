// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// Template apply against the REAL core/172 revoke (#4088).
//
// TestTemplateApplyAnswersTheFreeze proves the handler answers a SIMULATED
// 42501. This proves what a simulation cannot: that the error a really
// revoked dynamic_policies raises, through the real TemplateService and
// PolicyRepository, reaches the handler still classifiable - and that an
// owner-pool deployment (AXONFLOW_DB_USE_APP_ROLE=false) still applies
// templates, so the fix is a classification and not a static refusal.
//
// The template is a SHIPPED one, tpl_general_rate_limiting, seeded by
// migrations/core/024; its one variable has a default, so the request needs
// no values the seed does not define.
//
// Gating: TEST_PG_INTEGRATION=1 + docker (approletest.SkipUnlessEnabled).
// Runs in the `Unit Tests: Enterprise-Tagged + Real-PG` lane, which sets that
// variable for the whole platform module. That lane never runs on the PR
// board (its if: excludes pull_request): it runs in the merge queue, in the
// nightly test.yml dispatch on main, and on release tags.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/shared/legacyfreeze"
)

func TestTemplateApplyAgainstTheRealRevoke_RealPG(t *testing.T) {
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

	const (
		org      = "w3f-4088-org"
		template = "tpl_general_rate_limiting"
	)
	apply := func(db *sql.DB, policyName string) *httptest.ResponseRecorder {
		h := NewTemplateAPIHandler(NewTemplateService(NewTemplateRepository(db), NewPolicyRepository(db)))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/"+template+"/apply",
			strings.NewReader(`{"policy_name":"`+policyName+`","variables":{"max_requests_per_hour":100},"enabled":true}`))
		req.Header.Set("X-Tenant-ID", org)
		req.Header.Set("X-Org-ID", org)
		rr := httptest.NewRecorder()
		h.HandleApplyTemplate(rr, req, template)
		return rr
	}
	countNamed := func(t *testing.T, name string) int {
		t.Helper()
		var n int
		if err := owner.QueryRow(`SELECT count(*) FROM dynamic_policies WHERE name = $1`, name).Scan(&n); err != nil {
			t.Fatalf("count %q as the owner: %v", name, err)
		}
		return n
	}

	// THE TEMPLATE EXISTS - asserted, so a 404 cannot hide behind the 409
	// assertion below being the only thing that fails.
	var present int
	if err := owner.QueryRow(`SELECT count(*) FROM policy_templates WHERE id = $1`, template).Scan(&present); err != nil || present != 1 {
		t.Fatalf("the shipped template %s is not seeded (count %d, err %v); core/024 should have seeded it", template, present, err)
	}

	t.Run("the application role is refused with the freeze's answer, and no policy is created", func(t *testing.T) {
		const name = "W3F 4088 app role"
		rr := apply(app, name)
		if rr.Code != http.StatusConflict {
			t.Fatalf("apply as axonflow_app_role: status %d, want 409 - the real revoke did not reach the answer. body=%s",
				rr.Code, rr.Body.String())
		}
		var out TemplateAPIError
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.Error.Code != legacyfreeze.ErrCode {
			t.Fatalf("code %q (decode err %v), want %q. body=%s", out.Error.Code, err, legacyfreeze.ErrCode, rr.Body.String())
		}
		if !strings.Contains(out.Error.Message, TypedAuthoringRoutePrefix) {
			t.Fatalf("the refusal does not name the typed authoring route: %q", out.Error.Message)
		}
		if n := countNamed(t, name); n != 0 {
			t.Fatalf("the refused apply left %d policy row(s)", n)
		}
	})

	t.Run("the owner still applies templates - the fix is a classification, not a static refusal", func(t *testing.T) {
		const name = "W3F 4088 owner"
		if rr := apply(owner, name); rr.Code != http.StatusCreated {
			t.Fatalf("apply as the owner: status %d, want 201. body=%s", rr.Code, rr.Body.String())
		}
		if n := countNamed(t, name); n != 1 {
			t.Fatalf("the owner's apply left %d policy row(s), want 1", n)
		}
	})

	// #4237 follow-up: apply refuses before reading its body, so a request that
	// fails decoding is the freeze on the application role - it was a 400 - and
	// still the handler's own 400 for the owner.
	t.Run("an apply that fails decoding is the freeze on the application role and a 400 for the owner", func(t *testing.T) {
		raw := func(db *sql.DB, body string) *httptest.ResponseRecorder {
			h := NewTemplateAPIHandler(NewTemplateService(NewTemplateRepository(db), NewPolicyRepository(db)))
			req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/"+template+"/apply", strings.NewReader(body))
			req.Header.Set("X-Tenant-ID", org)
			req.Header.Set("X-Org-ID", org)
			rr := httptest.NewRecorder()
			h.HandleApplyTemplate(rr, req, template)
			return rr
		}
		rr := raw(app, "{")
		var out TemplateAPIError
		if err := json.Unmarshal(rr.Body.Bytes(), &out); rr.Code != http.StatusConflict || err != nil ||
			out.Error.Code != legacyfreeze.ErrCode || out.Error.Message != legacyfreeze.Message {
			t.Fatalf("app role: status %d code %q (decode err %v), want 409 %s with legacyfreeze.Message. body=%s",
				rr.Code, out.Error.Code, err, legacyfreeze.ErrCode, rr.Body.String())
		}
		if rr := raw(owner, "{"); rr.Code != http.StatusBadRequest {
			t.Fatalf("owner: status %d, want the handler's own 400. body=%s", rr.Code, rr.Body.String())
		}
	})
}
