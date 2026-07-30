// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3076 — revokeOverrideHandler had no verifyAgentProxyAuth guard; create did.
//
// The two handlers are the same ingress class. Create keys created_by on a
// client-assertable per-user header; revoke keys revoked_by on the same header
// AND decides, from the same header, whether a non-admin caller may revoke this
// override at all. The #2896 WS1b census named create and stopped there.
//
// Scope note, stated honestly: since #3068 the whole orchestrator mux sits
// behind requireInternalProxyAuth, so an unauthenticated caller is already
// refused one layer out. These tests therefore assert the INNER layer directly
// — that is where the asymmetry lived and where a reviewer would otherwise read
// the difference as intent — and then assert, through the real served handler,
// that the two layers compose without breaking the authenticated path.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"github.com/rs/cors"

	"axonflow/platform/shared/serviceauth"
)

// revokeRequest builds the DELETE the plugins issue, with a per-user identity
// attached. The identity is deliberately FORGED for the direct-access cases: it
// is the value the handler would otherwise write to revoked_by and match
// against created_by.
func revokeRequest(id string) *http.Request {
	r := httptest.NewRequest("DELETE", "/api/v1/overrides/"+id, nil)
	r = mux.SetURLVars(r, map[string]string{"id": id})
	r.Header.Set("X-Tenant-ID", "tenant-x")
	r.Header.Set("X-Org-ID", "org-x")
	r.Header.Set("X-User-Email", "attacker@corp.example")
	return r
}

// The headline. A caller that did not come through the Agent gateway is
// refused by the handler's own guard, before any identity is read and before
// any DB statement runs.
//
// Deliberately credential-less: the property under test is "an unauthenticated
// caller is refused". Handing this probe a proxy token would invert exactly
// what it proves.
func TestRevokeOverride_DirectAccess_BlockedByHandlerGuard(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	// A live sqlmock with NO expectations: any statement the handler issues is
	// an error, so "rejected before touching Postgres" is asserted, not assumed.
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		rr := httptest.NewRecorder()
		revokeOverrideHandler(rr, revokeRequest("ov-1"))

		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body: %s", rr.Code, rr.Body.String())
		}
		if msg := errorBody(t, rr); !strings.Contains(msg, "routed through AxonFlow Agent") {
			t.Errorf("403 body must name the cause, got: %s", msg)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unexpected SQL before the guard: %v", err)
		}
	})
}

// A forged proxy token is no better than none.
func TestRevokeOverride_ForgedProxyToken_Blocked(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		req := revokeRequest("ov-1")
		req.Header.Set("X-Axonflow-Proxy-Auth", "forged-token")

		rr := httptest.NewRecorder()
		revokeOverrideHandler(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body: %s", rr.Code, rr.Body.String())
		}
		if msg := errorBody(t, rr); !strings.Contains(msg, "invalid proxy authentication") {
			t.Errorf("403 body must name the cause, got: %s", msg)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unexpected SQL before the guard: %v", err)
		}
	})
}

// The control that keeps the refusals honest: the SAME request, once it carries
// a valid agent token, revokes the override and returns 200. Without this, a
// regression that denied everything would pass the two tests above.
func TestRevokeOverride_ValidProxyToken_Revokes200(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	origAudit := auditLogger
	auditLogger = nil
	t.Cleanup(func() { auditLogger = origAudit })

	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("org-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT policy_id, created_by FROM policy_overrides").
			WithArgs("ov-live", "tenant-x").
			WillReturnRows(sqlmock.NewRows([]string{"policy_id", "created_by"}).
				AddRow("pol-1", "dev@corp.example"))
		mock.ExpectCommit()

		mock.ExpectBegin()
		mock.ExpectExec("set_config").WithArgs("org-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("UPDATE policy_overrides SET revoked_at").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		req := revokeRequest("ov-live")
		// The agent's own token, and the identity the agent vouched for.
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set("X-User-Email", "dev@corp.example")

		rr := httptest.NewRecorder()
		revokeOverrideHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode 200 body: %v (raw %s)", err, rr.Body.String())
		}
		if resp["id"] != "ov-live" {
			t.Errorf("id: got %v, want ov-live", resp["id"])
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("the revoke did not actually run: %v", err)
		}
	})
}

// Community mode has no internal-service secret to mint a token with, so the
// helper exempts it — for revoke exactly as it already did for create. Without
// this, adding the guard would have made the override lifecycle 403 on every
// default self-hosted community stack, which is the deployment #3062 was
// reported against. The refusal here must still be the identity 401.
func TestRevokeOverride_CommunityMode_NotBlockedByTheGuard(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	installProxyTokenValidator(t, "")

	r := httptest.NewRequest("DELETE", "/api/v1/overrides/ov-1", nil)
	r = mux.SetURLVars(r, map[string]string{"id": "ov-1"})
	r.Header.Set("X-Tenant-ID", "tenant-x")
	// No identity: the community stack's default-off trust gate stripped it.

	rr := httptest.NewRecorder()
	revokeOverrideHandler(rr, r)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (the identity refusal, not the proxy guard); body: %s",
			rr.Code, rr.Body.String())
	}
}

// The invariant, expressed as an invariant rather than as two handler tests:
// create and revoke are the same ingress class, so they must answer the same
// unauthenticated request the same way. This is what fails if someone adds a
// third override-lifecycle write handler and forgets the guard on it — it
// compares dispositions rather than re-listing doors.
func TestOverrideLifecycle_CreateAndRevoke_ProxyAuthParity(t *testing.T) {
	type call struct {
		name string
		run  func(w http.ResponseWriter, token string)
	}
	calls := []call{
		{"create", func(w http.ResponseWriter, token string) {
			req := httptest.NewRequest("POST", "/api/v1/overrides",
				strings.NewReader(createOverrideBody()))
			req.Header.Set("X-Tenant-ID", "tenant-x")
			req.Header.Set("X-User-Email", "attacker@corp.example")
			if token != "" {
				req.Header.Set("X-Axonflow-Proxy-Auth", token)
			}
			createOverrideHandler(w, req)
		}},
		{"revoke", func(w http.ResponseWriter, token string) {
			req := revokeRequest("ov-1")
			if token != "" {
				req.Header.Set("X-Axonflow-Proxy-Auth", token)
			}
			revokeOverrideHandler(w, req)
		}},
	}

	for _, tc := range []struct {
		name  string
		token func(t *testing.T) string
	}{
		{"no token", func(*testing.T) string { return "" }},
		{"forged token", func(*testing.T) string { return "forged-token" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", "enterprise")
			installProxyTokenValidator(t, proxyGuardTestSecret)

			withUsageDB(t, func(mock sqlmock.Sqlmock) {
				got := map[string]int{}
				for _, c := range calls {
					rr := httptest.NewRecorder()
					c.run(rr, tc.token(t))
					got[c.name] = rr.Code
				}
				if got["create"] != got["revoke"] {
					t.Fatalf("create and revoke disagree on an unauthenticated request: "+
						"create=%d revoke=%d — both key a per-user identity, so both must refuse alike",
						got["create"], got["revoke"])
				}
				if got["revoke"] != http.StatusForbidden {
					t.Fatalf("both agreed on %d, want 403", got["revoke"])
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Errorf("unexpected SQL: %v", err)
				}
			})
		})
	}
}

// The outer layer is not a substitute for the inner one, but it must not be
// broken by it either. Driven through buildOrchestratorHandler — the single
// function Run() calls — with the real route table entry for revoke.
func TestRevokeOverride_ThroughServedHandler_RefusesThenServes(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	// One secret for both layers, as every shipped topology provisions.
	installProxyTokenValidator(t, authnTestSecret)

	reached := false
	r := mux.NewRouter()
	r.HandleFunc("/api/v1/overrides/{id}", func(w http.ResponseWriter, req *http.Request) {
		// Stand-in for revokeOverrideHandler: this test is about the wiring
		// reaching it, and the handler's own guard is asserted above.
		if ok, msg := verifyAgentProxyAuth(req, "OverrideRevoke"); !ok {
			sendErrorResponse(w, msg, http.StatusForbidden)
			return
		}
		reached = true
		w.WriteHeader(http.StatusOK)
	}).Methods("DELETE")

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})
	handler := buildOrchestratorHandler(c, r)

	// Unauthenticated: refused, and the route handler is never entered.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("DELETE", "/api/v1/overrides/ov-1", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("served handler answered a token-less revoke with %d, want 403", rr.Code)
	}
	if reached {
		t.Fatal("token-less revoke reached the route handler through the SERVED handler")
	}

	// Authenticated: both layers pass. A guard that refused the agent itself
	// would fail here.
	req := httptest.NewRequest("DELETE", "/api/v1/overrides/ov-1", nil)
	req.Header.Set("X-Axonflow-Proxy-Auth",
		serviceauth.GetInternalServiceToken(serviceauth.NewTokenGenerator(authnTestSecret, nil)))
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !reached {
		t.Fatalf("served handler rejected the AGENT's own revoke: status=%d reached=%v; body: %s",
			rr.Code, reached, rr.Body.String())
	}
}
