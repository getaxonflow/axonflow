// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axonflow/platform/shared/legacyfreeze"
	"github.com/gorilla/mux"
)

// TestCreateOverrideHandler_RejectsMissingUserEmail locks in the ADR-044
// requirement that every override must be attributable to a user. An
// unauthenticated create (empty X-User-Email, X-User-ID) must 401 BEFORE
// any DB work, not silently produce an orphan record.
func TestCreateOverrideHandler_RejectsMissingUserEmail(t *testing.T) {
	body := `{"policy_id":"pol-1","policy_type":"static","override_reason":"test"}`
	req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-x")
	// deliberately no X-User-Email or X-User-ID

	rr := httptest.NewRecorder()
	createOverrideHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("missing user identity: status = %d, want 401", rr.Code)
	}
}

// TestCreateOverrideHandler_RejectsMissingTenant locks in the requirement
// that a tenant header is required. This runs before DB work, so it's
// unit-testable without a live DB.
func TestCreateOverrideHandler_RejectsMissingTenant(t *testing.T) {
	body := `{"policy_id":"pol-1","policy_type":"static","override_reason":"test"}`
	req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(body))
	req.Header.Set("X-User-Email", "dev@example.com")
	// deliberately no X-Tenant-ID

	rr := httptest.NewRecorder()
	createOverrideHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing tenant: status = %d, want 400", rr.Code)
	}
}

// TestRevokeOverrideHandler_RejectsMissingIdentityHeaders ensures the
// tenant + user identity checks run before any DB work. Per the security
// fix: a caller without both X-Tenant-ID and X-User-Email cannot attempt
// revocation against another tenant's overrides.
//
// Uses mux.SetURLVars to simulate mux routing in the unit test.
func TestRevokeOverrideHandler_RejectsMissingIdentityHeaders(t *testing.T) {
	mk := func(headers map[string]string) *http.Request {
		r := httptest.NewRequest("DELETE", "/api/v1/overrides/some-id", nil)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return mux.SetURLVars(r, map[string]string{"id": "some-id"})
	}

	// Case 1: no X-User-Email — should 401.
	rr1 := httptest.NewRecorder()
	revokeOverrideHandler(rr1, mk(map[string]string{"X-Tenant-ID": "tenant-x"}))
	if rr1.Code != http.StatusUnauthorized {
		t.Errorf("no user identity: status = %d, want 401", rr1.Code)
	}

	// Case 2: no X-Tenant-ID — should 400.
	rr2 := httptest.NewRecorder()
	revokeOverrideHandler(rr2, mk(map[string]string{"X-User-Email": "dev@example.com"}))
	if rr2.Code != http.StatusBadRequest {
		t.Errorf("no tenant: status = %d, want 400", rr2.Code)
	}
}

// TestGetOverrideHandler_RequiresTenantHeader ensures the security fix
// scoping GET by tenant. A caller without X-Tenant-ID cannot fetch an
// override (which would leak cross-tenant data).
func TestGetOverrideHandler_RequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/overrides/some-id", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "some-id"})
	rr := httptest.NewRecorder()
	getOverrideHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("no tenant: status = %d, want 400", rr.Code)
	}
}

// TestSessionOverrideWritesAnswerTheFreeze is #4252's route-level proof: an
// authenticated POST or DELETE with a per-user identity and a tenant is answered
// 409 LEGACY_POLICY_WRITE_FROZEN in the coded envelope, naming the typed
// document, and reads neither the body nor the database. usageDB is nil and the
// body is not JSON, so a handler that still decoded the body would answer 400
// and one that still looked the policy up would answer 404, 500 or panic.
// TestCreateOverrideHandler_RejectsMissingUserEmail and _RejectsMissingTenant
// above are the other half of the bracket: the guards answer before the freeze.
func TestSessionOverrideWritesAnswerTheFreeze(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	origValidator := proxyTokenValidator
	proxyTokenValidator = nil
	t.Cleanup(func() { proxyTokenValidator = origValidator })
	origDB := usageDB
	usageDB = nil
	t.Cleanup(func() { usageDB = origDB })

	for _, tc := range []struct {
		name    string
		method  string
		path    string
		handler http.HandlerFunc
	}{
		{"create", http.MethodPost, "/", createOverrideHandler},
		{"revoke", http.MethodDelete, "/", revokeOverrideHandler},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{not json"))
			req.Header.Set("X-Tenant-ID", "tenant-x")
			req.Header.Set("X-User-Email", "dev@corp.example")
			rr := httptest.NewRecorder()
			tc.handler(rr, req)
			if rr.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body = %s", rr.Code, rr.Body.String())
			}
			var body struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("the 409 is not the coded envelope: %v (raw %s)", err, rr.Body.String())
			}
			if body.Error.Code != legacyfreeze.ErrCode {
				t.Errorf("code = %q, want %q", body.Error.Code, legacyfreeze.ErrCode)
			}
			if body.Error.Message != legacyfreeze.OverrideMessage || !strings.Contains(body.Error.Message, "system_controls") {
				t.Errorf("message = %q, want the override freeze remedy naming system_controls", body.Error.Message)
			}
		})
	}
}
