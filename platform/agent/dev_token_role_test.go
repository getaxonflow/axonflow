// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Role-param coverage for the dev-mode token endpoint (#2991, #2): the optional
// {"role":"..."} body, the developer-default (own-rows, no escalation), the
// admin/owner loud-log opt-in, unknown-role rejection, and the prod-404
// registration gate. Generic acme-ops / acme-org identities only.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

// mintDevToken drives devTokenHandler directly (bypassing apiAuthMiddleware)
// with an optional JSON body and the authenticated identity in context.
func mintDevToken(t *testing.T, body, clientID, orgID string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(http.MethodPost, "/api/v1/dev/token", nil)
	} else {
		r = httptest.NewRequest(http.MethodPost, "/api/v1/dev/token", strings.NewReader(body))
	}
	ctx := context.WithValue(r.Context(), ContextKeyClientID, clientID)
	ctx = context.WithValue(ctx, ContextKeyOrgID, orgID)
	r = r.WithContext(ctx)
	rec := httptest.NewRecorder()
	devTokenHandler(rec, r)
	return rec
}

type devTokenResp struct {
	UserToken string `json:"user_token"`
	TenantID  string `json:"tenant_id"`
	OrgID     string `json:"org_id"`
	Role      string `json:"role"`
	Email     string `json:"email"`
	ExpiresIn int    `json:"expires_in"`
}

func decodeDevTokenResp(t *testing.T, rec *httptest.ResponseRecorder) devTokenResp {
	t.Helper()
	var resp devTokenResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	return resp
}

// parseClaimsUnverified reads the claims WITHOUT signature verification — only
// to assert what was stamped into the token.
func parseClaimsUnverified(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		t.Fatalf("parse token claims: %v", err)
	}
	return claims
}

const loudMintMarker = "TENANT-WIDE"

func TestDevTokenHandler_DefaultRoleIsDeveloper(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	buf := captureLog(t)

	rec := mintDevToken(t, "", "acme-ops", "acme-org")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeDevTokenResp(t, rec)
	if resp.Role != "developer" {
		t.Errorf("response role = %q, want developer (own-rows default, no escalation)", resp.Role)
	}
	if claims := parseClaimsUnverified(t, resp.UserToken); claims["role"] != "developer" {
		t.Errorf("token role claim = %v, want developer", claims["role"])
	}
	// developer is own-rows, NOT tenant-wide → the loud admin log must NOT fire.
	if strings.Contains(buf.String(), loudMintMarker) {
		t.Errorf("developer default must NOT emit the loud tenant-wide log; got:\n%s", buf.String())
	}
}

func TestDevTokenHandler_EmptyJSONObjectDefaultsToDeveloper(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	rec := mintDevToken(t, `{}`, "acme-ops", "acme-org")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if resp := decodeDevTokenResp(t, rec); resp.Role != "developer" {
		t.Errorf("role = %q, want developer for an empty JSON object", resp.Role)
	}
}

func TestDevTokenHandler_ExplicitAdminHonoredAndLoudLogged(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	buf := captureLog(t)

	rec := mintDevToken(t, `{"role":"admin"}`, "acme-ops", "acme-org")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeDevTokenResp(t, rec)
	if resp.Role != "admin" {
		t.Errorf("response role = %q, want admin", resp.Role)
	}
	if claims := parseClaimsUnverified(t, resp.UserToken); claims["role"] != "admin" {
		t.Errorf("token role claim = %v, want admin", claims["role"])
	}
	logged := buf.String()
	if !strings.Contains(logged, loudMintMarker) || !strings.Contains(logged, "DEV-ONLY ORACLE") {
		t.Errorf("admin mint must emit the loud auditable line; got:\n%s", logged)
	}
	// The loud line must name the org so it is auditable.
	if !strings.Contains(logged, "acme-org") {
		t.Errorf("loud line must name the org; got:\n%s", logged)
	}
}

func TestDevTokenHandler_OwnerHonoredAndLoudLogged(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	buf := captureLog(t)
	rec := mintDevToken(t, `{"role":"owner"}`, "acme-ops", "acme-org")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if resp := decodeDevTokenResp(t, rec); resp.Role != "owner" {
		t.Errorf("role = %q, want owner", resp.Role)
	}
	if !strings.Contains(buf.String(), loudMintMarker) {
		t.Errorf("owner mint (tenant-wide) must emit the loud line; got:\n%s", buf.String())
	}
}

func TestDevTokenHandler_ViewerHonoredNoLoudLog(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	buf := captureLog(t)

	rec := mintDevToken(t, `{"role":"viewer"}`, "acme-ops", "acme-org")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if resp := decodeDevTokenResp(t, rec); resp.Role != "viewer" {
		t.Errorf("role = %q, want viewer", resp.Role)
	}
	// viewer is own-rows (not tenant-wide) → no loud log.
	if strings.Contains(buf.String(), loudMintMarker) {
		t.Errorf("viewer mint must NOT emit the loud tenant-wide log; got:\n%s", buf.String())
	}
}

func TestDevTokenHandler_UnknownRoleRejected(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	rec := mintDevToken(t, `{"role":"superuser"}`, "acme-ops", "acme-org")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown role; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// The 400 must list every canonical role so the caller can self-correct.
	// "member" was dropped from the role model in #2993.
	for _, want := range []string{"admin", "owner", "policy_admin", "developer", "viewer"} {
		if !strings.Contains(body, want) {
			t.Errorf("400 message should list valid role %q; got: %s", want, body)
		}
	}
	// Fail-closed: an unknown role must NEVER mint a token.
	if strings.Contains(body, "user_token") {
		t.Errorf("unknown role must NOT mint a token; got: %s", body)
	}
}

func TestDevTokenHandler_UnknownRoleCaseInsensitiveRejected(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	// A role that is only valid by a different case is normalized (lower+trim);
	// a genuinely unknown value stays rejected.
	rec := mintDevToken(t, `{"role":" ADMIN "}`, "acme-ops", "acme-org")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (‘ ADMIN ’ normalizes to admin); body=%s", rec.Code, rec.Body.String())
	}
	if resp := decodeDevTokenResp(t, rec); resp.Role != "admin" {
		t.Errorf("role = %q, want admin after trim+lowercase", resp.Role)
	}
}

func TestDevTokenHandler_MalformedBodyRejected(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	rec := mintDevToken(t, `{"role":`, "acme-ops", "acme-org") // truncated JSON
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for malformed JSON body; body=%s", rec.Code, rec.Body.String())
	}
}

// TestRegisterDevTokenHandler_UnregisteredInProd pins the load-bearing
// fail-closed gate: on an all-unset (production) env the route must not be
// registered at all, so the router does not match it (404).
func TestRegisterDevTokenHandler_UnregisteredInProd(t *testing.T) {
	clearGateEnv(t) // all unset → production
	router := mux.NewRouter()
	RegisterDevTokenHandler(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dev/token", nil)
	var match mux.RouteMatch
	if router.Match(req, &match) {
		t.Error("prod (all-unset env): POST /api/v1/dev/token must be UNREGISTERED, but the router matched it")
	}
}

func TestRegisterDevTokenHandler_RegisteredInNonProd(t *testing.T) {
	clearGateEnv(t)
	t.Setenv("DEPLOYMENT_MODE", "community") // explicit non-prod signal
	router := mux.NewRouter()
	RegisterDevTokenHandler(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dev/token", nil)
	var match mux.RouteMatch
	if !router.Match(req, &match) {
		t.Error("non-prod: POST /api/v1/dev/token must be REGISTERED, but the router did not match it")
	}
}
