// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #2896 WS1b — the override-create identity (X-User-Email) and the WCP
// step-gate identity KEY ADR-044 override behavior (a deny→allow flip), so
// the orchestrator must reject requests that did not come through the Agent
// gateway (which trust-gates those headers and injects the HMAC proxy
// token). These tests pin verifyAgentProxyAuth's semantics (an exact mirror
// of the audit-tool-call enforcement) and the createOverrideHandler wiring,
// including the B4-style adversarial case: a direct caller with a forged
// X-User-Email is rejected BEFORE any identity or DB work.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"

	"axonflow/platform/shared/serviceauth"
)

const proxyGuardTestSecret = "ws1b-proxy-guard-test-secret-32-bytes!!"

// installProxyTokenValidator swaps the package validator and restores it.
func installProxyTokenValidator(t *testing.T, secret string) {
	t.Helper()
	orig := proxyTokenValidator
	if secret == "" {
		proxyTokenValidator = nil
	} else {
		proxyTokenValidator = serviceauth.NewTokenValidator(secret, nil, serviceauth.DefaultClockSkew)
	}
	t.Cleanup(func() { proxyTokenValidator = orig })
}

func validProxyToken(t *testing.T) string {
	t.Helper()
	return serviceauth.GetInternalServiceToken(serviceauth.NewTokenGenerator(proxyGuardTestSecret, nil))
}

func TestVerifyAgentProxyAuth(t *testing.T) {
	mk := func(token string) *http.Request {
		r := httptest.NewRequest("POST", "/api/v1/overrides", nil)
		if token != "" {
			r.Header.Set("X-Axonflow-Proxy-Auth", token)
		}
		return r
	}

	t.Run("community + no validator → skip (secret optional)", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "community")
		installProxyTokenValidator(t, "")
		if ok, _ := verifyAgentProxyAuth(mk(""), "test"); !ok {
			t.Error("community without secret must skip")
		}
	})

	t.Run("non-community + no validator → fail closed (misconfigured)", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "enterprise")
		installProxyTokenValidator(t, "")
		ok, msg := verifyAgentProxyAuth(mk(""), "test")
		if ok || !strings.Contains(msg, "not configured") {
			t.Errorf("enterprise without secret must fail closed, got ok=%v msg=%q", ok, msg)
		}
	})

	t.Run("validator set + missing token → direct access blocked", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "enterprise")
		installProxyTokenValidator(t, proxyGuardTestSecret)
		ok, msg := verifyAgentProxyAuth(mk(""), "test")
		if ok || !strings.Contains(msg, "routed through AxonFlow Agent") {
			t.Errorf("missing token must be blocked with an actionable message, got ok=%v msg=%q", ok, msg)
		}
	})

	t.Run("validator set + forged token → blocked", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "enterprise")
		installProxyTokenValidator(t, proxyGuardTestSecret)
		ok, msg := verifyAgentProxyAuth(mk("forged-token"), "test")
		if ok || !strings.Contains(msg, "invalid proxy authentication") {
			t.Errorf("forged token must be blocked, got ok=%v msg=%q", ok, msg)
		}
	})

	t.Run("validator set + valid token → proceeds (all modes)", func(t *testing.T) {
		for _, mode := range []string{"enterprise", "community"} {
			t.Setenv("DEPLOYMENT_MODE", mode)
			installProxyTokenValidator(t, proxyGuardTestSecret)
			if ok, _ := verifyAgentProxyAuth(mk(validProxyToken(t)), "test"); !ok {
				t.Errorf("mode=%s: valid token must proceed", mode)
			}
		}
	})
}

// TestCreateOverrideHandler_DirectAccessForgedIdentityBlocked is the B4
// adversarial case on the orchestrator ingress: a NON-agent caller supplies
// a forged X-User-Email (the identity that would KEY the override) — the
// request must be rejected by proxy-auth before the identity is even read.
func TestCreateOverrideHandler_DirectAccessForgedIdentityBlocked(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	body, _ := json.Marshal(CreateOverrideRequest{
		PolicyID:       "pol-1",
		PolicyType:     "static",
		OverrideReason: "attacker-supplied",
	})
	req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(string(body)))
	req.Header.Set("X-Tenant-ID", "victim-tenant")
	req.Header.Set("X-User-Email", "victim@corp.example") // forged, no proxy token

	rr := httptest.NewRecorder()
	createOverrideHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("SECURITY: direct forged override-create not blocked: status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "routed through AxonFlow Agent") {
		t.Errorf("403 body should name the agent-routing requirement, got %s", rr.Body.String())
	}
}

// TestCreateOverrideHandler_ValidProxyTokenReachesIdentityCheck proves the
// guard does not break the legitimate agent-routed path: with a valid proxy
// token the handler proceeds PAST the proxy-auth gate to its existing
// identity validation (here: missing X-User-Email → 401, the pre-existing
// behavior), rather than 403-ing at the gate.
func TestCreateOverrideHandler_ValidProxyTokenReachesIdentityCheck(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	body, _ := json.Marshal(CreateOverrideRequest{
		PolicyID:       "pol-1",
		PolicyType:     "static",
		OverrideReason: "legit",
	})
	req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(string(body)))
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set("X-Tenant-ID", "tenant-x")
	// No X-User-Email → pre-existing 401 (NOT the 403 proxy-auth gate).

	rr := httptest.NewRecorder()
	createOverrideHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("valid proxy token must reach identity check (401), got %d; body=%s", rr.Code, rr.Body.String())
	}
}

// TestCreateOverrideHandler_CommunityModeSkipsProxyAuth confirms Community
// mode (no internal-service secret) is exempt, matching audit-tool-call, so
// local single-trust-domain deployments keep working.
func TestCreateOverrideHandler_CommunityModeSkipsProxyAuth(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	installProxyTokenValidator(t, "")

	body, _ := json.Marshal(CreateOverrideRequest{
		PolicyID:       "pol-1",
		PolicyType:     "static",
		OverrideReason: "local",
	})
	req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(string(body)))
	req.Header.Set("X-Tenant-ID", "tenant-x")
	// No proxy token, no user email: must pass the proxy gate (community) and
	// hit the pre-existing 401 identity check — NOT a 403.
	rr := httptest.NewRecorder()
	createOverrideHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("community mode must skip proxy-auth and reach identity check (401), got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// #2896 WS1c — the checkpoint-resume override-hijack chain.
// ---------------------------------------------------------------------------

// TestApplyOverrideToResult_IsIdentityKeyed_TheSink demonstrates the SINK the
// checkpoint-resume chain feeds: ApplyOverrideToResult flips a DENY to ALLOW
// when the passed actor identity (in the exploit: the checkpoint's stored
// cp.UserID, seeded from a forged X-User-Id) has an active override on a
// non-critical overridable policy. This is why a forged identity reaching the
// resume is a deny→allow hijack — and why WS1c gates the identity at the agent
// AND requires proxy-auth on the resume ingresses so this identity can never
// be attacker-controlled. Mutation reference: this is the behavior the two
// guards prevent an attacker from triggering with a victim's identity.
func TestApplyOverrideToResult_IsIdentityKeyed_TheSink(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	// The victim has an active "allow" override on the blocking policy.
	// #3048: the lookup runs org-scoped.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org"). // ApplyOverrideToResult passes orgID as the scope key (R3 HIGH-3)
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT id, policy_id, policy_type`).
		WithArgs("sys_block_marker", "victim@corp.example", "tenant-shared", "").
		WillReturnRows(sqlmock.NewRows([]string{"id", "policy_id", "policy_type", "tool_signature", "override_reason", "expires_at"}).
			AddRow("ovr-victim", "sys_block_marker", "dynamic", "", "victim needed it", nil))
	mock.ExpectCommit()

	result := &PolicyEvaluationResult{
		Allowed: false,
		AppliedPoliciesDetail: []AppliedPolicyDetail{
			{PolicyID: "sys_block_marker", RiskLevel: "low", AllowOverride: true},
		},
	}
	// Passing the VICTIM identity (what a hijacked checkpoint would carry)
	// flips the deny — proving the sink is identity-keyed and real.
	applied, ov := ApplyOverrideToResult(context.Background(), mockDB, nil, result, "tenant-shared", "org", "victim@corp.example", "")
	if !applied || ov == nil || ov.ID != "ovr-victim" {
		t.Fatalf("victim's override must apply when the resume feeds the victim identity (applied=%v ov=%v)", applied, ov)
	}
	if !result.Allowed || !result.OverrideApplied {
		t.Fatal("deny must have flipped to allow via the victim override — this is the hijack WS1c prevents by gating the identity")
	}

	// Control: the SAME denied result with the attacker's own (override-less)
	// identity does NOT flip — the exploit's whole value is borrowing the
	// victim's identity, which the WS1c guards make unreachable.
	mock2DB, mock2, _ := sqlmock.New()
	defer mock2DB.Close()
	mock2.ExpectBegin()
	mock2.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org"). // ApplyOverrideToResult passes orgID as the scope key (R3 HIGH-3)
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock2.ExpectQuery(`SELECT id, policy_id, policy_type`).
		WithArgs("sys_block_marker", "attacker@corp.example", "tenant-shared", "").
		WillReturnRows(sqlmock.NewRows([]string{"id", "policy_id", "policy_type", "tool_signature", "override_reason", "expires_at"}))
	mock2.ExpectRollback()
	result2 := &PolicyEvaluationResult{
		Allowed:               false,
		AppliedPoliciesDetail: []AppliedPolicyDetail{{PolicyID: "sys_block_marker", RiskLevel: "low", AllowOverride: true}},
	}
	if applied2, _ := ApplyOverrideToResult(context.Background(), mock2DB, nil, result2, "tenant-shared", "org", "attacker@corp.example", ""); applied2 || result2.Allowed {
		t.Error("attacker's own identity has no override — deny must stand (confirms the value is in borrowing the victim identity)")
	}
}

// TestResumePlanHandler_DirectAccessBlocked is the B4 case on the MAP
// plan-resume ingress: a direct (non-agent) caller in Enterprise mode is
// rejected before the handler forwards the request's X-User-Id into the
// checkpoint's actor identity. Mutation: removing the resumePlanHandler
// proxy-auth check lets the direct request through.
func TestResumePlanHandler_DirectAccessBlocked(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	req := httptest.NewRequest("POST", "/api/v1/plan/plan-1/resume", strings.NewReader(`{"approved":true}`))
	req = mux.SetURLVars(req, map[string]string{"id": "plan-1"})
	req.Header.Set("X-User-Id", "victim@corp.example") // forged actor, no proxy token
	rr := httptest.NewRecorder()
	resumePlanHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("SECURITY: direct plan-resume not blocked: status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "routed through AxonFlow Agent") {
		t.Errorf("403 body should name the agent-routing requirement, got %s", rr.Body.String())
	}
}

// TestResumePlanHandler_ValidProxyTokenPastGate proves the guard doesn't break
// the legit agent-routed path: with a valid proxy token the handler proceeds
// PAST proxy-auth to its downstream nil-service checks (503 here), not 403.
func TestResumePlanHandler_ValidProxyTokenPastGate(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	req := httptest.NewRequest("POST", "/api/v1/plan/plan-1/resume", strings.NewReader(`{"approved":true}`))
	req = mux.SetURLVars(req, map[string]string{"id": "plan-1"})
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	rr := httptest.NewRecorder()
	resumePlanHandler(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Fatalf("valid proxy token must pass the resume proxy-auth gate, got 403: %s", rr.Body.String())
	}
}

// TestExecutePlanHandler_DirectAccessBlocked (#2896 WS1c, R3-CRITICAL fix):
// the MAP confirm-mode execute path persists a resumable checkpoint whose
// actor identity keys a later override apply. A direct (non-agent) caller in
// Enterprise mode must be rejected before that checkpoint-write path.
// Mutation: removing the executePlanHandler proxy-auth check lets the direct
// request through to the workflow-engine nil check (503) or further.
func TestExecutePlanHandler_DirectAccessBlocked(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	// Forge the checkpoint actor identity in the BODY (the channel the header
	// gate does not cover) — must never be reached without proxy-auth.
	body := `{"query":"x","execution_mode":"auto","user":{"id":1,"email":"victim@corp.example"},"context":{"plan_id":"p1"}}`
	req := httptest.NewRequest("POST", "/api/v1/plan/execute", strings.NewReader(body))
	rr := httptest.NewRecorder()
	executePlanHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("SECURITY: direct plan-execute not blocked: status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "routed through AxonFlow Agent") {
		t.Errorf("403 body should name the agent-routing requirement, got %s", rr.Body.String())
	}
}

// TestApplyAuthoritativeIdentity_EmailFromHeaderNeverBody (#2896 WS1c,
// R3-CRITICAL fix): the actor email that seeds a checkpoint must come from the
// trust-gated X-User-Email header, NEVER the forgeable request body. Mutation:
// dropping the `req.User.Email = header` line lets the body's victim identity
// through to the checkpoint.
func TestApplyAuthoritativeIdentity_EmailFromHeaderNeverBody(t *testing.T) {
	t.Run("header present → header wins over body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/plan/execute", nil)
		req.Header.Set("X-Tenant-ID", "t1")
		req.Header.Set("X-User-Email", "dev@corp.example")
		pr := &PlanRequest{User: UserContext{Email: "victim@corp.example"}}
		applyAuthoritativeIdentity(req, pr)
		if pr.User.Email != "dev@corp.example" {
			t.Errorf("actor email must come from the trusted header, got %q", pr.User.Email)
		}
	})

	t.Run("header absent (gate off) → body email is dropped, not trusted", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/plan/execute", nil)
		req.Header.Set("X-Tenant-ID", "t1")
		// No X-User-Email (the agent stripped it under gate off).
		pr := &PlanRequest{User: UserContext{Email: "victim@corp.example"}}
		applyAuthoritativeIdentity(req, pr)
		if pr.User.Email != "" {
			t.Errorf("body-supplied actor email must be dropped when the gate stripped the header, got %q", pr.User.Email)
		}
	})
}
