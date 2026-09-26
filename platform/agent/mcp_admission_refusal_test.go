// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent/license"
	"axonflow/platform/agent/license/admission"
)

// #4249 row 5682255301: the MCP server answers a tier admission refusal (a
// VALID credential past its organization's ceiling) in the tier-family
// envelope with its own status, never as the 401 "Authentication required".
// The requests below go through the registered MCP router and the real Authenticate on
// a Community deployment whose organization is at its service-principal
// ceiling, the shape the row measured.

const mcpAdmissionTestOrg = "org-4249-mcp-admission"

// fillServicePrincipalCeiling wires a Community admitter and admits the
// organization's whole service-principal allowance, so the next unadmitted
// client id is refused.
func fillServicePrincipalCeiling(t *testing.T) *admission.MemoryLedger {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ORG_ID", mcpAdmissionTestOrg)
	mem := wireMemoryAdmitter(t, license.TierCommunity)
	for i := 0; i < license.CommunityLimits.MaxServicePrincipals; i++ {
		if ref := admitPrincipal(context.Background(), admission.ServicePrincipal, mcpAdmissionTestOrg, fmt.Sprintf("admitted-%d", i)); ref != nil {
			t.Fatalf("admitting principal %d under the ceiling was refused: %v", i, ref)
		}
	}
	return mem
}

// admissionPost sends one JSON-RPC call through the registered MCP server
// router with a Basic credential for clientID (a community agent checks no
// secret, so the client id is the principal).
func admissionPost(t *testing.T, clientID, method string, params interface{}) *httptest.ResponseRecorder {
	t.Helper()
	return mcpServerPost(t, setupMCPServerRouter(), method, "4249-"+method, params,
		"Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":wrong")))
}

// assertAdmissionAnswer asserts the ruled answer: the status, the tier-family
// headers, Retry-After exactly when the refusal is the outage one, no
// WWW-Authenticate, and the envelope carrying the refusal's own code.
func assertAdmissionAnswer(t *testing.T, rr *httptest.ResponseRecorder, wantStatus int, wantRetry string, dim admission.Dimension, wantCode string) {
	t.Helper()
	if rr.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body: %s", rr.Code, wantStatus, rr.Body.String())
	}
	if got := rr.Header().Get("Retry-After"); got != wantRetry {
		t.Errorf("Retry-After = %q, want %q", got, wantRetry)
	}
	if got := rr.Header().Get("X-Axonflow-Tier-Limit"); got != string(dim) {
		t.Errorf("X-Axonflow-Tier-Limit = %q, want %q", got, dim)
	}
	if got := rr.Header().Get("X-Axonflow-Upgrade-URL"); got != v1ProUpgradeCompareURL {
		t.Errorf("X-Axonflow-Upgrade-URL = %q, want %q", got, v1ProUpgradeCompareURL)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q: a tier refusal is not an authentication challenge", got)
	}
	env := decodeMCPEnvelope(t, rr)
	if env.Code != wantCode {
		t.Errorf("envelope.code = %q, want %q", env.Code, wantCode)
	}
	if env.LimitType != string(dim) {
		t.Errorf("envelope.limit_type = %q, want %q", env.LimitType, dim)
	}
	if !strings.HasPrefix(env.Error, wantCode+":") {
		t.Errorf("envelope.error = %q, want it to begin with %q", env.Error, wantCode+":")
	}
	if env.Error != env.Upgrade.Wording {
		t.Errorf("envelope.error %q and upgrade.wording %q differ", env.Error, env.Upgrade.Wording)
	}
	if env.Upgrade.BuyURL != "" {
		t.Errorf("envelope.upgrade.buy_url = %q: the Plugin Pro buy link lifts no edition ceiling", env.Upgrade.BuyURL)
	}
	if env.Remaining != 0 {
		t.Errorf("envelope.remaining = %d, want 0", env.Remaining)
	}
}

func TestMCPServer_ServicePrincipalCeiling_IsATierRefusalNotA401(t *testing.T) {
	cases := []struct {
		method string
		params interface{}
	}{
		{"initialize", map[string]interface{}{"protocolVersion": "2025-03-26", "clientInfo": map[string]string{"name": "t", "version": "1"}}},
		{"tools/list", nil},
		{"tools/call", map[string]interface{}{"name": "check_policy", "arguments": map[string]interface{}{"connector_type": "postgres", "statement": "select 1"}}},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			fillServicePrincipalCeiling(t)
			rr := admissionPost(t, "unadmitted-client", tc.method, tc.params)
			assertAdmissionAnswer(t, rr, http.StatusForbidden, "", admission.ServicePrincipal, "ERR_TIER_LIMIT_SERVICE_PRINCIPAL")
			env := decodeMCPEnvelope(t, rr)
			if env.Limit != license.CommunityLimits.MaxServicePrincipals {
				t.Errorf("envelope.limit = %d, want %d", env.Limit, license.CommunityLimits.MaxServicePrincipals)
			}
			if env.Tier != "community" {
				t.Errorf("envelope.tier = %q, want the edition, community", env.Tier)
			}
		})
	}
}

// The outage refusal (the ledger cannot admit an unseen principal) is a window
// that passes: 429 with the admission's Retry-After.
func TestMCPServer_AdmissionLedgerOutage_Is429WithRetryAfter(t *testing.T) {
	for _, method := range []string{"initialize", "tools/list"} {
		t.Run(method, func(t *testing.T) {
			mem := fillServicePrincipalCeiling(t)
			mem.SetDown(true)
			rr := admissionPost(t, "unseen-during-outage", method, nil)
			assertAdmissionAnswer(t, rr, http.StatusTooManyRequests,
				fmt.Sprint(int(admission.RetryAfter.Seconds())), admission.ServicePrincipal, "ERR_TIER_LIMIT_SERVICE_PRINCIPAL")
		})
	}
}

// The control: an admitted client id at the same ceiling is served, so the
// cells above are refusing the principal, not the request.
func TestMCPServer_AdmittedPrincipalAtTheCeilingIsServed(t *testing.T) {
	fillServicePrincipalCeiling(t)
	rr := admissionPost(t, "admitted-0", "tools/list", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("an admitted principal was answered %d: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Axonflow-Tier-Limit") != "" {
		t.Errorf("an admitted principal's answer carries X-Axonflow-Tier-Limit")
	}
}

// Every other authentication failure keeps the 401: only a tier admission
// refusal is re-classed.
func TestMCPServer_NonAdmissionAuthFailureKeeps401(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise") // real auth required; no credential below
	rr := mcpServerPost(t, setupMCPServerRouter(), "tools/list", "x", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Axonflow-Tier-Limit") != "" {
		t.Error("an unauthenticated call carries X-Axonflow-Tier-Limit")
	}
}

// The HUMAN-principal refusal (a validated per-user token past the ceiling)
// travels as a *tierLimitRefusal rather than an *AuthError; both forms are
// recognised and answered alike, with the human_principal dimension.
func TestAdmissionRefusalOf_BothForms(t *testing.T) {
	human := admission.Decision{
		Dimension: admission.HumanPrincipal, Reason: admission.ReasonOverLimit,
		Code: "ERR_TIER_LIMIT_HUMAN_PRINCIPAL", Edition: "community", Limit: 25, Count: 25,
	}
	service := admission.Decision{
		Dimension: admission.ServicePrincipal, Reason: admission.ReasonDependencyUnreachable,
		Code: "ERR_TIER_LIMIT_SERVICE_PRINCIPAL", Edition: "community", RetryAfter: admission.RetryAfter,
	}
	cases := []struct {
		name       string
		err        error
		want       admission.Decision
		wantStatus int
		wantRetry  string
	}{
		{"human principal, *tierLimitRefusal", &tierLimitRefusal{Decision: human}, human, http.StatusForbidden, ""},
		{"human principal, wrapped", fmt.Errorf("resolve: %w", &tierLimitRefusal{Decision: human}), human, http.StatusForbidden, ""},
		{"service principal, *AuthError", (&tierLimitRefusal{Decision: service}).AuthError(), service, http.StatusTooManyRequests, "30"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := admissionRefusalOf(tc.err)
			if !ok || got.Code != tc.want.Code || got.Dimension != tc.want.Dimension {
				t.Fatalf("admissionRefusalOf = %+v, %v; want %+v", got, ok, tc.want)
			}
			rr := httptest.NewRecorder()
			if !writeMCPAdmissionRefused(rr, "id", tc.err) {
				t.Fatal("writeMCPAdmissionRefused returned false for a tier refusal")
			}
			assertAdmissionAnswer(t, rr, tc.wantStatus, tc.wantRetry, tc.want.Dimension, tc.want.Code)

			// The session DELETE answers with no body, same status and headers.
			nb := httptest.NewRecorder()
			if !writeMCPAdmissionRefusedNoBody(nb, tc.err) {
				t.Fatal("writeMCPAdmissionRefusedNoBody returned false for a tier refusal")
			}
			if nb.Code != tc.wantStatus || nb.Header().Get("Retry-After") != tc.wantRetry ||
				nb.Header().Get("X-Axonflow-Tier-Limit") != string(tc.want.Dimension) || nb.Body.Len() != 0 {
				t.Errorf("no-body answer = %d Retry-After=%q Tier-Limit=%q body=%q",
					nb.Code, nb.Header().Get("Retry-After"), nb.Header().Get("X-Axonflow-Tier-Limit"), nb.Body.String())
			}
		})
	}
	for _, other := range []error{
		nil,
		errors.New("invalid user token: expired"),
		&AuthError{Code: "invalid_credentials", HTTPStatus: http.StatusUnauthorized},
		&AuthError{Code: "rate_limited", HTTPStatus: http.StatusTooManyRequests, RetryAfter: "60"},
	} {
		rr := httptest.NewRecorder()
		if writeMCPAdmissionRefused(rr, "id", other) || writeMCPAdmissionRefusedNoBody(rr, other) {
			t.Errorf("%v was answered as a tier refusal", other)
		}
	}
}

// tools/call files the refusal as the tier limit (the decide plane's
// tier_limit_refused marker), not as unauthenticated.
func TestHandleMCPToolsCall_TierRefusal_AuditsAsTierLimit(t *testing.T) {
	fillServicePrincipalCeiling(t)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	orig := usageDB
	usageDB = db
	t.Cleanup(func() { usageDB = orig })

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), 0,
			sqlmock.AnyArg(), "service", sqlmock.AnyArg(),
			mcpUnauthenticatedTenant, "",
			"mcp_tools_call", "mcp tools/call: tier admission refused", sqlmock.AnyArg(),
			mcpVerdictBlocked,
			detailsNaming{"tier_limit_refused", "tier admission refused"},
			sqlmock.AnyArg(),
			PlaneMCP,
			nil, nil,
			nil,
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	rr := admissionPost(t, "unadmitted-client", "tools/call",
		map[string]interface{}{"name": "check_policy", "arguments": map[string]interface{}{"connector_type": "postgres", "statement": "select 1"}})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rr.Code, rr.Body.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for mock.ExpectationsWereMet() != nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the tier refusal was not audited as tier_limit_refused: %v", err)
	}
}

// The session DELETE route carries no JSON-RPC body, so it answers the refusal
// as the status and the tier headers alone (writeMCPAdmissionRefusedNoBody).
// This is the route-level cell for that arm: the whole handler, through the
// registered router, on a Community deployment at its service-principal
// ceiling - where every other MCP route already refuses, and where this one
// answered 200 and DELETED the session until the admission read moved above
// the community branch.
func TestMCPSessionDelete_ATierRefusalIsAnsweredAsTheTierLimitAndKeepsTheSession(t *testing.T) {
	fillServicePrincipalCeiling(t)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	t.Cleanup(func() { usageDB = origDB })

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			"mcp_session_delete", sqlmock.AnyArg(), sqlmock.AnyArg(),
			mcpVerdictBlocked,
			detailsNaming{"tier_limit_refused", "tier admission refused"},
			sqlmock.AnyArg(), PlaneMCP,
			nil, nil, nil,
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	now := time.Now()
	sessionID := "sess-4249-admission-delete"
	cacheMCPSession(t, &mcpSession{id: sessionID, createdAt: now, lastUsed: now,
		tenantID: mcpAdmissionTestOrg, orgID: mcpAdmissionTestOrg, clientID: "admitted-0"})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/mcp-server", nil)
	req.Header.Set(mcpSessionHeaderKey, sessionID)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("unadmitted-delete-client:wrong")))
	w := httptest.NewRecorder()
	setupMCPServerRouter().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (the boundary refusal), body: %q", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Axonflow-Tier-Limit"); got != string(admission.ServicePrincipal) {
		t.Errorf("X-Axonflow-Tier-Limit = %q, want %q", got, admission.ServicePrincipal)
	}
	if got := w.Header().Get("X-Axonflow-Upgrade-URL"); got != v1ProUpgradeCompareURL {
		t.Errorf("X-Axonflow-Upgrade-URL = %q, want %q", got, v1ProUpgradeCompareURL)
	}
	if got := w.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q: a ceiling with no reset is not a window that passes", got)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q: a tier refusal is not an authentication challenge", got)
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("body = %q, want empty: a DELETE carries no JSON-RPC body", body)
	}
	if getSessionByID(sessionID) == nil {
		t.Error("a refused DELETE removed the session")
	}
	deadline := time.Now().Add(2 * time.Second)
	for mock.ExpectationsWereMet() != nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the refused DELETE was not audited as tier_limit_refused: %v", err)
	}
}
