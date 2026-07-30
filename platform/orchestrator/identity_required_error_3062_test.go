// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3062 — the override 401 must name its cause.
//
// `axonflow_create_override` / `axonflow_revoke_override` are two of the
// eleven agent tools every host plugin advertises, and both were dead out of
// the box on a default self-hosted community stack AND on Community SaaS: the
// agent strips X-User-Email unless AXONFLOW_TRUST_IDENTITY_HEADERS is exactly
// "true" (default off since 9.9.0), so the orchestrator saw no identity and
// answered `401 Authenticated user identity required (X-User-Email header)` —
// telling the user to send the header they had just sent.
//
// The DoD for this fix is a matched pair:
//   - gate OFF ⇒ still 401, but the body names the cause and the remedy;
//   - gate ON  ⇒ 201, the control proving the diagnosis was right.
//
// The gate itself lives in the agent, so the pair is asserted across two
// packages: platform/agent TestGateProxyIdentityHeaders_* proves gate ON
// forwards the identity and gate OFF drops it and stamps the marker; the tests
// below prove what the orchestrator does with each of those two outcomes.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"

	sharedidentity "axonflow/platform/shared/identity"
)

// assertActionableIdentityError checks the properties that make the body
// useful to the person reading it: it must name the flag, the remedy, and
// where to read more — and must not be the old dead-end sentence.
func assertActionableIdentityError(t *testing.T, body string) {
	t.Helper()
	for _, want := range []string{
		sharedidentity.EnvVar,          // the flag that governs the behavior
		"X-User-Token",                 // the alternative remedy
		sharedidentity.TrustDocRef,     // where to read the security tradeoff
		"scoped to an individual user", // why identity is required at all
	} {
		if !strings.Contains(body, want) {
			t.Errorf("401 body must mention %q, got: %s", want, body)
		}
	}
	// The whole defect was a body that stopped at "send X-User-Email".
	if strings.TrimSpace(body) == "Authenticated user identity required (X-User-Email header)" {
		t.Error("401 body is still the pre-fix unactionable message")
	}
}

func errorBody(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error body: %v (raw %s)", err, rr.Body.String())
	}
	return resp.Error
}

func createOverrideBody() string {
	b, _ := json.Marshal(CreateOverrideRequest{
		PolicyID:       "pol-1",
		PolicyType:     "static",
		OverrideReason: "debugging a false positive",
	})
	return string(b)
}

// Gate OFF, marker present: this is the exact request the agent forwards when
// a plugin user runs /axonflow-override on a default deployment. The 401 must
// state that the platform removed an identity the caller DID send.
func TestCreateOverride_GateDropped_401NamesTheGateAsTheCause(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(createOverrideBody()))
	req.Header.Set("X-Tenant-ID", "tenant-x")
	// No X-User-Email: the agent already stripped it — and said so.
	req.Header.Set(sharedidentity.HeaderIdentityGated, sharedidentity.IdentityGatedTrue)

	rr := httptest.NewRecorder()
	createOverrideHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	body := errorBody(t, rr)
	assertActionableIdentityError(t, body)
	if !strings.Contains(body, "DID send") {
		t.Errorf("with the marker present the body must diagnose, not speculate; got: %s", body)
	}
}

// No marker: the caller reached the orchestrator without the agent's verdict.
// The body still has to name the gate — it is by far the most common cause —
// but as a possibility rather than a diagnosis.
func TestCreateOverride_NoMarker_401StillNamesTheGateAsAPossibility(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(createOverrideBody()))
	req.Header.Set("X-Tenant-ID", "tenant-x")

	rr := httptest.NewRecorder()
	createOverrideHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	body := errorBody(t, rr)
	assertActionableIdentityError(t, body)
	if strings.Contains(body, "DID send") {
		t.Errorf("without the marker the body must not claim to know the caller sent identity; got: %s", body)
	}
}

// Revoke is the other half of the lifecycle the plugins expose and failed the
// same opaque way.
func TestRevokeOverride_IdentityMissing_401IsActionable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		marker   bool
		wantDiag bool
	}{
		{"gate dropped the identity", true, true},
		{"no marker", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("DELETE", "/api/v1/overrides/ovr-1", nil)
			r.Header.Set("X-Tenant-ID", "tenant-x")
			if tc.marker {
				r.Header.Set(sharedidentity.HeaderIdentityGated, sharedidentity.IdentityGatedTrue)
			}
			r = mux.SetURLVars(r, map[string]string{"id": "ovr-1"})

			rr := httptest.NewRecorder()
			revokeOverrideHandler(rr, r)

			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rr.Code)
			}
			body := errorBody(t, rr)
			assertActionableIdentityError(t, body)
			if got := strings.Contains(body, "DID send"); got != tc.wantDiag {
				t.Errorf("diagnosed=%v, want %v; body: %s", got, tc.wantDiag, body)
			}
		})
	}
}

// The marker selects PROSE ONLY. Forging it (possible only by bypassing the
// agent, which deletes it) must not change the authorization outcome.
func TestIdentityGatedMarker_ChangesOnlyTheMessageNeverTheOutcome(t *testing.T) {
	statuses := map[bool]int{}
	for _, marker := range []bool{false, true} {
		req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(createOverrideBody()))
		req.Header.Set("X-Tenant-ID", "tenant-x")
		if marker {
			req.Header.Set(sharedidentity.HeaderIdentityGated, sharedidentity.IdentityGatedTrue)
		}
		rr := httptest.NewRecorder()
		createOverrideHandler(rr, req)
		statuses[marker] = rr.Code
	}
	if statuses[false] != statuses[true] {
		t.Fatalf("marker changed the outcome: without=%d with=%d — it must only select the message",
			statuses[false], statuses[true])
	}
}

// The marker is matched exactly, like the trust gate itself: a value that
// fails to parse must degrade to the generic message, never to a wrong
// diagnosis ("your client sent identity") that sends the operator hunting.
func TestIdentityRequiredMessage_MarkerIsExactMatch(t *testing.T) {
	for _, tc := range []struct {
		raw      string
		wantDiag bool
	}{
		{"true", true},
		{"  true  ", true}, // trimmed, per Parse's contract
		{"TRUE", false},
		{"1", false},
		{"yes", false},
		{"false", false},
		{"", false},
	} {
		t.Run("marker="+tc.raw, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api/v1/overrides", nil)
			if tc.raw != "" {
				r.Header.Set(sharedidentity.HeaderIdentityGated, tc.raw)
			}
			msg := identityRequiredMessage(r, "policy overrides")
			if got := strings.Contains(msg, "DID send"); got != tc.wantDiag {
				t.Errorf("marker %q: diagnosed=%v, want %v", tc.raw, got, tc.wantDiag)
			}
			// Either way the message stays actionable.
			assertActionableIdentityError(t, msg)
		})
	}
}

// R3 round 2: the no-marker branch must not assert deployment state it cannot
// observe. It is reached with the gate ON too — a caller who sent no identity,
// a value that sanitized away (deliberately unmarked), and EVERY
// MCP-server-plane request, because mcpProxyToOrchestrator builds a fresh
// request that carries no marker. Telling an operator who has already enabled
// the gate that the flag "is not true" is the same confidently-wrong diagnosis
// this file exists to remove, one layer over. It may state the DEFAULT — a
// fact about the release — but never the deployment's current value.
func TestIdentityRequiredMessage_GenericBranchDoesNotAssertDeploymentState(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/v1/overrides", nil) // no marker
	msg := identityRequiredMessage(r, "policy overrides")

	for _, forbidden := range []string{
		sharedidentity.EnvVar + " is not",
		"is not \"true\"",
		"has not declared",
	} {
		if strings.Contains(msg, forbidden) {
			t.Errorf("generic branch asserts a deployment state it cannot observe (%q): %s", forbidden, msg)
		}
	}
	// It must still name the flag and its default, or it stops being actionable.
	if !strings.Contains(msg, sharedidentity.EnvVar) || !strings.Contains(msg, "defaults to off") {
		t.Errorf("generic branch must name the flag and its default: %s", msg)
	}
	assertActionableIdentityError(t, msg)
}

// The MARKED branch may be assertive: the agent only stamps the marker when the
// gate is off, so "this deployment has not declared its source trusted" is an
// observed fact there, not a guess.
func TestIdentityRequiredMessage_MarkedBranchMayAssertTheGateIsOff(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/v1/overrides", nil)
	r.Header.Set(sharedidentity.HeaderIdentityGated, sharedidentity.IdentityGatedTrue)
	msg := identityRequiredMessage(r, "policy overrides")
	if !strings.Contains(msg, "DID send") {
		t.Errorf("marked branch must diagnose: %s", msg)
	}
	assertActionableIdentityError(t, msg)
}

// The control that proves the diagnosis: with a per-user identity present —
// which is exactly what the agent forwards once AXONFLOW_TRUST_IDENTITY_HEADERS=true
// (platform/agent TestGateProxyIdentityHeaders_*) — the same request that 401'd
// above creates the override and returns 201.
//
// Community mode + no proxy validator mirrors a default self-hosted stack,
// which verifyAgentProxyAuth exempts; that is the deployment the issue was
// reported on.
func TestCreateOverride_WithIdentity_Creates201(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	origValidator := proxyTokenValidator
	proxyTokenValidator = nil
	t.Cleanup(func() { proxyTokenValidator = origValidator })

	origAudit := auditLogger
	auditLogger = nil
	t.Cleanup(func() { auditLogger = origAudit })

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	t.Cleanup(func() { usageDB = origDB })

	// policyRiskAndOverride: tenant-scoped pass resolves the policy.
	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
		WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT risk_level, allow_override, id::text").
		WithArgs("pol-1", "tenant-x").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "id"}).
			AddRow("medium", true, "11111111-1111-1111-1111-111111111111"))
	mock.ExpectCommit()

	// The override INSERT, org-scoped (mig 110 RLS key).
	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
		WithArgs("org-x").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO policy_overrides").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(createOverrideBody()))
	req.Header.Set("X-Tenant-ID", "tenant-x")
	req.Header.Set("X-Org-ID", "org-x")
	req.Header.Set("X-User-Email", "dev@corp.example") // survives a gate that is ON
	// No marker: nothing was dropped.

	rr := httptest.NewRecorder()
	createOverrideHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rr.Code, rr.Body.String())
	}
	var resp CreateOverrideResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode 201 body: %v (raw %s)", err, rr.Body.String())
	}
	if resp.ID == "" || resp.ExpiresAt.IsZero() {
		t.Errorf("201 body must carry the created override, got %+v", resp)
	}
	// Both scoped statements must have run — a 201 with no INSERT would be a
	// vacuous control.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet SQL expectations — the override was not actually written: %v", err)
	}
}
