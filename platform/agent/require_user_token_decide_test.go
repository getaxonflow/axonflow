// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3476 Phase B — /decide gate: when the caller's org resolves
// require_user_token=true, a token-less AuthKindEnterprise caller must be
// REJECTED at authentication (401, audited "user_token_required") instead of
// synthesized into a service identity. A PRESENTED-but-invalid token must keep
// auditing "user_token_rejected" (#3472) unchanged, in both directions of the
// flag.
//
// These tests drive handleDecide directly (decideEnterpriseReq, mirroring
// TestHandleDecide_EnterpriseMode_ServiceCaller_NoUserToken /
// TestHandleDecide_AuditsUserTokenRejected_AsBlocked in decision_handler_test.go)
// and wire the require_user_token resolver via installTestRequireUserTokenCache
// (require_user_token_test.go) so no real DB is needed.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

const rutDecideOrg = "rut-decide-org"

// rutInstallCache wires the require_user_token resolver with an explicit
// per-org row, for the duration of the test.
func rutInstallCache(t *testing.T, orgID string, required bool) {
	t.Helper()
	t.Setenv(EnvRequireUserToken, "") // env default false: any `true` below can only come from the row
	installTestRequireUserTokenCache(t,
		&fakeRequireUserTokenReader{rows: map[string]bool{orgID: required}}, time.Minute)
}

// rutInstallCacheErr wires the resolver to fail every read, proving the
// fail-closed contract at a real gate point (not just the resolver's own unit
// tests in require_user_token_test.go).
func rutInstallCacheErr(t *testing.T) {
	t.Helper()
	t.Setenv(EnvRequireUserToken, "") // env default false: a resulting `true` can only be fail-closed
	installTestRequireUserTokenCache(t,
		&fakeRequireUserTokenReader{err: errors.New("db down")}, time.Minute)
}

// --- 1. Flag OFF: compatibility path intact (MAJOR-semver claim). ---

func TestHandleDecide_RequireUserToken_FlagOff_AbsentToken_StillSynthesizesServiceUser(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)
	rutInstallCache(t, rutDecideOrg, false)

	req := decideEnterpriseReq(t, DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{GatewayID: "llm-gateway-01"},
		Target:         DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:          "hello",
		// user_token intentionally empty.
	}, "ent-tenant", rutDecideOrg)
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("flag off: service-caller path must still succeed: got HTTP %d; body=%s", rr.Code, rr.Body.String())
	}
	var resp DecideResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v -- body=%s", err, rr.Body.String())
	}
	if resp.Verdict != VerdictAllow {
		t.Errorf("verdict: got %q want %q", resp.Verdict, VerdictAllow)
	}
}

// --- 2. Flag ON: a token-less enterprise caller is rejected 401, audited
// under the NEW "user_token_required" marker (distinct from "user_token_rejected"). ---

func TestHandleDecide_RequireUserToken_FlagOn_AbsentToken_401_AuditsUserTokenRequired(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	rutInstallCache(t, rutDecideOrg, true)
	mock := withMockUsageDB(t)

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(decideAuditInsertArgs(AuditVerdictBlocked,
			decideSecurityDetailsMatcher{wantEvent: "user_token_required"})...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := decideEnterpriseReq(t, DecideRequest{
		Stage:  DecisionStageLLM,
		Target: DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:  "hello",
		// user_token intentionally empty -- the case under test.
	}, "ent-tenant", rutDecideOrg)
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("required-but-absent token must write a blocked audit row carrying user_token_required: %v", err)
	}
}

// --- 3. Flag ON: a caller presenting a VALID token is unaffected (served,
// not 401). The control proving the refusal is conditional on token-ABSENCE,
// not a blanket tightening. ---

func TestHandleDecide_RequireUserToken_FlagOn_ValidToken_Unaffected(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)
	rutInstallCache(t, rutDecideOrg, true)

	origSecret := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = origSecret })
	token := mintUserTokenWithTenant(t, "ent-tenant")

	req := decideEnterpriseReq(t, DecideRequest{
		Stage:     DecisionStageLLM,
		Target:    DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:     "hello",
		UserToken: token,
	}, "ent-tenant", rutDecideOrg)
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("flag on + valid token: must be served, not rejected: got HTTP %d; body=%s", rr.Code, rr.Body.String())
	}
}

// --- 4. Flag ON: a presented-but-INVALID token still audits as
// "user_token_rejected", never "user_token_required" -- the two causes must
// not collapse (#3472 behaviour is byte-identical regardless of the flag). ---

func TestHandleDecide_RequireUserToken_FlagOn_InvalidToken_StillAuditsUserTokenRejected(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	rutInstallCache(t, rutDecideOrg, true)
	origSecret := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = origSecret })
	mock := withMockUsageDB(t)

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(decideAuditInsertArgs(AuditVerdictBlocked,
			decideSecurityDetailsMatcher{wantEvent: "user_token_rejected"})...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := decideEnterpriseReq(t, DecideRequest{
		Stage:     DecisionStageLLM,
		Target:    DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:     "hello",
		UserToken: "not.a.valid.jwt",
	}, "ent-tenant", rutDecideOrg)
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("rejected user_token must still write user_token_rejected, not user_token_required, with the flag on: %v", err)
	}
}

// --- 5. An unreadable posture fails closed at THIS gate point: a token-less
// enterprise caller is rejected when the org-posture read errors. ---

func TestHandleDecide_RequireUserToken_ReaderError_FailsClosed_AbsentTokenRejected(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	rutInstallCacheErr(t)
	mock := withMockUsageDB(t)

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(decideAuditInsertArgs(AuditVerdictBlocked,
			decideSecurityDetailsMatcher{wantEvent: "user_token_required"})...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := decideEnterpriseReq(t, DecideRequest{
		Stage:  DecisionStageLLM,
		Target: DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:  "hello",
	}, "ent-tenant", rutDecideOrg)
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("posture-read error must fail closed: got HTTP %d want 401; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("fail-closed rejection must still audit user_token_required: %v", err)
	}
}
