// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3476 Phase B — the four MCP REST routes (mcp_handler.go: mcpQueryHandler,
// mcpExecuteHandler, mcpCheckInputHandler, mcpCheckOutputHandler): when the
// caller's org resolves require_user_token=true, a token-less
// AuthKindEnterprise caller must be REJECTED (401) instead of synthesized
// into a service identity. #3472's presented-but-invalid-token rejection
// (audited "user_token_rejected") must stay byte-identical regardless of the
// flag; the NEW required-but-absent case gets its own marker,
// "user_token_required", so the two causes never collapse.
//
// Fixtures reused verbatim from mcp_rest_user_token_rejected_test.go (#3472):
// setupMCPUserTokenRejectedTest / utrInjectMintedWhitelistEntry (minted
// license, valid under BOTH the community and `-tags enterprise` builds) /
// utrDoQuery / utrDoExecute / utrDoCheckInput / utrDoCheckOutput /
// utrMintValidToken / utrPolicyIDsMatcher / utrAssertUserTokenRejected.
//
// Every writeMCPDecisionAudit call inserts exactly 20 positional audit_logs
// columns (mcp_richer_context.go); policy_details (JSONB) is column index 13
// (0-based) / the 14th value. rutAuditArgsWithPolicyMatcher below builds that
// 20-value list with every position AnyArg() except the policy_details match.

import (
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

const rutMCPRestOrg = "rut-mcprest-org"

// setupRUTMCPRestTest layers the require_user_token resolver on top of the
// #3472 whitelist fixture. The minted license carries no org_id claim, so
// auth.OrgID resolves to "" and ResolveRequireUserToken substitutes
// getDeploymentOrgID() -- pin ORG_ID so the fake reader has a known key.
func setupRUTMCPRestTest(t *testing.T) {
	t.Helper()
	t.Setenv("ORG_ID", rutMCPRestOrg)
	setupMCPUserTokenRejectedTest(t)
}

func rutInstallRestCache(t *testing.T, required bool) {
	t.Helper()
	t.Setenv(EnvRequireUserToken, "")
	installTestRequireUserTokenCache(t,
		&fakeRequireUserTokenReader{rows: map[string]bool{rutMCPRestOrg: required}}, time.Minute)
}

func rutInstallRestCacheErr(t *testing.T) {
	t.Helper()
	t.Setenv(EnvRequireUserToken, "")
	installTestRequireUserTokenCache(t,
		&fakeRequireUserTokenReader{err: errors.New("db down")}, time.Minute)
}

// rutAuditArgsWithPolicyMatcher builds the 20-value positional WithArgs list
// for a writeMCPDecisionAudit INSERT, with policy_details (index 13) pinned
// to matcher and every other column AnyArg().
func rutAuditArgsWithPolicyMatcher(matcher driver.Value) []driver.Value {
	args := make([]driver.Value, 20)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[13] = matcher
	return args
}

// =============================================================================
// 1. Flag OFF: compatibility path intact for all four routes (MAJOR-semver
// claim). mcp_rest_user_token_rejected_test.go's existing
// TestMCP*Handler_AbsentToken_CompatFallbackIntact tests already exercise
// this against the DEFAULT (no cache wired) resolution; these add the same
// proof with the cache explicitly wired and resolving false, so a regression
// in the wiring itself (not just the default) is caught too.
// =============================================================================

func TestMCPRestHandlers_RequireUserToken_FlagOff_AbsentToken_CompatIntact(t *testing.T) {
	cases := []struct {
		name       string
		do         func(t *testing.T) *httptest.ResponseRecorder
		wantStatus int
	}{
		{"query", func(t *testing.T) *httptest.ResponseRecorder { return utrDoQuery(t, "") }, utrQueryExecuteCompatStatus},
		{"execute", func(t *testing.T) *httptest.ResponseRecorder { return utrDoExecute(t, "") }, utrQueryExecuteCompatStatus},
		{"check-input", func(t *testing.T) *httptest.ResponseRecorder { return utrDoCheckInput(t, "") }, utrCheckInputOutputCompatStatus},
		{"check-output", func(t *testing.T) *httptest.ResponseRecorder { return utrDoCheckOutput(t, "") }, utrCheckInputOutputCompatStatus},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupRUTMCPRestTest(t)
			mock := withMockUsageDB(t)
			mock.MatchExpectationsInOrder(false)
			mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))
			rutInstallRestCache(t, false)

			w := tc.do(t)
			if w.Code != tc.wantStatus {
				t.Fatalf("flag off must leave the compat fallback intact: got %d want %d: %s", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

// =============================================================================
// 2. Flag ON: a token-less enterprise caller gets 401 on all four routes.
// =============================================================================

func TestMCPRestHandlers_RequireUserToken_FlagOn_AbsentToken_401(t *testing.T) {
	cases := []struct {
		name string
		do   func(t *testing.T) *httptest.ResponseRecorder
	}{
		{"query", func(t *testing.T) *httptest.ResponseRecorder { return utrDoQuery(t, "") }},
		{"execute", func(t *testing.T) *httptest.ResponseRecorder { return utrDoExecute(t, "") }},
		{"check-input", func(t *testing.T) *httptest.ResponseRecorder { return utrDoCheckInput(t, "") }},
		{"check-output", func(t *testing.T) *httptest.ResponseRecorder { return utrDoCheckOutput(t, "") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupRUTMCPRestTest(t)
			mock := withMockUsageDB(t)
			mock.MatchExpectationsInOrder(false)
			mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))
			rutInstallRestCache(t, true)

			w := tc.do(t)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("flag on + absent token must reject with 401, got %d: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "Invalid user token:") {
				t.Errorf("rejection message must be the user-token rejection shape, got: %s", w.Body.String())
			}
		})
	}
}

// =============================================================================
// 3. Flag ON: a caller presenting a VALID token is unaffected -- the control
// proving the refusal is conditional on token-ABSENCE, not a blanket
// tightening. Expected statuses mirror the established
// AbsentToken_CompatFallbackIntact fixtures (downstream connector-auth /
// static-policy outcomes unrelated to this gate) -- the only thing this proves
// is the ABSENCE of a 401 from the require_user_token gate itself.
// =============================================================================

func TestMCPRestHandlers_RequireUserToken_FlagOn_ValidToken_Unaffected(t *testing.T) {
	cases := []struct {
		name       string
		do         func(t *testing.T, tok string) *httptest.ResponseRecorder
		wantStatus int
	}{
		{"query", func(t *testing.T, tok string) *httptest.ResponseRecorder { return utrDoQuery(t, tok) }, utrQueryExecuteCompatStatus},
		{"execute", func(t *testing.T, tok string) *httptest.ResponseRecorder { return utrDoExecute(t, tok) }, utrQueryExecuteCompatStatus},
		{"check-input", func(t *testing.T, tok string) *httptest.ResponseRecorder { return utrDoCheckInput(t, tok) }, utrCheckInputOutputCompatStatus},
		{"check-output", func(t *testing.T, tok string) *httptest.ResponseRecorder { return utrDoCheckOutput(t, tok) }, utrCheckInputOutputCompatStatus},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupRUTMCPRestTest(t)
			mock := withMockUsageDB(t)
			mock.MatchExpectationsInOrder(false)
			mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))
			rutInstallRestCache(t, true)

			token := utrMintValidToken(t, "jti-"+tc.name+"-valid")
			w := tc.do(t, token)

			if w.Code == http.StatusUnauthorized {
				t.Fatalf("flag on + VALID token must not be rejected by the require_user_token gate, got 401: %s", w.Body.String())
			}
			if w.Code != tc.wantStatus {
				t.Fatalf("got %d want %d (the unrelated downstream outcome); a mismatch here means something ELSE changed: %s",
					w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

// =============================================================================
// 4. Flag ON: a presented-but-INVALID token still audits as
// "user_token_rejected", never "user_token_required" -- the two causes must
// not collapse. Representative subset (query + check-input), mirroring the
// "one representative cause" pattern in mcp_rest_user_token_rejected_test.go.
// =============================================================================

func TestMCPQueryHandler_RequireUserToken_FlagOn_InvalidToken_StillUserTokenRejected(t *testing.T) {
	setupRUTMCPRestTest(t)
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(rutAuditArgsWithPolicyMatcher(utrPolicyIDsMatcher{want: "user_token_rejected"})...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	rutInstallRestCache(t, true)

	w := utrDoQuery(t, utrMalformedToken)
	utrAssertUserTokenRejected(t, w, "malformed, flag on")
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("presented-invalid token must still audit user_token_rejected with the flag on: %v", err)
	}
}

func TestMCPCheckInputHandler_RequireUserToken_FlagOn_InvalidToken_StillUserTokenRejected(t *testing.T) {
	setupRUTMCPRestTest(t)
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(rutAuditArgsWithPolicyMatcher(utrPolicyIDsMatcher{want: "user_token_rejected"})...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	rutInstallRestCache(t, true)

	w := utrDoCheckInput(t, utrMalformedToken)
	utrAssertUserTokenRejected(t, w, "malformed, flag on")
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("presented-invalid token must still audit user_token_rejected with the flag on: %v", err)
	}
}

// =============================================================================
// 5. Audit distinguishability: flag ON + absent token writes the NEW
// "user_token_required" marker (never "user_token_rejected", never silent).
// =============================================================================

func TestMCPQueryHandler_RequireUserToken_FlagOn_AbsentToken_AuditsUserTokenRequired(t *testing.T) {
	setupRUTMCPRestTest(t)
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(rutAuditArgsWithPolicyMatcher(utrPolicyIDsMatcher{want: "user_token_required"})...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	rutInstallRestCache(t, true)

	w := utrDoQuery(t, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("flag on + absent token must reject with 401, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("required-but-absent token must write a blocked audit row carrying user_token_required: %v", err)
	}
}

func TestMCPCheckInputHandler_RequireUserToken_FlagOn_AbsentToken_AuditsUserTokenRequired(t *testing.T) {
	setupRUTMCPRestTest(t)
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(rutAuditArgsWithPolicyMatcher(utrPolicyIDsMatcher{want: "user_token_required"})...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	rutInstallRestCache(t, true)

	w := utrDoCheckInput(t, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("flag on + absent token must reject with 401, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("required-but-absent token must write a blocked audit row carrying user_token_required: %v", err)
	}
}

// Negative control mirroring TestMCPCheckInputHandler_AbsentToken_NoUserTokenRejectedRow:
// flag on + absent token must NEVER write a user_token_rejected row (only
// user_token_required).
func TestMCPCheckInputHandler_RequireUserToken_FlagOn_AbsentToken_NoUserTokenRejectedRow(t *testing.T) {
	setupRUTMCPRestTest(t)
	mock := withMockUsageDB(t)
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(rutAuditArgsWithPolicyMatcher(utrPolicyIDsMatcher{want: "user_token_rejected"})...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	rutInstallRestCache(t, true)

	w := utrDoCheckInput(t, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("flag on + absent token must reject with 401, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err == nil {
		t.Fatal("flag-on absent-token rejection must NEVER write a user_token_rejected row (must be user_token_required instead)")
	}
}

// =============================================================================
// 6. An unreadable posture fails closed at a REST gate point.
// =============================================================================

func TestMCPQueryHandler_RequireUserToken_ReaderError_FailsClosed_AbsentTokenRejected(t *testing.T) {
	setupRUTMCPRestTest(t)
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))
	rutInstallRestCacheErr(t)

	w := utrDoQuery(t, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("posture-read error must fail closed: got %d want 401: %s", w.Code, w.Body.String())
	}
}
