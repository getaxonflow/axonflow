// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Per-plane security proofs for the identity-header trust gate (#2896).
//
// Contract under test, on all four governance planes (/api/v1/decide, MCP
// check-input, MCP check-output, MCP-server):
//
//  1. ATTRIBUTION — gate ON ⇒ audit_logs.user_email/session_id come from
//     X-User-Email/X-Session-Id; gate OFF ⇒ the validated identity, headers
//     dropped.
//  2. VERDICT INVARIANCE — the governance verdict is identical with and
//     without the headers. If anyone wires the header into a decision path,
//     these tests go red.
//  3. FORGERY DROPPED WHEN OFF — a forged X-User-Email cannot land in the
//     audit row NOR hijack another user's ADR-044 session override (the
//     pre-#2896 deny→allow flip). Mirrors the gateway adapters' B4
//     adversarial test on the platform side.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
)

// installUsageDBMock swaps usageDB for a sqlmock and restores it after the
// test. Returns the mock for expectation pinning.
func installUsageDBMock(t *testing.T) sqlmock.Sqlmock {
	t.Helper()
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	orig := usageDB
	usageDB = mockDB
	t.Cleanup(func() {
		usageDB = orig
		_ = mockDB.Close()
	})
	return mock
}

// expectDecideWriterRow pins the writeDecisionAuditLog INSERT (the writer
// shared by /decide and the check-input/check-output allow+block emits) on
// the two attribution columns this feature owns: user_email and session_id.
func expectDecideWriterRow(mock sqlmock.Sqlmock, wantEmail string, wantSessionID interface{}) {
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), // id
			sqlmock.AnyArg(), // request_id
			sqlmock.AnyArg(), // timestamp
			sqlmock.AnyArg(), // user_id
			wantEmail,        // user_email — THE attribution column (#2896)
			sqlmock.AnyArg(), // user_role
			sqlmock.AnyArg(), // client_id
			sqlmock.AnyArg(), // tenant_id
			sqlmock.AnyArg(), // org_id
			sqlmock.AnyArg(), // request_type
			sqlmock.AnyArg(), // query
			sqlmock.AnyArg(), // query_hash
			sqlmock.AnyArg(), // policy_decision
			sqlmock.AnyArg(), // policy_details
			sqlmock.AnyArg(), // decision_id
			sqlmock.AnyArg(), // plane
			sqlmock.AnyArg(), // obligations
			sqlmock.AnyArg(), // correlation_id
			sqlmock.AnyArg(), // redacted_fields
			wantSessionID,    // session_id — trust-gated (#2896)
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

// ---------------------------------------------------------------------------
// Plane 1: /api/v1/decide
// ---------------------------------------------------------------------------

func decideAttributionRequest(t *testing.T, withHeaders bool) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(DecideRequest{
		Stage: DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{
			GatewayID: "claude_desktop.test-host",
			TenantID:  "test-tenant",
		},
		Target: DecisionTarget{Type: "llm", Model: "gpt-4o", Provider: "openai"},
		Query:  "What is the weather today?",
	})
	req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	if withHeaders {
		req.Header.Set(identityHeaderUserEmail, "leader@corp.example")
		req.Header.Set(identityHeaderSessionID, "sess-desktop-42")
	}
	rr := httptest.NewRecorder()
	handleDecide(rr, req)
	return rr
}

func TestDecide_Attribution_GateOn_HeadersLandInAuditRow(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)
	mock := installUsageDBMock(t)

	expectDecideWriterRow(mock, "leader@corp.example", "sess-desktop-42")

	rr := decideAttributionRequest(t, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("gate on: X-User-Email/X-Session-Id did not land in the decide audit row: %v", err)
	}
}

func TestDecide_Attribution_GateOff_ForgedHeadersDropped(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv(sharedidentity.EnvVar, "false")
	resetIdentityWarnLatches(t)
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)
	mock := installUsageDBMock(t)

	// The forged header must NOT appear: user_email is the validated community
	// identity, session_id NULL. (Brief DoD: forgery-dropped-when-off.)
	expectDecideWriterRow(mock, "local-dev@axonflow.local", nil)

	rr := decideAttributionRequest(t, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("gate off: forged identity headers reached the decide audit row: %v", err)
	}
}

// TestDecide_VerdictInvariance proves the verdict-bearing response fields are
// identical with and without identity headers, under BOTH gate states. Runs
// the same clean request four ways and diffs everything except the
// per-request ids (decision_id, trace_id, expires_at).
func TestDecide_VerdictInvariance(t *testing.T) {
	type verdictShape struct {
		Verdict           string
		Stage             string
		Reasons           []string
		EvaluatedPolicies []string
		ObligationCount   int
	}
	run := func(t *testing.T, gate string, withHeaders bool) verdictShape {
		t.Setenv("DEPLOYMENT_MODE", "community")
		t.Setenv("ENVIRONMENT", "development")
		t.Setenv(sharedidentity.EnvVar, gate)
		resetIdentityWarnLatches(t)
		installSharedEngineWithMockDB(t)
		installCircuitBreaker(t)
		installUsageDBMock(t) // permissive: audit write is best-effort, never verdict-bearing

		rr := decideAttributionRequest(t, withHeaders)
		if rr.Code != http.StatusOK {
			t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
		}
		var resp DecideResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return verdictShape{
			Verdict:           resp.Verdict,
			Stage:             resp.Stage,
			Reasons:           resp.Reasons,
			EvaluatedPolicies: resp.EvaluatedPolicies,
			ObligationCount:   len(resp.Obligations),
		}
	}

	baseline := run(t, "false", false)
	for _, tc := range []struct {
		name        string
		gate        string
		withHeaders bool
	}{
		{"gate off + headers", "false", true},
		{"gate on + no headers", "true", false},
		{"gate on + headers", "true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := run(t, tc.gate, tc.withHeaders)
			if !reflect.DeepEqual(got, baseline) {
				t.Errorf("verdict shape diverged from baseline (identity headers influenced the decision):\n got: %+v\nwant: %+v", got, baseline)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Plane 2: /api/v1/mcp/check-input
// ---------------------------------------------------------------------------

// checkInputCleanAllow drives the clean allow path (no engines) with optional
// identity headers, mirroring TestMCPCheckInputHandler_AllowEmitsAuditLogsDecisionRow.
func checkInputCleanAllow(t *testing.T, withHeaders bool) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT * FROM orders",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	if withHeaders {
		req.Header.Set(identityHeaderUserEmail, "leader@corp.example")
		req.Header.Set(identityHeaderSessionID, "sess-desktop-42")
	}
	w := httptest.NewRecorder()
	mcpCheckInputHandler(w, req)
	return w
}

func disablePolicyEngines(t *testing.T) {
	t.Helper()
	origEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(origEngine) })
	origEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalDynamicPolicyEvaluator(origEval) })
}

func TestCheckInput_Attribution_GateOn_HeadersLandInAuditRow(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)
	disablePolicyEngines(t)
	mock := installUsageDBMock(t)

	expectDecideWriterRow(mock, "leader@corp.example", "sess-desktop-42")

	w := checkInputCleanAllow(t, true)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (allow), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("gate on: X-User-Email/X-Session-Id did not land in the check-input audit row: %v", err)
	}
}

func TestCheckInput_Attribution_GateOff_ForgedHeadersDropped(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "false")
	resetIdentityWarnLatches(t)
	disablePolicyEngines(t)
	mock := installUsageDBMock(t)

	// Pre-#2896 this plane trusted the header unconditionally — the forged
	// value would have landed. Now: validated identity, session NULL.
	expectDecideWriterRow(mock, "local-dev@axonflow.local", nil)

	w := checkInputCleanAllow(t, true)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (allow), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("gate off: forged identity headers reached the check-input audit row: %v", err)
	}
}

func TestCheckInput_VerdictInvariance_CleanAllow(t *testing.T) {
	type respShape struct {
		Allowed            bool
		BlockReason        string
		PoliciesEvaluated  int
		Redacted           bool
		RedactionEvaluated bool
	}
	run := func(t *testing.T, gate string, withHeaders bool) respShape {
		cleanup := setupCommunityModeForTest(t)
		defer cleanup()
		t.Setenv(sharedidentity.EnvVar, gate)
		resetIdentityWarnLatches(t)
		disablePolicyEngines(t)
		installUsageDBMock(t)

		w := checkInputCleanAllow(t, withHeaders)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp MCPCheckInputResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return respShape{resp.Allowed, resp.BlockReason, resp.PoliciesEvaluated, resp.Redacted, resp.RedactionEvaluated}
	}

	baseline := run(t, "false", false)
	for _, tc := range []struct {
		name        string
		gate        string
		withHeaders bool
	}{
		{"gate off + headers", "false", true},
		{"gate on + no headers", "true", false},
		{"gate on + headers", "true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(t, tc.gate, tc.withHeaders); !reflect.DeepEqual(got, baseline) {
				t.Errorf("check-input response diverged (identity headers influenced the verdict):\n got: %+v\nwant: %+v", got, baseline)
			}
		})
	}
}

// --- The ADR-044 override flip: the one identity-SCOPED feature (#2896) ---

// installBlockingStaticEngine wires a real UnifiedPolicyEngine over sqlmock
// whose policy set contains exactly one blocking, overridable request-phase
// policy (category security-sqli, pattern FORBIDDEN_MARKER). Returns the
// engine-side mock so callers can add the richer-context expectations.
func installBlockingStaticEngine(t *testing.T) sqlmock.Sqlmock {
	t.Helper()
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mock.MatchExpectationsInOrder(false)

	policyCols := policytest.LoaderCols()
	// The loader may fetch more than once (per phase/org cache key); a few
	// identical expectations cover every load. Unconsumed ones are harmless —
	// these tests assert on the RESPONSE, not ExpectationsWereMet.
	//
	// #3048: each load is now TWO scoped passes (tenant then 'global'). The
	// 'global'-scope pass (args 'global') returns the system policy; those
	// expectations are registered FIRST so unordered matching binds them by
	// args. The argless expectations after them absorb the tenant passes
	// (empty — the fixture has no tenant policies). ScopedTxPlumbing absorbs
	// the BEGIN/set_config/COMMIT traffic.
	for i := 0; i < 4; i++ {
		mock.ExpectQuery(`SELECT\s+id, policy_id`).WithArgs("global").WillReturnRows(
			policytest.SystemPolicyRow(sqlmock.NewRows(policyCols),
				"11111111-1111-1111-1111-111111111111", "sys_test_block_marker",
				"security-sqli", "FORBIDDEN_MARKER", "high", "request", "block", 100),
		)
	}
	for i := 0; i < 4; i++ {
		mock.ExpectQuery(`SELECT\s+id, policy_id`).WillReturnRows(sqlmock.NewRows(policyCols))
	}
	policytest.ScopedTxPlumbing(mock, 16)

	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, sharedpolicy.EngineConfig{}, nil)
	old := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(old) })

	origEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalDynamicPolicyEvaluator(origEval) })

	return mock
}

// expectOverridableRicherContext adds the usageDB-side richer-context lookups
// for the blocked request: policy meta (non-critical + overridable) and two
// active-override lookups (buildRicherCheckInputBlock + the apply loop), both
// keyed on the override-owner email the test expects the handler to use.
func expectOverridableRicherContext(mock sqlmock.Sqlmock, ownerEmail, overrideID string) {
	// #3048: the lookups now run inside WithOrgScope transactions; the
	// override lookup resolves the policy UUID first, then reads the
	// override row keyed by that UUID. Plumbing spares absorb the
	// BEGIN/set_config/COMMIT/ROLLBACK traffic (unordered mocks).
	policytest.ScopedTxPlumbing(mock, 12)
	mock.ExpectQuery(`SELECT risk_level, allow_override, version`).
		WithArgs("sys_test_block_marker").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "version"}).
			AddRow("low", true, 3))
	for i := 0; i < 2; i++ {
		mock.ExpectQuery(`SELECT sp\.id`).
			WithArgs("sys_test_block_marker").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("11111111-1111-1111-1111-111111111111"))
		mock.ExpectQuery(`SELECT po\.id`).
			WithArgs("11111111-1111-1111-1111-111111111111", ownerEmail, sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(overrideID))
	}
}

func checkInputBlockedStatement(t *testing.T, forgedEmail string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT * FROM t WHERE FORBIDDEN_MARKER",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	if forgedEmail != "" {
		req.Header.Set(identityHeaderUserEmail, forgedEmail)
	}
	w := httptest.NewRecorder()
	mcpCheckInputHandler(w, req)
	return w
}

// TestCheckInput_ForgedOverride_GateOff_BlockStands is the platform-side B4:
// the attacker forges X-User-Email = a victim who HAS an active override on
// the blocking policy. Pre-#2896 the unconditional header read handed the
// attacker the victim's override — deny flipped to allow. With the gate OFF
// the override lookup must key on the VALIDATED identity (which has no
// override), so the block stands. If anyone re-wires the raw header into the
// override scope, the seeded victim override applies and this test goes RED
// on the 403 assertion.
func TestCheckInput_ForgedOverride_GateOff_BlockStands(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "false")
	t.Setenv("MCP_SQLI_ACTION", "block")
	resetIdentityWarnLatches(t)
	installBlockingStaticEngine(t)

	mock := installUsageDBMock(t)
	mock.MatchExpectationsInOrder(false)
	// Seed the VICTIM's active override. Correct code never queries with the
	// forged email (it uses the validated identity → args don't match → no
	// override found → block stands). The mutation this defends against —
	// wiring the raw header back into the override scope — matches these
	// expectations, flips the deny, and fails the 403 assert below.
	expectOverridableRicherContext(mock, "victim@corp.example", "ovr-hijacked")
	// The static-block audit write (writeExplainableAuditLog) — permissive.
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	w := checkInputBlockedStatement(t, "victim@corp.example")
	if w.Code != http.StatusForbidden {
		t.Fatalf("SECURITY: forged X-User-Email flipped a deny with the trust gate OFF — got %d, want 403; body=%s", w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Allowed {
		t.Fatal("SECURITY: allowed=true on a forged-override attempt with the gate off")
	}
	if resp.OverrideExistingID != "" {
		t.Errorf("SECURITY: victim's override id leaked to the forger: %q", resp.OverrideExistingID)
	}
}

// TestCheckInput_Override_GateOn_TrustedIdentityScopesOverride documents the
// deliberate ADR-044 behavior under the gate: a TRUSTED deployment's asserted
// identity scopes the per-user session override, so the pre-#2896 plugin flow
// (blocked → create override → retry → allowed) keeps working once the
// operator sets the flag.
func TestCheckInput_Override_GateOn_TrustedIdentityScopesOverride(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	t.Setenv("MCP_SQLI_ACTION", "block")
	resetIdentityWarnLatches(t)
	installBlockingStaticEngine(t)

	mock := installUsageDBMock(t)
	mock.MatchExpectationsInOrder(false)
	expectOverridableRicherContext(mock, "dev@corp.example", "ovr-own")
	// override_used audit event (writeOverrideUsedEvent) + satellite writes.
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	w := checkInputBlockedStatement(t, "dev@corp.example")
	if w.Code != http.StatusOK {
		t.Fatalf("trusted identity's own override must flip the block: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Allowed {
		t.Error("expected allowed=true via the user's own ADR-044 override")
	}
	if resp.OverrideExistingID != "ovr-own" {
		t.Errorf("override_existing_id: got %q, want ovr-own", resp.OverrideExistingID)
	}
}

// ---------------------------------------------------------------------------
// Plane 3: /api/v1/mcp/check-output
// ---------------------------------------------------------------------------

func checkOutputCleanAllow(t *testing.T, withHeaders bool) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Message:       "1 row affected",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	if withHeaders {
		req.Header.Set(identityHeaderUserEmail, "leader@corp.example")
		req.Header.Set(identityHeaderSessionID, "sess-desktop-42")
	}
	w := httptest.NewRecorder()
	mcpCheckOutputHandler(w, req)
	return w
}

func disableOutputCheckers(t *testing.T) {
	t.Helper()
	origChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	sharedpolicy.SetGlobalExfiltrationChecker(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalExfiltrationChecker(origChecker) })
}

func TestCheckOutput_Attribution_GateOn_HeadersLandInAuditRow(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)
	disablePolicyEngines(t)
	disableOutputCheckers(t)
	mock := installUsageDBMock(t)

	// check-output ignored X-User-Email entirely before #2896 — the desktop
	// proxy's per-leader identity never attributed. Gate on ⇒ it lands.
	expectDecideWriterRow(mock, "leader@corp.example", "sess-desktop-42")

	w := checkOutputCleanAllow(t, true)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (allow), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("gate on: X-User-Email/X-Session-Id did not land in the check-output audit row: %v", err)
	}
}

func TestCheckOutput_Attribution_GateOff_ForgedHeadersDropped(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "false")
	resetIdentityWarnLatches(t)
	disablePolicyEngines(t)
	disableOutputCheckers(t)
	mock := installUsageDBMock(t)

	expectDecideWriterRow(mock, "local-dev@axonflow.local", nil)

	w := checkOutputCleanAllow(t, true)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (allow), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("gate off: forged identity headers reached the check-output audit row: %v", err)
	}
}

func TestCheckOutput_VerdictInvariance(t *testing.T) {
	run := func(t *testing.T, gate string, withHeaders bool) MCPCheckOutputResponse {
		cleanup := setupCommunityModeForTest(t)
		defer cleanup()
		t.Setenv(sharedidentity.EnvVar, gate)
		resetIdentityWarnLatches(t)
		disablePolicyEngines(t)
		disableOutputCheckers(t)
		installUsageDBMock(t)

		w := checkOutputCleanAllow(t, withHeaders)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp MCPCheckOutputResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		resp.DecisionID = "" // per-request id — the only field allowed to differ
		return resp
	}

	baseline := run(t, "false", false)
	for _, tc := range []struct {
		name        string
		gate        string
		withHeaders bool
	}{
		{"gate off + headers", "false", true},
		{"gate on + no headers", "true", false},
		{"gate on + headers", "true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(t, tc.gate, tc.withHeaders); !reflect.DeepEqual(got, baseline) {
				t.Errorf("check-output response diverged (identity headers influenced the verdict):\n got: %+v\nwant: %+v", got, baseline)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Plane 4: MCP-server (session identity feeding tools/call)
// ---------------------------------------------------------------------------

// TestMCPServerIdentity_GateOff_ForgedHeadersDropped: with the gate off the
// session identity must be the client-scoped pseudo-identity — the forged
// per-user headers (previously honored unconditionally at
// authenticateMCPServerRequest) are ignored, and the forged X-Session-Id
// never becomes the session's clientSessionID.
func TestMCPServerIdentity_GateOff_ForgedHeadersDropped(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "false")
	resetIdentityWarnLatches(t)

	r := httptest.NewRequest("POST", "/api/v1/mcp-server", nil)
	r.Header.Set(identityHeaderUserEmail, "forged@victim.example")
	r.Header.Set(identityHeaderUserID, "forged-uid")
	r.Header.Set(identityHeaderSessionID, "forged-session")

	_, _, userID, userEmail, _, clientID, _, _, err := authenticateMCPServerRequest(r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	wantPseudo := "mcp-client:" + clientID
	if userEmail != wantPseudo {
		t.Errorf("gate off: session email = %q, want pseudo-identity %q (forged header must be dropped)", userEmail, wantPseudo)
	}
	if userID != wantPseudo {
		t.Errorf("gate off: session userID = %q, want %q (forged X-User-ID must be dropped)", userID, wantPseudo)
	}

	session := resolveMCPSession(r)
	if session == nil {
		t.Fatal("resolveMCPSession returned nil")
	}
	if session.clientSessionID != "" {
		t.Errorf("gate off: clientSessionID = %q, want empty (forged X-Session-Id must be dropped)", session.clientSessionID)
	}
}

// TestMCPServerIdentity_GateOn_TrustedHeadersHonored preserves the trusted
// fleet behavior (per-developer attribution via managed plugin settings).
func TestMCPServerIdentity_GateOn_TrustedHeadersHonored(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)

	r := httptest.NewRequest("POST", "/api/v1/mcp-server", nil)
	r.Header.Set(identityHeaderUserEmail, "dev@corp.example")
	r.Header.Set(identityHeaderSessionID, "sess-cc-7")

	_, _, _, userEmail, _, _, _, _, err := authenticateMCPServerRequest(r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if userEmail != "dev@corp.example" {
		t.Errorf("gate on: session email = %q, want dev@corp.example", userEmail)
	}

	session := resolveMCPSession(r)
	if session == nil {
		t.Fatal("resolveMCPSession returned nil")
	}
	if session.clientSessionID != "sess-cc-7" {
		t.Errorf("gate on: clientSessionID = %q, want sess-cc-7", session.clientSessionID)
	}
}

// ---------------------------------------------------------------------------
// Shared pseudo-identity override guard (#2896 R3 HIGH findings 1+2)
// ---------------------------------------------------------------------------

// TestSharedPseudoIdentity_NeverAppliesOverride: an override row keyed to the
// client-shared "mcp-client:<id>" pseudo-identity must never flip a deny —
// it would be one caller's override applied to EVERY caller on the client.
// The sqlmock seeds an override FOR the pseudo-identity; correct code
// short-circuits before any lookup, so a mutation that removes the guard
// matches the seeded row, flips the deny, and turns this red.
func TestSharedPseudoIdentity_NeverAppliesOverride(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()
	mock.MatchExpectationsInOrder(false)
	for i := 0; i < 2; i++ {
		mock.ExpectQuery(`SELECT po\.id`).
			WithArgs(sqlmock.AnyArg(), "mcp-client:acme-corp", sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("ovr-shared"))
	}

	matches := []RicherPolicyMatch{{PolicyID: "sys_test_block_marker", RiskLevel: "low", AllowOverride: true}}
	id, m, applied := applyOverrideToCheckInputBlock(context.Background(), mockDB, "t1", "mcp-client:acme-corp", matches)
	if applied || id != "" || m != nil {
		t.Fatalf("SECURITY: client-shared pseudo-identity applied an override (id=%q) — one caller's override would flip denies for the whole client", id)
	}

	// buildRicherCheckInputBlock must not offer the override CTA either —
	// the plugin would create an override that can never legitimately apply.
	mock2DB, mock2, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mock2DB.Close()
	mock2.MatchExpectationsInOrder(false)
	mock2.ExpectQuery(`SELECT risk_level, allow_override, version`).
		WithArgs("sys_test_block_marker").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "version"}).AddRow("low", true, 1))
	_, _, overrideAvailable, overrideID := buildRicherCheckInputBlock(context.Background(), mock2DB, "t1", "mcp-client:acme-corp",
		[]sharedpolicy.PolicyMatch{{PolicyID: "sys_test_block_marker"}})
	if overrideAvailable != nil || overrideID != "" {
		t.Errorf("client-shared pseudo-identity must get no override affordance, got available=%v id=%q", overrideAvailable, overrideID)
	}
}

// TestMcpToolCreateOverride_SharedPseudoIdentityRefusedLoudly: creating an
// override under the pseudo-identity must fail with an actionable error (not
// silently create a row that never applies / applies client-wide).
func TestMcpToolCreateOverride_SharedPseudoIdentityRefusedLoudly(t *testing.T) {
	_, err := mcpToolCreateOverride(&mcpSession{
		tenantID: "t1", clientID: "acme-corp", userEmail: "mcp-client:acme-corp",
	}, map[string]interface{}{
		"policy_id": "sys_x", "policy_type": "static", "override_reason": "need it",
	})
	if err == nil {
		t.Fatal("expected create_override to refuse a client-shared pseudo-identity")
	}
	for _, want := range []string{"AXONFLOW_TRUST_IDENTITY_HEADERS", "mcp-client:acme-corp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal must be actionable (missing %q): %v", want, err)
		}
	}
}

// TestCheckInput_VerdictInvariance_BlockedPath: with a real static-blocking
// engine wired and the gate OFF, the deny is identical with and without a
// forged header — invariance on a policy-evaluated (non-trivial) verdict, not
// just the clean allow.
func TestCheckInput_VerdictInvariance_BlockedPath(t *testing.T) {
	run := func(t *testing.T, forgedEmail string) (int, bool, string) {
		cleanup := setupCommunityModeForTest(t)
		defer cleanup()
		t.Setenv(sharedidentity.EnvVar, "false")
		t.Setenv("MCP_SQLI_ACTION", "block")
		resetIdentityWarnLatches(t)
		installBlockingStaticEngine(t)
		mock := installUsageDBMock(t)
		mock.MatchExpectationsInOrder(false)
		mock.ExpectQuery(`SELECT risk_level, allow_override, version`).
			WithArgs("sys_test_block_marker").
			WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "version"}).AddRow("low", true, 3))
		mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

		w := checkInputBlockedStatement(t, forgedEmail)
		var resp MCPCheckInputResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return w.Code, resp.Allowed, resp.BlockReason
	}

	codeNo, allowedNo, reasonNo := run(t, "")
	codeHdr, allowedHdr, reasonHdr := run(t, "someone@else.example")
	if codeNo != http.StatusForbidden || allowedNo {
		t.Fatalf("baseline should be blocked, got code=%d allowed=%v", codeNo, allowedNo)
	}
	if codeHdr != codeNo || allowedHdr != allowedNo || reasonHdr != reasonNo {
		t.Errorf("blocked-path verdict diverged with a forged header (gate off): (%d,%v,%q) vs (%d,%v,%q)",
			codeHdr, allowedHdr, reasonHdr, codeNo, allowedNo, reasonNo)
	}
}

// ---------------------------------------------------------------------------
// #2896 WS1b — shared-identity census: NO synthesized shared identity may
// create, be offered, or apply a session override, on any plane.
// ---------------------------------------------------------------------------

// TestSharedIdentityCensus_NeverAppliesOverride runs the WS1 adversarial
// shape over EVERY shared identity form in the census (identity_trust.go):
// an override row seeded FOR the identity must not flip a deny and must not
// surface an override affordance. Removing any census arm from
// isClientSharedPseudoIdentity turns the corresponding case red.
func TestSharedIdentityCensus_NeverAppliesOverride(t *testing.T) {
	shared := []struct {
		name  string
		email string
		mode  string // DEPLOYMENT_MODE for the case
	}{
		{"mcp-client pseudo", "mcp-client:acme-corp", "enterprise"},
		{"enterprise no-token service fallback", "acme-corp@axonflow.local", "enterprise"},
		{"audit-writer fallback", "unknown@axonflow.local", "enterprise"},
		{"internal-service identity", "orchestrator@axonflow.internal", "enterprise"},
		{"community-saas evaluator", "evaluator@try.getaxonflow.com", "community-saas"},
		{"community synthetic asserted OUTSIDE community mode", "local-dev@axonflow.local", "enterprise"},
	}
	for _, tc := range shared {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", tc.mode)

			mockDB, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer mockDB.Close()
			mock.MatchExpectationsInOrder(false)
			for i := 0; i < 2; i++ {
				mock.ExpectQuery(`SELECT po\.id`).
					WithArgs(sqlmock.AnyArg(), tc.email, sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("ovr-shared"))
			}
			matches := []RicherPolicyMatch{{PolicyID: "sys_test_block_marker", RiskLevel: "low", AllowOverride: true}}
			if id, _, applied := applyOverrideToCheckInputBlock(context.Background(), mockDB, "t1", tc.email, matches); applied {
				t.Fatalf("SECURITY: shared identity %q applied an override (id=%q)", tc.email, id)
			}

			mock2DB, mock2, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer mock2DB.Close()
			mock2.MatchExpectationsInOrder(false)
			mock2.ExpectQuery(`SELECT risk_level, allow_override, version`).
				WithArgs("sys_test_block_marker").
				WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "version"}).AddRow("low", true, 1))
			_, _, avail, existing := buildRicherCheckInputBlock(context.Background(), mock2DB, "t1", tc.email,
				[]sharedpolicy.PolicyMatch{{PolicyID: "sys_test_block_marker"}})
			if avail != nil || existing != "" {
				t.Errorf("shared identity %q must get no override affordance (available=%v id=%q)", tc.email, avail, existing)
			}
		})
	}

	// The one documented exception: community mode's local-dev identity IS
	// the (single) local developer — override behavior is preserved there.
	t.Run("community local-dev keeps overrides IN community mode", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "community")
		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		defer mockDB.Close()
		// #3048 scoped shape: resolve UUID, then read the override.
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_config\('app\.current_org_id'`).
			WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(`SELECT sp\.id`).
			WithArgs("sys_test_block_marker").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("uuid-marker"))
		mock.ExpectCommit()
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_config\('app\.current_org_id'`).
			WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(`SELECT po\.id`).
			WithArgs("uuid-marker", "local-dev@axonflow.local", sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("ovr-local"))
		mock.ExpectCommit()
		matches := []RicherPolicyMatch{{PolicyID: "sys_test_block_marker", RiskLevel: "low", AllowOverride: true}}
		id, _, applied := applyOverrideToCheckInputBlock(context.Background(), mockDB, "t1", "local-dev@axonflow.local", matches)
		if !applied || id != "ovr-local" {
			t.Errorf("community local-dev must keep ADR-044 overrides in community mode (applied=%v id=%q)", applied, id)
		}
	})
}

// installBlockingOutputEngine wires an engine whose single policy blocks on
// the RESPONSE plane (category sensitive-data, phase both) so the MCP-server
// check_output tool's static-block + override-apply branch runs.
func installBlockingOutputEngine(t *testing.T) {
	t.Helper()
	t.Setenv("SENSITIVE_DATA_ACTION", "block")
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mock.MatchExpectationsInOrder(false)
	policyCols := []string{
		"id", "policy_id", "name", "category", "tier", "pattern", "severity",
		"description", "phase", "action_request", "action_response",
		"enabled", "priority", "tenant_id", "organization_id", "metadata",
	}
	for i := 0; i < 6; i++ {
		mock.ExpectQuery(`SELECT\s+id, policy_id`).WillReturnRows(
			sqlmock.NewRows(policyCols).AddRow(
				"22222222-2222-2222-2222-222222222222",
				"sys_test_output_block",
				"Test output blocking policy",
				"sensitive-data",
				"system",
				"FORBIDDEN_MARKER",
				"high",
				nil,
				"both",
				"block",
				"block",
				true,
				100,
				"global",
				nil,
				[]byte(`{}`),
			),
		)
	}
	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, sharedpolicy.EngineConfig{}, nil)
	old := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(old) })
	origEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalDynamicPolicyEvaluator(origEval) })
	origChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	sharedpolicy.SetGlobalExfiltrationChecker(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalExfiltrationChecker(origChecker) })
}

// TestMcpToolCheckPolicy_SharedServiceIdentity_BlockStands drives the REAL
// MCP-server check_policy tool (the check-input plane of the tools surface)
// with a session attributed to the enterprise service fallback
// "<client>@axonflow.local" and an override row seeded for that identity:
// the deny must stand. Mirrors the WS1 pseudo-identity proof for the second
// shared-identity family the R3 census added.
func TestMcpToolCheckPolicy_SharedServiceIdentity_BlockStands(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv("DEPLOYMENT_MODE", "enterprise") // guard must treat @axonflow.local as shared
	t.Setenv("MCP_SQLI_ACTION", "block")
	installBlockingStaticEngine(t)
	mock := installUsageDBMock(t)
	mock.MatchExpectationsInOrder(false)
	expectOverridableRicherContext(mock, "acme-corp@axonflow.local", "ovr-shared-svc")
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	resp, err := mcpToolCheckPolicy(context.Background(), &mcpSession{
		tenantID: "t1", orgID: "o1", userID: "u1", userRole: "unknown", clientID: "acme-corp",
		userEmail: "acme-corp@axonflow.local",
	}, map[string]interface{}{
		"connector_type": "postgres",
		"statement":      "SELECT * FROM t WHERE FORBIDDEN_MARKER",
	})
	if err != nil {
		t.Fatalf("check_policy: %v", err)
	}
	m := resp.(map[string]interface{})
	if allowed, _ := m["allowed"].(bool); allowed {
		t.Fatalf("SECURITY: shared service identity flipped a check_policy deny: %v", m)
	}
	if id, ok := m["override_existing_id"].(string); ok && id != "" {
		t.Errorf("shared service identity leaked an override id: %q", id)
	}
}

// TestMcpToolCheckOutput_SharedServiceIdentity_BlockStands is the response
// plane (check_output tool) proof for the same family.
func TestMcpToolCheckOutput_SharedServiceIdentity_BlockStands(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installBlockingOutputEngine(t)
	mock := installUsageDBMock(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectQuery(`SELECT risk_level, allow_override, version`).
		WithArgs("sys_test_output_block").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "version"}).AddRow("low", true, 1))
	for i := 0; i < 2; i++ {
		mock.ExpectQuery(`SELECT po\.id`).
			WithArgs(sqlmock.AnyArg(), "acme-corp@axonflow.local", sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("ovr-shared-svc"))
	}
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	resp, err := mcpToolCheckOutput(context.Background(), &mcpSession{
		tenantID: "t1", orgID: "o1", userID: "u1", userRole: "unknown", clientID: "acme-corp",
		userEmail: "acme-corp@axonflow.local",
	}, map[string]interface{}{
		"connector_type": "postgres",
		"message":        "credentials: FORBIDDEN_MARKER leaked",
	})
	if err != nil {
		t.Fatalf("check_output: %v", err)
	}
	m := resp.(map[string]interface{})
	if allowed, _ := m["allowed"].(bool); allowed {
		t.Fatalf("SECURITY: shared service identity flipped a check_output deny: %v", m)
	}
	if id, ok := m["override_existing_id"].(string); ok && id != "" {
		t.Errorf("shared service identity leaked an override id: %q", id)
	}
}

// ---------------------------------------------------------------------------
// #2896 WS1c — agent proxy boundary: the per-user identity headers are trust-
// gated on EVERY proxied route (global, not per-prefix — the per-prefix
// allowlist missed the MAP plan-resume / checkpoint-resume override plane).
// ---------------------------------------------------------------------------

func TestGateProxyIdentityHeaders(t *testing.T) {
	mk := func(path string) *http.Request {
		r := httptest.NewRequest("POST", path, nil)
		r.Header.Set(identityHeaderUserEmail, "forged@victim.example")
		r.Header.Set(identityHeaderUserID, "forged-uid")
		r.Header.Set(identityHeaderSessionID, "sess-forged")
		// Auth-derived headers the middleware sets from the validated
		// credential — must survive the gate untouched.
		r.Header.Set("X-Tenant-ID", "tenant-real")
		r.Header.Set("X-Org-ID", "org-real")
		r.Header.Set("X-Axonflow-Proxy-Auth", "proxy-token")
		return r
	}

	// Gate OFF: every proxied route — including the ones the WS1b per-prefix
	// allowlist MISSED — must have the forgeable per-user headers stripped.
	offRoutes := []struct {
		name string
		path string
	}{
		{"override route", "/api/v1/overrides"},
		{"workflows step-gate", "/api/v1/workflows/wf-1/steps/s1/gate"},
		{"MAP plan-resume (WS1c: was ungated)", "/api/v1/plan/plan-1/resume"},
		{"workflow checkpoint resume (WS1c: was ungated)", "/api/v1/workflows/wf-1/checkpoints/resume"},
		{"specific checkpoint resume (WS1c: was ungated)", "/api/v1/workflows/wf-1/checkpoints/7/resume"},
		{"audit route (WS1c: now gated too)", "/api/v1/audit/search"},
		{"process route", "/api/v1/process"},
	}
	for _, tc := range offRoutes {
		t.Run("gate off strips identity — "+tc.name, func(t *testing.T) {
			resetIdentityWarnLatches(t)
			t.Setenv(sharedidentity.EnvVar, "false")
			r := mk(tc.path)
			gateProxyIdentityHeaders(r)
			for _, h := range []string{identityHeaderUserEmail, identityHeaderUserID, identityHeaderSessionID} {
				if v := r.Header.Get(h); v != "" {
					t.Errorf("gate off on %s: %s must be stripped before proxying, got %q", tc.path, h, v)
				}
			}
			// Auth-derived + proxy-auth headers are NEVER touched.
			if r.Header.Get("X-Tenant-ID") != "tenant-real" || r.Header.Get("X-Org-ID") != "org-real" {
				t.Error("gate must not strip auth-derived X-Tenant-ID / X-Org-ID")
			}
			if r.Header.Get("X-Axonflow-Proxy-Auth") != "proxy-token" {
				t.Error("gate must not strip the proxy-auth token")
			}
		})
	}

	t.Run("gate on forwards sanitized identity", func(t *testing.T) {
		resetIdentityWarnLatches(t)
		t.Setenv(sharedidentity.EnvVar, "true")
		r := mk("/api/v1/plan/plan-1/resume")
		r.Header.Set(identityHeaderUserEmail, "dev\x01@corp.example")
		gateProxyIdentityHeaders(r)
		if v := r.Header.Get(identityHeaderUserEmail); v != "dev@corp.example" {
			t.Errorf("gate on: expected sanitized pass-through, got %q", v)
		}
		if v := r.Header.Get(identityHeaderSessionID); v != "sess-forged" {
			t.Errorf("gate on: session id must be forwarded, got %q", v)
		}
		if v := r.Header.Get(identityHeaderUserID); v != "forged-uid" {
			t.Errorf("gate on: X-User-ID must be forwarded (trusted deployment), got %q", v)
		}
	})
}
