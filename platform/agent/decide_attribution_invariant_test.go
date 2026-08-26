// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
)

// =============================================================================
// THE ATTRIBUTION INVARIANT (#3484)
//
//	Audit attribution ALWAYS names the principal whose VERIFIED identity the
//	decision was evaluated against. It is never a claim the system did not act
//	on.
//
// Why this plane needs it pinned, not merely documented: segment-scoped policy
// (ADR-060) makes the principal decide WHICH policies apply at all. A row
// naming a human whose segments were never consulted does not just misname the
// caller — it misdescribes what was governed, in the artifact the compliance
// exports and the portal decisions feed read. And it is the only place the
// enforcement subject is observable, so if the row can name someone else, a
// correctly-enforced request is indistinguishable from a mis-enforced one.
//
// An invariant nobody checks drifts. That is the same lesson as the
// cross-plane refusal literal, kept byte-identical across five files by
// convention with nothing comparing them.
// =============================================================================

// decideAttributionMatcher asserts the policy_details JSONB carries (or does
// not carry) the asserted-but-unused claim.
type decideAttributionMatcher struct {
	wantAttemptedUserEmail string // "" means: the key must be ABSENT
}

func (m decideAttributionMatcher) Match(v driver.Value) bool {
	raw, ok := jsonbBytes(v)
	if !ok {
		return false
	}
	var d map[string]interface{}
	if json.Unmarshal(raw, &d) != nil {
		return false
	}
	got, present := d["attempted_user_email"]
	if m.wantAttemptedUserEmail == "" {
		return !present
	}
	return present && got == m.wantAttemptedUserEmail
}

func decideInvariantToken(t *testing.T, email, tenant string) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   float64(11),
		"tenant_id": tenant,
		"org_id":    tenant,
		"email":     email,
		"role":      "developer",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signed
}

// setupDecideInvariantTest wires enterprise mode, the JWT secret and the
// identity-header trust gate (without the gate the header is dropped and the
// test would pass vacuously).
func setupDecideInvariantTest(t *testing.T) sqlmock.Sqlmock {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	t.Setenv("AXONFLOW_TRUST_IDENTITY_HEADERS", "true")
	orig := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = orig })
	return withMockUsageDB(t)
}

// --- 1. A VALIDATED identity is never displaced by an asserted header. ---
//
// The pair is what makes this real: the same request, differing only in which
// email the header asserts, must attribute to the TOKEN's email either way.
func TestDecideAttributionInvariant_ValidatedIdentityWinsOverAssertedHeader(t *testing.T) {
	const tokenEmail = "alice@corp.example"
	const assertedEmail = "bob@corp.example"

	mock := setupDecideInvariantTest(t)

	args := decideAuditInsertArgs(AuditVerdictAllowed, decideAttributionMatcher{
		wantAttemptedUserEmail: assertedEmail, // recorded as a CLAIM...
	})
	args[4] = tokenEmail // ...while user_email names the principal enforced against
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := decideEnterpriseReq(t, DecideRequest{
		Stage:     DecisionStageLLM,
		Target:    DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:     "hello",
		UserToken: decideInvariantToken(t, tokenEmail, "auth-tenant"),
	}, "auth-tenant", "auth-tenant")
	req.Header.Set(identityHeaderUserEmail, assertedEmail)

	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("INVARIANT VIOLATED: audit_logs.user_email must name the VALIDATED principal (%s), "+
			"never the asserted header (%s), which belongs in attempted_user_email: %v",
			tokenEmail, assertedEmail, err)
	}
}

// --- 2. A header AGREEING with the token records no spurious claim. ---
//
// Without this, a fix that recorded attempted_user_email unconditionally would
// pass test 1 while polluting every trusted-fleet row with a redundant claim.
func TestDecideAttributionInvariant_AgreeingHeaderRecordsNoClaim(t *testing.T) {
	const tokenEmail = "alice@corp.example"

	mock := setupDecideInvariantTest(t)

	args := decideAuditInsertArgs(AuditVerdictAllowed, decideAttributionMatcher{
		wantAttemptedUserEmail: "", // must be ABSENT
	})
	args[4] = tokenEmail
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := decideEnterpriseReq(t, DecideRequest{
		Stage:     DecisionStageLLM,
		Target:    DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:     "hello",
		UserToken: decideInvariantToken(t, tokenEmail, "auth-tenant"),
	}, "auth-tenant", "auth-tenant")
	req.Header.Set(identityHeaderUserEmail, tokenEmail) // agrees

	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a header agreeing with the validated identity must record NO attempted_user_email "+
			"claim (nothing was displaced): %v", err)
	}
}

// --- 3. NO verified identity: #2896 behaviour is deliberately UNCHANGED. ---
//
// The invariant bites only where a VERIFIED identity exists to be displaced.
// A community / community-SaaS / internal-service caller, and the token-ABSENT
// enterprise fallback, resolve to a SYNTHETIC identity, and nothing
// principal-specific is evaluated for them — so the asserted header does not
// misdescribe what was governed, and it remains strictly better than naming a
// synthetic service email. Narrowing this wrongly is not theoretical: an
// earlier revision of this fix applied "validated wins" here too and broke
// TestDecide_Attribution_GateOn_HeadersLandInAuditRow, which pins exactly this
// population.
func TestDecideAttributionInvariant_NoVerifiedIdentityKeepsHeaderAttribution(t *testing.T) {
	const assertedEmail = "leader@corp.example"

	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("AXONFLOW_TRUST_IDENTITY_HEADERS", "true")
	mock := withMockUsageDB(t)

	args := decideAuditInsertArgs(AuditVerdictAllowed, decideAttributionMatcher{
		wantAttemptedUserEmail: "", // nothing was displaced, so no claim is recorded
	})
	args[4] = assertedEmail // the header IS the attribution here
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := decideEnterpriseReq(t, DecideRequest{
		Stage:  DecisionStageLLM,
		Target: DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:  "hello",
	}, "auth-tenant", "auth-tenant")
	req.Header.Set(identityHeaderUserEmail, assertedEmail)

	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("with NO verified per-user identity the asserted header must remain the attribution "+
			"(#2896, unchanged) — the invariant constrains DISPLACEMENT of a verified identity, "+
			"not attribution in its absence: %v", err)
	}
}
