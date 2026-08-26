// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"bytes"
	"crypto/ed25519"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"

	"axonflow/platform/agent/license"
	"axonflow/platform/connectors/registry"
)

// =============================================================================
// #3472 — the four legacy MCP REST handlers (mcpQueryHandler, mcpExecuteHandler,
// mcpCheckInputHandler, mcpCheckOutputHandler) previously collapsed EVERY
// ResolveUser failure into the enterprise service-user downgrade, so a
// malformed / expired / wrong-alg / bad-signature / jti-revoked user_token
// presented alongside a valid shared Basic credential was silently served as
// an unenforced "service" identity instead of being rejected. Revocation did
// not revoke on these four routes.
//
// The fix (decision_handler.go:788 shape, applied verbatim): the synthetic
// service-user fallback now requires BOTH AuthKindEnterprise AND an ABSENT
// user_token (req.UserToken == ""). A PRESENTED-but-invalid token takes the
// else-branch: audited (policy_ids=["user_token_rejected"]), then 401.
//
// These tests exercise the four HTTP handlers directly (not ResolveUser in
// isolation) so a regression in the handler-side condition — not just in
// ResolveUser — is caught.
// =============================================================================

// utrTestClientID / utrTestTenant: the in-memory enterprise whitelist client
// used to drive real Basic-auth success without a DB. The whitelist entry's
// LicenseKey is swapped out (see utrInjectMintedWhitelistEntry) for a license
// this test mints and self-verifies with an overridden Ed25519 keypair, so
// Basic auth succeeds identically under BOTH the community and `-tags
// enterprise` builds — see R3 HIGH-1: the *shipped* healthcare-demo key only
// validates in the community build (its signature is stale against the
// production key, which the community loader forgives via a soft fallback
// but the enterprise loader treats as a hard authentication failure), which
// left these tests unable to run — not merely skip — under `-tags
// enterprise`, the exact lane CI's `go test -tags enterprise ./...` covers.
const (
	utrTestClientID = "healthcare-demo"
	utrTestTenant   = "healthcare_tenant"
)

// utrMalformedToken is not a JWT at all — validateUserToken's jwt.Parse fails
// immediately.
const utrMalformedToken = "not-a-valid-jwt-token"

// --- build-tag-independent license minting -------------------------------
//
// Ported from platform/orchestrator/policy_tier_test.go (testEntSeedB64,
// genTestLicenseKey, setupTestKeypair — an untagged file that already proves
// this pattern works under both build tags). Renamed utr-prefixed and kept
// local to this package rather than exported/shared: orchestrator and agent
// are different packages, and the license package's untagged
// OverridePublicKeysForTest seam (agent/license/testing.go) is the only thing
// that needs to be shared, which it already is.

// utrTestEntSeedB64 is a throwaway Ed25519 seed used ONLY to sign license
// keys minted by this test file. It is not a production key and never
// verifies against the production public keys embedded in the binary.
const utrTestEntSeedB64 = "fifqSWAaVJy1qk89VwvqXYnXmlSCF3VfGRiK4e1kF0g="

// utrGenTestLicenseKey mints an Ed25519-signed AXON- license key for the
// given tier, signed with utrTestEntSeedB64. Only valid once
// utrSetupTestKeypair has overridden the package's embedded public keys to
// match — otherwise it verifies against neither the evaluation nor
// enterprise production key, in either build.
func utrGenTestLicenseKey(tier string) string {
	seed, _ := base64.StdEncoding.DecodeString(utrTestEntSeedB64)
	privKey := ed25519.NewKeyFromSeed(seed)

	// Deliberately no ServiceName/ServiceType/Permissions (unlike
	// orchestrator/policy_tier_test.go's genTestLicenseKey, which this is
	// ported from): mcp_handler.go's validateServiceLicense grants a
	// service-license permission bypass whenever validationResult.ServiceName
	// != "", short-circuiting past the tenant/connector-authorization check
	// these tests rely on for their (empirically-determined, non-401) control
	// status. Leaving ServiceName empty keeps this a plain client-credential
	// license — Basic auth succeeds, but no MCP-permission side door opens.
	type payload struct {
		Tier      string `json:"tier"`
		TenantID  string `json:"tenant_id"`
		IssuedAt  string `json:"issued_at"`
		ExpiresAt string `json:"expires_at"`
	}

	p := payload{
		Tier:      tier,
		TenantID:  "utr-test-deployment",
		IssuedAt:  time.Now().Format("20060102"),
		ExpiresAt: time.Now().AddDate(1, 0, 0).Format("20060102"),
	}
	pJSON, _ := json.Marshal(p)
	pB64 := base64.RawURLEncoding.EncodeToString(pJSON)
	sig := ed25519.Sign(privKey, []byte(pB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return "AXON-" + pB64 + "." + sigB64
}

// utrSetupTestKeypair overrides the license package's embedded production
// public keys (both the evaluation and enterprise slots — these tests only
// mint Enterprise-tier licenses) with the public half of utrTestEntSeedB64,
// via the untagged agent/license.OverridePublicKeysForTest seam. Restored in
// t.Cleanup. Not safe for concurrent use (matches the seam's own contract);
// none of these tests call t.Parallel().
func utrSetupTestKeypair(t *testing.T) {
	t.Helper()
	seed, _ := base64.StdEncoding.DecodeString(utrTestEntSeedB64)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	restore := license.OverridePublicKeysForTest(pub, pub)
	t.Cleanup(restore)
}

// utrInjectMintedWhitelistEntry overrides knownClients[utrTestClientID]'s
// LicenseKey with a freshly minted, self-verifying Enterprise license (see
// utrSetupTestKeypair/utrGenTestLicenseKey above), so Basic auth succeeds via
// license.ValidateLicense in BOTH build lanes instead of relying on the
// shipped whitelist entry's key (community-build-only, per R3 HIGH-1).
// TenantID is set explicitly to utrTestTenant so the minted token's
// tenant_id claim matches client.TenantID and none of these tests trip the
// `user.TenantID != client.TenantID` 403 (mcp_handler.go:1867/2326/2904/3467)
// by accident. The prior whitelist entry (or its absence) is restored
// exactly in t.Cleanup to avoid cross-test pollution — authDB is nil for the
// duration of this package's whitelist-path tests, but other test files in
// this package (e.g. mcp_identity_test.go's withEnterpriseWhitelist) read
// this same map.
func utrInjectMintedWhitelistEntry(t *testing.T) {
	t.Helper()
	utrSetupTestKeypair(t)
	minted := utrGenTestLicenseKey("Enterprise")

	origEntry, existed := knownClients[utrTestClientID]
	var origCopy *ClientAuth
	if existed {
		c := *origEntry
		origCopy = &c
	}
	knownClients[utrTestClientID] = &ClientAuth{
		ClientID:    utrTestClientID,
		LicenseKey:  minted,
		Name:        "UTR Test Client (minted license)",
		TenantID:    utrTestTenant,
		Permissions: []string{"query", "llm", "connectors", "planning"},
		RateLimit:   1000,
		Enabled:     true,
	}
	t.Cleanup(func() {
		if existed {
			knownClients[utrTestClientID] = origCopy
		} else {
			delete(knownClients, utrTestClientID)
		}
	})
}

// setupMCPUserTokenRejectedTest wires enterprise mode with the in-memory
// (no-DB) client whitelist so Basic auth succeeds without a real authDB
// (via a minted license — see utrInjectMintedWhitelistEntry), and gives the
// two connector-exec handlers a non-nil (empty) registry so they pass their
// leading `mcpRegistry == nil` guard and reach ResolveUser.
func setupMCPUserTokenRejectedTest(t *testing.T) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	origAuthDB := authDB
	authDB = nil
	t.Cleanup(func() { authDB = origAuthDB })

	utrInjectMintedWhitelistEntry(t)

	origSecret := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = origSecret })

	origRegistry := mcpRegistry
	mcpRegistry = registry.NewRegistry()
	t.Cleanup(func() { mcpRegistry = origRegistry })

	// Baseline: no revocation checker wired unless a test opts in via withChecker.
	withChecker(t, nil)
}

func utrBasicAuthHeader() string {
	creds := base64.StdEncoding.EncodeToString([]byte(utrTestClientID + ":" + knownClients[utrTestClientID].LicenseKey))
	return "Basic " + creds
}

// --- token minting helpers -------------------------------------------------

func utrMintValidToken(t *testing.T, jti string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"tenant_id": utrTestTenant,
		"email":     "user@example.com",
		"role":      "user",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	if jti != "" {
		claims["jti"] = jti
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
	if err != nil {
		t.Fatalf("mint valid user token: %v", err)
	}
	return tok
}

func utrMintExpiredToken(t *testing.T) string {
	t.Helper()
	claims := jwt.MapClaims{
		"tenant_id": utrTestTenant,
		"email":     "user@example.com",
		"exp":       time.Now().Add(-time.Hour).Unix(),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
	if err != nil {
		t.Fatalf("mint expired user token: %v", err)
	}
	return tok
}

func utrMintBadSignatureToken(t *testing.T) string {
	t.Helper()
	claims := jwt.MapClaims{
		"tenant_id": utrTestTenant,
		"email":     "user@example.com",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("a-completely-different-secret"))
	if err != nil {
		t.Fatalf("mint bad-signature user token: %v", err)
	}
	return tok
}

func utrMintAlgNoneToken(t *testing.T) string {
	t.Helper()
	claims := jwt.MapClaims{
		"tenant_id": utrTestTenant,
		"email":     "user@example.com",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("mint alg:none user token: %v", err)
	}
	return s
}

// --- request drivers ---------------------------------------------------

func utrDoQuery(t *testing.T, userToken string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(MCPQueryRequest{
		Connector: "test-db",
		Statement: "SELECT 1",
		UserToken: userToken,
	})
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", utrBasicAuthHeader())
	w := httptest.NewRecorder()
	mcpQueryHandler(w, req)
	return w
}

func utrDoExecute(t *testing.T, userToken string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(MCPExecuteRequest{
		Connector: "test-db",
		Action:    "INSERT",
		Statement: "INSERT INTO t VALUES (1)",
		UserToken: userToken,
	})
	req := httptest.NewRequest("POST", "/mcp/tools/execute", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", utrBasicAuthHeader())
	w := httptest.NewRecorder()
	mcpExecuteHandler(w, req)
	return w
}

func utrDoCheckInput(t *testing.T, userToken string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
		UserToken:     userToken,
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", utrBasicAuthHeader())
	w := httptest.NewRecorder()
	mcpCheckInputHandler(w, req)
	return w
}

func utrDoCheckOutput(t *testing.T, userToken string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Message:       "1 row affected",
		UserToken:     userToken,
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", utrBasicAuthHeader())
	w := httptest.NewRecorder()
	mcpCheckOutputHandler(w, req)
	return w
}

// utrPolicyIDsMatcher asserts the policy_details JSONB column's policy_ids
// array contains an EXACT element equal to `want` — JSONB containment, never
// a LIKE/substring match (a `_` in LIKE is a single-char wildcard and would
// false-positive on unrelated prose sharing the same row).
type utrPolicyIDsMatcher struct{ want string }

func (m utrPolicyIDsMatcher) Match(v driver.Value) bool {
	raw, ok := jsonbBytes(v)
	if !ok {
		return false
	}
	var d map[string]interface{}
	if json.Unmarshal(raw, &d) != nil {
		return false
	}
	ids, ok := d["policy_ids"].([]interface{})
	if !ok {
		return false
	}
	for _, id := range ids {
		if s, ok := id.(string); ok && s == m.want {
			return true
		}
	}
	return false
}

// utrAssertUserTokenRejected pins WHY a 401 happened, not just that one
// happened (R3 HIGH-2). A failed Basic auth ALSO returns 401 with
// success=false — that similarity is exactly why the enterprise-lane
// authentication failure (R3 HIGH-1) hid behind these tests, unnoticed, for a
// full review round: every rejection test asserted only the status code, so
// Authenticate() failing before ResolveUser was ever reached looked
// identical to a passing test.
//
// ResolveUser's rejection path (authenticator.go:325) always formats its
// message as "Invalid user token: <cause>" — assert that prefix so an
// auth-layer 401 (bad credentials, disabled client, license failure) can
// never be mistaken for the user-token-rejection 401 this fix produces.
//
// Also checks the defect's actual signature: the pre-fix bug SILENTLY
// DOWNGRADED a presented-but-invalid token to the synthetic enterprise
// service identity (email client.ID+"@axonflow.local") instead of rejecting
// it. Confirms that marker never appears in the response body.
func utrAssertUserTokenRejected(t *testing.T, w *httptest.ResponseRecorder, cause string) {
	t.Helper()

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("cause=%s: expected 401 (rejected, NOT downgraded to service), got %d: %s",
			cause, w.Code, w.Body.String())
	}

	var resp ClientResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("cause=%s: decode response: %v", cause, err)
	}
	if resp.Success {
		t.Fatalf("cause=%s: expected success=false on rejection", cause)
	}
	if !strings.HasPrefix(resp.Error, "Invalid user token:") {
		t.Fatalf("cause=%s: expected a user-token-rejection message (prefix %q), got %q — "+
			"this 401 may be an unrelated auth failure (bad Basic credentials, license "+
			"validation, etc.) masquerading as the rejection under test",
			cause, "Invalid user token:", resp.Error)
	}
	// NOTE: no response-body check for the synthetic service email here. None
	// of the four response shapes (ClientResponse, MCPCheckInputResponse,
	// MCPCheckOutputResponse) carries a user email at all, so such a check
	// discriminates nothing — it would pass against the pre-fix downgrade too.
	// The status + message prefix above already catch the downgrade; the real
	// proof that the row is not attributed to the synthetic identity is the
	// AUDIT assertion in TestMCPCheckInputHandler_UserTokenRejected_AuditsBlockedRow,
	// which pins user_email and is mutation-proved.
}

// =============================================================================
// Per-cause rejection matrix — check-input carries the full cause matrix;
// the other three handlers each get one representative cause below.
// =============================================================================

func TestMCPCheckInputHandler_RejectsPresentedInvalidToken(t *testing.T) {
	cases := []struct {
		name  string
		token func(t *testing.T) string
	}{
		{"malformed", func(t *testing.T) string { return utrMalformedToken }},
		{"wrong signing algorithm (alg:none)", utrMintAlgNoneToken},
		{"bad signature", utrMintBadSignatureToken},
		{"expired", utrMintExpiredToken},
		{"jti revoked", func(t *testing.T) string {
			withChecker(t, &fakeRevocations{revoked: true})
			return utrMintValidToken(t, "jti-dead")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupMCPUserTokenRejectedTest(t)
			mock := withMockUsageDB(t)
			mock.MatchExpectationsInOrder(false)
			mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

			token := tc.token(t)
			w := utrDoCheckInput(t, token)

			utrAssertUserTokenRejected(t, w, tc.name)
		})
	}
}

func TestMCPQueryHandler_RejectsPresentedInvalidToken(t *testing.T) {
	setupMCPUserTokenRejectedTest(t)
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	w := utrDoQuery(t, utrMalformedToken)

	utrAssertUserTokenRejected(t, w, "malformed")
}

func TestMCPExecuteHandler_RejectsPresentedInvalidToken(t *testing.T) {
	setupMCPUserTokenRejectedTest(t)
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	w := utrDoExecute(t, utrMalformedToken)

	utrAssertUserTokenRejected(t, w, "malformed")
}

func TestMCPCheckOutputHandler_RejectsPresentedInvalidToken(t *testing.T) {
	setupMCPUserTokenRejectedTest(t)
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	w := utrDoCheckOutput(t, utrMalformedToken)

	utrAssertUserTokenRejected(t, w, "malformed")
}

// =============================================================================
// Revocation control pair (R3 MEDIUM-1) — a bare 401 on a revoked token
// proves nothing by itself: a token that's invalid for an unrelated reason
// (wrong tenant, a broken fixture, an unparseable claim) yields the identical
// 401. The only way to prove REVOCATION specifically caused the denial is a
// paired control: the SAME minted token (same jti, same fixture), differing
// ONLY in what the revocation checker reports, must behave oppositely.
//
// utrQueryHandlerNonRevokedDeniedStatus is 403 "Unauthorized connector
// access" (not a 2xx) — determined empirically, not guessed: "test-db" isn't
// a connector configured for utrTestTenant in this fixture, so even a
// legitimately-resolved, non-revoked real user is denied by the downstream
// tenant/connector authorization check (mcp_handler.go:1892). That's fine —
// what this test proves is that the request got PAST ResolveUser (a 401
// there would look identical to the revoked case), which only happens when
// revocation is NOT what's rejecting it.
// =============================================================================

const utrQueryHandlerNonRevokedDeniedStatus = http.StatusForbidden

func TestMCPQueryHandler_RevokedTokenControl(t *testing.T) {
	const controlJTI = "jti-utr-revocation-control"

	t.Run("revoked_is_denied_not_demoted", func(t *testing.T) {
		setupMCPUserTokenRejectedTest(t)
		withChecker(t, &fakeRevocations{revoked: true})
		mock := withMockUsageDB(t)
		mock.MatchExpectationsInOrder(false)
		mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

		token := utrMintValidToken(t, controlJTI)
		w := utrDoQuery(t, token)

		utrAssertUserTokenRejected(t, w, "revoked")
	})

	t.Run("not_revoked_is_not_denied", func(t *testing.T) {
		setupMCPUserTokenRejectedTest(t)
		withChecker(t, &fakeRevocations{revoked: false})
		mock := withMockUsageDB(t)
		mock.MatchExpectationsInOrder(false)
		mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

		// Same jti as the revoked half above — only the checker's `revoked`
		// flag differs between the two subtests.
		token := utrMintValidToken(t, controlJTI)
		w := utrDoQuery(t, token)

		if w.Code != utrQueryHandlerNonRevokedDeniedStatus {
			t.Fatalf("not-revoked token: expected %d (past ResolveUser, denied downstream "+
				"for an unrelated reason), got %d: %s",
				utrQueryHandlerNonRevokedDeniedStatus, w.Code, w.Body.String())
		}
		// The exact-status check above already excludes 401, so a separate
		// "is it 401" branch here would be unreachable. The pair's meaning is
		// carried by that exact match: the not-revoked half must reach a
		// DOWNSTREAM outcome, not any refusal.

	})
}

// =============================================================================
// Compatibility path intact — an enterprise caller presenting NO token is
// still served by the synthetic-service fallback. Regression guard for the
// population #3476 owns (infra gateways with no end-user JWT to forward).
//
// R3 MEDIUM-2: the prior `if w.Code == http.StatusUnauthorized { t.Fatalf }`
// shape passes on ANY non-401 outcome — a 500, a 403 that means something
// went wrong elsewhere, anything. Pin the ACTUAL expected status for each
// handler (determined empirically below, not guessed) and assert with `!=`
// so a regression that breaks the compat path in some other way (not a 401)
// is still caught.
//
// Query/Execute: "test-db" isn't a connector configured for utrTestTenant in
// this fixture, so even the synthetic service identity — which DOES have
// "connectors" permission — is denied by the downstream tenant/connector
// authorization check (mcp_handler.go:1892/2382), 403 "Unauthorized
// connector access". That 403 is what proves the compat fallback ran: had
// the fix's condition wrongly rejected the absent-token case, this would be
// a 401 from ResolveUser instead.
//
// Check-Input/Check-Output: no connector-authorization gate on this path;
// the synthetic service user's static policy evaluation runs to completion
// and allows the (harmless) fixture statement, 200 {"allowed":true,...}.
// =============================================================================

const (
	utrQueryExecuteCompatStatus     = http.StatusForbidden // "Unauthorized connector access" — reached AFTER ResolveUser succeeded
	utrCheckInputOutputCompatStatus = http.StatusOK
)

func TestMCPQueryHandler_AbsentToken_CompatFallbackIntact(t *testing.T) {
	setupMCPUserTokenRejectedTest(t)
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	w := utrDoQuery(t, "")

	if w.Code != utrQueryExecuteCompatStatus {
		t.Fatalf("absent token must still hit the compat service-user fallback (expected %d), got %d: %s",
			utrQueryExecuteCompatStatus, w.Code, w.Body.String())
	}
}

func TestMCPExecuteHandler_AbsentToken_CompatFallbackIntact(t *testing.T) {
	setupMCPUserTokenRejectedTest(t)
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	w := utrDoExecute(t, "")

	if w.Code != utrQueryExecuteCompatStatus {
		t.Fatalf("absent token must still hit the compat service-user fallback (expected %d), got %d: %s",
			utrQueryExecuteCompatStatus, w.Code, w.Body.String())
	}
}

func TestMCPCheckInputHandler_AbsentToken_CompatFallbackIntact(t *testing.T) {
	setupMCPUserTokenRejectedTest(t)
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	w := utrDoCheckInput(t, "")

	if w.Code != utrCheckInputOutputCompatStatus {
		t.Fatalf("absent token must still hit the compat service-user fallback (expected %d), got %d: %s",
			utrCheckInputOutputCompatStatus, w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("compat service-user path expected to allow the fixture statement, got block_reason=%q", resp.BlockReason)
	}
}

func TestMCPCheckOutputHandler_AbsentToken_CompatFallbackIntact(t *testing.T) {
	setupMCPUserTokenRejectedTest(t)
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	w := utrDoCheckOutput(t, "")

	if w.Code != utrCheckInputOutputCompatStatus {
		t.Fatalf("absent token must still hit the compat service-user fallback (expected %d), got %d: %s",
			utrCheckInputOutputCompatStatus, w.Code, w.Body.String())
	}
	var resp MCPCheckOutputResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("compat service-user path expected to allow the fixture message, got block_reason=%q", resp.BlockReason)
	}
}

// =============================================================================
// Audit assertion — the blocked audit_logs row must carry the
// "user_token_rejected" marker in policy_details->'policy_ids', via JSONB
// containment (utrPolicyIDsMatcher), never a LIKE substring match.
// =============================================================================

func TestMCPCheckInputHandler_UserTokenRejected_AuditsBlockedRow(t *testing.T) {
	setupMCPUserTokenRejectedTest(t)
	mock := withMockUsageDB(t)

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(),         // id
			sqlmock.AnyArg(),         // request_id
			sqlmock.AnyArg(),         // timestamp
			sqlmock.AnyArg(),         // user_id (unresolved user → 0)
			"unknown@axonflow.local", // user_email: writeMCPDecisionAudit's "" fallback.
			// R3 HIGH-2 (at-least-one-cause check): pinned, not AnyArg — this is
			// the audit-row evidence that the defect's actual signature (a
			// silent downgrade to the synthetic enterprise service identity,
			// email client.ID+"@axonflow.local", i.e.
			// "healthcare-demo@axonflow.local") did NOT happen. A regression
			// that downgraded instead of rejecting would write that synthetic
			// email here, not the generic unresolved-caller placeholder.
			"unknown", // user_role: #3472 — deliberately "" -> "unknown",
			// NOT "service" (RBAC-1: no user was resolved here, so
			// "service" would be a fabrication; divergence from the
			// sibling tenant_mismatch rows on this same plane).
			sqlmock.AnyArg(),  // client_id
			sqlmock.AnyArg(),  // tenant_id
			sqlmock.AnyArg(),  // org_id
			"mcp_check_input", // request_type
			sqlmock.AnyArg(),  // query (non-PII descriptor)
			sqlmock.AnyArg(),  // query_hash
			mcpVerdictBlocked, // policy_decision
			utrPolicyIDsMatcher{want: "user_token_rejected"}, // policy_details JSONB
			sqlmock.AnyArg(), // decision_id
			PlaneMCP,         // plane
			nil,              // correlation_id (no traceparent header)
			nil,              // redacted_fields
			nil,              // session_id
			sqlmock.AnyArg(), // response_time_ms
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := utrDoCheckInput(t, utrMalformedToken)

	utrAssertUserTokenRejected(t, w, "malformed")
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("rejected user_token must write a blocked audit row carrying user_token_rejected: %v", err)
	}
}

// =============================================================================
// Negative control — the token-ABSENT (compat) path must write NO
// user_token_rejected row. Implemented by declaring the expectation we must
// NEVER see satisfied: sqlmock only marks an ExpectExec expectation fulfilled
// when an actual INSERT's arguments match it — WithArgs' per-position
// matchers, including utrPolicyIDsMatcher's JSONB-containment check on
// policy_details, all have to agree. If the compat path issues an audit
// INSERT whose policy_details carries the "user_token_rejected" marker, that
// match succeeds, the expectation is recorded fulfilled, and
// ExpectationsWereMet() returns nil — which this test treats as FAILURE.
// The passing outcome is the expectation staying unfulfilled: either no
// INSERT happened at all, or one happened but didn't carry the marker.
//
// R3 LOW-1: the original version of this test discarded the recorder and
// never asserted the request actually reached a real (non-401) outcome. If
// the handler had failed early for an unrelated reason (auth, a panic
// recovered elsewhere, etc.), no audit row would be written either way, the
// "unmet expectation" would still read as a pass, and the test would prove
// nothing. Capture the recorder and pin the compat path's real status
// (utrCheckInputOutputCompatStatus, 200 allowed=true) BEFORE trusting the
// audit-absence assertion.
// =============================================================================

// utrCapturePolicyIDs records every audit INSERT's policy_ids, for BOTH audit
// writers this plane can reach: writeMCPDecisionAudit's 20-column INSERT and
// the decide-plane writer's 21-column one. Both put policy_details at
// position 14.
//
// Capture rather than a match/no-match expectation, because sqlmock rejects on
// argument COUNT before it ever consults an argument matcher. A single-arity
// expectation against the other writer is unmet because of the column count,
// not because the marker was absent — which is how this control previously
// passed while measuring nothing.
func utrCapturePolicyIDs(mock sqlmock.Sqlmock, into *[]string) {
	for _, argc := range []int{20, 21} {
		args := make([]driver.Value, argc)
		for i := range args {
			args[i] = sqlmock.AnyArg()
		}
		args[13] = policyIDsCapture{into}
		mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
}

// policyIDsCapture always matches and records the policy_ids it saw, so the
// assertion lives in the test body rather than in the matcher.
type policyIDsCapture struct{ into *[]string }

func (c policyIDsCapture) Match(v driver.Value) bool {
	raw, ok := jsonbBytes(v)
	if !ok {
		return true
	}
	var d struct {
		PolicyIDs []string `json:"policy_ids"`
	}
	if json.Unmarshal(raw, &d) == nil {
		*c.into = append(*c.into, d.PolicyIDs...)
	}
	return true
}

func containsStr(hay []string, want string) bool {
	for _, h := range hay {
		if h == want {
			return true
		}
	}
	return false
}

// The absence control, with its own POSITIVE control.
//
// "No matching row" proves nothing on its own — it is satisfied equally by
// "the marker was absent" and by "the assertion could never have fired". The
// rejected-token sub-run rules the second out using the SAME capture, so if
// the capture stops working that sub-run fails loudly instead of the absence
// sub-run passing quietly.
func TestMCPCheckInputHandler_UserTokenRejectedRow_PresentThenAbsent(t *testing.T) {
	t.Run("positive control: a REJECTED token does write the marker", func(t *testing.T) {
		setupMCPUserTokenRejectedTest(t)
		mock := withMockUsageDB(t)
		mock.MatchExpectationsInOrder(false)
		var seen []string
		utrCapturePolicyIDs(mock, &seen)

		w := utrDoCheckInput(t, utrMalformedToken)
		utrAssertUserTokenRejected(t, w, "malformed")

		if !containsStr(seen, "user_token_rejected") {
			t.Fatalf("the rejected-token deny wrote NO audit row carrying user_token_rejected "+
				"(captured %v) — the absence control below would then be vacuous", seen)
		}
	})

	t.Run("a token-less (compat) caller writes no such row", func(t *testing.T) {
		setupMCPUserTokenRejectedTest(t)
		mock := withMockUsageDB(t)
		mock.MatchExpectationsInOrder(false)
		var seen []string
		utrCapturePolicyIDs(mock, &seen)

		w := utrDoCheckInput(t, "")

		if w.Code != utrCheckInputOutputCompatStatus {
			t.Fatalf("absent token must reach the real compat outcome (expected %d) before the "+
				"audit-absence assertion means anything, got %d: %s",
				utrCheckInputOutputCompatStatus, w.Code, w.Body.String())
		}
		var resp MCPCheckInputResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if !resp.Allowed {
			t.Fatalf("compat service-user path expected to allow the fixture statement, got block_reason=%q", resp.BlockReason)
		}
		// The load-bearing assertions for this sub-run are the two above: the
		// compat path reaches its real outcome and ALLOWS. The audit check
		// below is corroborative only, and deliberately does not require the
		// capture to be non-empty: this path's audit write is not observable
		// through the sqlmock seam here (its INSERT does not reach the
		// expectations this test declares), so demanding a row would fail for
		// a reason unrelated to the property under test.
		//
		// The absence claim is proven where it can be: on a live stack, by
		// runtime-e2e/3472_mcp_rest_token_rejected assertion [17], which now
		// refuses to read a zero over a window it has not first proven
		// non-empty.
		if containsStr(seen, "user_token_rejected") {
			t.Fatalf("absent (compat) token wrote a user_token_rejected audit row: captured %v", seen)
		}
	})
}
