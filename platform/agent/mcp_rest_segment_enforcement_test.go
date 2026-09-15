// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// The four MCP REST handlers (mcpQueryHandler /mcp/resources/query,
// mcpExecuteHandler /mcp/tools/execute, mcpCheckInputHandler
// /api/v1/mcp/check-input, mcpCheckOutputHandler /api/v1/mcp/check-output)
// authenticate a real human via ResolveUser -> validateUserToken. What that
// principal still decides on these routes is pinned here: whether the audit
// row names it as a verified human (callerIsVerifiedHuman), and which
// idempotency scope a check-input response is cached under
// (mcpCheckInputIdempEndpoint, mcp_rest_principal.go).
//
// What it no longer decides is governance segments. The request pass is the
// anchored engine's mcp:request scope and the response pass its mcp:response
// scope; neither reads segments, so no route consults the segment resolver.
// The gate that resolved them (#3447) refused a verified human on behalf of an
// organization's segment-scoped rows, which no longer decide (PRD v11 §1.2).
//
// FIXTURE NOTE. The knownClients static AXON- whitelist keys only satisfy
// license.ValidateLicense in the COMMUNITY build, so a fixture relying on them
// passes VACUOUSLY under `-tags enterprise`. These tests reuse the
// minted-licence machinery from mcp_rest_user_token_rejected_test.go
// (utrSetupTestKeypair / utrGenTestLicenseKey / the knownClients swap) with an
// org_id added to the payload, so Basic auth succeeds identically in BOTH
// build lanes and auth.OrgID is a real org rather than "".

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
	"axonflow/platform/shared/idempotency"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
)

const (
	// seg3447MemberSegment is a segment a resolver returns for the caller, so
	// a plane that consulted one would have a membership to act on.
	seg3447MemberSegment = "finance-3447"

	seg3447OrgID = "org-3447"

	// seg3447Benign is content no policy intervenes on, so anything but an
	// allow is a refusal for some other reason.
	seg3447Benign = "what is the weather forecast"

	seg3447Connector = "test-db" // registered connector for query/execute
)

// =============================================================================
// Fixtures
// =============================================================================

// seg3447GenLicenseKey mints an Ed25519-signed AXON- license carrying org_id,
// signed with utrTestEntSeedB64 (valid only once utrSetupTestKeypair has
// overridden the embedded public keys). ServiceName is deliberately absent —
// see utrGenTestLicenseKey's comment: a service license would open
// validateServiceLicense's permission bypass and skip the tenant/connector
// authorization these tests need to pass through.
func seg3447GenLicenseKey(t *testing.T, tier, orgID string) string {
	t.Helper()
	seed, err := base64.StdEncoding.DecodeString(utrTestEntSeedB64)
	if err != nil {
		t.Fatalf("decode test seed: %v", err)
	}
	privKey := ed25519.NewKeyFromSeed(seed)

	type payload struct {
		Tier      string `json:"tier"`
		TenantID  string `json:"tenant_id"`
		OrgID     string `json:"org_id"`
		IssuedAt  string `json:"issued_at"`
		ExpiresAt string `json:"expires_at"`
	}
	p := payload{
		Tier:      tier,
		TenantID:  "seg3447-test-deployment",
		OrgID:     orgID,
		IssuedAt:  time.Now().Format("20060102"),
		ExpiresAt: time.Now().AddDate(1, 0, 0).Format("20060102"),
	}
	pJSON, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal license payload: %v", err)
	}
	pB64 := base64.RawURLEncoding.EncodeToString(pJSON)
	sig := ed25519.Sign(privKey, []byte(pB64))
	return "AXON-" + pB64 + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// setupSeg3447Test wires an enterprise deployment whose Basic auth succeeds in
// BOTH build lanes on a minted, org-bearing licence; a JWT secret so
// validateUserToken can validate the per-user tokens these tests mint; an
// empty connector registry (tests that need one register it); and nils the
// optional services so the only DB traffic is what a test wires for itself.
func setupSeg3447Test(t *testing.T) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	origAuthDB := authDB
	authDB = nil
	t.Cleanup(func() { authDB = origAuthDB })

	utrSetupTestKeypair(t)
	minted := seg3447GenLicenseKey(t, "Enterprise", seg3447OrgID)
	origEntry, existed := knownClients[utrTestClientID]
	var origCopy *ClientAuth
	if existed {
		c := *origEntry
		origCopy = &c
	}
	knownClients[utrTestClientID] = &ClientAuth{
		ClientID:    utrTestClientID,
		LicenseKey:  minted,
		Name:        "Seg3447 Test Client (minted license)",
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

	origSecret := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = origSecret })

	origRegistry := mcpRegistry
	mcpRegistry = registry.NewRegistry()
	t.Cleanup(func() { mcpRegistry = origRegistry })

	withChecker(t, nil)

	// usageDB nil: every audit writer these tests reach nil-guards on it.
	origUsageDB := usageDB
	usageDB = nil
	t.Cleanup(func() { usageDB = origUsageDB })

	sharedpolicy.ResetGlobalExfiltrationChecker()
	t.Cleanup(sharedpolicy.ResetGlobalExfiltrationChecker)

	// The detection-config cache is process-global and DEPLOYMENT_MODE just
	// changed under it.
	ResetDetectionConfigCache()
	t.Cleanup(ResetDetectionConfigCache)
}

// seg3447MintUserToken mints a valid per-user HS256 token for email. The
// email claim is the principal these routes attribute the request to.
func seg3447MintUserToken(t *testing.T, email string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":       sharedidentity.UserTokenIssuer,
		"sub":       email,
		"tenant_id": utrTestTenant,
		"org_id":    seg3447OrgID,
		"email":     email,
		"jti":       "jti-seg3447-" + email,
		"role":      "developer",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
	if err != nil {
		t.Fatalf("mint user token: %v", err)
	}
	return tok
}

func seg3447RegisterConnector(t *testing.T, conn *mockConnector) {
	t.Helper()
	if err := mcpRegistry.Register(seg3447Connector, conn,
		&base.ConnectorConfig{Name: seg3447Connector, TenantID: "*"}); err != nil {
		t.Fatalf("register connector: %v", err)
	}
}

// =============================================================================
// Route drivers — one per handler, all four driven as real HTTP requests so a
// regression in the HANDLER-side wiring (not just in the helper) is caught.
// =============================================================================

func seg3447Post(t *testing.T, path string, body interface{}, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	return seg3447PostWithHeaders(t, path, body, h, nil)
}

func seg3447PostWithHeaders(t *testing.T, path string, body interface{}, h http.HandlerFunc, extra http.Header) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	r := httptest.NewRequest("POST", path, bytes.NewBuffer(b))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", utrBasicAuthHeader())
	for k, vs := range extra {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func seg3447DoQuery(t *testing.T, token, statement string) *httptest.ResponseRecorder {
	t.Helper()
	return seg3447Post(t, "/mcp/resources/query", MCPQueryRequest{
		Connector: seg3447Connector, Statement: statement, UserToken: token,
	}, mcpQueryHandler)
}

func seg3447DoExecute(t *testing.T, token, statement string) *httptest.ResponseRecorder {
	t.Helper()
	return seg3447Post(t, "/mcp/tools/execute", MCPExecuteRequest{
		Connector: seg3447Connector, Action: "SELECT", Statement: statement, UserToken: token,
	}, mcpExecuteHandler)
}

func seg3447DoCheckInput(t *testing.T, token, statement string) *httptest.ResponseRecorder {
	t.Helper()
	return seg3447Post(t, "/api/v1/mcp/check-input", MCPCheckInputRequest{
		ConnectorType: "postgres", Statement: statement, UserToken: token,
	}, mcpCheckInputHandler)
}

func seg3447DoCheckOutput(t *testing.T, token, message string) *httptest.ResponseRecorder {
	t.Helper()
	return seg3447Post(t, "/api/v1/mcp/check-output", MCPCheckOutputRequest{
		ConnectorType: "postgres", Message: message, UserToken: token,
	}, mcpCheckOutputHandler)
}

func seg3447AssertAllowed(t *testing.T, w *httptest.ResponseRecorder, what string) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("%s: expected 200 (allowed), got %d: %s", what, w.Code, w.Body.String())
	}
}

// TestMCP3447_VerifiedHumanDiscriminator pins which callers count as a
// verified human, the fact the audit row's user attribution keys on
// (attributedUserEmail on check-input and check-output).
func TestMCP3447_VerifiedHumanDiscriminator(t *testing.T) {
	authErr := &AuthError{Code: "invalid_user_token"}
	const tok = "presented.jwt.value"
	cases := []struct {
		name  string
		kind  AuthKind
		err   *AuthError
		token string
		want  bool
	}{
		{"enterprise + validated token", AuthKindEnterprise, nil, tok, true},
		{"enterprise + ResolveUser error (synthetic service identity)", AuthKindEnterprise, authErr, tok, false},
		// A token-ABSENT enterprise caller reaches the synthetic service
		// identity, not a verified one — pinned explicitly because the
		// no-error/enterprise pair alone does not exclude it.
		{"enterprise + NO token presented", AuthKindEnterprise, nil, "", false},
		{"community", AuthKindCommunity, nil, tok, false},
		{"community-saas", AuthKindCommunitySaaS, nil, tok, false},
		{"internal service", AuthKindInternalService, nil, tok, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := callerIsVerifiedHuman(&AuthResult{Kind: tc.kind}, tc.err, tc.token)
			if got != tc.want {
				t.Fatalf("callerIsVerifiedHuman = %v, want %v", got, tc.want)
			}
		})
	}

	// The deployment-mode short-circuit: validateUserToken returns a synthetic
	// identity with NO error in community / community-SaaS deployments even
	// under AuthKindEnterprise, so the enterprise+no-error pair alone would
	// misclassify those synthetics as verified humans.
	for _, mode := range []string{"community", "community-saas"} {
		t.Run("deployment mode "+mode+" is never a verified human", func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)
			if callerIsVerifiedHuman(&AuthResult{Kind: AuthKindEnterprise}, nil, tok) {
				t.Fatalf("DEPLOYMENT_MODE=%s must never yield a verified human: validateUserToken "+
					"short-circuits there and the identity is synthetic", mode)
			}
		})
	}
}

// =============================================================================
// The check-input idempotency cache is scoped to the principal the verdict was
// computed for.
//
// idempotency.Wrap replays a cache hit WITHOUT invoking the handler, and its
// key is (org, tenant, Idempotency-Key, endpoint). The anchored engine decides
// for the admitted principal, so the endpoint carries the principal: a shared
// row would replay one principal's allow to another, on a key the caller
// chooses. The 403 caches the same way.
// =============================================================================

func TestMCP3447_IdempotencyScopeIsPerPrincipal(t *testing.T) {
	alice := mcpCheckInputIdempEndpoint("alice@corp.example")
	bob := mcpCheckInputIdempEndpoint("bob@corp.example")

	if alice == bob {
		t.Fatalf("two different principals share an idempotency scope (%q) — one could replay "+
			"the other's cached allow on a statement a published document refuses them", alice)
	}
	// A genuine retry by the SAME caller must still dedup, or the fix has
	// simply disabled idempotency on this route.
	if alice != mcpCheckInputIdempEndpoint("alice@corp.example") {
		t.Fatal("the same principal must map to a stable scope, otherwise no retry ever dedups")
	}
	// Canonicalised, so a case/whitespace variant is the same principal rather
	// than a second cache partition (and cannot be used to force a miss).
	if alice != mcpCheckInputIdempEndpoint("  Alice@Corp.Example  ") {
		t.Fatal("scope must be computed on the canonical identity, so a case variant is not a second partition")
	}
	// Identity material must not land in idempotency_keys.endpoint.
	if strings.Contains(alice, "alice") || strings.Contains(alice, "@") {
		t.Fatalf("scope leaks identity material into the endpoint column: %q", alice)
	}
	if !strings.HasPrefix(alice, "mcp.check-input|") {
		t.Fatalf("scope must stay recognisable as this endpoint, got %q", alice)
	}
}

// The wiring half: drive the real handler with two different verified
// principals and assert the STORE was consulted with two different endpoint
// values. TestMCP3447_IdempotencyScopeIsPerPrincipal alone would pass even if
// the helper were never called.
func TestMCP3447_CheckInputIdempotencyLookupIsScopedToPrincipal(t *testing.T) {
	seen := make([]string, 0, 2)

	for _, email := range []string{"alice-idem-3447@corp.example", "bob-idem-3447@corp.example"} {
		setupSeg3447Test(t)

		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		t.Cleanup(func() { _ = mockDB.Close() })
		// rls.WithOrgAndTenantScope opens a txn and sets two GUCs before the
		// lookup. Declare that shape for the Lookup txn; the handler's own
		// later writes fall through harmlessly once the capture has happened.
		mock.MatchExpectationsInOrder(false)
		mock.ExpectBegin()
		for i := 0; i < 5; i++ {
			mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 1))
		}
		mock.ExpectQuery("FROM idempotency_keys").
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), endpointCapture{&seen}).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()

		origStore := mcpIdempStore
		mcpIdempStore = idempotency.NewStore(mockDB, nil)
		t.Cleanup(func() { mcpIdempStore = origStore })

		seg3447PostWithHeaders(t, "/api/v1/mcp/check-input", MCPCheckInputRequest{
			ConnectorType: "postgres",
			Statement:     seg3447Benign,
			UserToken:     seg3447MintUserToken(t, email),
		}, mcpCheckInputHandler, http.Header{"Idempotency-Key": []string{"shared-key-3447"}})
	}

	// sqlmock may consult an argument matcher more than once while resolving
	// expectations, so compare the DISTINCT endpoints rather than the raw
	// capture count.
	distinct := map[string]struct{}{}
	for _, e := range seen {
		distinct[e] = struct{}{}
	}
	if len(seen) == 0 {
		t.Fatal("the idempotency store was never consulted — the wiring assertion measured nothing")
	}
	if len(distinct) != 2 {
		t.Fatalf("two different principals must look up two different idempotency rows; got %d distinct "+
			"endpoint(s) %v — a shared row replays one principal's decision to another",
			len(distinct), seen)
	}
}

// endpointCapture records the endpoint argument the store was queried with and
// always matches, so the assertion lives in the test body rather than in the
// matcher.
type endpointCapture struct{ into *[]string }

func (c endpointCapture) Match(v driver.Value) bool {
	if s, ok := v.(string); ok {
		*c.into = append(*c.into, s)
	}
	return true
}

// TestMCP3447_RoutesAreDecidedWithoutConsultingSegments: every MCP REST route
// is decided by the anchored engine, which reads no segments, so none of the
// four consults the segment resolver, even for a verified human whose
// resolution would fail, and that failure changes no verdict (PRD v11 §1.1,
// §1.2).
func TestMCP3447_RoutesAreDecidedWithoutConsultingSegments(t *testing.T) {
	for _, rt := range []struct {
		name  string
		drive func(t *testing.T, token, content string) *httptest.ResponseRecorder
	}{
		{"resources/query", seg3447DoQuery},
		{"tools/execute", seg3447DoExecute},
		{"check-input", seg3447DoCheckInput},
		{"check-output", seg3447DoCheckOutput},
	} {
		t.Run(rt.name, func(t *testing.T) {
			setupSeg3447Test(t)
			seg3447RegisterConnector(t, &mockConnector{})
			res := &fakeSegmentResolver{err: errors.New("segment query failed (3447)")}
			withFleetSegmentResolver(t, res)

			w := rt.drive(t, seg3447MintUserToken(t, "verified-3447@corp.example"), seg3447Benign)

			seg3447AssertAllowed(t, w, rt.name+" for a verified human whose segment resolution would fail")
			if c := res.callCount(); c != 0 {
				t.Fatalf("%s consulted the segment resolver %d time(s); the anchored engine reads no segments", rt.name, c)
			}
		})
	}
}
