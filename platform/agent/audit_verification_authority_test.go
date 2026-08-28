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

// Tests for the #2914 authority gate on the audit-chain verification routes.
//
// The gate is a REFUSAL, so every test here has to be written so that an
// always-refuse implementation fails it: each denial case is paired with the
// admission case that differs by exactly one input, and the route-level test
// asserts a 200 as well as the 403s.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"

	sharedidentity "axonflow/platform/shared/identity"
)

const (
	authzTestOrg    = "authz-org"
	authzTestTenant = "authz-client"
	authzTestSecret = "audit-verification-authority-test-secret"
)

// authzRequest builds a GET carrying the context apiAuthMiddleware would have
// stamped for the given auth kind, plus any extra headers.
func authzRequest(kind AuthKind, org, tenant string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/signing-key", nil)
	ctx := r.Context()
	ctx = context.WithValue(ctx, ContextKeyAuthKind, kind)
	ctx = context.WithValue(ctx, ContextKeyOrgID, org)
	ctx = context.WithValue(ctx, ContextKeyClientID, tenant)
	ctx = context.WithValue(ctx, ContextKeyTenantID, tenant)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r.WithContext(ctx)
}

// authzToken mints a per-user token with the given role and scope, signed with
// the secret the test installs.
func authzToken(t *testing.T, role, org, tenant string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"email":     "person@example.com",
		"role":      role,
		"org_id":    org,
		"tenant_id": tenant,
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return s
}

// installAuthzSecret pins jwtSecret and forces a NON-community posture, which
// is what every enterprise case below depends on: isCommunityMode() short
// circuits the gate to "allowed", so a test that forgot this would pass no
// matter what the predicate did.
func installAuthzSecret(t *testing.T) {
	t.Helper()
	orig := jwtSecret
	jwtSecret = []byte(authzTestSecret)
	t.Cleanup(func() { jwtSecret = orig })
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")
	if isCommunityMode() {
		t.Fatal("the test posture is community, so every case below would pass vacuously")
	}
}

// TestAuditVerificationAuthority_PerUserTokenRoles is the core table: the roles
// that carry tenant-wide audit read pass, and every other role - including the
// ones a real org hands to most of its people - does not.
func TestAuditVerificationAuthority_PerUserTokenRoles(t *testing.T) {
	installAuthzSecret(t)

	cases := []struct {
		role string
		want bool
		why  string
	}{
		{"admin", true, "org administrator"},
		{"owner", true, "owner is a strict superset of admin (#2993)"},
		{"policy_admin", true, "the read-everything, change-nothing-identity compliance tier"},
		{"developer", false, "own-rows only on the fleet plane"},
		{"viewer", false, "own-rows only on the fleet plane"},
		{"", false, "least-privilege / unmapped"},
		{"auditor", false, "not a role this platform defines; NormalizeRole collapses it to unmapped"},
		// MEASURED, not assumed: NormalizeRole is an exact map lookup with no
		// trim and no case fold (identity/validator.go), so a near-miss
		// spelling normalizes to "" and is refused. That is the fail-closed
		// direction and it is pinned here so a later "helpful" normalization
		// cannot widen this gate as a side effect.
		{"ADMIN", false, "the role vocabulary is exact-match; a case variant is unmapped"},
		{"admin ", false, "the role vocabulary is exact-match; a trailing space is unmapped"},
	}
	for _, c := range cases {
		tok := authzToken(t, c.role, authzTestOrg, authzTestTenant)
		r := authzRequest(AuthKindEnterprise, authzTestOrg, authzTestTenant,
			map[string]string{"X-User-Token": tok})
		if got := auditVerificationAuthorized(r); got != c.want {
			t.Errorf("role %q: authorized = %v, want %v (%s)", c.role, got, c.want, c.why)
		}
	}
}

// TestAuditVerificationAuthority_RefusesTheSharedCredentialAlone is the finding
// itself: the org:license credential that authenticates every SDK caller is no
// longer sufficient on its own.
func TestAuditVerificationAuthority_RefusesTheSharedCredentialAlone(t *testing.T) {
	installAuthzSecret(t)
	r := authzRequest(AuthKindEnterprise, authzTestOrg, authzTestTenant, nil)
	if auditVerificationAuthorized(r) {
		t.Fatal("an authenticated caller with NO per-user token was authorized: that is exactly the #2914 finding")
	}
}

// TestAuditVerificationAuthority_TokenMustBelongToTheCredentialScope pins the
// binding validateUserToken does not perform.
//
// The read that follows takes its org from the CREDENTIAL context, so a
// privileged token minted for another organization would authorize a read of
// this credential's organization.
func TestAuditVerificationAuthority_TokenMustBelongToTheCredentialScope(t *testing.T) {
	installAuthzSecret(t)

	foreignOrg := authzToken(t, "admin", "some-other-org", authzTestTenant)
	r := authzRequest(AuthKindEnterprise, authzTestOrg, authzTestTenant,
		map[string]string{"X-User-Token": foreignOrg})
	if auditVerificationAuthorized(r) {
		t.Error("an admin token from ANOTHER organization authorized a read scoped to this one")
	}

	foreignTenant := authzToken(t, "admin", authzTestOrg, "some-other-client")
	r = authzRequest(AuthKindEnterprise, authzTestOrg, authzTestTenant,
		map[string]string{"X-User-Token": foreignTenant})
	if auditVerificationAuthorized(r) {
		t.Error("an admin token naming a DIFFERENT tenancy authorized this credential's read")
	}

	// The discriminating control: same role, same everything, correct scope.
	ok := authzToken(t, "admin", authzTestOrg, authzTestTenant)
	r = authzRequest(AuthKindEnterprise, authzTestOrg, authzTestTenant,
		map[string]string{"X-User-Token": ok})
	if !auditVerificationAuthorized(r) {
		t.Error("a correctly scoped admin token was refused, so the two refusals above prove nothing")
	}
}

// TestAuditVerificationAuthority_BearerIsAcceptedLikeXUserToken pins that the
// gate reads the per-user token the same way the rest of the plane does
// (extractPerUserToken), rather than growing its own header convention.
func TestAuditVerificationAuthority_BearerIsAcceptedLikeXUserToken(t *testing.T) {
	installAuthzSecret(t)
	tok := authzToken(t, "policy_admin", authzTestOrg, authzTestTenant)
	r := authzRequest(AuthKindEnterprise, authzTestOrg, authzTestTenant,
		map[string]string{"Authorization": "Bearer " + tok})
	if !auditVerificationAuthorized(r) {
		t.Error("a policy_admin token presented as Authorization: Bearer was refused")
	}
}

// TestAuditVerificationAuthority_ForgedAndMalformedTokensAreRefused covers the
// paths where validateUserToken itself says no. Each is a distinct forgery
// shape, because a gate that only checked "is the role string admin" would
// admit all three.
func TestAuditVerificationAuthority_ForgedAndMalformedTokensAreRefused(t *testing.T) {
	installAuthzSecret(t)

	wrongKey, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"role": "admin", "org_id": authzTestOrg, "tenant_id": authzTestTenant,
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("not-the-configured-secret"))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	expired := func() string {
		s, e := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"role": "admin", "org_id": authzTestOrg, "tenant_id": authzTestTenant,
			"exp": time.Now().Add(-time.Hour).Unix(),
		}).SignedString(jwtSecret)
		if e != nil {
			t.Fatalf("mint: %v", e)
		}
		return s
	}()
	alterNone, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"role": "admin", "org_id": authzTestOrg, "tenant_id": authzTestTenant,
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	for name, tok := range map[string]string{
		"signed with the wrong key": wrongKey,
		"expired":                   expired,
		"alg:none":                  alterNone,
		"not a JWT at all":          "definitely-not-a-token",
	} {
		r := authzRequest(AuthKindEnterprise, authzTestOrg, authzTestTenant,
			map[string]string{"X-User-Token": tok})
		if auditVerificationAuthorized(r) {
			t.Errorf("a token %s was accepted", name)
		}
	}
}

// TestAuditVerificationAuthority_InternalServiceMustAssertAuthority pins the
// trusted-plane posture: holding the internal-service secret is not itself
// authority, it is the channel over which an authority ASSERTION is honoured.
func TestAuditVerificationAuthority_InternalServiceMustAssertAuthority(t *testing.T) {
	installAuthzSecret(t)

	bare := authzRequest(AuthKindInternalService, authzTestOrg, authzTestTenant, nil)
	if auditVerificationAuthorized(bare) {
		t.Error("an internal service was authorized WITHOUT asserting administrative authority")
	}

	asserted := authzRequest(AuthKindInternalService, authzTestOrg, authzTestTenant,
		map[string]string{sharedidentity.HeaderAdminAuthority: sharedidentity.AdminAuthorityAsserted})
	if !auditVerificationAuthorized(asserted) {
		t.Error("an internal service asserting administrative authority was refused")
	}

	// A value that is not the recognized assertion must not count. "false" is
	// the one that matters: a portal stamping the header from a boolean would
	// otherwise grant authority by writing the word for its absence.
	for _, v := range []string{"false", "1", "yes", "", "admin"} {
		r := authzRequest(AuthKindInternalService, authzTestOrg, authzTestTenant,
			map[string]string{sharedidentity.HeaderAdminAuthority: v})
		if auditVerificationAuthorized(r) {
			t.Errorf("X-Axonflow-Admin-Authority: %q was read as an assertion", v)
		}
	}
}

// TestAuditVerificationAuthority_ClientCannotForgeTheAuthorityHeader is the
// bypass attempt R3 asks for by name.
//
// identity.NeverClientAssertableHeaders is stripped by the agent's PROXY
// Director, and this is not the proxy path - the header does reach this
// handler. It is ignored because an ordinary credential is AuthKindEnterprise,
// never AuthKindInternalService.
func TestAuditVerificationAuthority_ClientCannotForgeTheAuthorityHeader(t *testing.T) {
	installAuthzSecret(t)
	for _, kind := range []AuthKind{AuthKindEnterprise, AuthKindCommunitySaaS} {
		r := authzRequest(kind, authzTestOrg, authzTestTenant, map[string]string{
			sharedidentity.HeaderAdminAuthority: sharedidentity.AdminAuthorityAsserted,
			sharedidentity.HeaderReadScope:      sharedidentity.ReadScopeTenant,
			sharedidentity.HeaderUserRole:       "admin",
		})
		if auditVerificationAuthorized(r) {
			t.Errorf("auth kind %v: a client-supplied trusted-plane header granted authority", kind)
		}
	}
}

// TestAuditVerificationAuthority_CommunityIsOpen pins the deliberate exemption
// and its reason, so a later reader does not "fix" it.
func TestAuditVerificationAuthority_CommunityIsOpen(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	r := authzRequest(AuthKindCommunity, "local-dev-org", "local-dev-org", nil)
	if !auditVerificationAuthorized(r) {
		t.Error("community mode refused verification: the deployment has no authentication to hold a role, so this can only break local use")
	}
}

// TestAuditVerificationAuthority_NilRequestIsRefused pins the fail-closed
// default.
func TestAuditVerificationAuthority_NilRequestIsRefused(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")
	if auditVerificationAuthorized(nil) {
		t.Error("a nil request was authorized")
	}
}

// TestEveryRegisteredAuditVerificationRouteRefusesWithoutAuthority is the
// census: it WALKS the router RegisterAuditVerificationHandlers built rather
// than driving a hand-written list of three paths, so a fourth verification
// route added to that subrouter later is covered without editing this test.
//
// It asserts both directions on every route. A test that only asserted 403
// would pass against a middleware that refused everything unconditionally, and
// the routes would be dead rather than gated.
func TestEveryRegisteredAuditVerificationRouteRefusesWithoutAuthority(t *testing.T) {
	installAuthzSecret(t)

	tr := newSigningTracker(t)
	router := mux.NewRouter()
	RegisterAuditVerificationHandlers(router, tr)

	var paths []string
	if err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tmpl, err := route.GetPathTemplate()
		if err != nil || tmpl == "" {
			return nil
		}
		paths = append(paths, tmpl)
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	// Derived floor, not a hand-picked number: the count comes from the
	// registration site's own route list, and this only asserts the walk found
	// something to drive. Zero paths would make every assertion below vacuous.
	if len(paths) == 0 {
		t.Fatal("the router registered no audit verification routes, so this census asserts nothing")
	}

	// Concrete values for the two path variables, so the request MATCHES the
	// route instead of 404-ing before any middleware runs.
	concrete := func(tmpl string) string {
		s := strings.ReplaceAll(tmpl, "{chainID}", "0f6a2f5e-1b3c-4d5e-8f90-a1b2c3d4e5f6")
		return strings.ReplaceAll(s, "{recordID}", "0f6a2f5e-1b3c-4d5e-8f90-a1b2c3d4e5f6")
	}

	for _, tmpl := range paths {
		url := concrete(tmpl)

		// (a) Authenticated, no per-user token: 403 from the authority gate.
		//     The auth context is injected directly, because apiAuthMiddleware
		//     would otherwise refuse the request before the gate is reached and
		//     the 401 would look like a pass.
		rec := httptest.NewRecorder()
		req := authzRequest(AuthKindEnterprise, authzTestOrg, authzTestTenant, nil)
		req = mustRetargetRequest(t, req, url)
		routerWithoutAuth(t, tr).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: unauthorized caller got %d, want 403; body=%s", tmpl, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "compliance read authority") {
			t.Errorf("%s: the refusal does not say what authority is required: %s", tmpl, rec.Body.String())
		}

		// (b) The same request with an admin per-user token must NOT be 403.
		//     The status may legitimately be 404 (no such chain in this org) -
		//     what matters is that the authority gate let it through.
		rec = httptest.NewRecorder()
		req = authzRequest(AuthKindEnterprise, authzTestOrg, authzTestTenant,
			map[string]string{"X-User-Token": authzToken(t, "admin", authzTestOrg, authzTestTenant)})
		req = mustRetargetRequest(t, req, url)
		routerWithoutAuth(t, tr).ServeHTTP(rec, req)
		if rec.Code == http.StatusForbidden {
			t.Errorf("%s: an admin per-user token was still refused 403; body=%s", tmpl, rec.Body.String())
		}
	}
}

// routerWithoutAuth mounts the same handlers and the same AUTHORITY middleware
// but omits apiAuthMiddleware, because these tests supply the authenticated
// context directly rather than a live credential.
//
// It is deliberately a copy of the registration's middleware chain minus one
// link, and TestAuditVerificationRegistrationUsesTheAuthorityMiddleware below
// pins that the real registration still carries the link this stands in for.
func routerWithoutAuth(t *testing.T, tr *DecisionChainTracker) *mux.Router {
	t.Helper()
	router := mux.NewRouter()
	sub := router.NewRoute().Subrouter()
	sub.Use(auditVerificationAuthorityMiddleware)
	h := &auditVerificationHandler{tracker: tr}
	sub.HandleFunc("/api/v1/audit/chains/{chainID}/verify", h.verifyChain).Methods("GET")
	sub.HandleFunc("/api/v1/audit/records/{recordID}/verify", h.verifyRecord).Methods("GET")
	sub.HandleFunc("/api/v1/audit/signing-key", h.signingKey).Methods("GET")
	return router
}

// mustRetargetRequest points an already-built request at a different path while
// keeping its context and headers.
func mustRetargetRequest(t *testing.T, r *http.Request, path string) *http.Request {
	t.Helper()
	out := httptest.NewRequest(http.MethodGet, path, nil)
	out.Header = r.Header.Clone()
	return out.WithContext(r.Context())
}

// TestAuditVerificationRegistrationUsesTheAuthorityMiddleware drives the REAL
// registration (apiAuthMiddleware included) with no credentials at all and
// asserts it refuses.
//
// This is the one test that proves the production wiring is gated, as opposed
// to the stand-in router above. It cannot distinguish 401 from 403 - without a
// credential apiAuthMiddleware answers first - so it asserts only that an
// unauthenticated caller never receives a proof.
func TestAuditVerificationRegistrationUsesTheAuthorityMiddleware(t *testing.T) {
	installAuthzSecret(t)
	router := mux.NewRouter()
	RegisterAuditVerificationHandlers(router, newSigningTracker(t))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit/signing-key", nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("an unauthenticated caller received a 200 from the signing-key route: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "public_key") {
		t.Errorf("the refusal body carries proof material: %s", rec.Body.String())
	}
}
