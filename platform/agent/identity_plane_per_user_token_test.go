// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	sharedidentity "axonflow/platform/shared/identity"
)

// ON A VERIFYING DEPLOYMENT, A PER-USER TOKEN THAT FAILS THE PER-USER CLAIM RULE
// IS REFUSED BEFORE ANY POLICY (#4311).
//
// A token stamped with the per-user mint's issuer was admitted by the agent on
// a verified signature alone, so suite 3297's P7 (W3-G) and P8 (W3-G) token,
// the mint's claim set without an email, was decided as a verified user on
// /api/request instead of refused. These tests hold the rule on the admission
// every token-bearing route shares, and every case names its deployment mode.

const perUserTestOrg = "org-4311"

// perUserTestToken mints the per-user mint's claim set for org, signed with
// key, with mutate applied to the claims (nil for the full set).
func perUserTestToken(t *testing.T, key []byte, org string, mutate func(jwt.MapClaims)) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       sharedidentity.UserTokenIssuer,
		"sub":       "alice@corp.example",
		"email":     "alice@corp.example",
		"role":      "user",
		"org_id":    org,
		"tenant_id": org,
		"jti":       "jti-4311-" + org,
		"iat":       now.Add(-time.Minute).Unix(),
		"nbf":       now.Add(-time.Minute).Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// onAVerifyingDeployment runs the test as an Enterprise deployment signing with
// the test secret.
func onAVerifyingDeployment(t *testing.T) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	saved := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = saved })
}

// enterpriseCredentialOf is an authenticated Enterprise credential of org: the
// organization the claim rule compares a token's org_id with.
func enterpriseCredentialOf(org string) *AuthResult {
	return &AuthResult{Kind: AuthKindEnterprise, OrgID: org, TenantID: org}
}

// countForwards points the agent at an orchestrator that counts what reaches
// it, so a test can show a refusal happened before anything was forwarded.
func countForwards(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	orch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":"forwarded"}`))
	}))
	t.Cleanup(orch.Close)
	prev := orchestratorURL
	orchestratorURL = orch.URL
	t.Cleanup(func() { orchestratorURL = prev })
	return &n
}

func TestAPerUserTokenFailingTheClaimRuleIsRefusedOnAVerifyingDeployment(t *testing.T) {
	onAVerifyingDeployment(t)
	for name, c := range map[string]struct {
		mutate func(jwt.MapClaims)
		reason string
	}{
		"enterprise: no email claim (the shape of suite 3297's P7/P8 token)": {func(c jwt.MapClaims) { delete(c, "email") }, "missing email claim"},
		"enterprise: no jti claim":                                          {func(c jwt.MapClaims) { delete(c, "jti") }, "missing jti claim (per-user tokens must be revocable)"},
		"enterprise: no org_id claim":                                       {func(c jwt.MapClaims) { delete(c, "org_id") }, "missing org_id claim"},
		"enterprise: another organization's org_id":                         {func(c jwt.MapClaims) { c["org_id"] = "org-other" }, `token org "org-other" does not match authenticated org`},
		"enterprise: no exp claim":                                          {func(c jwt.MapClaims) { delete(c, "exp") }, "missing exp claim (per-user tokens must expire)"},
		"enterprise: an exp of 0, which the token parse reads as no expiry": {func(c jwt.MapClaims) { c["exp"] = 0 }, "missing exp claim (per-user tokens must expire)"},
	} {
		t.Run(name, func(t *testing.T) {
			token := perUserTestToken(t, jwtSecret, perUserTestOrg, c.mutate)
			user, aerr := ResolveUser(enterpriseCredentialOf(perUserTestOrg), token)
			if aerr == nil {
				t.Fatalf("admitted as %+v; a per-user token failing the claim rule must be refused", user)
			}
			if aerr.HTTPStatus != http.StatusUnauthorized || aerr.Code != "invalid_user_token" {
				t.Fatalf("got %d %s; want 401 invalid_user_token", aerr.HTTPStatus, aerr.Code)
			}
			if want := "Invalid user token: per-user token invalid: " + c.reason; aerr.Message != want {
				t.Fatalf("message %q; want the rule's reason %q", aerr.Message, want)
			}
			if got := callerUserIdentity(AuthKindEnterprise, aerr, token); got != userUnverified {
				t.Fatalf("the seam classifies the refused token as %v; want userUnverified, never the credential", got)
			}
		})
	}
}

func TestAValidPerUserTokenIsAdmittedAsTheUserOnAVerifyingDeployment(t *testing.T) {
	onAVerifyingDeployment(t)
	token := perUserTestToken(t, jwtSecret, perUserTestOrg, nil)
	user, aerr := ResolveUser(enterpriseCredentialOf(perUserTestOrg), token)
	if aerr != nil {
		t.Fatalf("enterprise: the mint's full claim set was refused %s: %s", aerr.Code, aerr.Message)
	}
	if user == nil || user.Email != "alice@corp.example" || user.OrgID != perUserTestOrg {
		t.Fatalf("enterprise: admitted %+v; want alice of %s", user, perUserTestOrg)
	}
	if got := callerUserIdentity(AuthKindEnterprise, nil, token); got != userVerified {
		t.Fatalf("enterprise: the seam classifies the admitted token as %v; want userVerified", got)
	}
}

// The rule keys on the mint's issuer alone. A token without it is admitted
// exactly as validateUserToken admits it, as before #4311.
func TestATokenWithoutTheMintIssuerKeepsItsHandlingOnAVerifyingDeployment(t *testing.T) {
	onAVerifyingDeployment(t)
	exp := time.Now().Add(time.Hour).Unix()
	for name, claims := range map[string]jwt.MapClaims{
		"enterprise: the tenant token kind (no issuer, no email)": {"user_id": 1, "tenant_id": perUserTestOrg, "role": "developer", "permissions": []string{"query"}, "exp": exp},
		"enterprise: another issuer, no email":                    {"iss": "https://idp.example", "sub": "someone", "tenant_id": perUserTestOrg, "exp": exp},
	} {
		t.Run(name, func(t *testing.T) {
			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
			if err != nil {
				t.Fatal(err)
			}
			want, wantErr := validateUserToken(token, perUserTestOrg)
			if wantErr != nil {
				t.Fatalf("validateUserToken refused the token: %v", wantErr)
			}
			user, aerr := ResolveUser(enterpriseCredentialOf(perUserTestOrg), token)
			if aerr != nil {
				t.Fatalf("refused %s: %s; a token without the mint's issuer keeps its handling", aerr.Code, aerr.Message)
			}
			if user.Email != want.Email || user.TenantID != want.TenantID || user.OrgID != want.OrgID || user.Role != want.Role {
				t.Fatalf("admitted %+v; want what validateUserToken admits: %+v", user, want)
			}
		})
	}
}

func TestAWrongSignatureIsRefusedOnAVerifyingDeployment(t *testing.T) {
	onAVerifyingDeployment(t)
	token := perUserTestToken(t, []byte("a-different-secret-0123456789abcdef"), perUserTestOrg, nil)
	_, aerr := ResolveUser(enterpriseCredentialOf(perUserTestOrg), token)
	if aerr == nil || aerr.HTTPStatus != http.StatusUnauthorized || aerr.Code != "invalid_user_token" {
		t.Fatalf("enterprise: got %+v; want a 401 invalid_user_token for a token signed with another key", aerr)
	}
	if !strings.Contains(aerr.Message, "signature") {
		t.Fatalf("enterprise: message %q does not name the signature", aerr.Message)
	}
	if got := callerUserIdentity(AuthKindEnterprise, aerr, token); got != userUnverified {
		t.Fatalf("enterprise: the seam classifies the forged token as %v; want userUnverified", got)
	}
}

// Through the handlers themselves: the refusal comes before any engine and
// before anything is forwarded, and the no-token case is decided per route.
func TestTheRequestAndDecidePlanesRefuseAPerUserTokenFailingTheClaimRuleBeforeAnyEngine(t *testing.T) {
	enfProxySetup(t) // enterprise, the test secret, the organizations' licences
	forwards := countForwards(t)
	noEmail := func(org string) string {
		return perUserTestToken(t, jwtSecret, org, func(c jwt.MapClaims) { delete(c, "email") })
	}

	t.Run("enterprise /api/request: the email-less per-user token is refused 401 naming the claim, and nothing is forwarded", func(t *testing.T) {
		before := forwards.Load()
		r := enfProxy(t, enfOrgImplicit, noEmail(enfOrgImplicit), "SELECT id FROM products")
		if r.code != http.StatusUnauthorized {
			t.Fatalf("got HTTP %d; want 401. body=%s", r.code, r.raw)
		}
		if _, has := r.body["engine"]; has {
			t.Fatalf("the refusal carries an engine member; no engine may decide a refused token. body=%s", r.raw)
		}
		if !strings.Contains(string(r.raw), "missing email claim") {
			t.Fatalf("the refusal does not name the failed claim. body=%s", r.raw)
		}
		if got := forwards.Load(); got != before {
			t.Fatalf("the orchestrator received %d request(s) for a refused token", got-before)
		}
		// CONTROL: the same request with the mint's full claim set is forwarded,
		// so the counter above can see a forward when one happens.
		ok := enfProxy(t, enfOrgImplicit, enfMintUserToken(t, enfOrgImplicit, enfUser), "SELECT id FROM products")
		if ok.code != http.StatusOK || forwards.Load() == before {
			t.Fatalf("CONTROL: the full claim set got HTTP %d with %d forward(s); want 200 and a forward. body=%s", ok.code, forwards.Load()-before, ok.raw)
		}
		if ok.str(t, "subject_type") != string(sharedidentity.SubjectUser) {
			t.Fatalf("CONTROL: subject_type %q; want User", ok.str(t, "subject_type"))
		}
	})

	t.Run("enterprise /api/request: no token is refused 401 before anything is forwarded", func(t *testing.T) {
		before := forwards.Load()
		r := enfProxy(t, enfOrgImplicit, "", "SELECT id FROM products")
		if r.code != http.StatusUnauthorized || forwards.Load() != before {
			t.Fatalf("got HTTP %d with %d forward(s); /api/request requires a token on a verifying deployment. body=%s", r.code, forwards.Load()-before, r.raw)
		}
	})

	t.Run("enterprise /api/v1/decide: the email-less per-user token is refused 401 naming the claim, and no engine decides it", func(t *testing.T) {
		r := enfDecideWithToken(t, enfOrgImplicit, noEmail(enfOrgImplicit), DecisionStageLLM, "What is the weather today?")
		if r.code != http.StatusUnauthorized {
			t.Fatalf("got HTTP %d; want 401. body=%s", r.code, r.raw)
		}
		if _, has := r.body["engine"]; has {
			t.Fatalf("the refusal carries an engine member. body=%s", r.raw)
		}
		if !strings.Contains(string(r.raw), "missing email claim") {
			t.Fatalf("the refusal does not name the failed claim. body=%s", r.raw)
		}
	})

	t.Run("enterprise /api/v1/decide: the mint's full claim set is decided for the User", func(t *testing.T) {
		r := enfDecide(t, enfOrgImplicit, true, DecisionStageLLM, "What is the weather today?")
		if r.code != http.StatusOK || r.str(t, "subject_type") != string(sharedidentity.SubjectUser) {
			t.Fatalf("got HTTP %d subject_type %q; want 200 for the User. body=%s", r.code, r.str(t, "subject_type"), r.raw)
		}
	})

	t.Run("enterprise /api/v1/decide: no token is decided for the client credential, recorded as a Client", func(t *testing.T) {
		r := enfDecide(t, enfOrgImplicit, false, DecisionStageLLM, "What is the weather today?")
		if r.code != http.StatusOK || r.str(t, "subject_type") != string(sharedidentity.SubjectClient) {
			t.Fatalf("got HTTP %d subject_type %q; want 200 for a Client. body=%s", r.code, r.str(t, "subject_type"), r.raw)
		}
	})
}

// The org match compares the token's org_id with the organization the
// CREDENTIAL authenticated as, never with the credential's tenant: the two
// differ here, so comparing the wrong one refuses the right token and admits
// the wrong one.
func TestTheClaimRuleComparesTheCredentialsOrganizationNeverTheTenant(t *testing.T) {
	onAVerifyingDeployment(t)
	const tenant = "tenant-4311"
	credential := &AuthResult{Kind: AuthKindEnterprise, OrgID: perUserTestOrg, TenantID: tenant}
	withOrg := func(org string) string {
		return perUserTestToken(t, jwtSecret, org, func(c jwt.MapClaims) { c["tenant_id"] = tenant })
	}

	t.Run("enterprise: a token whose org_id is the credential's tenant is refused with the rule's reason", func(t *testing.T) {
		token := withOrg(tenant)
		user, aerr := ResolveUser(credential, token)
		if aerr == nil {
			t.Fatalf("admitted as %+v; the token's org_id names the tenant, not the credential's organization", user)
		}
		want := `Invalid user token: per-user token invalid: token org "tenant-4311" does not match authenticated org`
		if aerr.HTTPStatus != http.StatusUnauthorized || aerr.Code != "invalid_user_token" || aerr.Message != want {
			t.Fatalf("got %d %s %q; want 401 invalid_user_token %q", aerr.HTTPStatus, aerr.Code, aerr.Message, want)
		}
		if got := callerUserIdentity(AuthKindEnterprise, aerr, token); got != userUnverified {
			t.Fatalf("the seam classifies the refused token as %v; want userUnverified", got)
		}
	})

	t.Run("enterprise: a token whose org_id is the credential's organization is admitted", func(t *testing.T) {
		user, aerr := ResolveUser(credential, withOrg(perUserTestOrg))
		if aerr != nil {
			t.Fatalf("refused %s: %s; the token names the credential's organization", aerr.Code, aerr.Message)
		}
		if user == nil || user.OrgID != perUserTestOrg || user.Email != "alice@corp.example" {
			t.Fatalf("admitted %+v; want alice of %s", user, perUserTestOrg)
		}
	})
}

// An Enterprise credential with no authenticated organization (an org-less
// deployment) refuses a per-user token, as the fleet validator does: there is
// no organization the token's org_id could match. The tenant token kind on the
// same credential keeps its handling.
func TestAnOrgLessEnterpriseCredentialRefusesAPerUserToken(t *testing.T) {
	onAVerifyingDeployment(t)
	orgLess := &AuthResult{Kind: AuthKindEnterprise, OrgID: "", TenantID: perUserTestOrg}

	user, aerr := ResolveUser(orgLess, perUserTestToken(t, jwtSecret, perUserTestOrg, nil))
	if aerr == nil {
		t.Fatalf("enterprise, org-less: admitted %+v; a per-user token needs an authenticated organization to match", user)
	}
	if want := "Invalid user token: per-user token invalid: no authenticated org"; aerr.HTTPStatus != http.StatusUnauthorized || aerr.Message != want {
		t.Fatalf("enterprise, org-less: got %d %q; want 401 %q", aerr.HTTPStatus, aerr.Message, want)
	}

	// CONTROL: the tenant token kind is admitted on the same org-less credential.
	tenantKind, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": 1, "tenant_id": perUserTestOrg, "role": "developer", "permissions": []string{"query"},
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(jwtSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, aerr := ResolveUser(orgLess, tenantKind); aerr != nil {
		t.Fatalf("CONTROL, enterprise, org-less: the tenant token kind was refused %s: %s", aerr.Code, aerr.Message)
	}
}

// A deployment that verifies no user token does not start refusing one.
func TestTheClaimRuleDoesNotReachCommunityDeployments(t *testing.T) {
	for _, mode := range []string{"community", "community-saas"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)
			saved := jwtSecret
			jwtSecret = []byte(testJWTSecret)
			t.Cleanup(func() { jwtSecret = saved })
			token := perUserTestToken(t, jwtSecret, perUserTestOrg, func(c jwt.MapClaims) { delete(c, "email") })
			user, err := admitUserToken(perUserTestOrg, token, perUserTestOrg)
			if err != nil || user == nil {
				t.Fatalf("%s: refused (%v); a deployment that verifies no user token must not refuse one", mode, err)
			}
			if got := callerUserIdentity(AuthKindEnterprise, nil, token); got != userAbsent {
				t.Fatalf("%s: the seam classifies the token as %v; want userAbsent, the credential as the principal", mode, got)
			}
		})
	}
}
