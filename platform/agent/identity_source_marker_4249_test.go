// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #4249 row 5697957634, ADR-067 Decision 4 step 1b: the agent tells the
// orchestrator where the X-User-Email beside a request came from with
// X-Axonflow-Identity-Source. Only "validated_token" establishes segment
// membership, and only the agent sets it: on the reverse proxy's validated
// X-User-Token branch, and on forwardToOrchestrator for a user resolved from
// verified token claims. A header identity never carries it, and a client-sent
// value never survives the proxy.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// Every cell of the proxy: trust gate on/off × no token / a validated token with
// an email / a validated token without one × the client sending no marker or a
// forged validated_token. The marker is forwarded exactly when a validated token
// supplied the email, whatever the client sent.
func TestProxyAuthMiddleware_IdentitySourceMarkerOnlyForAValidatedTokenEmail(t *testing.T) {
	type tokenCase struct {
		name      string
		token     string
		email     string
		wantEmail func(gateOn bool) string
		wantMark  bool
	}
	tokens := []tokenCase{
		{"no token", "", "", func(gateOn bool) string {
			if gateOn {
				return "self-asserted@corp.example"
			}
			return ""
		}, false},
		{"validated token with an email", "tok", "alice@corp.example", func(bool) string { return "alice@corp.example" }, true},
		// A validated token that resolves to no address overwrites the header
		// identity with the empty one, under either gate setting.
		{"validated token without an email", "tok", "", func(bool) string { return "" }, false},
	}
	for _, gateOn := range []bool{false, true} {
		for _, tc := range tokens {
			for _, forged := range []bool{false, true} {
				name := tc.name
				if gateOn {
					name = "gate on/" + name
				} else {
					name = "gate off/" + name
				}
				if forged {
					name += "/client sends the marker"
				}
				t.Run(name, func(t *testing.T) {
					withEnterpriseWhitelist(t)
					withFleetValidator(t, stubFleetValidator{
						name: sharedidentity.ValidatorNameHS256,
						id: &sharedidentity.ValidatedIdentity{
							Email: tc.email, Role: "developer", Validated: true,
							Source: sharedidentity.ValidatorNameHS256,
						},
					})
					if gateOn {
						t.Setenv(sharedidentity.EnvVar, "true")
					} else {
						t.Setenv(sharedidentity.EnvVar, "false")
					}
					req := proxiedOverrideRequest(t, "self-asserted@corp.example", tc.token)
					if forged {
						req.Header.Set(sharedidentity.HeaderIdentitySource, sharedidentity.IdentitySourceValidatedToken)
					}

					seen, code := forwardedHeaders(t, req)
					if code != http.StatusOK {
						t.Fatalf("middleware returned %d, want 200", code)
					}
					// PREMISE: the identity the cell describes is the one forwarded,
					// so a cell cannot pass on a request the token branch never saw.
					if got, want := seen.Get(identityHeaderUserEmail), tc.wantEmail(gateOn); got != want {
						t.Fatalf("PREMISE: %s = %q, want %q", identityHeaderUserEmail, got, want)
					}
					got := seen.Get(sharedidentity.HeaderIdentitySource)
					if tc.wantMark && got != sharedidentity.IdentitySourceValidatedToken {
						t.Errorf("%s = %q, want %q: the email came from a validated token",
							sharedidentity.HeaderIdentitySource, got, sharedidentity.IdentitySourceValidatedToken)
					}
					if !tc.wantMark && got != "" {
						t.Errorf("%s = %q forwarded for an identity no validated token supplied: "+
							"a header identity would select only its own segment's route rows",
							sharedidentity.HeaderIdentitySource, got)
					}
				})
			}
		}
	}
}

// THE FORWARD OVER THE USERS ResolveUser ACTUALLY RETURNS (R3 round 1 finding
// 8): every auth kind, and the enterprise kind in the modes whose
// validateUserToken synthesises its user, forwarded as clientRequestHandler
// forwards it. Only the enterprise kind with a verified token, outside the
// community modes, carries the marker; a future branch that set TokenClaims on a
// synthesised user would red here.
func TestForwardToOrchestrator_IdentitySourceMarkerOverResolvedUsers(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		kind     AuthKind
		token    func(t *testing.T) string
		wantMark bool
	}{
		{"community kind", "community", AuthKindCommunity, func(*testing.T) string { return "" }, false},
		{"community-saas kind", "community-saas", AuthKindCommunitySaaS, func(*testing.T) string { return "" }, false},
		{"internal-service kind", "", AuthKindInternalService, func(*testing.T) string { return "" }, false},
		{"enterprise kind, community mode, a token", "community", AuthKindEnterprise, func(t *testing.T) string { return mrsTokenFor(t, "dev@corp.example") }, false},
		{"enterprise kind, community-saas mode, a token", "community-saas", AuthKindEnterprise, func(t *testing.T) string { return mrsTokenFor(t, "dev@corp.example") }, false},
		{"enterprise kind, a verified token", "", AuthKindEnterprise, func(t *testing.T) string { return mrsTokenFor(t, "dev@corp.example") }, true},
	}
	origSecret := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = origSecret })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", tc.mode)
			auth := &AuthResult{Kind: tc.kind, OrgID: mrsOrg, TenantID: utrTestTenant, ClientID: utrTestClientID}
			user, authErr := ResolveUser(auth, tc.token(t))
			if authErr != nil {
				t.Fatalf("ResolveUser: %s", authErr.Message)
			}
			if user == nil || user.Email == "" {
				t.Fatalf("PREMISE: the resolved user carries no email (%+v), so the forward could not mark one", user)
			}

			var got http.Header
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Clone()
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			}))
			defer srv.Close()
			prev := orchestratorURL
			orchestratorURL = srv.URL
			defer func() { orchestratorURL = prev }()

			client := &Client{ClientID: utrTestClientID, OrgID: mrsOrg, TenantID: utrTestTenant}
			if _, err := forwardToOrchestrator(ClientRequest{RequestType: "chat"}, user, client, false); err != nil {
				t.Fatalf("forward failed: %v", err)
			}
			if got.Get("X-User-Email") != user.Email {
				t.Fatalf("PREMISE: forwarded X-User-Email = %q, want %q", got.Get("X-User-Email"), user.Email)
			}
			mark := got.Get(sharedidentity.HeaderIdentitySource)
			if tc.wantMark && mark != sharedidentity.IdentitySourceValidatedToken {
				t.Errorf("%s = %q for %s, want %q", sharedidentity.HeaderIdentitySource, mark, user.Email, sharedidentity.IdentitySourceValidatedToken)
			}
			if !tc.wantMark && mark != "" {
				t.Errorf("%s = %q for the synthesised %s, want none", sharedidentity.HeaderIdentitySource, mark, user.Email)
			}
		})
	}
}

// forwardToOrchestrator builds its request fresh, so no inbound value can reach
// it; it sets the marker only for a user carrying verified token claims. A
// synthesised user (community, community-SaaS, internal service) has an email
// and no claims, and a nil user has neither.
func TestForwardToOrchestrator_IdentitySourceMarkerOnlyForVerifiedClaims(t *testing.T) {
	cases := []struct {
		name     string
		user     *User
		wantMark bool
	}{
		{"verified claims", &User{Email: "dev@corp.example", TenantID: "tenant-a", TokenClaims: map[string]any{"email": "dev@corp.example"}}, true},
		{"verified claims without an email", &User{TenantID: "tenant-a", TokenClaims: map[string]any{}}, false},
		{"synthesised community user", &User{Email: "local-dev@axonflow.local", TenantID: "tenant-a"}, false},
		{"synthesised community-SaaS user", &User{Email: "evaluator@try.getaxonflow.com", TenantID: "tenant-a"}, false},
		{"no user", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got http.Header
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Clone()
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			}))
			defer srv.Close()
			prev := orchestratorURL
			orchestratorURL = srv.URL
			defer func() { orchestratorURL = prev }()

			client := &Client{ClientID: "client-1", OrgID: "org-a", TenantID: "tenant-a"}
			if _, err := forwardToOrchestrator(ClientRequest{RequestType: "chat"}, tc.user, client, false); err != nil {
				t.Fatalf("forward failed: %v", err)
			}
			mark := got.Get(sharedidentity.HeaderIdentitySource)
			if tc.wantMark != (mark == sharedidentity.IdentitySourceValidatedToken) || (!tc.wantMark && mark != "") {
				t.Errorf("%s = %q, want marked=%v", sharedidentity.HeaderIdentitySource, mark, tc.wantMark)
			}
		})
	}
}
