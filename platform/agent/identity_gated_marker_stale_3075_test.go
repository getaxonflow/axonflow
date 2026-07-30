// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3075 — the X-Axonflow-Identity-Gated marker could survive as a stale TRUE.
//
// proxyAuthMiddleware does two things in order:
//
//  1. gateProxyIdentityHeaders strips X-User-Email under the default-off trust
//     gate and stamps the marker, whose invariant is "we removed the identity
//     this caller sent, and that is why you have none";
//  2. the per-user-token branch resolves a validated X-User-Token and RE-SETS
//     X-User-Email from the validated identity.
//
// After (2) the forwarded request carried a per-user identity AND a marker
// saying its identity was dropped. Both cannot be true. The marker is only
// worth reading because it means exactly one thing.
//
// These tests drive the real middleware, not gateProxyIdentityHeaders in
// isolation: the defect is in the ORDER of two correct steps, so a test of
// either step alone cannot see it.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// forwardedHeaders runs a request through proxyAuthMiddleware and returns the
// headers the orchestrator would receive.
func forwardedHeaders(t *testing.T, req *http.Request) (http.Header, int) {
	t.Helper()
	var seen http.Header
	handler := proxyAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	rr := httptest.NewRecorder()
	handler(rr, req)
	return seen, rr.Code
}

// proxiedOverrideRequest is the DELETE a plugin issues against the override
// lifecycle, authenticated as an enterprise tenant, carrying whatever per-user
// credentials the caller has.
func proxiedOverrideRequest(t *testing.T, userEmail, userToken string) *http.Request {
	t.Helper()
	req := httptest.NewRequest("DELETE", "/api/v1/overrides/ov-1", nil)
	setBasicAuth(req, "healthcare-demo", knownClients["healthcare-demo"].LicenseKey)
	if userEmail != "" {
		req.Header.Set(identityHeaderUserEmail, userEmail)
	}
	if userToken != "" {
		req.Header.Set("X-User-Token", userToken)
	}
	return req
}

// The headline. Trust gate OFF (the default), caller presents BOTH a header
// identity — which the gate correctly drops — and a validated per-user token,
// which restores one. The marker must not survive: the request now carries an
// identity, so nothing downstream should be told that identity was removed.
func TestProxyAuthMiddleware_ValidUserTokenClearsTheGatedMarker(t *testing.T) {
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		id: &sharedidentity.ValidatedIdentity{
			Email:     "alice@corp.example",
			Role:      "developer",
			Validated: true,
			Source:    sharedidentity.ValidatorNameHS256,
		},
	})
	// Explicitly off, which is also the default since 9.9.0.
	t.Setenv(sharedidentity.EnvVar, "false")

	seen, code := forwardedHeaders(t,
		proxiedOverrideRequest(t, "self-asserted@corp.example", "tok"))

	if code != http.StatusOK {
		t.Fatalf("middleware returned %d, want 200", code)
	}
	// The identity WAS restored — otherwise this test would pass vacuously on a
	// build where the token branch never ran.
	if got := seen.Get(identityHeaderUserEmail); got != "alice@corp.example" {
		t.Fatalf("validated identity was not forwarded: %s = %q, want alice@corp.example",
			identityHeaderUserEmail, got)
	}
	// …so the marker's claim is false and it must be gone.
	if got := seen.Get(sharedidentity.HeaderIdentityGated); got != "" {
		t.Errorf("%s = %q — the request carries a per-user identity, so the marker asserting "+
			"that its identity was dropped is stale", sharedidentity.HeaderIdentityGated, got)
	}
}

// The control that keeps the fix honest in the other direction: with no token
// to restore an identity, the marker is still stamped and still forwarded. A
// change that simply deleted the marker everywhere would pass the test above
// and fail this one.
func TestProxyAuthMiddleware_NoUserToken_MarkerStillStamped(t *testing.T) {
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		id: &sharedidentity.ValidatedIdentity{
			Email: "alice@corp.example", Validated: true,
			Source: sharedidentity.ValidatorNameHS256,
		},
	})
	t.Setenv(sharedidentity.EnvVar, "false")

	seen, code := forwardedHeaders(t,
		proxiedOverrideRequest(t, "self-asserted@corp.example", ""))

	if code != http.StatusOK {
		t.Fatalf("middleware returned %d, want 200", code)
	}
	if got := seen.Get(identityHeaderUserEmail); got != "" {
		t.Fatalf("the default-off gate must strip the self-asserted identity, got %q", got)
	}
	if !sharedidentity.IdentityWasGated(seen.Get(sharedidentity.HeaderIdentityGated)) {
		t.Errorf("%s = %q, want the marker: an identity the caller sent WAS dropped",
			sharedidentity.HeaderIdentityGated, seen.Get(sharedidentity.HeaderIdentityGated))
	}
}

// A validated identity that carries no address restores nothing, so the marker
// is still the truthful explanation for the missing identity and must stay.
// This is the edge the one-line fix is guarded on; without the guard, the
// clear would fire on a token that left the request just as identity-less as
// the gate did.
func TestProxyAuthMiddleware_TokenWithoutEmail_MarkerRetained(t *testing.T) {
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		id: &sharedidentity.ValidatedIdentity{
			Email: "", Role: "developer", Validated: true,
			Source: sharedidentity.ValidatorNameHS256,
		},
	})
	t.Setenv(sharedidentity.EnvVar, "false")

	seen, code := forwardedHeaders(t,
		proxiedOverrideRequest(t, "self-asserted@corp.example", "tok"))

	if code != http.StatusOK {
		t.Fatalf("middleware returned %d, want 200", code)
	}
	if got := seen.Get(identityHeaderUserEmail); got != "" {
		t.Fatalf("no address was validated, so none may be forwarded; got %q", got)
	}
	if !sharedidentity.IdentityWasGated(seen.Get(sharedidentity.HeaderIdentityGated)) {
		t.Error("nothing restored the identity, so the marker must survive to explain its absence")
	}
}

// The invariant, stated as an invariant rather than as a sequence of steps:
// whenever the forwarded request carries a per-user identity, it must NOT carry
// the marker — under either gate setting, and whatever the client sent. The two
// gate settings reach that state by different routes (gate on ⇒ the header is
// forwarded and no marker is ever stamped; gate off ⇒ the header is dropped,
// the marker IS stamped, and the validated token then restores the identity and
// clears it), which is exactly why asserting the end state catches more than
// asserting either route. It also pins that a client-supplied marker never
// survives on its own merits: gateProxyIdentityHeaders Del()s it on ingress.
func TestProxyAuthMiddleware_IdentityPresentImpliesNoMarker(t *testing.T) {
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		id: &sharedidentity.ValidatedIdentity{
			Email: "alice@corp.example", Validated: true,
			Source: sharedidentity.ValidatorNameHS256,
		},
	})

	for _, gate := range []string{"false", "true"} {
		t.Run("gate="+gate, func(t *testing.T) {
			t.Setenv(sharedidentity.EnvVar, gate)

			req := proxiedOverrideRequest(t, "alice@corp.example", "tok")
			req.Header.Set(sharedidentity.HeaderIdentityGated, sharedidentity.IdentityGatedTrue)

			seen, code := forwardedHeaders(t, req)
			if code != http.StatusOK {
				t.Fatalf("middleware returned %d, want 200", code)
			}
			if got := seen.Get(identityHeaderUserEmail); got != "alice@corp.example" {
				t.Fatalf("no identity was forwarded (%q) — the invariant below would hold vacuously", got)
			}
			if got := seen.Get(sharedidentity.HeaderIdentityGated); got != "" {
				t.Errorf("%s = %q on a request that DOES carry a per-user identity — "+
					"the marker asserts the identity was removed, so the two cannot coexist",
					sharedidentity.HeaderIdentityGated, got)
			}
		})
	}
}
