// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3074 — the X-Axonflow-Identity-Gated marker had half the pattern.
//
// The agent Del()s any inbound value before setting its own, so a caller
// through the gateway cannot assert it. But the sibling agent-asserted headers
// X-Axonflow-User-Role and X-Axonflow-Read-Scope are stripped on ingress AND
// honored only behind a validated X-Axonflow-Proxy-Auth token
// (resolveCallerReadScope). This one had the strip and not the binding.
//
// The tests below pin the binding. They also pin what the binding must NOT
// change: the marker still selects prose only, and the two 401 bodies still
// carry the same status and the same authorization outcome. The point of
// binding a header that can only change wording is to keep it that way.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// markedRequest is the shape of the request the agent forwards when the
// default-off trust gate dropped an identity the caller sent.
func markedRequest() *http.Request {
	r := httptest.NewRequest("POST", "/api/v1/overrides", nil)
	r.Header.Set("X-Tenant-ID", "tenant-x")
	r.Header.Set(sharedidentity.HeaderIdentityGated, sharedidentity.IdentityGatedTrue)
	return r
}

// diagnosed reports whether the message took the branch that asserts the
// caller's identity was dropped ("your client DID send it").
func diagnosed(msg string) bool { return strings.Contains(msg, "DID send") }

func TestIdentityGatedMarker_HonoredOnlyOverTheProxyAuthChannel(t *testing.T) {
	for _, tc := range []struct {
		name string
		// mode is DEPLOYMENT_MODE; "" means unset (which isCommunityMode
		// treats as community).
		mode string
		// secret installs a proxy-token validator; "" means none configured.
		secret string
		// token is the X-Axonflow-Proxy-Auth value the caller presents.
		token func(t *testing.T) string
		want  bool
		why   string
	}{
		{
			name:   "enterprise + validator + valid agent token → honored",
			mode:   "enterprise",
			secret: proxyGuardTestSecret,
			token:  validProxyToken,
			want:   true,
			why:    "the agent stamped it and proved it is the agent",
		},
		{
			// The defect. A caller reaching an orchestrator port directly set
			// the marker and selected the assertive sentence.
			name:   "enterprise + validator + NO token → ignored",
			mode:   "enterprise",
			secret: proxyGuardTestSecret,
			token:  func(*testing.T) string { return "" },
			want:   false,
			why:    "nothing vouches for a marker that did not come through the agent",
		},
		{
			name:   "enterprise + validator + forged token → ignored",
			mode:   "enterprise",
			secret: proxyGuardTestSecret,
			token:  func(*testing.T) string { return "forged-token" },
			want:   false,
			why:    "an unverifiable token is no better than none",
		},
		{
			// Misconfigured deployment: no secret, so no token CAN be checked.
			// Fall back to the generic message, which is the safe default —
			// mirroring verifyAgentProxyAuth's fail-closed posture.
			name:   "enterprise + NO validator → ignored (misconfigured)",
			mode:   "enterprise",
			secret: "",
			token:  func(*testing.T) string { return "" },
			want:   false,
			why:    "no secret configured ⇒ nothing can be verified ⇒ do not trust",
		},
		{
			// The regression this binding must not cause. A default community
			// stack has no internal-service secret, so no token exists to
			// present — and it is exactly the deployment #3062 was reported on.
			// Refusing the marker there would silently delete the diagnostic
			// for the users who needed it.
			name:   "community + NO validator → honored",
			mode:   "community",
			secret: "",
			token:  func(*testing.T) string { return "" },
			want:   true,
			why:    "community has no secret to mint a token with; same exemption verifyAgentProxyAuth grants",
		},
		{
			// #3096 (PR #3117) removed the unset-is-community default:
			// isCommunityMode() now matches the literal "community" only, so an
			// unset DEPLOYMENT_MODE no longer inherits the carve-out above.
			// This row asserted want:true on that former default and was
			// correct when written. It is inverted rather than deleted,
			// because unset is exactly where a regression would land.
			name:   "unset DEPLOYMENT_MODE + NO validator → ignored (fail closed)",
			mode:   "",
			secret: "",
			token:  func(*testing.T) string { return "" },
			want:   false,
			why:    "unset is no longer community (#3096); nothing verifiable ⇒ do not trust",
		},
		{
			// A community deployment that DID configure the secret is held to
			// the same bar as any other: validator set ⇒ token required.
			name:   "community + validator + NO token → ignored",
			mode:   "community",
			secret: proxyGuardTestSecret,
			token:  func(*testing.T) string { return "" },
			want:   false,
			why:    "once a validator exists the token is checkable, so check it",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", tc.mode)
			installProxyTokenValidator(t, tc.secret)

			r := markedRequest()
			if tok := tc.token(t); tok != "" {
				r.Header.Set("X-Axonflow-Proxy-Auth", tok)
			}

			msg := identityRequiredMessage(r, "policy overrides")
			if got := diagnosed(msg); got != tc.want {
				t.Errorf("diagnosed=%v, want %v (%s); body: %s", got, tc.want, tc.why, msg)
			}
			// Whichever branch was taken, the caller still gets something they
			// can act on. A binding that produced a dead-end message would be a
			// regression on #3062 dressed up as a fix.
			assertActionableIdentityError(t, msg)
		})
	}
}

// The binding must not turn the marker into an authorization input. Same
// property #3062 pinned, re-asserted on the trusted channel: with a VALID agent
// token, present-vs-absent marker changes the sentence and nothing else.
func TestIdentityGatedMarker_BindingDidNotMakeItLoadBearing(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	statuses := map[bool]int{}
	bodies := map[bool]string{}
	for _, marker := range []bool{false, true} {
		req := httptest.NewRequest("POST", "/api/v1/overrides",
			strings.NewReader(createOverrideBody()))
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		if marker {
			req.Header.Set(sharedidentity.HeaderIdentityGated, sharedidentity.IdentityGatedTrue)
		}
		rr := httptest.NewRecorder()
		createOverrideHandler(rr, req)
		statuses[marker] = rr.Code
		bodies[marker] = rr.Body.String()
	}
	if statuses[false] != statuses[true] {
		t.Fatalf("marker changed the outcome: without=%d with=%d — it must only select the message",
			statuses[false], statuses[true])
	}
	if statuses[true] != http.StatusUnauthorized {
		t.Fatalf("expected the identity 401 on both, got %d; body: %s", statuses[true], bodies[true])
	}
	if bodies[false] == bodies[true] {
		t.Error("the marker selected nothing at all — the diagnostic is gone, not bound")
	}
}

// A forged marker on the direct path must now select the SAME message as no
// marker at all. Stated as an equality rather than as "does not contain DID
// send", so it also catches a third branch appearing later.
func TestIdentityGatedMarker_ForgedOnDirectPathIsIndistinguishableFromAbsent(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	bare := httptest.NewRequest("POST", "/api/v1/overrides", nil)
	forged := httptest.NewRequest("POST", "/api/v1/overrides", nil)
	forged.Header.Set(sharedidentity.HeaderIdentityGated, sharedidentity.IdentityGatedTrue)

	got := identityRequiredMessage(forged, "policy overrides")
	want := identityRequiredMessage(bare, "policy overrides")
	if got != want {
		t.Errorf("a forged marker still selects a different sentence:\n forged: %s\n absent: %s", got, want)
	}
}

// Round-2 R3 on #3069 changed the UNMARKED branch to state the release default
// rather than the deployment's actual setting. That property is load-bearing
// for this issue's severity — it is why an unbound marker was prose-only rather
// than a configuration oracle — so it is re-asserted here against the branch
// this fix newly routes forged markers into, not just against the absent case.
func TestIdentityGatedMarker_ForgedMarkerCannotProbeTheDeploymentsGateState(t *testing.T) {
	for _, mode := range []string{"enterprise", "community-saas"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)
			installProxyTokenValidator(t, proxyGuardTestSecret)

			// The gate is ON in this deployment...
			t.Setenv(sharedidentity.EnvVar, "true")

			msg := identityRequiredMessage(markedRequest(), "policy overrides")
			// ...so the message must not claim it is off, and must not claim to
			// know either way.
			for _, forbidden := range []string{
				sharedidentity.EnvVar + " is not",
				"is not \"true\"",
				"has not declared",
			} {
				if strings.Contains(msg, forbidden) {
					t.Errorf("forged marker produced an assertion about deployment state (%q): %s",
						forbidden, msg)
				}
			}
			if !strings.Contains(msg, "defaults to off") {
				t.Errorf("the safe branch must still name the release default: %s", msg)
			}
		})
	}
}
