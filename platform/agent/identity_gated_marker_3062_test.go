// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3062 — the advisory X-Axonflow-Identity-Gated marker.
//
// The override endpoints refuse to act without a per-user identity. With the
// trust gate off (the default since 9.9.0) the agent strips X-User-Email from
// every proxied route, so the orchestrator cannot tell "the caller sent no
// identity" from "the caller sent one and we removed it" — and answered both
// with a 401 that told the user to send the header they had just sent.
//
// This marker carries that one bit across the hop. These tests pin the two
// properties the diagnosis rests on: it is set on EXACTLY the drop case, and
// it can never be asserted by the client.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// gatedMarkerRequest builds a proxied request carrying the auth-derived
// headers the middleware sets, plus whatever per-user identity the caller
// asserted.
func gatedMarkerRequest(identity map[string]string) *http.Request {
	r := httptest.NewRequest("POST", "/api/v1/overrides", nil)
	r.Header.Set("X-Tenant-ID", "tenant-real")
	r.Header.Set("X-Org-ID", "org-real")
	for k, v := range identity {
		r.Header.Set(k, v)
	}
	return r
}

func TestGateProxyIdentityHeaders_MarkerSetOnlyWhenAnIdentityWasDropped(t *testing.T) {
	cases := []struct {
		name       string
		gate       string
		identity   map[string]string
		wantMarker bool
	}{
		{
			// The reported case: the plugin sends an identity, the default-off
			// gate removes it, and the override 401 needs to say so.
			name:       "gate off + email present → marker",
			gate:       "false",
			identity:   map[string]string{identityHeaderUserEmail: "dev@corp.example"},
			wantMarker: true,
		},
		{
			name:       "gate off + user-id only → marker",
			gate:       "false",
			identity:   map[string]string{identityHeaderUserID: "uid-1"},
			wantMarker: true,
		},
		{
			// X-Session-Id names a conversation, not a person. No
			// identity-required endpoint reads it (createOverrideHandler /
			// revokeOverrideHandler take X-User-Email with an X-User-ID
			// fallback, never this), so dropping it is never why one of them
			// refused. Marking it would tell a caller who sent NO identity
			// that we removed the identity they sent, and the remedy that
			// advice implies — enabling the trust gate — relaxes the posture
			// on every proxied route without fixing their call.
			name:       "gate off + session-id only → NO marker (names a session, not a principal)",
			gate:       "false",
			identity:   map[string]string{identityHeaderSessionID: "sess-1"},
			wantMarker: false,
		},
		{
			// …but a session id riding ALONGSIDE a real principal must not
			// suppress the marker: the principal was still dropped.
			name: "gate off + email AND session-id → marker",
			gate: "false",
			identity: map[string]string{
				identityHeaderUserEmail: "dev@corp.example",
				identityHeaderSessionID: "sess-1",
			},
			wantMarker: true,
		},
		{
			// Nothing was dropped, so there is nothing to explain: the caller
			// genuinely sent no identity and must be told to send one.
			name:       "gate off + no identity → no marker",
			gate:       "false",
			identity:   nil,
			wantMarker: false,
		},
		{
			// Unset env is the real-world default, not just "false".
			name:       "gate unset + email present → marker",
			gate:       "",
			identity:   map[string]string{identityHeaderUserEmail: "dev@corp.example"},
			wantMarker: true,
		},
		{
			// An unrecognized value is treated as OFF (fail-safe), so a header
			// IS dropped — and the marker must reflect that, or the operator
			// gets the "you sent nothing" message while their typo'd flag is
			// the actual cause.
			name:       "gate typo'd to TRUE (unrecognized ⇒ off) + email → marker",
			gate:       "TRUE",
			identity:   map[string]string{identityHeaderUserEmail: "dev@corp.example"},
			wantMarker: true,
		},
		{
			name:       "gate on + email present → forwarded, no marker",
			gate:       "true",
			identity:   map[string]string{identityHeaderUserEmail: "dev@corp.example"},
			wantMarker: false,
		},
		{
			name:       "gate on + no identity → no marker",
			gate:       "true",
			identity:   nil,
			wantMarker: false,
		},
		{
			// Gate ON but the value sanitizes to nothing: the header is still
			// deleted, but the cause is malformed input, NOT configuration.
			// Marking it would send the operator to flip a flag that is
			// already on.
			name:       "gate on + unsanitizable value → no marker",
			gate:       "true",
			identity:   map[string]string{identityHeaderUserEmail: "\x01\x02"},
			wantMarker: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetIdentityWarnLatches(t)
			t.Setenv(sharedidentity.EnvVar, tc.gate)

			r := gatedMarkerRequest(tc.identity)
			gateProxyIdentityHeaders(r)

			got := sharedidentity.IdentityWasGated(r.Header.Get(sharedidentity.HeaderIdentityGated))
			if got != tc.wantMarker {
				t.Errorf("marker = %v (raw %q), want %v",
					got, r.Header.Get(sharedidentity.HeaderIdentityGated), tc.wantMarker)
			}

			// The marker never changes the gate's actual behavior: auth-derived
			// headers survive, and an off gate still strips every identity header.
			if r.Header.Get("X-Tenant-ID") != "tenant-real" || r.Header.Get("X-Org-ID") != "org-real" {
				t.Error("auth-derived headers must survive the gate untouched")
			}
			if trusted, _ := sharedidentity.Parse(tc.gate); !trusted {
				for _, h := range []string{identityHeaderUserEmail, identityHeaderUserID, identityHeaderSessionID} {
					if v := r.Header.Get(h); v != "" {
						t.Errorf("gate off: %s must still be stripped, got %q", h, v)
					}
				}
			}
		})
	}
}

// The marker is the agent's to stamp. A governed caller must never be able to
// assert it through the gateway — it is deleted on the way in, in EVERY gate
// state, including the states where the agent will not re-set it.
func TestGateProxyIdentityHeaders_InboundForgedMarkerIsAlwaysStripped(t *testing.T) {
	for _, gate := range []string{"true", "false", "", "TRUE"} {
		for _, forged := range []string{"true", "TRUE", "1", "yes"} {
			t.Run("gate="+gate+"/forged="+forged, func(t *testing.T) {
				resetIdentityWarnLatches(t)
				t.Setenv(sharedidentity.EnvVar, gate)

				// No identity headers ⇒ nothing is dropped ⇒ the agent has no
				// reason to set the marker. Anything left is the client's forgery.
				r := gatedMarkerRequest(nil)
				r.Header.Set(sharedidentity.HeaderIdentityGated, forged)

				gateProxyIdentityHeaders(r)

				if v := r.Header.Get(sharedidentity.HeaderIdentityGated); v != "" {
					t.Fatalf("client-asserted marker survived the gate as %q — it must be deleted", v)
				}
			})
		}
	}
}

// A forged marker must not be able to SUPPRESS a real one either: the agent
// overwrites, it does not merge. (Set-after-Del, not Add.)
func TestGateProxyIdentityHeaders_ForgedMarkerReplacedByTheRealVerdict(t *testing.T) {
	resetIdentityWarnLatches(t)
	t.Setenv(sharedidentity.EnvVar, "false")

	r := gatedMarkerRequest(map[string]string{identityHeaderUserEmail: "dev@corp.example"})
	r.Header.Set(sharedidentity.HeaderIdentityGated, "false")

	gateProxyIdentityHeaders(r)

	if vals := r.Header.Values(sharedidentity.HeaderIdentityGated); len(vals) != 1 {
		t.Fatalf("marker must be a single authoritative value, got %v", vals)
	}
	if !sharedidentity.IdentityWasGated(r.Header.Get(sharedidentity.HeaderIdentityGated)) {
		t.Error("the agent's verdict must overwrite a client-supplied marker value")
	}
}
