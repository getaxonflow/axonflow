// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// #3241 round 2. Adding X-Axonflow-Admin-Authority to the orchestrator's
// trusted-header vocabulary is a privilege escalation UNLESS the agent strips
// it at every boundary its siblings are stripped at.
//
// There are two such boundaries in proxy.go and they had independently
// maintained literal lists: the preflight branch
// (stripClientAssertedProxyHeaders) and the authenticated branch (inside
// proxyAuthMiddleware). A header added to one and not the other is stripped on
// a route that never reaches the orchestrator and forwarded on the route that
// does - the worst possible split, and invisible to a test that only checks the
// header it happens to name.
//
// So these tests iterate sharedidentity.NeverClientAssertableHeaders rather
// than naming headers. A newly trusted header is covered on the commit that
// adds it to the census, or it fails here.

// TestEveryNeverClientAssertableHeaderIsStripped drives the AUTHENTICATED
// branch - the one whose output actually reaches the orchestrator.
func TestEveryNeverClientAssertableHeaderIsStripped(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	if len(sharedidentity.NeverClientAssertableHeaders) == 0 {
		t.Fatal("NeverClientAssertableHeaders is empty - this test would pass vacuously")
	}

	for _, h := range sharedidentity.NeverClientAssertableHeaders {
		t.Run(h, func(t *testing.T) {
			var seen string
			handler := proxyAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
				seen = r.Header.Get(h)
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest("GET", "/api/v1/audit/search", nil)
			// The forged value is the one that would actually elevate, not a
			// placeholder: a header stripped only when it carries some other
			// value is not stripped.
			req.Header.Set(h, forgedValueFor(h))
			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", w.Code)
			}
			if seen != "" {
				t.Errorf("client-forged %s reached the proxied handler as %q. The orchestrator honours this "+
					"header on proxy-auth'd requests and the Director adds proxy-auth to everything we "+
					"forward, so this is a caller minting the authority the header names.", h, seen)
			}
		})
	}
}

// TestEveryNeverClientAssertableHeaderIsStrippedOnPreflight drives the OTHER
// branch. Kept separate rather than folded in, because the two strips are
// separate code paths and a single test exercising one of them would report
// green while the other leaked.
func TestEveryNeverClientAssertableHeaderIsStrippedOnPreflight(t *testing.T) {
	for _, h := range sharedidentity.NeverClientAssertableHeaders {
		t.Run(h, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, "/api/v1/audit/search", nil)
			req.Header.Set(h, forgedValueFor(h))

			stripClientAssertedProxyHeaders(req)

			if got := req.Header.Get(h); got != "" {
				t.Errorf("client-forged %s survived stripClientAssertedProxyHeaders as %q", h, got)
			}
		})
	}
}

// TestStripCensusIsAliveOnAKnownHeader is the positive control for both tests
// above: it pins that the strip helper is actually capable of leaving a header
// alone, so a "strip everything" implementation could not satisfy them
// vacuously.
func TestStripCensusIsAliveOnAKnownHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/audit/search", nil)
	req.Header.Set("X-Request-ID", "keep-me")
	req.Header.Set(sharedidentity.HeaderAdminAuthority, sharedidentity.AdminAuthorityAsserted)

	stripClientAssertedProxyHeaders(req)

	if req.Header.Get("X-Request-ID") != "keep-me" {
		t.Error("an ordinary header was stripped - the tests above would pass for the wrong reason")
	}
	if req.Header.Get(sharedidentity.HeaderAdminAuthority) != "" {
		t.Error("the admin-authority header survived")
	}
}

// forgedValueFor returns the value a caller would actually forge for a given
// trusted header - the one that grants something.
func forgedValueFor(header string) string {
	switch header {
	case sharedidentity.HeaderUserRole:
		return "admin"
	case sharedidentity.HeaderReadScope:
		return sharedidentity.ReadScopeTenant
	case sharedidentity.HeaderAdminAuthority:
		return sharedidentity.AdminAuthorityAsserted
	default:
		// A header in the census with no forged value here is a gap in this
		// test, not a pass. Return something non-empty so the strip assertion
		// still runs, and make the omission visible in the failure text.
		return "FORGED-VALUE-NOT-MODELLED-FOR-" + header
	}
}
