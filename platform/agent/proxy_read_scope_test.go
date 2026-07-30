// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// #2922: proxyAuthMiddleware is the global choke point for the proxied REST
// read plane. A client-supplied role/read-scope header must NEVER reach the
// orchestrator — the orchestrator honors those only over the trusted
// proxy-auth channel, so forwarding an inbound value would let any governed
// caller mint tenant-wide read authority. The strip is unconditional (every
// proxied route, every mode) per the #2896 census lesson.
func TestProxyAuthMiddleware_StripsForgedRoleAndScopeHeaders(t *testing.T) {
	// Community mode so Authenticate passes with no credentials. #3096: this
	// used to lean on unset being the community default; it is now named.
	t.Setenv("DEPLOYMENT_MODE", "community")

	var seenRole, seenScope string
	handler := proxyAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		seenRole = r.Header.Get(sharedidentity.HeaderUserRole)
		seenScope = r.Header.Get(sharedidentity.HeaderReadScope)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/v1/audit/search", nil)
	// A malicious client forges both trust headers directly.
	req.Header.Set(sharedidentity.HeaderUserRole, "admin")
	req.Header.Set(sharedidentity.HeaderReadScope, sharedidentity.ReadScopeTenant)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if seenRole != "" {
		t.Errorf("forged %s must be stripped before forwarding, downstream saw %q",
			sharedidentity.HeaderUserRole, seenRole)
	}
	if seenScope != "" {
		t.Errorf("forged %s must be stripped before forwarding, downstream saw %q",
			sharedidentity.HeaderReadScope, seenScope)
	}
}
