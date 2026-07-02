// Copyright 2025-2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// Per-developer identity on the check_policy (PreToolUse) path — issue #2754.
//
// authenticateMCPServerRequest resolves the audit-attributed user email for the
// MCP-server protocol. The contract these tests pin:
//
//  1. When the client sends X-User-Email (the Claude Code plugin's
//     AXONFLOW_USER_EMAIL → git fallback), that REAL email is used verbatim so
//     the portal User column shows the developer, not "mcp-client:<org>".
//  2. When NO per-user header is present, the synthetic client-scoped fallback
//     ("mcp-client:<clientID>") is RETAINED — graceful degradation, never a hard
//     NULL that breaks the column. Removing the fallback would regress this.
//
// These are the DoD "real-email path does NOT regress the synthetic fallback"
// guards. Mutation test: delete the `resolvedEmail = headerEmail` preference and
// case (1) fails; delete the `mcp-client:%s` fallback and case (2) fails.

func TestAuthenticateMCPServerRequest_PrefersRealUserEmail(t *testing.T) {
	// Community mode lets Authenticate succeed without a DB, matching the
	// existing authenticateMCPServerRequest test corpus.
	t.Setenv("AXONFLOW_MODE", "community")

	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-User-Email", "alice@example.com")

	_, _, _, userEmail, _, _, _, _, err := authenticateMCPServerRequest(req)
	if err != nil {
		t.Fatalf("authenticateMCPServerRequest: %v", err)
	}
	if userEmail != "alice@example.com" {
		t.Errorf("userEmail: got %q, want %q (real X-User-Email must be preferred)", userEmail, "alice@example.com")
	}
	if strings.HasPrefix(userEmail, "mcp-client:") {
		t.Errorf("userEmail fell back to the synthetic id despite a real X-User-Email header: %q", userEmail)
	}
}

func TestAuthenticateMCPServerRequest_SyntheticFallbackRetained(t *testing.T) {
	t.Setenv("AXONFLOW_MODE", "community")

	// No X-User-Email and no X-User-ID → the synthetic client-scoped identity
	// must still be produced (never empty/NULL).
	req := httptest.NewRequest("POST", "/", nil)

	_, _, _, userEmail, _, clientID, _, _, err := authenticateMCPServerRequest(req)
	if err != nil {
		t.Fatalf("authenticateMCPServerRequest: %v", err)
	}
	if userEmail == "" {
		t.Fatal("userEmail is empty — the synthetic fallback was removed (would NULL the portal User column)")
	}
	wantPrefix := "mcp-client:"
	if !strings.HasPrefix(userEmail, wantPrefix) {
		t.Errorf("userEmail: got %q, want prefix %q (synthetic client-scoped fallback)", userEmail, wantPrefix)
	}
	// The synthetic id is client-scoped, so it must carry the resolved clientID.
	if clientID != "" && !strings.Contains(userEmail, clientID) {
		t.Errorf("synthetic userEmail %q does not embed clientID %q", userEmail, clientID)
	}
}

// TestAuthenticateMCPServerRequest_UserIDFallbackBeforeSynthetic pins the middle
// tier of the precedence: X-User-ID is used when X-User-Email is absent, still
// ahead of the synthetic id.
func TestAuthenticateMCPServerRequest_UserIDFallbackBeforeSynthetic(t *testing.T) {
	t.Setenv("AXONFLOW_MODE", "community")

	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-User-ID", "u-12345")

	_, _, _, userEmail, _, _, _, _, err := authenticateMCPServerRequest(req)
	if err != nil {
		t.Fatalf("authenticateMCPServerRequest: %v", err)
	}
	if userEmail != "u-12345" {
		t.Errorf("userEmail: got %q, want %q (X-User-ID used before synthetic fallback)", userEmail, "u-12345")
	}
}
