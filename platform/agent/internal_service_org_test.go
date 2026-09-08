// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "testing"

// TestAnInternalServiceUserCarriesTheAuthenticatedOrganization is the agent half
// of #3828.
//
// The orchestrator now sends X-Org-ID on the mcp-query hop, and the
// internal-service branch of authenticateLegacy reads it into auth.OrgID -
// trusted because IsValidInternalServiceRequest has already proved the caller
// holds the shared secret. ResolveUser then DROPPED it: the value arrived, was
// authenticated, and went nowhere, because the MCP call sites read
// user.OrgID rather than auth.OrgID.
//
// That is the whole difference between a plane with a window and a plane
// without one, and nothing about the request looked wrong - it succeeded, it was
// governed, and it produced a refusal in a counter nobody was reading.
//
// The other two thirds of the fix are pinned where they live:
// TestRouteToAgentCarriesTheOrganization (package orchestrator) proves the
// header is sent, and TestAnEmptyOrgWithATenantIsTheRefusedShape (package
// shared/policy) drives the REAL policy engine and the REAL observation site to
// prove the resulting option shape is compared rather than refused.
func TestAnInternalServiceUserCarriesTheAuthenticatedOrganization(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth *AuthResult
		want string
	}{
		{
			name: "the org the orchestrator sent reaches the user",
			auth: &AuthResult{
				Kind:     AuthKindInternalService,
				TenantID: "tenant-a",
				OrgID:    "org-a",
				Client:   &Client{ID: "orchestrator", TenantID: "tenant-a", OrgID: "org-a"},
			},
			want: "org-a",
		},
		{
			name: "no org sent - the user has none, and that is still an honest answer",
			auth: &AuthResult{
				Kind:     AuthKindInternalService,
				TenantID: "tenant-a",
				Client:   &Client{ID: "orchestrator", TenantID: "tenant-a"},
			},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user, err := ResolveUser(tc.auth, "")
			if err != nil {
				t.Fatalf("ResolveUser: %v", err)
			}
			if user.OrgID != tc.want {
				t.Fatalf("user.OrgID = %q, want %q.\n\nThe MCP call sites pass user.OrgID to "+
					"evaluateInputPolicies. With it empty, OrgScopePtr(\"\") returns nil, "+
					"orgScopeOf falls back to the tenant id, and planeshadow.Observe refuses "+
					"every `mcp` observation as \"an org scope but no org id\" - so the plane's "+
					"ADR-065 window is structurally empty on every enterprise stack (#3828).",
					user.OrgID, tc.want)
			}
			// ANTI-VACUITY: the tenant was already carried, so a ResolveUser
			// that returned a zero User would satisfy the "no org" case above.
			if user.TenantID != tc.auth.TenantID {
				t.Fatalf("user.TenantID = %q, want %q; ResolveUser is not building the user this "+
					"test thinks it is", user.TenantID, tc.auth.TenantID)
			}
		})
	}
}
