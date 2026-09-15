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
// Nothing about such a request looked wrong - it succeeded and it was governed -
// but it was governed under the tenant's policy scope rather than the
// organization's, because the organization it authenticated as never reached
// the evaluation.
//
// The other half of the fix is pinned where it lives:
// TestRouteToAgentCarriesTheOrganization (package orchestrator) proves the
// header is sent.
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
					"evaluateInputPolicies. With it empty, OrgScopePtr(\"\") returns nil and the "+
					"policy load falls back to the tenant id, so the request is governed under a "+
					"scope other than the organization it authenticated as (#3828).",
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
