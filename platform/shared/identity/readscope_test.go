// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import "testing"

// TestRoleCanReadTenant pins the read-authority contract: admin, owner and
// policy_admin (as of #2993) may read cross-user (tenant-wide) rows; every
// other role — including the least-privilege "" sentinel and any unrecognized
// string — is own-rows. Fail-closed by construction (NormalizeRole collapses
// unknowns to "").
func TestRoleCanReadTenant(t *testing.T) {
	tenantWide := []string{"admin", "owner", "policy_admin"}
	for _, r := range tenantWide {
		if !RoleCanReadTenant(r) {
			t.Errorf("RoleCanReadTenant(%q) = false, want true", r)
		}
	}

	ownRowsOnly := []string{
		"",              // least-privilege sentinel (shared credential / no token)
		"developer",     // own-rows; distinguished from viewer by token:rotate:self
		"member",        // dropped from the model (#2993) → unknown → own-rows
		"viewer",        // read role, but scoped per-user for cross-user data
		"Admin",         // case-sensitive — not the canonical "admin"
		"administrator", // near-miss, unknown → least-privilege
		"root",          // unknown privileged-sounding string must NOT elevate
		"superuser",     //
		"  admin  ",     // whitespace variant — unknown → least-privilege
	}
	for _, r := range ownRowsOnly {
		if RoleCanReadTenant(r) {
			t.Errorf("RoleCanReadTenant(%q) = true, want false (fail-closed)", r)
		}
	}
}

// TestIsSharedSyntheticIdentity pins the #2938 census contract: every spelling
// the platform synthesizes as a MULTI-CALLER pool is flagged (so read scopes
// fail closed and per-user overrides are refused), while real customer
// addresses — including near-miss domains — are never caught. The census is
// documented on IsSharedSyntheticIdentity; the sixth-string case proves new
// entries are covered by the census RULES, not a copied five-string list.
func TestIsSharedSyntheticIdentity(t *testing.T) {
	cases := []struct {
		email     string
		community bool
		want      bool
	}{
		// The five shared spellings (#2896 WS1b census).
		{"mcp-client:acme-org", false, true},            // token-less MCP pseudo
		{"mcp-client:", false, true},                    // degenerate client id
		{"acme-org@axonflow.local", false, true},        // enterprise no-token fallback
		{"unknown@axonflow.local", false, true},         // audit-writer fallback
		{"orchestrator@axonflow.internal", false, true}, // internal-service ResolveUser
		{"system@axonflow.internal", false, true},       // HITL auto-approve reviewer (#2938 R3)
		{"evaluator@try.getaxonflow.com", false, true},  // community-saas ResolveUser

		// A NEW census entry under either reserved domain is covered without
		// touching any consumer (#2938 regression: one predicate, no copies).
		{"sixth-new-census-entry@axonflow.local", false, true},
		{"future-service@axonflow.internal", false, true},

		// Case/whitespace evasion: the predicate canonicalizes before matching.
		{"MCP-CLIENT:ACME-ORG", false, true},
		{" Evaluator@Try.GetAxonflow.Com ", false, true},
		{"ACME-ORG@AXONFLOW.LOCAL", false, true},
		{"Orchestrator@Axonflow.Internal", false, true},

		// local-dev: a real single user ONLY in community mode; a spoof anywhere else.
		{"local-dev@axonflow.local", true, false},
		{"local-dev@axonflow.local", false, true},

		// Real identities are never census-flagged — including near-miss
		// domains that would be caught by a careless suffix match.
		{"alice@corp.com", false, false},
		{"dev@acme.com", true, false},
		{"ops@corp.local", false, false},               // customer .local domain ≠ axonflow.local
		{"x@notaxonflow.local", false, false},          // suffix must include the "@"
		{"x@sub.axonflow.local", false, false},         // nothing mints subdomains
		{"a@axonflow.local.evil.com", false, false},    // reserved domain must be terminal
		{"a@axonflow.internal.evil.com", false, false}, // internal domain must be terminal too
		{"x@corp.internal", false, false},              // customer .internal domain ≠ axonflow.internal
		{"x@sub.axonflow.internal", false, false},      // nothing mints internal subdomains
		{"evaluator@try.getaxonflow.com.evil", false, false},
		{"orchestrator@axonflow.internal.evil", false, false},
		{"", false, false}, // empty is "no identity", handled by callers as zero rows
	}
	for _, c := range cases {
		if got := IsSharedSyntheticIdentity(c.email, c.community); got != c.want {
			t.Errorf("IsSharedSyntheticIdentity(%q, community=%v) = %v, want %v", c.email, c.community, got, c.want)
		}
	}
}

// #3001: RoleIsAdministrative exists so "owner is a strict superset of admin"
// cannot be broken again by a literal role compare. Two sites string-compared
// `== "admin"` and both EXCLUDED owner, inverting the model.
func TestRoleIsAdministrative(t *testing.T) {
	for _, tc := range []struct {
		role string
		want bool
	}{
		{"admin", true},
		{"owner", true},
		// policy_admin administers POLICIES, not the org. It reads tenant-wide
		// but must not inherit org-administrative enforcement relaxations.
		{"policy_admin", false},
		{"developer", false},
		{"viewer", false},
		// Least-privilege / unmapped, and anything unrecognized, fail closed
		// via NormalizeRole.
		{"", false},
		{"member", false},
		{"root", false},
		{"Admin", false}, // vocabulary is exact-match; case variants are unknown
		{"superuser", false},
	} {
		if got := RoleIsAdministrative(tc.role); got != tc.want {
			t.Errorf("RoleIsAdministrative(%q) = %v, want %v", tc.role, got, tc.want)
		}
	}
}

// The superset invariant itself: owner must never be treated as LESS than
// admin by any shared role predicate. This is the property #3001 found broken.
func TestOwnerIsNeverLessThanAdmin(t *testing.T) {
	for name, pred := range map[string]func(string) bool{
		"RoleIsAdministrative": RoleIsAdministrative,
		"RoleCanReadTenant":    RoleCanReadTenant,
	} {
		if pred("admin") && !pred("owner") {
			t.Errorf("%s: admin=true but owner=false — owner is a strict SUPERSET of admin (#2993); this inverts the model", name)
		}
	}
}
