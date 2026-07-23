//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Characterization + parity suite for the #2989 (ADR-060 Phase 1)
// IdentityAttributeResolver seam extraction. The extraction is supposed to
// be BEHAVIOR-PRESERVING: it must not change a single bit of role
// resolution. This file pins the pre-extraction scimRoleResolver behavior
// (the characterization net) and then proves, case by case, that the new
// combined resolver produces byte-identical Role output on the same inputs
// (the parity net) while Segments stays the Phase 1 no-op (always nil).
//
// Real-Postgres, same pattern as TestSCIMRoleResolver_RealPostgres
// (provisioning_realpg_test.go): a minimal mirror of custom_roles (mig 023)
// and role_assignments (org_id post-mig-111), seeded directly (no SCIM sync
// simulated — the resolver only ever reads role_assignments/custom_roles).
package identity

import (
	"context"
	"testing"
	"time"

	"axonflow/platform/testutil"
)

// seedIdentityAttrSchema creates the minimal role_assignments/custom_roles
// mirror the resolver reads. Deliberately does NOT create any SCIM group
// table: this is structural proof that role resolution reads only
// role_assignments/custom_roles and never joins to group membership, so a
// manual/API grant with no backing group cannot be silently dropped.
func seedIdentityAttrSchema(t *testing.T, pc *testutil.PostgresContainer) {
	t.Helper()
	pc.RunMigration(t, `
		CREATE TABLE custom_roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id VARCHAR(255) NOT NULL,
			name VARCHAR(100) NOT NULL,
			permissions JSONB NOT NULL DEFAULT '[]'::jsonb
		);
		CREATE TABLE role_assignments (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id VARCHAR(255) NOT NULL,
			user_email VARCHAR(255) NOT NULL,
			role_id UUID NOT NULL REFERENCES custom_roles(id),
			source VARCHAR(20) DEFAULT 'scim',
			expires_at TIMESTAMPTZ,
			assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`)
}

// identityAttrFixture seeds the characterization matrix once and returns
// helpers + the case table shared by every test in this file.
type identityAttrFixture struct {
	db *testutil.PostgresContainer
}

type identityAttrCase struct {
	name  string
	email string
	want  string
}

// setupIdentityAttrFixture seeds one org ("org-a") with roles + assignments
// covering every characterization requirement from the SEG-1 brief:
//   - admin/wildcard short-circuit (scim_role_resolver.go's wildcard rule)
//   - owner outranks admin even though owner's seeded bundle also carries "*"
//   - the full precedence ladder among non-admin roles
//   - unmapped (custom-only) role -> ""
//   - an expired assignment is excluded
//   - a manual grant with NO backing group survives (source='manual', no
//     group table exists in this schema at all)
//   - a manual elevation outranks a lower group-sourced (source='scim') role
//   - #2967: a non-admin-named role carrying the wildcard permission still
//     resolves to "admin" — PINNED, not fixed, here (see the dedicated test
//     below for the issue reference).
func setupIdentityAttrFixture(t *testing.T) *identityAttrFixture {
	t.Helper()
	testutil.SkipIfNoDocker(t)
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	seedIdentityAttrSchema(t, pc)

	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := pc.DB.Exec(q, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	roleID := func(name, perms string) string {
		t.Helper()
		var id string
		if err := pc.DB.QueryRow(`INSERT INTO custom_roles (org_id, name, permissions) VALUES ('org-a', $1, $2::jsonb) RETURNING id`, name, perms).Scan(&id); err != nil {
			t.Fatalf("role %s: %v", name, err)
		}
		return id
	}
	assign := func(email, rid, source string, expires *time.Time) {
		t.Helper()
		mustExec(`INSERT INTO role_assignments (org_id, user_email, role_id, source, expires_at) VALUES ('org-a', $1, $2, $3, $4)`, email, rid, source, expires)
	}

	adminID := roleID("admin", `["*"]`)
	ownerID := roleID("owner", `["*","sso:configure"]`)
	policyAdminID := roleID("policy_admin", `["policy:write"]`)
	developerID := roleID("developer", `["query","mcp_query"]`)
	viewerID := roleID("viewer", `["read"]`)
	customID := roleID("data_scientist", `["query","export"]`)
	// #2967: a role that is NOT named "admin" and is NOT "owner", but grants
	// the wildcard permission. The resolver's adminSignal check
	// (scim_role_resolver.go) fires on the wildcard alone, so this resolves
	// to "admin" even though nothing named it that — a known gap tracked
	// separately as #2967. This fixture seeds it; the dedicated test below
	// pins the behavior without attempting to fix it.
	legacyWildcardID := roleID("legacy_superuser", `["*"]`)

	past := time.Now().Add(-time.Hour)

	assign("wildcard-admin@example.com", adminID, "scim", nil)
	assign("owner@example.com", ownerID, "scim", nil)
	assign("owner-and-admin@example.com", ownerID, "scim", nil)
	assign("owner-and-admin@example.com", adminID, "scim", nil)
	assign("policy-admin@example.com", policyAdminID, "scim", nil)
	assign("developer@example.com", developerID, "scim", nil)
	assign("viewer@example.com", viewerID, "scim", nil)
	assign("ladder@example.com", viewerID, "scim", nil)
	assign("ladder@example.com", developerID, "scim", nil)
	assign("ladder@example.com", policyAdminID, "scim", nil)
	assign("custom-only@example.com", customID, "scim", nil)
	assign("expired-admin@example.com", adminID, "scim", &past)
	assign("expired-admin@example.com", viewerID, "scim", nil)
	// Manual grant, NO backing group (no group table exists in this schema
	// at all) — a contractor's project role, #2919/#2989 "role-derivation
	// wrinkle". Must resolve exactly as any other assignment: role
	// resolution never looks at `source`.
	assign("manual-only@example.com", policyAdminID, "manual", nil)
	assign("api-only@example.com", developerID, "api", nil)
	// Manual elevation OUTRANKS a lower group-sourced (source='scim') role —
	// the on-call incident-elevation shape. Must resolve to the manual
	// grant's higher precedence, proving `source` never gates or
	// deprioritizes a manual assignment.
	assign("elevated@example.com", viewerID, "scim", nil)
	assign("elevated@example.com", ownerID, "manual", nil)
	assign("wildcard-nonadmin@example.com", legacyWildcardID, "scim", nil)

	return &identityAttrFixture{db: pc}
}

// cases is the full characterization + parity matrix. Every case here is
// exercised against BOTH the pre-extraction scimRoleResolver (via
// NewSCIMRoleResolver) and the new IdentityAttributeResolver — the parity
// test asserts they agree, and this table is the single source of truth for
// "what the correct answer is" so the two assertions can never drift apart.
func (f *identityAttrFixture) cases() []identityAttrCase {
	return []identityAttrCase{
		{"wildcard permission named admin resolves admin", "wildcard-admin@example.com", "admin"},
		{"owner with wildcard resolves owner, not admin (#2993 superset)", "owner@example.com", "owner"},
		{"owner + admin resolves owner (owner outranks admin)", "owner-and-admin@example.com", "owner"},
		{"policy_admin-only resolves policy_admin", "policy-admin@example.com", "policy_admin"},
		{"developer-only resolves developer", "developer@example.com", "developer"},
		{"viewer-only resolves viewer", "viewer@example.com", "viewer"},
		{"precedence ladder: policy_admin beats developer and viewer", "ladder@example.com", "policy_admin"},
		{"custom-only role is unmapped (least privilege)", "custom-only@example.com", ""},
		{"expired admin assignment excluded, live viewer wins", "expired-admin@example.com", "viewer"},
		{"manual grant with no backing group survives", "manual-only@example.com", "policy_admin"},
		{"api-source grant with no backing group survives", "api-only@example.com", "developer"},
		{"manual elevation outranks a lower group-sourced role", "elevated@example.com", "owner"},
		{"unknown identity is unmapped", "ghost@example.com", ""},
		// #2967 (pinned, not fixed): wildcard permission on a non-admin-named
		// role still short-circuits to "admin".
		{"#2967: non-admin role with wildcard permission resolves admin", "wildcard-nonadmin@example.com", "admin"},
	}
}

// --- characterization: the pre-extraction resolver, pinned ---

func TestSCIMRoleResolver_Characterization(t *testing.T) {
	f := setupIdentityAttrFixture(t)
	resolver, err := NewSCIMRoleResolver(f.db.DB)
	if err != nil {
		t.Fatalf("NewSCIMRoleResolver: %v", err)
	}
	ctx := context.Background()
	for _, tc := range f.cases() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolver.ResolveRole(ctx, "org-a", tc.email)
			if err != nil {
				t.Fatalf("ResolveRole(%q): %v", tc.email, err)
			}
			if got != tc.want {
				t.Fatalf("ResolveRole(%q) = %q, want %q", tc.email, got, tc.want)
			}
		})
	}

	t.Run("other org sees no assignments", func(t *testing.T) {
		got, err := resolver.ResolveRole(ctx, "org-b", "wildcard-admin@example.com")
		if err != nil {
			t.Fatalf("ResolveRole: %v", err)
		}
		if got != "" {
			t.Fatalf("org-b must not inherit org-a roles, got %q", got)
		}
	})
}

// --- parity: the new IdentityAttributeResolver against the same fixture ---

func TestIdentityAttributeResolver_ParityWithSCIMRoleResolver(t *testing.T) {
	f := setupIdentityAttrFixture(t)

	oldResolver, err := NewSCIMRoleResolver(f.db.DB)
	if err != nil {
		t.Fatalf("NewSCIMRoleResolver: %v", err)
	}
	newResolver, err := NewIdentityAttributeResolver(f.db.DB)
	if err != nil {
		t.Fatalf("NewIdentityAttributeResolver: %v", err)
	}
	ctx := context.Background()

	for _, tc := range f.cases() {
		t.Run(tc.name, func(t *testing.T) {
			oldRole, err := oldResolver.ResolveRole(ctx, "org-a", tc.email)
			if err != nil {
				t.Fatalf("old resolver ResolveRole(%q): %v", tc.email, err)
			}
			resolved, err := newResolver.Resolve(ctx, "org-a", tc.email)
			if err != nil {
				t.Fatalf("new resolver Resolve(%q): %v", tc.email, err)
			}
			if resolved.Role != oldRole {
				t.Fatalf("parity break for %q: old resolver = %q, new resolver = %q", tc.email, oldRole, resolved.Role)
			}
			if resolved.Role != tc.want {
				t.Fatalf("new resolver Resolve(%q).Role = %q, want %q", tc.email, resolved.Role, tc.want)
			}
			if resolved.Segments != nil {
				t.Fatalf("Segments must be the Phase 1 no-op (nil) for %q, got %v", tc.email, resolved.Segments)
			}

			// The embedded RoleResolver path (used by NewOIDCVerifier) must
			// agree too — it is the SAME underlying call, not a second
			// implementation.
			viaRoleResolver, err := newResolver.ResolveRole(ctx, "org-a", tc.email)
			if err != nil {
				t.Fatalf("new resolver ResolveRole(%q): %v", tc.email, err)
			}
			if viaRoleResolver != resolved.Role {
				t.Fatalf("ResolveRole/Resolve disagree for %q: %q vs %q", tc.email, viaRoleResolver, resolved.Role)
			}
		})
	}
}

// TestNewIdentityAttributeResolver_NilDB proves construction fails loudly
// (propagating NewSCIMRoleResolver's own nil-db error unchanged) rather than
// building a resolver that would panic or fail closed only much later on
// first use.
func TestNewIdentityAttributeResolver_NilDB(t *testing.T) {
	if _, err := NewIdentityAttributeResolver(nil); err == nil {
		t.Fatal("NewIdentityAttributeResolver(nil) must error, not build a resolver over a nil db")
	}
}

// TestIdentityAttributeResolver_SatisfiesRoleResolver is a compile-time +
// runtime proof that IdentityAttributeResolver can be used directly wherever
// a RoleResolver is required (NewOIDCVerifier's dependency) — no adapter
// needed. If IdentityAttributeResolver ever stops embedding RoleResolver,
// this line fails to compile.
func TestIdentityAttributeResolver_SatisfiesRoleResolver(t *testing.T) {
	f := setupIdentityAttrFixture(t)
	resolver, err := NewIdentityAttributeResolver(f.db.DB)
	if err != nil {
		t.Fatalf("NewIdentityAttributeResolver: %v", err)
	}
	var asRoleResolver RoleResolver = resolver // compile-time assertion
	got, err := asRoleResolver.ResolveRole(context.Background(), "org-a", "owner@example.com")
	if err != nil {
		t.Fatalf("ResolveRole via RoleResolver interface: %v", err)
	}
	if got != "owner" {
		t.Fatalf("ResolveRole via RoleResolver interface = %q, want owner", got)
	}

	// And it wires straight into NewOIDCVerifier, exactly the #2989 rewire
	// (mcp_identity.go registerFleetValidators).
	if _, err := NewOIDCVerifier(&stubConfigs{}, resolver); err != nil {
		t.Fatalf("NewOIDCVerifier must accept an IdentityAttributeResolver as its RoleResolver dependency: %v", err)
	}
}

// --- identity-absent / malformed input: fail closed, not silent ---

// TestIdentityAttributeResolver_IdentityAbsent_FailsClosed pins the
// Real-World-Path contract for the resolver itself (the #2832 observability
// shape, adjacent to #2948): an absent org or absent email is NEVER resolved
// to a guessed/least-privilege ResolvedIdentity silently — it is a loud
// error, so the caller (oidcVerifier.Validate, mcp_identity.go's
// registerFleetValidators wiring) is forced to reject/log rather than
// silently downgrade. This is unchanged from scimRoleResolver.ResolveRole's
// existing contract (see TestSCIMRoleResolver_Characterization above for the
// authenticated-but-unknown-identity case, which DOES resolve to "" by
// design — the distinction is "no org/email to resolve at all" vs "resolved,
// and simply unmapped").
//
// The upstream observable signals for the two other Real-World-Path shapes —
// "per-user token presented but no validator registered" (#2932) and "a
// presented token is rejected" (audited as security event
// user_token_rejected) — are NOT touched by this extraction and are pinned
// by their own existing suites: TestWarnPerUserTokenWithoutValidator_RateLimited
// (platform/agent/mcp_identity_warn_test.go) and
// TestHandleDecide_AuditsUserTokenRejected_AsBlocked
// (platform/agent/decision_handler_test.go). Both remain green, unmodified,
// after this rewire — verified as part of this PR's full test run.
func TestIdentityAttributeResolver_IdentityAbsent_FailsClosed(t *testing.T) {
	f := setupIdentityAttrFixture(t)
	resolver, err := NewIdentityAttributeResolver(f.db.DB)
	if err != nil {
		t.Fatalf("NewIdentityAttributeResolver: %v", err)
	}
	ctx := context.Background()

	t.Run("empty org", func(t *testing.T) {
		if _, err := resolver.Resolve(ctx, "", "someone@example.com"); err == nil {
			t.Fatal("Resolve with no org must fail closed (error), never a guessed identity")
		}
	})
	t.Run("empty email", func(t *testing.T) {
		if _, err := resolver.Resolve(ctx, "org-a", ""); err == nil {
			t.Fatal("Resolve with no email must fail closed (error), never a guessed identity")
		}
	})
	t.Run("both empty", func(t *testing.T) {
		if _, err := resolver.Resolve(ctx, "", ""); err == nil {
			t.Fatal("Resolve with no org/email must fail closed (error), never a guessed identity")
		}
	})
	// The embedded RoleResolver path must fail exactly the same way — it is
	// the same call, not a parallel lenient path.
	t.Run("ResolveRole (embedded) empty email", func(t *testing.T) {
		if _, err := resolver.ResolveRole(ctx, "org-a", ""); err == nil {
			t.Fatal("ResolveRole with no email must fail closed (error)")
		}
	})
}
