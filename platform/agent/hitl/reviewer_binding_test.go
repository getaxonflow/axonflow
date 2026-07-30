// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - HITL reviewer identity binding tests

//go:build enterprise

package hitl

import (
	"net/http/httptest"
	"testing"

	"axonflow/platform/shared/identity"
)

// #3065 F5 — the EU AI Act Article 14 oversight record's ACTOR was
// self-asserted.
//
// The approve / reject / override handlers built the Reviewer wholly from the
// request body (reviewer_id / reviewer_email / reviewer_role), and that value
// lands in hitl_approval_history.actor_* — the human-oversight evidence. Any
// caller authorized to approve could therefore attribute the approval to a
// colleague, an auditor, or a fabricated compliance officer.
//
// Binding the TARGET of a state transition to the caller's tenancy (which the
// rest of #3065 does) is not sufficient on its own: an oversight record whose
// actor is self-asserted is not evidence of oversight.

func TestResolveReviewer_IgnoresTheBodyAndUsesTheAuthenticatedCredential(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/v1/hitl/queue/x/approve", nil)
	// The agent's apiAuthMiddleware Sets these from the validated credential.
	r.Header.Set("X-Client-ID", "acme-prod")
	r.Header.Set("X-Org-ID", "org-a")
	// A caller-chosen identity, of the kind the body used to supply verbatim.
	r.Header.Set("X-User-Email", "cfo@victim.example")

	rev, ok := resolveReviewer(r)
	if !ok {
		t.Fatal("an authenticated client must always resolve to a reviewer")
	}
	if rev.ID != "acme-prod" {
		t.Errorf("reviewer id = %q, want the authenticated client id", rev.ID)
	}
	if rev.Email != "acme-prod@axonflow.local" {
		t.Errorf("reviewer email = %q, want the reserved synthetic domain so the record reads as a credential, not a person", rev.Email)
	}
	if rev.Role != reviewerRoleService {
		t.Errorf("reviewer role = %q, want %q — the role must describe how the actor authenticated, not what the caller claimed",
			rev.Role, reviewerRoleService)
	}
}

func TestResolveReviewer_TrustGatedPerUserIdentity(t *testing.T) {
	// The trust gate is the existing #2896 contract; this change does not
	// alter its default (OFF) — it only consumes it.
	t.Setenv(identity.EnvVar, "true")

	r := httptest.NewRequest("POST", "/api/v1/hitl/queue/x/approve", nil)
	r.Header.Set("X-Client-ID", "acme-prod")
	r.Header.Set("X-User-Email", "Reviewer@Example.COM")

	rev, ok := resolveReviewer(r)
	if !ok {
		t.Fatal("resolveReviewer must succeed with a trusted per-user identity")
	}
	if rev.Email != "reviewer@example.com" {
		t.Errorf("email = %q, want the canonicalized form (attribution and read-scoping must key on the same value)", rev.Email)
	}
	if rev.Role != reviewerRoleUser {
		t.Errorf("role = %q, want %q", rev.Role, reviewerRoleUser)
	}
}

func TestResolveReviewer_GateOffIgnoresTheForgeableHeader(t *testing.T) {
	t.Setenv(identity.EnvVar, "false")

	r := httptest.NewRequest("POST", "/api/v1/hitl/queue/x/approve", nil)
	r.Header.Set("X-Client-ID", "acme-prod")
	r.Header.Set("X-User-Email", "ceo@victim.example")

	rev, ok := resolveReviewer(r)
	if !ok {
		t.Fatal("resolveReviewer must fall back to the authenticated credential")
	}
	if rev.Email == "ceo@victim.example" {
		t.Fatal("with the trust gate OFF, a client-asserted identity must never reach the oversight record")
	}
	if rev.ID != "acme-prod" {
		t.Errorf("reviewer id = %q, want the authenticated client id", rev.ID)
	}
}

func TestResolveReviewer_NoIdentityIsADenial(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/v1/hitl/queue/x/approve", nil)
	if _, ok := resolveReviewer(r); ok {
		t.Fatal("a request with no authenticated identity must not produce a reviewer — the handler maps this to 401")
	}
}

func TestResolveReviewer_FallsBackToTheTenantAlias(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/v1/hitl/queue/x/approve", nil)
	// X-Client-ID is the v9 identity wire field; X-Tenant-ID is its
	// compatibility alias and is Set by the same middleware.
	r.Header.Set("X-Tenant-ID", "legacy-client")

	rev, ok := resolveReviewer(r)
	if !ok {
		t.Fatal("the deprecated alias must still resolve an identity during the v9 window")
	}
	if rev.ID != "legacy-client" {
		t.Errorf("reviewer id = %q, want legacy-client", rev.ID)
	}
}
