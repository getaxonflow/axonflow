// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - HITL reviewer identity binding

//go:build enterprise

package hitl

import (
	"net/http"
	"strings"

	"axonflow/platform/shared/identity"
)

// Reviewer-identity binding for the HITL oversight endpoints (#3065 F5).
//
// The approve / reject / override handlers used to build the Reviewer WHOLLY
// from the request body:
//
//	reviewer := &Reviewer{ID: input.ReviewerID, Email: input.ReviewerEmail, Role: input.ReviewerRole}
//
// That value is what lands in hitl_approval_history.actor_id / actor_email /
// actor_role — the EU AI Act Article 14 human-oversight record. Any caller
// authorized to approve could therefore attribute their approval to a
// colleague, an auditor, or a fabricated compliance officer. Binding the
// TARGET of a state transition to the caller's tenancy (which the rest of
// this change does) is not sufficient on its own: an oversight record whose
// actor is self-asserted is not evidence of oversight.
//
// The reviewer is now derived from the request's AUTHENTICATED identity.
// The body fields are ignored for attribution.

// reviewerRoleUser / reviewerRoleService describe HOW the actor was
// authenticated, which is the only role claim this plane can make honestly.
// The previous `reviewer_role` body field asserted things like
// "compliance_officer" with nothing behind it.
const (
	reviewerRoleUser    = "user"
	reviewerRoleService = "service"
)

// syntheticReviewerDomain is the platform's reserved domain for identities
// that are a CREDENTIAL rather than a person. The audit identity classifier
// (#2805) keys on it, so a shared-credential approval is never mistaken for a
// named human reviewer. Same family the agent and the customer portal already
// synthesize.
const syntheticReviewerDomain = "@axonflow.local"

// resolveReviewer derives the acting reviewer from the authenticated request,
// returning ok=false when the request carries no identity at all (the caller
// must then write a 401 and stop — never fall back to the body).
//
// Precedence:
//
//  1. A per-user identity from the trust-gated X-User-Email / X-User-ID
//     headers. AXONFLOW_TRUST_IDENTITY_HEADERS is read through the shared
//     contract in platform/shared/identity and its default (OFF) is NOT
//     changed here: when the gate is off these headers are ignored, exactly
//     as every other governance plane ignores them.
//  2. The authenticated client credential — X-Client-ID (the v9 identity
//     wire field), falling back to its X-Tenant-ID alias. Both are Set (not
//     Add) by the agent's apiAuthMiddleware from the validated credential, so
//     a client cannot choose this value. Recorded in the reserved synthetic
//     domain so the record reads as "approved by this credential", which is
//     the truth, rather than as a named person.
func resolveReviewer(r *http.Request) (*Reviewer, bool) {
	if r == nil {
		return nil, false
	}

	if trusted, _ := identity.FromEnv(); trusted {
		email := identity.CanonicalEmail(r.Header.Get("X-User-Email"))
		userID := strings.TrimSpace(r.Header.Get("X-User-ID"))
		if email != "" || userID != "" {
			if userID == "" {
				userID = email
			}
			if email == "" {
				email = userID
			}
			return &Reviewer{
				ID:    userID,
				Email: email,
				Role:  reviewerRoleUser,
				IP:    getClientIP(r),
			}, true
		}
	}

	clientID := strings.TrimSpace(r.Header.Get("X-Client-ID"))
	if clientID == "" {
		clientID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if clientID == "" {
		return nil, false
	}
	return &Reviewer{
		ID:    clientID,
		Email: identity.CanonicalEmail(clientID + syntheticReviewerDomain),
		Role:  reviewerRoleService,
		IP:    getClientIP(r),
	}, true
}
