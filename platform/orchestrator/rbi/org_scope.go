// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"net"
	"net/http"
	"strings"

	"axonflow/platform/shared/identity"
)

// orgIDHeader is the gateway-stamped organization identity.
//
// platform/agent/proxy.go proxyAuthMiddleware Set()s it (not Add()s) from the
// cryptographically validated client credential on every proxied route, and
// /api/v1/rbi is in the proxied prefix list — so on this plane the header is
// server-derived and a client-supplied value is overwritten before the request
// reaches the orchestrator.
const orgIDHeader = "X-Org-ID"

// resolveOrgID returns the organization the caller is AUTHENTICATED for, or ""
// when there is none.
//
// #3066 C3-3 / epic #3071. Every RBI handler family used to accept the scoping
// org from a client-supplied `?org_id=` query parameter — in the audit-export
// family the parameter outranked the header outright, in the other five it was
// taken whenever the header was absent. No gateway policy can neutralise a
// query parameter, so that made the tenant boundary a value the caller chose:
//
//	GET    /api/v1/rbi/audit-exports?org_id=<victim>       → victim's exports
//	DELETE /api/v1/rbi/audit-exports/{id}?org_id=<victim>  → destroyed them
//	POST   /api/v1/rbi/audit-exports/{id}/process?org_id=… → ran a victim export
//
// The capability is DELETED, not narrowed: there is no route in this module
// that legitimately names a target org other than the caller's own (the only
// in-repo callers — ee/examples/compliance/audit-export-cloud/* — pass their
// own identifier, and every create/read/delete in a session now derives the
// same authenticated org, so they keep working with the parameter inert).
// Should a genuine "admin reads another org" need appear, it must be
// authorized against the caller's own org and role at the door, never inferred
// from an unauthenticated parameter.
//
// The result is TRIMMED so a whitespace-only header cannot pass the callers'
// `orgID == ""` fail-closed check and reach the repositories as a blank scope.
// A blank org is the recurring defect in this codebase: an empty-string org
// predicate aliases every row whose org was written blank, and on an INSERT it plants a
// row nothing can subsequently scope. Callers MUST treat "" as 401 — they must
// never pass it downstream.
func resolveOrgID(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get(orgIDHeader))
}

// -----------------------------------------------------------------------------
// Acting-principal binding (#3150)
// -----------------------------------------------------------------------------

// actorRoleUser / actorRoleService describe HOW the acting principal
// authenticated, which is the only role claim this module can make honestly.
// The `actor_role` body field they replace asserted things like
// "compliance_officer" with nothing behind it.
//
// Same vocabulary as platform/agent/hitl/reviewer_binding.go, deliberately: an
// auditor reading hitl_approval_history.actor_role and
// rbi_kill_switch_history.actor_role should not have to learn two spellings for
// "this was a person" and "this was a credential".
const (
	actorRoleUser    = "user"
	actorRoleService = "service"
)

// syntheticActorDomain is the platform's reserved domain for identities that
// are a CREDENTIAL rather than a person. The audit identity classifier (#2805,
// identity.IsSharedSyntheticIdentity) keys on it, so a shared-credential
// approval is never mistaken for a named human approver.
const syntheticActorDomain = "@axonflow.local"

// systemActorID is the last-resort actor for a request that carries neither a
// per-user identity nor a client credential — the same sentinel the sibling
// regulatory modules use (euaiact conformity_handlers.go, masfeat
// getUserFromRequest, sebi getUserID), and the same one this module's own
// automated paths already write (killswitch_service.go ActorID: "system").
const systemActorID = "system"

// complianceActor is the resolved acting principal for an RBI compliance
// action: who is recorded as having requested an audit export, generated or
// approved a board report, or armed or released a kill switch.
type complianceActor struct {
	ID    string
	Email string
	Role  string
	IP    string
}

// resolveActor derives the acting principal from the AUTHENTICATED request.
//
// # The defect (#3150)
//
// Eight RBI handlers took the compliance actor from the JSON body —
// `requested_by`, `generated_by`, `submitted_by`, `approved_by`, `rejected_by`,
// `actor_id`/`actor_email`/`actor_role`/`actor_ip`, `approver` — and persisted
// it as the actor of the action. The whole module was the outlier: a grep for
// "X-User" across platform/orchestrator/rbi returned exactly one hit, a CORS
// Access-Control-Allow-Headers string naming X-User-ID that nothing read.
// Its siblings euaiact and masfeat both resolved from the headers already.
//
// This crosses no tenant boundary — resolveOrgID above still binds every one of
// these to the authenticated organization, and #3066 closed the query-parameter
// scope hole separately — and the caller must already hold a valid credential.
// What it defeats is ATTRIBUTION and NON-REPUDIATION on a compliance action.
// Given the artefacts are RBI FREE-AI evidence submitted to a regulator, being
// able to say who approved the board report is the entire point of recording
// it. An approval whose approver is self-asserted is not evidence of approval.
//
// # Precedence
//
//  1. A per-user identity from the trust-gated X-User-Email / X-User-ID
//     headers. AXONFLOW_TRUST_IDENTITY_HEADERS is read through the shared
//     contract in platform/shared/identity and its default (OFF) is NOT changed
//     here: with the gate off these headers are ignored, exactly as every other
//     governance plane ignores them. Note the agent also re-sets X-User-Email
//     from a cryptographically VALIDATED per-user token irrespective of the
//     gate (proxy.go), so an enterprise fleet gets a named actor without
//     opting into header trust at all.
//  2. The authenticated client credential — X-Client-ID (the v9 identity wire
//     field), falling back to its X-Tenant-ID alias. Both are Set (not Add) by
//     the agent's proxyAuthMiddleware from the validated credential on every
//     /api/v1/rbi route, so a client cannot choose this value. Recorded in the
//     reserved synthetic domain so the record reads as "requested by this
//     credential" — which is the truth — rather than as a named person.
//  3. systemActorID.
//
// # Why this does not fail closed
//
// It never refuses. resolveOrgID is the authentication gate on these routes and
// already 401s a caller with no authenticated org; this function only decides
// how precisely the resulting record names the actor. Refusing here would break
// real callers for no security gain: the in-tree RBI clients
// (ee/examples/compliance/audit-export-cloud/{go,python,typescript,java,http},
// ee/examples/rbi-free-ai/http/rbi-flow.sh) and both runtime-e2e suites send
// X-Org-ID and a Basic credential and no per-user identity at all, and the
// direct-to-orchestrator harnesses send neither X-Client-ID nor X-Tenant-ID.
// Degrading to a truthful "system" is strictly better than today's forgeable
// name and costs nobody their access.
func resolveActor(r *http.Request) complianceActor {
	if r == nil {
		return complianceActor{ID: systemActorID, Email: "", Role: actorRoleService}
	}

	ip := actorClientIP(r)

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
			return complianceActor{ID: userID, Email: email, Role: actorRoleUser, IP: ip}
		}
	}

	clientID := strings.TrimSpace(r.Header.Get("X-Client-ID"))
	if clientID == "" {
		clientID = strings.TrimSpace(r.Header.Get(tenantIDHeader))
	}
	if clientID != "" {
		return complianceActor{
			ID:    clientID,
			Email: identity.CanonicalEmail(clientID + syntheticActorDomain),
			Role:  actorRoleService,
			IP:    ip,
		}
	}

	return complianceActor{ID: systemActorID, Email: "", Role: actorRoleService, IP: ip}
}

// tenantIDHeader is the v9 alias of X-Client-ID; both are stamped by the agent
// from the validated credential during the compatibility window (ADR-052 §5).
const tenantIDHeader = "X-Tenant-ID"

// actorClientIP records where the action came from. It is BEST EFFORT and is
// documented as such rather than being quietly trusted: X-Forwarded-For and
// X-Real-IP are client-assertable, so on a deployment whose ingress does not
// rewrite them the recorded address is the caller's claim. That is still worth
// recording next to a non-forgeable actor id, and it is a strict improvement on
// the previous `actor_ip` — a plain body field with no relationship to the
// connection at all. It must never become an authorization input.
func actorClientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
