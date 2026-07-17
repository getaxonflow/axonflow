// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Read-scope authorization primitives (#2922, epic #2919).
//
// The fleet plane resolves a validated per-user {identity, role} (#2920/#2924);
// this file defines how a role translates into READ authority over cross-user
// rows (audit_logs, policy_overrides, decision/session listings), and the
// trusted wire headers internal services use to carry that authority between
// planes.
//
// Trust model for the wire headers: they are honored ONLY on requests bearing
// a valid X-Axonflow-Proxy-Auth internal-service token (#2896 trusted channel).
// The agent strips both headers from every inbound client request before
// proxying and re-asserts them from the VALIDATED per-user token, so a caller
// can never smuggle an elevated role or scope through the gateway. A request
// without valid proxy-auth is always least-privilege regardless of what the
// headers claim.
package identity

import "strings"

// Wire headers for the trusted agent/portal → orchestrator identity channel.
const (
	// HeaderUserRole carries the validated per-user authz role (one of
	// knownRoles, or empty for least-privilege). Set exclusively by the agent
	// from a validated per-user token — never forwarded from a client.
	HeaderUserRole = "X-Axonflow-User-Role"

	// HeaderReadScope carries a plane-level read-scope assertion by an
	// internal service that has ALREADY authorized the caller for tenant-wide
	// reads under its own access model (the customer-portal session plane,
	// where tenant-wide audit visibility is gated by portal RBAC). The only
	// recognized value is ReadScopeTenant; anything else is ignored.
	HeaderReadScope = "X-Axonflow-Read-Scope"

	// ReadScopeTenant is the sole recognized HeaderReadScope value.
	ReadScopeTenant = "tenant"
)

// RoleCanReadTenant reports whether the resolved authz role grants tenant-wide
// (cross-user) READ access on the fleet plane: admin and owner do; every other
// role — including "" (least-privilege / unmapped) and any unknown string —
// reads own-rows only. Fail-closed by construction: NormalizeRole collapses
// unrecognized input to "" before the check, so no minting or forwarding path
// can smuggle an unrecognized-but-privileged role string past this gate.
func RoleCanReadTenant(role string) bool {
	switch NormalizeRole(role) {
	case "admin", "owner":
		return true
	default:
		return false
	}
}

// Shared synthetic-identity census (#2896 WS1b, lifted here in #2938 so the
// agent trust plane and the orchestrator read plane consume ONE predicate).
//
// These are the identities the platform synthesizes for a caller it cannot
// resolve to a person. Each is SHARED by every caller that hits its minting
// path, so none may ever key a per-user feature (ADR-044 session overrides) or
// a per-user read scope — scoping a read to one of them returns the whole
// multi-developer pool (the #2919/#2938 cross-developer audit-read leak).
const (
	// ClientPseudoIdentityPrefix marks the shared, client-scoped
	// pseudo-identity the fleet plane assigns a token-less caller:
	// "mcp-client:<clientID>". It is shared across every developer
	// authenticating with one org:license credential, so it is NOT a per-user
	// identity.
	ClientPseudoIdentityPrefix = "mcp-client:"

	// SharedServiceIdentitySuffix is a reserved domain of the platform's
	// synthesized service identities: the enterprise no-user-token fallback
	// "<client-id>@axonflow.local" (agent mcp_handler.go, decision_handler.go,
	// openai_compat_handler.go; the customer-portal orchestrator proxy mints
	// "<org>@axonflow.local" for degenerate sessions) and the audit-writer
	// fallback "unknown@axonflow.local". Nothing legitimate mints a personal
	// identity under this domain. The match is on the full "@axonflow.local"
	// domain — a customer address under some other .local domain (or under a
	// subdomain of axonflow.local) does not end with this suffix and is
	// untouched.
	SharedServiceIdentitySuffix = "@axonflow.local"

	// InternalServiceIdentitySuffix is the platform's reserved internal-service
	// domain. Every identity it mints here is a SHARED synthetic, not a person:
	// "orchestrator@axonflow.internal" (agent authenticator.go internal-service
	// ResolveUser) and "system@axonflow.internal" (ee HITL auto-approve reviewer
	// — risk_routing.go, written into audit_logs.user_email by
	// writeHITLAuditEventTx). Reserving the whole domain (not just the two exact
	// spellings) fail-closes any future internal-service synthetic by
	// construction — the #2896 writer-census discipline (#2938 R3 caught
	// system@ as a spelling the exact-match enumeration missed).
	InternalServiceIdentitySuffix = "@axonflow.internal"

	// OrchestratorServiceIdentity is the internal-service ResolveUser identity
	// (agent authenticator.go); subsumed by InternalServiceIdentitySuffix,
	// retained as a named reference for the mint site.
	OrchestratorServiceIdentity = "orchestrator@axonflow.internal"

	// CommunitySaaSEvaluatorIdentity is the community-saas ResolveUser
	// identity — one spelling shared by every try.getaxonflow.com evaluator.
	CommunitySaaSEvaluatorIdentity = "evaluator@try.getaxonflow.com"

	// CommunityLocalDevIdentity is the community-mode ResolveUser identity
	// (agent authenticator.go). Community is a no-auth, single-trust-domain
	// deployment where every caller IS the local developer, so this is the
	// one reserved-domain spelling that names a real (single) user — but only
	// while actually running in community mode; in any other mode a caller
	// asserting it is spoofing the community synthetic.
	CommunityLocalDevIdentity = "local-dev@axonflow.local"
)

// IsSharedSyntheticIdentity reports whether email is a platform-synthesized
// identity SHARED by more than one caller — not a person. This is THE census
// predicate: the agent trust plane (isClientSharedPseudoIdentity — ADR-044
// override create/offer/apply refusal, #2896) and the orchestrator read plane
// (resolveCallerReadScope — fail-closed empty read scope, #2936/#2938) both
// delegate here, so adding a census entry fail-closes BOTH surfaces at once.
// Never copy this list into a second predicate.
//
// Census of every synthesized identity the platform can resolve a governed
// caller to (keep in sync with agent ResolveUser in authenticator.go and the
// per-plane no-user-token fallbacks):
//
//	"mcp-client:<client-id>"           MCP-server pseudo-identity   → shared
//	"<client-id>@axonflow.local"       enterprise no-token fallback → shared
//	"unknown@axonflow.local"           audit-writer fallback        → shared
//	"orchestrator@axonflow.internal"   internal-service ResolveUser → shared
//	"system@axonflow.internal"         HITL auto-approve reviewer   → shared
//	"evaluator@try.getaxonflow.com"    community-saas ResolveUser   → shared
//	"local-dev@axonflow.local"         community ResolveUser        → single
//	                                   user by construction (no-auth local
//	                                   deployment); treated as shared in any
//	                                   OTHER mode, where a caller asserting
//	                                   it is spoofing the community synthetic
//
// The two reserved domains (@axonflow.local, @axonflow.internal) are matched
// by suffix so any future synthetic under them fail-closes without a census
// edit; the remaining spellings are exact-matched.
//
// The input is canonicalized (CanonicalEmail: trim + lowercase) before
// matching, so a case/whitespace variant ("MCP-CLIENT:x", " Evaluator@… ")
// cannot evade the census. The audit write path stamps the canonical form,
// so the canonical spelling is exactly the one a read scope would leak.
//
// communityMode selects the local-dev posture above. A caller that has
// already short-circuited community mode (e.g. resolveCallerReadScope returns
// tenant-wide for community before any identity check) passes false: at that
// point the deployment is NOT community, so an asserted local-dev identity is
// a spoof and fails closed.
func IsSharedSyntheticIdentity(email string, communityMode bool) bool {
	email = CanonicalEmail(email)
	if strings.HasPrefix(email, ClientPseudoIdentityPrefix) {
		return true
	}
	if email == CommunitySaaSEvaluatorIdentity {
		return true
	}
	if email == CommunityLocalDevIdentity {
		return !communityMode
	}
	// Reserved platform domains: "<client-id>@axonflow.local" +
	// "unknown@axonflow.local" (SharedServiceIdentitySuffix), and
	// "orchestrator@" + "system@axonflow.internal" (InternalServiceIdentitySuffix).
	return strings.HasSuffix(email, SharedServiceIdentitySuffix) ||
		strings.HasSuffix(email, InternalServiceIdentitySuffix)
}
