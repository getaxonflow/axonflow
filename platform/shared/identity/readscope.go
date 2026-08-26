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

	// HeaderAdminAuthority carries a plane-level ADMINISTRATIVE-authority
	// assertion by an internal service that has already authorized the caller
	// as an administrator of the tenant under its own access model. The only
	// recognized value is AdminAuthorityAsserted; anything else is ignored.
	//
	// WHY THIS IS A SEPARATE HEADER FROM HeaderReadScope (#3241 round 2)
	//
	// Read scope and admin authority are two axes (see callerReadScope in
	// platform/orchestrator/read_scope.go), and they were split there in #3060
	// precisely so answering "how wide may this caller see?" could not also
	// answer "is this caller an administrator?".
	//
	// The portal plane re-created the conflation one layer up: the orchestrator
	// granted AdminAuthority on HeaderReadScope alone, and the portal stamps
	// that header for ANY session holding audit:read - which the seeded VIEWER
	// role holds. So through the portal a viewer passed every AdminAuthority
	// gate: whole-tenant compliance exports, /api/v1/evidence/export,
	// /api/v1/sebi/audit/export, budget-governance CRUD, execution
	// cancel/delete, and unredacted spend on budgets/check.
	//
	// Two headers, because one header cannot carry two independent answers. A
	// caller may present read scope without authority (viewer: tenant-wide
	// reads, no administration).
	//
	// Authority WITHOUT read scope resolves to NEITHER, not to authority alone:
	// read_scope.go reads this header only inside the branch that has already
	// matched HeaderReadScope, so an authority assertion on its own is
	// discarded. That is the coherent direction (AdminAuthority implies
	// TenantWide) and it fails closed, but it is a silent drop - a caller that
	// stamps only this header gets least-privilege with no diagnostic. The
	// portal always stamps both, in that order.
	HeaderAdminAuthority = "X-Axonflow-Admin-Authority"

	// AdminAuthorityAsserted is the sole recognized HeaderAdminAuthority value.
	AdminAuthorityAsserted = "true"

	// HeaderTenancyScope carries a TENANCY-WIDTH assertion by an internal
	// service: "the caller I am forwarding for is bound to the ORG, and the
	// X-Tenant-ID on this request is a display default rather than an
	// authorization narrowing".
	//
	// WHY THIS IS A THIRD HEADER AND NOT A REUSE OF THE OTHER TWO (#3367)
	//
	// HeaderReadScope answers "how wide may this caller see ACROSS USERS
	// within one tenant" and HeaderAdminAuthority answers "is this caller an
	// administrator". Neither answers "which TENANCY KEY is this caller
	// actually bound to", and the two existing headers are deliberately kept
	// apart precisely because one header cannot carry two independent answers
	// (#3060, #3241 round 2). Folding tenancy width into either of them would
	// repeat that conflation a third time: the portal stamps HeaderReadScope
	// for every audit:read holder, so reusing it would silently widen the
	// tenancy key for the seeded viewer role as a side effect of a read-scope
	// grant.
	//
	// The distinction is real on this platform because execution_history and
	// its siblings stamp tenant_id from the EXECUTING CALLER'S CREDENTIAL
	// (the Basic-auth username; migration 049 dropped the organizations FK
	// exactly so an SDK client id could live there, and migration 092 records
	// tenant_id as a deprecated alias of client_id). A customer-portal session
	// has no credential identity at all: its tenancy authority is the org, and
	// portal_default_tenant_id (migration 065/104) hands it an ARBITRARY tenant
	// of that org - the canonical one if present, else the oldest - purely as a
	// display default. Comparing that value against a credential-shaped column
	// is not a narrowing, it is a category error, and it renders a confident
	// zero over data the session is fully authorized to see.
	//
	// Trust: honored ONLY over a valid X-Axonflow-Proxy-Auth token, exactly
	// like the two headers above, and listed in NeverClientAssertableHeaders
	// so the agent strips it from inbound client traffic at both sites.
	//
	// Fail-closed: absence means "narrow by the tenant header as before", so
	// every existing caller (the agent gateway, every SDK client, axonctl)
	// keeps its current per-credential narrowing untouched.
	HeaderTenancyScope = "X-Axonflow-Tenancy-Scope"

	// TenancyScopeOrg is the sole recognized HeaderTenancyScope value.
	TenancyScopeOrg = "org"
)

// TenancyScopeIsOrg reports whether a HeaderTenancyScope value asserts
// org-wide tenancy binding.
//
// Trimmed and case-insensitive for the same reason AdminAuthorityFromHeader is:
// a proxy that normalizes header casing must not silently drop the assertion.
// Anything other than "org" is ignored, so an absent header can never become an
// assertion.
func TenancyScopeIsOrg(v string) bool {
	return strings.EqualFold(strings.TrimSpace(v), TenancyScopeOrg)
}

// NeverClientAssertableHeaders is the closed set of trusted-plane headers a
// CLIENT may never assert, in any spelling, on any route.
//
// The orchestrator honours every one of these on a proxy-auth'd request, and
// the agent's Director adds proxy-auth to everything it forwards, so an inbound
// value that survived the hop would let any governed caller mint the authority
// the header names.
//
// This exists as ONE list because the strip is performed at two separate sites
// in platform/agent/proxy.go (the preflight branch and the authenticated
// branch) and they had independently-maintained literal lists. Adding a header
// here fail-closes both at once. Two tests pin it, one per site, because they
// are separate code paths and a single test would report green while the other
// leaked: TestEveryNeverClientAssertableHeaderIsStripped drives the
// authenticated branch and ...IsStrippedOnPreflight drives the preflight one.
//
// Do not copy this list into a third place.
var NeverClientAssertableHeaders = []string{
	HeaderUserRole,
	HeaderReadScope,
	HeaderAdminAuthority,
	HeaderTenancyScope,
}

// AdminAuthorityFromHeader reports whether a HeaderAdminAuthority value asserts
// administrative authority.
//
// Trimmed and case-insensitive so a proxy that normalizes header casing or
// appends whitespace cannot silently drop the assertion; anything other than
// "true" is ignored, so "false", "1", "yes" and "" all mean no authority. The
// permissive parse is safe in only this direction: it can never turn an absent
// header into an assertion.
func AdminAuthorityFromHeader(v string) bool {
	return strings.EqualFold(strings.TrimSpace(v), AdminAuthorityAsserted)
}

// RoleCanReadTenant reports whether the resolved authz role grants tenant-wide
// (cross-user) READ access on the fleet plane: admin, owner and policy_admin
// do; every other role — including "" (least-privilege / unmapped) and any
// unknown string — reads own-rows only. Fail-closed by construction:
// NormalizeRole collapses unrecognized input to "" before the check, so no
// minting or forwarding path can smuggle an unrecognized-but-privileged role
// string past this gate.
//
// policy_admin joined the tenant-wide set in #2993: it is the "read-everything,
// change-nothing-identity" tier (tenant-wide audit/decision visibility without
// SSO/SCIM/user administration), so a per-user policy_admin token must see the
// whole tenant trail. developer and viewer stay own-rows — that own-vs-tenant
// split is the enforced distinction between them and policy_admin on the fleet
// plane (portal-plane distinctions live in the seeded role permission sets).
func RoleCanReadTenant(role string) bool {
	switch NormalizeRole(role) {
	case "admin", "owner", "policy_admin":
		return true
	default:
		return false
	}
}

// RoleIsAdministrative reports whether the resolved authz role carries
// ORG-ADMINISTRATIVE authority: admin and owner do, every other role — including
// "" (least-privilege / unmapped) and any unknown string — does not.
//
// #3001: this exists so the "owner is a strict superset of admin" guarantee
// (#2993) cannot be broken again by a literal `role == "admin"` compare. Two
// sites did exactly that, and both EXCLUDED owner, inverting the model — an
// owner received strictly LESS than an admin. Any site that wants "an org
// administrator" must ask here rather than string-compare, so adding a role to
// the administrative tier is one edit.
//
// Deliberately NOT policy_admin: that tier administers POLICIES, not the org
// (it is the read-everything, change-nothing-identity role). Widening it here
// would hand it enforcement relaxations the five-role model does not grant it.
//
// Fail-closed by construction: NormalizeRole collapses unrecognized input to ""
// before the check, so no minting or forwarding path can smuggle an
// unrecognized-but-privileged role string past this gate.
func RoleIsAdministrative(role string) bool {
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
