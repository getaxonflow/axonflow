// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Dev-mode token endpoint (#2541, design: technical-docs/AUTH_AND_IDENTITY_DESIGN.md §2/§4).
//
// POST /api/v1/dev/token mints a valid HS256 user_token (signed with the same
// JWT_SECRET the validators use) from the authenticated Basic org:license
// credential, FORCING the token's tenant_id to equal the Basic-auth username.
// This kills the "403 Tenant mismatch" first-run foot-gun: an evaluator who
// only has org + license never has to hand-mint a JWT or make tenant_id match
// the username by hand.
//
// SUPERSET claim shape (#2991). The minted token carries BOTH:
//   - the per-user FLEET claims the platform/shared/identity HS256 validator
//     requires (iss=UserTokenIssuer, sub, email, org_id, jti, exp) — so it is
//     accepted on the fleet read plane (ResolveToken) exactly like a
//     portal-minted per-user token (mirrors ee/platform/customer-portal/api/
//     user_tokens.go and the #2937 e2e superset), and
//   - the legacy body-token claims (tenant_id, role, permissions) the /decide
//     and gateway planes' validateUserToken reads.
// Each validator ignores the other plane's extra claims (validateUserToken does
// NOT pin iss; the HS256 validator ignores permissions/tenant_id). Before this,
// the token carried NEITHER iss/email/jti, so the fleet HS256 validator
// REJECTED it (401 "iss claim is required") on every /api/v1/audit/* read — the
// role claim never even reached the read-scope layer, making role-scoped reads
// undemonstrable from the dev endpoint (#2991 diagnosis).
//
// ROLE (#2991, #2). The optional request body {"role":"..."} selects the
// minted token's authz role. Absent/empty ⇒ "developer" — a canonical
// own-rows role: the historical behavior (the old hardcoded "evaluator" is not
// in the canonical role set and already normalized to own-rows), with NO
// escalation. A supplied role is validated against the canonical fleet
// vocabulary (sharedidentity.IsFleetRole: admin/owner/policy_admin/developer/
// member/viewer) and REJECTED with 400 if unknown, so this signing oracle can
// never mint an unrecognized-but-nonempty role. admin/owner IS allowed but is a
// VISIBLE, LOGGED opt-in (log.Printf below), never silent.
//
// What admin/owner grants (two consequences, both named in the loud log):
//   - tenant-wide audit READS on the fleet plane (RoleCanReadTenant), and
//   - (role=admin only) relaxed ENFORCEMENT: the /process proxy plane skips the
//     CategoryAdminAccess detector for an admin-role token (run.go, `user.Role
//     == "admin"`). So an admin dev token reused for governed traffic disables
//     admin-access DETECTION, not just reads. This is intended for admin tokens
//     generally; the point here is only that the dev endpoint can mint one, so
//     the warning must say so.
//
// "own-rows" is really "the SHARED dev-credential's rows", NOT per-person. The
// minted identity is email=<username>@dev-token.local, and on the service-
// license path username == clientID == tenant_id == the Basic org:license
// (db_auth.go:279-283). So EVERY dev token minted under one org:license shares
// that identity: two developers using the same dev credential read each other's
// dev-token-attributed rows. That is acceptable for a shared-credential dev/eval
// box (the whole point is a low-friction demo), but it is NOT per-developer
// isolation — true per-person scoping requires provisioned per-user tokens
// (Path A admin-mint / Path B OIDC), which carry a real per-person email.
//
// WHY admin is NOT the default. This endpoint is a SIGNING ORACLE behind the
// SHARED Basic org:license credential: it signs with the server-held jwtSecret,
// so the caller never needs the secret. In a multi-developer dev/staging
// deployment sharing one org:license, a default-admin token would let ANY
// developer mint themselves tenant-wide reads over every colleague's audit rows
// — exactly the cross-developer leak #2919/#2933 closes. Post-9.10.0 an
// org:license-only holder cannot otherwise reach tenant-wide reads (direct REST
// → zero rows; token-less MCP → own-rows; portal needs its own password;
// hand-mint needs JWT_SECRET), so defaulting to admin here would be a genuine
// escalation. The default therefore stays own-rows; tenant-wide is the explicit,
// logged `{"role":"admin"}` opt-in. The dev-only 404-in-prod gate does NOT by
// itself mitigate this — dev/staging is precisely where shared-credential
// multi-dev setups (and real eval data) live.
//
// FAIL-CLOSED gating (§4): the endpoint is registered ONLY when an environment
// signal is EXPLICITLY a known non-production value. Unset or unrecognized is
// treated as production and the route is NOT registered (→ 404). This is the
// deliberate INVERSE of the existing isDevOrStaging() precedent
// (ee/platform/customer-portal/api/organizations.go:1661-1664) and of
// isCommunityMode()/getDeploymentKind(), all of which fail OPEN on an unset
// value. A token minter silently live in production is a critical exposure, so
// none of those helpers are reused here.
//
// Honest scope (§4 "bounded blast radius"): service-license auth is stateless
// and accepts any caller-chosen username (db_auth.go:253-290), so this endpoint
// mints for whatever tenant *label* the caller asserts under their own
// authenticated org. It does NOT — and cannot — restrict which tenant label is
// minted; it only forces tenant_id == the username presented in that request,
// and never changes org_id (the real RLS boundary). That is exactly why it is
// dev-only.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
	logutil "axonflow/platform/shared/logger"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// devTokenTTL is the lifetime of a minted dev token. Short by design — this is
// an onboarding convenience, not a long-lived credential.
const devTokenTTL = time.Hour

// devTokenDefaultRole is the role a dev token carries when the request body
// supplies none. "developer" is a canonical own-rows role (NOT tenant-wide),
// preserving the pre-#2991 own-rows behavior with no escalation.
const devTokenDefaultRole = "developer"

// devTokenEmailDomain is the domain of the identity stamped into the minted
// token's email/sub claims. It is deliberately NOT a reserved platform domain
// (@axonflow.local / @axonflow.internal) so the resulting identity is a real
// (non-synthetic) own-rows key — sharedidentity.IsSharedSyntheticIdentity must
// NOT match it, or a developer-role read would fail closed to zero rows instead
// of scoping to own-rows.
//
// This is NOT a per-person identity. The local-part is the Basic-auth username
// (== clientID == tenant_id, db_auth.go:279-283), which is the SHARED
// org:license credential — so every dev token minted under one credential
// carries the SAME email. A developer-role dev token therefore scopes to the
// shared dev-credential's rows, not to one person's; see the file header. True
// per-person isolation needs a provisioned per-user token (Path A/B).
const devTokenEmailDomain = "dev-token.local"

// devTokenEnvAllowlist is the set of EXPLICIT, recognized non-production values
// accepted from ENVIRONMENT / DEPLOYMENT_KIND (the pinned set from the design
// doc §4). Anything not in this set (including the empty string) is treated as
// production.
var devTokenEnvAllowlist = map[string]bool{
	"development": true,
	"dev":         true,
	"staging":     true,
	"local":       true,
}

// isExplicitNonProd reports whether v is an explicit, recognized non-production
// environment token. The empty string and unrecognized values return false
// (fail closed).
func isExplicitNonProd(v string) bool {
	return devTokenEnvAllowlist[strings.ToLower(strings.TrimSpace(v))]
}

// devTokenEndpointEnabled reports whether the dev-mode token endpoint may be
// registered. FAIL-CLOSED: returns true ONLY when at least one environment
// signal is EXPLICITLY a known non-production value. All-unset ⇒ false
// (production). See the file header for why the fail-open isCommunityMode() /
// getDeploymentKind() / isDevOrStaging() helpers are intentionally NOT used.
//
// Recognized explicit non-prod signals (any one suffices):
//   - ENVIRONMENT      ∈ {development, dev, staging, local, test}
//   - DEPLOYMENT_MODE  == "community"   (an explicit local-dev/eval mode)
//   - DEPLOYMENT_KIND  ∈ {development, dev, staging, local, test}
//
// ENVIRONMENT=production, DEPLOYMENT_KIND=production, and every unset/unknown
// combination return false.
func devTokenEndpointEnabled() bool {
	if isExplicitNonProd(os.Getenv("ENVIRONMENT")) {
		return true
	}
	// DEPLOYMENT_MODE=community is an explicit signal; check the raw env value,
	// NOT isCommunityMode(), because that helper also returns true on UNSET.
	if strings.ToLower(strings.TrimSpace(os.Getenv("DEPLOYMENT_MODE"))) == "community" {
		return true
	}
	// DEPLOYMENT_KIND: check the raw env value, NOT getDeploymentKind(), which
	// defaults UNSET → "dev" (fail open).
	if isExplicitNonProd(os.Getenv("DEPLOYMENT_KIND")) {
		return true
	}
	return false
}

// RegisterDevTokenHandler registers POST /api/v1/dev/token behind
// apiAuthMiddleware (Basic org:license auth) — but ONLY when
// devTokenEndpointEnabled() is true. When it is not, the route is left
// unregistered so the router returns 404, and the production stance is logged.
func RegisterDevTokenHandler(router *mux.Router) {
	if !devTokenEndpointEnabled() {
		log.Println("🔒 dev-mode token endpoint NOT registered — no explicit non-prod ENVIRONMENT/DEPLOYMENT_MODE/DEPLOYMENT_KIND (fail-closed). POST /api/v1/dev/token → 404")
		return
	}
	router.Handle("/api/v1/dev/token", apiAuthMiddleware(http.HandlerFunc(devTokenHandler))).Methods("POST")
	log.Println("⚠️  DEV-ONLY: POST /api/v1/dev/token ENABLED (explicit non-production environment) — mints HS256 user_tokens from the Basic credential. MUST NOT be reachable in production.")
}

// devTokenRequest is the optional JSON request body. A missing/empty body mints
// a default developer-role token; role selects a different canonical role.
type devTokenRequest struct {
	Role string `json:"role"`
}

// resolveDevTokenRole reads the optional role from the request body and returns
// the resolved canonical role, or a 400 message + false when the supplied role
// is unrecognized. An absent/empty role resolves to devTokenDefaultRole. A
// malformed non-empty body is a validation error so a caller is never silently
// downgraded to the default by a typo'd payload.
func resolveDevTokenRole(r *http.Request) (role string, badRequestMsg string, ok bool) {
	role = devTokenDefaultRole
	if r.Body == nil {
		return role, "", true
	}
	var body devTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		if errors.Is(err, io.EOF) {
			return role, "", true // empty body → default
		}
		return "", `invalid request body: expected optional JSON {"role":"..."}`, false
	}
	requested := strings.ToLower(strings.TrimSpace(body.Role))
	if requested == "" {
		return role, "", true
	}
	if !sharedidentity.IsFleetRole(requested) {
		return "", fmt.Sprintf("invalid role %q; valid roles: %s", requested, strings.Join(sortedFleetRoleNames(), ", ")), false
	}
	return requested, "", true
}

// sortedFleetRoleNames returns the canonical fleet roles in a stable (sorted)
// order for deterministic error messages.
func sortedFleetRoleNames() []string {
	names := sharedidentity.FleetRoleNames()
	sort.Strings(names)
	return names
}

// devTokenHandler mints an HS256 user_token for the authenticated caller.
// It runs behind apiAuthMiddleware, so the Basic org:license credential has
// already been validated and the identity is in the request context.
func devTokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Refuse the internal-service auth kind. This endpoint mints onboarding
	// identities for a human evaluator using their OWN Basic org:license
	// credential, where org_id is strictly credential-derived. On the
	// internal-service path, Authenticate() lifts OrgID from the
	// caller-supplied X-Org-ID header (authenticator.go:132-135), which would
	// let an internal-secret holder mint a portable token for an ARBITRARY
	// org_id — breaking this endpoint's "tenant_id forced, org_id never
	// changed" invariant. Internal services have no need to mint onboarding
	// tokens. (R3 round 2.)
	if AuthKindFromContext(ctx) == AuthKindInternalService {
		writeJSONError(w, "dev-token endpoint is not available to internal-service callers", http.StatusForbidden)
		return
	}

	// Resolve the requested role BEFORE touching auth state so a bad body is a
	// clean 400. Unknown role ⇒ 400 (fail-closed: never mint an unrecognized
	// role); absent ⇒ developer (own-rows).
	role, badMsg, ok := resolveDevTokenRole(r)
	if !ok {
		writeJSONError(w, badMsg, http.StatusBadRequest)
		return
	}

	// The Basic-auth username is the client/tenant identity on the
	// service-license path (db_auth.go:278-290: TenantID == ClientID == username).
	username := ClientIDFromContext(ctx)
	if username == "" {
		username = TenantIDFromContext(ctx) // canonical fallback; same value
	}
	orgID := OrgIDFromContext(ctx)
	if username == "" || orgID == "" {
		// apiAuthMiddleware should have populated both; treat absence as unauthenticated.
		writeJSONError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	// Fail loudly rather than mint a token signed with an empty key.
	if len(jwtSecret) == 0 {
		log.Println("[dev/token] JWT_SECRET is not configured — refusing to mint")
		writeJSONError(w, "JWT_SECRET not configured on this deployment; cannot mint dev token", http.StatusServiceUnavailable)
		return
	}

	// A tenant-wide-read role (admin/owner) is a genuine escalation for a signing
	// oracle behind the shared org:license credential. Allowed, but NEVER silent:
	// emit a loud, auditable line naming the grant + the dev-only gate.
	// (Non-tenant-wide roles are the quiet default path.) Gate on the SAME
	// predicate the read layer uses to grant tenant-wide reads
	// (sharedidentity.RoleCanReadTenant) rather than a hardcoded admin/owner
	// list, so a future tenant-wide role can never be minted WITHOUT this log —
	// the codebase's "never copy this predicate into a second site" discipline.
	if sharedidentity.RoleCanReadTenant(role) {
		log.Printf("⚠️  DEV-ONLY ORACLE: minted a TENANT-WIDE %q dev token for org=%s tenant=%s — it grants cross-user audit READS over the WHOLE tenant, and (for role=admin) ALSO relaxes ENFORCEMENT: the /process plane skips the CategoryAdminAccess detector for admin-role traffic. Gated to non-production; if you see this in prod, treat it as a critical exposure.",
			role, logutil.Sanitize(orgID), logutil.Sanitize(username))
	}

	now := time.Now().UTC().Truncate(time.Second)
	// Per-caller identity for own-rows attribution + the fleet validator's
	// required non-empty email/sub. Non-reserved domain so it is NOT treated as
	// a shared synthetic identity (which would fail-close a developer read to
	// zero rows). The fleet validator canonicalizes (lower+trim) before use.
	email := strings.TrimSpace(username) + "@" + devTokenEmailDomain
	// SUPERSET claims (see file header): fleet claims (iss/sub/email/org_id/jti/
	// exp) so ResolveToken accepts it, PLUS legacy claims (tenant_id/role/
	// permissions) so validateUserToken accepts it. tenant_id is FORCED to the
	// authenticated username — the request body cannot influence it. org_id is
	// fixed to the authenticated org (the RLS boundary the fleet validator
	// matches on). nbf is backdated so the no-leeway legacy validator never
	// rejects a just-minted token on clock skew.
	//
	// NB (coupling introduced by jti): a jti makes this token revocable, but it
	// also means that when the token is reused for ENFORCEMENT traffic
	// (/process → validateUserToken → checkUserTokenRevoked) its acceptance now
	// depends on the revocation store: fail-closed on a store error, no-op when
	// the store is unwired (community / no enterprise revocations). Dev-only and
	// low-impact, but worth naming.
	claims := jwt.MapClaims{
		"iss":         sharedidentity.UserTokenIssuer,
		"sub":         email,
		"email":       email,
		"role":        role,
		"org_id":      orgID,
		"tenant_id":   username,
		"permissions": []string{"query", "llm", "mcp_query"},
		"jti":         uuid.NewString(),
		"iat":         now.Unix(),
		"nbf":         now.Add(-60 * time.Second).Unix(),
		"exp":         now.Add(devTokenTTL).Unix(),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
	if err != nil {
		log.Printf("[dev/token] signing failed: %v", err)
		writeJSONError(w, "token minting failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"user_token": signed,
		"tenant_id":  username,
		"org_id":     orgID,
		"role":       role,
		"email":      email,
		"expires_in": int(devTokenTTL.Seconds()),
	}); err != nil {
		log.Printf("[dev/token] encode failed: %v", err)
	}
}
