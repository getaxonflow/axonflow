// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Dev-mode token endpoint (#2541, design: technical-docs/AUTH_AND_IDENTITY_DESIGN.md §2/§4).
//
// POST /api/v1/dev/token mints a valid HS256 user_token (signed with the same
// JWT_SECRET the validator uses) from the authenticated Basic org:license
// credential, FORCING the token's tenant_id to equal the Basic-auth username.
// This kills the "403 Tenant mismatch" first-run foot-gun: an evaluator who
// only has org + license never has to hand-mint a JWT or make tenant_id match
// the username by hand.
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
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

// devTokenTTL is the lifetime of a minted dev token. Short by design — this is
// an onboarding convenience, not a long-lived credential.
const devTokenTTL = time.Hour

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

	now := time.Now()
	// tenant_id is FORCED to the authenticated username — the request body
	// cannot influence it. org_id is fixed to the authenticated org. Claim
	// shape mirrors scripts/generate-jwt.sh so the validator parses it
	// unchanged.
	claims := jwt.MapClaims{
		"tenant_id":   username,
		"org_id":      orgID,
		"role":        "evaluator",
		"permissions": []string{"query", "llm", "mcp_query"},
		"iat":         now.Unix(),
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
		"expires_in": int(devTokenTTL.Seconds()),
	}); err != nil {
		log.Printf("[dev/token] encode failed: %v", err)
	}
}
