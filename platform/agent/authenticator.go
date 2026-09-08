// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"axonflow/platform/agent/license/admission"
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
	logutil "axonflow/platform/shared/logger"
	serviceauth "axonflow/platform/shared/serviceauth"
)

// =============================================================================
// Unified Authenticator — single entry point for all request authentication
// =============================================================================
//
// Every handler and middleware calls Authenticate() instead of duplicating
// mode-switching logic. This function NEVER writes to http.ResponseWriter —
// callers translate *AuthError into their own wire format (REST JSON,
// JSON-RPC, proxy, etc.).
//
// Auth mode is determined by deployment config (DEPLOYMENT_MODE env var),
// NOT by caller preferences or body fields. Body fields (via AuthHints)
// are used ONLY for internal service detection.
//
// Hard invariant: headers/credentials establish canonical identity.
// Body client_id/tenant_id can only MATCH the canonical identity or be
// empty — they never override it. Handlers enforce mismatch rejection.

// AuthKind identifies how the request was authenticated.
type AuthKind int

const (
	// AuthKindCommunity — DEPLOYMENT_MODE=community or "" (no credentials required).
	AuthKindCommunity AuthKind = iota
	// AuthKindCommunitySaaS — DEPLOYMENT_MODE=community-saas (bcrypt registration credentials).
	AuthKindCommunitySaaS
	// AuthKindEnterprise — default mode (Ed25519 license key via Basic auth).
	AuthKindEnterprise
	// AuthKindInternalService — orchestrator-to-agent routing (HMAC-signed tokens).
	AuthKindInternalService
)

// String returns a human-readable label for the auth kind.
func (k AuthKind) String() string {
	switch k {
	case AuthKindCommunity:
		return "community"
	case AuthKindCommunitySaaS:
		return "community-saas"
	case AuthKindEnterprise:
		return "enterprise"
	case AuthKindInternalService:
		return "internal-service"
	default:
		return "unknown"
	}
}

// AuthHints carries credentials parsed from request body fields.
// These are NARROW and EXPLICIT — only fields that MCP handlers extract
// from parsed JSON bodies for internal service detection.
//
// Auth mode is ALWAYS determined by deployment config + credentials +
// internal-service proof, never by caller preference.
//
// Passing nil hints is safe and means "header-only auth" — internal
// service detection is skipped (body fields are empty).
type AuthHints struct {
	ClientID  string // from req.ClientID (body field, for internal service detection)
	UserToken string // from req.UserToken (body field, for internal service HMAC)
	TenantID  string // from req.TenantID (body field, for internal service routing)
}

// AuthResult is the outcome of a successful authentication.
// TenantID/OrgID/ClientID are the canonical identity derived from
// credentials — never from body fields.
type AuthResult struct {
	Kind     AuthKind
	Client   *Client
	TenantID string // canonical tenant (from credentials, never from body)
	OrgID    string // canonical org (from license or deployment)
	ClientID string // canonical client ID (from credentials)
	// Synthetic marks a request driven by AxonFlow's own observation-window
	// canary (#3602). It reaches the ADR-065 counterfactual as a metric label
	// and NOTHING else: it is never an authorization input, never consulted by
	// realm verification, and never reaches an audit attribution field.
	//
	// It is carried on the AuthResult rather than re-read at each recording
	// site because only THIS function sees the request for the client-
	// credential and per-user-token paths - ResolveUser and
	// adaptedValidateUserToken have no *http.Request, deliberately. See
	// sharedidentity.LegacyAuth.Synthetic for why a caller-assertable header
	// is an acceptable channel for this one fact.
	Synthetic bool
}

// AuthError is protocol-neutral — callers translate to their wire format.
// REST handlers render JSON, MCP JSON-RPC renders jsonrpc error objects,
// proxy writes raw JSON.
type AuthError struct {
	Code       string // machine-readable: "missing_credentials", "invalid_credentials", "rate_limited", "client_disabled"
	Message    string // human-readable error message
	HTTPStatus int    // suggested HTTP status code
	RetryAfter string // non-empty → rate limited, caller should set Retry-After header
}

func (e *AuthError) Error() string { return e.Message }

// Authenticate is the single entry point for request authentication.
// It NEVER writes to http.ResponseWriter.
//
// Parameters:
//   - r: the HTTP request (reads Authorization header for Basic auth)
//   - hints: optional body-field credentials for internal service detection (nil for header-only auth)
//
// The function checks modes in this order:
//  1. Internal service (only when hints non-nil) → HMAC token validation (checked first in ALL modes)
//  2. Community mode → no auth required, default client
//  3. Community-SaaS mode → bcrypt validation, rate limits
//  4. Enterprise → Ed25519 license key via Basic auth
func Authenticate(r *http.Request, hints *AuthHints) (*AuthResult, *AuthError) {
	auth, authErr := authenticateLegacy(r, hints)

	// ADR-065 identity compatibility adapter (#3550). It runs HERE, wrapping
	// the whole legacy decision, rather than at any of the callers: every
	// handler, middleware and proxy in this package reaches client-credential
	// authentication through this function, so wiring it here covers all of
	// them and one added tomorrow.
	//
	// A FAILED authentication is deliberately not adapted. There is no
	// authenticated organization on that path, and the identity plane is
	// organization-scoped by construction - a realm lookup with no org is not
	// a refusal to record, it is a question that cannot be asked. Attributing
	// the attempt to the deployment's own org would be worse: it would file
	// another tenant's failed credential under ours.
	//
	// Under the default mode (off) Resolve returns before reading a clock or
	// touching the registry, so this is one nil-pointer comparison.
	if auth != nil && authErr == nil {
		// Stamped BEFORE the adapter runs, on the one function every
		// client-credential path traverses, so both the client-credential
		// counterfactual below and the per-user-token one further down
		// (ResolveUser -> adaptedValidateUserToken) describe the same request
		// consistently. A request tagged on one path and not the other would
		// make the synthetic split unreadable.
		//
		// IT IS NOT GATED ON THE MODE, AND THAT IS DELIBERATE. Under mode off
		// this costs one header lookup and a two-element membership test per
		// authenticated request, and Resolve below still returns before it
		// reads a clock, touches the registry, or calls a recorder - so the
		// flag-off guarantee that matters (no behaviour change, nothing
		// recorded, nothing exported) is unaffected, and
		// TestModeOffIncrementsNoMetric pins it.
		//
		// Gating it would be worse than the lookup it saves: the only way to
		// ask "is the adapter evaluating" here is to read the mode, and
		// compat.go's structural invariant is that the mode is read in exactly
		// ONE function (effectiveMode). TestCompatModeIsConsultedAtExactlyOneSite
		// walks the AST and fails on a second reader. A cheap optimisation is
		// not worth reintroducing the shape that whole invariant exists to
		// prevent.
		auth.Synthetic = sharedidentity.IsSyntheticProbeHeader(
			r.Header.Get(sharedidentity.SyntheticProbeHeader))
	}
	if legacy, adaptable := authResultLegacyAuth(auth, time.Now()); adaptable && authErr == nil {
		if ref := sharedidentity.CompatResolve(r.Context(), legacy).Refusal(); ref != nil {
			return nil, compatAuthError(ref)
		}
	}
	// Tier scale limit (#3593): the authenticated client is a SERVICE
	// PRINCIPAL of its organization, admitted here - on the one function every
	// client-credential path traverses, for the same reason the adapter above
	// is here - against the signed licence's ceiling. An internal-service call
	// is the orchestrator calling back, not a principal. A refusal is a 402
	// with its own code (admission.HTTPStatus / ERR_TIER_LIMIT_SERVICE_PRINCIPAL),
	// never a 401: the credential was VALID.
	if auth != nil && authErr == nil && auth.Kind != AuthKindInternalService {
		if refusal := admitPrincipal(r.Context(), admission.ServicePrincipal, auth.OrgID, auth.ClientID); refusal != nil {
			return nil, refusal.AuthError()
		}
	}
	return auth, authErr
}

// authenticateLegacy is the unchanged legacy authentication. Every semantic
// below is what Authenticate has always done; the split exists so the identity
// adapter has exactly one place to wrap, and so a future edit to a branch here
// cannot bypass it.
func authenticateLegacy(r *http.Request, hints *AuthHints) (*AuthResult, *AuthError) {
	// 1. Internal service detection — checked FIRST in all modes.
	// The orchestrator calls back to agent MCP handlers with HMAC-signed body
	// fields. This must be checked before mode-specific auth because the
	// orchestrator doesn't have community-saas bcrypt credentials or enterprise
	// license keys — it uses its own HMAC token for authentication.
	if hints != nil && hints.ClientID != "" && hints.UserToken != "" {
		// Allow the static fallback token only in Community / Community-SaaS deployments,
		// where shipping with no shared secret is part of the dev experience. Enterprise
		// deployments must always validate against a configured HMAC secret — otherwise
		// the literal TokenFallback could be used to impersonate the orchestrator.
		allowFallback := isCommunityMode() || isCommunitySaasMode()
		if serviceauth.IsValidInternalServiceRequest(hints.ClientID, hints.UserToken, internalTokenValidator, allowFallback) {
			tenantID := hints.TenantID
			if tenantID == "" {
				tenantID = hints.ClientID
			}

			// Internal service org: read from the X-Org-ID header an internal
			// caller sets when forwarding.
			//
			// AN EARLIER VERSION OF THIS COMMENT SAID "trusted because internal
			// service auth already proved the caller is the orchestrator via
			// HMAC". That is true on an ENTERPRISE deployment and false on
			// community / community-SaaS, where `allowFallback` above is true and
			// the branch accepts the PUBLIC fallback constants when no
			// AXONFLOW_INTERNAL_SERVICE_SECRET is configured. Corrected here
			// because this is the line that actually reads the header, and it was
			// being cited as the authority for the claim (R3 round 3, H4).
			//
			// What the value can and cannot do is traced once, on ResolveUser's
			// internal-service arm below. Do not restate it here: three revisions
			// of a short summary were wrong in three different ways.
			orgID := r.Header.Get("X-Org-ID")

			return &AuthResult{
				Kind: AuthKindInternalService,
				Client: &Client{
					ID:          serviceauth.ClientID,
					ClientID:    serviceauth.ClientID,
					Name:        "Orchestrator Internal",
					OrgID:       orgID,
					TenantID:    tenantID,
					Permissions: []string{"query", "execute", "mcp"},
					Enabled:     true,
				},
				TenantID: tenantID,
				OrgID:    orgID,
				ClientID: serviceauth.ClientID,
			}, nil
		}
		// Invalid HMAC falls through to mode-specific auth (not an error by itself —
		// the body fields may just happen to be present in a normal client request)
	}

	// 2. Community mode: no credentials required
	if isCommunityMode() {
		clientID := extractClientID(r)
		if clientID == "" && hints != nil && hints.ClientID != "" {
			clientID = hints.ClientID
		}
		if clientID == "" {
			clientID = "community"
		}

		return &AuthResult{
			Kind: AuthKindCommunity,
			Client: &Client{
				ID:          clientID,
				ClientID:    clientID, // v9 ADR-052
				Name:        "Community",
				OrgID:       getDeploymentOrgID(),
				TenantID:    clientID,
				Enabled:     true,
				LicenseTier: "Community",
			},
			TenantID: clientID,
			OrgID:    getDeploymentOrgID(),
			ClientID: clientID,
		}, nil
	}

	// 3. Community-SaaS mode: bcrypt validation from registration table
	if isCommunitySaasMode() {
		client, csErr := validateCommunitySaasAuth(r)
		if csErr != nil {
			retryAfter := ""
			if csErr.RetryAfter != "" {
				retryAfter = csErr.RetryAfter
			}
			code := "invalid_credentials"
			if csErr.StatusCode == http.StatusTooManyRequests {
				code = "rate_limited"
			} else if csErr.StatusCode == http.StatusUnauthorized && csErr.Message == "Registration required. POST to /api/v1/register to get credentials." {
				code = "missing_credentials"
			}
			return nil, &AuthError{
				Code:       code,
				Message:    csErr.Message,
				HTTPStatus: csErr.StatusCode,
				RetryAfter: retryAfter,
			}
		}

		return buildAuthResult(AuthKindCommunitySaaS, client), nil
	}

	// 4. Enterprise mode: Basic auth with Ed25519 license key
	clientID := extractClientID(r)
	clientSecret := extractClientSecret(r)

	if clientID == "" || clientSecret == "" {
		return nil, &AuthError{
			Code:       "missing_credentials",
			Message:    "Authentication required: provide Authorization header with Basic auth (clientId:clientSecret)",
			HTTPStatus: http.StatusUnauthorized,
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var client *Client
	var err error
	if authDB != nil {
		client, err = validateClientCredentialsDB(ctx, authDB, clientID, clientSecret)
	} else {
		client, err = validateClientCredentials(ctx, clientID, clientSecret)
	}
	if err != nil {
		log.Printf("[AUTH] Enterprise auth failed for client '%s': %v",
			logutil.Sanitize(clientID), err)
		return nil, &AuthError{
			Code:       "invalid_credentials",
			Message:    "Authentication failed: " + err.Error(),
			HTTPStatus: http.StatusUnauthorized,
		}
	}

	if !client.Enabled {
		return nil, &AuthError{
			Code:       "client_disabled",
			Message:    fmt.Sprintf("Client '%s' is disabled", clientID),
			HTTPStatus: http.StatusForbidden,
		}
	}

	return buildAuthResult(AuthKindEnterprise, client), nil
}

// buildAuthResult is the canonical Client → AuthResult field mapping for
// both the CommunitySaaS and Enterprise auth branches.
//
// ADR-052 §5: AuthResult.ClientID is the credential identity (api_key_id
// for API-keyed callers post Fix 4 of PR #2309). For community-saas +
// organization-license paths client.ID == client.ClientID, so this is a
// no-op there. For the validateViaAPIKeys path the two diverge and
// AuthResult.ClientID MUST surface client.ClientID — downstream consumers
// (mcpSession.clientID, X-Client-ID forwarding, BasicAuth username,
// rate-limiter buckets, audit_logs.client_id, usage_events.client_id,
// ContextKeyClientID) all read auth.ClientID, not client.ClientID
// directly. See feedback_client_id_propagation_through_authresult.md.
//
// Extracted from inline field-mapping at both auth branches so a single
// unit test can mutation-prove the invariant for both kinds without
// having to drive validateCommunitySaasAuth + validateViaAPIKeys
// through DB mocks (R3 finding F1-B on PR #2309).
func buildAuthResult(kind AuthKind, client *Client) *AuthResult {
	return &AuthResult{
		Kind:     kind,
		Client:   client,
		TenantID: client.TenantID,
		OrgID:    client.OrgID,
		ClientID: client.ClientID,
	}
}

// ResolveUser resolves user identity from a token or synthesizes a default user
// based on the auth kind. This is separate from Authenticate — handlers that
// need a *User call this after authentication.
//
// Parameters:
//   - auth: the result from Authenticate()
//   - userToken: the raw user token string (JWT in enterprise, ignored in community)
//
// Returns a *User on success, or *AuthError if token validation fails.
func ResolveUser(auth *AuthResult, userToken string) (*User, *AuthError) {
	switch auth.Kind {
	case AuthKindCommunity:
		return &User{
			ID:          1,
			Email:       "local-dev@axonflow.local",
			Name:        "Local Development User",
			TenantID:    auth.TenantID,
			Role:        "admin",
			Permissions: []string{"query", "llm", "mcp_query", "admin"},
		}, nil

	case AuthKindCommunitySaaS:
		return &User{
			ID:          1,
			Email:       "evaluator@try.getaxonflow.com",
			Name:        "Evaluation User",
			TenantID:    auth.TenantID,
			Role:        "evaluator",
			Permissions: []string{"query", "llm", "mcp_query"},
		}, nil

	case AuthKindInternalService:
		return &User{
			ID:    0,
			Email: "orchestrator@axonflow.internal",
			Name:  "Orchestrator Internal",
			// THE ORGANIZATION IS CARRIED, AND IT USED NOT TO BE (#3828).
			//
			// auth.OrgID on this branch is the X-Org-ID the orchestrator sent.
			// Dropping it here meant the value
			// arrived, was authenticated, and then went nowhere: the MCP call
			// sites read user.OrgID, so they evaluated with an empty
			// organization, OrgScopePtr("") returned nil, orgScopeOf fell back
			// to the tenant id, and the decision shadow refused every `mcp`
			// observation as "an org scope but no org id".
			//
			// Setting it makes two per-organization levers reach this path for
			// the first time - the detection posture (ResolveMCPDetectionConfig)
			// and the per-org policy scope - which is a behaviour change and is
			// stated as one on the PR. It is the correct direction: an
			// orchestrator-routed MCP query is served for a real organization,
			// and resolving it as though it had none is what made a per-org
			// override silently not apply.
			//
			// The three sibling arms are deliberately unchanged. Community and
			// community-SaaS synthesize a user for a deployment that has one
			// organization, and the enterprise arm resolves its own from a
			// verified token; neither is on the traced path, and widening this
			// to them would move per-org resolution on every plane at once.
			//
			// # HOW FAR THE "IT IS AUTHENTICATED" ARGUMENT ACTUALLY GOES
			//
			// R3 round 1 (finding F11) is right that an earlier revision of this
			// comment overstated it. It said X-Org-ID is "trusted because
			// IsValidInternalServiceRequest already proved the caller holds the
			// shared secret", and that is true ON AN ENTERPRISE DEPLOYMENT and
			// NOT on community or community-SaaS: there `allowFallback` is true,
			// so the branch accepts the PUBLIC fallback constants when no
			// AXONFLOW_INTERNAL_SERVICE_SECRET is configured. On such a
			// deployment anything that can reach the agent can take this branch
			// and name its own org.
			//
			// What that buys is bounded. Two earlier revisions of this comment
			// got the bound wrong in opposite directions, so the correct version
			// is stated with its trace rather than asserted.
			//
			// R3 round 2 (G14) removed two claims that were FALSE in the very
			// mode they excused - "a community deployment has ONE organization"
			// (community-SaaS mints a cs_<uuid> org per registration) and a
			// rebuttal naming the decision-shadow store instead of this lever.
			//
			// R3 round 3 (H2, H3) then found the replacement had two more:
			//
			//   - "no admission decision reads it" is FALSE, and the mechanism is
			//     conceded 15 lines above. The chain is real and short:
			//     user.OrgID -> ResolveMCPDetectionConfig ->
			//     applyOrgDetectionOverrides (detection_override.go:315) ->
			//     ModeDetectionConfig -> BuildActionOverrides() ->
			//     EvalOptions.ActionOverrides (mcp_handler.go:962) ->
			//     out.StaticResult.Blocked. A per-org posture row CAN flip an
			//     action to block. Selecting an org therefore selects a verdict.
			//   - the "what is not established" paragraph greped
			//     `org_detection_overrides`, which does not exist: one hit
			//     repo-wide, in that comment. The real table is
			//     `detection_action_overrides`, and under its real name the
			//     guards surface at once.
			//
			// SO, THE ACTUAL BOUND:
			//
			//   - WRITING a posture row is well guarded, and by two independent
			//     mechanisms. ee/platform/customer-portal/posture/posture.go
			//     mounts it on the session-authenticated router behind
			//     `sso:configure`, taking the org from the session and NEVER from
			//     a header, body or path; and migration 120 puts
			//     detection_action_overrides under FORCE ROW LEVEL SECURITY with
			//     a WITH CHECK on `app.current_org_id`, so a write for the wrong
			//     org is refused at the database even if a bug got it that far.
			//   - READING one is what this branch can influence, and only by
			//     naming an org. On a secretless community deployment a caller
			//     taking this branch can select which org's posture applies to
			//     ITS OWN request - which can make its own request stricter or
			//     laxer than the deployment default.
			//   - the same caller already controls `tenant_id` here, through
			//     hints.TenantID, and has since this branch existed - and
			//     TenantID is the selector the policy LOAD keys on. So the
			//     organization is a second selector beside one that was always
			//     there, not a new class of control.
			//
			// That last point is why this is a MEDIUM and not a stop: the branch
			// was already trusting this caller for tenancy. It is NOT why it is
			// harmless, and the honest summary is that a secretless community
			// deployment lets a caller choose the posture applied to its own
			// traffic. Whether the fallback should exist at all on a deployment
			// with a database is a question for the auth lane, not this change.
			//
			// This change does not create any of that: it stops DISCARDING a
			// value the branch already authenticated. The comment is corrected
			// rather than the code.
			OrgID:       auth.OrgID,
			TenantID:    auth.TenantID,
			Role:        "service",
			Permissions: []string{"query", "execute", "mcp"},
		}, nil

	case AuthKindEnterprise:
		// The HS256 path's single production entry point, which is where the
		// ADR-065 compat adapter lives (#3550). It is NOT here, because
		// validateUserToken has a second production caller
		// (resolveAuditReadAuthority) and a guard at one of two callers is not
		// a guard. See adaptedValidateUserToken.
		user, err := adaptedValidateUserToken(auth.OrgID, userToken, auth.TenantID, auth.Synthetic)
		if err != nil {
			// A tier-limit refusal (#3593) is not an invalid token: the token
			// VERIFIED and the principal was refused by the licence's ceiling.
			// It carries its own code and a 402, never this branch's 401.
			if ref, ok := asTierLimitRefusal(err); ok {
				return nil, ref.AuthError()
			}
			// An identity-plane refusal carries its own code so it is
			// distinguishable from a tampered or expired token, which share
			// this branch. See CompatRefusalCode.
			code := "invalid_user_token"
			if strings.HasPrefix(err.Error(), sharedidentity.CompatRefusalCode+":") {
				code = sharedidentity.CompatRefusalCode
			}
			return nil, &AuthError{
				Code:       code,
				Message:    fmt.Sprintf("Invalid user token: %v", err),
				HTTPStatus: http.StatusUnauthorized,
			}
		}
		return user, nil

	default:
		return nil, &AuthError{
			Code:       "unknown_auth_kind",
			Message:    "Unknown authentication kind",
			HTTPStatus: http.StatusInternalServerError,
		}
	}
}
