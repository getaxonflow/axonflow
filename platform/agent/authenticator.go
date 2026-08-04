// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"fmt"
	"log"
	"net/http"
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

	// Segments carries the resolved ADR-060 (#2989) governance-segment set
	// for a per-user validated identity on the enterprise fleet/MCP-server
	// plane (populated only after a per-user token validates via Path A
	// HS256 or Path B OIDC — see authenticateMCPServerRequest in
	// mcp_server_handler.go). nil for every other auth kind/path: community,
	// no per-user token presented, or the identity attribute resolver is
	// unavailable. Threaded here purely for observability/downstream
	// wiring (mcpSession.userSegments, request context) — still NOT consumed
	// for any policy decision on the MCP-server plane (that stays P3b/#3052
	// scope, orchestrator-adjacent). #3051 (ADR-060 P3) instead promotes
	// segment resolution to policy-affecting on the agent STATIC-policy
	// proxy plane (clientRequestHandler / tierAwarePolicyEngine, run.go) via
	// its own resolution call (resolveSegmentsForPolicy, segment_policy_gate.go)
	// — a separate resolve, not a read of this field, since this field is
	// populated only on the MCP-server session-auth path, not the proxy
	// plane's Basic-Auth+user_token path.
	Segments []sharedidentity.Segment
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

			// Internal service org: read from X-Org-ID header set by the proxy
			// middleware when forwarding requests. This is trusted because internal
			// service auth already proved the caller is the orchestrator via HMAC.
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
			ID:          0,
			Email:       "orchestrator@axonflow.internal",
			Name:        "Orchestrator Internal",
			TenantID:    auth.TenantID,
			Role:        "service",
			Permissions: []string{"query", "execute", "mcp"},
		}, nil

	case AuthKindEnterprise:
		user, err := validateUserToken(userToken, auth.TenantID)
		if err != nil {
			return nil, &AuthError{
				Code:       "invalid_user_token",
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
