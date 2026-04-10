// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	serviceauth "axonflow/platform/shared/serviceauth"
	logutil "axonflow/platform/shared/logger"
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
		if serviceauth.IsValidInternalServiceRequest(hints.ClientID, hints.UserToken, internalTokenValidator) {
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
					Name:        "Orchestrator Internal",
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

		return &AuthResult{
			Kind:     AuthKindCommunitySaaS,
			Client:   client,
			TenantID: client.TenantID,
			OrgID:    client.OrgID,
			ClientID: client.ID,
		}, nil
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

	return &AuthResult{
		Kind:     AuthKindEnterprise,
		Client:   client,
		TenantID: client.TenantID,
		OrgID:    client.OrgID,
		ClientID: client.ID,
	}, nil
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
