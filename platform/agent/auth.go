// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"axonflow/platform/agent/license"
	logutil "axonflow/platform/shared/logger"
)

// ClientAuth represents authentication configuration for a known client.
// This structure holds the client's credentials, permissions, and rate limits.
// In production, client configurations should be loaded from the database
// via db_auth.go rather than using the in-memory whitelist.
//
// Fields:
//   - ClientID: Unique identifier for the client
//   - LicenseKey: Ed25519-signed license key (AXON-{payload}.{signature})
//   - Name: Human-readable client name
//   - TenantID: Tenant for multi-tenant isolation
//   - Permissions: List of allowed operations (query, llm, connectors, planning)
//   - RateLimit: Maximum requests per minute
//   - Enabled: Whether the client is active
type ClientAuth struct {
	ClientID    string
	LicenseKey  string
	Name        string
	TenantID    string
	Permissions []string
	RateLimit   int // requests per minute
	Enabled     bool
}

// RateLimitEntry tracks request counts for in-memory rate limiting.
// Each client has an entry that tracks requests within a sliding window.
// When the window expires (1 minute), the counter resets.
type RateLimitEntry struct {
	Count     int
	ResetTime time.Time
	mu        sync.Mutex
}

// Known clients whitelist with their Ed25519-signed license keys.
// In production, this should be loaded from database or config file.
var knownClients = map[string]*ClientAuth{
	"healthcare-demo": {
		ClientID:    "healthcare-demo",
		LicenseKey:  "AXON-eyJ0aWVyIjoiRW50ZXJwcmlzZSIsInRlbmFudF9pZCI6ImhlYWx0aGNhcmUiLCJzZXJ2aWNlX25hbWUiOiJwbGF0Zm9ybSIsInNlcnZpY2VfdHlwZSI6ImJhY2tlbmQtc2VydmljZSIsInBlcm1pc3Npb25zIjpbInF1ZXJ5IiwibGxtIiwiY29ubmVjdG9ycyIsInBsYW5uaW5nIl0sImlzc3VlZF9hdCI6IjIwMjYwMjI2IiwiZXhwaXJlc19hdCI6IjIwMzYwMjI0In0.cEmmt3O6bFgaGJks54nedMa4fu4qqcB0kaKuHqXGTd37Devni3TGIYkV0TBZbk2ps5vCPwuXLY1St0tXcmfJDg",
		Name:        "Healthcare Demo",
		TenantID:    "healthcare_tenant",
		Permissions: []string{"query", "llm", "connectors", "planning"},
		RateLimit:   1000,
		Enabled:     true,
	},
	"ecommerce-demo": {
		ClientID:    "ecommerce-demo",
		LicenseKey:  "AXON-eyJ0aWVyIjoiRW50ZXJwcmlzZSIsInRlbmFudF9pZCI6ImVjb21tZXJjZSIsInNlcnZpY2VfbmFtZSI6InBsYXRmb3JtIiwic2VydmljZV90eXBlIjoiYmFja2VuZC1zZXJ2aWNlIiwicGVybWlzc2lvbnMiOlsicXVlcnkiLCJsbG0iLCJjb25uZWN0b3JzIl0sImlzc3VlZF9hdCI6IjIwMjYwMjI2IiwiZXhwaXJlc19hdCI6IjIwMzYwMjI0In0.ejI5UBXB0SwPI52x9fE8_EaJKEHjQEmvBemgBikO6DI5iEnSVUVYA-iHu5IzLWjG-B56ni8hFdTCALdP_Hz3CQ",
		Name:        "E-commerce Demo",
		TenantID:    "ecommerce_tenant",
		Permissions: []string{"query", "llm", "connectors"},
		RateLimit:   1000,
		Enabled:     true,
	},
	"client_1": {
		ClientID:    "client_1",
		LicenseKey:  "AXON-eyJ0aWVyIjoiRW50ZXJwcmlzZSIsInRlbmFudF9pZCI6ImNsaWVudDEiLCJzZXJ2aWNlX25hbWUiOiJwbGF0Zm9ybSIsInNlcnZpY2VfdHlwZSI6ImJhY2tlbmQtc2VydmljZSIsInBlcm1pc3Npb25zIjpbInF1ZXJ5IiwibGxtIl0sImlzc3VlZF9hdCI6IjIwMjYwMjI2IiwiZXhwaXJlc19hdCI6IjIwMzYwMjI0In0.BIXc5Q3MALK-UGuCU-fTusTTqQaZkLo43VMi67swHZeZXht5CcAISFJPZYNF6BvqtA56MiyWQs8rQHQGZ2DtAw",
		Name:        "Client 1",
		TenantID:    "tenant_1",
		Permissions: []string{"query", "llm"},
		RateLimit:   500,
		Enabled:     true,
	},
	"client_2": {
		ClientID:    "client_2",
		LicenseKey:  "AXON-eyJ0aWVyIjoiRW50ZXJwcmlzZSIsInRlbmFudF9pZCI6ImNsaWVudDIiLCJzZXJ2aWNlX25hbWUiOiJwbGF0Zm9ybSIsInNlcnZpY2VfdHlwZSI6ImJhY2tlbmQtc2VydmljZSIsInBlcm1pc3Npb25zIjpbInF1ZXJ5IiwibGxtIl0sImlzc3VlZF9hdCI6IjIwMjYwMjI2IiwiZXhwaXJlc19hdCI6IjIwMzYwMjI0In0.T-gsODveLIO8x8PV-YHnohYBXzv5XWqcsGFgSJ_hCkVVEDE3rsmC3DIdkODLIrvZE0hIvFd2gD1w4fqqdEUeCw",
		Name:        "Client 2",
		TenantID:    "tenant_2",
		Permissions: []string{"query", "llm"},
		RateLimit:   500,
		Enabled:     true,
	},
	"loadtest": {
		ClientID:    "loadtest",
		LicenseKey:  "AXON-eyJ0aWVyIjoiRW50ZXJwcmlzZSIsInRlbmFudF9pZCI6ImxvYWR0ZXN0Iiwic2VydmljZV9uYW1lIjoicGxhdGZvcm0iLCJzZXJ2aWNlX3R5cGUiOiJiYWNrZW5kLXNlcnZpY2UiLCJwZXJtaXNzaW9ucyI6WyJxdWVyeSIsImxsbSJdLCJpc3N1ZWRfYXQiOiIyMDI2MDIyNiIsImV4cGlyZXNfYXQiOiIyMDM2MDIyNCJ9.lfjTp6yEA3XR_ag0oE90X7nydp8w98tPhzRSOzJkZ9i6Xu9gUXB1DG9hPl7epTjUIWp-B91l-W4ci_0izTVXAQ",
		Name:        "Load Testing Client",
		TenantID:    "loadtest_tenant",
		Permissions: []string{"query", "llm"},
		RateLimit:   10000,
		Enabled:     true,
	},
}

// In-memory rate limiting (simple implementation for Option 2)
var rateLimitMap = make(map[string]*RateLimitEntry)
var rateLimitMu sync.RWMutex

// validateClientCredentials validates a client using their OAuth2 client credentials.
// The clientSecret is the Ed25519-signed license key sent via Basic auth.
func validateClientCredentials(ctx context.Context, clientID, clientSecret string) (*Client, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client ID required")
	}

	if clientSecret == "" {
		return nil, fmt.Errorf("client secret required")
	}

	// Look up client in whitelist
	clientAuth, exists := knownClients[clientID]
	if !exists {
		return nil, fmt.Errorf("client '%s' not found in whitelist", clientID)
	}

	if !clientAuth.Enabled {
		return nil, fmt.Errorf("client '%s' is disabled", clientID)
	}

	// Verify client secret matches the stored license key
	if clientSecret != clientAuth.LicenseKey {
		return nil, fmt.Errorf("invalid credentials for client '%s'", clientID)
	}

	// Validate license key format with license validation system
	validationResult, err := license.ValidateLicense(ctx, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("license validation failed: %w", err)
	}

	if !validationResult.Valid {
		return nil, fmt.Errorf("license invalid or expired: %s", validationResult.Error)
	}

	// Check rate limit
	if err := checkRateLimit(clientID, clientAuth.RateLimit); err != nil {
		return nil, err
	}

	// Return authenticated client
	return &Client{
		ID:          clientAuth.ClientID,
		Name:        clientAuth.Name,
		OrgID:       validationResult.OrgID, // From license validation
		TenantID:    clientAuth.TenantID,
		Permissions: clientAuth.Permissions,
		RateLimit:   clientAuth.RateLimit,
		Enabled:     true,
		LicenseTier: string(validationResult.Tier),
		LicenseExpiry: validationResult.ExpiresAt,
	}, nil
}

// checkRateLimit implements simple in-memory rate limiting
// Returns error if rate limit exceeded
func checkRateLimit(clientID string, limitPerMinute int) error {
	now := time.Now()

	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()

	entry, exists := rateLimitMap[clientID]
	if !exists {
		// First request from this client
		rateLimitMap[clientID] = &RateLimitEntry{
			Count:     1,
			ResetTime: now.Add(time.Minute),
		}
		return nil
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Check if rate limit window has reset
	if now.After(entry.ResetTime) {
		entry.Count = 1
		entry.ResetTime = now.Add(time.Minute)
		return nil
	}

	// Increment counter
	entry.Count++

	// Check if limit exceeded
	if entry.Count > limitPerMinute {
		return fmt.Errorf("rate limit exceeded: %d requests/minute (limit: %d)", entry.Count, limitPerMinute)
	}

	return nil
}

// getRateLimitStatus returns current rate limit status for a client
//
//nolint:unused // Used in tests
func getRateLimitStatus(clientID string) (count int, limit int, resetTime time.Time) {
	rateLimitMu.RLock()
	defer rateLimitMu.RUnlock()

	entry, exists := rateLimitMap[clientID]
	if !exists {
		return 0, 0, time.Time{}
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	clientAuth, exists := knownClients[clientID]
	if !exists {
		return entry.Count, 0, entry.ResetTime
	}

	return entry.Count, clientAuth.RateLimit, entry.ResetTime
}

// extractClientSecret extracts the client secret from OAuth2 Basic auth header.
// Format: Authorization: Basic base64(clientId:clientSecret)
//
// The clientSecret is used as the license key for authentication.
// Returns empty string if not found or invalid.
func extractClientSecret(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Basic ") {
		return ""
	}

	encoded := strings.TrimPrefix(authHeader, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}

	// Format: clientId:clientSecret
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) == 2 && parts[1] != "" {
		return parts[1] // clientSecret is the license key
	}

	return ""
}

// extractClientID extracts the client ID from OAuth2 Basic auth header.
// Format: Authorization: Basic base64(clientId:clientSecret)
//
// Returns empty string if not found or invalid.
func extractClientID(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Basic ") {
		return ""
	}

	encoded := strings.TrimPrefix(authHeader, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}

	// Format: clientId:clientSecret
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) >= 1 && parts[0] != "" {
		return parts[0]
	}

	return ""
}

// =============================================================================
// Shared authentication — single entry point for all handlers
// =============================================================================

// CommunitySaasAuthError represents a community-saas authentication failure.
// Callers inspect StatusCode + Message to format an appropriate response for
// their protocol (REST JSON, JSON-RPC, etc.).
type CommunitySaasAuthError struct {
	StatusCode int
	Message    string
	RetryAfter string // non-empty → set Retry-After header
}

func (e *CommunitySaasAuthError) Error() string { return e.Message }

// validateCommunitySaasAuth is a pure function that validates community-saas
// credentials. It never writes to http.ResponseWriter — callers translate the
// returned error into their own wire format (REST, JSON-RPC, etc.).
//
// This is the single source of truth for community-saas auth logic.
func validateCommunitySaasAuth(r *http.Request) (*Client, *CommunitySaasAuthError) {
	cID := extractClientID(r)
	cSecret := extractClientSecret(r)
	if cID == "" || cSecret == "" {
		return nil, &CommunitySaasAuthError{
			StatusCode: http.StatusUnauthorized,
			Message:    "Registration required. POST to /api/v1/register to get credentials.",
		}
	}

	// Per-minute rate limit BEFORE bcrypt to prevent CPU exhaustion attacks
	minuteLimit := getEnvInt("COMMUNITY_SAAS_MINUTE_LIMIT", 20)
	if err := checkRateLimitRedis(r.Context(), cID, minuteLimit); err != nil {
		return nil, &CommunitySaasAuthError{
			StatusCode: http.StatusTooManyRequests,
			Message:    fmt.Sprintf("Rate limit exceeded (%d req/min). Try again shortly.", minuteLimit),
			RetryAfter: "60",
		}
	}

	// Validate credentials (bcrypt — ~400ms). Detached context so client
	// disconnect doesn't cause spurious auth failure.
	authCtx, authCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer authCancel()

	if err := validateCommunityRegistration(authCtx, authDB, cID, cSecret); err != nil {
		log.Printf("[AUTH] community-saas auth failed for tenant %s: %v",
			logutil.Sanitize(cID), err)
		// Differentiate terminated tenants from other auth failures so the client
		// can distinguish "your registration is gone, re-register" from "your
		// secret is wrong". Terminated is permanent (sweep cleared the data);
		// re-trying with the same credentials will never succeed.
		message := "Invalid credentials or registration expired"
		if errors.Is(err, ErrRegistrationTerminated) {
			message = "Registration terminated by retention policy (3-month inactivity or 1-year cap). " +
				"Re-register at POST /api/v1/register."
		}
		return nil, &CommunitySaasAuthError{
			StatusCode: http.StatusUnauthorized,
			Message:    message,
		}
	}

	enqueueActivityUpdate(authDB, cID)

	// ADR-050 §4: derive request scope from X-Axonflow-Client. Absent header
	// defaults to "full" — a caller hitting raw HTTP without identification
	// is by construction a sophisticated user; a plugin-only token paired
	// with that request would correctly reject below.
	clientHeader := r.Header.Get("X-Axonflow-Client")
	scope := license.DeriveScopeFromClientHeader(clientHeader)

	// Per-tenant effective tier per ADR-049 §3 + ADR-050 §9. Default is
	// the SaaS Plugin Free baseline (applied when no X-License-Token is
	// present). A valid token + matching plugin_user_licenses row
	// promotes the request to the row's tier (today: Pro). Token
	// validation runs first (signature, aud accept-list, scope); the
	// DB lookup runs only after the token is otherwise valid so we
	// don't burn a query per malformed-token request.
	effectiveTier := string(license.TierFree)

	// ADR-050 §3 + §4: when the caller presents a license token, validate it
	// against the SaaS Plugin path's accept list and check that the token's
	// aud.scope satisfies the request scope derived above. Cross-quadrant
	// misuse (e.g. self_hosted token sent as X-License-Token, or plugin-scope
	// token paired with an SDK client header) is rejected here.
	if licenseToken := r.Header.Get("X-License-Token"); licenseToken != "" {
		payload, err := license.ParseAndVerifyServiceToken(licenseToken)
		if err != nil {
			log.Printf("[AUTH] X-License-Token parse/verify failed for tenant %s: %v",
				logutil.Sanitize(cID), err)
			return nil, &CommunitySaasAuthError{
				StatusCode: http.StatusUnauthorized,
				Message:    "invalid_license_token: " + err.Error(),
			}
		}
		if !license.IsSaaSPluginPathAud(payload.Aud) {
			log.Printf("[AUTH] cross-quadrant token rejected for tenant %s: aud=%q",
				logutil.Sanitize(cID), payload.Aud)
			return nil, &CommunitySaasAuthError{
				StatusCode: http.StatusUnauthorized,
				Message:    fmt.Sprintf("cross_quadrant_token: aud %q not accepted on SaaS plugin path", payload.Aud),
			}
		}
		if !payload.HasScope(scope) {
			log.Printf("[AUTH] scope mismatch for tenant %s: token aud=%q, request scope=%q (client=%q)",
				logutil.Sanitize(cID), payload.Aud, scope, logutil.Sanitize(clientHeader))
			return nil, &CommunitySaasAuthError{
				StatusCode: http.StatusUnauthorized,
				Message:    fmt.Sprintf("scope_mismatch: token aud %q does not grant scope %q (client %q)", payload.Aud, scope, clientHeader),
			}
		}

		// The token's tenant_id MUST match the auth-resolved tenant. A
		// buyer presenting their token from another tenant is a forgery
		// / token-leak scenario.
		if payload.TenantID != cID {
			log.Printf("[AUTH] license token tenant mismatch: token=%s auth=%s",
				logutil.Sanitize(payload.TenantID), logutil.Sanitize(cID))
			return nil, &CommunitySaasAuthError{
				StatusCode: http.StatusForbidden,
				Message:    "license_tenant_mismatch: token tenant_id does not match authenticated tenant",
			}
		}

		// Per-request DB lookup so revocation is effective within ~60s
		// of a chargeback or dispute (ADR-049 §2). The row carries the
		// canonical tier — the token's tier claim is informational
		// only. This is the work that used to live in
		// `plugin_claim_middleware.go`; it folds inline here per
		// ADR-049 §3 / ADR-050 §9 so per-tenant tier resolution stays
		// in the single auth path.
		rowTier, lookupErr := lookupActivePluginLicenseTier(r.Context(), authDB, payload.JTI, cID)
		if lookupErr != nil {
			authErr := mapPluginLicenseLookupError(lookupErr, payload.JTI)
			log.Printf("[AUTH] plugin_user_licenses lookup failed for jti=%s: %v",
				logutil.Sanitize(payload.JTI), lookupErr)
			return nil, authErr
		}
		effectiveTier = string(rowTier)
	}

	return &Client{
		ID:            cID,
		Name:          "Community-SaaS",
		OrgID:         communitySaasOrgID,
		TenantID:      cID,
		Enabled:       true,
		LicenseTier:   "Community",
		RateLimit:     minuteLimit,
		Permissions:   []string{},
		ClientHeader:  clientHeader,
		Scope:         scope,
		EffectiveTier: effectiveTier,
	}, nil
}

// =============================================================================
// Request Context — Auth-derived tenant identity (RFC 6749 pattern)
// =============================================================================

// authContextKey is a typed key for storing auth-derived identity in request context.
// Using a typed key prevents collisions with other context values.
type authContextKey string

const (
	// ContextKeyTenantID stores the authenticated tenant ID in request context.
	ContextKeyTenantID authContextKey = "auth_tenant_id"
	// ContextKeyOrgID stores the authenticated org ID in request context.
	ContextKeyOrgID authContextKey = "auth_org_id"
	// ContextKeyClientID stores the authenticated client ID in request context.
	ContextKeyClientID authContextKey = "auth_client_id"
	// ContextKeyAuthKind stores the AuthKind in request context so handlers
	// behind apiAuthMiddleware can call ResolveUser() with the correct kind.
	ContextKeyAuthKind authContextKey = "auth_kind"
)

// TenantIDFromContext extracts the auth-derived tenant ID from request context.
// Returns empty string if not set (should not happen if apiAuthMiddleware is applied).
func TenantIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ContextKeyTenantID).(string); ok {
		return v
	}
	return ""
}

// OrgIDFromContext extracts the auth-derived org ID from request context.
func OrgIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ContextKeyOrgID).(string); ok {
		return v
	}
	return ""
}

// ClientIDFromContext extracts the auth-derived client ID from request context.
func ClientIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ContextKeyClientID).(string); ok {
		return v
	}
	return ""
}

// AuthKindFromContext extracts the auth kind from request context.
// Returns AuthKindEnterprise as default (most restrictive) if not set.
func AuthKindFromContext(ctx context.Context) AuthKind {
	if v, ok := ctx.Value(ContextKeyAuthKind).(AuthKind); ok {
		return v
	}
	return AuthKindEnterprise
}

// apiAuthMiddleware authenticates API requests using OAuth2 Client Credentials
// (RFC 6749 Section 4.4) and stores the authenticated identity in request context.
//
// In community mode: no auth required, defaults to "community" tenant.
// In enterprise mode: requires Basic auth, derives tenant from authenticated client.
//
// All downstream handlers read tenant from context via TenantIDFromContext(),
// never from X-Tenant-ID header. If the deprecated X-Tenant-ID header is present,
// a warning is logged but the auth-derived tenant is used.
func apiAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS preflight passthrough
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// Internal-service auth via headers — used by the customer-portal
		// to call agent endpoints (e.g. /static-policies/effective) without
		// holding a customer license. The portal signs each request with
		// AXONFLOW_INTERNAL_SERVICE_SECRET and supplies the tenant scope it
		// has resolved from the user's session. Authenticate() looks for the
		// signed credentials in `hints` only, so we have to lift them off the
		// request headers ourselves before calling it.
		var hints *AuthHints
		if svcID := r.Header.Get("X-Internal-Service-ID"); svcID != "" {
			hints = &AuthHints{
				ClientID:  svcID,
				UserToken: r.Header.Get("X-Internal-Service-Token"),
				TenantID:  r.Header.Get("X-Tenant-ID"),
			}
		}

		// Use unified Authenticate() for all deployment modes
		auth, authErr := Authenticate(r, hints)
		if authErr != nil {
			if authErr.RetryAfter != "" {
				w.Header().Set("Retry-After", authErr.RetryAfter)
			}
			writeJSONError(w, authErr.Message, authErr.HTTPStatus)
			return
		}

		tenantID := auth.TenantID
		orgID := auth.OrgID
		clientID := auth.ClientID

		// Community-SaaS daily cap (per-request concern, not in Authenticate).
		// Per ADR-049 §3 + ADR-050 §9 the cap is per-tenant: validateCommunitySaasAuth
		// has already resolved Client.EffectiveTier (Free / Pro / Premium); we
		// look up the tier's `DailyEventQuota` here. The locked numbers per
		// PRD_TENANT_DURABILITY_AND_CLAIM (V1 Plugin Pro umbrella #1958):
		// Free=200, Pro=2,000, Premium=5,000. The legacy
		// `COMMUNITY_SAAS_DAILY_LIMIT` env var is still honored as a
		// fallback for the Free baseline so operators running their own
		// stacks can override without rebuilding (e.g. the perf-testing
		// rig). On limit hit we emit the V1 Plugin Pro structured
		// upgrade envelope (locked shape per umbrella #1958).
		if auth.Kind == AuthKindCommunitySaaS {
			dailyCtx, dailyCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer dailyCancel()
			dailyLimit := dailyLimitForTenant(auth.Client)
			if err := checkCommunityDailyLimit(dailyCtx, tenantID, dailyLimit, authDB); err != nil {
				tier := "Free"
				if auth.Client != nil && auth.Client.EffectiveTier != "" {
					tier = auth.Client.EffectiveTier
				}
				writeRateLimitError(w, tenantID, tier, dailyLimit)
				return
			}
		}

		// X-Tenant-ID header is deprecated — tenant is derived from auth credentials.
		// Accept and ignore for transition period while SDKs are updated (Phase 2-3).
		// Auth-derived tenant always takes precedence.
		// Skip the warning for internal-service callers (the customer-portal
		// intentionally supplies the tenant scope via X-Tenant-ID and the
		// Authenticate() internal-service path already consumes it).
		if headerTenant := r.Header.Get("X-Tenant-ID"); headerTenant != "" && auth.Kind != AuthKindInternalService {
			log.Printf("[API Auth] DEPRECATED: X-Tenant-ID header '%s' ignored — using auth-derived tenant '%s'. Update your SDK to remove this header.",
				logutil.Sanitize(headerTenant), logutil.Sanitize(tenantID))
		}

		// Store authenticated identity in request context
		ctx := r.Context()
		ctx = context.WithValue(ctx, ContextKeyTenantID, tenantID)
		ctx = context.WithValue(ctx, ContextKeyOrgID, orgID)
		ctx = context.WithValue(ctx, ContextKeyClientID, clientID)
		ctx = context.WithValue(ctx, ContextKeyAuthKind, auth.Kind)

		// Populate telemetry identity container (set by outer telemetry middleware)
		SetTelemetryTenantID(ctx, tenantID)

		// Inject identity headers so downstream handlers (e.g. circuit breaker)
		// can read them without context key type coupling across packages.
		r.Header.Set("X-Tenant-ID", tenantID)
		r.Header.Set("X-Org-ID", orgID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
