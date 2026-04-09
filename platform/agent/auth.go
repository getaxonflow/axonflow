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

		var tenantID, orgID, clientID string

		if isCommunityMode() {
			// Community mode: extract clientId from Basic auth if present, else default
			cID := extractClientID(r)
			if cID == "" {
				cID = "community"
			}
			tenantID = cID
			orgID = getDeploymentOrgID()
			clientID = cID
		} else if isCommunitySaasMode() {
			// Community-SaaS mode: require Basic auth (tenant_id:secret) validated
			// against community_saas_registrations table. No Ed25519 license.
			cID := extractClientID(r)
			cSecret := extractClientSecret(r)
			if cID == "" || cSecret == "" {
				writeJSONError(w, "Registration required. POST to /api/v1/register to get credentials.", http.StatusUnauthorized)
				return
			}

			// Per-minute rate limit BEFORE bcrypt validation to protect against
			// CPU exhaustion attacks. An attacker with a valid tenant_id but invalid
			// secret would otherwise burn ~400ms of bcrypt per request.
			minuteLimit := getEnvInt("COMMUNITY_SAAS_MINUTE_LIMIT", 20)
			if err := checkRateLimitRedis(r.Context(), cID, minuteLimit); err != nil {
				w.Header().Set("Retry-After", "60")
				writeJSONError(w, fmt.Sprintf("Rate limit exceeded (%d req/min). Try again shortly.", minuteLimit), http.StatusTooManyRequests)
				return
			}

			// Validate credentials (bcrypt comparison — ~400ms)
			// Use a detached context so client disconnection doesn't cause a spurious auth failure
			authCtx, authCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer authCancel()

			if err := validateCommunityRegistration(authCtx, authDB, cID, cSecret); err != nil {
				log.Printf("[AUTH] community-saas auth failed for tenant %s: %v",
					logutil.Sanitize(cID), err)
				writeJSONError(w, "Invalid credentials or registration expired", http.StatusUnauthorized)
				return
			}

			tenantID = cID
			orgID = communitySaasOrgID
			clientID = cID

			// Update last_seen_at + increment request_count via bounded worker channel
			enqueueActivityUpdate(authDB, cID)

			// Daily cap (use detached context to avoid client disconnect causing false 429)
			dailyCtx, dailyCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer dailyCancel()
			dailyLimit := getEnvInt("COMMUNITY_SAAS_DAILY_LIMIT", 500)
			if err := checkCommunityDailyLimit(dailyCtx, tenantID, dailyLimit, authDB); err != nil {
				writeJSONError(w, "Daily request limit reached. Resets at midnight UTC.", http.StatusTooManyRequests)
				return
			}
		} else {
			// Enterprise mode: require Basic auth (OAuth2 Client Credentials)
			cID := extractClientID(r)
			cSecret := extractClientSecret(r)
			if cID == "" || cSecret == "" {
				writeJSONError(w, "Authentication required: provide Authorization header with Basic auth (clientId:clientSecret)", http.StatusUnauthorized)
				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()

			var client *Client
			var err error
			if authDB != nil {
				client, err = validateClientCredentialsDB(ctx, authDB, cID, cSecret)
			} else {
				client, err = validateClientCredentials(ctx, cID, cSecret)
			}
			if err != nil || client == nil {
				msg := "Authentication failed"
				if err != nil {
					msg += ": " + err.Error()
				}
				writeJSONError(w, msg, http.StatusUnauthorized)
				return
			}

			if !client.Enabled {
				writeJSONError(w, "Client disabled", http.StatusForbidden)
				return
			}

			tenantID = client.TenantID
			orgID = client.OrgID
			clientID = client.ID
		}

		// X-Tenant-ID header is deprecated — tenant is derived from auth credentials.
		// Accept and ignore for transition period while SDKs are updated (Phase 2-3).
		// Auth-derived tenant always takes precedence.
		if headerTenant := r.Header.Get("X-Tenant-ID"); headerTenant != "" {
			log.Printf("[API Auth] DEPRECATED: X-Tenant-ID header '%s' ignored — using auth-derived tenant '%s'. Update your SDK to remove this header.",
				logutil.Sanitize(headerTenant), logutil.Sanitize(tenantID))
		}

		// Store authenticated identity in request context
		ctx := r.Context()
		ctx = context.WithValue(ctx, ContextKeyTenantID, tenantID)
		ctx = context.WithValue(ctx, ContextKeyOrgID, orgID)
		ctx = context.WithValue(ctx, ContextKeyClientID, clientID)

		// Inject identity headers so downstream handlers (e.g. circuit breaker)
		// can read them without context key type coupling across packages.
		r.Header.Set("X-Tenant-ID", tenantID)
		r.Header.Set("X-Org-ID", orgID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
