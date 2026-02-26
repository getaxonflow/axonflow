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
	"net/http"
	"strings"
	"sync"
	"time"

	"axonflow/platform/agent/license"
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
