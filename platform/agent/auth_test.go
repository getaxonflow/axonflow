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
	"bytes"
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestValidateClientCredentials tests the whitelist-based client authentication
func TestValidateClientCredentials(t *testing.T) {
	if !isCommunityBuild {
		t.Skip("uses community whitelist keys that don't validate with enterprise Ed25519 signing")
	}
	ctx := context.Background()

	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "valid healthcare demo client",
			clientID:     "healthcare-demo",
			clientSecret: knownClients["healthcare-demo"].LicenseKey,
			expectError:  false,
		},
		{
			name:         "valid ecommerce demo client",
			clientID:     "ecommerce-demo",
			clientSecret: knownClients["ecommerce-demo"].LicenseKey,
			expectError:  false,
		},
		{
			name:         "valid loadtest client",
			clientID:     "loadtest",
			clientSecret: knownClients["loadtest"].LicenseKey,
			expectError:  false,
		},
		{
			name:         "missing client ID",
			clientID:     "",
			clientSecret: "AXON-invalid.invalid",
			expectError:  true,
			errorMsg:     "client ID required",
		},
		{
			name:         "missing client secret",
			clientID:     "healthcare-demo",
			clientSecret: "",
			expectError:  true,
			errorMsg:     "client secret required",
		},
		{
			name:         "unknown client",
			clientID:     "unknown-client",
			clientSecret: "AXON-invalid.invalid",
			expectError:  true,
			errorMsg:     "not found in whitelist",
		},
		{
			name:         "invalid credentials for known client",
			clientID:     "healthcare-demo",
			clientSecret: "AXON-wrong-credentials.wrong",
			expectError:  true,
			errorMsg:     "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := validateClientCredentials(ctx, tt.clientID, tt.clientSecret)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}

				if client != nil {
					t.Error("Expected nil client on error")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}

				if client == nil {
					t.Fatal("Expected non-nil client")
				}

				// Verify client properties
				if client.ID != tt.clientID {
					t.Errorf("Expected client ID '%s', got '%s'", tt.clientID, client.ID)
				}

				if client.TenantID == "" {
					t.Error("Expected non-empty tenant ID")
				}

				if len(client.Permissions) == 0 {
					t.Error("Expected non-empty permissions")
				}

				if client.RateLimit <= 0 {
					t.Error("Expected positive rate limit")
				}

				if !client.Enabled {
					t.Error("Expected client to be enabled")
				}

				if client.LicenseTier == "" {
					t.Error("Expected non-empty license tier")
				}
			}
		})
	}
}

// TestValidateClientCredentialsPermissions tests permission handling
func TestValidateClientCredentialsPermissions(t *testing.T) {
	if !isCommunityBuild {
		t.Skip("uses community whitelist keys that don't validate with enterprise Ed25519 signing")
	}
	ctx := context.Background()

	// Test healthcare demo permissions
	client, err := validateClientCredentials(ctx, "healthcare-demo", knownClients["healthcare-demo"].LicenseKey)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Healthcare demo should have planning permission
	if !hasPermission(client.Permissions, "planning") {
		t.Error("Healthcare demo should have planning permission")
	}

	// Test client without planning permission
	client2, err := validateClientCredentials(ctx, "client_1", knownClients["client_1"].LicenseKey)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if hasPermission(client2.Permissions, "planning") {
		t.Error("Legacy client should not have planning permission")
	}
}

// TestCheckRateLimit tests the in-memory rate limiting
func TestCheckRateLimit(t *testing.T) {
	// Reset rate limit map for clean test
	rateLimitMu.Lock()
	rateLimitMap = make(map[string]*RateLimitEntry)
	rateLimitMu.Unlock()

	clientID := "test-client-rate-limit"
	limit := 10 // 10 requests per minute

	// First 10 requests should succeed
	for i := 0; i < limit; i++ {
		err := checkRateLimit(clientID, limit)
		if err != nil {
			t.Errorf("Request %d should succeed, got error: %v", i+1, err)
		}
	}

	// 11th request should fail (rate limit exceeded)
	err := checkRateLimit(clientID, limit)
	if err == nil {
		t.Error("Expected rate limit error on 11th request")
	}

	if err != nil && !contains(err.Error(), "rate limit exceeded") {
		t.Errorf("Expected 'rate limit exceeded' error, got: %v", err)
	}
}

// TestCheckRateLimitReset tests rate limit window reset
func TestCheckRateLimitReset(t *testing.T) {
	// Reset rate limit map
	rateLimitMu.Lock()
	rateLimitMap = make(map[string]*RateLimitEntry)
	rateLimitMu.Unlock()

	clientID := "test-client-reset"
	limit := 5

	// Use up the limit
	for i := 0; i < limit; i++ {
		_ = checkRateLimit(clientID, limit)
	}

	// Next request should fail
	err := checkRateLimit(clientID, limit)
	if err == nil {
		t.Error("Expected rate limit error")
	}

	// Manually reset the time window
	rateLimitMu.Lock()
	if entry, exists := rateLimitMap[clientID]; exists {
		entry.mu.Lock()
		entry.ResetTime = time.Now().Add(-1 * time.Second) // Force reset
		entry.mu.Unlock()
	}
	rateLimitMu.Unlock()

	// Now request should succeed (new window)
	err = checkRateLimit(clientID, limit)
	if err != nil {
		t.Errorf("Expected success after window reset, got error: %v", err)
	}
}

// TestCheckRateLimitConcurrent tests concurrent rate limit checks
func TestCheckRateLimitConcurrent(t *testing.T) {
	// Reset rate limit map
	rateLimitMu.Lock()
	rateLimitMap = make(map[string]*RateLimitEntry)
	rateLimitMu.Unlock()

	clientID := "test-client-concurrent"
	limit := 100

	// Run 50 concurrent requests (should all succeed)
	concurrency := 50
	results := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			results <- checkRateLimit(clientID, limit)
		}()
	}

	// Collect results
	successCount := 0
	for i := 0; i < concurrency; i++ {
		if err := <-results; err == nil {
			successCount++
		}
	}

	if successCount != concurrency {
		t.Errorf("Expected %d successful requests, got %d", concurrency, successCount)
	}

	// Verify count is correct
	count, _, _ := getRateLimitStatus(clientID)
	if count != concurrency {
		t.Errorf("Expected count %d, got %d", concurrency, count)
	}
}

// TestGetRateLimitStatus tests rate limit status retrieval
func TestGetRateLimitStatus(t *testing.T) {
	// Reset rate limit map
	rateLimitMu.Lock()
	rateLimitMap = make(map[string]*RateLimitEntry)
	rateLimitMu.Unlock()

	// Use a known client from the whitelist
	clientID := "healthcare-demo"
	clientAuth := knownClients[clientID]
	if clientAuth == nil {
		t.Fatal("healthcare-demo not found in knownClients")
	}
	limit := clientAuth.RateLimit

	// Make some requests
	requestCount := 5
	for i := 0; i < requestCount; i++ {
		_ = checkRateLimit(clientID, limit)
	}

	// Get status
	count, returnedLimit, resetTime := getRateLimitStatus(clientID)

	if count != requestCount {
		t.Errorf("Expected count %d, got %d", requestCount, count)
	}

	if returnedLimit != limit {
		t.Errorf("Expected limit %d, got %d", limit, returnedLimit)
	}

	if resetTime.IsZero() {
		t.Error("Expected non-zero reset time")
	}

	if !resetTime.After(time.Now()) {
		t.Error("Reset time should be in the future")
	}
}

// TestGetRateLimitStatusUnknownClient tests status for unknown client
func TestGetRateLimitStatusUnknownClient(t *testing.T) {
	count, limit, resetTime := getRateLimitStatus("unknown-client-xyz")

	if count != 0 {
		t.Errorf("Expected count 0 for unknown client, got %d", count)
	}

	if limit != 0 {
		t.Errorf("Expected limit 0 for unknown client, got %d", limit)
	}

	if !resetTime.IsZero() {
		t.Error("Expected zero reset time for unknown client")
	}
}

// TestRateLimitDifferentClients tests that rate limits are per-client
func TestRateLimitDifferentClients(t *testing.T) {
	// Reset rate limit map
	rateLimitMu.Lock()
	rateLimitMap = make(map[string]*RateLimitEntry)
	rateLimitMu.Unlock()

	client1 := "client-1"
	client2 := "client-2"
	limit := 5

	// Max out client1's rate limit
	for i := 0; i < limit; i++ {
		_ = checkRateLimit(client1, limit)
	}

	// Client1 should be rate limited
	err := checkRateLimit(client1, limit)
	if err == nil {
		t.Error("Expected rate limit error for client1")
	}

	// Client2 should NOT be rate limited
	err = checkRateLimit(client2, limit)
	if err != nil {
		t.Errorf("Client2 should not be rate limited: %v", err)
	}

	// Verify separate counts
	count1, _, _ := getRateLimitStatus(client1)
	count2, _, _ := getRateLimitStatus(client2)

	if count1 != limit+1 { // limit + 1 failed attempt
		t.Errorf("Client1 count should be %d, got %d", limit+1, count1)
	}

	if count2 != 1 {
		t.Errorf("Client2 count should be 1, got %d", count2)
	}
}

// TestClientAuthStructure tests the ClientAuth data structure
func TestClientAuthStructure(t *testing.T) {
	// Verify all known clients have required fields
	for clientID, auth := range knownClients {
		t.Run(clientID, func(t *testing.T) {
			if auth.ClientID != clientID {
				t.Errorf("ClientID mismatch: expected '%s', got '%s'", clientID, auth.ClientID)
			}

			if auth.LicenseKey == "" {
				t.Error("LicenseKey should not be empty")
			}

			if auth.Name == "" {
				t.Error("Name should not be empty")
			}

			if auth.TenantID == "" {
				t.Error("TenantID should not be empty")
			}

			if auth.RateLimit <= 0 {
				t.Error("RateLimit should be positive")
			}

			if !auth.Enabled {
				t.Error("Client should be enabled")
			}

			if len(auth.Permissions) == 0 {
				t.Error("Permissions should not be empty")
			}

			// Verify license key format
			if !contains(auth.LicenseKey, "AXON-") {
				t.Error("License key should start with 'AXON-'")
			}
		})
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func hasPermission(permissions []string, permission string) bool {
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// TestExtractClientSecret tests OAuth2 Basic auth extraction
func TestExtractClientSecret(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedResult string
	}{
		{
			name:           "OAuth2 Basic auth - valid",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client-id:my-license-key")),
			expectedResult: "my-license-key",
		},
		{
			name:           "no auth provided",
			authHeader:     "",
			expectedResult: "",
		},
		{
			name:           "OAuth2 Basic auth - invalid base64",
			authHeader:     "Basic not-valid-base64!!!",
			expectedResult: "",
		},
		{
			name:           "OAuth2 Basic auth - missing colon",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("noclientid")),
			expectedResult: "",
		},
		{
			name:           "OAuth2 Basic auth - empty secret",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("client:")),
			expectedResult: "",
		},
		{
			name:           "Bearer token (not Basic)",
			authHeader:     "Bearer some-jwt-token",
			expectedResult: "",
		},
		{
			name:           "real AXON license key via OAuth2",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("healthcare-demo:AXON-V2-eyJ0aWVyIjoiUExVUyJ9-abc123")),
			expectedResult: "AXON-V2-eyJ0aWVyIjoiUExVUyJ9-abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/api/request", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			result := extractClientSecret(req)

			if result != tt.expectedResult {
				t.Errorf("extractClientSecret() = %q, want %q", result, tt.expectedResult)
			}
		})
	}
}

// TestExtractClientID tests OAuth2 Basic auth client ID extraction
func TestExtractClientID(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedResult string
	}{
		{
			name:           "OAuth2 Basic auth - valid",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client-id:my-secret")),
			expectedResult: "my-client-id",
		},
		{
			name:           "no auth provided",
			authHeader:     "",
			expectedResult: "",
		},
		{
			name:           "OAuth2 Basic auth - invalid base64",
			authHeader:     "Basic not-valid-base64!!!",
			expectedResult: "",
		},
		{
			name:           "Bearer token (not Basic)",
			authHeader:     "Bearer some-jwt-token",
			expectedResult: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/api/request", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			result := extractClientID(req)

			if result != tt.expectedResult {
				t.Errorf("extractClientID() = %q, want %q", result, tt.expectedResult)
			}
		})
	}
}

// TestValidateCommunitySaasAuth_NoCredentialsEmitsLog is the regression guard
// for issue #2280. The no-credentials early-return path used to return 401
// without any log.Printf, leaving #2275-class storms attribution-blind.
// The hostile-review investigation of #2275 hit this gap concretely: a
// CloudWatch query for "auth failed" across the 24-hour storm window
// returned 0 matches, because all 716 × 401s landed on this silent path.
//
// Assertion: the new `[CSAAS-AUTH] no_credentials` log line fires, and
// includes the request path + User-Agent + remote address (all already
// in ALB logs — no new PII surface).
//
// Mutation-tested: deleting the new log.Printf in auth.go makes this test
// fail at the `[CSAAS-AUTH]` substring assertion.
func TestValidateCommunitySaasAuth_NoCredentialsEmitsLog(t *testing.T) {
	var buf bytes.Buffer
	origFlags := log.Default().Flags()
	log.Default().SetOutput(&buf)
	log.Default().SetFlags(0)
	t.Cleanup(func() {
		log.Default().SetOutput(os.Stderr)
		log.Default().SetFlags(origFlags)
	})

	cases := []struct {
		name string
		path string
		ua   string
		// remoteAddr simulates the ALB → agent TCP peer (always the LB IP
		// under prod; only equal to the real client IP in unit tests with
		// no XFF or in direct-internet test setups).
		remoteAddr string
		// xff simulates the X-Forwarded-For header ALB attaches. Empty
		// means no XFF (e.g., direct localhost or test client without an
		// LB in front).
		xff string
		// expectedRemote is what the log line's `remote=` field should
		// contain. Under ALB-with-XFF the expectation is the LAST XFF
		// entry; under no-XFF the expectation is the host portion of
		// remoteAddr (port stripped by extractClientIP).
		expectedRemote string
		auth           string
	}{
		{
			// The #2275 storm shape: ALB hands the real client IP to the
			// agent via the LAST entry of X-Forwarded-For. r.RemoteAddr
			// is the LB's internal IP — using it directly is the bug
			// the post-#2280 hostile review caught.
			name:           "ALB-fronted: XFF last entry is the real client IP",
			path:           "/api/v1/audit/tool-call",
			ua:             "node",
			remoteAddr:     "10.1.2.160:54321", // ALB internal peer
			xff:            "49.73.19.130",     // real client (the #2275 storm IP)
			expectedRemote: "49.73.19.130",
			auth:           "",
		},
		{
			// Multi-hop XFF: still trust the LAST entry only. The first
			// entry is what the original client claimed (can be spoofed);
			// the last entry is what the trusted proxy (ALB) observed at
			// its peer socket.
			name:           "multi-hop XFF: last entry only",
			path:           "/api/v1/mcp/check-input",
			ua:             "curl/8.4.0",
			remoteAddr:     "10.1.2.160:33333",
			xff:            "spoofed-by-client, 203.0.113.7",
			expectedRemote: "203.0.113.7",
			auth:           "Bearer notbasic",
		},
		{
			// No XFF (direct test client or local dev). Fall back to the
			// host portion of RemoteAddr — extractClientIP strips the port.
			name:           "no XFF — RemoteAddr host portion (port stripped)",
			path:           "/api/v1/audit/tool-call",
			ua:             "openclaw-plugin/2.6.0",
			remoteAddr:     "198.51.100.42:12345",
			xff:            "",
			expectedRemote: "198.51.100.42",
			auth:           "Basic " + base64.StdEncoding.EncodeToString([]byte(":secret-only")),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			req := httptest.NewRequest("POST", tc.path, nil)
			req.Header.Set("User-Agent", tc.ua)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}

			_, authErr := validateCommunitySaasAuth(req)
			if authErr == nil {
				t.Fatal("expected CommunitySaasAuthError, got nil")
			}
			if authErr.StatusCode != http.StatusUnauthorized {
				t.Errorf("StatusCode = %d, want 401", authErr.StatusCode)
			}

			out := buf.String()
			if !strings.Contains(out, "[CSAAS-AUTH] no_credentials") {
				t.Errorf("missing [CSAAS-AUTH] no_credentials prefix; got: %q", out)
			}
			// path is now quoted with %q in the log format.
			if !strings.Contains(out, "path="+strconv.Quote(tc.path)) {
				t.Errorf("missing path=%q in log; got: %q", tc.path, out)
			}
			if !strings.Contains(out, "user_agent="+strconv.Quote(tc.ua)) {
				t.Errorf("missing user_agent=%q in log; got: %q", tc.ua, out)
			}
			// Load-bearing assertion for the #2280 attribution promise:
			// the log records the REAL client IP, not the LB internal IP.
			// This is what the storm-alarm forensic chain ("grep the IP
			// in agent logs") depends on. If a future refactor drops the
			// extractClientIP() helper and reverts to r.RemoteAddr, this
			// assertion fails.
			if !strings.Contains(out, "remote="+tc.expectedRemote) {
				t.Errorf("expected remote=%q in log; got: %q", tc.expectedRemote, out)
			}
			// Anti-regression: the LB internal IP must NEVER appear in
			// the log when there's an XFF (i.e., the real-prod shape).
			if tc.xff != "" {
				lbIP := strings.Split(tc.remoteAddr, ":")[0]
				if strings.Contains(out, "remote="+lbIP) {
					t.Errorf("LB internal IP %q leaked into log instead of XFF last entry; got: %q", lbIP, out)
				}
			}
			// Must NOT log the Authorization header.
			if tc.auth != "" && strings.Contains(out, tc.auth) {
				t.Errorf("Authorization header leaked into log; got: %q", out)
			}
		})
	}
}
