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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestNewReverseProxyHandler(t *testing.T) {
	tests := []struct {
		name    string
		config  ProxyConfig
		wantErr bool
	}{
		{
			name: "valid orchestrator URL",
			config: ProxyConfig{
				OrchestratorInternalURL: "http://localhost:8081",
			},
			wantErr: false,
		},
		{
			name: "valid portal URL",
			config: ProxyConfig{
				PortalInternalURL: "http://localhost:8082",
			},
			wantErr: false,
		},
		{
			name: "both URLs valid",
			config: ProxyConfig{
				OrchestratorInternalURL: "http://orchestrator:8081",
				PortalInternalURL:       "http://portal:8082",
			},
			wantErr: false,
		},
		{
			name: "empty config",
			config: ProxyConfig{},
			wantErr: false,
		},
		{
			name: "invalid orchestrator URL",
			config: ProxyConfig{
				OrchestratorInternalURL: "://invalid-url",
			},
			wantErr: true,
		},
		{
			name: "invalid portal URL",
			config: ProxyConfig{
				PortalInternalURL: "://invalid-url",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := NewReverseProxyHandler(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewReverseProxyHandler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && handler == nil {
				t.Error("NewReverseProxyHandler() returned nil handler without error")
			}
		})
	}
}

func TestProxyToOrchestrator_NotConfigured(t *testing.T) {
	handler := &ReverseProxyHandler{}

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
	w := httptest.NewRecorder()

	handler.ProxyToOrchestrator(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["error"] != "Orchestrator service not configured" {
		t.Errorf("Unexpected error message: %s", response["error"])
	}
}

func TestProxyToPortal_NotConfigured(t *testing.T) {
	handler := &ReverseProxyHandler{}

	req := httptest.NewRequest("GET", "/api/v1/code-governance/metrics", nil)
	w := httptest.NewRecorder()

	handler.ProxyToPortal(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["error"] != "Portal service not configured" {
		t.Errorf("Unexpected error message: %s", response["error"])
	}
}

func TestProxyToOrchestrator_Success(t *testing.T) {
	// Create a mock backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers are preserved
		if r.Header.Get("X-Tenant-ID") != "test-tenant" {
			t.Errorf("X-Tenant-ID header not preserved, got: %s", r.Header.Get("X-Tenant-ID"))
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization header not preserved, got: %s", r.Header.Get("Authorization"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"policies":[],"pagination":{"page":1,"page_size":20,"total_items":0,"total_pages":0}}`))
	}))
	defer backend.Close()

	handler, err := NewReverseProxyHandler(ProxyConfig{
		OrchestratorInternalURL: backend.URL,
	})
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	handler.ProxyToOrchestrator(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxyToPortal_Success(t *testing.T) {
	// Create a mock backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer backend.Close()

	handler, err := NewReverseProxyHandler(ProxyConfig{
		PortalInternalURL: backend.URL,
	})
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/portal/status", nil)
	w := httptest.NewRecorder()

	handler.ProxyToPortal(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxyToPortal_AuthLogin(t *testing.T) {
	// Create a mock backend server that simulates login response with session cookie
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify path is correct
		if r.URL.Path != "/api/v1/auth/login" {
			t.Errorf("Expected path /api/v1/auth/login, got %s", r.URL.Path)
		}

		// Verify method
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		// Simulate login response with session cookie
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session_token=abc123; HttpOnly; Path=/")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"org_id":"test-org-001"}`))
	}))
	defer backend.Close()

	handler, err := NewReverseProxyHandler(ProxyConfig{
		PortalInternalURL: backend.URL,
	})
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ProxyToPortal(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify session cookie is passed through
	cookies := w.Result().Cookies()
	foundSessionCookie := false
	for _, cookie := range cookies {
		if cookie.Name == "session_token" {
			foundSessionCookie = true
			if cookie.Value != "abc123" {
				t.Errorf("Expected session_token=abc123, got %s", cookie.Value)
			}
		}
	}
	if !foundSessionCookie {
		t.Error("Expected session_token cookie to be passed through")
	}
}

func TestProxyToPortal_AuthLogout(t *testing.T) {
	// Create a mock backend server that simulates logout
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify path is correct
		if r.URL.Path != "/api/v1/auth/logout" {
			t.Errorf("Expected path /api/v1/auth/logout, got %s", r.URL.Path)
		}

		// Verify session cookie is passed through from client
		cookie := r.Header.Get("Cookie")
		if cookie == "" {
			t.Error("Expected Cookie header to be passed through")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer backend.Close()

	handler, err := NewReverseProxyHandler(ProxyConfig{
		PortalInternalURL: backend.URL,
	})
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	req.Header.Set("Cookie", "session_token=abc123")
	w := httptest.NewRecorder()

	handler.ProxyToPortal(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxyToPortal_BackendDown(t *testing.T) {
	// Configure proxy with URL that will fail
	handler, err := NewReverseProxyHandler(ProxyConfig{
		PortalInternalURL: "http://localhost:99998", // Invalid port
	})
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	w := httptest.NewRecorder()

	handler.ProxyToPortal(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", w.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["error"] != "Backend service unavailable" {
		t.Errorf("Unexpected error message: %s", response["error"])
	}
	if response["service"] != "portal" {
		t.Errorf("Unexpected service: %s", response["service"])
	}
}

func TestProxyToOrchestrator_BackendDown(t *testing.T) {
	// Configure proxy with URL that will fail
	handler, err := NewReverseProxyHandler(ProxyConfig{
		OrchestratorInternalURL: "http://localhost:99999", // Invalid port
	})
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
	w := httptest.NewRecorder()

	handler.ProxyToOrchestrator(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", w.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["error"] != "Backend service unavailable" {
		t.Errorf("Unexpected error message: %s", response["error"])
	}
	if response["service"] != "orchestrator" {
		t.Errorf("Unexpected service: %s", response["service"])
	}
}

func TestRegisterProxyRoutes(t *testing.T) {
	handler, err := NewReverseProxyHandler(ProxyConfig{
		OrchestratorInternalURL: "http://localhost:8081",
		PortalInternalURL:       "http://localhost:8082",
	})
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	r := mux.NewRouter()
	handler.RegisterProxyRoutes(r)

	// Test that routes are registered by checking they match
	routeTests := []struct {
		method string
		path   string
		want   bool
	}{
		// Orchestrator routes
		{"GET", "/api/v1/dynamic-policies", true},
		{"POST", "/api/v1/dynamic-policies", true},
		{"GET", "/api/v1/connectors", true},
		{"GET", "/api/v1/cost/budgets", true},
		{"GET", "/api/v1/executions", true},
		{"GET", "/api/v1/llm-providers", true},
		// Portal routes
		{"POST", "/api/v1/auth/login", true},
		{"POST", "/api/v1/auth/logout", true},
		{"GET", "/api/v1/auth/session", true},
		{"GET", "/api/v1/code-governance/metrics", true},
		{"GET", "/api/v1/portal/status", true},
		{"GET", "/api/v1/git-providers", true},
		// Legacy /api/v1/policies GET is now proxied for dynamic policy reads
		{"GET", "/api/v1/policies", true},
		// Non-proxied routes should not match
		{"GET", "/health", false},
	}

	for _, tt := range routeTests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := r.Match(req, &match)

			if matched != tt.want {
				t.Errorf("Route %s %s matched=%v, want=%v", tt.method, tt.path, matched, tt.want)
			}
		})
	}
}

func TestIsProxiedPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Orchestrator paths
		{"/api/v1/dynamic-policies", true},
		{"/api/v1/dynamic-policies/123", true},
		{"/api/v1/connectors", true},
		{"/api/v1/connectors/amadeus", true},
		{"/api/v1/cost/budgets", true},
		{"/api/v1/budgets", true},
		{"/api/v1/usage", true},
		{"/api/v1/executions", true},
		{"/api/v1/executions/123", true},
		{"/api/v1/llm-providers", true},
		{"/api/v1/llm-providers/openai", true},
		// Compliance modules — all four must proxy. Missing any one here
		// is how #1646 (EU AI Act conformity 404) happened: euaiact was
		// left out of IsProxiedPath while rbi/sebi/masfeat were listed.
		{"/api/v1/euaiact/conformity", true},
		{"/api/v1/euaiact/accuracy", true},
		{"/api/v1/euaiact/export", true},
		{"/api/v1/masfeat/registry", true},
		{"/api/v1/rbi/ai-systems", true},
		{"/api/v1/sebi/dashboard", true},
		// Portal paths - auth
		{"/api/v1/auth/login", true},
		{"/api/v1/auth/logout", true},
		{"/api/v1/auth/session", true},
		// Portal paths - code governance
		{"/api/v1/code-governance/metrics", true},
		{"/api/v1/portal/status", true},
		{"/api/v1/git-providers", true},
		{"/api/v1/git-providers/github", true},
		// Non-proxied paths
		{"/api/v1/policies", false},
		{"/api/v1/static-policies", false},
		{"/health", false},
		{"/metrics", false},
		{"/api/request", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := IsProxiedPath(tt.path)
			if got != tt.want {
				t.Errorf("IsProxiedPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestGetProxyConfig(t *testing.T) {
	// Test that GetProxyConfig returns valid configuration
	// In test environment (not Docker), should return localhost URLs
	config := GetProxyConfig()

	// Should be either Docker or local URLs
	validOrchestratorURLs := map[string]bool{
		LocalOrchestratorURL:   true,
		DefaultOrchestratorURL: true,
	}
	validPortalURLs := map[string]bool{
		LocalPortalURL:   true,
		DefaultPortalURL: true,
	}

	if !validOrchestratorURLs[config.OrchestratorInternalURL] {
		t.Errorf("OrchestratorInternalURL = %s, want either %s or %s",
			config.OrchestratorInternalURL, LocalOrchestratorURL, DefaultOrchestratorURL)
	}
	if !validPortalURLs[config.PortalInternalURL] {
		t.Errorf("PortalInternalURL = %s, want either %s or %s",
			config.PortalInternalURL, LocalPortalURL, DefaultPortalURL)
	}
}

func TestProxyAuthMiddleware_CommunityModePassesThrough(t *testing.T) {
	// #3096: this used to rely on DEPLOYMENT_MODE="" being the community
	// default. Unset now means the enterprise posture, so the mode the test is
	// actually about has to be named.
	t.Setenv("DEPLOYMENT_MODE", "community")

	called := false
	handler := proxyAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/v1/audit/tenant/test", nil)
	// No auth headers — should still pass in community mode
	w := httptest.NewRecorder()

	handler(w, req)

	if !called {
		t.Error("Expected handler to be called in community mode")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

// TestProxyAuthMiddleware_OptionsIsTerminatedNotForwarded replaces
// TestProxyAuthMiddleware_OptionsPassesThrough, which asserted that OPTIONS
// "should always pass without auth" — the #3092 defect stated as a
// requirement. An unauthenticated preflight is now answered at the auth
// boundary; it is never handed to the proxy, which would append a valid
// internal HMAC to it.
func TestProxyAuthMiddleware_OptionsIsTerminatedNotForwarded(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "production")

	called := false
	handler := proxyAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("OPTIONS", "/api/v1/audit/tool-call", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if called {
		t.Error("OPTIONS must not be forwarded to the proxy handler (#3092)")
	}
	if w.Code != http.StatusNoContent {
		t.Errorf("Expected 204 for OPTIONS, got %d", w.Code)
	}
}

func TestProxyAuthMiddleware_ProductionRequiresAuth(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "production")

	called := false
	handler := proxyAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", nil)
	// No auth headers
	w := httptest.NewRecorder()

	handler(w, req)

	if called {
		t.Error("Handler should NOT be called without auth in production mode")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestProxyAuthMiddleware_ProductionInvalidCreds(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "production")

	called := false
	handler := proxyAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", nil)
	req.SetBasicAuth("nonexistent-client", "bad-secret")
	w := httptest.NewRecorder()

	handler(w, req)

	if called {
		t.Error("Handler should NOT be called with invalid credentials")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestGetProxyConfig_EnvOverrides(t *testing.T) {
	t.Setenv("ORCHESTRATOR_URL", "http://custom-orchestrator:9090")
	t.Setenv("PORTAL_URL", "http://custom-portal:9091")

	config := GetProxyConfig()

	if config.OrchestratorInternalURL != "http://custom-orchestrator:9090" {
		t.Errorf("OrchestratorInternalURL = %s, want http://custom-orchestrator:9090", config.OrchestratorInternalURL)
	}
	if config.PortalInternalURL != "http://custom-portal:9091" {
		t.Errorf("PortalInternalURL = %s, want http://custom-portal:9091", config.PortalInternalURL)
	}
}

func TestIsRunningInDocker(t *testing.T) {
	// In test environment, should detect correctly
	// We can't fully test Docker detection in non-Docker environment,
	// but we can verify the function doesn't panic
	result := isRunningInDocker()
	// Just verify it returns a boolean without panicking
	_ = result
}
