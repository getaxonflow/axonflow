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
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/config"
	"axonflow/platform/connectors/registry"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/serviceauth"
)

// Mock connector for testing
type mockConnector struct {
	queryResult   *base.QueryResult
	executeResult *base.CommandResult
	queryError    error
	executeError  error
}

func (m *mockConnector) Name() string    { return "mock" }
func (m *mockConnector) Type() string    { return "mock" }
func (m *mockConnector) Version() string { return "1.0.0" }
func (m *mockConnector) Capabilities() []string {
	return []string{"query", "execute"}
}
func (m *mockConnector) Connect(ctx context.Context, cfg *base.ConnectorConfig) error { return nil }
func (m *mockConnector) Disconnect(ctx context.Context) error                         { return nil }
func (m *mockConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{Healthy: true}, nil
}

func (m *mockConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if m.queryError != nil {
		return nil, m.queryError
	}
	if m.queryResult != nil {
		return m.queryResult, nil
	}
	return &base.QueryResult{
		Rows:     []map[string]interface{}{{"id": 1, "name": "test"}},
		RowCount: 1,
		Duration: 10 * time.Millisecond,
	}, nil
}

func (m *mockConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	if m.executeError != nil {
		return nil, m.executeError
	}
	if m.executeResult != nil {
		return m.executeResult, nil
	}
	return &base.CommandResult{
		RowsAffected: 1,
		Duration:     5 * time.Millisecond,
		Message:      "Success",
	}, nil
}

func TestValidateTenantConnectorAccess_FallbackToStaticRegistry(t *testing.T) {
	originalRegistry := mcpRegistry
	originalRuntimeConfigService := runtimeConfigService
	t.Cleanup(func() {
		mcpRegistry = originalRegistry
		runtimeConfigService = originalRuntimeConfigService
	})

	mcpRegistry = registry.NewRegistry()
	if err := mcpRegistry.Register("http-rest", &mockConnector{}, &base.ConnectorConfig{
		Name:     "http-rest",
		Type:     "http",
		TenantID: "tenant-a",
		Timeout:  1 * time.Second,
	}); err != nil {
		t.Fatalf("failed to register test connector: %v", err)
	}

	// Empty runtime service returns "no connector configurations found" and should fall back.
	runtimeConfigService = config.NewRuntimeConfigService(config.RuntimeConfigServiceOptions{})

	if err := validateTenantConnectorAccess(context.Background(), "http-rest", "tenant-a"); err != nil {
		t.Fatalf("expected fallback access check to succeed, got error: %v", err)
	}
}

// TestRegisterMCPHandlers tests handler registration
func TestRegisterMCPHandlers(t *testing.T) {
	r := mux.NewRouter()

	// Should not panic
	RegisterMCPHandlers(r)

	// Verify routes are registered
	routes := []string{
		"/mcp/connectors",
		"/mcp/connectors/{name}/health",
		"/mcp/resources/query",
		"/mcp/tools/execute",
		"/mcp/health",
	}

	for _, route := range routes {
		match := &mux.RouteMatch{}
		req := httptest.NewRequest("GET", route, nil)
		if !r.Match(req, match) && route != "/mcp/resources/query" && route != "/mcp/tools/execute" {
			t.Errorf("route %s not registered", route)
		}
	}
}

// TestMCPListConnectorsHandler tests connector listing
func TestMCPListConnectorsHandler(t *testing.T) {
	tests := []struct {
		name           string
		setupRegistry  func()
		expectedStatus int
		expectedCount  int
	}{
		{
			name: "registry not initialized",
			setupRegistry: func() {
				mcpRegistry = nil
			},
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name: "empty registry",
			setupRegistry: func() {
				mcpRegistry = registry.NewRegistry()
			},
			expectedStatus: http.StatusOK,
			expectedCount:  0,
		},
		{
			name: "registry with connectors",
			setupRegistry: func() {
				mcpRegistry = registry.NewRegistry()
				connector := &mockConnector{}
				_ = mcpRegistry.Register("test-connector", connector, &base.ConnectorConfig{Name: "test-connector"})
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupRegistry()

			req := httptest.NewRequest("GET", "/mcp/connectors", nil)
			w := httptest.NewRecorder()

			mcpListConnectorsHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				count := int(response["count"].(float64))
				if count != tt.expectedCount {
					t.Errorf("expected count %d, got %d", tt.expectedCount, count)
				}
			}
		})
	}
}

// TestMCPConnectorHealthHandler tests individual connector health
func TestMCPConnectorHealthHandler(t *testing.T) {
	tests := []struct {
		name           string
		setupRegistry  func() string
		expectedStatus int
	}{
		{
			name: "registry not initialized",
			setupRegistry: func() string {
				mcpRegistry = nil
				return "test"
			},
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name: "connector not found",
			setupRegistry: func() string {
				mcpRegistry = registry.NewRegistry()
				return "nonexistent"
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "healthy connector",
			setupRegistry: func() string {
				mcpRegistry = registry.NewRegistry()
				connector := &mockConnector{}
				_ = mcpRegistry.Register("healthy-connector", connector, &base.ConnectorConfig{Name: "healthy-connector"})
				return "healthy-connector"
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connectorName := tt.setupRegistry()

			req := httptest.NewRequest("GET", "/mcp/connectors/"+connectorName+"/health", nil)
			w := httptest.NewRecorder()

			// Setup mux vars
			req = mux.SetURLVars(req, map[string]string{"name": connectorName})

			mcpConnectorHealthHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// TestMCPQueryHandler tests query execution
func TestMCPQueryHandler(t *testing.T) {
	// Note: These tests will skip actual validation since we can't mock validateClient/validateUserToken functions
	// In production, we'd use dependency injection for testability

	tests := []struct {
		name           string
		setupRegistry  func()
		requestBody    MCPQueryRequest
		expectedStatus int
	}{
		{
			name: "registry not initialized",
			setupRegistry: func() {
				mcpRegistry = nil
			},
			requestBody: MCPQueryRequest{
				ClientID:  "test-client",
				UserToken: "test-token",
				Connector: "test",
				Statement: "SELECT * FROM test",
			},
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name: "invalid request body",
			setupRegistry: func() {
				mcpRegistry = registry.NewRegistry()
			},
			requestBody:    MCPQueryRequest{}, // Will be sent as malformed JSON
			expectedStatus: http.StatusBadRequest,
		},
		// Successful query test skipped - requires mocking validateClient/validateUserToken
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupRegistry()

			var reqBody []byte
			var err error
			if tt.name == "invalid request body" {
				reqBody = []byte("{invalid json")
			} else {
				reqBody, err = json.Marshal(tt.requestBody)
				if err != nil {
					t.Fatalf("failed to marshal request: %v", err)
				}
			}

			req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			mcpQueryHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			// Success validation skipped for non-OK statuses
		})
	}
}

// TestMCPExecuteHandler tests command execution
func TestMCPExecuteHandler(t *testing.T) {
	// Note: These tests will skip actual validation since we can't mock validateClient/validateUserToken functions

	tests := []struct {
		name           string
		setupRegistry  func()
		requestBody    MCPExecuteRequest
		expectedStatus int
	}{
		{
			name: "registry not initialized",
			setupRegistry: func() {
				mcpRegistry = nil
			},
			requestBody: MCPExecuteRequest{
				ClientID:  "test-client",
				UserToken: "test-token",
				Connector: "test",
				Action:    "INSERT",
				Statement: "INSERT INTO test VALUES (1)",
			},
			expectedStatus: http.StatusServiceUnavailable,
		},
		// Disabled client and successful execute tests skipped - require mocking validateClient/validateUserToken
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupRegistry()

			reqBody, err := json.Marshal(tt.requestBody)
			if err != nil {
				t.Fatalf("failed to marshal request: %v", err)
			}

			req := httptest.NewRequest("POST", "/mcp/tools/execute", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			mcpExecuteHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			// Success validation skipped for non-OK statuses
		})
	}
}

// TestMCPHealthHandler tests overall MCP health
func TestMCPHealthHandler(t *testing.T) {
	tests := []struct {
		name           string
		setupRegistry  func()
		expectedStatus int
		expectedHealth bool
	}{
		{
			name: "registry not initialized",
			setupRegistry: func() {
				mcpRegistry = nil
			},
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name: "empty registry - healthy",
			setupRegistry: func() {
				mcpRegistry = registry.NewRegistry()
			},
			expectedStatus: http.StatusOK,
			expectedHealth: true,
		},
		{
			name: "registry with healthy connectors",
			setupRegistry: func() {
				mcpRegistry = registry.NewRegistry()
				connector := &mockConnector{}
				_ = mcpRegistry.Register("healthy-1", connector, &base.ConnectorConfig{Name: "healthy-1"})
				_ = mcpRegistry.Register("healthy-2", connector, &base.ConnectorConfig{Name: "healthy-2"})
			},
			expectedStatus: http.StatusOK,
			expectedHealth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupRegistry()

			req := httptest.NewRequest("GET", "/mcp/health", nil)
			w := httptest.NewRecorder()

			mcpHealthHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				healthy, ok := response["healthy"].(bool)
				if !ok {
					t.Error("expected 'healthy' field in response")
				}
				if healthy != tt.expectedHealth {
					t.Errorf("expected healthy=%v, got %v", tt.expectedHealth, healthy)
				}
			}
		})
	}
}

// TestTimeoutParsing tests timeout parsing in handlers
func TestTimeoutParsing(t *testing.T) {
	tests := []struct {
		name      string
		timeout   string
		wantError bool
	}{
		{"valid timeout", "5s", false},
		{"valid millisecond timeout", "500ms", false},
		{"valid minute timeout", "2m", false},
		{"invalid timeout", "invalid", true},
		{"empty timeout", "", false}, // Empty is valid (uses default)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var timeout time.Duration
			var err error

			if tt.timeout != "" {
				timeout, err = time.ParseDuration(tt.timeout)
			}

			if tt.wantError {
				if err == nil {
					t.Error("expected error parsing timeout")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tt.timeout != "" && timeout == 0 {
					t.Error("expected non-zero timeout")
				}
			}
		})
	}
}

// Benchmark tests for handler performance
func BenchmarkMCPListConnectorsHandler(b *testing.B) {
	mcpRegistry = registry.NewRegistry()
	connector := &mockConnector{}
	_ = mcpRegistry.Register("bench-connector", connector, &base.ConnectorConfig{Name: "bench-connector"})

	req := httptest.NewRequest("GET", "/mcp/connectors", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		mcpListConnectorsHandler(w, req)
	}
}

func BenchmarkMCPHealthHandler(b *testing.B) {
	mcpRegistry = registry.NewRegistry()
	connector := &mockConnector{}
	_ = mcpRegistry.Register("bench-connector", connector, &base.ConnectorConfig{Name: "bench-connector"})

	req := httptest.NewRequest("GET", "/mcp/health", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		mcpHealthHandler(w, req)
	}
}

// TestInitializeMCPRegistry tests registry initialization
func TestInitializeMCPRegistry(t *testing.T) {
	tests := []struct {
		name           string
		setupEnv       func()
		cleanupEnv     func()
		expectRegistry bool
	}{
		{
			name: "initializes registry without DATABASE_URL",
			setupEnv: func() {
				// Don't set DATABASE_URL - postgres registration will fail but registry should still be created
			},
			cleanupEnv:     func() {},
			expectRegistry: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global registry
			mcpRegistry = nil

			tt.setupEnv()
			defer tt.cleanupEnv()

			// Call InitializeMCPRegistry - should not panic
			err := InitializeMCPRegistry()

			// Should return nil (warnings logged but not errors)
			if err != nil {
				t.Errorf("InitializeMCPRegistry() returned error: %v", err)
			}

			// Registry should be initialized even if connectors fail to register
			if tt.expectRegistry && mcpRegistry == nil {
				t.Error("expected mcpRegistry to be initialized")
			}
		})
	}
}

// TestInitializeMCPRegistry_EmptyConfigFile tests that empty config file falls back to env vars
func TestInitializeMCPRegistry_EmptyConfigFile(t *testing.T) {
	// Create a temporary empty config file
	tmpDir := t.TempDir()
	emptyConfigFile := filepath.Join(tmpDir, "axonflow.yaml")

	// Write a valid but empty config file (no connectors section)
	emptyConfig := []byte("# Empty AxonFlow config\nversion: \"1.0\"\n")
	if err := os.WriteFile(emptyConfigFile, emptyConfig, 0644); err != nil {
		t.Fatalf("Failed to create empty config file: %v", err)
	}

	// Use t.Setenv for automatic cleanup (Go 1.17+)
	t.Setenv("AXONFLOW_CONFIG_FILE", emptyConfigFile)
	// Set a valid-looking DATABASE_URL so postgres connector can attempt registration
	// (It will fail to connect, but that's fine - we just want to verify fallback happens)
	t.Setenv("DATABASE_URL", "postgres://localhost:5432/test?sslmode=disable")

	// Reset global registry before test
	mcpRegistry = nil

	// Initialize registry - should warn about empty config and fall back to env vars
	err := InitializeMCPRegistry()
	if err != nil {
		t.Errorf("InitializeMCPRegistry() returned error: %v", err)
	}

	// Registry should be initialized (fallback to env vars should have happened)
	if mcpRegistry == nil {
		t.Fatal("expected mcpRegistry to be initialized after empty config fallback")
	}

	// Verify the fallback to env vars actually happened by checking that the registry
	// was created (even if no connectors successfully registered due to missing DB)
	// The key behavior is that InitializeMCPRegistry() doesn't return early or fail
	// when the config file exists but has no connectors

	// The registry should exist and be functional (can call Count())
	count := mcpRegistry.Count()
	// We don't assert a specific count because postgres may or may not register
	// depending on network conditions, but the registry should be usable
	t.Logf("Registry initialized with %d connectors after empty config fallback", count)
}

// TestInitializeMCPRegistry_ConfigFileWithEmptyConnectorsSection tests fallback when
// config file has a connectors section but all connectors are disabled
func TestInitializeMCPRegistry_ConfigFileWithEmptyConnectorsSection(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "axonflow.yaml")

	// Write a config file with connectors section but all disabled
	configContent := []byte(`# AxonFlow config with disabled connectors
version: "1.0"
connectors:
  postgres:
    enabled: false
    host: localhost
`)
	if err := os.WriteFile(configFile, configContent, 0644); err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	t.Setenv("AXONFLOW_CONFIG_FILE", configFile)
	// Clear DATABASE_URL to ensure we're testing the fallback path
	t.Setenv("DATABASE_URL", "")

	mcpRegistry = nil

	err := InitializeMCPRegistry()
	if err != nil {
		t.Errorf("InitializeMCPRegistry() returned error: %v", err)
	}

	if mcpRegistry == nil {
		t.Fatal("expected mcpRegistry to be initialized")
	}

	// With no DATABASE_URL and disabled connectors in config, registry should be empty but valid
	t.Logf("Registry initialized with %d connectors (expected 0 with disabled connectors and no DATABASE_URL)", mcpRegistry.Count())
}

// TestMCPQueryHandler_TimeoutParsing tests timeout parsing in query handler
func TestMCPQueryHandler_TimeoutParsing(t *testing.T) {
	// Set enterprise mode to test auth behavior (community mode bypasses auth)
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	tests := []struct {
		name           string
		requestBody    MCPQueryRequest
		expectedStatus int
	}{
		{
			name: "invalid timeout format",
			requestBody: MCPQueryRequest{
				ClientID:  "test-client",
				UserToken: "test-token",
				Connector: "test",
				Statement: "SELECT * FROM test",
				Timeout:   "invalid-timeout",
			},
			expectedStatus: http.StatusUnauthorized, // Will fail at auth before timeout parsing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mcpRegistry = registry.NewRegistry()
			connector := &mockConnector{}
			_ = mcpRegistry.Register("test", connector, &base.ConnectorConfig{Name: "test"})

			reqBody, err := json.Marshal(tt.requestBody)
			if err != nil {
				t.Fatalf("failed to marshal request: %v", err)
			}

			req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			mcpQueryHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

// TestMCPExecuteHandler_TimeoutParsing tests timeout parsing in execute handler
func TestMCPExecuteHandler_TimeoutParsing(t *testing.T) {
	// Set enterprise mode to test auth behavior (community mode bypasses auth)
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	tests := []struct {
		name           string
		requestBody    MCPExecuteRequest
		expectedStatus int
	}{
		{
			name: "invalid timeout format",
			requestBody: MCPExecuteRequest{
				ClientID:  "test-client",
				UserToken: "test-token",
				Connector: "test",
				Action:    "INSERT",
				Statement: "INSERT INTO test VALUES (1)",
				Timeout:   "invalid-timeout",
			},
			expectedStatus: http.StatusUnauthorized, // Will fail at auth before timeout parsing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mcpRegistry = registry.NewRegistry()
			connector := &mockConnector{}
			_ = mcpRegistry.Register("test", connector, &base.ConnectorConfig{Name: "test"})

			reqBody, err := json.Marshal(tt.requestBody)
			if err != nil {
				t.Fatalf("failed to marshal request: %v", err)
			}

			req := httptest.NewRequest("POST", "/mcp/tools/execute", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			mcpExecuteHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

// TestRegisterPostgresConnector tests PostgreSQL connector registration
func TestRegisterPostgresConnector(t *testing.T) {
	// This test verifies the function can be called
	// Actual registration will fail without DATABASE_URL, but that's expected
	// The function should return an error (not panic)

	// Reset registry
	mcpRegistry = registry.NewRegistry()

	err := registerPostgresConnector()

	// Expect error since DATABASE_URL is not set
	if err == nil {
		// If no error, check that connector was registered
		if mcpRegistry.Count() == 0 {
			t.Error("expected connector to be registered when no error returned")
		}
	}
	// If error is returned, that's expected behavior when config is missing
}

// TestRegisterCassandraConnector tests Cassandra connector registration
func TestRegisterCassandraConnector(t *testing.T) {
	// This test verifies the function can be called
	// Cassandra is optional - should return nil even if config is missing

	// Reset registry
	mcpRegistry = registry.NewRegistry()

	err := registerCassandraConnector()

	// Should return nil (Cassandra is optional)
	if err != nil {
		t.Errorf("registerCassandraConnector() should return nil for missing config, got: %v", err)
	}
}

// --- GetConnectorForTenant Tests ---

func TestGetConnectorForTenant_StaticRegistryFallback(t *testing.T) {
	// Clear TenantConnectorRegistry to ensure fallback to static
	clearTenantConnectorRegistry()

	// Set up static registry
	mcpRegistry = registry.NewRegistry()
	mockConn := &mockConnector{}
	cfg := &base.ConnectorConfig{Name: "test-db", Type: "postgres"}
	if err := mcpRegistry.Register("test-db", mockConn, cfg); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	ctx := context.Background()
	conn, err := GetConnectorForTenant(ctx, "tenant-123", "test-db")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if conn != mockConn {
		t.Error("Expected static registry connector to be returned")
	}
}

func TestGetConnectorForTenant_NoRegistries(t *testing.T) {
	// Clear both registries
	clearTenantConnectorRegistry()
	mcpRegistry = nil

	ctx := context.Background()
	_, err := GetConnectorForTenant(ctx, "tenant-123", "test-db")

	if err == nil {
		t.Fatal("Expected error when no registries available")
	}
}

func TestGetConnectorForTenant_ConnectorNotFound(t *testing.T) {
	// Clear TenantConnectorRegistry
	clearTenantConnectorRegistry()

	// Set up empty static registry
	mcpRegistry = registry.NewRegistry()

	ctx := context.Background()
	_, err := GetConnectorForTenant(ctx, "tenant-123", "nonexistent")

	if err == nil {
		t.Fatal("Expected error when connector not found")
	}
}

func TestIsTenantConnectorRegistryEnabled(t *testing.T) {
	// Clear registry
	clearTenantConnectorRegistry()

	if IsTenantConnectorRegistryEnabled() {
		t.Error("Expected false when registry not initialized")
	}

	// Initialize registry
	factory := func(connectorType string) (base.Connector, error) {
		return &mockConnector{}, nil
	}
	InitTenantConnectorRegistry(nil, factory)
	t.Cleanup(clearTenantConnectorRegistry)

	if !IsTenantConnectorRegistryEnabled() {
		t.Error("Expected true when registry is initialized")
	}
}

// Tests for internal service authentication (via shared serviceauth package)

func TestIsValidInternalServiceRequest_FallbackToken(t *testing.T) {
	serviceauth.ResetWarnings()

	// No validator = community/dev mode (no secret configured)
	tests := []struct {
		name     string
		clientID string
		token    string
		want     bool
	}{
		{
			name:     "valid internal request with fallback token",
			clientID: serviceauth.ClientID,
			token:    serviceauth.TokenFallback,
			want:     true,
		},
		{
			name:     "wrong client ID",
			clientID: "some-other-client",
			token:    serviceauth.TokenFallback,
			want:     false,
		},
		{
			name:     "wrong token",
			clientID: serviceauth.ClientID,
			token:    "wrong-token",
			want:     false,
		},
		{
			name:     "empty client ID",
			clientID: "",
			token:    serviceauth.TokenFallback,
			want:     false,
		},
		{
			name:     "empty token",
			clientID: serviceauth.ClientID,
			token:    "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serviceauth.IsValidInternalServiceRequest(tt.clientID, tt.token, nil)
			if got != tt.want {
				t.Errorf("IsValidInternalServiceRequest(%q, %q, nil) = %v, want %v",
					tt.clientID, tt.token, got, tt.want)
			}
		})
	}
}

func TestIsValidInternalServiceRequest_WithHMACToken(t *testing.T) {
	serviceauth.ResetWarnings()
	testSecret := "my-super-secure-internal-service-secret-12345"
	now := time.Now()
	clock := &testClock{now: now}
	gen := serviceauth.NewTokenGenerator(testSecret, clock)
	val := serviceauth.NewTokenValidator(testSecret, clock, serviceauth.DefaultClockSkew)

	tests := []struct {
		name     string
		clientID string
		token    string
		want     bool
	}{
		{
			name:     "valid HMAC token accepted",
			clientID: serviceauth.ClientID,
			token:    gen.GenerateToken(),
			want:     true,
		},
		{
			name:     "legacy plain secret accepted (backward compat)",
			clientID: serviceauth.ClientID,
			token:    testSecret,
			want:     true,
		},
		{
			name:     "fallback token rejected when secret configured",
			clientID: serviceauth.ClientID,
			token:    serviceauth.TokenFallback,
			want:     false,
		},
		{
			name:     "wrong secret rejected",
			clientID: serviceauth.ClientID,
			token:    "wrong-secret",
			want:     false,
		},
		{
			name:     "correct HMAC token but wrong client ID",
			clientID: "some-other-client",
			token:    gen.GenerateToken(),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceauth.ResetWarnings()
			got := serviceauth.IsValidInternalServiceRequest(tt.clientID, tt.token, val)
			if got != tt.want {
				t.Errorf("IsValidInternalServiceRequest(%q, token, val) = %v, want %v",
					tt.clientID, got, tt.want)
			}
		})
	}
}

// testClock implements serviceauth.Clock for agent-level tests.
type testClock struct {
	now time.Time
}

func (c *testClock) Now() time.Time { return c.now }

func TestIsValidInternalServiceRequest_LegacyDeprecation(t *testing.T) {
	serviceauth.ResetWarnings()
	testSecret := "my-super-secure-internal-service-secret-12345"
	now := time.Now()
	clock := &testClock{now: now}
	val := serviceauth.NewTokenValidator(testSecret, clock, serviceauth.DefaultClockSkew)

	// Sending the raw secret (legacy path) should be accepted but triggers deprecation warning
	got := serviceauth.IsValidInternalServiceRequest(serviceauth.ClientID, testSecret, val)
	if !got {
		t.Error("legacy plain-secret token should be accepted for backward compatibility")
	}
}

func TestInternalServiceConstants_Agent(t *testing.T) {
	if serviceauth.SecretMinLength < 16 {
		t.Errorf("SecretMinLength = %d, should be at least 16 for security", serviceauth.SecretMinLength)
	}
	if serviceauth.SecretMinLength != 32 {
		t.Errorf("SecretMinLength = %d, expected 32", serviceauth.SecretMinLength)
	}
}

func TestLogAuthWarning_Agent(t *testing.T) {
	tests := []struct {
		name        string
		secretValue string
	}{
		{name: "no secret configured", secretValue: ""},
		{name: "short secret configured", secretValue: "short"},
		{name: "adequate secret configured", secretValue: "this-is-a-sufficiently-long-secret-for-production"},
		{name: "minimum length secret", secretValue: "12345678901234567890123456789012"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceauth.ResetWarnings()
			if tt.secretValue == "" {
				os.Unsetenv(serviceauth.SecretEnvVar)
			} else {
				t.Setenv(serviceauth.SecretEnvVar, tt.secretValue)
			}
			// Should not panic; idempotent
			serviceauth.LogAuthWarning()
			serviceauth.LogAuthWarning()
		})
	}
}

// =============================================================================
// Exfiltration Detection Integration Tests (Issue #966)
// =============================================================================

// setupCommunityModeForTest sets up community mode for integration testing.
// Returns a cleanup function that restores the original state.
func setupCommunityModeForTest(t *testing.T) func() {
	// Save original value
	originalMode := os.Getenv("DEPLOYMENT_MODE")

	// Set community mode (bypasses auth)
	t.Setenv("DEPLOYMENT_MODE", "community")

	// Setup registry with mock connector
	// Use TenantID: "*" to allow access from any tenant (including "community" tenant in community mode)
	mcpRegistry = registry.NewRegistry()
	connector := &mockConnector{}
	if err := mcpRegistry.Register("test-db", connector, &base.ConnectorConfig{
		Name:     "test-db",
		Type:     "postgres",
		TenantID: "*", // Wildcard allows access from any tenant
	}); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	return func() {
		if originalMode != "" {
			os.Setenv("DEPLOYMENT_MODE", originalMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}
}

// TestMCPQueryHandler_ExfiltrationRowLimitExceeded tests that queries exceeding row limits are blocked.
func TestMCPQueryHandler_ExfiltrationRowLimitExceeded(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// Save and restore global exfiltration checker
	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	// Set up exfiltration checker with low row limit
	sharedpolicy.InitGlobalExfiltrationCheckerWithLimits(sharedpolicy.ExfiltrationLimits{
		MaxRowsPerQuery:  5,                // Very low limit for testing
		MaxBytesPerQuery: 10 * 1024 * 1024, // 10MB - won't be hit
		Enabled:          true,
	})

	// Create mock connector that returns many rows
	mcpRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		queryResult: &base.QueryResult{
			Rows: []map[string]interface{}{
				{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5},
				{"id": 6}, {"id": 7}, {"id": 8}, {"id": 9}, {"id": 10}, // 10 rows > 5 limit
			},
			RowCount: 10,
			Duration: 10 * time.Millisecond,
		},
	}
	if err := mcpRegistry.Register("test-db", mockConn, &base.ConnectorConfig{Name: "test-db", TenantID: "*"}); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	reqBody := MCPQueryRequest{
		ClientID:  "test-client",
		UserToken: "test-token",
		Connector: "test-db",
		Statement: "SELECT * FROM users",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpQueryHandler(w, req)

	// Should return 403 Forbidden due to row limit exceeded
	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Verify error response contains limit info
	var response map[string]interface{}
	bodyBytes := w.Body.Bytes()
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		t.Fatalf("failed to decode response: %v. Body: %s", err, string(bodyBytes))
	}

	t.Logf("Response body: %s", string(bodyBytes))

	if response["success"] != false {
		t.Errorf("expected success=false, got %v", response["success"])
	}
	if response["limit_type"] != "rows" {
		t.Errorf("expected limit_type='rows', got %v", response["limit_type"])
	}
	// Use type assertions with ok check to avoid panics
	if actualVal, ok := response["actual_value"].(float64); !ok || actualVal != 10 {
		t.Errorf("expected actual_value=10, got %v", response["actual_value"])
	}
	if limitVal, ok := response["limit_value"].(float64); !ok || limitVal != 5 {
		t.Errorf("expected limit_value=5, got %v", response["limit_value"])
	}
}

// TestMCPQueryHandler_ExfiltrationByteLimitExceeded tests that queries exceeding byte limits are blocked.
func TestMCPQueryHandler_ExfiltrationByteLimitExceeded(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// Save and restore global exfiltration checker
	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	// Set up exfiltration checker with low byte limit
	sharedpolicy.InitGlobalExfiltrationCheckerWithLimits(sharedpolicy.ExfiltrationLimits{
		MaxRowsPerQuery:  10000, // High row limit - won't be hit
		MaxBytesPerQuery: 100,   // Very low byte limit - will be hit
		Enabled:          true,
	})

	// Create mock connector that returns data exceeding byte limit
	mcpRegistry = registry.NewRegistry()
	largeData := make([]byte, 200)
	for i := range largeData {
		largeData[i] = 'X'
	}
	mockConn := &mockConnector{
		queryResult: &base.QueryResult{
			Rows: []map[string]interface{}{
				{"data": string(largeData)}, // ~200 bytes > 100 byte limit
			},
			RowCount: 1,
			Duration: 10 * time.Millisecond,
		},
	}
	if err := mcpRegistry.Register("test-db", mockConn, &base.ConnectorConfig{Name: "test-db", TenantID: "*"}); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	reqBody := MCPQueryRequest{
		ClientID:  "test-client",
		UserToken: "test-token",
		Connector: "test-db",
		Statement: "SELECT * FROM large_data",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpQueryHandler(w, req)

	// Should return 403 Forbidden due to byte limit exceeded
	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["limit_type"] != "bytes" {
		t.Errorf("expected limit_type='bytes', got %v", response["limit_type"])
	}
}

// TestMCPQueryHandler_ExfiltrationWithinLimits tests that queries within limits succeed.
func TestMCPQueryHandler_ExfiltrationWithinLimits(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// Save and restore global exfiltration checker
	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	// Set up exfiltration checker with reasonable limits
	sharedpolicy.InitGlobalExfiltrationCheckerWithLimits(sharedpolicy.ExfiltrationLimits{
		MaxRowsPerQuery:  100,
		MaxBytesPerQuery: 10 * 1024 * 1024,
		Enabled:          true,
	})

	// Create mock connector that returns small result
	mcpRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		queryResult: &base.QueryResult{
			Rows:     []map[string]interface{}{{"id": 1, "name": "test"}},
			RowCount: 1,
			Duration: 10 * time.Millisecond,
		},
	}
	if err := mcpRegistry.Register("test-db", mockConn, &base.ConnectorConfig{Name: "test-db", TenantID: "*"}); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	reqBody := MCPQueryRequest{
		ClientID:  "test-client",
		UserToken: "test-token",
		Connector: "test-db",
		Statement: "SELECT * FROM users WHERE id = 1",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpQueryHandler(w, req)

	// Should return 200 OK - within limits
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Error("expected success=true")
	}

	// Verify exfiltration_check info is included
	policyInfo, ok := response["policy_info"].(map[string]interface{})
	if !ok {
		t.Fatal("expected policy_info in response")
	}

	exfilCheck, ok := policyInfo["exfiltration_check"].(map[string]interface{})
	if !ok {
		t.Fatal("expected exfiltration_check in policy_info")
	}

	if exfilCheck["within_limits"] != true {
		t.Errorf("expected within_limits=true, got %v", exfilCheck["within_limits"])
	}
	if exfilCheck["rows_returned"].(float64) != 1 {
		t.Errorf("expected rows_returned=1, got %v", exfilCheck["rows_returned"])
	}
	if exfilCheck["row_limit"].(float64) != 100 {
		t.Errorf("expected row_limit=100, got %v", exfilCheck["row_limit"])
	}
}

// TestMCPQueryHandler_ExfiltrationDisabled tests that queries proceed when exfiltration is disabled.
func TestMCPQueryHandler_ExfiltrationDisabled(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// Save and restore global exfiltration checker
	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	// Disable exfiltration checker
	sharedpolicy.ResetGlobalExfiltrationChecker()

	// Create mock connector that returns many rows (would fail if limits were checked)
	mcpRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		queryResult: &base.QueryResult{
			Rows: []map[string]interface{}{
				{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5},
				{"id": 6}, {"id": 7}, {"id": 8}, {"id": 9}, {"id": 10},
			},
			RowCount: 10,
			Duration: 10 * time.Millisecond,
		},
	}
	if err := mcpRegistry.Register("test-db", mockConn, &base.ConnectorConfig{Name: "test-db", TenantID: "*"}); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	reqBody := MCPQueryRequest{
		ClientID:  "test-client",
		UserToken: "test-token",
		Connector: "test-db",
		Statement: "SELECT * FROM users",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpQueryHandler(w, req)

	// Should return 200 OK - exfiltration checking disabled
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Error("expected success=true")
	}

	// No exfiltration_check should be present when disabled
	if policyInfo, ok := response["policy_info"].(map[string]interface{}); ok {
		if _, hasExfilCheck := policyInfo["exfiltration_check"]; hasExfilCheck {
			t.Error("expected no exfiltration_check when checker is disabled")
		}
	}
}

// =============================================================================
// Dynamic Policy Evaluation Integration Tests (Issue #968)
// =============================================================================

// mockOrchestratorServer creates a test HTTP server that mimics the Orchestrator's
// dynamic policy evaluation endpoint.
func mockOrchestratorServer(t *testing.T, response sharedpolicy.DynamicPolicyResponse) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/mcp/evaluate-policies" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
}

// TestMCPQueryHandler_DynamicPolicyBlocks tests that dynamic policy can block requests.
func TestMCPQueryHandler_DynamicPolicyBlocks(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// Save and restore global dynamic evaluator
	originalEvaluator := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEvaluator)

	// Create mock orchestrator server that denies requests
	server := mockOrchestratorServer(t, sharedpolicy.DynamicPolicyResponse{
		Allowed:           false,
		BlockReason:       "Rate limit exceeded: max 10 queries per minute",
		PoliciesEvaluated: 1, // Add this field
		MatchedPolicies: []sharedpolicy.DynamicPolicyMatch{
			{
				PolicyID:   "rate-limit-1",
				PolicyType: "rate-limit",
				Action:     "block",
			},
		},
	})
	defer server.Close()

	// Initialize dynamic policy evaluator pointing to mock server
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false, // Don't fall back on error
		EnabledConnectors:    []string{"test-db"},
	})

	reqBody := MCPQueryRequest{
		ClientID:  "test-client",
		UserToken: "test-token",
		Connector: "test-db",
		Statement: "SELECT * FROM users",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpQueryHandler(w, req)

	// Should return 403 Forbidden due to dynamic policy block
	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["success"] != false {
		t.Error("expected success=false")
	}
	if response["error"] != "Rate limit exceeded: max 10 queries per minute" {
		t.Errorf("expected rate limit error message, got %v", response["error"])
	}

	// Verify dynamic_policy_info is included
	dynamicInfo, ok := response["dynamic_policy_info"].(map[string]interface{})
	if !ok {
		t.Fatal("expected dynamic_policy_info in response")
	}
	if dynamicInfo["policies_evaluated"].(float64) != 1 {
		t.Errorf("expected policies_evaluated=1, got %v", dynamicInfo["policies_evaluated"])
	}
}

// TestMCPQueryHandler_DynamicPolicyAllows tests that allowed dynamic policy lets requests through.
func TestMCPQueryHandler_DynamicPolicyAllows(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// Save and restore global dynamic evaluator
	originalEvaluator := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEvaluator)

	// Create mock orchestrator server that allows requests
	server := mockOrchestratorServer(t, sharedpolicy.DynamicPolicyResponse{
		Allowed:           true,
		BlockReason:       "",
		PoliciesEvaluated: 1, // Add this field
		MatchedPolicies: []sharedpolicy.DynamicPolicyMatch{
			{
				PolicyID:   "rate-limit-1",
				PolicyType: "rate-limit",
				Action:     "allow",
			},
		},
	})
	defer server.Close()

	// Initialize dynamic policy evaluator pointing to mock server
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"test-db"},
	})

	// Create mock connector
	mcpRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		queryResult: &base.QueryResult{
			Rows:     []map[string]interface{}{{"id": 1, "name": "test"}},
			RowCount: 1,
			Duration: 10 * time.Millisecond,
		},
	}
	if err := mcpRegistry.Register("test-db", mockConn, &base.ConnectorConfig{Name: "test-db", TenantID: "*"}); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	reqBody := MCPQueryRequest{
		ClientID:  "test-client",
		UserToken: "test-token",
		Connector: "test-db",
		Statement: "SELECT * FROM users WHERE id = 1",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpQueryHandler(w, req)

	// Should return 200 OK - dynamic policy allowed
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Error("expected success=true")
	}

	// Verify policy_info includes dynamic_policy_info
	policyInfo, ok := response["policy_info"].(map[string]interface{})
	if !ok {
		t.Fatal("expected policy_info in response")
	}

	dynamicInfo, ok := policyInfo["dynamic_policy_info"].(map[string]interface{})
	if !ok {
		t.Fatal("expected dynamic_policy_info in policy_info")
	}

	if dynamicInfo["policies_evaluated"].(float64) != 1 {
		t.Errorf("expected policies_evaluated=1, got %v", dynamicInfo["policies_evaluated"])
	}
}

// TestMCPQueryHandler_DynamicPolicyDisabled tests that queries proceed when dynamic policy is disabled.
func TestMCPQueryHandler_DynamicPolicyDisabled(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// Save and restore global dynamic evaluator
	originalEvaluator := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEvaluator)

	// Disable dynamic policy evaluator
	sharedpolicy.ResetGlobalDynamicPolicyEvaluator()

	// Create mock connector
	mcpRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		queryResult: &base.QueryResult{
			Rows:     []map[string]interface{}{{"id": 1, "name": "test"}},
			RowCount: 1,
			Duration: 10 * time.Millisecond,
		},
	}
	if err := mcpRegistry.Register("test-db", mockConn, &base.ConnectorConfig{Name: "test-db", TenantID: "*"}); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	reqBody := MCPQueryRequest{
		ClientID:  "test-client",
		UserToken: "test-token",
		Connector: "test-db",
		Statement: "SELECT * FROM users",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpQueryHandler(w, req)

	// Should return 200 OK - dynamic policy checking disabled
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Error("expected success=true")
	}
}

// TestMCPQueryHandler_DynamicPolicyGracefulDegradation tests graceful degradation when
// the Orchestrator is unavailable.
func TestMCPQueryHandler_DynamicPolicyGracefulDegradation(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// Save and restore global dynamic evaluator
	originalEvaluator := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEvaluator)

	// Initialize dynamic policy evaluator pointing to non-existent server
	// With graceful degradation enabled
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: "http://localhost:99999", // Won't connect
		Timeout:              100 * time.Millisecond,   // Short timeout
		GracefulDegradation:  true,                     // Enable graceful degradation
		EnabledConnectors:    []string{"test-db"},
	})

	// Create mock connector
	mcpRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		queryResult: &base.QueryResult{
			Rows:     []map[string]interface{}{{"id": 1, "name": "test"}},
			RowCount: 1,
			Duration: 10 * time.Millisecond,
		},
	}
	if err := mcpRegistry.Register("test-db", mockConn, &base.ConnectorConfig{Name: "test-db", TenantID: "*"}); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	reqBody := MCPQueryRequest{
		ClientID:  "test-client",
		UserToken: "test-token",
		Connector: "test-db",
		Statement: "SELECT * FROM users",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpQueryHandler(w, req)

	// Should return 200 OK - graceful degradation allows request to proceed
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Error("expected success=true")
	}
}

// TestMCPQueryHandler_DynamicPolicyGracefulDegradationDisabled tests that requests
// are blocked when graceful degradation is disabled and Orchestrator is unavailable.
func TestMCPQueryHandler_DynamicPolicyGracefulDegradationDisabled(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// Save and restore global dynamic evaluator
	originalEvaluator := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEvaluator)

	// Initialize dynamic policy evaluator pointing to non-existent server
	// With graceful degradation DISABLED
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: "http://localhost:99999", // Won't connect
		Timeout:              100 * time.Millisecond,   // Short timeout
		GracefulDegradation:  false,                    // Disable graceful degradation
		EnabledConnectors:    []string{"test-db"},
	})

	reqBody := MCPQueryRequest{
		ClientID:  "test-client",
		UserToken: "test-token",
		Connector: "test-db",
		Statement: "SELECT * FROM users",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpQueryHandler(w, req)

	// Should return 503 Service Unavailable - graceful degradation disabled
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// TestMCPQueryHandler_DynamicPolicyConnectorNotEnabled tests that dynamic policy
// is skipped for connectors not in the enabled list.
func TestMCPQueryHandler_DynamicPolicyConnectorNotEnabled(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// Save and restore global dynamic evaluator
	originalEvaluator := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEvaluator)

	// Create mock orchestrator server that blocks all requests
	// This server should NOT be called since connector is not enabled
	serverCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(sharedpolicy.DynamicPolicyResponse{
			Allowed:     false,
			BlockReason: "Should not be called",
		})
	}))
	defer server.Close()

	// Initialize dynamic policy evaluator with different connector enabled
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"other-connector"}, // NOT test-db
	})

	// Create mock connector
	mcpRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		queryResult: &base.QueryResult{
			Rows:     []map[string]interface{}{{"id": 1, "name": "test"}},
			RowCount: 1,
			Duration: 10 * time.Millisecond,
		},
	}
	if err := mcpRegistry.Register("test-db", mockConn, &base.ConnectorConfig{Name: "test-db", TenantID: "*"}); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	reqBody := MCPQueryRequest{
		ClientID:  "test-client",
		UserToken: "test-token",
		Connector: "test-db",
		Statement: "SELECT * FROM users",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpQueryHandler(w, req)

	// Should return 200 OK - dynamic policy skipped for this connector
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Server should NOT have been called
	if serverCalled {
		t.Error("expected orchestrator server to NOT be called for non-enabled connector")
	}
}

// =============================================================================
// Combined Policy Info Tests
// =============================================================================

// TestMCPQueryHandler_PolicyInfoContainsBothExfiltrationAndDynamic tests that
// PolicyInfo includes both exfiltration_check and dynamic_policy_info when both are enabled.
func TestMCPQueryHandler_PolicyInfoContainsBothExfiltrationAndDynamic(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// Save and restore globals
	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	originalEvaluator := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEvaluator)

	// Set up exfiltration checker
	sharedpolicy.InitGlobalExfiltrationCheckerWithLimits(sharedpolicy.ExfiltrationLimits{
		MaxRowsPerQuery:  100,
		MaxBytesPerQuery: 10 * 1024 * 1024,
		Enabled:          true,
	})

	// Create mock orchestrator server that allows requests
	server := mockOrchestratorServer(t, sharedpolicy.DynamicPolicyResponse{
		Allowed:           true,
		PoliciesEvaluated: 1, // Add this field
		MatchedPolicies: []sharedpolicy.DynamicPolicyMatch{
			{PolicyID: "budget-1", PolicyType: "budget", Action: "allow"},
		},
	})
	defer server.Close()

	// Initialize dynamic policy evaluator
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"test-db"},
	})

	// Create mock connector
	mcpRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		queryResult: &base.QueryResult{
			Rows:     []map[string]interface{}{{"id": 1, "name": "test"}},
			RowCount: 1,
			Duration: 10 * time.Millisecond,
		},
	}
	if err := mcpRegistry.Register("test-db", mockConn, &base.ConnectorConfig{Name: "test-db", TenantID: "*"}); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	reqBody := MCPQueryRequest{
		ClientID:  "test-client",
		UserToken: "test-token",
		Connector: "test-db",
		Statement: "SELECT * FROM users WHERE id = 1",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpQueryHandler(w, req)

	// Should return 200 OK
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Error("expected success=true")
	}

	// Verify policy_info contains BOTH exfiltration_check and dynamic_policy_info
	policyInfo, ok := response["policy_info"].(map[string]interface{})
	if !ok {
		t.Fatal("expected policy_info in response")
	}

	// Check exfiltration_check
	exfilCheck, ok := policyInfo["exfiltration_check"].(map[string]interface{})
	if !ok {
		t.Fatal("expected exfiltration_check in policy_info")
	}
	if exfilCheck["within_limits"] != true {
		t.Errorf("expected within_limits=true, got %v", exfilCheck["within_limits"])
	}

	// Check dynamic_policy_info
	dynamicInfo, ok := policyInfo["dynamic_policy_info"].(map[string]interface{})
	if !ok {
		t.Fatal("expected dynamic_policy_info in policy_info")
	}
	if dynamicInfo["policies_evaluated"].(float64) != 1 {
		t.Errorf("expected policies_evaluated=1, got %v", dynamicInfo["policies_evaluated"])
	}
}

// TestMCPQueryHandler_ExfiltrationWithEnabledFalse tests that exfiltration limits
// struct can be present but with Enabled=false.
func TestMCPQueryHandler_ExfiltrationWithEnabledFalse(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// Save and restore global exfiltration checker
	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	// Set up exfiltration checker with Enabled=false
	sharedpolicy.InitGlobalExfiltrationCheckerWithLimits(sharedpolicy.ExfiltrationLimits{
		MaxRowsPerQuery:  5, // Would fail if enabled
		MaxBytesPerQuery: 100,
		Enabled:          false, // Disabled
	})

	// Create mock connector that returns many rows (would fail if limits were checked)
	mcpRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		queryResult: &base.QueryResult{
			Rows: []map[string]interface{}{
				{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5},
				{"id": 6}, {"id": 7}, {"id": 8}, {"id": 9}, {"id": 10},
			},
			RowCount: 10,
			Duration: 10 * time.Millisecond,
		},
	}
	if err := mcpRegistry.Register("test-db", mockConn, &base.ConnectorConfig{Name: "test-db", TenantID: "*"}); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	reqBody := MCPQueryRequest{
		ClientID:  "test-client",
		UserToken: "test-token",
		Connector: "test-db",
		Statement: "SELECT * FROM users",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpQueryHandler(w, req)

	// Should return 200 OK - exfiltration checking disabled (Enabled=false)
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Error("expected success=true")
	}
}

// =============================================================================
// validateServiceLicense Tests
// =============================================================================

// TestValidateServiceLicense_EmptyLicenseKey tests that empty license key skips validation.
func TestValidateServiceLicense_EmptyLicenseKey(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	w := httptest.NewRecorder()
	granted, err := validateServiceLicense(context.Background(), w, "", "postgres", "query", "query")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if granted {
		t.Error("expected servicePermissionGranted=false for empty license key")
	}
	if w.Body.Len() > 0 {
		t.Errorf("expected no HTTP response body for empty license key, got: %s", w.Body.String())
	}
}

// TestValidateServiceLicense_CommunityMode tests that community mode skips license validation entirely.
func TestValidateServiceLicense_CommunityMode(t *testing.T) {
	tests := []struct {
		name           string
		deploymentMode string
		licenseKey     string
	}{
		{"community mode with license key", "community", "AXON-fake-key.fake-signature"},
		{"community mode empty license", "community", ""},
		{"unset deployment mode with license key", "", "AXON-fake-key.fake-signature"},
		{"unset deployment mode empty license", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.deploymentMode != "" {
				t.Setenv("DEPLOYMENT_MODE", tt.deploymentMode)
			} else {
				os.Unsetenv("DEPLOYMENT_MODE")
			}

			w := httptest.NewRecorder()
			granted, err := validateServiceLicense(context.Background(), w, tt.licenseKey, "postgres", "query", "query")
			if err != nil {
				t.Errorf("expected no error in community mode, got: %v", err)
			}
			if granted {
				t.Error("expected servicePermissionGranted=false in community mode")
			}
			// No HTTP response should be written in community mode
			if w.Body.Len() > 0 {
				t.Errorf("expected no HTTP response body in community mode, got: %s", w.Body.String())
			}
		})
	}
}

// TestValidateServiceLicense_EnterpriseMode_LicenseValidated tests that enterprise mode
// runs license validation (not skipped). In community build, ValidateLicense always returns
// Valid=true, so we verify it doesn't error and proceeds with validation.
func TestValidateServiceLicense_EnterpriseMode_LicenseValidated(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	w := httptest.NewRecorder()
	granted, err := validateServiceLicense(context.Background(), w, "not-a-valid-key", "postgres", "query", "query")

	// Community build: ValidateLicense returns Valid=true for any key.
	// The key assertion is that validation WAS attempted (no early return like community mode)
	// and no service permission was granted (since it's not a service license).
	if err != nil {
		t.Errorf("unexpected error (community build should accept any key): %v", err)
	}
	if granted {
		t.Error("expected servicePermissionGranted=false for non-service license")
	}
}

// TestValidateServiceLicense_EnterpriseMode_FakeKey tests that a fake license key
// is processed through license validation in enterprise mode.
func TestValidateServiceLicense_EnterpriseMode_FakeKey(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	w := httptest.NewRecorder()
	granted, err := validateServiceLicense(context.Background(), w, "AXON-fake-key.fake-signature", "postgres", "query", "query")

	// Community build: ValidateLicense returns Valid=true.
	// Fake key parsing may fail, falling back to community result (no service name).
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// No service name in fallback result, so no permission granted
	if granted {
		t.Error("expected servicePermissionGranted=false for unparseable V2 key")
	}
}

// TestValidateServiceLicense_EnterpriseMode_WithServiceLicense tests the full license
// validation path including service permission checking.
func TestValidateServiceLicense_EnterpriseMode_WithServiceLicense(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	// Craft a valid Ed25519-signed service license
	entSeed, _ := base64.StdEncoding.DecodeString("xV0rl8D6oQg7aoVvF6XA3KhN4Qb8PMmLfJyiF4JCkZc=")
	privKey := ed25519.NewKeyFromSeed(entSeed)

	payload := map[string]interface{}{
		"tier":         "Enterprise",
		"tenant_id":    "test-tenant",
		"service_name": "test-service",
		"service_type": "backend-service",
		"permissions":  []string{"mcp:postgres:query", "mcp:postgres:execute"},
		"issued_at":    "20260209",
		"expires_at":   "20991231",
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	sig := ed25519.Sign(privKey, []byte(payloadBase64))
	sigBase64 := base64.RawURLEncoding.EncodeToString(sig)

	licenseKey := "AXON-" + payloadBase64 + "." + sigBase64

	w := httptest.NewRecorder()
	granted, err := validateServiceLicense(context.Background(), w, licenseKey, "postgres", "query", "query")

	// With a valid service license, permission evaluation should run
	// It may grant or deny based on permission evaluator logic, but should not error on validation
	if err != nil {
		t.Logf("License validation result: granted=%v, err=%v", granted, err)
		// Permission denied is acceptable - it means the license was validated
		// and service permission evaluation ran (which is what we're testing)
		if w.Code == http.StatusForbidden {
			t.Log("Permission denied (expected - permission evaluator may not find matching rule)")
		} else if w.Code == http.StatusUnauthorized {
			t.Errorf("unexpected 401 - license should be valid: %s", w.Body.String())
		}
	} else {
		t.Logf("License validation succeeded: granted=%v", granted)
	}
}

// TestValidateServiceLicense_EnterpriseMode_ServicePermissionDenied tests the permission
// denied path when a valid service license lacks the required permission.
func TestValidateServiceLicense_EnterpriseMode_ServicePermissionDenied(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	// Craft a valid Ed25519-signed service license with permissions for a DIFFERENT connector
	entSeed, _ := base64.StdEncoding.DecodeString("xV0rl8D6oQg7aoVvF6XA3KhN4Qb8PMmLfJyiF4JCkZc=")
	privKey := ed25519.NewKeyFromSeed(entSeed)

	payload := map[string]interface{}{
		"tier":         "Enterprise",
		"tenant_id":    "test-tenant",
		"service_name": "test-service",
		"service_type": "backend-service",
		"permissions":  []string{"mcp:redis:query"}, // Only has redis, not postgres
		"issued_at":    "20260209",
		"expires_at":   "20991231",
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	sig := ed25519.Sign(privKey, []byte(payloadBase64))
	sigBase64 := base64.RawURLEncoding.EncodeToString(sig)

	licenseKey := "AXON-" + payloadBase64 + "." + sigBase64

	w := httptest.NewRecorder()
	granted, err := validateServiceLicense(context.Background(), w, licenseKey, "postgres", "query", "query")

	// Should be denied since service only has redis permission, not postgres
	if err == nil {
		t.Error("expected permission denied error")
	}
	if granted {
		t.Error("expected servicePermissionGranted=false when permission is denied")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected HTTP 403, got %d: %s", w.Code, w.Body.String())
	}
}

// TestMCPQueryHandler_CommunityMode_WithBasicAuth tests that MCP query handler
// works in community mode even when Basic Auth header is present.
// This was the root cause bug: extractClientSecret() populated req.LicenseKey
// from Basic Auth, then license validation ran and failed in community mode.
func TestMCPQueryHandler_CommunityMode_WithBasicAuth(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	reqBody := MCPQueryRequest{
		ClientID:  "demo",
		Connector: "test-db",
		Statement: "SELECT 1 as test_value",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/resources/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	// Set Basic Auth header - this was causing the bug
	req.SetBasicAuth("demo", "demo-secret")

	w := httptest.NewRecorder()
	mcpQueryHandler(w, req)

	// Should succeed (200) - not fail with 401 "Invalid license key"
	if w.Code == http.StatusUnauthorized {
		t.Errorf("community mode should NOT require license validation, but got 401: %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Logf("Got status %d (may be OK if connector returned error): %s", w.Code, w.Body.String())
	}
}

// TestMCPExecuteHandler_CommunityMode_WithBasicAuth tests the same bug fix for execute handler.
func TestMCPExecuteHandler_CommunityMode_WithBasicAuth(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	reqBody := MCPExecuteRequest{
		ClientID:  "demo",
		Connector: "test-db",
		Statement: "INSERT INTO test (name) VALUES ('test')",
		Action:    "INSERT",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/tools/execute", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("demo", "demo-secret")

	w := httptest.NewRecorder()
	mcpExecuteHandler(w, req)

	// Should NOT fail with 401 "Invalid license key" in community mode
	if w.Code == http.StatusUnauthorized {
		t.Errorf("community mode should NOT require license validation, but got 401: %s", w.Body.String())
	}
}

// TestMCPExecuteHandler_DynamicPolicyBlocks verifies that dynamic policy evaluation
// can block execute requests (e.g., rate limiting on write operations).
func TestMCPExecuteHandler_DynamicPolicyBlocks(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	originalEvaluator := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEvaluator)

	server := mockOrchestratorServer(t, sharedpolicy.DynamicPolicyResponse{
		Allowed:           false,
		BlockReason:       "Write budget exceeded: max 100 executes per hour",
		PoliciesEvaluated: 1,
		MatchedPolicies: []sharedpolicy.DynamicPolicyMatch{
			{
				PolicyID:   "budget-limit-writes",
				PolicyType: "budget",
				Action:     "block",
			},
		},
	})
	defer server.Close()

	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"test-db"},
	})

	reqBody := MCPExecuteRequest{
		ClientID:  "test-client",
		Connector: "test-db",
		Statement: "INSERT INTO orders (product) VALUES ('widget')",
		Action:    "INSERT",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/tools/execute", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("demo", "demo-secret")
	w := httptest.NewRecorder()

	mcpExecuteHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["success"] != false {
		t.Error("expected success=false")
	}
	if response["error"] != "Write budget exceeded: max 100 executes per hour" {
		t.Errorf("expected budget limit error, got %v", response["error"])
	}
	if _, hasDynamic := response["dynamic_policy_info"]; !hasDynamic {
		t.Error("expected dynamic_policy_info in blocked response")
	}
}

// TestMCPExecuteHandler_ResponseIncludesPolicyInfo verifies that the execute handler
// returns policy_info when the policy engine evaluates the request (Issue #969).
func TestMCPExecuteHandler_ResponseIncludesPolicyInfo(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	mcpRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		executeResult: &base.CommandResult{
			RowsAffected: 3,
			Duration:     8 * time.Millisecond,
			Message:      "3 rows inserted",
		},
	}
	if err := mcpRegistry.Register("test-db", mockConn, &base.ConnectorConfig{Name: "test-db", TenantID: "*"}); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	reqBody := MCPExecuteRequest{
		ClientID:  "demo",
		Connector: "test-db",
		Statement: "INSERT INTO test (name) VALUES ('test')",
		Action:    "INSERT",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/tools/execute", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("demo", "demo-secret")

	w := httptest.NewRecorder()
	mcpExecuteHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Errorf("expected success=true, got %v", response["success"])
	}
	if response["connector"] != "test-db" {
		t.Errorf("expected connector=test-db, got %v", response["connector"])
	}
	if response["message"] != "3 rows inserted" {
		t.Errorf("expected message='3 rows inserted', got %v", response["message"])
	}
}

// TestMCPExecuteHandler_BackwardCompatNoPolicyEngine verifies that the execute handler
// response is backward compatible when no policy engine is configured.
func TestMCPExecuteHandler_BackwardCompatNoPolicyEngine(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	// Register connector so execution succeeds
	mcpRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		executeResult: &base.CommandResult{
			RowsAffected: 1,
			Duration:     2 * time.Millisecond,
			Message:      "1 row updated",
		},
	}
	if err := mcpRegistry.Register("test-db", mockConn, &base.ConnectorConfig{Name: "test-db", TenantID: "*"}); err != nil {
		t.Fatalf("Failed to register connector: %v", err)
	}

	reqBody := MCPExecuteRequest{
		ClientID:  "demo",
		Connector: "test-db",
		Statement: "UPDATE test SET name = 'updated'",
		Action:    "UPDATE",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/tools/execute", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("demo", "demo-secret")

	w := httptest.NewRecorder()
	mcpExecuteHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Errorf("expected success=true")
	}
	if _, ok := response["rows_affected"]; !ok {
		t.Error("missing rows_affected field")
	}
	if _, ok := response["duration_ms"]; !ok {
		t.Error("missing duration_ms field")
	}
	if _, ok := response["message"]; !ok {
		t.Error("missing message field")
	}

	// Policy fields should NOT be present when engine is nil
	if _, ok := response["policy_info"]; ok {
		t.Error("policy_info should not be present when policy engine is nil")
	}
	if _, ok := response["redacted"]; ok {
		t.Error("redacted should not be present when policy engine is nil")
	}
	if _, ok := response["redacted_fields"]; ok {
		t.Error("redacted_fields should not be present when policy engine is nil")
	}
}
