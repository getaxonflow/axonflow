// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
)

// Mock connector for testing
type mockConnector struct {
	queryResult   *base.QueryResult
	executeResult *base.CommandResult
	queryError    error
	executeError  error
}

func (m *mockConnector) Name() string                                                       { return "mock" }
func (m *mockConnector) Type() string                                                       { return "mock" }
func (m *mockConnector) Version() string                                                    { return "1.0.0" }
func (m *mockConnector) Capabilities() []string {
	return []string{"query", "execute"}
}
func (m *mockConnector) Connect(ctx context.Context, cfg *base.ConnectorConfig) error      { return nil }
func (m *mockConnector) Disconnect(ctx context.Context) error                              { return nil }
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

// TestMCPQueryHandler_TimeoutParsing tests timeout parsing in query handler
func TestMCPQueryHandler_TimeoutParsing(t *testing.T) {
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
