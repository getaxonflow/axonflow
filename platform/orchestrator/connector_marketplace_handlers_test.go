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

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"

	"github.com/gorilla/mux"
)

// Test getConnectorMetadata returns all 4 connectors
func TestConnectorMarketplace_GetConnectorMetadata(t *testing.T) {
	metadata := getConnectorMetadata()

	if len(metadata) != 4 {
		t.Fatalf("Expected 4 connectors, got %d", len(metadata))
	}

	// Verify each connector has required fields
	expectedIDs := []string{"amadeus-travel", "redis-cache", "http-rest", "postgresql"}
	for i, expected := range expectedIDs {
		if metadata[i].ID != expected {
			t.Errorf("Expected connector %d to have ID %s, got %s", i, expected, metadata[i].ID)
		}
		if metadata[i].Name == "" {
			t.Errorf("Connector %s missing name", metadata[i].ID)
		}
		if metadata[i].Type == "" {
			t.Errorf("Connector %s missing type", metadata[i].ID)
		}
		if len(metadata[i].Capabilities) == 0 {
			t.Errorf("Connector %s has no capabilities", metadata[i].ID)
		}
	}
}

// Test getConnectorMetadata - amadeus connector details
func TestConnectorMarketplace_GetConnectorMetadata_AmadeusDetails(t *testing.T) {
	metadata := getConnectorMetadata()

	var amadeus *ConnectorMetadata
	for i := range metadata {
		if metadata[i].ID == "amadeus-travel" {
			amadeus = &metadata[i]
			break
		}
	}

	if amadeus == nil {
		t.Fatal("Amadeus connector not found in metadata")
	}

	if amadeus.Type != "amadeus" {
		t.Errorf("Expected type 'amadeus', got %s", amadeus.Type)
	}

	if amadeus.Category != "Travel" {
		t.Errorf("Expected category 'Travel', got %s", amadeus.Category)
	}

	expectedCapabilities := []string{"query", "flights", "hotels", "airports"}
	if len(amadeus.Capabilities) != len(expectedCapabilities) {
		t.Errorf("Expected %d capabilities, got %d", len(expectedCapabilities), len(amadeus.Capabilities))
	}
}

// Test listConnectorsHandler - success with no installed connectors
func TestConnectorMarketplace_ListConnectorsHandler_Empty(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create empty registry
	connectorRegistry = registry.NewRegistry()

	req := httptest.NewRequest("GET", "/connectors", nil)
	w := httptest.NewRecorder()

	listConnectorsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	connectors, ok := response["connectors"].([]interface{})
	if !ok {
		t.Fatal("Response missing 'connectors' array")
	}

	if len(connectors) != 4 {
		t.Errorf("Expected 4 connectors in catalog, got %d", len(connectors))
	}

	// Verify none are installed
	for _, conn := range connectors {
		connMap := conn.(map[string]interface{})
		if installed, ok := connMap["installed"].(bool); ok && installed {
			t.Errorf("Connector %s should not be installed", connMap["id"])
		}
	}
}

// Test listConnectorsHandler - with installed connectors
func TestConnectorMarketplace_ListConnectorsHandler_WithInstalled(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create registry with mock connector
	connectorRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		name: "amadeus-travel",
	}
	config := &base.ConnectorConfig{
		Name: "amadeus-travel",
		Type: "amadeus",
	}
	_ = connectorRegistry.Register("amadeus-travel", mockConn, config)

	req := httptest.NewRequest("GET", "/connectors", nil)
	w := httptest.NewRecorder()

	listConnectorsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	connectors := response["connectors"].([]interface{})

	// Find amadeus connector
	var amadeusInstalled bool
	for _, conn := range connectors {
		connMap := conn.(map[string]interface{})
		if connMap["id"] == "amadeus-travel" {
			amadeusInstalled = connMap["installed"].(bool)
			break
		}
	}

	if !amadeusInstalled {
		t.Error("Amadeus connector should be marked as installed")
	}
}

// Test getConnectorDetailsHandler - connector not found
func TestConnectorMarketplace_GetConnectorDetailsHandler_NotFound(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	connectorRegistry = registry.NewRegistry()

	req := httptest.NewRequest("GET", "/connectors/unknown-connector", nil)
	w := httptest.NewRecorder()

	// Simulate mux vars
	req = mux.SetURLVars(req, map[string]string{"id": "unknown-connector"})

	getConnectorDetailsHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

// Test getConnectorDetailsHandler - success
func TestConnectorMarketplace_GetConnectorDetailsHandler_Success(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	connectorRegistry = registry.NewRegistry()

	req := httptest.NewRequest("GET", "/connectors/amadeus-travel", nil)
	w := httptest.NewRecorder()

	req = mux.SetURLVars(req, map[string]string{"id": "amadeus-travel"})

	getConnectorDetailsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var metadata ConnectorMetadata
	if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if metadata.ID != "amadeus-travel" {
		t.Errorf("Expected ID 'amadeus-travel', got %s", metadata.ID)
	}

	if metadata.Type != "amadeus" {
		t.Errorf("Expected type 'amadeus', got %s", metadata.Type)
	}
}

// Test getConnectorDetailsHandler - with health status
func TestConnectorMarketplace_GetConnectorDetailsHandler_WithHealth(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create registry with mock connector
	connectorRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		name: "redis-cache",
	}
	config := &base.ConnectorConfig{
		Name: "redis-cache",
		Type: "redis",
	}
	_ = connectorRegistry.Register("redis-cache", mockConn, config)

	req := httptest.NewRequest("GET", "/connectors/redis-cache", nil)
	w := httptest.NewRecorder()

	req = mux.SetURLVars(req, map[string]string{"id": "redis-cache"})

	getConnectorDetailsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var metadata ConnectorMetadata
	if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !metadata.Installed {
		t.Error("Connector should be marked as installed")
	}

	if !metadata.Healthy {
		t.Error("Connector should be marked as healthy")
	}
}

// Test installConnectorHandler - invalid JSON body
func TestConnectorMarketplace_InstallConnectorHandler_InvalidJSON(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	connectorRegistry = registry.NewRegistry()

	invalidJSON := []byte(`{invalid json`)
	req := httptest.NewRequest("POST", "/connectors/amadeus-travel/install", bytes.NewReader(invalidJSON))
	w := httptest.NewRecorder()

	req = mux.SetURLVars(req, map[string]string{"id": "amadeus-travel"})

	installConnectorHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// Test installConnectorHandler - connector not found
func TestConnectorMarketplace_InstallConnectorHandler_NotFound(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	connectorRegistry = registry.NewRegistry()

	installReq := ConnectorInstallRequest{
		Name:     "My Unknown Connector",
		TenantID: "test-tenant",
	}
	body, _ := json.Marshal(installReq)

	req := httptest.NewRequest("POST", "/connectors/unknown-connector/install", bytes.NewReader(body))
	w := httptest.NewRecorder()

	req = mux.SetURLVars(req, map[string]string{"id": "unknown-connector"})

	installConnectorHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

// Test installConnectorHandler - success (redis connector)
// Note: Redis connector requires actual Redis instance, so this test
// verifies the handler processes the request but may fail at connection
func TestConnectorMarketplace_InstallConnectorHandler_Success_Redis(t *testing.T) {
	t.Skip("Skipping - requires actual Redis instance for connection")
}

// Test installConnectorHandler - success (http connector)
// Note: HTTP connector now has SSRF protection that resolves hostnames,
// which requires actual DNS resolution. Skip in CI environments.
func TestConnectorMarketplace_InstallConnectorHandler_Success_HTTP(t *testing.T) {
	t.Skip("Skipping - HTTP connector SSRF protection requires DNS resolution of base_url hostname")
}

// Test installConnectorHandler - success (postgres connector)
// Note: Postgres connector requires actual PostgreSQL instance
func TestConnectorMarketplace_InstallConnectorHandler_Success_Postgres(t *testing.T) {
	t.Skip("Skipping - requires actual PostgreSQL instance for connection")
}

// Test installConnectorHandler - amadeus connector
// Note: Amadeus connector requires real API credentials and tries to connect
func TestConnectorMarketplace_InstallConnectorHandler_Success_Amadeus(t *testing.T) {
	t.Skip("Skipping - Amadeus connector requires real API credentials and connection")
}

// Test installConnectorHandler - unsupported connector type
func TestConnectorMarketplace_InstallConnectorHandler_UnsupportedType(t *testing.T) {
	// This test is challenging because the handler validates connectorID against metadata
	// before checking the type. We'd need to mock getConnectorMetadata() to return
	// a connector with an unsupported type, which isn't currently possible.
	// The default case in the switch statement (line 390-392) is defensive coding
	// but may be unreachable in practice.
	t.Skip("Skipping - default case in switch may be unreachable without mocking metadata")
}

// Test uninstallConnectorHandler - success
func TestConnectorMarketplace_UninstallConnectorHandler_Success(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create registry with mock connector
	connectorRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		name: "redis-cache",
	}
	config := &base.ConnectorConfig{
		Name: "redis-cache",
		Type: "redis",
	}
	_ = connectorRegistry.Register("redis-cache", mockConn, config)

	req := httptest.NewRequest("DELETE", "/connectors/redis-cache", nil)
	w := httptest.NewRecorder()

	req = mux.SetURLVars(req, map[string]string{"id": "redis-cache"})

	uninstallConnectorHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("Expected success=true in response")
	}
}

// Test uninstallConnectorHandler - connector not found
func TestConnectorMarketplace_UninstallConnectorHandler_NotFound(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	connectorRegistry = registry.NewRegistry()

	req := httptest.NewRequest("DELETE", "/connectors/unknown-connector", nil)
	w := httptest.NewRecorder()

	req = mux.SetURLVars(req, map[string]string{"id": "unknown-connector"})

	uninstallConnectorHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

// Test connectorHealthCheckHandler - success
func TestConnectorMarketplace_ConnectorHealthCheckHandler_Success(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create registry with mock connector
	connectorRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		name: "redis-cache",
	}
	config := &base.ConnectorConfig{
		Name: "redis-cache",
		Type: "redis",
	}
	_ = connectorRegistry.Register("redis-cache", mockConn, config)

	req := httptest.NewRequest("GET", "/connectors/redis-cache/health", nil)
	w := httptest.NewRecorder()

	req = mux.SetURLVars(req, map[string]string{"id": "redis-cache"})

	connectorHealthCheckHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var status base.HealthStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !status.Healthy {
		t.Error("Expected connector to be healthy")
	}
}

// Test connectorHealthCheckHandler - connector not found
func TestConnectorMarketplace_ConnectorHealthCheckHandler_NotFound(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	connectorRegistry = registry.NewRegistry()

	req := httptest.NewRequest("GET", "/connectors/unknown-connector/health", nil)
	w := httptest.NewRecorder()

	req = mux.SetURLVars(req, map[string]string{"id": "unknown-connector"})

	connectorHealthCheckHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

// Test connectorHealthCheckHandler - unhealthy connector
func TestConnectorMarketplace_ConnectorHealthCheckHandler_Unhealthy(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create registry with mock connector that connects but is unhealthy
	connectorRegistry = registry.NewRegistry()
	mockConn := &mockMarketplaceConnector{
		name:          "redis-cache",
		shouldFail:    false, // Connects successfully
		healthyStatus: false, // But health check returns unhealthy
	}
	config := &base.ConnectorConfig{
		Name: "redis-cache",
		Type: "redis",
	}
	_ = connectorRegistry.Register("redis-cache", mockConn, config)

	req := httptest.NewRequest("GET", "/connectors/redis-cache/health", nil)
	w := httptest.NewRecorder()

	req = mux.SetURLVars(req, map[string]string{"id": "redis-cache"})

	connectorHealthCheckHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var status base.HealthStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if status.Healthy {
		t.Error("Expected connector to be unhealthy")
	}
}

// Test initializeConnectorRegistry - various initialization scenarios
func TestConnectorMarketplace_InitializeConnectorRegistry(t *testing.T) {
	tests := []struct {
		name           string
		databaseURL    string
		expectRegistry bool
		description    string
	}{
		{
			name:           "In-memory registry (no DATABASE_URL)",
			databaseURL:    "",
			expectRegistry: true,
			description:    "Should initialize in-memory registry when no DATABASE_URL",
		},
		{
			name:           "PostgreSQL registry with valid URL",
			databaseURL:    "postgresql://user:pass@localhost:5432/testdb",
			expectRegistry: true,
			description:    "Should attempt PostgreSQL registry with valid URL (may fall back to in-memory if DB unavailable)",
		},
		{
			name:           "Invalid DATABASE_URL falls back to in-memory",
			databaseURL:    "invalid-database-url",
			expectRegistry: true,
			description:    "Should fall back to in-memory registry on invalid URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore original state
			originalRegistry := connectorRegistry
			originalDBURL := os.Getenv("DATABASE_URL")
			defer func() {
				connectorRegistry = originalRegistry
				_ = os.Setenv("DATABASE_URL", originalDBURL)
			}()

			// Set test environment
			if tt.databaseURL != "" {
				_ = os.Setenv("DATABASE_URL", tt.databaseURL)
			} else {
				_ = os.Unsetenv("DATABASE_URL")
			}

			// Initialize registry
			initializeConnectorRegistry()

			// Verify registry was created
			if tt.expectRegistry && connectorRegistry == nil {
				t.Fatalf("%s: Registry should be initialized", tt.description)
			}

			if !tt.expectRegistry && connectorRegistry != nil {
				t.Fatalf("%s: Registry should not be initialized", tt.description)
			}
		})
	}
}

// Test createConnectorInstance - redis type
func TestConnectorMarketplace_CreateConnectorInstance_Redis(t *testing.T) {
	connector, err := createConnectorInstance("redis")

	if err != nil {
		t.Fatalf("Unexpected error creating redis connector: %v", err)
	}

	if connector == nil {
		t.Fatal("Expected redis connector instance, got nil")
	}

	if connector.Type() != "redis" {
		t.Errorf("Expected type 'redis', got %s", connector.Type())
	}
}

// Test createConnectorInstance - http type
func TestConnectorMarketplace_CreateConnectorInstance_HTTP(t *testing.T) {
	connector, err := createConnectorInstance("http")

	if err != nil {
		t.Fatalf("Unexpected error creating http connector: %v", err)
	}

	if connector == nil {
		t.Fatal("Expected http connector instance, got nil")
	}

	if connector.Type() != "http" {
		t.Errorf("Expected type 'http', got %s", connector.Type())
	}
}

// Test createConnectorInstance - postgres type
func TestConnectorMarketplace_CreateConnectorInstance_Postgres(t *testing.T) {
	connector, err := createConnectorInstance("postgres")

	if err != nil {
		t.Fatalf("Unexpected error creating postgres connector: %v", err)
	}

	if connector == nil {
		t.Fatal("Expected postgres connector instance, got nil")
	}

	if connector.Type() != "postgres" {
		t.Errorf("Expected type 'postgres', got %s", connector.Type())
	}
}

// Test createConnectorInstance - unsupported type
func TestConnectorMarketplace_CreateConnectorInstance_Amadeus(t *testing.T) {
	connector, err := createConnectorInstance("amadeus")

	if err != nil {
		t.Fatalf("Unexpected error creating amadeus connector: %v", err)
	}

	if connector == nil {
		t.Fatal("Expected amadeus connector instance, got nil")
	}

	if connector.Type() != "amadeus" {
		t.Errorf("Expected type 'amadeus', got %s", connector.Type())
	}
}

func TestConnectorMarketplace_CreateConnectorInstance_Unsupported(t *testing.T) {
	connector, err := createConnectorInstance("unknown-type")

	if err == nil {
		t.Error("Expected error for unsupported connector type")
	}

	if connector != nil {
		t.Error("Expected nil connector for unsupported type")
	}
}

// Mock connector for testing (simple implementation)
type mockMarketplaceConnector struct {
	name           string
	shouldFail     bool
	healthyStatus  bool // Separate flag for health check status
}

func (m *mockMarketplaceConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	if m.shouldFail {
		return base.NewConnectorError(m.name, "connect", "Mock connection failure", nil)
	}
	return nil
}

func (m *mockMarketplaceConnector) Disconnect(ctx context.Context) error {
	return nil
}

func (m *mockMarketplaceConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	status := &base.HealthStatus{
		Healthy:   m.healthyStatus,
		Timestamp: time.Now(),
		Latency:   10 * time.Millisecond,
	}
	if !m.healthyStatus {
		status.Error = "Mock health check failure"
	}
	return status, nil
}

func (m *mockMarketplaceConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if m.shouldFail {
		return nil, base.NewConnectorError(m.name, "query", "Mock query failure", nil)
	}
	return &base.QueryResult{
		Rows:      []map[string]interface{}{},
		RowCount:  0,
		Duration:  10 * time.Millisecond,
		Connector: m.name,
	}, nil
}

func (m *mockMarketplaceConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	if m.shouldFail {
		return nil, base.NewConnectorError(m.name, "execute", "Mock execute failure", nil)
	}
	return &base.CommandResult{
		Success:      true,
		RowsAffected: 0,
		Duration:     10 * time.Millisecond,
		Connector:    m.name,
	}, nil
}

func (m *mockMarketplaceConnector) Name() string {
	return m.name
}

func (m *mockMarketplaceConnector) Type() string {
	return "mock"
}

func (m *mockMarketplaceConnector) Version() string {
	return "1.0.0"
}

func (m *mockMarketplaceConnector) Capabilities() []string {
	return []string{"query", "execute"}
}

// Test buildConnectionURL for PostgreSQL
func TestBuildConnectionURL_Postgres(t *testing.T) {
	tests := []struct {
		name        string
		options     map[string]interface{}
		credentials map[string]string
		want        string
	}{
		{
			name: "full credentials",
			options: map[string]interface{}{
				"host":     "db.example.com",
				"port":     float64(5432), // JSON numbers are float64
				"database": "mydb",
			},
			credentials: map[string]string{
				"username": "admin",
				"password": "secret123",
			},
			want: "postgres://admin:secret123@db.example.com:5432/mydb?sslmode=disable",
		},
		{
			name: "with ssl_mode (underscore)",
			options: map[string]interface{}{
				"host":     "secure.db.com",
				"port":     float64(5432),
				"database": "proddb",
				"ssl_mode": "require",
			},
			credentials: map[string]string{
				"username": "user",
				"password": "pass",
			},
			want: "postgres://user:pass@secure.db.com:5432/proddb?sslmode=require",
		},
		{
			name: "with sslmode (no underscore)",
			options: map[string]interface{}{
				"host":     "secure.db.com",
				"port":     float64(5432),
				"database": "proddb",
				"sslmode":  "verify-full",
			},
			credentials: map[string]string{
				"username": "user",
				"password": "pass",
			},
			want: "postgres://user:pass@secure.db.com:5432/proddb?sslmode=verify-full",
		},
		{
			name: "explicit connection_url takes precedence",
			options: map[string]interface{}{
				"connection_url": "postgres://custom:url@host:1234/db",
				"host":           "ignored.com",
			},
			credentials: map[string]string{
				"username": "ignored",
				"password": "ignored",
			},
			want: "postgres://custom:url@host:1234/db",
		},
		{
			name: "default port",
			options: map[string]interface{}{
				"host":     "localhost",
				"database": "test",
			},
			credentials: map[string]string{
				"username": "user",
				"password": "pass",
			},
			want: "postgres://user:pass@localhost:5432/test?sslmode=disable",
		},
		{
			name: "special characters in password - URL encoded",
			options: map[string]interface{}{
				"host":     "db.example.com",
				"port":     float64(5432),
				"database": "mydb",
			},
			credentials: map[string]string{
				"username": "admin",
				"password": "p@ss:word/123#test",
			},
			want: "postgres://admin:p%40ss%3Aword%2F123%23test@db.example.com:5432/mydb?sslmode=disable",
		},
		{
			name: "special characters in username",
			options: map[string]interface{}{
				"host":     "db.example.com",
				"database": "mydb",
			},
			credentials: map[string]string{
				"username": "user@domain.com",
				"password": "pass",
			},
			want: "postgres://user%40domain.com:pass@db.example.com:5432/mydb?sslmode=disable",
		},
		{
			name: "nil credentials map",
			options: map[string]interface{}{
				"host":     "db.example.com",
				"database": "mydb",
			},
			credentials: nil,
			want:        "postgres://db.example.com:5432/mydb?sslmode=disable",
		},
		{
			name:        "nil options map",
			options:     nil,
			credentials: map[string]string{"username": "user", "password": "pass"},
			want:        "postgres://user:pass@localhost:5432/?sslmode=disable",
		},
		{
			name:        "both nil",
			options:     nil,
			credentials: nil,
			want:        "postgres://localhost:5432/?sslmode=disable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildConnectionURL("postgres", tt.options, tt.credentials)
			if got != tt.want {
				t.Errorf("buildConnectionURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Test buildConnectionURL for Redis
func TestBuildConnectionURL_Redis(t *testing.T) {
	tests := []struct {
		name        string
		options     map[string]interface{}
		credentials map[string]string
		want        string
	}{
		{
			name: "with password",
			options: map[string]interface{}{
				"host": "redis.example.com",
				"port": float64(6379),
				"db":   float64(1),
			},
			credentials: map[string]string{
				"password": "redispass",
			},
			want: "redis://:redispass@redis.example.com:6379/1",
		},
		{
			name: "without password",
			options: map[string]interface{}{
				"host": "localhost",
			},
			credentials: map[string]string{},
			want:        "redis://localhost:6379/0",
		},
		{
			name: "special characters in password",
			options: map[string]interface{}{
				"host": "redis.example.com",
				"port": float64(6379),
				"db":   float64(0),
			},
			credentials: map[string]string{
				"password": "p@ss:word/123",
			},
			want: "redis://:p%40ss%3Aword%2F123@redis.example.com:6379/0",
		},
		{
			name:        "nil credentials",
			options:     map[string]interface{}{"host": "localhost"},
			credentials: nil,
			want:        "redis://localhost:6379/0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildConnectionURL("redis", tt.options, tt.credentials)
			if got != tt.want {
				t.Errorf("buildConnectionURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Test buildConnectionURL for MySQL
func TestBuildConnectionURL_MySQL(t *testing.T) {
	tests := []struct {
		name        string
		options     map[string]interface{}
		credentials map[string]string
		want        string
	}{
		{
			name: "full credentials",
			options: map[string]interface{}{
				"host":     "mysql.example.com",
				"port":     float64(3306),
				"database": "app",
			},
			credentials: map[string]string{
				"username": "root",
				"password": "secret",
			},
			want: "root:secret@tcp(mysql.example.com:3306)/app",
		},
		{
			name: "special characters in password",
			options: map[string]interface{}{
				"host":     "mysql.example.com",
				"port":     float64(3306),
				"database": "app",
			},
			credentials: map[string]string{
				"username": "root",
				"password": "p@ss:word/123",
			},
			want: "root:p%40ss%3Aword%2F123@tcp(mysql.example.com:3306)/app",
		},
		{
			name: "username only",
			options: map[string]interface{}{
				"host":     "mysql.example.com",
				"database": "app",
			},
			credentials: map[string]string{
				"username": "root",
			},
			want: "root@tcp(mysql.example.com:3306)/app",
		},
		{
			name: "no credentials",
			options: map[string]interface{}{
				"host":     "mysql.example.com",
				"database": "app",
			},
			credentials: nil,
			want:        "tcp(mysql.example.com:3306)/app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildConnectionURL("mysql", tt.options, tt.credentials)
			if got != tt.want {
				t.Errorf("buildConnectionURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Test buildConnectionURL for MongoDB
func TestBuildConnectionURL_MongoDB(t *testing.T) {
	tests := []struct {
		name        string
		options     map[string]interface{}
		credentials map[string]string
		want        string
	}{
		{
			name: "full credentials",
			options: map[string]interface{}{
				"host":     "mongo.example.com",
				"port":     float64(27017),
				"database": "docs",
			},
			credentials: map[string]string{
				"username": "mongouser",
				"password": "mongopass",
			},
			want: "mongodb://mongouser:mongopass@mongo.example.com:27017/docs",
		},
		{
			name: "with authSource",
			options: map[string]interface{}{
				"host":        "mongo.example.com",
				"port":        float64(27017),
				"database":    "docs",
				"auth_source": "admin",
			},
			credentials: map[string]string{
				"username": "mongouser",
				"password": "mongopass",
			},
			want: "mongodb://mongouser:mongopass@mongo.example.com:27017/docs?authSource=admin",
		},
		{
			name: "special characters in password",
			options: map[string]interface{}{
				"host":     "mongo.example.com",
				"port":     float64(27017),
				"database": "docs",
			},
			credentials: map[string]string{
				"username": "mongouser",
				"password": "p@ss:word/123",
			},
			want: "mongodb://mongouser:p%40ss%3Aword%2F123@mongo.example.com:27017/docs",
		},
		{
			name: "nil credentials",
			options: map[string]interface{}{
				"host":     "mongo.example.com",
				"database": "docs",
			},
			credentials: nil,
			want:        "mongodb://mongo.example.com:27017/docs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildConnectionURL("mongodb", tt.options, tt.credentials)
			if got != tt.want {
				t.Errorf("buildConnectionURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Test buildConnectionURL for Cassandra
func TestBuildConnectionURL_Cassandra(t *testing.T) {
	tests := []struct {
		name        string
		options     map[string]interface{}
		credentials map[string]string
		want        string
	}{
		{
			name: "full credentials",
			options: map[string]interface{}{
				"host":     "cassandra.example.com",
				"port":     float64(9042),
				"keyspace": "mykeyspace",
			},
			credentials: map[string]string{
				"username": "cassuser",
				"password": "casspass",
			},
			want: "cassandra://cassuser:casspass@cassandra.example.com:9042/mykeyspace",
		},
		{
			name: "using database as keyspace fallback",
			options: map[string]interface{}{
				"host":     "cassandra.example.com",
				"port":     float64(9042),
				"database": "fallbackkeyspace",
			},
			credentials: map[string]string{
				"username": "cassuser",
				"password": "casspass",
			},
			want: "cassandra://cassuser:casspass@cassandra.example.com:9042/fallbackkeyspace",
		},
		{
			name: "special characters in password",
			options: map[string]interface{}{
				"host":     "cassandra.example.com",
				"keyspace": "mykeyspace",
			},
			credentials: map[string]string{
				"username": "cassuser",
				"password": "p@ss:word/123",
			},
			want: "cassandra://cassuser:p%40ss%3Aword%2F123@cassandra.example.com:9042/mykeyspace",
		},
		{
			name: "no credentials",
			options: map[string]interface{}{
				"host":     "cassandra.example.com",
				"keyspace": "mykeyspace",
			},
			credentials: nil,
			want:        "cassandra://cassandra.example.com:9042/mykeyspace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildConnectionURL("cassandra", tt.options, tt.credentials)
			if got != tt.want {
				t.Errorf("buildConnectionURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Test buildConnectionURL for HTTP connector
func TestBuildConnectionURL_HTTP(t *testing.T) {
	tests := []struct {
		name        string
		options     map[string]interface{}
		credentials map[string]string
		want        string
	}{
		{
			name: "with base_url",
			options: map[string]interface{}{
				"base_url": "https://api.example.com/v1",
			},
			credentials: nil,
			want:        "https://api.example.com/v1",
		},
		{
			name:        "without base_url returns empty",
			options:     map[string]interface{}{},
			credentials: nil,
			want:        "",
		},
		{
			name:        "nil options returns empty",
			options:     nil,
			credentials: nil,
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildConnectionURL("http", tt.options, tt.credentials)
			if got != tt.want {
				t.Errorf("buildConnectionURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Test buildConnectionURL for unknown connector type
func TestBuildConnectionURL_UnknownType(t *testing.T) {
	options := map[string]interface{}{
		"base_url": "https://custom.example.com",
	}
	got := buildConnectionURL("unknown", options, nil)
	want := "https://custom.example.com"

	if got != want {
		t.Errorf("buildConnectionURL(unknown) = %q, want %q", got, want)
	}

	// Without base_url, should return empty
	got = buildConnectionURL("unknown", map[string]interface{}{}, nil)
	if got != "" {
		t.Errorf("buildConnectionURL(unknown) without base_url = %q, want empty", got)
	}
}

// Test helper functions
func TestGetStringOption(t *testing.T) {
	tests := []struct {
		name       string
		options    map[string]interface{}
		key        string
		defaultVal string
		want       string
	}{
		{
			name:       "existing key",
			options:    map[string]interface{}{"host": "example.com"},
			key:        "host",
			defaultVal: "default",
			want:       "example.com",
		},
		{
			name:       "missing key",
			options:    map[string]interface{}{"host": "example.com"},
			key:        "missing",
			defaultVal: "default",
			want:       "default",
		},
		{
			name:       "nil options",
			options:    nil,
			key:        "host",
			defaultVal: "default",
			want:       "default",
		},
		{
			name:       "wrong type returns default",
			options:    map[string]interface{}{"port": 5432},
			key:        "port",
			defaultVal: "default",
			want:       "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getStringOption(tt.options, tt.key, tt.defaultVal)
			if got != tt.want {
				t.Errorf("getStringOption() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetIntOption(t *testing.T) {
	tests := []struct {
		name       string
		options    map[string]interface{}
		key        string
		defaultVal int
		want       int
	}{
		{
			name:       "float64 value (JSON)",
			options:    map[string]interface{}{"port": float64(5432)},
			key:        "port",
			defaultVal: 0,
			want:       5432,
		},
		{
			name:       "int value",
			options:    map[string]interface{}{"port": 3306},
			key:        "port",
			defaultVal: 0,
			want:       3306,
		},
		{
			name:       "missing key",
			options:    map[string]interface{}{},
			key:        "port",
			defaultVal: 9999,
			want:       9999,
		},
		{
			name:       "nil options",
			options:    nil,
			key:        "port",
			defaultVal: 9999,
			want:       9999,
		},
		{
			name:       "wrong type returns default",
			options:    map[string]interface{}{"port": "not a number"},
			key:        "port",
			defaultVal: 9999,
			want:       9999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getIntOption(tt.options, tt.key, tt.defaultVal)
			if got != tt.want {
				t.Errorf("getIntOption() = %d, want %d", got, tt.want)
			}
		})
	}
}
