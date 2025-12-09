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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	"axonflow/platform/connectors/base"
)

// setupTestRegistry creates a test TenantConnectorRegistry
func setupTestRegistry(t *testing.T) {
	t.Helper()

	factory := func(connectorType string) (base.Connector, error) {
		return &tenantRegistryMockConnector{connectorType: connectorType}, nil
	}

	InitTenantConnectorRegistry(nil, factory)
	t.Cleanup(clearTenantConnectorRegistry)
}

// TestConnectorRefreshAllHandler_NotInitialized tests refresh when registry not initialized
func TestConnectorRefreshAllHandler_NotInitialized(t *testing.T) {
	clearTenantConnectorRegistry()

	req := httptest.NewRequest("POST", "/api/v1/connectors/refresh", nil)
	w := httptest.NewRecorder()

	connectorRefreshAllHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["success"] != false {
		t.Error("Expected success to be false")
	}
}

// TestConnectorRefreshAllHandler_Success tests successful refresh all
func TestConnectorRefreshAllHandler_Success(t *testing.T) {
	setupTestRegistry(t)

	req := httptest.NewRequest("POST", "/api/v1/connectors/refresh", nil)
	w := httptest.NewRecorder()

	connectorRefreshAllHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp ConnectorRefreshResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("Expected success to be true")
	}
	if resp.Scope != "all" {
		t.Errorf("Expected scope 'all', got '%s'", resp.Scope)
	}
	if resp.Duration == "" {
		t.Error("Expected duration to be set")
	}
}

// TestConnectorRefreshTenantHandler_MissingTenantID tests missing tenant ID
func TestConnectorRefreshTenantHandler_MissingTenantID(t *testing.T) {
	setupTestRegistry(t)

	req := httptest.NewRequest("POST", "/api/v1/connectors/refresh/", nil)
	req = mux.SetURLVars(req, map[string]string{"tenant_id": ""})
	w := httptest.NewRecorder()

	connectorRefreshTenantHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestConnectorRefreshTenantHandler_Success tests successful tenant refresh
func TestConnectorRefreshTenantHandler_Success(t *testing.T) {
	setupTestRegistry(t)

	req := httptest.NewRequest("POST", "/api/v1/connectors/refresh/tenant-123", nil)
	req = mux.SetURLVars(req, map[string]string{"tenant_id": "tenant-123"})
	w := httptest.NewRecorder()

	connectorRefreshTenantHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp ConnectorRefreshResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("Expected success to be true")
	}
	if resp.Scope != "tenant" {
		t.Errorf("Expected scope 'tenant', got '%s'", resp.Scope)
	}
	if resp.TenantID != "tenant-123" {
		t.Errorf("Expected tenant_id 'tenant-123', got '%s'", resp.TenantID)
	}
}

// TestConnectorRefreshSingleHandler_MissingParams tests missing parameters
func TestConnectorRefreshSingleHandler_MissingParams(t *testing.T) {
	setupTestRegistry(t)

	tests := []struct {
		name     string
		tenantID string
		connName string
	}{
		{"missing tenant", "", "mydb"},
		{"missing connector", "tenant-123", ""},
		{"missing both", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/connectors/refresh/x/y", nil)
			req = mux.SetURLVars(req, map[string]string{
				"tenant_id":      tt.tenantID,
				"connector_name": tt.connName,
			})
			w := httptest.NewRecorder()

			connectorRefreshSingleHandler(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
			}
		})
	}
}

// TestConnectorRefreshSingleHandler_Success tests successful single connector refresh
func TestConnectorRefreshSingleHandler_Success(t *testing.T) {
	setupTestRegistry(t)

	req := httptest.NewRequest("POST", "/api/v1/connectors/refresh/tenant-123/mydb", nil)
	req = mux.SetURLVars(req, map[string]string{
		"tenant_id":      "tenant-123",
		"connector_name": "mydb",
	})
	w := httptest.NewRecorder()

	connectorRefreshSingleHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp ConnectorRefreshResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("Expected success to be true")
	}
	if resp.Scope != "connector" {
		t.Errorf("Expected scope 'connector', got '%s'", resp.Scope)
	}
	if resp.TenantID != "tenant-123" {
		t.Errorf("Expected tenant_id 'tenant-123', got '%s'", resp.TenantID)
	}
	if resp.Connector != "mydb" {
		t.Errorf("Expected connector 'mydb', got '%s'", resp.Connector)
	}
}

// TestConnectorCacheStatsHandler_NotInitialized tests stats when registry not initialized
func TestConnectorCacheStatsHandler_NotInitialized(t *testing.T) {
	clearTenantConnectorRegistry()

	req := httptest.NewRequest("GET", "/api/v1/connectors/cache/stats", nil)
	w := httptest.NewRecorder()

	connectorCacheStatsHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

// TestConnectorCacheStatsHandler_Success tests successful stats retrieval
func TestConnectorCacheStatsHandler_Success(t *testing.T) {
	setupTestRegistry(t)

	// Pre-populate some stats by doing operations
	registry := GetTenantConnectorRegistry()
	registry.recordHit()
	registry.recordHit()
	registry.recordMiss()

	req := httptest.NewRequest("GET", "/api/v1/connectors/cache/stats", nil)
	w := httptest.NewRecorder()

	connectorCacheStatsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["registry_enabled"] != true {
		t.Error("Expected registry_enabled to be true")
	}
	if resp["hits"].(float64) != 2 {
		t.Errorf("Expected 2 hits, got %v", resp["hits"])
	}
	if resp["misses"].(float64) != 1 {
		t.Errorf("Expected 1 miss, got %v", resp["misses"])
	}
}

// TestRefreshConnectorCacheWithContext tests programmatic refresh
func TestRefreshConnectorCacheWithContext(t *testing.T) {
	setupTestRegistry(t)
	ctx := context.Background()

	// Test refresh all
	err := RefreshConnectorCacheWithContext(ctx, "", "")
	if err != nil {
		t.Errorf("RefreshAll failed: %v", err)
	}

	// Test refresh tenant
	err = RefreshConnectorCacheWithContext(ctx, "tenant-123", "")
	if err != nil {
		t.Errorf("RefreshTenant failed: %v", err)
	}

	// Test refresh connector
	err = RefreshConnectorCacheWithContext(ctx, "tenant-123", "mydb")
	if err != nil {
		t.Errorf("RefreshConnector failed: %v", err)
	}
}

// TestRefreshConnectorCacheWithContext_NoRegistry tests programmatic refresh without registry
func TestRefreshConnectorCacheWithContext_NoRegistry(t *testing.T) {
	clearTenantConnectorRegistry()
	ctx := context.Background()

	// Should be no-op, not error
	err := RefreshConnectorCacheWithContext(ctx, "", "")
	if err != nil {
		t.Errorf("Expected nil error when registry not initialized, got: %v", err)
	}
}

// TestRegisterConnectorRefreshHandlers tests handler registration
func TestRegisterConnectorRefreshHandlers(t *testing.T) {
	r := mux.NewRouter()
	RegisterConnectorRefreshHandlers(r)

	// Check routes are registered
	routes := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/connectors/refresh"},
		{"POST", "/api/v1/connectors/refresh/test-tenant"},
		{"POST", "/api/v1/connectors/refresh/test-tenant/test-connector"},
		{"GET", "/api/v1/connectors/cache/stats"},
	}

	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, nil)
		match := &mux.RouteMatch{}
		if !r.Match(req, match) {
			t.Errorf("Route %s %s should be registered", route.method, route.path)
		}
	}
}
