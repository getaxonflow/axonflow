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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/connectors/base"
)

// refreshTestTenant is the authenticated tenancy these handler tests run as.
// #3067 put every connector-cache route behind apiAuthMiddleware and bound it
// to the credential, so a handler-level test has to supply the identity the
// middleware would have stamped into the request context.
const refreshTestTenant = "tenant-123"

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

	req := authedRequest("POST", "/api/v1/connectors/refresh", refreshTestTenant, nil)
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

	req := authedRequest("POST", "/api/v1/connectors/refresh", refreshTestTenant, nil)
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

	req := authedRequest("POST", "/api/v1/connectors/refresh/", refreshTestTenant, map[string]string{"tenant_id": ""})
	w := httptest.NewRecorder()

	connectorRefreshTenantHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestConnectorRefreshTenantHandler_Success tests successful tenant refresh
func TestConnectorRefreshTenantHandler_Success(t *testing.T) {
	setupTestRegistry(t)

	req := authedRequest("POST", "/api/v1/connectors/refresh/tenant-123", refreshTestTenant,
		map[string]string{"tenant_id": refreshTestTenant})
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
			req := authedRequest("POST", "/api/v1/connectors/refresh/x/y", refreshTestTenant, map[string]string{
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

	req := authedRequest("POST", "/api/v1/connectors/refresh/tenant-123/mydb", refreshTestTenant, map[string]string{
		"tenant_id":      refreshTestTenant,
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

// seedCachedConnectors puts entries straight into the registry map so a
// handler test can observe a real cached-connector count without a live
// RuntimeConfigService.
func seedCachedConnectors(r *TenantConnectorRegistry, tenantID string, names ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, name := range names {
		r.connectors[connectorKey(tenantID, name)] = &TenantConnectorEntry{
			Config:     &base.ConnectorConfig{Name: name, TenantID: tenantID},
			CreatedAt:  time.Now(),
			LastAccess: time.Now(),
			ExpiresAt:  time.Now().Add(time.Hour),
		}
	}
}

// refreshStatsKeys decodes a refresh response and returns the exact key set of
// its `stats` object, so the wire shape is asserted rather than assumed.
func refreshStatsKeys(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()

	var envelope struct {
		Stats map[string]interface{} `json:"stats"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode refresh response: %v (body: %s)", err, body)
	}
	if envelope.Stats == nil {
		t.Fatalf("refresh response carried no stats object: %s", body)
	}
	return envelope.Stats
}

// TestConnectorRefreshResponseShapeIsTenantScoped pins the refresh wire shape
// (#3067 S-6 follow-up).
//
// The counters were dropped from RefreshStatsInfo rather than tagged
// `omitempty`, because `omitempty` would erase a legitimate zero — and a zero
// IS a real value for a hit counter. Without this test the struct could regain
// them silently: nothing else asserts the field SET, only individual values.
//
// Vacuity: against the previous struct every case below fails, because
// tenantRefreshStats never populated hits/misses/evictions/hit_rate_percent
// and encoding/json emitted all four as hard zeros on every response.
func TestConnectorRefreshResponseShapeIsTenantScoped(t *testing.T) {
	setupTestRegistry(t)

	registry := GetTenantConnectorRegistry()
	// Non-zero deployment-wide counters: if any of them could reach the wire,
	// these are the values that would show up.
	registry.recordHit()
	registry.recordHit()
	registry.recordMiss()
	registry.recordEvictions(3)

	reseed := func() {
		seedCachedConnectors(registry, refreshTestTenant, "mydb", "other-db")
		seedCachedConnectors(registry, "someone-else-org", "their-db", "their-other-db")
	}

	asInternalService := func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), ContextKeyAuthKind, AuthKindInternalService))
	}

	cases := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		request func() *http.Request
	}{
		{
			name:    "refresh all (tenant credential)",
			handler: connectorRefreshAllHandler,
			request: func() *http.Request {
				return authedRequest("POST", "/api/v1/connectors/refresh", refreshTestTenant, nil)
			},
		},
		{
			name:    "refresh all (internal-service credential, deployment-wide)",
			handler: connectorRefreshAllHandler,
			request: func() *http.Request {
				return asInternalService(authedRequest("POST", "/api/v1/connectors/refresh", refreshTestTenant, nil))
			},
		},
		{
			name:    "refresh tenant",
			handler: connectorRefreshTenantHandler,
			request: func() *http.Request {
				return authedRequest("POST", "/api/v1/connectors/refresh/"+refreshTestTenant, refreshTestTenant,
					map[string]string{"tenant_id": refreshTestTenant})
			},
		},
		{
			name:    "refresh single connector",
			handler: connectorRefreshSingleHandler,
			request: func() *http.Request {
				return authedRequest("POST", "/api/v1/connectors/refresh/"+refreshTestTenant+"/mydb", refreshTestTenant,
					map[string]string{"tenant_id": refreshTestTenant, "connector_name": "mydb"})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reseed()

			w := httptest.NewRecorder()
			tc.handler(w, tc.request())

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}

			stats := refreshStatsKeys(t, w.Body.Bytes())
			if len(stats) != 1 {
				t.Errorf("stats must carry exactly cached_connectors, got %d field(s): %v", len(stats), stats)
			}
			if _, ok := stats["cached_connectors"]; !ok {
				t.Errorf("stats lost cached_connectors: %v", stats)
			}
			for _, counter := range []string{"hits", "misses", "evictions", "hit_rate_percent",
				"factory_creations", "factory_failures", "connection_errors", "last_eviction"} {
				if _, present := stats[counter]; present {
					t.Errorf("deployment-wide counter %q is back on the refresh response (value %v) — "+
						"tenantRefreshStats never sets it, so it serializes as a misleading hard zero",
						counter, stats[counter])
				}
			}
			// Belt and braces: the counter names must not appear anywhere in
			// the body, not merely outside the stats object.
			for _, counter := range []string{`"hits"`, `"misses"`, `"evictions"`, `"hit_rate_percent"`} {
				if strings.Contains(w.Body.String(), counter) {
					t.Errorf("refresh response body still contains %s: %s", counter, w.Body.String())
				}
			}
		})
	}

	// Anti-vacuity: cached_connectors is a real number, not a placeholder the
	// assertions above would pass on regardless. Refreshing one of the
	// tenant's two connectors leaves exactly one cached.
	t.Run("cached_connectors reports the caller's real count", func(t *testing.T) {
		reseed()

		w := httptest.NewRecorder()
		connectorRefreshSingleHandler(w, authedRequest("POST", "/api/v1/connectors/refresh/"+refreshTestTenant+"/mydb",
			refreshTestTenant, map[string]string{"tenant_id": refreshTestTenant, "connector_name": "mydb"}))

		stats := refreshStatsKeys(t, w.Body.Bytes())
		if got := stats["cached_connectors"]; got != float64(1) {
			t.Fatalf("expected cached_connectors 1 after evicting 1 of the tenant's 2 connectors, got %v", got)
		}
		// And it is the CALLER's count, not the deployment's (4 seeded).
		if got := stats["cached_connectors"]; got == float64(3) {
			t.Fatalf("cached_connectors leaked the deployment-wide count: %v", got)
		}
	})
}

// TestConnectorCacheStatsHandler_NotInitialized tests stats when registry not initialized
func TestConnectorCacheStatsHandler_NotInitialized(t *testing.T) {
	clearTenantConnectorRegistry()

	req := authedRequest("GET", "/api/v1/connectors/cache/stats", refreshTestTenant, nil)
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

	req := authedRequest("GET", "/api/v1/connectors/cache/stats", refreshTestTenant, nil)
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
	if resp["tenant_id"] != refreshTestTenant {
		t.Errorf("Expected tenant_id %q, got %v", refreshTestTenant, resp["tenant_id"])
	}
	// #3067: the deployment-wide hit/miss counters are no longer served to a
	// tenant caller — they disclose other tenants' cache activity. Operators
	// read them un-scoped from /prometheus (still updated above).
	if _, leaked := resp["hits"]; leaked {
		t.Error("deployment-wide hit counter disclosed to a tenant caller")
	}
	if _, leaked := resp["misses"]; leaked {
		t.Error("deployment-wide miss counter disclosed to a tenant caller")
	}
}

// TestConnectorCacheStatsHandler_InternalServiceSeesDeploymentCounters keeps
// the operator lane working: the customer-portal's HMAC-signed internal-service
// credential still gets the deployment-wide counters (#3067).
func TestConnectorCacheStatsHandler_InternalServiceSeesDeploymentCounters(t *testing.T) {
	setupTestRegistry(t)

	registry := GetTenantConnectorRegistry()
	registry.recordHit()
	registry.recordHit()
	registry.recordMiss()

	req := authedRequest("GET", "/api/v1/connectors/cache/stats", refreshTestTenant, nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyAuthKind, AuthKindInternalService))
	w := httptest.NewRecorder()

	connectorCacheStatsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	deployment, ok := resp["deployment"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected a deployment block for the internal-service credential, got %v", resp)
	}
	if deployment["hits"].(float64) != 2 {
		t.Errorf("Expected 2 hits, got %v", deployment["hits"])
	}
	if deployment["misses"].(float64) != 1 {
		t.Errorf("Expected 1 miss, got %v", deployment["misses"])
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
