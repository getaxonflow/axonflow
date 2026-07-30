// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Authentication + tenant binding for the connector-facing agent routes
// (#3067 S-5 / S-6).
//
// Before this change:
//   - GET  /mcp/connectors and /mcp/connectors/{name}/health had NO auth
//     middleware and dumped every tenant's connector inventory, capabilities
//     and raw driver error strings; /health additionally opened a live
//     connection with the victim's decrypted credentials.
//   - POST /api/v1/connectors/refresh[/{tenant_id}[/{connector_name}]] and
//     GET /api/v1/connectors/cache/stats were registered bare on globalRouter
//     and took the tenant straight from the URL path, so an anonymous caller
//     could evict any tenant's connector pool (or every tenant's at once) and
//     read the eviction delta as an existence oracle.
//
// Vacuity: against the pre-fix code these routes were registered with
// r.HandleFunc (no middleware), so the unauthenticated requests below returned
// 200 rather than 401, and requireRefreshTenant did not exist at all.

package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
)

func withEnterpriseMode(t *testing.T) {
	t.Helper()
	old := os.Getenv("DEPLOYMENT_MODE")
	_ = os.Setenv("DEPLOYMENT_MODE", "enterprise")
	t.Cleanup(func() {
		if old != "" {
			_ = os.Setenv("DEPLOYMENT_MODE", old)
		} else {
			_ = os.Unsetenv("DEPLOYMENT_MODE")
		}
	})
}

// TestMCPConnectorRoutesRequireAuthentication is the S-5 gate: the inventory
// and per-connector health routes must refuse an anonymous caller outright.
func TestMCPConnectorRoutesRequireAuthentication(t *testing.T) {
	withEnterpriseMode(t)

	r := mux.NewRouter()
	RegisterMCPHandlers(r)

	for _, path := range []string{
		"/mcp/connectors",
		"/mcp/connectors/some-connector/health",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Errorf("%s served an unauthenticated caller (status 200): %s", path, w.Body.String())
			continue
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401 for an unauthenticated caller, got %d: %s", path, w.Code, w.Body.String())
		}
	}
}

// TestMCPConnectorRoutesRejectPreflightBypass (R3 BLOCKER): apiAuthMiddleware
// forwards CORS preflights UNAUTHENTICATED (auth.go: `if r.Method ==
// http.MethodOptions { next.ServeHTTP(...) }`). Registering these routes for
// "OPTIONS" would therefore hand an anonymous caller the handler with no
// identity in context — which resolves to the deployment-shared scope and
// serves the very inventory + live health check this change closes. They are
// registered GET-only, so an OPTIONS must not reach a handler at all.
func TestMCPConnectorRoutesRejectPreflightBypass(t *testing.T) {
	withEnterpriseMode(t)

	origRegistry := mcpRegistry
	mcpRegistry = registry.NewRegistry()
	t.Cleanup(func() { mcpRegistry = origRegistry })

	// A deployment-shared connector is the reachable half of the bypass: an
	// empty tenancy resolves to SharedTenant.
	shared := &listTestConnector{healthy: true}
	if err := mcpRegistry.Register("operator-db", shared,
		&base.ConnectorConfig{Name: "operator-db", Type: "postgres", TenantID: registry.SharedTenant, Timeout: time.Second}); err != nil {
		t.Fatalf("register shared: %v", err)
	}

	r := mux.NewRouter()
	RegisterMCPHandlers(r)

	for _, path := range []string{"/mcp/connectors", "/mcp/connectors/operator-db/health"} {
		req := httptest.NewRequest(http.MethodOptions, path, nil)
		req.Header.Set("Origin", "https://attacker.example")
		req.Header.Set("Access-Control-Request-Method", "GET")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Errorf("SECURITY: anonymous OPTIONS %s reached the handler (200): %s", path, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "operator-db") {
			t.Errorf("SECURITY: anonymous OPTIONS %s disclosed connector inventory: %s", path, w.Body.String())
		}
	}

	// The live health check must never have run for an anonymous preflight.
	if shared.healthChecks != 0 {
		t.Fatalf("SECURITY: an anonymous OPTIONS opened %d connection(s) with the connector's credentials", shared.healthChecks)
	}
}

// TestConnectorRefreshRoutesRequireAuthentication is the S-6 gate.
func TestConnectorRefreshRoutesRequireAuthentication(t *testing.T) {
	withEnterpriseMode(t)

	r := mux.NewRouter()
	RegisterConnectorRefreshHandlers(r)

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/connectors/refresh"},
		{http.MethodPost, "/api/v1/connectors/refresh/victim-org"},
		{http.MethodPost, "/api/v1/connectors/refresh/victim-org/customer-db"},
		{http.MethodGet, "/api/v1/connectors/cache/stats"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Errorf("%s %s served an unauthenticated caller: %s", c.method, c.path, w.Body.String())
			continue
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: expected 401, got %d: %s", c.method, c.path, w.Code, w.Body.String())
		}
	}
}

// authedRequest builds a request whose context already carries the identity
// apiAuthMiddleware would have stamped, so the handler's own binding logic can
// be exercised without a live credential.
func authedRequest(method, path, tenantID string, vars map[string]string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	if vars != nil {
		req = mux.SetURLVars(req, vars)
	}
	ctx := context.WithValue(req.Context(), ContextKeyTenantID, tenantID)
	ctx = context.WithValue(ctx, ContextKeyAuthKind, AuthKindEnterprise)
	return req.WithContext(ctx)
}

// TestConnectorRefreshBindsToAuthenticatedTenant: the {tenant_id} path segment
// is validated against the credential, never trusted.
func TestConnectorRefreshBindsToAuthenticatedTenant(t *testing.T) {
	origRegistry := GetTenantConnectorRegistry()
	SetTenantConnectorRegistry(NewTenantConnectorRegistry(TenantConnectorRegistryOptions{}))
	t.Cleanup(func() { SetTenantConnectorRegistry(origRegistry) })

	t.Run("refuses a path tenant that is not the caller", func(t *testing.T) {
		w := httptest.NewRecorder()
		connectorRefreshTenantHandler(w, authedRequest(
			http.MethodPost, "/api/v1/connectors/refresh/victim-org", "attacker-org",
			map[string]string{"tenant_id": "victim-org"}))

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for a foreign tenant_id, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("refuses a foreign tenant on the single-connector route", func(t *testing.T) {
		w := httptest.NewRecorder()
		connectorRefreshSingleHandler(w, authedRequest(
			http.MethodPost, "/api/v1/connectors/refresh/victim-org/customer-db", "attacker-org",
			map[string]string{"tenant_id": "victim-org", "connector_name": "customer-db"}))

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("allows the caller's own tenant", func(t *testing.T) {
		w := httptest.NewRecorder()
		connectorRefreshTenantHandler(w, authedRequest(
			http.MethodPost, "/api/v1/connectors/refresh/own-org", "own-org",
			map[string]string{"tenant_id": "own-org"}))

		if w.Code != http.StatusOK {
			t.Fatalf("positive control: a tenant must refresh its own pool, got %d: %s", w.Code, w.Body.String())
		}
		var resp ConnectorRefreshResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.TenantID != "own-org" {
			t.Errorf("expected tenant_id own-org, got %q", resp.TenantID)
		}
	})

	t.Run("refuses a caller with no authenticated tenant", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/connectors/refresh/any", nil)
		req = mux.SetURLVars(req, map[string]string{"tenant_id": "any"})
		connectorRefreshTenantHandler(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 without an authenticated tenant, got %d", w.Code)
		}
	})
}

// TestConnectorCacheStatsIsTenantScoped: the JSON body must not disclose the
// deployment-wide cache population or activity counters to a tenant.
func TestConnectorCacheStatsIsTenantScoped(t *testing.T) {
	origRegistry := GetTenantConnectorRegistry()
	SetTenantConnectorRegistry(NewTenantConnectorRegistry(TenantConnectorRegistryOptions{}))
	t.Cleanup(func() { SetTenantConnectorRegistry(origRegistry) })

	w := httptest.NewRecorder()
	connectorCacheStatsHandler(w, authedRequest(http.MethodGet, "/api/v1/connectors/cache/stats", "own-org", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["tenant_id"] != "own-org" {
		t.Errorf("expected the response to name the caller's tenant, got %v", body["tenant_id"])
	}
	for _, leaked := range []string{"hits", "misses", "evictions", "factory_creations", "hit_rate_percent"} {
		if _, present := body[leaked]; present {
			t.Errorf("deployment-wide counter %q disclosed to a tenant caller", leaked)
		}
	}
	if _, present := body["deployment"]; present {
		t.Error("deployment block must be reserved for the internal-service credential")
	}
}

// TestMCPListConnectorsIsTenantScoped drives the inventory handler behind the
// identity the middleware stamps and asserts the response carries only the
// caller's connectors — no names, capabilities or driver errors from others.
func TestMCPListConnectorsIsTenantScoped(t *testing.T) {
	origRegistry := mcpRegistry
	mcpRegistry = registry.NewRegistry()
	t.Cleanup(func() { mcpRegistry = origRegistry })

	if err := mcpRegistry.Register("victim-db", &listTestConnector{healthy: false, errText: "dial tcp victim-db.internal:5432: refused"},
		&base.ConnectorConfig{Name: "victim-db", Type: "postgres", TenantID: "victim-org", Timeout: time.Second}); err != nil {
		t.Fatalf("register victim: %v", err)
	}
	if err := mcpRegistry.Register("own-db", &listTestConnector{healthy: true},
		&base.ConnectorConfig{Name: "own-db", Type: "postgres", TenantID: "own-org", Timeout: time.Second}); err != nil {
		t.Fatalf("register own: %v", err)
	}

	w := httptest.NewRecorder()
	mcpListConnectorsHandler(w, authedRequest(http.MethodGet, "/mcp/connectors", "own-org", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Connectors []map[string]interface{} `json:"connectors"`
		Count      int                      `json:"count"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Count != 1 {
		t.Fatalf("expected exactly the caller's 1 connector, got %d: %+v", resp.Count, resp.Connectors)
	}
	if resp.Connectors[0]["name"] != "own-db" {
		t.Fatalf("positive control failed: expected own-db, got %v", resp.Connectors[0]["name"])
	}
	if b := w.Body.String(); strings.Contains(b, "victim-db") {
		t.Fatalf("response disclosed another tenant's connector or driver error: %s", b)
	}
}

// TestMCPConnectorHealthIsTenantScoped: naming a foreign connector must be
// indistinguishable from naming a nonexistent one, and must not open a
// connection with the victim's credentials.
func TestMCPConnectorHealthIsTenantScoped(t *testing.T) {
	origRegistry := mcpRegistry
	mcpRegistry = registry.NewRegistry()
	t.Cleanup(func() { mcpRegistry = origRegistry })

	victim := &listTestConnector{healthy: true}
	if err := mcpRegistry.Register("victim-db", victim,
		&base.ConnectorConfig{Name: "victim-db", Type: "postgres", TenantID: "victim-org", Timeout: time.Second}); err != nil {
		t.Fatalf("register victim: %v", err)
	}
	own := &listTestConnector{healthy: true}
	if err := mcpRegistry.Register("own-db", own,
		&base.ConnectorConfig{Name: "own-db", Type: "postgres", TenantID: "own-org", Timeout: time.Second}); err != nil {
		t.Fatalf("register own: %v", err)
	}

	w := httptest.NewRecorder()
	mcpConnectorHealthHandler(w, authedRequest(http.MethodGet, "/mcp/connectors/victim-db/health",
		"own-org", map[string]string{"name": "victim-db"}))

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a foreign connector, got %d: %s", w.Code, w.Body.String())
	}
	if victim.healthChecks != 0 {
		t.Fatalf("the victim's connector was health-checked %d time(s) by another tenant", victim.healthChecks)
	}

	// Positive control: the owner's own connector still health-checks.
	w = httptest.NewRecorder()
	mcpConnectorHealthHandler(w, authedRequest(http.MethodGet, "/mcp/connectors/own-db/health",
		"own-org", map[string]string{"name": "own-db"}))

	if w.Code != http.StatusOK {
		t.Fatalf("positive control: owner health check must succeed, got %d: %s", w.Code, w.Body.String())
	}
	if own.healthChecks != 1 {
		t.Fatalf("positive control: expected 1 health check on the owner's connector, got %d", own.healthChecks)
	}
}

// listTestConnector is a minimal base.Connector that records health checks.
type listTestConnector struct {
	healthy      bool
	errText      string
	healthChecks int
}

func (c *listTestConnector) Connect(ctx context.Context, cfg *base.ConnectorConfig) error { return nil }
func (c *listTestConnector) Disconnect(ctx context.Context) error                         { return nil }
func (c *listTestConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	c.healthChecks++
	return &base.HealthStatus{Healthy: c.healthy, Error: c.errText, Timestamp: time.Now()}, nil
}
func (c *listTestConnector) Query(ctx context.Context, q *base.Query) (*base.QueryResult, error) {
	return &base.QueryResult{}, nil
}
func (c *listTestConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return &base.CommandResult{}, nil
}
func (c *listTestConnector) Type() string           { return "postgres" }
func (c *listTestConnector) Version() string        { return "1.0.0" }
func (c *listTestConnector) Capabilities() []string { return []string{"query"} }
func (c *listTestConnector) Name() string           { return "list-test" }
