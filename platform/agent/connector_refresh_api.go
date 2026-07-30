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
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics for connector refresh operations
var (
	connectorRefreshTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_connector_refresh_total",
			Help: "Total number of connector refresh operations",
		},
		[]string{"scope", "status"},
	)

	connectorRefreshDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "axonflow_connector_refresh_duration_seconds",
			Help:    "Duration of connector refresh operations",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"scope"},
	)

	connectorCacheStats = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "axonflow_connector_cache_stats",
			Help: "Connector cache statistics",
		},
		[]string{"stat"},
	)
)

// ConnectorRefreshRequest represents a request to refresh connector cache
type ConnectorRefreshRequest struct {
	TenantID      string `json:"tenant_id,omitempty"`      // Optional: specific tenant
	ConnectorName string `json:"connector_name,omitempty"` // Optional: specific connector
}

// ConnectorRefreshResponse represents the response from a refresh operation
type ConnectorRefreshResponse struct {
	Success   bool              `json:"success"`
	Message   string            `json:"message"`
	Scope     string            `json:"scope"` // "all", "tenant", "connector"
	TenantID  string            `json:"tenant_id,omitempty"`
	Connector string            `json:"connector,omitempty"`
	Stats     *RefreshStatsInfo `json:"stats,omitempty"`
	Duration  string            `json:"duration"`
}

// RefreshStatsInfo contains the cache statistics a refresh response may carry.
//
// #3067 (S-6): this used to also carry `hits`, `misses`, `evictions` and
// `hit_rate_percent`. Those are deployment-wide counters — they disclose other
// tenants' cache activity and made a targeted refresh's eviction delta an
// existence oracle — so they were dropped from the refresh path entirely.
//
// They were REMOVED rather than tagged `omitempty`: no producer sets them, and
// `omitempty` on an int64/float64 counter is the wrong tool anyway — it erases
// a legitimate zero, which is a real value for a hit counter. Operators read
// the un-scoped counters from /prometheus, or from the `deployment` block of
// GET /api/v1/connectors/cache/stats with the internal-service credential.
type RefreshStatsInfo struct {
	// CachedConnectors is the caller's own cached-connector count, or — for a
	// deployment-wide refresh performed with the internal-service credential —
	// the deployment-wide count, matching the scope of the work just done.
	CachedConnectors int64 `json:"cached_connectors"`
}

// RegisterConnectorRefreshHandlers adds connector refresh API endpoints to the router.
// These endpoints allow manual cache invalidation for connector configurations.
//
// Endpoints:
//   - POST /api/v1/connectors/refresh - Refresh the caller's connectors (all tenants for internal-service callers)
//   - POST /api/v1/connectors/refresh/{tenant_id} - Refresh tenant's connectors
//   - POST /api/v1/connectors/refresh/{tenant_id}/{connector_name} - Refresh specific connector
//   - GET /api/v1/connectors/cache/stats - Get cache statistics
//
// #3067 (S-6) / #2883: all four were registered bare on globalRouter — no auth
// middleware at all — and took the tenant straight from the URL path with no
// caller binding. Unauthenticated, anyone could evict any named tenant's
// connector pool or every tenant's at once, and read the `evictions` delta as
// an existence oracle for (tenant, connector) pairs. They are now behind
// apiAuthMiddleware and bound to the authenticated tenant; the {tenant_id}
// path segment is validated against it rather than trusted. That is #2883's
// stated fix verbatim ("wrap the subrouter in apiAuthMiddleware ... and scope
// per-tenant refresh to the authenticated org"), so this closes it.
//
// Registered for their real methods ONLY (no "OPTIONS"): apiAuthMiddleware
// forwards CORS preflights unauthenticated, so an OPTIONS registration would
// reach the handler with no identity in context. requireRefreshTenant would
// 401 anyway, but keeping the surface off is the cheaper guarantee.
//
// The gate is applied HERE rather than on a subrouter, so it travels with the
// handler and cannot be bypassed by route ordering. These four exact paths are
// nonetheless registered before proxy.go's PathPrefix("/api/v1/connectors")
// (run.go:1416 vs run.go:1675) and only win because gorilla/mux matches in
// registration order — a re-order would silently 404/405 them via the
// orchestrator. That fragility is tracked as #3102; it is an availability
// class, not an authn one, and is NOT what #2883 tracks.
func RegisterConnectorRefreshHandlers(r *mux.Router) {
	// Refresh all connectors the caller owns
	r.Handle("/api/v1/connectors/refresh", apiAuthMiddleware(http.HandlerFunc(connectorRefreshAllHandler))).Methods("POST")

	// Refresh by tenant
	r.Handle("/api/v1/connectors/refresh/{tenant_id}", apiAuthMiddleware(http.HandlerFunc(connectorRefreshTenantHandler))).Methods("POST")

	// Refresh specific connector
	r.Handle("/api/v1/connectors/refresh/{tenant_id}/{connector_name}", apiAuthMiddleware(http.HandlerFunc(connectorRefreshSingleHandler))).Methods("POST")

	// Cache statistics
	r.Handle("/api/v1/connectors/cache/stats", apiAuthMiddleware(http.HandlerFunc(connectorCacheStatsHandler))).Methods("GET")

	log.Println("[Connector API] Registered connector refresh endpoints (authenticated, tenant-scoped)")
}

// requireRefreshTenant resolves the authenticated tenant for a connector-cache
// request, or writes the refusal and returns false.
//
// The tenancy comes from the auth context populated by apiAuthMiddleware —
// never from the {tenant_id} path segment. When a path segment IS present it
// must equal the authenticated tenant; a mismatch is 403 rather than a silent
// downgrade, so an operator who mistypes a tenant learns about it.
func requireRefreshTenant(w http.ResponseWriter, r *http.Request, scope string) (string, bool) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		connectorRefreshTotal.WithLabelValues(scope, "error").Inc()
		sendConnectorRefreshError(w, "authenticated tenant required", http.StatusUnauthorized)
		return "", false
	}

	if pathTenant := mux.Vars(r)["tenant_id"]; pathTenant != "" && pathTenant != tenantID {
		connectorRefreshTotal.WithLabelValues(scope, "error").Inc()
		sendConnectorRefreshError(w, "tenant_id does not match the authenticated tenant", http.StatusForbidden)
		return "", false
	}

	return tenantID, true
}

// connectorRefreshAllHandler refreshes all cached connectors
// POST /api/v1/connectors/refresh
func connectorRefreshAllHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	tenantID, ok := requireRefreshTenant(w, r, "all")
	if !ok {
		return
	}

	registry := GetTenantConnectorRegistry()
	if registry == nil {
		connectorRefreshTotal.WithLabelValues("all", "error").Inc()
		sendConnectorRefreshError(w, "TenantConnectorRegistry not initialized", http.StatusServiceUnavailable)
		return
	}

	// #3067 (S-6): a true deployment-wide eviction is reserved for the
	// internal-service credential (the customer-portal's HMAC-signed identity
	// — the operator lane the runbook uses). A customer credential refreshes
	// its OWN pool: letting a tenant evict every tenant's connectors is a
	// free availability lever.
	deploymentWide := AuthKindFromContext(ctx) == AuthKindInternalService

	var err error
	message := "Tenant connector caches refreshed"
	if deploymentWide {
		err = registry.RefreshAll(ctx)
		message = "All connector caches refreshed"
	} else {
		err = registry.RefreshTenant(ctx, tenantID)
	}
	if err != nil {
		connectorRefreshTotal.WithLabelValues("all", "error").Inc()
		sendConnectorRefreshError(w, "Failed to refresh connectors: "+err.Error(), http.StatusInternalServerError)
		return
	}

	duration := time.Since(start)
	connectorRefreshTotal.WithLabelValues("all", "success").Inc()
	connectorRefreshDuration.WithLabelValues("all").Observe(duration.Seconds())

	resp := &ConnectorRefreshResponse{
		Success:  true,
		Message:  message,
		Scope:    "all",
		Duration: duration.String(),
		Stats:    tenantRefreshStats(registry, tenantID),
	}
	if deploymentWide {
		resp.Stats = deploymentRefreshStats(registry)
	} else {
		resp.TenantID = tenantID
	}
	sendConnectorRefreshResponse(w, resp)

	log.Printf("[Connector API] Refreshed connectors (deployment_wide=%t) in %v", deploymentWide, duration)
}

// connectorRefreshTenantHandler refreshes connectors for a specific tenant
// POST /api/v1/connectors/refresh/{tenant_id}
func connectorRefreshTenantHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	if vars := mux.Vars(r); vars["tenant_id"] == "" {
		connectorRefreshTotal.WithLabelValues("tenant", "error").Inc()
		sendConnectorRefreshError(w, "tenant_id is required", http.StatusBadRequest)
		return
	}

	// Authenticated tenant wins; the path segment is only validated against it.
	tenantID, ok := requireRefreshTenant(w, r, "tenant")
	if !ok {
		return
	}

	registry := GetTenantConnectorRegistry()
	if registry == nil {
		connectorRefreshTotal.WithLabelValues("tenant", "error").Inc()
		sendConnectorRefreshError(w, "TenantConnectorRegistry not initialized", http.StatusServiceUnavailable)
		return
	}

	// Refresh connectors for this tenant
	if err := registry.RefreshTenant(ctx, tenantID); err != nil {
		connectorRefreshTotal.WithLabelValues("tenant", "error").Inc()
		sendConnectorRefreshError(w, "Failed to refresh tenant connectors: "+err.Error(), http.StatusInternalServerError)
		return
	}

	duration := time.Since(start)
	connectorRefreshTotal.WithLabelValues("tenant", "success").Inc()
	connectorRefreshDuration.WithLabelValues("tenant").Observe(duration.Seconds())

	sendConnectorRefreshResponse(w, &ConnectorRefreshResponse{
		Success:  true,
		Message:  "Tenant connector caches refreshed",
		Scope:    "tenant",
		TenantID: tenantID,
		Duration: duration.String(),
		Stats:    tenantRefreshStats(registry, tenantID),
	})

	log.Printf("[Connector API] Refreshed connectors for tenant '%s' in %v", tenantID, duration)
}

// connectorRefreshSingleHandler refreshes a specific connector for a tenant
// POST /api/v1/connectors/refresh/{tenant_id}/{connector_name}
func connectorRefreshSingleHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	vars := mux.Vars(r)
	connectorName := vars["connector_name"]

	if vars["tenant_id"] == "" || connectorName == "" {
		connectorRefreshTotal.WithLabelValues("connector", "error").Inc()
		sendConnectorRefreshError(w, "tenant_id and connector_name are required", http.StatusBadRequest)
		return
	}

	tenantID, ok := requireRefreshTenant(w, r, "connector")
	if !ok {
		return
	}

	registry := GetTenantConnectorRegistry()
	if registry == nil {
		connectorRefreshTotal.WithLabelValues("connector", "error").Inc()
		sendConnectorRefreshError(w, "TenantConnectorRegistry not initialized", http.StatusServiceUnavailable)
		return
	}

	// Refresh specific connector
	if err := registry.RefreshConnector(ctx, tenantID, connectorName); err != nil {
		connectorRefreshTotal.WithLabelValues("connector", "error").Inc()
		sendConnectorRefreshError(w, "Failed to refresh connector: "+err.Error(), http.StatusInternalServerError)
		return
	}

	duration := time.Since(start)
	connectorRefreshTotal.WithLabelValues("connector", "success").Inc()
	connectorRefreshDuration.WithLabelValues("connector").Observe(duration.Seconds())

	sendConnectorRefreshResponse(w, &ConnectorRefreshResponse{
		Success:   true,
		Message:   "Connector cache refreshed",
		Scope:     "connector",
		TenantID:  tenantID,
		Connector: connectorName,
		Duration:  duration.String(),
		Stats:     tenantRefreshStats(registry, tenantID),
	})

	log.Printf("[Connector API] Refreshed connector '%s' for tenant '%s' in %v", connectorName, tenantID, duration)
}

// connectorCacheStatsHandler returns cache statistics
// GET /api/v1/connectors/cache/stats
func connectorCacheStatsHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := requireRefreshTenant(w, r, "stats")
	if !ok {
		return
	}

	registry := GetTenantConnectorRegistry()
	if registry == nil {
		sendConnectorRefreshError(w, "TenantConnectorRegistry not initialized", http.StatusServiceUnavailable)
		return
	}

	stats := registry.GetStats()

	// Update Prometheus gauges. These stay deployment-wide: /prometheus is an
	// operator surface, not a tenant one.
	connectorCacheStats.WithLabelValues("cached_connectors").Set(float64(registry.Count()))
	connectorCacheStats.WithLabelValues("hits").Set(float64(stats.Hits))
	connectorCacheStats.WithLabelValues("misses").Set(float64(stats.Misses))
	connectorCacheStats.WithLabelValues("evictions").Set(float64(stats.Evictions))
	connectorCacheStats.WithLabelValues("hit_rate").Set(registry.HitRate())

	// #3067 (S-6): the JSON body is tenant-scoped. It used to return the
	// deployment-wide cached-connector count and hit/miss/eviction counters,
	// which disclose other tenants' cache population and activity volume —
	// and made the `evictions` delta an existence oracle for a targeted
	// (tenant, connector) refresh. Operators read the same counters, un-
	// scoped, from /prometheus.
	body := map[string]interface{}{
		"tenant_id":         tenantID,
		"cached_connectors": registry.CountByTenant(tenantID),
		"registry_enabled":  true,
		"timestamp":         time.Now().UTC(),
	}
	if AuthKindFromContext(r.Context()) == AuthKindInternalService {
		body["deployment"] = map[string]interface{}{
			"cached_connectors":   registry.Count(),
			"hits":                stats.Hits,
			"misses":              stats.Misses,
			"evictions":           stats.Evictions,
			"factory_creations":   stats.FactoryCreations,
			"factory_failures":    stats.FactoryFailures,
			"connection_errors":   stats.ConnectionErrors,
			"hit_rate_percent":    registry.HitRate(),
			"last_eviction":       stats.LastEviction,
			"last_factory_create": stats.LastFactoryCreate,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("Error encoding cache stats response: %v", err)
	}
}

// RefreshConnectorCacheWithContext refreshes connector cache programmatically.
// This is useful for internal cache invalidation (e.g., after config changes).
func RefreshConnectorCacheWithContext(ctx context.Context, tenantID, connectorName string) error {
	registry := GetTenantConnectorRegistry()
	if registry == nil {
		return nil // No-op if not initialized
	}

	if tenantID == "" && connectorName == "" {
		return registry.RefreshAll(ctx)
	}

	if connectorName == "" {
		return registry.RefreshTenant(ctx, tenantID)
	}

	return registry.RefreshConnector(ctx, tenantID, connectorName)
}

// Helper functions

// tenantRefreshStats reports only what the calling tenant may observe about
// the cache (#3067 S-6): its own cached-connector count. The deployment-wide
// hit/miss/eviction counters are operator telemetry and stay on /prometheus —
// returning them here disclosed other tenants' cache activity and gave a
// targeted refresh an eviction-delta oracle. RefreshStatsInfo no longer has
// fields for them, so no caller can reintroduce them by accident.
func tenantRefreshStats(registry *TenantConnectorRegistry, tenantID string) *RefreshStatsInfo {
	return &RefreshStatsInfo{
		CachedConnectors: int64(registry.CountByTenant(tenantID)),
	}
}

// deploymentRefreshStats is the internal-service counterpart: a deployment-wide
// refresh reports the deployment-wide cached-connector count, so the number
// describes the work that was actually done. The internal-service credential
// already reads this same figure from the `deployment` block of
// GET /api/v1/connectors/cache/stats, so this discloses nothing new.
func deploymentRefreshStats(registry *TenantConnectorRegistry) *RefreshStatsInfo {
	return &RefreshStatsInfo{
		CachedConnectors: int64(registry.Count()),
	}
}

func sendConnectorRefreshError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	}); err != nil {
		log.Printf("Error encoding connector refresh error response: %v", err)
	}
}

func sendConnectorRefreshResponse(w http.ResponseWriter, resp *ConnectorRefreshResponse) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Error encoding connector refresh response: %v", err)
	}
}
