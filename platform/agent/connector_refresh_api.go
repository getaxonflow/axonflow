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

// RefreshStatsInfo contains cache statistics after refresh
type RefreshStatsInfo struct {
	CachedConnectors int64   `json:"cached_connectors"`
	Hits             int64   `json:"hits"`
	Misses           int64   `json:"misses"`
	Evictions        int64   `json:"evictions"`
	HitRate          float64 `json:"hit_rate_percent"`
}

// RegisterConnectorRefreshHandlers adds connector refresh API endpoints to the router.
// These endpoints allow manual cache invalidation for connector configurations.
//
// Endpoints:
//   - POST /api/v1/connectors/refresh - Refresh all connectors
//   - POST /api/v1/connectors/refresh/{tenant_id} - Refresh tenant's connectors
//   - POST /api/v1/connectors/refresh/{tenant_id}/{connector_name} - Refresh specific connector
//   - GET /api/v1/connectors/cache/stats - Get cache statistics
func RegisterConnectorRefreshHandlers(r *mux.Router) {
	// Refresh all connectors
	r.HandleFunc("/api/v1/connectors/refresh", connectorRefreshAllHandler).Methods("POST")

	// Refresh by tenant
	r.HandleFunc("/api/v1/connectors/refresh/{tenant_id}", connectorRefreshTenantHandler).Methods("POST")

	// Refresh specific connector
	r.HandleFunc("/api/v1/connectors/refresh/{tenant_id}/{connector_name}", connectorRefreshSingleHandler).Methods("POST")

	// Cache statistics
	r.HandleFunc("/api/v1/connectors/cache/stats", connectorCacheStatsHandler).Methods("GET")

	log.Println("[Connector API] Registered connector refresh endpoints")
}

// connectorRefreshAllHandler refreshes all cached connectors
// POST /api/v1/connectors/refresh
func connectorRefreshAllHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	registry := GetTenantConnectorRegistry()
	if registry == nil {
		connectorRefreshTotal.WithLabelValues("all", "error").Inc()
		sendConnectorRefreshError(w, "TenantConnectorRegistry not initialized", http.StatusServiceUnavailable)
		return
	}

	// Refresh all cached connectors
	if err := registry.RefreshAll(ctx); err != nil {
		connectorRefreshTotal.WithLabelValues("all", "error").Inc()
		sendConnectorRefreshError(w, "Failed to refresh connectors: "+err.Error(), http.StatusInternalServerError)
		return
	}

	duration := time.Since(start)
	connectorRefreshTotal.WithLabelValues("all", "success").Inc()
	connectorRefreshDuration.WithLabelValues("all").Observe(duration.Seconds())

	stats := registry.GetStats()
	sendConnectorRefreshResponse(w, &ConnectorRefreshResponse{
		Success:  true,
		Message:  "All connector caches refreshed",
		Scope:    "all",
		Duration: duration.String(),
		Stats:    toRefreshStatsInfo(registry, &stats),
	})

	log.Printf("[Connector API] Refreshed all connectors in %v", duration)
}

// connectorRefreshTenantHandler refreshes connectors for a specific tenant
// POST /api/v1/connectors/refresh/{tenant_id}
func connectorRefreshTenantHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	vars := mux.Vars(r)
	tenantID := vars["tenant_id"]

	if tenantID == "" {
		connectorRefreshTotal.WithLabelValues("tenant", "error").Inc()
		sendConnectorRefreshError(w, "tenant_id is required", http.StatusBadRequest)
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

	stats := registry.GetStats()
	sendConnectorRefreshResponse(w, &ConnectorRefreshResponse{
		Success:  true,
		Message:  "Tenant connector caches refreshed",
		Scope:    "tenant",
		TenantID: tenantID,
		Duration: duration.String(),
		Stats:    toRefreshStatsInfo(registry, &stats),
	})

	log.Printf("[Connector API] Refreshed connectors for tenant '%s' in %v", tenantID, duration)
}

// connectorRefreshSingleHandler refreshes a specific connector for a tenant
// POST /api/v1/connectors/refresh/{tenant_id}/{connector_name}
func connectorRefreshSingleHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	vars := mux.Vars(r)
	tenantID := vars["tenant_id"]
	connectorName := vars["connector_name"]

	if tenantID == "" || connectorName == "" {
		connectorRefreshTotal.WithLabelValues("connector", "error").Inc()
		sendConnectorRefreshError(w, "tenant_id and connector_name are required", http.StatusBadRequest)
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

	stats := registry.GetStats()
	sendConnectorRefreshResponse(w, &ConnectorRefreshResponse{
		Success:   true,
		Message:   "Connector cache refreshed",
		Scope:     "connector",
		TenantID:  tenantID,
		Connector: connectorName,
		Duration:  duration.String(),
		Stats:     toRefreshStatsInfo(registry, &stats),
	})

	log.Printf("[Connector API] Refreshed connector '%s' for tenant '%s' in %v", connectorName, tenantID, duration)
}

// connectorCacheStatsHandler returns cache statistics
// GET /api/v1/connectors/cache/stats
func connectorCacheStatsHandler(w http.ResponseWriter, r *http.Request) {
	registry := GetTenantConnectorRegistry()
	if registry == nil {
		sendConnectorRefreshError(w, "TenantConnectorRegistry not initialized", http.StatusServiceUnavailable)
		return
	}

	stats := registry.GetStats()

	// Update Prometheus gauges
	connectorCacheStats.WithLabelValues("cached_connectors").Set(float64(registry.Count()))
	connectorCacheStats.WithLabelValues("hits").Set(float64(stats.Hits))
	connectorCacheStats.WithLabelValues("misses").Set(float64(stats.Misses))
	connectorCacheStats.WithLabelValues("evictions").Set(float64(stats.Evictions))
	connectorCacheStats.WithLabelValues("hit_rate").Set(registry.HitRate())

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"cached_connectors":    registry.Count(),
		"hits":                 stats.Hits,
		"misses":               stats.Misses,
		"evictions":            stats.Evictions,
		"factory_creations":    stats.FactoryCreations,
		"factory_failures":     stats.FactoryFailures,
		"connection_errors":    stats.ConnectionErrors,
		"hit_rate_percent":     registry.HitRate(),
		"last_eviction":        stats.LastEviction,
		"last_factory_create":  stats.LastFactoryCreate,
		"registry_enabled":     true,
		"timestamp":            time.Now().UTC(),
	}); err != nil {
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

func toRefreshStatsInfo(registry *TenantConnectorRegistry, stats *TenantRegistryStats) *RefreshStatsInfo {
	return &RefreshStatsInfo{
		CachedConnectors: int64(registry.Count()),
		Hits:             stats.Hits,
		Misses:           stats.Misses,
		Evictions:        stats.Evictions,
		HitRate:          registry.HitRate(),
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
