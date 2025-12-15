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
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/config"
)

// Connector name constants for validation and consistency.
// Use these constants instead of magic strings when referencing connectors.
const (
	ConnectorPostgres   = "postgres"
	ConnectorMySQL      = "mysql"
	ConnectorMongoDB    = "mongodb"
	ConnectorCassandra  = "cassandra"
	ConnectorRedis      = "redis"
	ConnectorHTTP       = "http"
	ConnectorS3         = "s3"
	ConnectorAzureBlob  = "azure_blob"
	ConnectorGCS        = "gcs"
	ConnectorAmadeus    = "amadeus"
	ConnectorSalesforce = "salesforce"
	ConnectorSlack      = "slack"
	ConnectorSnowflake  = "snowflake"
	ConnectorHubSpot    = "hubspot"
	ConnectorJira       = "jira"
	ConnectorServiceNow = "servicenow"
)

// ValidConnectorTypes is the list of supported connector types.
var ValidConnectorTypes = []string{
	ConnectorPostgres,
	ConnectorMySQL,
	ConnectorMongoDB,
	ConnectorCassandra,
	ConnectorRedis,
	ConnectorHTTP,
	ConnectorS3,
	ConnectorAzureBlob,
	ConnectorGCS,
	ConnectorAmadeus,
	ConnectorSalesforce,
	ConnectorSlack,
	ConnectorSnowflake,
	ConnectorHubSpot,
	ConnectorJira,
	ConnectorServiceNow,
}

// IsValidConnectorType checks if the given connector type is valid.
func IsValidConnectorType(connectorType string) bool {
	for _, ct := range ValidConnectorTypes {
		if ct == connectorType {
			return true
		}
	}
	return false
}

// tenantConnectorRegistryMu protects access to tenantConnectorRegistry global variable.
// This mutex ensures thread-safe initialization and access during concurrent operations.
var tenantConnectorRegistryMu sync.RWMutex

// tenantConnectorRegistry is the global TenantConnectorRegistry instance for the agent.
// It implements ADR-007 dynamic connector loading: per-tenant connector isolation.
// Access to this variable must be protected by tenantConnectorRegistryMu.
var tenantConnectorRegistry *TenantConnectorRegistry

// TenantConnectorEntry represents a cached connector with its config and expiration.
type TenantConnectorEntry struct {
	Connector  base.Connector
	Config     *base.ConnectorConfig
	CreatedAt  time.Time
	LastAccess time.Time
	ExpiresAt  time.Time
}

// IsExpired checks if the connector cache entry has expired.
func (e *TenantConnectorEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// TenantConnectorRegistry provides per-tenant connector management with dynamic loading.
// It implements ADR-007 runtime connector configuration by:
// 1. Loading connector configs from RuntimeConfigService (DB > File > Env)
// 2. Caching connector instances per-tenant with 30-second TTL
// 3. Supporting lazy initialization of connectors on first use
// 4. Providing thread-safe concurrent access
type TenantConnectorRegistry struct {
	mu sync.RWMutex

	// connectors stores per-tenant connector instances
	// key format: "tenantID:connectorName"
	connectors map[string]*TenantConnectorEntry

	// configSvc is the RuntimeConfigService for three-tier configuration
	configSvc *config.RuntimeConfigService

	// factory creates connector instances from type names
	factory ConnectorFactory

	// cacheTTL is the time-to-live for cached connectors
	cacheTTL time.Duration

	// logger for registry operations
	logger *log.Logger

	// stats tracks cache performance
	stats TenantRegistryStats
}

// TenantRegistryStats tracks cache performance metrics.
type TenantRegistryStats struct {
	mu                sync.Mutex
	Hits              int64
	Misses            int64
	Evictions         int64
	FactoryCreations  int64
	FactoryFailures   int64
	ConnectionErrors  int64
	LastEviction      time.Time
	LastFactoryCreate time.Time
}

// ConnectorFactory creates a connector instance based on type.
type ConnectorFactory func(connectorType string) (base.Connector, error)

// TenantConnectorRegistryOptions holds options for creating a TenantConnectorRegistry.
type TenantConnectorRegistryOptions struct {
	ConfigService *config.RuntimeConfigService
	Factory       ConnectorFactory
	CacheTTL      time.Duration
	Logger        *log.Logger
}

// NewTenantConnectorRegistry creates a new TenantConnectorRegistry.
func NewTenantConnectorRegistry(opts TenantConnectorRegistryOptions) *TenantConnectorRegistry {
	logger := opts.Logger
	if logger == nil {
		logger = log.New(os.Stdout, "[TENANT_CONNECTOR_REGISTRY] ", log.LstdFlags)
	}

	cacheTTL := opts.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Second // Default 30s TTL as per ADR-007
	}

	return &TenantConnectorRegistry{
		connectors: make(map[string]*TenantConnectorEntry),
		configSvc:  opts.ConfigService,
		factory:    opts.Factory,
		cacheTTL:   cacheTTL,
		logger:     logger,
	}
}

// connectorKey generates a cache key for a tenant's connector.
func connectorKey(tenantID, connectorName string) string {
	return tenantID + ":" + connectorName
}

// GetConnector retrieves a connector for a specific tenant.
// It first checks the cache, then loads from RuntimeConfigService if not cached.
// Returns the connector or an error if not found or creation fails.
func (r *TenantConnectorRegistry) GetConnector(ctx context.Context, tenantID, connectorName string) (base.Connector, error) {
	key := connectorKey(tenantID, connectorName)

	// Fast path: check cache with read lock
	r.mu.RLock()
	entry, exists := r.connectors[key]
	if exists && !entry.IsExpired() {
		connector := entry.Connector
		r.mu.RUnlock()
		// Update last access with write lock (separate from read path to avoid data race)
		r.updateLastAccess(key)
		r.recordHit()
		return connector, nil
	}
	r.mu.RUnlock()

	// Slow path: need to create or refresh connector
	return r.loadConnector(ctx, tenantID, connectorName)
}

// updateLastAccess updates the last access time for a cache entry.
// This is separated from the read path to avoid holding a write lock during reads.
func (r *TenantConnectorRegistry) updateLastAccess(key string) {
	r.mu.Lock()
	if entry, exists := r.connectors[key]; exists {
		entry.LastAccess = time.Now()
	}
	r.mu.Unlock()
}

// loadConnector loads a connector from RuntimeConfigService and caches it.
func (r *TenantConnectorRegistry) loadConnector(ctx context.Context, tenantID, connectorName string) (base.Connector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := connectorKey(tenantID, connectorName)

	// Double-check if another goroutine already loaded it
	entry, exists := r.connectors[key]
	if exists && !entry.IsExpired() {
		entry.LastAccess = time.Now()
		r.recordHit()
		return entry.Connector, nil
	}

	r.recordMiss()

	// Load connector config from RuntimeConfigService
	if r.configSvc == nil {
		return nil, fmt.Errorf("RuntimeConfigService not initialized")
	}

	cfg, source, err := r.configSvc.GetConnectorConfig(ctx, tenantID, connectorName)
	if err != nil {
		r.logger.Printf("Failed to load connector config '%s' for tenant '%s': %v", connectorName, tenantID, err)
		return nil, fmt.Errorf("connector config not found: %w", err)
	}

	r.logger.Printf("Loaded connector config '%s' for tenant '%s' from %s", connectorName, tenantID, source)

	// Validate connector type
	if !IsValidConnectorType(cfg.Type) {
		r.logger.Printf("WARNING: Unknown connector type '%s' for connector '%s'", cfg.Type, connectorName)
		return nil, fmt.Errorf("unsupported connector type: %s", cfg.Type)
	}

	// Create connector instance using factory
	if r.factory == nil {
		return nil, fmt.Errorf("connector factory not configured")
	}

	connector, err := r.factory(cfg.Type)
	if err != nil {
		r.recordFactoryFailure()
		r.logger.Printf("Failed to create connector '%s' (type: %s): %v", connectorName, cfg.Type, err)
		return nil, fmt.Errorf("failed to create connector: %w", err)
	}

	r.recordFactoryCreate()

	// Connect the connector with timeout
	connectTimeout := cfg.Timeout
	if connectTimeout <= 0 {
		connectTimeout = 30 * time.Second
	}

	connectCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	if err := connector.Connect(connectCtx, cfg); err != nil {
		r.recordConnectionError()
		r.logger.Printf("Failed to connect connector '%s' for tenant '%s': %v", connectorName, tenantID, err)
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Cache the connector
	now := time.Now()
	r.connectors[key] = &TenantConnectorEntry{
		Connector:  connector,
		Config:     cfg,
		CreatedAt:  now,
		LastAccess: now,
		ExpiresAt:  now.Add(r.cacheTTL),
	}

	r.logger.Printf("Cached connector '%s' for tenant '%s' (TTL: %v)", connectorName, tenantID, r.cacheTTL)

	return connector, nil
}

// RefreshTenant invalidates all cached connectors for a tenant.
// This forces the next GetConnector call to reload from RuntimeConfigService.
func (r *TenantConnectorRegistry) RefreshTenant(ctx context.Context, tenantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	prefix := tenantID + ":"
	evicted := 0

	for key, entry := range r.connectors {
		if strings.HasPrefix(key, prefix) {
			// Disconnect the connector gracefully
			if entry.Connector != nil {
				disconnectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				if err := entry.Connector.Disconnect(disconnectCtx); err != nil {
					r.logger.Printf("Warning: Failed to disconnect connector '%s': %v", key, err)
				}
				cancel()
			}
			delete(r.connectors, key)
			evicted++
		}
	}

	if evicted > 0 {
		r.recordEvictions(evicted)
		r.logger.Printf("Evicted %d connectors for tenant '%s'", evicted, tenantID)
	}

	// Also invalidate RuntimeConfigService cache for this tenant
	if r.configSvc != nil {
		if err := r.configSvc.RefreshConnectorConfig(ctx, tenantID, ""); err != nil {
			r.logger.Printf("Warning: Failed to invalidate config cache for tenant '%s': %v", tenantID, err)
		}
	}

	return nil
}

// RefreshConnector invalidates a specific cached connector.
func (r *TenantConnectorRegistry) RefreshConnector(ctx context.Context, tenantID, connectorName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := connectorKey(tenantID, connectorName)

	if entry, exists := r.connectors[key]; exists {
		// Disconnect the connector gracefully
		if entry.Connector != nil {
			disconnectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := entry.Connector.Disconnect(disconnectCtx); err != nil {
				r.logger.Printf("Warning: Failed to disconnect connector '%s': %v", key, err)
			}
			cancel()
		}
		delete(r.connectors, key)
		r.recordEvictions(1)
		r.logger.Printf("Evicted connector '%s' for tenant '%s'", connectorName, tenantID)
	}

	// Also invalidate RuntimeConfigService cache for this connector
	if r.configSvc != nil {
		if err := r.configSvc.RefreshConnectorConfig(ctx, tenantID, connectorName); err != nil {
			r.logger.Printf("Warning: Failed to invalidate config cache: %v", err)
		}
	}

	return nil
}

// RefreshAll invalidates all cached connectors across all tenants.
func (r *TenantConnectorRegistry) RefreshAll(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	evicted := 0
	for key, entry := range r.connectors {
		// Disconnect the connector gracefully
		if entry.Connector != nil {
			disconnectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := entry.Connector.Disconnect(disconnectCtx); err != nil {
				r.logger.Printf("Warning: Failed to disconnect connector '%s': %v", key, err)
			}
			cancel()
		}
		delete(r.connectors, key)
		evicted++
	}

	if evicted > 0 {
		r.recordEvictions(evicted)
		r.logger.Printf("Evicted all %d cached connectors", evicted)
	}

	// Also invalidate all RuntimeConfigService cache
	if r.configSvc != nil {
		r.configSvc.RefreshAllConfigs()
	}

	return nil
}

// GetConnectorsByTenant returns all cached connector names for a tenant.
func (r *TenantConnectorRegistry) GetConnectorsByTenant(tenantID string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	prefix := tenantID + ":"
	names := make([]string, 0)

	for key := range r.connectors {
		if strings.HasPrefix(key, prefix) {
			names = append(names, strings.TrimPrefix(key, prefix))
		}
	}

	return names
}

// Count returns the total number of cached connectors.
func (r *TenantConnectorRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.connectors)
}

// CountByTenant returns the number of cached connectors for a specific tenant.
func (r *TenantConnectorRegistry) CountByTenant(tenantID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	prefix := tenantID + ":"
	count := 0

	for key := range r.connectors {
		if strings.HasPrefix(key, prefix) {
			count++
		}
	}

	return count
}

// Cleanup removes expired entries from the cache.
// Should be called periodically (e.g., every minute).
func (r *TenantConnectorRegistry) Cleanup(ctx context.Context) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	evicted := 0
	for key, entry := range r.connectors {
		if entry.IsExpired() {
			// Disconnect the connector gracefully
			if entry.Connector != nil {
				disconnectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				if err := entry.Connector.Disconnect(disconnectCtx); err != nil {
					r.logger.Printf("Warning: Failed to disconnect expired connector '%s': %v", key, err)
				}
				cancel()
			}
			delete(r.connectors, key)
			evicted++
		}
	}

	if evicted > 0 {
		r.recordEvictions(evicted)
		r.logger.Printf("Cleaned up %d expired connectors", evicted)
	}

	return evicted
}

// StartPeriodicCleanup starts a background goroutine that cleans up expired entries.
func (r *TenantConnectorRegistry) StartPeriodicCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				r.logger.Println("Stopping periodic connector cleanup")
				return
			case <-ticker.C:
				r.Cleanup(ctx)
			}
		}
	}()
}

// DisconnectAll disconnects all cached connectors.
// Useful for graceful shutdown.
func (r *TenantConnectorRegistry) DisconnectAll(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.logger.Println("Disconnecting all cached connectors...")

	for key, entry := range r.connectors {
		if entry.Connector != nil {
			disconnectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := entry.Connector.Disconnect(disconnectCtx); err != nil {
				r.logger.Printf("Warning: Failed to disconnect connector '%s': %v", key, err)
			}
			cancel()
		}
	}

	r.connectors = make(map[string]*TenantConnectorEntry)
	r.logger.Println("All connectors disconnected")
}

// GetStats returns cache performance statistics.
func (r *TenantConnectorRegistry) GetStats() TenantRegistryStats {
	r.stats.mu.Lock()
	defer r.stats.mu.Unlock()

	// Return a copy of stats values to avoid copying the mutex
	return TenantRegistryStats{
		Hits:              r.stats.Hits,
		Misses:            r.stats.Misses,
		Evictions:         r.stats.Evictions,
		FactoryCreations:  r.stats.FactoryCreations,
		FactoryFailures:   r.stats.FactoryFailures,
		ConnectionErrors:  r.stats.ConnectionErrors,
		LastEviction:      r.stats.LastEviction,
		LastFactoryCreate: r.stats.LastFactoryCreate,
	}
}

// HitRate returns the cache hit rate as a percentage (0-100).
func (r *TenantConnectorRegistry) HitRate() float64 {
	r.stats.mu.Lock()
	defer r.stats.mu.Unlock()

	total := r.stats.Hits + r.stats.Misses
	if total == 0 {
		return 0
	}
	return float64(r.stats.Hits) / float64(total) * 100
}

// Stats recording methods
func (r *TenantConnectorRegistry) recordHit() {
	r.stats.mu.Lock()
	r.stats.Hits++
	r.stats.mu.Unlock()
}

func (r *TenantConnectorRegistry) recordMiss() {
	r.stats.mu.Lock()
	r.stats.Misses++
	r.stats.mu.Unlock()
}

func (r *TenantConnectorRegistry) recordEvictions(count int) {
	r.stats.mu.Lock()
	r.stats.Evictions += int64(count)
	r.stats.LastEviction = time.Now()
	r.stats.mu.Unlock()
}

func (r *TenantConnectorRegistry) recordFactoryCreate() {
	r.stats.mu.Lock()
	r.stats.FactoryCreations++
	r.stats.LastFactoryCreate = time.Now()
	r.stats.mu.Unlock()
}

func (r *TenantConnectorRegistry) recordFactoryFailure() {
	r.stats.mu.Lock()
	r.stats.FactoryFailures++
	r.stats.mu.Unlock()
}

func (r *TenantConnectorRegistry) recordConnectionError() {
	r.stats.mu.Lock()
	r.stats.ConnectionErrors++
	r.stats.mu.Unlock()
}

// --- Global accessor functions (following runtime_config_integration.go pattern) ---

// InitTenantConnectorRegistry initializes the global TenantConnectorRegistry.
// This should be called during agent startup, after RuntimeConfigService is initialized.
// Thread-safe: uses mutex to protect global state.
func InitTenantConnectorRegistry(configSvc *config.RuntimeConfigService, factory ConnectorFactory) *TenantConnectorRegistry {
	logger := log.New(os.Stdout, "[TENANT_CONNECTOR_REGISTRY] ", log.LstdFlags)

	reg := NewTenantConnectorRegistry(TenantConnectorRegistryOptions{
		ConfigService: configSvc,
		Factory:       factory,
		CacheTTL:      30 * time.Second,
		Logger:        logger,
	})

	tenantConnectorRegistryMu.Lock()
	tenantConnectorRegistry = reg
	tenantConnectorRegistryMu.Unlock()

	logger.Println("TenantConnectorRegistry initialized")

	return reg
}

// GetTenantConnectorRegistry returns the global TenantConnectorRegistry instance.
// Returns nil if not initialized. Thread-safe.
func GetTenantConnectorRegistry() *TenantConnectorRegistry {
	tenantConnectorRegistryMu.RLock()
	defer tenantConnectorRegistryMu.RUnlock()
	return tenantConnectorRegistry
}

// SetTenantConnectorRegistry sets the global TenantConnectorRegistry.
// This should be used during initialization.
func SetTenantConnectorRegistry(reg *TenantConnectorRegistry) {
	tenantConnectorRegistryMu.Lock()
	defer tenantConnectorRegistryMu.Unlock()
	tenantConnectorRegistry = reg
}
