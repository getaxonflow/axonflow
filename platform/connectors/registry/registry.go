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

package registry

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"axonflow/platform/connectors/base"
)

// ConnectorFactory creates a connector instance based on type
type ConnectorFactory func(connectorType string) (base.Connector, error)

// Registry manages all registered MCP connectors
// Thread-safe for concurrent access
type Registry struct {
	connectors map[string]base.Connector
	configs    map[string]*base.ConnectorConfig
	storage    *PostgreSQLStorage // Optional persistent storage
	factory    ConnectorFactory   // Factory for lazy-loading connectors
	mu         sync.RWMutex
	logger     *log.Logger
}

// NewRegistry creates a new connector registry with in-memory storage
func NewRegistry() *Registry {
	return &Registry{
		connectors: make(map[string]base.Connector),
		configs:    make(map[string]*base.ConnectorConfig),
		storage:    nil, // No persistence by default
		factory:    nil, // No factory by default
		logger:     log.New(os.Stdout, "[MCP_REGISTRY] ", log.LstdFlags),
	}
}

// NewRegistryWithStorage creates a new connector registry with PostgreSQL persistence
func NewRegistryWithStorage(dbURL string) (*Registry, error) {
	storage, err := NewPostgreSQLStorage(dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	registry := &Registry{
		connectors: make(map[string]base.Connector),
		configs:    make(map[string]*base.ConnectorConfig),
		storage:    storage,
		factory:    nil, // Factory set later via SetFactory()
		logger:     log.New(os.Stdout, "[MCP_REGISTRY] ", log.LstdFlags),
	}

	// Load existing connectors from storage
	if err := registry.loadFromStorage(); err != nil {
		registry.logger.Printf("Warning: Failed to load connectors from storage: %v", err)
	}

	return registry, nil
}

// SetFactory sets the connector factory for lazy-loading
// This should be called after registry initialization to enable lazy connector instantiation
func (r *Registry) SetFactory(factory ConnectorFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factory = factory
	r.logger.Println("Connector factory configured for lazy-loading")
}

// loadFromStorage loads all persisted connectors and reconnects them
func (r *Registry) loadFromStorage() error {
	if r.storage == nil {
		return nil
	}

	ctx := context.Background()
	ids, err := r.storage.ListConnectors(ctx)
	if err != nil {
		return fmt.Errorf("failed to list connectors: %w", err)
	}

	r.logger.Printf("Loading %d connectors from storage...", len(ids))

	for _, id := range ids {
		config, err := r.storage.GetConnector(ctx, id)
		if err != nil {
			r.logger.Printf("Failed to load connector %s: %v", id, err)
			continue
		}

		// Connectors will be instantiated on first use
		r.configs[id] = config
		r.logger.Printf("Loaded connector config: %s (type: %s)", id, config.Type)
	}

	return nil
}

// ReloadFromStorage checks PostgreSQL for new connectors registered by other orchestrator instances
// and loads them into this instance's registry. This enables connector synchronization across replicas.
func (r *Registry) ReloadFromStorage(ctx context.Context) error {
	if r.storage == nil {
		return nil
	}

	ids, err := r.storage.ListConnectors(ctx)
	if err != nil {
		return fmt.Errorf("failed to list connectors: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	newConnectors := 0
	for _, id := range ids {
		// Skip if already loaded
		if _, exists := r.configs[id]; exists {
			continue
		}

		config, err := r.storage.GetConnector(ctx, id)
		if err != nil {
			r.logger.Printf("Failed to load connector %s: %v", id, err)
			continue
		}

		// Store config - connector will be instantiated on first use
		r.configs[id] = config
		newConnectors++
		r.logger.Printf("Auto-loaded new connector: %s (type: %s) from storage", id, config.Type)
	}

	if newConnectors > 0 {
		r.logger.Printf("Loaded %d new connector(s) from storage", newConnectors)
	}

	return nil
}

// StartPeriodicReload starts a background goroutine that periodically reloads connectors from PostgreSQL
// This ensures connector registry stays synchronized across multiple orchestrator replicas
func (r *Registry) StartPeriodicReload(ctx context.Context, interval time.Duration) {
	if r.storage == nil {
		r.logger.Println("Storage not configured - skipping periodic reload")
		return
	}

	r.logger.Printf("Starting periodic connector reload (every %v)", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				r.logger.Println("Stopping periodic connector reload")
				return
			case <-ticker.C:
				if err := r.ReloadFromStorage(ctx); err != nil {
					r.logger.Printf("Periodic reload failed: %v", err)
				}
			}
		}
	}()
}

// Register adds a new connector to the registry
// Returns error if a connector with the same name already exists
func (r *Registry) Register(name string, connector base.Connector, config *base.ConnectorConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.connectors[name]; exists {
		return fmt.Errorf("connector '%s' already registered", name)
	}

	// Attempt to connect the connector
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	if err := connector.Connect(ctx, config); err != nil {
		r.logger.Printf("Failed to connect connector '%s': %v", name, err)
		return fmt.Errorf("failed to connect connector '%s': %w", name, err)
	}

	r.connectors[name] = connector
	r.configs[name] = config

	// Persist to storage if available
	if r.storage != nil {
		if err := r.storage.SaveConnector(ctx, name, config); err != nil {
			r.logger.Printf("Warning: Failed to persist connector '%s': %v", name, err)
			// Don't fail registration if persistence fails
		}
	}

	r.logger.Printf("Registered connector '%s' (type: %s)", name, config.Type)

	return nil
}

// Unregister removes a connector from the registry and disconnects it
func (r *Registry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	connector, exists := r.connectors[name]
	if !exists {
		return fmt.Errorf("connector '%s' not found", name)
	}

	// Disconnect the connector
	ctx, cancel := context.WithTimeout(context.Background(), 5*1000000000) // 5 seconds
	defer cancel()

	if err := connector.Disconnect(ctx); err != nil {
		r.logger.Printf("Error disconnecting connector '%s': %v", name, err)
	}

	delete(r.connectors, name)
	delete(r.configs, name)

	// Delete from storage if available
	if r.storage != nil {
		if err := r.storage.DeleteConnector(ctx, name); err != nil {
			r.logger.Printf("Warning: Failed to delete connector '%s' from storage: %v", name, err)
			// Don't fail unregistration if storage deletion fails
		}
	}

	r.logger.Printf("Unregistered connector '%s'", name)

	return nil
}

// Get retrieves a connector by name, lazy-loading if necessary
func (r *Registry) Get(name string) (base.Connector, error) {
	// First try to get existing connector (read lock)
	r.mu.RLock()
	connector, exists := r.connectors[name]
	config, hasConfig := r.configs[name]
	r.mu.RUnlock()

	if exists {
		return connector, nil
	}

	// If we have a config but no connector instance, lazy-load it
	if hasConfig && r.factory != nil {
		return r.lazyLoadConnector(name, config)
	}

	return nil, fmt.Errorf("connector '%s' not found", name)
}

// lazyLoadConnector creates and connects a connector instance from its stored config
func (r *Registry) lazyLoadConnector(name string, config *base.ConnectorConfig) (base.Connector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check if connector was created by another goroutine
	if connector, exists := r.connectors[name]; exists {
		return connector, nil
	}

	r.logger.Printf("Lazy-loading connector '%s' (type: %s)", name, config.Type)

	// Create connector instance using factory
	connector, err := r.factory(config.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to create connector '%s': %w", name, err)
	}

	// Connect the connector
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	if err := connector.Connect(ctx, config); err != nil {
		r.logger.Printf("Failed to connect lazy-loaded connector '%s': %v", name, err)
		return nil, fmt.Errorf("failed to connect connector '%s': %w", name, err)
	}

	// Store the connected connector
	r.connectors[name] = connector
	r.logger.Printf("Successfully lazy-loaded connector '%s'", name)

	return connector, nil
}

// GetConfig retrieves a connector's configuration by name
func (r *Registry) GetConfig(name string) (*base.ConnectorConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	config, exists := r.configs[name]
	if !exists {
		return nil, fmt.Errorf("config for connector '%s' not found", name)
	}

	return config, nil
}

// List returns all registered connector names
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.connectors))
	for name := range r.connectors {
		names = append(names, name)
	}

	return names
}

// ListWithTypes returns all registered connectors with their types
func (r *Registry) ListWithTypes() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]string)
	for name, connector := range r.connectors {
		result[name] = connector.Type()
	}

	return result
}

// HealthCheck performs health checks on all connectors
// Returns a map of connector names to their health status
func (r *Registry) HealthCheck(ctx context.Context) map[string]*base.HealthStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	results := make(map[string]*base.HealthStatus)

	for name, connector := range r.connectors {
		status, err := connector.HealthCheck(ctx)
		if err != nil {
			r.logger.Printf("Health check failed for connector '%s': %v", name, err)
			status = &base.HealthStatus{
				Healthy: false,
				Error:   err.Error(),
			}
		}
		results[name] = status
	}

	return results
}

// HealthCheckSingle performs a health check on a specific connector
func (r *Registry) HealthCheckSingle(ctx context.Context, name string) (*base.HealthStatus, error) {
	connector, err := r.Get(name)
	if err != nil {
		return nil, err
	}

	status, err := connector.HealthCheck(ctx)
	if err != nil {
		r.logger.Printf("Health check failed for connector '%s': %v", name, err)
		return &base.HealthStatus{
			Healthy: false,
			Error:   err.Error(),
		}, nil
	}

	return status, nil
}

// Count returns the number of registered connectors
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.connectors)
}

// DisconnectAll disconnects all registered connectors
// Useful for graceful shutdown
func (r *Registry) DisconnectAll(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.logger.Println("Disconnecting all connectors...")

	for name, connector := range r.connectors {
		if err := connector.Disconnect(ctx); err != nil {
			r.logger.Printf("Error disconnecting connector '%s': %v", name, err)
		} else {
			r.logger.Printf("Disconnected connector '%s'", name)
		}
	}

	r.logger.Println("All connectors disconnected")
}

// GetConnectorsByTenant returns all connectors accessible to a specific tenant
func (r *Registry) GetConnectorsByTenant(tenantID string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0)
	for name, config := range r.configs {
		if config.TenantID == tenantID || config.TenantID == "*" {
			names = append(names, name)
		}
	}

	return names
}

// ValidateTenantAccess checks if a tenant can access a specific connector
func (r *Registry) ValidateTenantAccess(connectorName, tenantID string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	config, exists := r.configs[connectorName]
	if !exists {
		return fmt.Errorf("connector '%s' not found", connectorName)
	}

	if config.TenantID != tenantID && config.TenantID != "*" {
		return fmt.Errorf("tenant '%s' does not have access to connector '%s'", tenantID, connectorName)
	}

	return nil
}
