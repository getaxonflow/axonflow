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
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/config"
	logutil "axonflow/platform/shared/logger"
)

// ConnectorFactory creates a connector instance based on type
type ConnectorFactory func(connectorType string) (base.Connector, error)

// SharedTenant is the tenancy sentinel for connectors that belong to the
// deployment rather than to a single tenant — the operator-configured
// connectors registered from config files/env at boot, and marketplace
// installs made before a tenant could be resolved. It reproduces the
// pre-existing wildcard semantics of ValidateTenantAccess/
// ListConnectorsByTenant (`tenant_id = '*'`), which every tenant may reach.
const SharedTenant = "*"

// tenantSep separates the tenancy scope from the connector name inside the
// registry's map keys. NUL can never appear in either component (both come
// from Postgres text columns / Go identifiers), so the composite key is
// unambiguous and no name can be crafted to collide with another tenant's.
const tenantSep = "\x00"

// normalizeTenant maps the empty tenancy to the shared scope. An empty
// TenantID means "not tenant-scoped" for every writer in this package
// (config-file connectors carry no tenant; the marketplace substitutes "*"
// when usageDB is absent), so collapsing it here keeps one canonical scope
// rather than two that must be checked separately.
func normalizeTenant(tenantID string) string {
	if tenantID == "" {
		return SharedTenant
	}
	return tenantID
}

// scopeKey builds the composite registry key for a (tenant, connector) pair.
func scopeKey(tenantID, name string) string {
	return normalizeTenant(tenantID) + tenantSep + name
}

// splitScopeKey reverses scopeKey. The second return is false for a key that
// somehow lacks the separator (defensive — every key is written by scopeKey).
func splitScopeKey(key string) (tenantID, name string, ok bool) {
	idx := strings.Index(key, tenantSep)
	if idx < 0 {
		return "", "", false
	}
	return key[:idx], key[idx+len(tenantSep):], true
}

// visibleTo reports whether a registry key scoped to keyTenant may be served
// to a caller authenticated as tenantID. A tenant sees its own connectors
// plus the deployment-shared ones, and nothing else.
func visibleTo(keyTenant, tenantID string) bool {
	return keyTenant == normalizeTenant(tenantID) || keyTenant == SharedTenant
}

// Registry manages all registered MCP connectors
// Thread-safe for concurrent access
//
// #3067: connectors and configs are keyed by `tenantID + NUL + name`, NOT by
// name alone. The registry is loaded deployment-wide on a BYPASSRLS pool
// (see PostgreSQLStorage.lookup) because the cross-replica sync legitimately
// needs every tenant's rows in one process — but every read surface is
// tenant-scoped, so a caller that names another tenant's connector cannot
// resolve it. This mirrors platform/agent.TenantConnectorRegistry, which has
// always keyed its cache this way. There is deliberately NO by-name-only
// accessor: a filter a caller must remember to apply is exactly what failed
// here (GetConnectorsByTenant had zero production callers).
type Registry struct {
	connectors map[string]base.Connector
	configs    map[string]*base.ConnectorConfig
	// loadedIDs tracks which storage rows have already been synced into
	// configs, so the periodic cross-replica reload can skip them without
	// re-fetching + re-decrypting every row. Keyed by the SAME composite
	// (tenant, name) as configs — a bare-name key let one tenant's
	// unregister clear a colliding tenant's sync mark. Bookkeeping only:
	// it holds no connector, no config and no credentials, and nothing
	// reads a connector through it.
	loadedIDs map[string]bool
	// deploymentWideNames records that connector names are constrained
	// deployment-wide by the storage layer (`connectors.id` is a primary key
	// whose upsert does not rewrite tenant_id). Set whenever persistence is
	// configured; see the collision guard in Register.
	deploymentWideNames bool
	storage             *PostgreSQLStorage // Optional persistent storage
	factory             ConnectorFactory   // Factory for lazy-loading connectors
	mu                  sync.RWMutex
	logger              *log.Logger
}

// NewRegistry creates a new connector registry with in-memory storage
func NewRegistry() *Registry {
	return &Registry{
		connectors: make(map[string]base.Connector),
		configs:    make(map[string]*base.ConnectorConfig),
		loadedIDs:  make(map[string]bool),
		storage:    nil, // No persistence by default
		factory:    nil, // No factory by default
		logger:     log.New(os.Stdout, "[MCP_REGISTRY] ", log.LstdFlags),
	}
}

// RegistryOption configures a registry during creation.
type RegistryOption func(*registryOptions)

type registryOptions struct {
	encryptor     *config.CredentialEncryptor
	appRoleOpener AppRoleOpener
	// crossOrgDB is the BYPASSRLS pool for the storage's deployment-wide
	// reads (#3048) — see PostgreSQLStorage.lookupDB.
	crossOrgDB *sql.DB
}

// WithEncryptor sets a credential encryptor for the registry's storage layer.
func WithEncryptor(enc *config.CredentialEncryptor) RegistryOption {
	return func(o *registryOptions) {
		o.encryptor = enc
	}
}

// WithAppRoleOpener injects the platform/agent.OpenAppRoleConnection helper so
// the registry's runtime storage pool authenticates as axonflow_app_role
// under AXONFLOW_DB_USE_APP_ROLE=true. Without this option, the runtime pool
// uses raw sql.Open and bypasses the v9 RLS gate on connectors +
// connector_configs (both FORCE-RLS per migration 107). Production
// orchestrator code MUST pass this option; tests + dev paths may omit it.
func WithAppRoleOpener(opener AppRoleOpener) RegistryOption {
	return func(o *registryOptions) {
		o.appRoleOpener = opener
	}
}

// WithCrossOrgDB installs a BYPASSRLS (axonflow_platform_admin) pool for the
// storage's deployment-wide reads: the registry's cross-replica sync
// (ListConnectors) and by-id lazy loads (GetConnector) are cross-org by
// design and read ZERO rows through mig 107's FORCE RLS on the app-role
// runtime pool (#3048). Production orchestrator code SHOULD pass this when
// AXONFLOW_DB_USE_APP_ROLE=true; without it the reads fall back to the
// runtime pool (correct on owner-pool deployments).
func WithCrossOrgDB(db *sql.DB) RegistryOption {
	return func(o *registryOptions) {
		o.crossOrgDB = db
	}
}

// NewRegistryWithStorage creates a new connector registry with PostgreSQL persistence
func NewRegistryWithStorage(dbURL string, opts ...RegistryOption) (*Registry, error) {
	var o registryOptions
	for _, opt := range opts {
		opt(&o)
	}

	var (
		storage *PostgreSQLStorage
		err     error
	)
	if o.appRoleOpener != nil {
		storage, err = NewPostgreSQLStorageWithOpener(dbURL, o.appRoleOpener)
	} else {
		storage, err = NewPostgreSQLStorage(dbURL)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}
	storage.encryptor = o.encryptor
	if o.crossOrgDB != nil {
		storage.SetCrossOrgDB(o.crossOrgDB)
	}

	registry := &Registry{
		connectors: make(map[string]base.Connector),
		configs:    make(map[string]*base.ConnectorConfig),
		loadedIDs:  make(map[string]bool),
		storage:    storage,
		// Persistence is configured, so `connectors.id` constrains names
		// deployment-wide.
		deploymentWideNames: true,
		factory:             nil, // Factory set later via SetFactory()
		logger:              log.New(os.Stdout, "[MCP_REGISTRY] ", log.LstdFlags),
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

		// Connectors will be instantiated on first use. The load is
		// deployment-wide by design (cross-replica sync); the TENANCY of each
		// loaded row is preserved in the key so the read surface can scope it
		// (#3067).
		r.configs[scopeKey(config.TenantID, id)] = config
		r.loadedIDs[scopeKey(config.TenantID, id)] = true
		r.logger.Printf("Loaded connector config: %s (type: %s, tenant: %s)", id, config.Type, normalizeTenant(config.TenantID))
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
		// Skip if already loaded. `connectors.id` is a deployment-wide primary
		// key, so the id alone identifies at most one storage row; the fetch
		// is what tells us its tenancy, and the loaded-set is keyed by the
		// same composite as configs.
		if r.loadedIDByName(id) {
			continue
		}

		config, err := r.storage.GetConnector(ctx, id)
		if err != nil {
			r.logger.Printf("Failed to load connector %s: %v", id, err)
			continue
		}

		// Store config - connector will be instantiated on first use
		r.configs[scopeKey(config.TenantID, id)] = config
		r.loadedIDs[scopeKey(config.TenantID, id)] = true
		newConnectors++
		r.logger.Printf("Auto-loaded new connector: %s (type: %s, tenant: %s) from storage", id, config.Type, normalizeTenant(config.TenantID))
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

// Register adds a new connector to the registry under the tenancy carried by
// config.TenantID. An empty TenantID registers into the deployment-shared
// scope (SharedTenant), which is what the operator-configured, config-file
// connectors have always been.
//
// Returns an error if the SAME tenant already has a connector with this name.
// Two different tenants may each register `postgres` — that is the point of
// the tenant-keyed map (#3067) and it is why the duplicate check is no longer
// a cross-tenant existence oracle.
func (r *Registry) Register(name string, connector base.Connector, config *base.ConnectorConfig) error {
	if config == nil {
		return fmt.Errorf("connector '%s': config is required to determine tenancy", name)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	key := scopeKey(config.TenantID, name)
	if _, exists := r.connectors[key]; exists {
		return fmt.Errorf("connector '%s' already registered", name)
	}

	// #3067 (R3): the in-memory map is tenant-keyed, but PERSISTENCE is not —
	// `connectors.id` is a deployment-wide primary key and SaveConnector's
	// `ON CONFLICT (id) DO UPDATE` does not update tenant_id/org_id. Letting
	// two tenants hold the same name in memory would therefore diverge from
	// storage: either the second write fails (leaving a memory-only connector
	// that vanishes on restart and never reaches other replicas) or, on an
	// owner-pool deployment where RLS does not stop it, it overwrites the
	// first tenant's row with the second tenant's credentials. The flat map's
	// global duplicate check used to make both impossible; restore that
	// guarantee explicitly wherever storage is in play.
	if r.deploymentWideNames {
		for existing := range r.configs {
			if existingTenant, existingName, ok := splitScopeKey(existing); ok &&
				existingName == name && existingTenant != normalizeTenant(config.TenantID) {
				// Deliberately the SAME message as the same-tenancy duplicate
				// above: telling the caller that ANOTHER tenant holds the name
				// would be the existence oracle this change removes elsewhere.
				return fmt.Errorf("connector '%s' already registered", name)
			}
		}
	}

	// Attempt to connect the connector
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	if err := connector.Connect(ctx, config); err != nil {
		r.logger.Printf("Failed to connect connector '%s': %v", name, err)
		return fmt.Errorf("failed to connect connector '%s': %w", name, err)
	}

	r.connectors[key] = connector
	r.configs[key] = config

	// Persist to storage if available
	if r.storage != nil {
		if err := r.storage.SaveConnector(ctx, name, config); err != nil {
			r.logger.Printf("Warning: Failed to persist connector '%s': %v", name, err)
			// Don't fail registration if persistence fails
		} else {
			r.loadedIDs[key] = true
		}
	}

	r.logger.Printf("Registered connector '%s' (type: %s, tenant: %s)", name, config.Type, normalizeTenant(config.TenantID))

	return nil
}

// Unregister removes a connector from the registry and disconnects it.
//
// tenantID scopes the removal: a caller can only unregister a connector in
// its own tenancy (or a deployment-shared one). Passing another tenant's ID
// is not a way in — the composite key simply will not resolve (#3067).
func (r *Registry) Unregister(tenantID, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// #3067 (R3): a MUTATION resolves the caller's OWN key only — never the
	// shared fallback resolveKeyLocked applies for reads. With the read
	// resolver here, any tenant could unregister (and DELETE from storage) a
	// deployment-shared connector, taking it away from every other tenant.
	// This mirrors ownKey/readKeyLocked in the LLM registry.
	key := scopeKey(tenantID, name)
	_, hasConfig := r.configs[key]
	_, hasConnector := r.connectors[key]
	if !hasConfig && !hasConnector {
		return fmt.Errorf("connector '%s' not found", name)
	}

	connector, exists := r.connectors[key]

	// Disconnect the connector if instantiated
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if exists {
		if err := connector.Disconnect(ctx); err != nil {
			r.logger.Printf("Error disconnecting connector '%s': %v", logutil.Sanitize(name), err)
		}
	}

	// Capture orgID from the in-memory config BEFORE deleting — Storage's
	// DeleteConnector wraps the DELETE in a `SELECT set_config('app.current_org_id', orgID)`
	// transaction so the connectors RLS DELETE policy (`USING org_id = get_current_org_id()`)
	// matches under axonflow_app_role. config.TenantID carries the orgID at this writer
	// per the historical schema collapse.
	var orgID string
	if cfg, ok := r.configs[key]; ok && cfg != nil {
		orgID = cfg.TenantID
	}

	delete(r.connectors, key)
	delete(r.configs, key)
	delete(r.loadedIDs, key)

	// Delete from storage if available
	if r.storage != nil {
		if orgID == "" {
			r.logger.Printf("Warning: Unregister %q has no in-memory config to derive orgID — skipping storage delete to avoid cross-org wipe", logutil.Sanitize(name))
		} else if err := r.storage.DeleteConnector(ctx, orgID, name); err != nil {
			r.logger.Printf("Warning: Failed to delete connector '%s' from storage: %v", name, err)
			// Don't fail unregistration if storage deletion fails
		}
	}

	r.logger.Printf("Unregistered connector '%s' (tenant: %s)", name, normalizeTenant(tenantID))

	return nil
}

// loadedIDByName reports whether a storage id has already been synced under
// ANY tenancy. `connectors.id` is a deployment-wide primary key, so at most
// one row carries it and this answers "already fetched" without knowing the
// tenancy up front. Sync bookkeeping only — it returns a bool, never an entry.
//
// Callers must hold at least a read lock.
func (r *Registry) loadedIDByName(id string) bool {
	suffix := tenantSep + id
	for key := range r.loadedIDs {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

// resolveKeyLocked maps a (tenant, name) pair to the composite key that
// actually holds the entry, preferring the caller's own tenancy over the
// deployment-shared scope. Returns false when neither exists — which is also
// the answer for another tenant's connector, by construction.
//
// Callers must hold at least a read lock.
func (r *Registry) resolveKeyLocked(tenantID, name string) (string, bool) {
	own := scopeKey(tenantID, name)
	if _, ok := r.configs[own]; ok {
		return own, true
	}
	if _, ok := r.connectors[own]; ok {
		return own, true
	}
	shared := scopeKey(SharedTenant, name)
	if shared == own {
		return "", false
	}
	if _, ok := r.configs[shared]; ok {
		return shared, true
	}
	if _, ok := r.connectors[shared]; ok {
		return shared, true
	}
	return "", false
}

// Get retrieves a connector visible to tenantID by name, lazy-loading if
// necessary.
//
// #3067 (S-1, CRITICAL): this used to be Get(name) over a flat deployment-wide
// map, so a workflow step naming another tenant's connector executed against
// it with the victim's decrypted credentials. The lookup is now structurally
// incapable of crossing tenancies: there is no key for (callerTenant, name)
// unless the caller owns that connector or it is deployment-shared.
func (r *Registry) Get(tenantID, name string) (base.Connector, error) {
	// First try to get existing connector (read lock)
	r.mu.RLock()
	key, resolved := r.resolveKeyLocked(tenantID, name)
	var (
		connector base.Connector
		config    *base.ConnectorConfig
		exists    bool
		hasConfig bool
	)
	if resolved {
		connector, exists = r.connectors[key]
		config, hasConfig = r.configs[key]
	}
	r.mu.RUnlock()

	if exists {
		return connector, nil
	}

	// If we have a config but no connector instance, lazy-load it
	if hasConfig && r.factory != nil {
		return r.lazyLoadConnector(key, name, config)
	}

	return nil, fmt.Errorf("connector '%s' not found", name)
}

// lazyLoadConnector creates and connects a connector instance from its stored
// config. key is the already-resolved composite (tenant, name) key; name is
// carried separately for log/error text only.
func (r *Registry) lazyLoadConnector(key, name string, config *base.ConnectorConfig) (base.Connector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check if connector was created by another goroutine
	if connector, exists := r.connectors[key]; exists {
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
	r.connectors[key] = connector
	r.logger.Printf("Successfully lazy-loaded connector '%s'", name)

	return connector, nil
}

// GetConfig retrieves a connector's configuration by name, scoped to tenantID.
func (r *Registry) GetConfig(tenantID, name string) (*base.ConnectorConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key, ok := r.resolveKeyLocked(tenantID, name)
	if !ok {
		return nil, fmt.Errorf("config for connector '%s' not found", name)
	}
	config, exists := r.configs[key]
	if !exists {
		return nil, fmt.Errorf("config for connector '%s' not found", name)
	}

	return config, nil
}

// List returns the connector names visible to tenantID (its own plus the
// deployment-shared ones), including lazy-loaded configs.
func (r *Registry) List(tenantID string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]bool, len(r.connectors)+len(r.configs))
	collect := func(key string) {
		keyTenant, name, ok := splitScopeKey(key)
		if !ok || !visibleTo(keyTenant, tenantID) {
			return
		}
		seen[name] = true
	}
	for key := range r.connectors {
		collect(key)
	}
	for key := range r.configs {
		collect(key)
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}

	return names
}

// ListWithTypes returns the connectors visible to tenantID with their types
// (including lazy-loaded configs).
func (r *Registry) ListWithTypes(tenantID string) map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]string, len(r.connectors)+len(r.configs))
	for key, config := range r.configs {
		keyTenant, name, ok := splitScopeKey(key)
		if !ok || !visibleTo(keyTenant, tenantID) {
			continue
		}
		result[name] = config.Type
	}
	// Instantiated connectors override config entries (authoritative type)
	for key, connector := range r.connectors {
		keyTenant, name, ok := splitScopeKey(key)
		if !ok || !visibleTo(keyTenant, tenantID) {
			continue
		}
		result[name] = connector.Type()
	}

	return result
}

// HealthCheck performs health checks on the connectors visible to tenantID.
// Returns a map of connector names to their health status.
//
// #3067 (S-5): this used to health-check EVERY tenant's connector and return
// the raw driver error strings — which routinely embed host/db/user — to an
// unauthenticated caller. It now opens connections only for connectors the
// caller may reach.
func (r *Registry) HealthCheck(ctx context.Context, tenantID string) map[string]*base.HealthStatus {
	r.mu.RLock()
	type target struct {
		name string
		conn base.Connector
	}
	targets := make([]target, 0, len(r.connectors))
	for key, connector := range r.connectors {
		keyTenant, name, ok := splitScopeKey(key)
		if !ok || !visibleTo(keyTenant, tenantID) {
			continue
		}
		targets = append(targets, target{name: name, conn: connector})
	}
	r.mu.RUnlock()

	results := make(map[string]*base.HealthStatus, len(targets))
	for _, t := range targets {
		status, err := t.conn.HealthCheck(ctx)
		if err != nil {
			r.logger.Printf("Health check failed for connector '%s': %v", t.name, err)
			status = &base.HealthStatus{
				Healthy: false,
				Error:   err.Error(),
			}
		}
		results[t.name] = status
	}

	return results
}

// HealthCheckSingle performs a health check on a specific connector visible to
// tenantID.
func (r *Registry) HealthCheckSingle(ctx context.Context, tenantID, name string) (*base.HealthStatus, error) {
	connector, err := r.Get(tenantID, name)
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

// Count returns the number of instantiated connectors across the whole
// deployment. Operator/boot diagnostics only — it is never served to a tenant
// caller (a deployment-wide count is an inference channel). Use
// CountForTenant for anything a tenant can observe.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.connectors)
}

// CountForTenant returns the number of instantiated connectors visible to
// tenantID.
func (r *Registry) CountForTenant(tenantID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	n := 0
	for key := range r.connectors {
		keyTenant, _, ok := splitScopeKey(key)
		if ok && visibleTo(keyTenant, tenantID) {
			n++
		}
	}
	return n
}

// DisconnectAll disconnects all registered connectors
// Useful for graceful shutdown
func (r *Registry) DisconnectAll(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.logger.Println("Disconnecting all connectors...")

	for key, connector := range r.connectors {
		_, name, ok := splitScopeKey(key)
		if !ok {
			name = key
		}
		if err := connector.Disconnect(ctx); err != nil {
			r.logger.Printf("Error disconnecting connector '%s': %v", name, err)
		} else {
			r.logger.Printf("Disconnected connector '%s'", name)
		}
	}

	r.logger.Println("All connectors disconnected")
}

// GetConnectorsByTenant returns all connector names accessible to a specific
// tenant. Equivalent to List — retained because it is the documented name for
// this query.
func (r *Registry) GetConnectorsByTenant(tenantID string) []string {
	return r.List(tenantID)
}

// ValidateTenantAccess checks if a tenant can access a specific connector.
//
// The tenancy decision now falls out of the composite key rather than a
// field comparison on a row fetched by name alone: if resolveKeyLocked finds
// nothing, the connector either does not exist or belongs to someone else,
// and both answers are "no access" with the same message (no disclosure of
// which).
func (r *Registry) ValidateTenantAccess(connectorName, tenantID string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, ok := r.resolveKeyLocked(tenantID, connectorName); !ok {
		return fmt.Errorf("tenant '%s' does not have access to connector '%s'", tenantID, connectorName)
	}

	return nil
}
