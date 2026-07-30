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

package llm

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	logutil "axonflow/platform/shared/logger"
)

// GlobalTenant is the tenancy sentinel for deployment-level providers — the
// ones the bootstrap registers from environment/config (ANTHROPIC_API_KEY,
// OPENAI_API_KEY, …). They carry no ProviderConfig.TenantID and are the pool
// the deployment router selects from for every tenant's traffic. Tenants may
// READ them (they are the deployment's own, not another customer's) but may
// not update or delete them, which is exactly the check the PUT/DELETE
// handlers already enforced by comparing TenantID.
const GlobalTenant = "*"

// tenantSep separates the tenancy scope from the provider name in the
// registry's map keys. NUL appears in neither component.
const tenantSep = "\x00"

// normalizeTenant collapses the empty tenancy onto GlobalTenant.
func normalizeTenant(tenantID string) string {
	if tenantID == "" {
		return GlobalTenant
	}
	return tenantID
}

// scopeKey builds the composite registry key for a (tenant, provider) pair.
func scopeKey(tenantID, name string) string {
	return normalizeTenant(tenantID) + tenantSep + name
}

// splitScopeKey reverses scopeKey.
func splitScopeKey(key string) (tenantID, name string, ok bool) {
	idx := strings.Index(key, tenantSep)
	if idx < 0 {
		return "", "", false
	}
	return key[:idx], key[idx+len(tenantSep):], true
}

// readableBy reports whether an entry scoped to keyTenant may be READ by a
// caller authenticated as tenantID: its own providers plus the deployment's.
func readableBy(keyTenant, tenantID string) bool {
	return keyTenant == normalizeTenant(tenantID) || keyTenant == GlobalTenant
}

// Registry manages LLM provider instances with lazy loading and health monitoring.
// It is thread-safe for concurrent access.
//
// The registry supports two modes:
//   - In-memory only: Providers are registered programmatically
//   - With storage: Providers are persisted to PostgreSQL and synced across replicas
//
// #3067 (S-2/S-3): providers, configs and healthResults are keyed by
// `tenantID + NUL + name`, NOT by name alone. ProviderConfig.TenantID has
// always existed but was not the key, so the read/test/routing handlers —
// unlike their PUT/DELETE siblings, which did compare TenantID — served and
// mutated other tenants' providers by name. Most severely, POST
// /api/v1/llm-providers/{name}/test ran a completion through another tenant's
// provider, spending and billing that tenant's API key. Keying removes the
// class rather than adding another check a caller must remember.
type Registry struct {
	providers    map[string]Provider        // Active provider instances, keyed tenant+name
	configs      map[string]*ProviderConfig // Provider configurations, keyed tenant+name
	storage      Storage                    // Optional persistent storage
	factory      *FactoryManager            // Factory for creating providers
	validator    LicenseValidator           // License validator for provider access control
	maxProviders int                        // Maximum provider count (-1 = unlimited, 0 = use default)
	logger       *log.Logger
	mu           sync.RWMutex

	// Health monitoring, keyed tenant+name
	healthResults map[string]*HealthCheckResult
	healthMu      sync.RWMutex
}

// Storage defines the interface for persistent provider configuration storage.
// Implement this interface to enable provider config persistence (e.g., PostgreSQL).
type Storage interface {
	// SaveProvider persists a provider configuration.
	SaveProvider(ctx context.Context, config *ProviderConfig) error

	// GetProvider retrieves a provider configuration by name.
	GetProvider(ctx context.Context, name string) (*ProviderConfig, error)

	// DeleteProvider removes a provider configuration. orgID scopes the
	// DELETE under v9 RLS (see [PostgresStorage.DeleteProvider]).
	DeleteProvider(ctx context.Context, orgID, name string) error

	// ListProviders returns all provider names for an organization.
	ListProviders(ctx context.Context, orgID string) ([]string, error)

	// ListAllProviders returns all provider names (admin use).
	ListAllProviders(ctx context.Context) ([]string, error)
}

// RegistryOption configures the registry during creation.
type RegistryOption func(*Registry)

// WithStorage sets persistent storage for the registry.
func WithStorage(storage Storage) RegistryOption {
	return func(r *Registry) {
		r.storage = storage
	}
}

// WithLogger sets a custom logger for the registry.
func WithLogger(logger *log.Logger) RegistryOption {
	return func(r *Registry) {
		r.logger = logger
	}
}

// WithFactoryManager sets a custom factory manager.
// If not set, the registry uses the global factory registry.
func WithFactoryManager(fm *FactoryManager) RegistryOption {
	return func(r *Registry) {
		r.factory = fm
	}
}

// WithLicenseValidator sets a custom license validator.
// If not set, the registry uses the DefaultValidator which enforces Community restrictions.
func WithLicenseValidator(v LicenseValidator) RegistryOption {
	return func(r *Registry) {
		r.validator = v
	}
}

// WithMaxProviders sets the maximum number of providers that can be registered.
// Use -1 for unlimited (Enterprise). Use 0 to defer to default behavior.
func WithMaxProviders(max int) RegistryOption {
	return func(r *Registry) {
		r.maxProviders = max
	}
}

// NewRegistry creates a new provider registry.
func NewRegistry(opts ...RegistryOption) *Registry {
	r := &Registry{
		providers:     make(map[string]Provider),
		configs:       make(map[string]*ProviderConfig),
		healthResults: make(map[string]*HealthCheckResult),
		logger:        log.New(os.Stdout, "[LLM_REGISTRY] ", log.LstdFlags),
	}

	for _, opt := range opts {
		opt(r)
	}

	// If no factory manager was provided, create one that uses the global registry
	if r.factory == nil {
		r.factory = NewFactoryManager()
		r.factory.CopyFromGlobal()
	}

	// If no license validator was provided, use the default
	if r.validator == nil {
		r.validator = DefaultValidator
	}

	return r
}

// Register adds a provider configuration to the registry under the tenancy
// carried by config.TenantID (empty => GlobalTenant, i.e. a deployment
// provider registered by the bootstrap).
// The provider will be instantiated lazily on first use.
// If the SAME tenant already has a provider with that name, it returns an
// error — the duplicate check is no longer a cross-tenant existence oracle.
func (r *Registry) Register(ctx context.Context, config *ProviderConfig) error {
	if config == nil {
		return &RegistryError{Code: ErrRegistryInvalidConfig, Message: "config cannot be nil"}
	}

	if config.Name == "" {
		return &RegistryError{Code: ErrRegistryInvalidConfig, Message: "provider name is required"}
	}

	// Validate the config
	if err := ValidateConfig(*config); err != nil {
		return &RegistryError{
			ProviderName: config.Name,
			Code:         ErrRegistryInvalidConfig,
			Message:      fmt.Sprintf("invalid configuration: %v", err),
			Cause:        err,
		}
	}

	// Check license allows this provider type
	if !r.validator.IsProviderAllowed(ctx, config.Type) {
		requiredTier := GetTierForProvider(config.Type)
		currentTier := r.validator.GetCurrentTier(ctx)
		return &RegistryError{
			ProviderName: config.Name,
			Code:         ErrRegistryLicenseRequired,
			Message: fmt.Sprintf("provider type %q requires %s license (current: %s) - upgrade at https://getaxonflow.com/enterprise",
				config.Type, requiredTier, currentTier),
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	key := scopeKey(config.TenantID, config.Name)

	// Check provider count limit (tier enforcement). This stays DEPLOYMENT-wide
	// on purpose: maxProviders comes from the deployment's license tier
	// (tierChecker.MaxLLMProviders), so scoping it per tenant would multiply
	// the licensed ceiling by the tenant count. It exposes only the
	// deployment's own configured limit, never another tenant's data.
	if r.maxProviders > 0 {
		currentCount := len(r.configs) + len(r.providers)
		// Deduplicate: don't double-count providers that also have configs
		for k := range r.providers {
			if _, hasConfig := r.configs[k]; hasConfig {
				currentCount--
			}
		}
		if currentCount >= r.maxProviders {
			return &RegistryError{
				ProviderName: config.Name,
				Code:         ErrRegistryProviderLimit,
				Message: fmt.Sprintf("maximum number of LLM providers reached (%d) - upgrade at https://getaxonflow.com/evaluation-license",
					r.maxProviders),
			}
		}
	}

	// Check for duplicate within this tenancy
	if _, exists := r.configs[key]; exists {
		return &RegistryError{
			ProviderName: config.Name,
			Code:         ErrRegistryDuplicate,
			Message:      fmt.Sprintf("provider %q already registered", config.Name),
		}
	}

	// Store config (provider will be created lazily)
	configCopy := *config
	r.configs[key] = &configCopy

	// Persist to storage if available
	if r.storage != nil {
		if err := r.storage.SaveProvider(ctx, &configCopy); err != nil {
			// Rollback in-memory registration
			delete(r.configs, key)
			return &RegistryError{
				ProviderName: config.Name,
				Code:         ErrRegistryStorageError,
				Message:      fmt.Sprintf("failed to persist provider: %v", err),
				Cause:        err,
			}
		}
	}

	r.logger.Printf("Registered provider config: %s (type: %s, tenant: %s)", config.Name, config.Type, normalizeTenant(config.TenantID))
	return nil
}

// RegisterProvider adds a pre-instantiated provider to the registry.
// Use this when you have an already-created provider instance. The tenancy
// comes from config.TenantID; a nil config registers a deployment provider.
func (r *Registry) RegisterProvider(name string, provider Provider, config *ProviderConfig) error {
	if provider == nil {
		return &RegistryError{Code: ErrRegistryInvalidConfig, Message: "provider cannot be nil"}
	}

	if name == "" {
		return &RegistryError{Code: ErrRegistryInvalidConfig, Message: "provider name is required"}
	}

	tenantID := ""
	if config != nil {
		tenantID = config.TenantID
	}
	key := scopeKey(tenantID, name)

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.providers[key]; exists {
		return &RegistryError{
			ProviderName: name,
			Code:         ErrRegistryDuplicate,
			Message:      fmt.Sprintf("provider %q already registered", name),
		}
	}

	r.providers[key] = provider
	if config != nil {
		configCopy := *config
		r.configs[key] = &configCopy
	}

	r.logger.Printf("Registered provider instance: %s (type: %s, tenant: %s)", name, provider.Type(), normalizeTenant(tenantID))
	return nil
}

// ownKey returns the composite key for a provider the caller OWNS. Mutations
// resolve through this — never through readKey — so a tenant cannot enable,
// disable, update or delete a deployment provider or another tenant's.
func ownKey(tenantID, name string) string {
	return scopeKey(tenantID, name)
}

// readKeyLocked resolves a (tenant, name) pair for a READ, preferring the
// caller's own provider over the deployment-level one of the same name.
// Returns false when neither exists — which is also the answer for another
// tenant's provider, by construction.
//
// Callers must hold at least a read lock.
func (r *Registry) readKeyLocked(tenantID, name string) (string, bool) {
	own := scopeKey(tenantID, name)
	if _, ok := r.configs[own]; ok {
		return own, true
	}
	if _, ok := r.providers[own]; ok {
		return own, true
	}
	global := scopeKey(GlobalTenant, name)
	if global == own {
		return "", false
	}
	if _, ok := r.configs[global]; ok {
		return global, true
	}
	if _, ok := r.providers[global]; ok {
		return global, true
	}
	return "", false
}

// Enable enables one of the caller's own providers for routing.
func (r *Registry) Enable(tenantID, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	config, exists := r.configs[ownKey(tenantID, name)]
	if !exists {
		return &RegistryError{
			ProviderName: name,
			Code:         ErrRegistryNotFound,
			Message:      fmt.Sprintf("provider %q not found", name),
		}
	}

	config.Enabled = true
	r.logger.Printf("Enabled provider: %s (tenant: %s)", name, normalizeTenant(tenantID))
	return nil
}

// Disable disables one of the caller's own providers (removes from routing).
func (r *Registry) Disable(tenantID, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	config, exists := r.configs[ownKey(tenantID, name)]
	if !exists {
		return &RegistryError{
			ProviderName: name,
			Code:         ErrRegistryNotFound,
			Message:      fmt.Sprintf("provider %q not found", name),
		}
	}

	config.Enabled = false
	r.logger.Printf("Disabled provider: %s (tenant: %s)", name, normalizeTenant(tenantID))
	return nil
}

// Update atomically replaces a provider's configuration within the tenancy
// carried by config.TenantID. It resolves the OWN key only, so it can never
// overwrite a deployment provider or another tenant's row (#3067 S-3: PUT
// /routing used to persist weights onto another tenant's provider, silently
// disabling their LLM routing).
// The old provider instance is removed and will be re-instantiated lazily on next use.
// This is atomic — there is no window where the provider is missing from the registry.
func (r *Registry) Update(ctx context.Context, config *ProviderConfig) error {
	if config == nil {
		return &RegistryError{Code: ErrRegistryInvalidConfig, Message: "config cannot be nil"}
	}
	if config.Name == "" {
		return &RegistryError{Code: ErrRegistryInvalidConfig, Message: "provider name is required"}
	}

	// Validate the new config
	if err := ValidateConfig(*config); err != nil {
		return &RegistryError{
			ProviderName: config.Name,
			Code:         ErrRegistryInvalidConfig,
			Message:      fmt.Sprintf("invalid configuration: %v", err),
			Cause:        err,
		}
	}

	// Check license allows this provider type
	if !r.validator.IsProviderAllowed(ctx, config.Type) {
		requiredTier := GetTierForProvider(config.Type)
		currentTier := r.validator.GetCurrentTier(ctx)
		return &RegistryError{
			ProviderName: config.Name,
			Code:         ErrRegistryLicenseRequired,
			Message: fmt.Sprintf("provider type %q requires %s license (current: %s) - upgrade at https://getaxonflow.com/enterprise",
				config.Type, requiredTier, currentTier),
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	key := ownKey(config.TenantID, config.Name)

	// Verify provider exists in the caller's own tenancy
	if _, exists := r.configs[key]; !exists {
		if _, exists := r.providers[key]; !exists {
			return &RegistryError{
				ProviderName: config.Name,
				Code:         ErrRegistryNotFound,
				Message:      fmt.Sprintf("provider %q not found", config.Name),
			}
		}
	}

	// Save old state for rollback
	oldConfig := r.configs[key]
	oldProvider := r.providers[key]

	// Atomically replace: remove old instance, store new config
	delete(r.providers, key)
	configCopy := *config
	r.configs[key] = &configCopy

	// Persist to storage if available — rollback in-memory on failure
	if r.storage != nil {
		if err := r.storage.SaveProvider(ctx, &configCopy); err != nil {
			// Rollback in-memory change to maintain consistency with storage
			r.configs[key] = oldConfig
			if oldProvider != nil {
				r.providers[key] = oldProvider
			}
			return &RegistryError{
				ProviderName: config.Name,
				Code:         ErrRegistryStorageError,
				Message:      fmt.Sprintf("failed to persist updated provider %s: %v", config.Name, err),
				Cause:        err,
			}
		}
	}

	// Clear stale health result
	r.healthMu.Lock()
	delete(r.healthResults, key)
	r.healthMu.Unlock()

	r.logger.Printf("Updated provider: %s (type: %s, tenant: %s)", config.Name, config.Type, normalizeTenant(config.TenantID))
	return nil
}

// Unregister removes one of the caller's own providers from the registry.
func (r *Registry) Unregister(ctx context.Context, tenantID, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := ownKey(tenantID, name)

	cfg, hasCfg := r.configs[key]
	if !hasCfg {
		if _, exists := r.providers[key]; !exists {
			return &RegistryError{
				ProviderName: name,
				Code:         ErrRegistryNotFound,
				Message:      fmt.Sprintf("provider %q not found", name),
			}
		}
	}

	// Remove from storage if available.
	// v9 Phase 8 PR-C2 (#2384): pass the in-memory config's TenantID so
	// Storage's DeleteProvider can wrap the DELETE in WithOrgScope. Without
	// orgID the DELETE silently affects 0 rows under axonflow_app_role.
	if r.storage != nil {
		var orgID string
		if cfg != nil {
			orgID = cfg.TenantID
		}
		if orgID == "" {
			r.logger.Printf("Warning: Unregister %q has no in-memory config TenantID to derive orgID — skipping storage delete to avoid cross-org wipe", logutil.Sanitize(name))
		} else if err := r.storage.DeleteProvider(ctx, orgID, name); err != nil {
			r.logger.Printf("Warning: failed to delete provider %s from storage: %v", logutil.Sanitize(name), err)
			// Continue with in-memory removal
		}
	}

	delete(r.providers, key)
	delete(r.configs, key)

	// Clean up health results
	r.healthMu.Lock()
	delete(r.healthResults, key)
	r.healthMu.Unlock()

	r.logger.Printf("Unregistered provider: %s (tenant: %s)", name, normalizeTenant(tenantID))
	return nil
}

// Get retrieves a provider visible to tenantID by name, instantiating it
// lazily if needed.
//
// #3067 (S-2, CRITICAL): this used to be Get(ctx, name) over a flat map. The
// /test endpoint fed it a caller-supplied path segment and then ran a
// completion — spending and billing the named tenant's API key and returning
// the completion to the attacker.
func (r *Registry) Get(ctx context.Context, tenantID, name string) (Provider, error) {
	// Fast path: check if provider is already instantiated
	r.mu.RLock()
	key, resolved := r.readKeyLocked(tenantID, name)
	var (
		provider  Provider
		config    *ProviderConfig
		exists    bool
		hasConfig bool
	)
	if resolved {
		provider, exists = r.providers[key]
		config, hasConfig = r.configs[key]
	}
	r.mu.RUnlock()

	if exists {
		return provider, nil
	}

	// Lazy instantiation if we have a config
	if hasConfig {
		return r.lazyInstantiate(ctx, key, name, config)
	}

	return nil, &RegistryError{
		ProviderName: name,
		Code:         ErrRegistryNotFound,
		Message:      fmt.Sprintf("provider %q not found", name),
	}
}

// lazyInstantiate creates a provider instance from its config. key is the
// already-resolved composite key; name is carried for log/error text only.
func (r *Registry) lazyInstantiate(ctx context.Context, key, name string, config *ProviderConfig) (Provider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check: another goroutine may have created it
	if provider, exists := r.providers[key]; exists {
		return provider, nil
	}

	r.logger.Printf("Lazy-instantiating provider: %s (type: %s)", name, config.Type)

	// Create provider using factory
	provider, err := r.factory.Create(*config)
	if err != nil {
		return nil, &RegistryError{
			ProviderName: name,
			Code:         ErrRegistryCreationFailed,
			Message:      fmt.Sprintf("failed to create provider: %v", err),
			Cause:        err,
		}
	}

	r.providers[key] = provider
	r.logger.Printf("Successfully instantiated provider: %s", name)

	return provider, nil
}

// GetConfig returns the configuration for a provider visible to tenantID.
func (r *Registry) GetConfig(tenantID, name string) (*ProviderConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key, ok := r.readKeyLocked(tenantID, name)
	if !ok {
		return nil, &RegistryError{
			ProviderName: name,
			Code:         ErrRegistryNotFound,
			Message:      fmt.Sprintf("config for provider %q not found", name),
		}
	}
	config, exists := r.configs[key]
	if !exists {
		return nil, &RegistryError{
			ProviderName: name,
			Code:         ErrRegistryNotFound,
			Message:      fmt.Sprintf("config for provider %q not found", name),
		}
	}

	// Return a copy to prevent external modification
	configCopy := *config
	return &configCopy, nil
}

// OwnsProvider reports whether tenantID is the OWNER of a provider with this
// name — i.e. whether it may mutate it. Deployment providers and other
// tenants' providers both answer false.
func (r *Registry) OwnsProvider(tenantID, name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	key := ownKey(tenantID, name)
	_, hasConfig := r.configs[key]
	_, hasProvider := r.providers[key]
	return hasConfig || hasProvider
}

// List returns the provider names visible to tenantID (its own plus the
// deployment's).
func (r *Registry) List(tenantID string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	nameSet := make(map[string]bool)
	collect := func(key string) {
		keyTenant, name, ok := splitScopeKey(key)
		if ok && readableBy(keyTenant, tenantID) {
			nameSet[name] = true
		}
	}
	for key := range r.configs {
		collect(key)
	}
	for key := range r.providers {
		collect(key)
	}

	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ListEnabled returns names of enabled providers visible to tenantID.
func (r *Registry) ListEnabled(tenantID string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	nameSet := make(map[string]bool)
	for key, config := range r.configs {
		keyTenant, name, ok := splitScopeKey(key)
		if ok && readableBy(keyTenant, tenantID) && config.Enabled {
			nameSet[name] = true
		}
	}
	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ListByType returns provider names of a specific type visible to tenantID.
func (r *Registry) ListByType(tenantID string, providerType ProviderType) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	nameSet := make(map[string]bool)
	for key, config := range r.configs {
		keyTenant, name, ok := splitScopeKey(key)
		if ok && readableBy(keyTenant, tenantID) && config.Type == providerType {
			nameSet[name] = true
		}
	}
	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Count returns the number of providers visible to tenantID.
// This includes both providers with configs and pre-instantiated providers.
func (r *Registry) Count(tenantID string) int {
	return len(r.List(tenantID))
}

// CountInstantiated returns the number of instantiated providers across the
// whole deployment. Operator diagnostics only — never served to a tenant.
func (r *Registry) CountInstantiated() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}

// Has returns true if a provider by this name is visible to tenantID.
func (r *Registry) Has(tenantID, name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.readKeyLocked(tenantID, name)
	return ok
}

// HealthCheck performs health checks on the instantiated providers OWNED by
// tenantID and returns the results by provider name.
//
// #3067 (R3): ownership, not visibility. A health check is an outbound call on
// the provider's credential AND it writes the cached health result the router
// selects on (GetHealthyProviders). Sweeping merely-visible providers would let
// any tenant spend the deployment's own API key in a loop and, once the
// provider rate-limits, cache the failure under the DEPLOYMENT key — evicting
// it from the routing pool for every tenant. Pass GlobalTenant explicitly (as
// the periodic sweep and the router do) to check the deployment's own pool.
func (r *Registry) HealthCheck(ctx context.Context, tenantID string) map[string]*HealthCheckResult {
	type target struct {
		key      string
		name     string
		provider Provider
	}

	owner := normalizeTenant(tenantID)

	r.mu.RLock()
	targets := make([]target, 0, len(r.providers))
	for key, p := range r.providers {
		keyTenant, name, ok := splitScopeKey(key)
		if !ok || keyTenant != owner {
			continue
		}
		targets = append(targets, target{key: key, name: name, provider: p})
	}
	r.mu.RUnlock()

	results := make(map[string]*HealthCheckResult, len(targets))

	for _, t := range targets {
		start := time.Now()
		result, err := t.provider.HealthCheck(ctx)
		if err != nil {
			result = &HealthCheckResult{
				Status:      HealthStatusUnhealthy,
				Latency:     time.Since(start),
				Message:     err.Error(),
				LastChecked: time.Now(),
			}
		}
		if result.LastChecked.IsZero() {
			result.LastChecked = time.Now()
		}
		results[t.name] = result

		// Update cached results
		r.healthMu.Lock()
		r.healthResults[t.key] = result
		r.healthMu.Unlock()
	}

	return results
}

// HealthCheckSingle performs a health check on a provider OWNED by tenantID.
//
// #3067 (R3): same reasoning as HealthCheck — this spends the credential and
// writes the cached health result the router reads, so it resolves the OWN key
// only. A tenant naming the deployment's provider gets ErrRegistryNotFound
// rather than a free outbound call on the operator's key.
func (r *Registry) HealthCheckSingle(ctx context.Context, tenantID, name string) (*HealthCheckResult, error) {
	key := ownKey(tenantID, name)

	r.mu.RLock()
	_, hasProvider := r.providers[key]
	_, hasConfig := r.configs[key]
	r.mu.RUnlock()
	if !hasProvider && !hasConfig {
		return nil, &RegistryError{
			ProviderName: name,
			Code:         ErrRegistryNotFound,
			Message:      fmt.Sprintf("provider %q not found", name),
		}
	}

	provider, err := r.Get(ctx, tenantID, name)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	result, err := provider.HealthCheck(ctx)
	if err != nil {
		result = &HealthCheckResult{
			Status:      HealthStatusUnhealthy,
			Latency:     time.Since(start),
			Message:     err.Error(),
			LastChecked: time.Now(),
		}
	}
	if result.LastChecked.IsZero() {
		result.LastChecked = time.Now()
	}

	// Update cached result
	r.healthMu.Lock()
	r.healthResults[key] = result
	r.healthMu.Unlock()

	return result, nil
}

// GetHealthResult returns the cached health result for a provider visible to
// tenantID.
func (r *Registry) GetHealthResult(tenantID, name string) *HealthCheckResult {
	r.mu.RLock()
	key, ok := r.readKeyLocked(tenantID, name)
	r.mu.RUnlock()
	if !ok {
		return nil
	}

	r.healthMu.RLock()
	defer r.healthMu.RUnlock()
	return r.healthResults[key]
}

// GetHealthyProviders returns names of healthy providers visible to tenantID.
func (r *Registry) GetHealthyProviders(tenantID string) []string {
	r.healthMu.RLock()
	healthy := make(map[string]bool, len(r.healthResults))
	for key, result := range r.healthResults {
		if result == nil || result.Status != HealthStatusHealthy {
			continue
		}
		keyTenant, name, ok := splitScopeKey(key)
		if ok && readableBy(keyTenant, tenantID) {
			healthy[name] = true
		}
	}
	r.healthMu.RUnlock()

	names := make([]string, 0, len(healthy))
	for name := range healthy {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ReloadFromStorage reloads provider configs from storage.
// This is used to sync configs from other orchestrator replicas.
func (r *Registry) ReloadFromStorage(ctx context.Context) error {
	if r.storage == nil {
		return nil
	}

	names, err := r.storage.ListAllProviders(ctx)
	if err != nil {
		return &RegistryError{
			Code:    ErrRegistryStorageError,
			Message: fmt.Sprintf("failed to list providers from storage: %v", err),
			Cause:   err,
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	newCount := 0
	for _, name := range names {
		config, err := r.storage.GetProvider(ctx, name)
		if err != nil {
			r.logger.Printf("Warning: failed to load provider %s from storage: %v", name, err)
			continue
		}

		// #3067 (R3 BLOCKER): refuse to key a row whose tenancy did not
		// arrive. normalizeTenant would otherwise map "" onto GlobalTenant,
		// silently promoting one tenant's provider into the deployment pool
		// the router selects from for EVERY tenant's traffic — the S-2
		// defect, reintroduced through the reload path.
		if config.TenantID == "" {
			r.logger.Printf("Warning: provider %s loaded from storage with no tenant_id — refusing to register it (it would otherwise be keyed deployment-global)", logutil.Sanitize(name))
			continue
		}

		// Skip if already loaded. The check runs AFTER the fetch because only
		// the fetched row carries the tenancy that forms the key (#3067);
		// llm_providers is keyed by name in storage, so a name identifies at
		// most one row and the extra fetch is bounded by the provider count.
		key := scopeKey(config.TenantID, name)
		if _, exists := r.configs[key]; exists {
			continue
		}

		r.configs[key] = config
		newCount++
		r.logger.Printf("Loaded provider config from storage: %s (type: %s, tenant: %s)", name, config.Type, normalizeTenant(config.TenantID))
	}

	if newCount > 0 {
		r.logger.Printf("Loaded %d new provider(s) from storage", newCount)
	}

	return nil
}

// StartPeriodicReload starts a background goroutine that periodically reloads from storage.
func (r *Registry) StartPeriodicReload(ctx context.Context, interval time.Duration) {
	if r.storage == nil {
		r.logger.Println("Storage not configured - skipping periodic reload")
		return
	}

	r.logger.Printf("Starting periodic provider reload (every %v)", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				r.logger.Println("Stopping periodic provider reload")
				return
			case <-ticker.C:
				if err := r.ReloadFromStorage(ctx); err != nil {
					r.logger.Printf("Periodic reload failed: %v", err)
				}
			}
		}
	}()
}

// StartPeriodicHealthCheck starts a background goroutine for health checking.
func (r *Registry) StartPeriodicHealthCheck(ctx context.Context, interval time.Duration) {
	r.logger.Printf("Starting periodic health check (every %v)", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				r.logger.Println("Stopping periodic health check")
				return
			case <-ticker.C:
				// Deployment-level pool only — see GlobalTenant (#3067).
				results := r.HealthCheck(ctx, GlobalTenant)
				healthy := 0
				unhealthy := 0
				for _, result := range results {
					if result.Status == HealthStatusHealthy {
						healthy++
					} else {
						unhealthy++
					}
				}
				if unhealthy > 0 {
					r.logger.Printf("Health check: %d healthy, %d unhealthy", healthy, unhealthy)
				}
			}
		}
	}()
}

// Close cleans up registry resources.
// This does not close individual providers (they should manage their own lifecycle).
func (r *Registry) Close() error {
	r.logger.Println("Closing registry...")

	// Clear providers and configs first
	r.mu.Lock()
	r.providers = make(map[string]Provider)
	r.configs = make(map[string]*ProviderConfig)
	r.mu.Unlock()

	// Clear health results separately to avoid holding multiple locks
	r.healthMu.Lock()
	r.healthResults = make(map[string]*HealthCheckResult)
	r.healthMu.Unlock()

	r.logger.Println("Registry closed")
	return nil
}

// RegistryError represents an error from registry operations.
type RegistryError struct {
	ProviderName string
	Code         string
	Message      string
	Cause        error
}

// Registry error codes.
const (
	// ErrRegistryNotFound indicates the provider was not found.
	ErrRegistryNotFound = "registry_not_found"

	// ErrRegistryDuplicate indicates a provider with that name exists.
	ErrRegistryDuplicate = "registry_duplicate"

	// ErrRegistryInvalidConfig indicates invalid provider configuration.
	ErrRegistryInvalidConfig = "registry_invalid_config"

	// ErrRegistryCreationFailed indicates provider creation failed.
	ErrRegistryCreationFailed = "registry_creation_failed"

	// ErrRegistryStorageError indicates a storage operation failed.
	ErrRegistryStorageError = "registry_storage_error"

	// ErrRegistryLicenseRequired indicates the provider type requires a license upgrade.
	ErrRegistryLicenseRequired = "registry_license_required"

	// ErrRegistryProviderLimit indicates the maximum number of providers has been reached.
	ErrRegistryProviderLimit = "registry_provider_limit"
)

// Error implements the error interface.
func (e *RegistryError) Error() string {
	if e.ProviderName != "" {
		return fmt.Sprintf("registry error for %q: %s", e.ProviderName, e.Message)
	}
	return fmt.Sprintf("registry error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *RegistryError) Unwrap() error {
	return e.Cause
}
