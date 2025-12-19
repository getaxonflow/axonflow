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
	"sync"
	"time"
)

// Registry manages LLM provider instances with lazy loading and health monitoring.
// It is thread-safe for concurrent access.
//
// The registry supports two modes:
//   - In-memory only: Providers are registered programmatically
//   - With storage: Providers are persisted to PostgreSQL and synced across replicas
type Registry struct {
	providers map[string]Provider        // Active provider instances
	configs   map[string]*ProviderConfig // Provider configurations (may not be instantiated yet)
	storage   Storage                    // Optional persistent storage
	factory   *FactoryManager            // Factory for creating providers
	validator LicenseValidator           // License validator for provider access control
	logger    *log.Logger
	mu        sync.RWMutex

	// Health monitoring
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

	// DeleteProvider removes a provider configuration.
	DeleteProvider(ctx context.Context, name string) error

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

// Register adds a provider configuration to the registry.
// The provider will be instantiated lazily on first use.
// If a provider with the same name exists, it returns an error.
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

	// Check for duplicate
	if _, exists := r.configs[config.Name]; exists {
		return &RegistryError{
			ProviderName: config.Name,
			Code:         ErrRegistryDuplicate,
			Message:      fmt.Sprintf("provider %q already registered", config.Name),
		}
	}

	// Store config (provider will be created lazily)
	configCopy := *config
	r.configs[config.Name] = &configCopy

	// Persist to storage if available
	if r.storage != nil {
		if err := r.storage.SaveProvider(ctx, &configCopy); err != nil {
			// Rollback in-memory registration
			delete(r.configs, config.Name)
			return &RegistryError{
				ProviderName: config.Name,
				Code:         ErrRegistryStorageError,
				Message:      fmt.Sprintf("failed to persist provider: %v", err),
				Cause:        err,
			}
		}
	}

	r.logger.Printf("Registered provider config: %s (type: %s)", config.Name, config.Type)
	return nil
}

// RegisterProvider adds a pre-instantiated provider to the registry.
// Use this when you have an already-created provider instance.
func (r *Registry) RegisterProvider(name string, provider Provider, config *ProviderConfig) error {
	if provider == nil {
		return &RegistryError{Code: ErrRegistryInvalidConfig, Message: "provider cannot be nil"}
	}

	if name == "" {
		return &RegistryError{Code: ErrRegistryInvalidConfig, Message: "provider name is required"}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.providers[name]; exists {
		return &RegistryError{
			ProviderName: name,
			Code:         ErrRegistryDuplicate,
			Message:      fmt.Sprintf("provider %q already registered", name),
		}
	}

	r.providers[name] = provider
	if config != nil {
		configCopy := *config
		r.configs[name] = &configCopy
	}

	r.logger.Printf("Registered provider instance: %s (type: %s)", name, provider.Type())
	return nil
}

// Unregister removes a provider from the registry.
func (r *Registry) Unregister(ctx context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.configs[name]; !exists {
		if _, exists := r.providers[name]; !exists {
			return &RegistryError{
				ProviderName: name,
				Code:         ErrRegistryNotFound,
				Message:      fmt.Sprintf("provider %q not found", name),
			}
		}
	}

	// Remove from storage if available
	if r.storage != nil {
		if err := r.storage.DeleteProvider(ctx, name); err != nil {
			r.logger.Printf("Warning: failed to delete provider %s from storage: %v", name, err)
			// Continue with in-memory removal
		}
	}

	delete(r.providers, name)
	delete(r.configs, name)

	// Clean up health results
	r.healthMu.Lock()
	delete(r.healthResults, name)
	r.healthMu.Unlock()

	r.logger.Printf("Unregistered provider: %s", name)
	return nil
}

// Get retrieves a provider by name, instantiating it lazily if needed.
func (r *Registry) Get(ctx context.Context, name string) (Provider, error) {
	// Fast path: check if provider is already instantiated
	r.mu.RLock()
	provider, exists := r.providers[name]
	config, hasConfig := r.configs[name]
	r.mu.RUnlock()

	if exists {
		return provider, nil
	}

	// Lazy instantiation if we have a config
	if hasConfig {
		return r.lazyInstantiate(ctx, name, config)
	}

	return nil, &RegistryError{
		ProviderName: name,
		Code:         ErrRegistryNotFound,
		Message:      fmt.Sprintf("provider %q not found", name),
	}
}

// lazyInstantiate creates a provider instance from its config.
func (r *Registry) lazyInstantiate(ctx context.Context, name string, config *ProviderConfig) (Provider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check: another goroutine may have created it
	if provider, exists := r.providers[name]; exists {
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

	r.providers[name] = provider
	r.logger.Printf("Successfully instantiated provider: %s", name)

	return provider, nil
}

// GetConfig returns the configuration for a provider.
func (r *Registry) GetConfig(name string) (*ProviderConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	config, exists := r.configs[name]
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

// List returns all registered provider names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Collect names from both configs and providers
	nameSet := make(map[string]bool)
	for name := range r.configs {
		nameSet[name] = true
	}
	for name := range r.providers {
		nameSet[name] = true
	}

	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ListEnabled returns names of enabled providers.
func (r *Registry) ListEnabled() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []string
	for name, config := range r.configs {
		if config.Enabled {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// ListByType returns provider names of a specific type.
func (r *Registry) ListByType(providerType ProviderType) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []string
	for name, config := range r.configs {
		if config.Type == providerType {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// Count returns the total number of registered providers.
// This includes both providers with configs and pre-instantiated providers.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Count unique names from both configs and providers
	nameSet := make(map[string]bool)
	for name := range r.configs {
		nameSet[name] = true
	}
	for name := range r.providers {
		nameSet[name] = true
	}
	return len(nameSet)
}

// CountInstantiated returns the number of instantiated providers.
func (r *Registry) CountInstantiated() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}

// Has returns true if a provider is registered.
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, hasConfig := r.configs[name]
	_, hasProvider := r.providers[name]
	return hasConfig || hasProvider
}

// HealthCheck performs health checks on all instantiated providers.
func (r *Registry) HealthCheck(ctx context.Context) map[string]*HealthCheckResult {
	r.mu.RLock()
	providers := make(map[string]Provider, len(r.providers))
	for name, p := range r.providers {
		providers[name] = p
	}
	r.mu.RUnlock()

	results := make(map[string]*HealthCheckResult, len(providers))

	for name, provider := range providers {
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
		results[name] = result

		// Update cached results
		r.healthMu.Lock()
		r.healthResults[name] = result
		r.healthMu.Unlock()
	}

	return results
}

// HealthCheckSingle performs a health check on a specific provider.
func (r *Registry) HealthCheckSingle(ctx context.Context, name string) (*HealthCheckResult, error) {
	provider, err := r.Get(ctx, name)
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
	r.healthResults[name] = result
	r.healthMu.Unlock()

	return result, nil
}

// GetHealthResult returns the cached health result for a provider.
func (r *Registry) GetHealthResult(name string) *HealthCheckResult {
	r.healthMu.RLock()
	defer r.healthMu.RUnlock()
	return r.healthResults[name]
}

// GetHealthyProviders returns names of healthy providers.
func (r *Registry) GetHealthyProviders() []string {
	r.healthMu.RLock()
	defer r.healthMu.RUnlock()

	var names []string
	for name, result := range r.healthResults {
		if result != nil && result.Status == HealthStatusHealthy {
			names = append(names, name)
		}
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
		// Skip if already loaded
		if _, exists := r.configs[name]; exists {
			continue
		}

		config, err := r.storage.GetProvider(ctx, name)
		if err != nil {
			r.logger.Printf("Warning: failed to load provider %s from storage: %v", name, err)
			continue
		}

		r.configs[name] = config
		newCount++
		r.logger.Printf("Loaded provider config from storage: %s (type: %s)", name, config.Type)
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
				results := r.HealthCheck(ctx)
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
