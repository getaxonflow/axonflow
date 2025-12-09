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

package llm

import (
	"fmt"
	"sync"
)

// ProviderFactory creates a Provider instance from configuration.
// Factories should validate the config and return an error if invalid.
type ProviderFactory func(config ProviderConfig) (Provider, error)

// factoryRegistry holds registered provider factories.
// Thread-safe for concurrent access.
type factoryRegistry struct {
	factories map[ProviderType]ProviderFactory
	mu        sync.RWMutex
}

// globalRegistry is the default factory registry.
var globalRegistry = &factoryRegistry{
	factories: make(map[ProviderType]ProviderFactory),
}

// RegisterFactory registers a factory function for a provider type.
// This is typically called during package init() to register built-in providers.
// If a factory is already registered for the type, it will be overwritten.
//
// Example:
//
//	func init() {
//	    llm.RegisterFactory(llm.ProviderTypeOpenAI, NewOpenAIProvider)
//	}
func RegisterFactory(providerType ProviderType, factory ProviderFactory) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()
	globalRegistry.factories[providerType] = factory
}

// UnregisterFactory removes a factory for a provider type.
// Returns true if a factory was removed, false if none existed.
func UnregisterFactory(providerType ProviderType) bool {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()
	_, existed := globalRegistry.factories[providerType]
	delete(globalRegistry.factories, providerType)
	return existed
}

// GetFactory returns the factory for a provider type, or nil if not registered.
func GetFactory(providerType ProviderType) ProviderFactory {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	return globalRegistry.factories[providerType]
}

// HasFactory returns true if a factory is registered for the provider type.
func HasFactory(providerType ProviderType) bool {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	_, ok := globalRegistry.factories[providerType]
	return ok
}

// ListFactories returns all registered provider types.
func ListFactories() []ProviderType {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	types := make([]ProviderType, 0, len(globalRegistry.factories))
	for pt := range globalRegistry.factories {
		types = append(types, pt)
	}
	return types
}

// CreateProvider creates a provider using the registered factory.
// Returns an error if no factory is registered for the provider type.
//
// Example:
//
//	config := ProviderConfig{
//	    Name:   "anthropic-primary",
//	    Type:   ProviderTypeAnthropic,
//	    APIKey: "sk-ant-...",
//	    Model:  "claude-3-5-sonnet-20241022",
//	}
//	provider, err := llm.CreateProvider(config)
func CreateProvider(config ProviderConfig) (Provider, error) {
	if config.Type == "" {
		return nil, &FactoryError{
			ProviderType: "",
			Code:         ErrFactoryMissingType,
			Message:      "provider type is required",
		}
	}

	factory := GetFactory(config.Type)
	if factory == nil {
		return nil, &FactoryError{
			ProviderType: config.Type,
			Code:         ErrFactoryNotRegistered,
			Message:      fmt.Sprintf("no factory registered for provider type %q", config.Type),
		}
	}

	provider, err := factory(config)
	if err != nil {
		return nil, &FactoryError{
			ProviderType: config.Type,
			Code:         ErrFactoryCreationFailed,
			Message:      fmt.Sprintf("failed to create provider: %v", err),
			Cause:        err,
		}
	}

	return provider, nil
}

// MustCreateProvider creates a provider or panics on error.
// Use this only in initialization code where failure should be fatal.
func MustCreateProvider(config ProviderConfig) Provider {
	provider, err := CreateProvider(config)
	if err != nil {
		panic(fmt.Sprintf("failed to create provider %q: %v", config.Name, err))
	}
	return provider
}

// FactoryError represents an error during provider factory operations.
type FactoryError struct {
	ProviderType ProviderType
	Code         string
	Message      string
	Cause        error
}

// Factory error codes.
const (
	// ErrFactoryNotRegistered indicates no factory is registered for the type.
	ErrFactoryNotRegistered = "factory_not_registered"

	// ErrFactoryMissingType indicates the provider type was not specified.
	ErrFactoryMissingType = "factory_missing_type"

	// ErrFactoryCreationFailed indicates the factory returned an error.
	ErrFactoryCreationFailed = "factory_creation_failed"

	// ErrFactoryInvalidConfig indicates the configuration is invalid.
	ErrFactoryInvalidConfig = "factory_invalid_config"
)

// Error implements the error interface.
func (e *FactoryError) Error() string {
	if e.ProviderType != "" {
		return fmt.Sprintf("factory error for %q: %s", e.ProviderType, e.Message)
	}
	return fmt.Sprintf("factory error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *FactoryError) Unwrap() error {
	return e.Cause
}

// ValidateConfig validates a ProviderConfig and returns any errors.
// This can be used before calling CreateProvider to get detailed validation errors.
func ValidateConfig(config ProviderConfig) error {
	if config.Type == "" {
		return &FactoryError{
			Code:    ErrFactoryInvalidConfig,
			Message: "provider type is required",
		}
	}

	if config.Name == "" {
		return &FactoryError{
			ProviderType: config.Type,
			Code:         ErrFactoryInvalidConfig,
			Message:      "provider name is required",
		}
	}

	// Type-specific validation
	switch config.Type {
	case ProviderTypeOpenAI, ProviderTypeAnthropic, ProviderTypeGemini:
		if config.APIKey == "" && config.APIKeySecretARN == "" {
			return &FactoryError{
				ProviderType: config.Type,
				Code:         ErrFactoryInvalidConfig,
				Message:      "API key or secret ARN is required",
			}
		}

	case ProviderTypeBedrock:
		if config.Region == "" {
			return &FactoryError{
				ProviderType: config.Type,
				Code:         ErrFactoryInvalidConfig,
				Message:      "AWS region is required for Bedrock",
			}
		}

	case ProviderTypeOllama:
		// Ollama has sensible defaults, no required fields
		// Endpoint defaults to localhost:11434

	case ProviderTypeCustom:
		// Custom providers may have their own validation
		// Let the factory handle it
	}

	// Validate weight if specified
	if config.Weight < 0 || config.Weight > 100 {
		return &FactoryError{
			ProviderType: config.Type,
			Code:         ErrFactoryInvalidConfig,
			Message:      "weight must be between 0 and 100",
		}
	}

	// Validate timeout if specified
	if config.TimeoutSeconds < 0 {
		return &FactoryError{
			ProviderType: config.Type,
			Code:         ErrFactoryInvalidConfig,
			Message:      "timeout must be non-negative",
		}
	}

	// Validate priority if specified
	if config.Priority < 0 {
		return &FactoryError{
			ProviderType: config.Type,
			Code:         ErrFactoryInvalidConfig,
			Message:      "priority must be non-negative",
		}
	}

	// Validate rate limit if specified
	if config.RateLimit < 0 {
		return &FactoryError{
			ProviderType: config.Type,
			Code:         ErrFactoryInvalidConfig,
			Message:      "rate limit must be non-negative (0 for unlimited)",
		}
	}

	return nil
}

// FactoryManager provides advanced factory management for custom registries.
// Use this when you need multiple isolated factory registries (e.g., testing).
type FactoryManager struct {
	factories map[ProviderType]ProviderFactory
	mu        sync.RWMutex
}

// NewFactoryManager creates a new factory manager with an empty registry.
func NewFactoryManager() *FactoryManager {
	return &FactoryManager{
		factories: make(map[ProviderType]ProviderFactory),
	}
}

// Register adds a factory to this manager.
func (m *FactoryManager) Register(providerType ProviderType, factory ProviderFactory) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.factories[providerType] = factory
}

// Unregister removes a factory from this manager.
func (m *FactoryManager) Unregister(providerType ProviderType) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, existed := m.factories[providerType]
	delete(m.factories, providerType)
	return existed
}

// Get returns a factory from this manager.
func (m *FactoryManager) Get(providerType ProviderType) ProviderFactory {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.factories[providerType]
}

// Has returns true if a factory is registered.
func (m *FactoryManager) Has(providerType ProviderType) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.factories[providerType]
	return ok
}

// List returns all registered provider types.
func (m *FactoryManager) List() []ProviderType {
	m.mu.RLock()
	defer m.mu.RUnlock()
	types := make([]ProviderType, 0, len(m.factories))
	for pt := range m.factories {
		types = append(types, pt)
	}
	return types
}

// Create creates a provider using a factory from this manager.
func (m *FactoryManager) Create(config ProviderConfig) (Provider, error) {
	if config.Type == "" {
		return nil, &FactoryError{
			Code:    ErrFactoryMissingType,
			Message: "provider type is required",
		}
	}

	factory := m.Get(config.Type)
	if factory == nil {
		return nil, &FactoryError{
			ProviderType: config.Type,
			Code:         ErrFactoryNotRegistered,
			Message:      fmt.Sprintf("no factory registered for provider type %q", config.Type),
		}
	}

	provider, err := factory(config)
	if err != nil {
		return nil, &FactoryError{
			ProviderType: config.Type,
			Code:         ErrFactoryCreationFailed,
			Message:      fmt.Sprintf("failed to create provider: %v", err),
			Cause:        err,
		}
	}

	return provider, nil
}

// CopyFromGlobal copies all factories from the global registry to this manager.
func (m *FactoryManager) CopyFromGlobal() {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	for pt, factory := range globalRegistry.factories {
		m.factories[pt] = factory
	}
}

// Count returns the number of registered factories.
func (m *FactoryManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.factories)
}

// Clear removes all registered factories.
func (m *FactoryManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.factories = make(map[ProviderType]ProviderFactory)
}
