// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package media

import (
	"fmt"
	"sync"
)

// AnalyzerFactory creates a MediaAnalyzer instance from configuration.
type AnalyzerFactory func(config AnalyzerConfig) (MediaAnalyzer, error)

// analyzerFactoryRegistry holds registered analyzer factories.
type analyzerFactoryRegistry struct {
	factories map[MediaAnalyzerType]AnalyzerFactory
	mu        sync.RWMutex
}

// globalAnalyzerRegistry is the default analyzer factory registry.
var globalAnalyzerRegistry = &analyzerFactoryRegistry{
	factories: make(map[MediaAnalyzerType]AnalyzerFactory),
}

// RegisterAnalyzerFactory registers a factory function for an analyzer type.
// This is typically called during package init() to register built-in analyzers.
func RegisterAnalyzerFactory(analyzerType MediaAnalyzerType, factory AnalyzerFactory) {
	globalAnalyzerRegistry.mu.Lock()
	defer globalAnalyzerRegistry.mu.Unlock()
	globalAnalyzerRegistry.factories[analyzerType] = factory
}

// UnregisterAnalyzerFactory removes a factory for an analyzer type.
func UnregisterAnalyzerFactory(analyzerType MediaAnalyzerType) bool {
	globalAnalyzerRegistry.mu.Lock()
	defer globalAnalyzerRegistry.mu.Unlock()
	_, existed := globalAnalyzerRegistry.factories[analyzerType]
	delete(globalAnalyzerRegistry.factories, analyzerType)
	return existed
}

// GetAnalyzerFactory returns the factory for an analyzer type, or nil if not registered.
func GetAnalyzerFactory(analyzerType MediaAnalyzerType) AnalyzerFactory {
	globalAnalyzerRegistry.mu.RLock()
	defer globalAnalyzerRegistry.mu.RUnlock()
	return globalAnalyzerRegistry.factories[analyzerType]
}

// HasAnalyzerFactory returns true if a factory is registered for the analyzer type.
func HasAnalyzerFactory(analyzerType MediaAnalyzerType) bool {
	globalAnalyzerRegistry.mu.RLock()
	defer globalAnalyzerRegistry.mu.RUnlock()
	_, ok := globalAnalyzerRegistry.factories[analyzerType]
	return ok
}

// ListAnalyzerFactories returns all registered analyzer types.
func ListAnalyzerFactories() []MediaAnalyzerType {
	globalAnalyzerRegistry.mu.RLock()
	defer globalAnalyzerRegistry.mu.RUnlock()
	types := make([]MediaAnalyzerType, 0, len(globalAnalyzerRegistry.factories))
	for at := range globalAnalyzerRegistry.factories {
		types = append(types, at)
	}
	return types
}

// CreateAnalyzer creates an analyzer using the registered factory.
func CreateAnalyzer(config AnalyzerConfig) (MediaAnalyzer, error) {
	if config.Type == "" {
		return nil, &FactoryError{
			AnalyzerType: "",
			Code:         ErrFactoryMissingType,
			Message:      "analyzer type is required",
		}
	}

	factory := GetAnalyzerFactory(config.Type)
	if factory == nil {
		return nil, &FactoryError{
			AnalyzerType: config.Type,
			Code:         ErrFactoryNotRegistered,
			Message:      fmt.Sprintf("no factory registered for analyzer type %q", config.Type),
		}
	}

	analyzer, err := factory(config)
	if err != nil {
		return nil, &FactoryError{
			AnalyzerType: config.Type,
			Code:         ErrFactoryCreationFailed,
			Message:      fmt.Sprintf("failed to create analyzer: %v", err),
			Cause:        err,
		}
	}

	return analyzer, nil
}

// AnalyzerFactoryManager provides advanced factory management for custom registries.
type AnalyzerFactoryManager struct {
	factories map[MediaAnalyzerType]AnalyzerFactory
	mu        sync.RWMutex
}

// NewAnalyzerFactoryManager creates a new factory manager with an empty registry.
func NewAnalyzerFactoryManager() *AnalyzerFactoryManager {
	return &AnalyzerFactoryManager{
		factories: make(map[MediaAnalyzerType]AnalyzerFactory),
	}
}

// Register adds a factory to this manager.
func (m *AnalyzerFactoryManager) Register(analyzerType MediaAnalyzerType, factory AnalyzerFactory) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.factories[analyzerType] = factory
}

// Get returns a factory from this manager.
func (m *AnalyzerFactoryManager) Get(analyzerType MediaAnalyzerType) AnalyzerFactory {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.factories[analyzerType]
}

// Has returns true if a factory is registered.
func (m *AnalyzerFactoryManager) Has(analyzerType MediaAnalyzerType) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.factories[analyzerType]
	return ok
}

// List returns all registered analyzer types.
func (m *AnalyzerFactoryManager) List() []MediaAnalyzerType {
	m.mu.RLock()
	defer m.mu.RUnlock()
	types := make([]MediaAnalyzerType, 0, len(m.factories))
	for at := range m.factories {
		types = append(types, at)
	}
	return types
}

// Create creates an analyzer using a factory from this manager.
func (m *AnalyzerFactoryManager) Create(config AnalyzerConfig) (MediaAnalyzer, error) {
	if config.Type == "" {
		return nil, &FactoryError{
			Code:    ErrFactoryMissingType,
			Message: "analyzer type is required",
		}
	}

	factory := m.Get(config.Type)
	if factory == nil {
		return nil, &FactoryError{
			AnalyzerType: config.Type,
			Code:         ErrFactoryNotRegistered,
			Message:      fmt.Sprintf("no factory registered for analyzer type %q", config.Type),
		}
	}

	analyzer, err := factory(config)
	if err != nil {
		return nil, &FactoryError{
			AnalyzerType: config.Type,
			Code:         ErrFactoryCreationFailed,
			Message:      fmt.Sprintf("failed to create analyzer: %v", err),
			Cause:        err,
		}
	}

	return analyzer, nil
}

// CopyFromGlobal copies all factories from the global registry to this manager.
func (m *AnalyzerFactoryManager) CopyFromGlobal() {
	globalAnalyzerRegistry.mu.RLock()
	defer globalAnalyzerRegistry.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	for at, factory := range globalAnalyzerRegistry.factories {
		m.factories[at] = factory
	}
}

// Count returns the number of registered factories.
func (m *AnalyzerFactoryManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.factories)
}

// Clear removes all registered factories.
func (m *AnalyzerFactoryManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.factories = make(map[MediaAnalyzerType]AnalyzerFactory)
}

// FactoryError represents an error during analyzer factory operations.
type FactoryError struct {
	AnalyzerType MediaAnalyzerType
	Code         string
	Message      string
	Cause        error
}

// Factory error codes.
const (
	ErrFactoryNotRegistered = "factory_not_registered"
	ErrFactoryMissingType   = "factory_missing_type"
	ErrFactoryCreationFailed = "factory_creation_failed"
	ErrFactoryInvalidConfig  = "factory_invalid_config"
)

// Error implements the error interface.
func (e *FactoryError) Error() string {
	if e.AnalyzerType != "" {
		return fmt.Sprintf("media factory error for %q: %s", e.AnalyzerType, e.Message)
	}
	return fmt.Sprintf("media factory error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *FactoryError) Unwrap() error {
	return e.Cause
}
