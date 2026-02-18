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
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
)

// Registry manages MediaAnalyzer instances with lazy loading and health monitoring.
// It is thread-safe for concurrent access.
type Registry struct {
	analyzers    map[string]MediaAnalyzer   // Active analyzer instances
	configs      map[string]*AnalyzerConfig // Analyzer configurations (may not be instantiated yet)
	factory      *AnalyzerFactoryManager    // Factory for creating analyzers
	validator    AnalyzerLicenseValidator   // License validator for analyzer access control
	maxAnalyzers int                        // Maximum analyzer count (-1 = unlimited, 0 = use default)
	logger       *log.Logger
	mu           sync.RWMutex
}

// RegistryOption configures the registry during creation.
type RegistryOption func(*Registry)

// WithRegistryLogger sets a custom logger for the registry.
func WithRegistryLogger(logger *log.Logger) RegistryOption {
	return func(r *Registry) {
		r.logger = logger
	}
}

// WithRegistryFactoryManager sets a custom factory manager.
func WithRegistryFactoryManager(fm *AnalyzerFactoryManager) RegistryOption {
	return func(r *Registry) {
		r.factory = fm
	}
}

// WithRegistryLicenseValidator sets a custom license validator.
func WithRegistryLicenseValidator(v AnalyzerLicenseValidator) RegistryOption {
	return func(r *Registry) {
		r.validator = v
	}
}

// WithMaxAnalyzers sets the maximum number of analyzers that can be registered.
func WithMaxAnalyzers(max int) RegistryOption {
	return func(r *Registry) {
		r.maxAnalyzers = max
	}
}

// NewRegistry creates a new analyzer registry.
func NewRegistry(opts ...RegistryOption) *Registry {
	r := &Registry{
		analyzers: make(map[string]MediaAnalyzer),
		configs:   make(map[string]*AnalyzerConfig),
		logger:    log.New(os.Stdout, "[MEDIA_REGISTRY] ", log.LstdFlags),
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.factory == nil {
		r.factory = NewAnalyzerFactoryManager()
		r.factory.CopyFromGlobal()
	}

	if r.validator == nil {
		r.validator = DefaultAnalyzerValidator
	}

	return r
}

// Register adds an analyzer configuration to the registry.
// The analyzer will be instantiated lazily on first use.
func (r *Registry) Register(ctx context.Context, config *AnalyzerConfig) error {
	if config == nil {
		return &RegistryError{Code: ErrRegistryInvalidConfig, Message: "config cannot be nil"}
	}

	if config.Name == "" {
		return &RegistryError{Code: ErrRegistryInvalidConfig, Message: "analyzer name is required"}
	}

	if config.Type == "" {
		return &RegistryError{
			AnalyzerName: config.Name,
			Code:         ErrRegistryInvalidConfig,
			Message:      "analyzer type is required",
		}
	}

	// Check license allows this analyzer type
	if !r.validator.IsAnalyzerAllowed(ctx, config.Type) {
		return &RegistryError{
			AnalyzerName: config.Name,
			Code:         ErrRegistryLicenseRequired,
			Message:      fmt.Sprintf("analyzer type %q requires Enterprise license - upgrade at https://getaxonflow.com/enterprise", config.Type),
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check analyzer count limit (tier enforcement)
	if r.maxAnalyzers > 0 {
		currentCount := len(r.configs)
		for name := range r.analyzers {
			if _, hasConfig := r.configs[name]; !hasConfig {
				currentCount++
			}
		}
		if currentCount >= r.maxAnalyzers {
			return &RegistryError{
				AnalyzerName: config.Name,
				Code:         ErrRegistryAnalyzerLimit,
				Message:      fmt.Sprintf("maximum number of media analyzers reached (%d) - upgrade at https://getaxonflow.com/enterprise", r.maxAnalyzers),
			}
		}
	}

	// Check for duplicate
	if _, exists := r.configs[config.Name]; exists {
		return &RegistryError{
			AnalyzerName: config.Name,
			Code:         ErrRegistryDuplicate,
			Message:      fmt.Sprintf("analyzer %q already registered", config.Name),
		}
	}

	configCopy := *config
	r.configs[config.Name] = &configCopy

	r.logger.Printf("Registered analyzer config: %s (type: %s)", config.Name, config.Type)
	return nil
}

// RegisterAnalyzer adds a pre-instantiated analyzer to the registry.
func (r *Registry) RegisterAnalyzer(name string, analyzer MediaAnalyzer) error {
	if analyzer == nil {
		return &RegistryError{Code: ErrRegistryInvalidConfig, Message: "analyzer cannot be nil"}
	}

	if name == "" {
		return &RegistryError{Code: ErrRegistryInvalidConfig, Message: "analyzer name is required"}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.analyzers[name]; exists {
		return &RegistryError{
			AnalyzerName: name,
			Code:         ErrRegistryDuplicate,
			Message:      fmt.Sprintf("analyzer %q already registered", name),
		}
	}

	r.analyzers[name] = analyzer
	r.logger.Printf("Registered analyzer instance: %s (type: %s)", name, analyzer.Type())
	return nil
}

// Get retrieves an analyzer by name, instantiating it lazily if needed.
func (r *Registry) Get(ctx context.Context, name string) (MediaAnalyzer, error) {
	r.mu.RLock()
	analyzer, exists := r.analyzers[name]
	config, hasConfig := r.configs[name]
	r.mu.RUnlock()

	if exists {
		return analyzer, nil
	}

	if hasConfig {
		return r.lazyInstantiate(name, config)
	}

	return nil, &RegistryError{
		AnalyzerName: name,
		Code:         ErrRegistryNotFound,
		Message:      fmt.Sprintf("analyzer %q not found", name),
	}
}

// lazyInstantiate creates an analyzer instance from its config.
func (r *Registry) lazyInstantiate(name string, config *AnalyzerConfig) (MediaAnalyzer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check: another goroutine may have created it
	if analyzer, exists := r.analyzers[name]; exists {
		return analyzer, nil
	}

	r.logger.Printf("Lazy-instantiating analyzer: %s (type: %s)", name, config.Type)

	analyzer, err := r.factory.Create(*config)
	if err != nil {
		return nil, &RegistryError{
			AnalyzerName: name,
			Code:         ErrRegistryCreationFailed,
			Message:      fmt.Sprintf("failed to create analyzer: %v", err),
			Cause:        err,
		}
	}

	r.analyzers[name] = analyzer
	r.logger.Printf("Successfully instantiated analyzer: %s", name)

	return analyzer, nil
}

// List returns all registered analyzer names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	nameSet := make(map[string]bool)
	for name := range r.configs {
		nameSet[name] = true
	}
	for name := range r.analyzers {
		nameSet[name] = true
	}

	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ListEnabled returns names of enabled analyzers.
func (r *Registry) ListEnabled() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []string
	for name, config := range r.configs {
		if config.Enabled {
			names = append(names, name)
		}
	}
	// Include pre-instantiated analyzers without configs (always enabled)
	for name := range r.analyzers {
		if _, hasConfig := r.configs[name]; !hasConfig {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// Count returns the total number of registered analyzers.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	nameSet := make(map[string]bool)
	for name := range r.configs {
		nameSet[name] = true
	}
	for name := range r.analyzers {
		nameSet[name] = true
	}
	return len(nameSet)
}

// Has returns true if an analyzer is registered.
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, hasConfig := r.configs[name]
	_, hasAnalyzer := r.analyzers[name]
	return hasConfig || hasAnalyzer
}

// Unregister removes an analyzer from the registry.
func (r *Registry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.configs[name]; !exists {
		if _, exists := r.analyzers[name]; !exists {
			return &RegistryError{
				AnalyzerName: name,
				Code:         ErrRegistryNotFound,
				Message:      fmt.Sprintf("analyzer %q not found", name),
			}
		}
	}

	delete(r.analyzers, name)
	delete(r.configs, name)

	r.logger.Printf("Unregistered analyzer: %s", name)
	return nil
}

// HealthCheck performs health checks on all instantiated analyzers.
func (r *Registry) HealthCheck(ctx context.Context) map[string]error {
	r.mu.RLock()
	analyzers := make(map[string]MediaAnalyzer, len(r.analyzers))
	for name, a := range r.analyzers {
		analyzers[name] = a
	}
	r.mu.RUnlock()

	results := make(map[string]error, len(analyzers))
	for name, analyzer := range analyzers {
		results[name] = analyzer.HealthCheck(ctx)
	}

	return results
}

// GetAllAnalyzers returns all instantiated analyzers. Used by the pipeline.
func (r *Registry) GetAllAnalyzers(ctx context.Context) ([]MediaAnalyzer, error) {
	names := r.ListEnabled()
	analyzers := make([]MediaAnalyzer, 0, len(names))

	for _, name := range names {
		a, err := r.Get(ctx, name)
		if err != nil {
			return nil, err
		}
		analyzers = append(analyzers, a)
	}

	return analyzers, nil
}

// Close cleans up registry resources.
func (r *Registry) Close() error {
	r.mu.Lock()
	r.analyzers = make(map[string]MediaAnalyzer)
	r.configs = make(map[string]*AnalyzerConfig)
	r.mu.Unlock()

	r.logger.Println("Media registry closed")
	return nil
}

// RegistryError represents an error from registry operations.
type RegistryError struct {
	AnalyzerName string
	Code         string
	Message      string
	Cause        error
}

// Registry error codes.
const (
	ErrRegistryNotFound       = "registry_not_found"
	ErrRegistryDuplicate      = "registry_duplicate"
	ErrRegistryInvalidConfig  = "registry_invalid_config"
	ErrRegistryCreationFailed = "registry_creation_failed"
	ErrRegistryLicenseRequired = "registry_license_required"
	ErrRegistryAnalyzerLimit  = "registry_analyzer_limit"
)

// Error implements the error interface.
func (e *RegistryError) Error() string {
	if e.AnalyzerName != "" {
		return fmt.Sprintf("media registry error for %q: %s", e.AnalyzerName, e.Message)
	}
	return fmt.Sprintf("media registry error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *RegistryError) Unwrap() error {
	return e.Cause
}
