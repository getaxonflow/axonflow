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
	"errors"
	"log"
	"os"
	"sync"
	"testing"
)

// mockStorage implements Storage for testing.
type mockStorage struct {
	providers map[string]*ProviderConfig
	mu        sync.RWMutex
	saveErr   error
	getErr    error
	deleteErr error
	listErr   error
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		providers: make(map[string]*ProviderConfig),
	}
}

func (s *mockStorage) SaveProvider(ctx context.Context, config *ProviderConfig) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	configCopy := *config
	s.providers[config.Name] = &configCopy
	return nil
}

func (s *mockStorage) GetProvider(ctx context.Context, name string) (*ProviderConfig, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	config, ok := s.providers[name]
	if !ok {
		return nil, errors.New("provider not found")
	}
	configCopy := *config
	return &configCopy, nil
}

func (s *mockStorage) DeleteProvider(ctx context.Context, name string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.providers, name)
	return nil
}

func (s *mockStorage) ListProviders(ctx context.Context, orgID string) ([]string, error) {
	return s.ListAllProviders(ctx)
}

func (s *mockStorage) ListAllProviders(ctx context.Context) ([]string, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.providers))
	for name := range s.providers {
		names = append(names, name)
	}
	return names, nil
}

func setupTestRegistry(t *testing.T) *Registry {
	// Create factory manager with test factory
	fm := NewFactoryManager()
	fm.Register(ProviderTypeOpenAI, func(config ProviderConfig) (Provider, error) {
		return NewMockProvider(config.Name, config.Type), nil
	})
	fm.Register(ProviderTypeAnthropic, func(config ProviderConfig) (Provider, error) {
		return NewMockProvider(config.Name, config.Type), nil
	})
	fm.Register(ProviderTypeOllama, func(config ProviderConfig) (Provider, error) {
		return NewMockProvider(config.Name, config.Type), nil
	})

	return NewRegistry(WithFactoryManager(fm))
}

func TestNewRegistry(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		r := NewRegistry()
		if r == nil {
			t.Fatal("NewRegistry returned nil")
		}
		if r.logger == nil {
			t.Error("logger should not be nil")
		}
		if r.factory == nil {
			t.Error("factory should not be nil")
		}
	})

	t.Run("with storage", func(t *testing.T) {
		storage := newMockStorage()
		r := NewRegistry(WithStorage(storage))
		if r.storage == nil {
			t.Error("storage should be set")
		}
	})

	t.Run("with factory manager", func(t *testing.T) {
		fm := NewFactoryManager()
		r := NewRegistry(WithFactoryManager(fm))
		if r.factory != fm {
			t.Error("factory manager should be the provided one")
		}
	})
}

func TestRegistry_Register(t *testing.T) {
	ctx := context.Background()

	t.Run("successful registration", func(t *testing.T) {
		r := setupTestRegistry(t)
		config := &ProviderConfig{
			Name:   "test-provider",
			Type:   ProviderTypeOllama,
			Enabled: true,
		}

		err := r.Register(ctx, config)
		if err != nil {
			t.Fatalf("Register error = %v", err)
		}

		if !r.Has("test-provider") {
			t.Error("provider should be registered")
		}
	})

	t.Run("nil config", func(t *testing.T) {
		r := setupTestRegistry(t)
		err := r.Register(ctx, nil)
		if err == nil {
			t.Fatal("Register should error on nil config")
		}
	})

	t.Run("empty name", func(t *testing.T) {
		r := setupTestRegistry(t)
		config := &ProviderConfig{
			Type: ProviderTypeOllama,
		}

		err := r.Register(ctx, config)
		if err == nil {
			t.Fatal("Register should error on empty name")
		}
	})

	t.Run("duplicate registration", func(t *testing.T) {
		r := setupTestRegistry(t)
		config := &ProviderConfig{
			Name: "test-provider",
			Type: ProviderTypeOllama,
		}

		err := r.Register(ctx, config)
		if err != nil {
			t.Fatalf("first Register error = %v", err)
		}

		err = r.Register(ctx, config)
		if err == nil {
			t.Fatal("second Register should error")
		}

		var regErr *RegistryError
		if !errors.As(err, &regErr) {
			t.Fatalf("expected RegistryError, got %T", err)
		}
		if regErr.Code != ErrRegistryDuplicate {
			t.Errorf("error code = %q, want %q", regErr.Code, ErrRegistryDuplicate)
		}
	})

	t.Run("with storage", func(t *testing.T) {
		storage := newMockStorage()
		fm := NewFactoryManager()
		fm.Register(ProviderTypeOllama, func(config ProviderConfig) (Provider, error) {
			return NewMockProvider(config.Name, config.Type), nil
		})
		r := NewRegistry(WithStorage(storage), WithFactoryManager(fm))

		config := &ProviderConfig{
			Name: "test-provider",
			Type: ProviderTypeOllama,
		}

		err := r.Register(ctx, config)
		if err != nil {
			t.Fatalf("Register error = %v", err)
		}

		// Check storage
		_, err = storage.GetProvider(ctx, "test-provider")
		if err != nil {
			t.Error("provider should be in storage")
		}
	})

	t.Run("storage error rolls back", func(t *testing.T) {
		storage := newMockStorage()
		storage.saveErr = errors.New("storage error")
		fm := NewFactoryManager()
		fm.Register(ProviderTypeOllama, func(config ProviderConfig) (Provider, error) {
			return NewMockProvider(config.Name, config.Type), nil
		})
		r := NewRegistry(WithStorage(storage), WithFactoryManager(fm))

		config := &ProviderConfig{
			Name: "test-provider",
			Type: ProviderTypeOllama,
		}

		err := r.Register(ctx, config)
		if err == nil {
			t.Fatal("Register should error when storage fails")
		}

		// Should not be registered in memory
		if r.Has("test-provider") {
			t.Error("provider should not be registered after storage error")
		}
	})

	t.Run("license gating allows OSS providers", func(t *testing.T) {
		// OSS validator allows Ollama, OpenAI, Anthropic
		r := NewRegistry(WithLicenseValidator(NewOSSLicenseValidator()))
		r.factory.Register(ProviderTypeOllama, func(config ProviderConfig) (Provider, error) {
			return NewMockProvider(config.Name, config.Type), nil
		})

		config := &ProviderConfig{
			Name: "ollama-test",
			Type: ProviderTypeOllama,
		}

		err := r.Register(ctx, config)
		if err != nil {
			t.Errorf("OSS provider should be allowed: %v", err)
		}
	})

	t.Run("license gating blocks enterprise providers in OSS mode", func(t *testing.T) {
		// OSS validator should block Bedrock, Gemini, Custom
		r := NewRegistry(WithLicenseValidator(NewOSSLicenseValidator()))
		r.factory.Register(ProviderTypeBedrock, func(config ProviderConfig) (Provider, error) {
			return NewMockProvider(config.Name, config.Type), nil
		})

		config := &ProviderConfig{
			Name:   "bedrock-test",
			Type:   ProviderTypeBedrock,
			Region: "us-east-1",
		}

		err := r.Register(ctx, config)
		if err == nil {
			t.Fatal("Enterprise provider should be blocked in OSS mode")
		}

		var regErr *RegistryError
		if !errors.As(err, &regErr) {
			t.Fatalf("expected RegistryError, got %T", err)
		}
		if regErr.Code != ErrRegistryLicenseRequired {
			t.Errorf("error code = %q, want %q", regErr.Code, ErrRegistryLicenseRequired)
		}
	})
}

func TestRegistry_RegisterProvider(t *testing.T) {
	t.Run("successful registration", func(t *testing.T) {
		r := setupTestRegistry(t)
		provider := NewMockProvider("test-provider", ProviderTypeOpenAI)
		config := &ProviderConfig{
			Name:   "test-provider",
			Type:   ProviderTypeOpenAI,
			APIKey: "test-key",
		}

		err := r.RegisterProvider("test-provider", provider, config)
		if err != nil {
			t.Fatalf("RegisterProvider error = %v", err)
		}

		if !r.Has("test-provider") {
			t.Error("provider should be registered")
		}
	})

	t.Run("nil provider", func(t *testing.T) {
		r := setupTestRegistry(t)
		err := r.RegisterProvider("test", nil, nil)
		if err == nil {
			t.Fatal("RegisterProvider should error on nil provider")
		}
	})

	t.Run("empty name", func(t *testing.T) {
		r := setupTestRegistry(t)
		provider := NewMockProvider("test", ProviderTypeOpenAI)
		err := r.RegisterProvider("", provider, nil)
		if err == nil {
			t.Fatal("RegisterProvider should error on empty name")
		}
	})
}

func TestRegistry_Get(t *testing.T) {
	ctx := context.Background()

	t.Run("get instantiated provider", func(t *testing.T) {
		r := setupTestRegistry(t)
		provider := NewMockProvider("test-provider", ProviderTypeOpenAI)
		_ = r.RegisterProvider("test-provider", provider, nil)

		got, err := r.Get(ctx, "test-provider")
		if err != nil {
			t.Fatalf("Get error = %v", err)
		}
		if got != provider {
			t.Error("Get should return the registered provider")
		}
	})

	t.Run("lazy instantiation", func(t *testing.T) {
		r := setupTestRegistry(t)
		config := &ProviderConfig{
			Name: "lazy-provider",
			Type: ProviderTypeOllama,
		}
		_ = r.Register(ctx, config)

		// Should not be instantiated yet
		if r.CountInstantiated() != 0 {
			t.Error("provider should not be instantiated before Get")
		}

		provider, err := r.Get(ctx, "lazy-provider")
		if err != nil {
			t.Fatalf("Get error = %v", err)
		}
		if provider == nil {
			t.Fatal("Get returned nil provider")
		}

		// Should be instantiated now
		if r.CountInstantiated() != 1 {
			t.Error("provider should be instantiated after Get")
		}
	})

	t.Run("provider not found", func(t *testing.T) {
		r := setupTestRegistry(t)
		_, err := r.Get(ctx, "non-existent")
		if err == nil {
			t.Fatal("Get should error for non-existent provider")
		}

		var regErr *RegistryError
		if !errors.As(err, &regErr) {
			t.Fatalf("expected RegistryError, got %T", err)
		}
		if regErr.Code != ErrRegistryNotFound {
			t.Errorf("error code = %q, want %q", regErr.Code, ErrRegistryNotFound)
		}
	})
}

func TestRegistry_Unregister(t *testing.T) {
	ctx := context.Background()

	t.Run("successful unregistration", func(t *testing.T) {
		r := setupTestRegistry(t)
		config := &ProviderConfig{
			Name: "test-provider",
			Type: ProviderTypeOllama,
		}
		_ = r.Register(ctx, config)

		err := r.Unregister(ctx, "test-provider")
		if err != nil {
			t.Fatalf("Unregister error = %v", err)
		}

		if r.Has("test-provider") {
			t.Error("provider should not exist after unregister")
		}
	})

	t.Run("unregister non-existent", func(t *testing.T) {
		r := setupTestRegistry(t)
		err := r.Unregister(ctx, "non-existent")
		if err == nil {
			t.Fatal("Unregister should error for non-existent provider")
		}
	})
}

func TestRegistry_List(t *testing.T) {
	ctx := context.Background()
	r := setupTestRegistry(t)

	// Register some providers
	_ = r.Register(ctx, &ProviderConfig{Name: "provider-a", Type: ProviderTypeOllama})
	_ = r.Register(ctx, &ProviderConfig{Name: "provider-b", Type: ProviderTypeOllama})
	_ = r.Register(ctx, &ProviderConfig{Name: "provider-c", Type: ProviderTypeOllama})

	names := r.List()
	if len(names) != 3 {
		t.Errorf("List() length = %d, want 3", len(names))
	}

	// Should be sorted
	if names[0] != "provider-a" || names[1] != "provider-b" || names[2] != "provider-c" {
		t.Errorf("List() = %v, want sorted order", names)
	}
}

func TestRegistry_ListEnabled(t *testing.T) {
	ctx := context.Background()
	r := setupTestRegistry(t)

	_ = r.Register(ctx, &ProviderConfig{Name: "enabled-1", Type: ProviderTypeOllama, Enabled: true})
	_ = r.Register(ctx, &ProviderConfig{Name: "disabled", Type: ProviderTypeOllama, Enabled: false})
	_ = r.Register(ctx, &ProviderConfig{Name: "enabled-2", Type: ProviderTypeOllama, Enabled: true})

	names := r.ListEnabled()
	if len(names) != 2 {
		t.Errorf("ListEnabled() length = %d, want 2", len(names))
	}
}

func TestRegistry_ListByType(t *testing.T) {
	ctx := context.Background()
	r := setupTestRegistry(t)

	_ = r.Register(ctx, &ProviderConfig{Name: "openai-1", Type: ProviderTypeOpenAI, APIKey: "key"})
	_ = r.Register(ctx, &ProviderConfig{Name: "ollama-1", Type: ProviderTypeOllama})
	_ = r.Register(ctx, &ProviderConfig{Name: "openai-2", Type: ProviderTypeOpenAI, APIKey: "key"})

	openaiProviders := r.ListByType(ProviderTypeOpenAI)
	if len(openaiProviders) != 2 {
		t.Errorf("ListByType(OpenAI) length = %d, want 2", len(openaiProviders))
	}

	ollamaProviders := r.ListByType(ProviderTypeOllama)
	if len(ollamaProviders) != 1 {
		t.Errorf("ListByType(Ollama) length = %d, want 1", len(ollamaProviders))
	}
}

func TestRegistry_Count(t *testing.T) {
	ctx := context.Background()
	r := setupTestRegistry(t)

	if r.Count() != 0 {
		t.Errorf("Count() = %d, want 0", r.Count())
	}

	_ = r.Register(ctx, &ProviderConfig{Name: "provider-1", Type: ProviderTypeOllama})
	_ = r.Register(ctx, &ProviderConfig{Name: "provider-2", Type: ProviderTypeOllama})

	if r.Count() != 2 {
		t.Errorf("Count() = %d, want 2", r.Count())
	}
}

func TestRegistry_GetConfig(t *testing.T) {
	ctx := context.Background()
	r := setupTestRegistry(t)

	config := &ProviderConfig{
		Name:   "test-provider",
		Type:   ProviderTypeOllama,
		Model:  "llama3.1",
		Weight: 50,
	}
	_ = r.Register(ctx, config)

	t.Run("get existing config", func(t *testing.T) {
		got, err := r.GetConfig("test-provider")
		if err != nil {
			t.Fatalf("GetConfig error = %v", err)
		}
		if got.Name != config.Name {
			t.Errorf("Name = %q, want %q", got.Name, config.Name)
		}
		if got.Model != config.Model {
			t.Errorf("Model = %q, want %q", got.Model, config.Model)
		}
	})

	t.Run("get non-existent config", func(t *testing.T) {
		_, err := r.GetConfig("non-existent")
		if err == nil {
			t.Fatal("GetConfig should error for non-existent provider")
		}
	})
}

func TestRegistry_HealthCheck(t *testing.T) {
	ctx := context.Background()
	r := setupTestRegistry(t)

	// Register and instantiate providers
	provider1 := NewMockProvider("provider-1", ProviderTypeOpenAI)
	provider1.healthStatus = HealthStatusHealthy
	_ = r.RegisterProvider("provider-1", provider1, nil)

	provider2 := NewMockProvider("provider-2", ProviderTypeOpenAI)
	provider2.healthStatus = HealthStatusUnhealthy
	_ = r.RegisterProvider("provider-2", provider2, nil)

	results := r.HealthCheck(ctx)
	if len(results) != 2 {
		t.Fatalf("HealthCheck returned %d results, want 2", len(results))
	}

	if results["provider-1"].Status != HealthStatusHealthy {
		t.Errorf("provider-1 status = %v, want %v", results["provider-1"].Status, HealthStatusHealthy)
	}
	if results["provider-2"].Status != HealthStatusUnhealthy {
		t.Errorf("provider-2 status = %v, want %v", results["provider-2"].Status, HealthStatusUnhealthy)
	}
}

func TestRegistry_GetHealthyProviders(t *testing.T) {
	ctx := context.Background()
	r := setupTestRegistry(t)

	// Register and instantiate providers
	provider1 := NewMockProvider("healthy-1", ProviderTypeOpenAI)
	provider1.healthStatus = HealthStatusHealthy
	_ = r.RegisterProvider("healthy-1", provider1, nil)

	provider2 := NewMockProvider("unhealthy", ProviderTypeOpenAI)
	provider2.healthStatus = HealthStatusUnhealthy
	_ = r.RegisterProvider("unhealthy", provider2, nil)

	provider3 := NewMockProvider("healthy-2", ProviderTypeOpenAI)
	provider3.healthStatus = HealthStatusHealthy
	_ = r.RegisterProvider("healthy-2", provider3, nil)

	// Run health check to populate results
	r.HealthCheck(ctx)

	healthy := r.GetHealthyProviders()
	if len(healthy) != 2 {
		t.Errorf("GetHealthyProviders() length = %d, want 2", len(healthy))
	}
}

func TestRegistry_ReloadFromStorage(t *testing.T) {
	ctx := context.Background()

	t.Run("reload new providers", func(t *testing.T) {
		storage := newMockStorage()
		// Pre-populate storage
		storage.providers["provider-1"] = &ProviderConfig{Name: "provider-1", Type: ProviderTypeOllama}
		storage.providers["provider-2"] = &ProviderConfig{Name: "provider-2", Type: ProviderTypeOllama}

		fm := NewFactoryManager()
		fm.Register(ProviderTypeOllama, func(config ProviderConfig) (Provider, error) {
			return NewMockProvider(config.Name, config.Type), nil
		})

		r := NewRegistry(WithStorage(storage), WithFactoryManager(fm))

		err := r.ReloadFromStorage(ctx)
		if err != nil {
			t.Fatalf("ReloadFromStorage error = %v", err)
		}

		if r.Count() != 2 {
			t.Errorf("Count() = %d, want 2", r.Count())
		}
	})

	t.Run("no storage configured", func(t *testing.T) {
		r := setupTestRegistry(t)
		err := r.ReloadFromStorage(ctx)
		if err != nil {
			t.Errorf("ReloadFromStorage should not error without storage: %v", err)
		}
	})
}

func TestRegistry_Close(t *testing.T) {
	ctx := context.Background()
	r := setupTestRegistry(t)

	_ = r.Register(ctx, &ProviderConfig{Name: "provider-1", Type: ProviderTypeOllama})
	_ = r.Register(ctx, &ProviderConfig{Name: "provider-2", Type: ProviderTypeOllama})

	err := r.Close()
	if err != nil {
		t.Fatalf("Close error = %v", err)
	}

	if r.Count() != 0 {
		t.Errorf("Count() after Close() = %d, want 0", r.Count())
	}
}

func TestRegistry_Concurrency(t *testing.T) {
	ctx := context.Background()
	r := setupTestRegistry(t)

	var wg sync.WaitGroup

	// Concurrent registrations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			config := &ProviderConfig{
				Name: string(rune('a' + n)),
				Type: ProviderTypeOllama,
			}
			_ = r.Register(ctx, config)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.List()
			_ = r.Count()
			_ = r.ListEnabled()
		}()
	}

	wg.Wait()

	// Should have registered some providers
	if r.Count() == 0 {
		t.Error("some providers should be registered")
	}
}

func TestRegistryError(t *testing.T) {
	t.Run("error with provider name", func(t *testing.T) {
		err := &RegistryError{
			ProviderName: "test-provider",
			Code:         ErrRegistryNotFound,
			Message:      "provider not found",
		}

		errStr := err.Error()
		if errStr == "" {
			t.Error("Error() returned empty string")
		}
	})

	t.Run("error without provider name", func(t *testing.T) {
		err := &RegistryError{
			Code:    ErrRegistryInvalidConfig,
			Message: "config is nil",
		}

		errStr := err.Error()
		if errStr == "" {
			t.Error("Error() returned empty string")
		}
	})

	t.Run("unwrap cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &RegistryError{
			Code:    ErrRegistryStorageError,
			Message: "storage failed",
			Cause:   cause,
		}

		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})
}

func TestRegistry_HealthCheckSingle(t *testing.T) {
	ctx := context.Background()
	r := setupTestRegistry(t)

	t.Run("healthy provider", func(t *testing.T) {
		provider := NewMockProvider("test-provider", ProviderTypeOpenAI)
		provider.healthStatus = HealthStatusHealthy
		_ = r.RegisterProvider("test-provider", provider, nil)

		result, err := r.HealthCheckSingle(ctx, "test-provider")
		if err != nil {
			t.Fatalf("HealthCheckSingle error = %v", err)
		}
		if result.Status != HealthStatusHealthy {
			t.Errorf("status = %v, want %v", result.Status, HealthStatusHealthy)
		}
	})

	t.Run("non-existent provider", func(t *testing.T) {
		_, err := r.HealthCheckSingle(ctx, "non-existent")
		if err == nil {
			t.Fatal("HealthCheckSingle should error for non-existent provider")
		}
	})
}

func TestRegistry_GetHealthResult(t *testing.T) {
	ctx := context.Background()
	r := setupTestRegistry(t)

	provider := NewMockProvider("test-provider", ProviderTypeOpenAI)
	provider.healthStatus = HealthStatusHealthy
	_ = r.RegisterProvider("test-provider", provider, nil)

	t.Run("no cached result", func(t *testing.T) {
		result := r.GetHealthResult("test-provider")
		if result != nil {
			t.Error("expected nil for uncached result")
		}
	})

	t.Run("after health check", func(t *testing.T) {
		r.HealthCheck(ctx)
		result := r.GetHealthResult("test-provider")
		if result == nil {
			t.Fatal("expected cached result after health check")
		}
		if result.Status != HealthStatusHealthy {
			t.Errorf("status = %v, want %v", result.Status, HealthStatusHealthy)
		}
	})
}

func TestRegistry_CountWithPreInstantiatedProvider(t *testing.T) {
	r := setupTestRegistry(t)

	// Register provider without config
	provider := NewMockProvider("no-config-provider", ProviderTypeOpenAI)
	_ = r.RegisterProvider("no-config-provider", provider, nil)

	if r.Count() != 1 {
		t.Errorf("Count() = %d, want 1 for pre-instantiated provider without config", r.Count())
	}
}

func TestRegistry_WithLogger(t *testing.T) {
	// Use custom logger
	customLogger := log.New(os.Stdout, "[CUSTOM] ", log.LstdFlags)
	r := NewRegistry(WithLogger(customLogger))

	if r.logger != customLogger {
		t.Error("custom logger should be set")
	}
}

func TestRegistry_HealthCheckWithError(t *testing.T) {
	ctx := context.Background()
	r := setupTestRegistry(t)

	// Register provider that returns error on health check
	provider := NewMockProvider("error-provider", ProviderTypeOpenAI)
	provider.healthCheckErr = errors.New("health check failed")
	_ = r.RegisterProvider("error-provider", provider, nil)

	results := r.HealthCheck(ctx)
	result := results["error-provider"]
	if result == nil {
		t.Fatal("expected result even for error")
	}
	if result.Status != HealthStatusUnhealthy {
		t.Errorf("status = %v, want %v", result.Status, HealthStatusUnhealthy)
	}
	if result.Message != "health check failed" {
		t.Errorf("message = %q, want %q", result.Message, "health check failed")
	}
}

func TestRegistry_FactoryCreationError(t *testing.T) {
	ctx := context.Background()

	// Create registry with factory that fails
	fm := NewFactoryManager()
	fm.Register(ProviderTypeOllama, func(config ProviderConfig) (Provider, error) {
		return nil, errors.New("factory error")
	})
	r := NewRegistry(WithFactoryManager(fm))

	config := &ProviderConfig{
		Name: "fail-provider",
		Type: ProviderTypeOllama,
	}
	_ = r.Register(ctx, config)

	// Get should fail when factory fails
	_, err := r.Get(ctx, "fail-provider")
	if err == nil {
		t.Fatal("Get should error when factory fails")
	}

	var regErr *RegistryError
	if !errors.As(err, &regErr) {
		t.Fatalf("expected RegistryError, got %T", err)
	}
	if regErr.Code != ErrRegistryCreationFailed {
		t.Errorf("error code = %q, want %q", regErr.Code, ErrRegistryCreationFailed)
	}
}

func TestRegistry_StorageListError(t *testing.T) {
	ctx := context.Background()

	storage := newMockStorage()
	storage.listErr = errors.New("list failed")

	fm := NewFactoryManager()
	r := NewRegistry(WithStorage(storage), WithFactoryManager(fm))

	err := r.ReloadFromStorage(ctx)
	if err == nil {
		t.Fatal("ReloadFromStorage should error when storage.ListAllProviders fails")
	}
}
