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
	"testing"
)

// testProviderFactory is a test factory that creates MockProvider instances.
func testProviderFactory(config ProviderConfig) (Provider, error) {
	if config.APIKey == "" && config.Type != ProviderTypeOllama && config.Type != ProviderTypeBedrock {
		return nil, errors.New("API key required")
	}
	provider := NewMockProvider(config.Name, config.Type)
	return provider, nil
}

// failingProviderFactory always returns an error.
func failingProviderFactory(config ProviderConfig) (Provider, error) {
	return nil, errors.New("factory always fails")
}

func TestRegisterFactory(t *testing.T) {
	// Clean up after test
	defer func() {
		UnregisterFactory(ProviderType("test-register"))
	}()

	providerType := ProviderType("test-register")

	// Verify not registered initially
	if HasFactory(providerType) {
		t.Error("factory should not exist before registration")
	}

	// Register factory
	RegisterFactory(providerType, testProviderFactory)

	// Verify registered
	if !HasFactory(providerType) {
		t.Error("factory should exist after registration")
	}

	// Verify factory is correct
	factory := GetFactory(providerType)
	if factory == nil {
		t.Fatal("GetFactory returned nil")
	}
}

func TestUnregisterFactory(t *testing.T) {
	providerType := ProviderType("test-unregister")

	// Register first
	RegisterFactory(providerType, testProviderFactory)
	if !HasFactory(providerType) {
		t.Fatal("factory should be registered")
	}

	// Unregister
	removed := UnregisterFactory(providerType)
	if !removed {
		t.Error("UnregisterFactory should return true when factory existed")
	}

	// Verify removed
	if HasFactory(providerType) {
		t.Error("factory should not exist after unregistration")
	}

	// Unregister again should return false
	removed = UnregisterFactory(providerType)
	if removed {
		t.Error("UnregisterFactory should return false when factory didn't exist")
	}
}

func TestGetFactory(t *testing.T) {
	// Clean up after test
	defer func() {
		UnregisterFactory(ProviderType("test-get"))
	}()

	t.Run("existing factory", func(t *testing.T) {
		providerType := ProviderType("test-get")
		RegisterFactory(providerType, testProviderFactory)

		factory := GetFactory(providerType)
		if factory == nil {
			t.Error("GetFactory should return factory for registered type")
		}
	})

	t.Run("non-existent factory", func(t *testing.T) {
		factory := GetFactory(ProviderType("non-existent"))
		if factory != nil {
			t.Error("GetFactory should return nil for unregistered type")
		}
	})
}

func TestHasFactory(t *testing.T) {
	// Clean up after test
	defer func() {
		UnregisterFactory(ProviderType("test-has"))
	}()

	providerType := ProviderType("test-has")

	// Not registered
	if HasFactory(providerType) {
		t.Error("HasFactory should return false for unregistered type")
	}

	// Register
	RegisterFactory(providerType, testProviderFactory)

	// Now registered
	if !HasFactory(providerType) {
		t.Error("HasFactory should return true for registered type")
	}
}

func TestListFactories(t *testing.T) {
	// Clean up after test
	defer func() {
		UnregisterFactory(ProviderType("test-list-1"))
		UnregisterFactory(ProviderType("test-list-2"))
	}()

	// Register some factories
	RegisterFactory(ProviderType("test-list-1"), testProviderFactory)
	RegisterFactory(ProviderType("test-list-2"), testProviderFactory)

	types := ListFactories()

	// Check that our test types are in the list
	found1 := false
	found2 := false
	for _, pt := range types {
		if pt == ProviderType("test-list-1") {
			found1 = true
		}
		if pt == ProviderType("test-list-2") {
			found2 = true
		}
	}

	if !found1 {
		t.Error("ListFactories should include test-list-1")
	}
	if !found2 {
		t.Error("ListFactories should include test-list-2")
	}
}

func TestCreateProvider(t *testing.T) {
	// Clean up after test
	defer func() {
		UnregisterFactory(ProviderType("test-create"))
	}()

	providerType := ProviderType("test-create")
	RegisterFactory(providerType, testProviderFactory)

	t.Run("successful creation", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "test-provider",
			Type:   providerType,
			APIKey: "test-key",
		}

		provider, err := CreateProvider(config)
		if err != nil {
			t.Fatalf("CreateProvider error = %v", err)
		}
		if provider == nil {
			t.Fatal("CreateProvider returned nil provider")
		}
		if provider.Name() != "test-provider" {
			t.Errorf("provider.Name() = %q, want %q", provider.Name(), "test-provider")
		}
	})

	t.Run("missing type", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "test-provider",
			APIKey: "test-key",
		}

		_, err := CreateProvider(config)
		if err == nil {
			t.Fatal("CreateProvider should error on missing type")
		}

		var factoryErr *FactoryError
		if !errors.As(err, &factoryErr) {
			t.Fatalf("expected FactoryError, got %T", err)
		}
		if factoryErr.Code != ErrFactoryMissingType {
			t.Errorf("error code = %q, want %q", factoryErr.Code, ErrFactoryMissingType)
		}
	})

	t.Run("unregistered type", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "test-provider",
			Type:   ProviderType("unregistered"),
			APIKey: "test-key",
		}

		_, err := CreateProvider(config)
		if err == nil {
			t.Fatal("CreateProvider should error on unregistered type")
		}

		var factoryErr *FactoryError
		if !errors.As(err, &factoryErr) {
			t.Fatalf("expected FactoryError, got %T", err)
		}
		if factoryErr.Code != ErrFactoryNotRegistered {
			t.Errorf("error code = %q, want %q", factoryErr.Code, ErrFactoryNotRegistered)
		}
	})

	t.Run("factory returns error", func(t *testing.T) {
		failType := ProviderType("test-fail")
		RegisterFactory(failType, failingProviderFactory)
		defer UnregisterFactory(failType)

		config := ProviderConfig{
			Name: "test-provider",
			Type: failType,
		}

		_, err := CreateProvider(config)
		if err == nil {
			t.Fatal("CreateProvider should error when factory fails")
		}

		var factoryErr *FactoryError
		if !errors.As(err, &factoryErr) {
			t.Fatalf("expected FactoryError, got %T", err)
		}
		if factoryErr.Code != ErrFactoryCreationFailed {
			t.Errorf("error code = %q, want %q", factoryErr.Code, ErrFactoryCreationFailed)
		}
	})
}

func TestMustCreateProvider(t *testing.T) {
	// Clean up after test
	defer func() {
		UnregisterFactory(ProviderType("test-must"))
	}()

	providerType := ProviderType("test-must")
	RegisterFactory(providerType, testProviderFactory)

	t.Run("successful creation", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "test-provider",
			Type:   providerType,
			APIKey: "test-key",
		}

		// Should not panic
		provider := MustCreateProvider(config)
		if provider == nil {
			t.Fatal("MustCreateProvider returned nil provider")
		}
	})

	t.Run("panics on error", func(t *testing.T) {
		config := ProviderConfig{
			Name: "test-provider",
			Type: ProviderType("unregistered"),
		}

		defer func() {
			if r := recover(); r == nil {
				t.Error("MustCreateProvider should panic on error")
			}
		}()

		MustCreateProvider(config)
	})
}

func TestFactoryError(t *testing.T) {
	t.Run("error with provider type", func(t *testing.T) {
		err := &FactoryError{
			ProviderType: ProviderTypeOpenAI,
			Code:         ErrFactoryCreationFailed,
			Message:      "test error",
		}

		errStr := err.Error()
		if errStr == "" {
			t.Error("Error() returned empty string")
		}
		// Should contain provider type
		if !containsString(errStr, string(ProviderTypeOpenAI)) {
			t.Error("Error() should contain provider type")
		}
	})

	t.Run("error without provider type", func(t *testing.T) {
		err := &FactoryError{
			Code:    ErrFactoryMissingType,
			Message: "test error",
		}

		errStr := err.Error()
		if errStr == "" {
			t.Error("Error() returned empty string")
		}
	})

	t.Run("unwrap cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &FactoryError{
			Code:    ErrFactoryCreationFailed,
			Message: "wrapper",
			Cause:   cause,
		}

		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  ProviderConfig
		wantErr bool
		errCode string
	}{
		{
			name: "valid OpenAI config",
			config: ProviderConfig{
				Name:   "openai-primary",
				Type:   ProviderTypeOpenAI,
				APIKey: "sk-test",
			},
			wantErr: false,
		},
		{
			name: "valid Anthropic config with secret ARN",
			config: ProviderConfig{
				Name:            "anthropic-primary",
				Type:            ProviderTypeAnthropic,
				APIKeySecretARN: "arn:aws:secretsmanager:...",
			},
			wantErr: false,
		},
		{
			name: "valid Bedrock config",
			config: ProviderConfig{
				Name:   "bedrock-primary",
				Type:   ProviderTypeBedrock,
				Region: "us-east-1",
			},
			wantErr: false,
		},
		{
			name: "valid Ollama config (no required fields)",
			config: ProviderConfig{
				Name: "ollama-local",
				Type: ProviderTypeOllama,
			},
			wantErr: false,
		},
		{
			name: "missing type",
			config: ProviderConfig{
				Name:   "test",
				APIKey: "test",
			},
			wantErr: true,
			errCode: ErrFactoryInvalidConfig,
		},
		{
			name: "missing name",
			config: ProviderConfig{
				Type:   ProviderTypeOpenAI,
				APIKey: "test",
			},
			wantErr: true,
			errCode: ErrFactoryInvalidConfig,
		},
		{
			name: "OpenAI missing API key",
			config: ProviderConfig{
				Name: "openai",
				Type: ProviderTypeOpenAI,
			},
			wantErr: true,
			errCode: ErrFactoryInvalidConfig,
		},
		{
			name: "Anthropic missing API key",
			config: ProviderConfig{
				Name: "anthropic",
				Type: ProviderTypeAnthropic,
			},
			wantErr: true,
			errCode: ErrFactoryInvalidConfig,
		},
		{
			name: "Bedrock missing region",
			config: ProviderConfig{
				Name: "bedrock",
				Type: ProviderTypeBedrock,
			},
			wantErr: true,
			errCode: ErrFactoryInvalidConfig,
		},
		{
			name: "invalid weight (negative)",
			config: ProviderConfig{
				Name:   "test",
				Type:   ProviderTypeOllama,
				Weight: -1,
			},
			wantErr: true,
			errCode: ErrFactoryInvalidConfig,
		},
		{
			name: "invalid weight (too high)",
			config: ProviderConfig{
				Name:   "test",
				Type:   ProviderTypeOllama,
				Weight: 101,
			},
			wantErr: true,
			errCode: ErrFactoryInvalidConfig,
		},
		{
			name: "invalid timeout",
			config: ProviderConfig{
				Name:           "test",
				Type:           ProviderTypeOllama,
				TimeoutSeconds: -1,
			},
			wantErr: true,
			errCode: ErrFactoryInvalidConfig,
		},
		{
			name: "invalid priority (negative)",
			config: ProviderConfig{
				Name:     "test",
				Type:     ProviderTypeOllama,
				Priority: -1,
			},
			wantErr: true,
			errCode: ErrFactoryInvalidConfig,
		},
		{
			name: "invalid rate limit (negative)",
			config: ProviderConfig{
				Name:      "test",
				Type:      ProviderTypeOllama,
				RateLimit: -1,
			},
			wantErr: true,
			errCode: ErrFactoryInvalidConfig,
		},
		{
			name: "valid config with all optional fields",
			config: ProviderConfig{
				Name:           "test",
				Type:           ProviderTypeOllama,
				Weight:         50,
				Priority:       100,
				RateLimit:      1000,
				TimeoutSeconds: 30,
			},
			wantErr: false,
		},
		{
			name: "custom provider (minimal validation)",
			config: ProviderConfig{
				Name: "custom",
				Type: ProviderTypeCustom,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Error("ValidateConfig should return error")
				}
				if tt.errCode != "" {
					var factoryErr *FactoryError
					if errors.As(err, &factoryErr) {
						if factoryErr.Code != tt.errCode {
							t.Errorf("error code = %q, want %q", factoryErr.Code, tt.errCode)
						}
					}
				}
			} else {
				if err != nil {
					t.Errorf("ValidateConfig error = %v", err)
				}
			}
		})
	}
}

func TestFactoryManager(t *testing.T) {
	t.Run("new manager is empty", func(t *testing.T) {
		m := NewFactoryManager()
		if m.Count() != 0 {
			t.Errorf("Count() = %d, want 0", m.Count())
		}
	})

	t.Run("register and get", func(t *testing.T) {
		m := NewFactoryManager()
		m.Register(ProviderTypeOpenAI, testProviderFactory)

		if !m.Has(ProviderTypeOpenAI) {
			t.Error("Has should return true after registration")
		}

		factory := m.Get(ProviderTypeOpenAI)
		if factory == nil {
			t.Error("Get should return factory after registration")
		}
	})

	t.Run("unregister", func(t *testing.T) {
		m := NewFactoryManager()
		m.Register(ProviderTypeOpenAI, testProviderFactory)

		removed := m.Unregister(ProviderTypeOpenAI)
		if !removed {
			t.Error("Unregister should return true when factory existed")
		}

		if m.Has(ProviderTypeOpenAI) {
			t.Error("Has should return false after unregistration")
		}
	})

	t.Run("list", func(t *testing.T) {
		m := NewFactoryManager()
		m.Register(ProviderTypeOpenAI, testProviderFactory)
		m.Register(ProviderTypeAnthropic, testProviderFactory)

		types := m.List()
		if len(types) != 2 {
			t.Errorf("List() length = %d, want 2", len(types))
		}
	})

	t.Run("create provider", func(t *testing.T) {
		m := NewFactoryManager()
		m.Register(ProviderTypeOpenAI, testProviderFactory)

		config := ProviderConfig{
			Name:   "test",
			Type:   ProviderTypeOpenAI,
			APIKey: "test-key",
		}

		provider, err := m.Create(config)
		if err != nil {
			t.Fatalf("Create error = %v", err)
		}
		if provider == nil {
			t.Fatal("Create returned nil provider")
		}
	})

	t.Run("create with missing type", func(t *testing.T) {
		m := NewFactoryManager()

		config := ProviderConfig{
			Name: "test",
		}

		_, err := m.Create(config)
		if err == nil {
			t.Error("Create should error on missing type")
		}
	})

	t.Run("create with unregistered type", func(t *testing.T) {
		m := NewFactoryManager()

		config := ProviderConfig{
			Name: "test",
			Type: ProviderTypeOpenAI,
		}

		_, err := m.Create(config)
		if err == nil {
			t.Error("Create should error on unregistered type")
		}
	})

	t.Run("copy from global", func(t *testing.T) {
		// Register in global
		RegisterFactory(ProviderType("test-copy-global"), testProviderFactory)
		defer UnregisterFactory(ProviderType("test-copy-global"))

		m := NewFactoryManager()
		m.CopyFromGlobal()

		if !m.Has(ProviderType("test-copy-global")) {
			t.Error("CopyFromGlobal should copy factory from global registry")
		}
	})

	t.Run("clear", func(t *testing.T) {
		m := NewFactoryManager()
		m.Register(ProviderTypeOpenAI, testProviderFactory)
		m.Register(ProviderTypeAnthropic, testProviderFactory)

		m.Clear()

		if m.Count() != 0 {
			t.Errorf("Count() after Clear() = %d, want 0", m.Count())
		}
	})
}

func TestFactoryManager_Concurrency(t *testing.T) {
	m := NewFactoryManager()

	// Run concurrent operations
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			m.Register(ProviderType("test"), testProviderFactory)
			m.Unregister(ProviderType("test"))
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			m.Has(ProviderType("test"))
			m.Get(ProviderType("test"))
			m.List()
			m.Count()
		}
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done
}

// containsString checks if a string contains a substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStringHelper(s, substr))
}

func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Ensure MockProvider implements Provider interface for factory tests.
var _ Provider = (*MockProvider)(nil)

// MockProvider already defined in provider_test.go, but we need to ensure
// it's available for factory tests. The tests will use the same mock.

func TestCreateProviderIntegration(t *testing.T) {
	// Clean up after test
	defer func() {
		UnregisterFactory(ProviderTypeOpenAI)
		UnregisterFactory(ProviderTypeAnthropic)
		UnregisterFactory(ProviderTypeOllama)
	}()

	// Register test factories
	RegisterFactory(ProviderTypeOpenAI, testProviderFactory)
	RegisterFactory(ProviderTypeAnthropic, testProviderFactory)
	RegisterFactory(ProviderTypeOllama, func(config ProviderConfig) (Provider, error) {
		// Ollama doesn't require API key
		return NewMockProvider(config.Name, config.Type), nil
	})

	t.Run("create OpenAI provider", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "openai-primary",
			Type:   ProviderTypeOpenAI,
			APIKey: "sk-test",
			Model:  "gpt-4",
		}

		provider, err := CreateProvider(config)
		if err != nil {
			t.Fatalf("CreateProvider error = %v", err)
		}
		if provider.Type() != ProviderTypeOpenAI {
			t.Errorf("Type() = %v, want %v", provider.Type(), ProviderTypeOpenAI)
		}
	})

	t.Run("create Anthropic provider", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "anthropic-primary",
			Type:   ProviderTypeAnthropic,
			APIKey: "sk-ant-test",
			Model:  "claude-3-5-sonnet-20241022",
		}

		provider, err := CreateProvider(config)
		if err != nil {
			t.Fatalf("CreateProvider error = %v", err)
		}
		if provider.Type() != ProviderTypeAnthropic {
			t.Errorf("Type() = %v, want %v", provider.Type(), ProviderTypeAnthropic)
		}
	})

	t.Run("create Ollama provider", func(t *testing.T) {
		config := ProviderConfig{
			Name:     "ollama-local",
			Type:     ProviderTypeOllama,
			Endpoint: "http://localhost:11434",
			Model:    "llama3.1",
		}

		provider, err := CreateProvider(config)
		if err != nil {
			t.Fatalf("CreateProvider error = %v", err)
		}
		if provider.Type() != ProviderTypeOllama {
			t.Errorf("Type() = %v, want %v", provider.Type(), ProviderTypeOllama)
		}
	})

	t.Run("use provider after creation", func(t *testing.T) {
		config := ProviderConfig{
			Name:   "test-provider",
			Type:   ProviderTypeOpenAI,
			APIKey: "test-key",
		}

		provider, err := CreateProvider(config)
		if err != nil {
			t.Fatalf("CreateProvider error = %v", err)
		}

		// Test provider methods
		ctx := context.Background()
		req := CompletionRequest{Prompt: "Hello"}

		resp, err := provider.Complete(ctx, req)
		if err != nil {
			t.Fatalf("Complete error = %v", err)
		}
		if resp == nil {
			t.Fatal("Complete returned nil response")
		}
	})
}
