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
	"strconv"
	"strings"
	"time"
)

// Environment variable names for provider configuration.
const (
	// Anthropic environment variables
	EnvAnthropicAPIKey      = "ANTHROPIC_API_KEY"
	EnvAnthropicModel       = "ANTHROPIC_MODEL"
	EnvAnthropicEndpoint    = "ANTHROPIC_ENDPOINT"
	EnvAnthropicTimeout     = "ANTHROPIC_TIMEOUT_SECONDS"

	// OpenAI environment variables
	EnvOpenAIAPIKey   = "OPENAI_API_KEY"
	EnvOpenAIModel    = "OPENAI_MODEL"
	EnvOpenAIEndpoint = "OPENAI_ENDPOINT"
	EnvOpenAITimeout  = "OPENAI_TIMEOUT_SECONDS"

	// Ollama environment variables
	EnvOllamaEndpoint = "OLLAMA_ENDPOINT"
	EnvOllamaModel    = "OLLAMA_MODEL"
	EnvOllamaTimeout  = "OLLAMA_TIMEOUT_SECONDS"

	// Google Gemini environment variables
	EnvGoogleAPIKey   = "GOOGLE_API_KEY"
	EnvGoogleModel    = "GOOGLE_MODEL"
	EnvGoogleEndpoint = "GOOGLE_ENDPOINT"
	EnvGoogleTimeout  = "GOOGLE_TIMEOUT_SECONDS"

	// AWS Bedrock environment variables (Enterprise)
	EnvBedrockRegion = "BEDROCK_REGION"
	EnvBedrockModel  = "BEDROCK_MODEL"

	// General configuration
	EnvLLMDefaultProvider = "LLM_DEFAULT_PROVIDER"
	EnvLLMProviders       = "LLM_PROVIDERS"
)

// BootstrapConfig contains configuration for the bootstrap process.
type BootstrapConfig struct {
	// Logger is the logger to use for bootstrap messages.
	// If nil, a default logger is created.
	Logger *log.Logger

	// Registry is the registry to populate with providers.
	// If nil, a new registry is created.
	Registry *Registry

	// SkipHealthCheck skips initial health check during bootstrap.
	SkipHealthCheck bool

	// HealthCheckTimeout is the timeout for health checks.
	// If 0, defaults to 10 seconds.
	HealthCheckTimeout time.Duration

	// EnabledProviders limits which providers are bootstrapped.
	// If empty, all detected providers are bootstrapped.
	EnabledProviders []ProviderType

	// DefaultWeights sets default routing weights for providers.
	// If nil, equal weights are used.
	DefaultWeights map[ProviderType]float64
}

// BootstrapResult contains the result of the bootstrap process.
type BootstrapResult struct {
	// Registry is the populated registry.
	Registry *Registry

	// ProvidersBootstrapped lists the providers that were successfully bootstrapped.
	ProvidersBootstrapped []string

	// ProvidersFailed lists the providers that failed to bootstrap with their errors.
	ProvidersFailed map[string]error

	// Warnings contains non-fatal warnings from the bootstrap process.
	Warnings []string

	// DefaultProvider is the name of the default provider (if any).
	DefaultProvider string
}

// BootstrapFromEnv bootstraps LLM providers from environment variables.
// This is the primary entry point for initializing the LLM system.
//
// Environment variables:
//   - ANTHROPIC_API_KEY: Anthropic API key (enables Anthropic provider)
//   - ANTHROPIC_MODEL: Default Anthropic model (optional)
//   - ANTHROPIC_ENDPOINT: Custom Anthropic endpoint (optional)
//   - OPENAI_API_KEY: OpenAI API key (enables OpenAI provider)
//   - OPENAI_MODEL: Default OpenAI model (optional)
//   - OPENAI_ENDPOINT: Custom OpenAI endpoint (optional)
//   - OLLAMA_ENDPOINT: Ollama endpoint (enables Ollama provider)
//   - OLLAMA_MODEL: Default Ollama model (optional)
//   - GOOGLE_API_KEY: Google API key (enables Gemini provider)
//   - GOOGLE_MODEL: Default Gemini model (optional)
//   - BEDROCK_REGION: AWS Bedrock region (enables Bedrock provider, Enterprise only)
//   - BEDROCK_MODEL: Default Bedrock model (optional)
//   - LLM_DEFAULT_PROVIDER: Name of the default provider
//   - LLM_PROVIDERS: Comma-separated list of enabled providers (optional filter)
func BootstrapFromEnv(cfg *BootstrapConfig) (*BootstrapResult, error) {
	if cfg == nil {
		cfg = &BootstrapConfig{}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stdout, "[LLM_BOOTSTRAP] ", log.LstdFlags)
	}

	registry := cfg.Registry
	if registry == nil {
		registry = NewRegistry(WithLogger(logger))
	}

	healthTimeout := cfg.HealthCheckTimeout
	if healthTimeout == 0 {
		healthTimeout = 10 * time.Second
	}

	result := &BootstrapResult{
		Registry:        registry,
		ProvidersFailed: make(map[string]error),
	}

	// Check for enabled providers filter from environment
	enabledFilter := cfg.EnabledProviders
	if len(enabledFilter) == 0 {
		if envProviders := os.Getenv(EnvLLMProviders); envProviders != "" {
			for _, p := range strings.Split(envProviders, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					enabledFilter = append(enabledFilter, ProviderType(p))
				}
			}
		}
	}

	// Bootstrap each provider type
	providers := []struct {
		name      string
		ptype     ProviderType
		bootstrap func() (*ProviderConfig, error)
	}{
		{"anthropic", ProviderTypeAnthropic, bootstrapAnthropic},
		{"openai", ProviderTypeOpenAI, bootstrapOpenAI},
		{"ollama", ProviderTypeOllama, bootstrapOllama},
		{"gemini", ProviderTypeGemini, bootstrapGemini},
	}

	ctx := context.Background()

	for _, p := range providers {
		// Check if this provider is enabled
		if len(enabledFilter) > 0 && !containsProviderType(enabledFilter, p.ptype) {
			logger.Printf("Skipping %s (not in enabled list)", p.name)
			continue
		}

		// Try to bootstrap the provider
		config, err := p.bootstrap()
		if err != nil {
			logger.Printf("Skipping %s: %v", p.name, err)
			continue
		}

		if config == nil {
			logger.Printf("Skipping %s: not configured", p.name)
			continue
		}

		// Set priority and weight from defaults
		if cfg.DefaultWeights != nil {
			if w, ok := cfg.DefaultWeights[p.ptype]; ok {
				config.Weight = int(w * 100)
			}
		}

		// Register the provider
		if err := registry.Register(ctx, config); err != nil {
			result.ProvidersFailed[p.name] = err
			logger.Printf("Failed to register %s: %v", p.name, err)
			continue
		}

		// Perform initial health check unless skipped
		if !cfg.SkipHealthCheck {
			healthCtx, cancel := context.WithTimeout(ctx, healthTimeout)
			healthResult, err := registry.HealthCheckSingle(healthCtx, config.Name)
			cancel()

			if err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("%s: health check failed: %v", p.name, err))
			} else if healthResult.Status != HealthStatusHealthy {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("%s: health check status: %s (%s)",
						p.name, healthResult.Status, healthResult.Message))
			}
		}

		result.ProvidersBootstrapped = append(result.ProvidersBootstrapped, config.Name)
		logger.Printf("Successfully bootstrapped %s", p.name)
	}

	// Set default provider
	defaultProvider := os.Getenv(EnvLLMDefaultProvider)
	if defaultProvider != "" {
		if registry.Has(defaultProvider) {
			result.DefaultProvider = defaultProvider
		} else {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("default provider %q not available", defaultProvider))
		}
	}

	// Log summary
	logger.Printf("Bootstrap complete: %d providers registered, %d failed",
		len(result.ProvidersBootstrapped), len(result.ProvidersFailed))

	if len(result.ProvidersBootstrapped) == 0 && len(result.ProvidersFailed) == 0 {
		logger.Println("WARNING: No LLM providers configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, or OLLAMA_ENDPOINT.")
	}

	return result, nil
}

// bootstrapAnthropic creates an Anthropic provider config from environment variables.
func bootstrapAnthropic() (*ProviderConfig, error) {
	apiKey := os.Getenv(EnvAnthropicAPIKey)
	if apiKey == "" {
		return nil, nil // Not configured
	}

	config := &ProviderConfig{
		Name:    "anthropic",
		Type:    ProviderTypeAnthropic,
		APIKey:  apiKey,
		Enabled: true,
	}

	if model := os.Getenv(EnvAnthropicModel); model != "" {
		config.Model = model
	}

	if endpoint := os.Getenv(EnvAnthropicEndpoint); endpoint != "" {
		config.Endpoint = endpoint
	}

	if timeoutStr := os.Getenv(EnvAnthropicTimeout); timeoutStr != "" {
		if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
			config.TimeoutSeconds = timeout
		}
	}

	return config, nil
}

// bootstrapOpenAI creates an OpenAI provider config from environment variables.
func bootstrapOpenAI() (*ProviderConfig, error) {
	apiKey := os.Getenv(EnvOpenAIAPIKey)
	if apiKey == "" {
		return nil, nil // Not configured
	}

	config := &ProviderConfig{
		Name:    "openai",
		Type:    ProviderTypeOpenAI,
		APIKey:  apiKey,
		Enabled: true,
	}

	if model := os.Getenv(EnvOpenAIModel); model != "" {
		config.Model = model
	}

	if endpoint := os.Getenv(EnvOpenAIEndpoint); endpoint != "" {
		config.Endpoint = endpoint
	}

	if timeoutStr := os.Getenv(EnvOpenAITimeout); timeoutStr != "" {
		if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
			config.TimeoutSeconds = timeout
		}
	}

	return config, nil
}

// bootstrapOllama creates an Ollama provider config from environment variables.
func bootstrapOllama() (*ProviderConfig, error) {
	endpoint := os.Getenv(EnvOllamaEndpoint)
	if endpoint == "" {
		return nil, nil // Not configured
	}

	config := &ProviderConfig{
		Name:     "ollama",
		Type:     ProviderTypeOllama,
		Endpoint: endpoint,
		Enabled:  true,
	}

	if model := os.Getenv(EnvOllamaModel); model != "" {
		config.Model = model
	}

	if timeoutStr := os.Getenv(EnvOllamaTimeout); timeoutStr != "" {
		if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
			config.TimeoutSeconds = timeout
		}
	}

	return config, nil
}

// bootstrapGemini creates a Gemini provider config from environment variables.
func bootstrapGemini() (*ProviderConfig, error) {
	apiKey := os.Getenv(EnvGoogleAPIKey)
	if apiKey == "" {
		return nil, nil // Not configured
	}

	config := &ProviderConfig{
		Name:    "gemini",
		Type:    ProviderTypeGemini,
		APIKey:  apiKey,
		Enabled: true,
	}

	if model := os.Getenv(EnvGoogleModel); model != "" {
		config.Model = model
	}

	if endpoint := os.Getenv(EnvGoogleEndpoint); endpoint != "" {
		config.Endpoint = endpoint
	}

	if timeoutStr := os.Getenv(EnvGoogleTimeout); timeoutStr != "" {
		if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
			config.TimeoutSeconds = timeout
		}
	}

	return config, nil
}

// containsProviderType checks if a provider type is in the list.
func containsProviderType(types []ProviderType, t ProviderType) bool {
	for _, pt := range types {
		if pt == t {
			return true
		}
	}
	return false
}

// QuickBootstrap is a convenience function for simple bootstrap scenarios.
// It bootstraps all available providers from environment variables and returns a Router.
func QuickBootstrap() (*Router, error) {
	result, err := BootstrapFromEnv(nil)
	if err != nil {
		return nil, fmt.Errorf("bootstrap failed: %w", err)
	}

	if len(result.ProvidersBootstrapped) == 0 {
		return nil, fmt.Errorf("no providers available")
	}

	// Build default weights (equal weight for all providers)
	weights := make(map[string]float64)
	equalWeight := 1.0 / float64(len(result.ProvidersBootstrapped))
	for _, name := range result.ProvidersBootstrapped {
		weights[name] = equalWeight
	}

	router := NewRouter(
		WithRouterRegistry(result.Registry),
		WithDefaultWeights(weights),
	)

	return router, nil
}

// MustBootstrap is like QuickBootstrap but panics on error.
// Use this only in initialization code where failure should be fatal.
func MustBootstrap() *Router {
	router, err := QuickBootstrap()
	if err != nil {
		panic(fmt.Sprintf("LLM bootstrap failed: %v", err))
	}
	return router
}

// DetectConfiguredProviders returns a list of provider types that have
// environment variables configured (but may not be bootstrapped yet).
func DetectConfiguredProviders() []ProviderType {
	var configured []ProviderType

	if os.Getenv(EnvAnthropicAPIKey) != "" {
		configured = append(configured, ProviderTypeAnthropic)
	}

	if os.Getenv(EnvOpenAIAPIKey) != "" {
		configured = append(configured, ProviderTypeOpenAI)
	}

	if os.Getenv(EnvOllamaEndpoint) != "" {
		configured = append(configured, ProviderTypeOllama)
	}

	if os.Getenv(EnvBedrockRegion) != "" {
		configured = append(configured, ProviderTypeBedrock)
	}

	return configured
}

// GetProviderEnvVars returns a map of environment variable names to their
// current values for a specific provider type.
func GetProviderEnvVars(providerType ProviderType) map[string]string {
	vars := make(map[string]string)

	switch providerType {
	case ProviderTypeAnthropic:
		vars[EnvAnthropicAPIKey] = maskAPIKey(os.Getenv(EnvAnthropicAPIKey))
		vars[EnvAnthropicModel] = os.Getenv(EnvAnthropicModel)
		vars[EnvAnthropicEndpoint] = os.Getenv(EnvAnthropicEndpoint)
		vars[EnvAnthropicTimeout] = os.Getenv(EnvAnthropicTimeout)

	case ProviderTypeOpenAI:
		vars[EnvOpenAIAPIKey] = maskAPIKey(os.Getenv(EnvOpenAIAPIKey))
		vars[EnvOpenAIModel] = os.Getenv(EnvOpenAIModel)
		vars[EnvOpenAIEndpoint] = os.Getenv(EnvOpenAIEndpoint)
		vars[EnvOpenAITimeout] = os.Getenv(EnvOpenAITimeout)

	case ProviderTypeOllama:
		vars[EnvOllamaEndpoint] = os.Getenv(EnvOllamaEndpoint)
		vars[EnvOllamaModel] = os.Getenv(EnvOllamaModel)
		vars[EnvOllamaTimeout] = os.Getenv(EnvOllamaTimeout)

	case ProviderTypeBedrock:
		vars[EnvBedrockRegion] = os.Getenv(EnvBedrockRegion)
		vars[EnvBedrockModel] = os.Getenv(EnvBedrockModel)
	}

	return vars
}

// maskAPIKey masks an API key for safe logging.
func maskAPIKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return "***"
	}
	return key[:4] + "..." + key[len(key)-4:]
}

// ValidateEnvironment checks that all required environment variables are set
// for at least one provider and returns validation errors.
func ValidateEnvironment() []string {
	var errors []string

	configured := DetectConfiguredProviders()
	if len(configured) == 0 {
		errors = append(errors,
			"No LLM providers configured. Set at least one of: "+
				"ANTHROPIC_API_KEY, OPENAI_API_KEY, OLLAMA_ENDPOINT, BEDROCK_REGION")
	}

	// Check for common configuration mistakes
	// Note: Bedrock without model is valid (has defaults), so no error needed

	// Check for Ollama without endpoint
	if os.Getenv(EnvOllamaModel) != "" && os.Getenv(EnvOllamaEndpoint) == "" {
		errors = append(errors,
			"OLLAMA_MODEL is set but OLLAMA_ENDPOINT is not. Set OLLAMA_ENDPOINT to enable Ollama.")
	}

	return errors
}
