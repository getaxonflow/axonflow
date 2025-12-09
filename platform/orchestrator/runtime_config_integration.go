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

package orchestrator

import (
	"context"
	"database/sql"
	"log"
	"os"
	"sync"
	"time"

	"axonflow/platform/connectors/config"
)

// LLM Provider name constants for validation and consistency.
// Use these constants instead of magic strings when referencing providers.
const (
	ProviderOpenAI    = "openai"
	ProviderAnthropic = "anthropic"
	ProviderBedrock   = "bedrock"
	ProviderOllama    = "ollama"
)

// ValidLLMProviders is the list of supported LLM provider names.
var ValidLLMProviders = []string{
	ProviderOpenAI,
	ProviderAnthropic,
	ProviderBedrock,
	ProviderOllama,
}

// isValidLLMProvider checks if the given provider name is valid.
func isValidLLMProvider(name string) bool {
	for _, p := range ValidLLMProviders {
		if p == name {
			return true
		}
	}
	return false
}

// runtimeConfigMu protects access to runtimeConfigService global variable.
// This mutex ensures thread-safe initialization and access during concurrent operations.
//
// Lock ordering: When acquiring multiple locks, always acquire runtimeConfigMu before
// llmRouterMu to prevent deadlocks. This ordering is used in RefreshLLMConfig.
var runtimeConfigMu sync.RWMutex

// runtimeConfigService is the global RuntimeConfigService instance for the orchestrator.
// It implements ADR-007 three-tier configuration priority: Database > Config File > Env Vars
// Access to this variable must be protected by runtimeConfigMu.
var runtimeConfigService *config.RuntimeConfigService

// llmRouterMu protects access to llmRouter global variable during refresh operations.
// This prevents race conditions when RefreshLLMConfig updates the router.
//
// Lock ordering: Always acquire runtimeConfigMu before llmRouterMu when both are needed.
// See RefreshLLMConfig for the canonical lock ordering pattern.
var llmRouterMu sync.RWMutex

// InitRuntimeConfigService initializes the RuntimeConfigService for the orchestrator.
// This should be called during orchestrator startup, after database connection is established.
// Thread-safe: uses mutex to protect global state.
func InitRuntimeConfigService(db *sql.DB, selfHosted bool) *config.RuntimeConfigService {
	logger := log.New(os.Stdout, "[ORCH_RUNTIME_CONFIG] ", log.LstdFlags)

	opts := config.RuntimeConfigServiceOptions{
		DB:         db,
		SelfHosted: selfHosted,
		CacheTTL:   30 * time.Second,
		Logger:     logger,
	}

	svc := config.NewRuntimeConfigService(opts)

	runtimeConfigMu.Lock()
	runtimeConfigService = svc
	runtimeConfigMu.Unlock()

	logger.Println("RuntimeConfigService initialized for orchestrator")

	return svc
}

// GetRuntimeConfigService returns the global RuntimeConfigService instance.
// Returns nil if not initialized. Thread-safe.
func GetRuntimeConfigService() *config.RuntimeConfigService {
	runtimeConfigMu.RLock()
	defer runtimeConfigMu.RUnlock()
	return runtimeConfigService
}

// LoadLLMConfigFromService loads LLM configuration from the RuntimeConfigService.
// This implements ADR-007 three-tier priority: Database > Config File > Env Vars
// Falls back to LoadLLMConfig() (env vars only) if RuntimeConfigService is not available.
// Thread-safe: uses mutex to protect access to runtimeConfigService.
func LoadLLMConfigFromService(ctx context.Context, tenantID string) LLMRouterConfig {
	runtimeConfigMu.RLock()
	svc := runtimeConfigService
	runtimeConfigMu.RUnlock()

	// Fall back to legacy env var loading if RuntimeConfigService not initialized
	if svc == nil {
		log.Println("[LLM Config] RuntimeConfigService not initialized, falling back to env vars")
		return LoadLLMConfig()
	}

	configs, source, err := svc.GetLLMProviderConfigs(ctx, tenantID)
	if err != nil {
		log.Printf("[LLM Config] Failed to load from RuntimeConfigService: %v, falling back to env vars", err)
		return LoadLLMConfig()
	}

	log.Printf("[LLM Config] Loaded %d providers from %s (tenant: %s)", len(configs), source, tenantID)

	// Convert RuntimeConfigService configs to LLMRouterConfig
	routerConfig := LLMRouterConfig{}

	for _, cfg := range configs {
		// Use local variables to avoid nil map access without modifying original config
		credentials := cfg.Credentials
		if credentials == nil {
			credentials = make(map[string]string)
		}
		providerConfig := cfg.Config
		if providerConfig == nil {
			providerConfig = make(map[string]interface{})
		}

		// Validate provider name
		if !isValidLLMProvider(cfg.ProviderName) {
			log.Printf("[LLM Config] WARNING: Unknown provider '%s' - ignoring. Valid providers: %v",
				cfg.ProviderName, ValidLLMProviders)
			continue
		}

		switch cfg.ProviderName {
		case ProviderOpenAI:
			if apiKey, ok := credentials["api_key"]; ok && apiKey != "" {
				routerConfig.OpenAIKey = apiKey
				log.Printf("[LLM Config] OpenAI provider loaded from %s", source)
			}
		case ProviderAnthropic:
			if apiKey, ok := credentials["api_key"]; ok && apiKey != "" {
				routerConfig.AnthropicKey = apiKey
				log.Printf("[LLM Config] Anthropic provider loaded from %s", source)
			}
		case ProviderBedrock:
			region, hasRegion := providerConfig["region"].(string)
			model, hasModel := providerConfig["model"].(string)

			// Validate Bedrock requires both region and model
			if hasRegion && region != "" && hasModel && model != "" {
				routerConfig.BedrockRegion = region
				routerConfig.BedrockModel = model
				log.Printf("[LLM Config] Bedrock provider loaded from %s (region: %s, model: %s)",
					source, region, model)
			} else if (hasRegion && region != "") || (hasModel && model != "") {
				// Warn if only one is set - this is a configuration error
				log.Printf("[LLM Config] WARNING: Bedrock provider requires both region and model. "+
					"Got region=%q, model=%q - provider disabled", region, model)
			}
		case ProviderOllama:
			endpoint, hasEndpoint := providerConfig["endpoint"].(string)
			model, hasModel := providerConfig["model"].(string)

			// Validate Ollama requires endpoint (model is optional, has defaults)
			if hasEndpoint && endpoint != "" {
				routerConfig.OllamaEndpoint = endpoint
				if hasModel && model != "" {
					routerConfig.OllamaModel = model
				}
				log.Printf("[LLM Config] Ollama provider loaded from %s (endpoint: %s, model: %s)",
					source, endpoint, routerConfig.OllamaModel)
			} else if hasModel && model != "" {
				log.Printf("[LLM Config] WARNING: Ollama provider requires endpoint. "+
					"Got model=%q but no endpoint - provider disabled", model)
			}
		}
	}

	// Log summary
	providers := []string{}
	if routerConfig.OpenAIKey != "" {
		providers = append(providers, ProviderOpenAI)
	}
	if routerConfig.AnthropicKey != "" {
		providers = append(providers, ProviderAnthropic)
	}
	if routerConfig.BedrockRegion != "" {
		providers = append(providers, ProviderBedrock)
	}
	if routerConfig.OllamaEndpoint != "" {
		providers = append(providers, ProviderOllama)
	}

	if len(providers) == 0 {
		log.Println("[LLM Config] WARNING: No LLM providers configured")
	} else {
		log.Printf("[LLM Config] Enabled providers: %v (source: %s)", providers, source)
	}

	return routerConfig
}

// RefreshLLMConfig refreshes the LLM configuration from the RuntimeConfigService.
// This can be called to pick up configuration changes without restarting.
// Thread-safe: uses mutexes to protect access to global state.
func RefreshLLMConfig(ctx context.Context, tenantID string) error {
	runtimeConfigMu.RLock()
	svc := runtimeConfigService
	runtimeConfigMu.RUnlock()

	if svc == nil {
		return nil // No-op if not using RuntimeConfigService
	}

	// Invalidate cache and reload
	svc.RefreshAllConfigs()

	// Reload configuration
	newConfig := LoadLLMConfigFromService(ctx, tenantID)

	// Update the global LLM router if it exists
	// Use mutex to prevent race condition during router swap
	llmRouterMu.Lock()
	defer llmRouterMu.Unlock()

	if llmRouter != nil {
		// Note: This creates a new router. In future, we could add a
		// ReconfigureRouter method to update config without recreation.
		llmRouter = NewLLMRouter(newConfig)
		log.Println("[LLM Config] LLM Router reconfigured with refreshed config")
	}

	return nil
}

// GetLLMRouter returns the global LLM router with thread-safe access.
// This should be used instead of directly accessing llmRouter when
// RefreshLLMConfig may be called concurrently.
func GetLLMRouter() *LLMRouter {
	llmRouterMu.RLock()
	defer llmRouterMu.RUnlock()
	return llmRouter
}

// SetLLMRouter sets the global LLM router with thread-safe access.
// This should be used during initialization.
func SetLLMRouter(router *LLMRouter) {
	llmRouterMu.Lock()
	defer llmRouterMu.Unlock()
	llmRouter = router
}
