// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"time"

	"axonflow/platform/orchestrator/llm"
)

// RoutingStrategy is an alias for llm.RoutingStrategy for backward compatibility.
type RoutingStrategy = llm.RoutingStrategy

// Routing strategy constants - re-exported from llm package for convenience.
const (
	RoutingStrategyWeighted   = llm.RoutingStrategyWeighted
	RoutingStrategyRoundRobin = llm.RoutingStrategyRoundRobin
	RoutingStrategyFailover   = llm.RoutingStrategyFailover
)

// RoutingConfig is an alias for llm.RoutingConfig for backward compatibility.
type RoutingConfig = llm.RoutingConfig

// LoadRoutingConfig loads routing configuration from environment variables.
// This is a thin wrapper around llm.LoadRoutingConfigFromEnv for backward compatibility.
func LoadRoutingConfig() RoutingConfig {
	return llm.LoadRoutingConfigFromEnv()
}

// LLMRouterConfig contains configuration for the LLM router.
// This struct is used to load configuration from the RuntimeConfigService
// and environment variables for LLM provider initialization.
type LLMRouterConfig struct {
	// API Keys
	OpenAIKey    string
	AnthropicKey string
	GeminiKey    string
	GeminiModel  string

	// Bedrock configuration
	BedrockRegion string
	BedrockModel  string

	// Ollama configuration
	OllamaEndpoint string
	OllamaModel    string

	// Deprecated: use OllamaEndpoint
	LocalEndpoint string

	// Routing configuration (Phase 1: Community env-based routing)
	RoutingStrategy RoutingStrategy    // "weighted" (default), "round_robin", "failover"
	ProviderWeights map[string]float64 // Custom weights (normalized to sum to 1.0)
	DefaultProvider string             // Fallback provider for failover strategy
}

// QueryOptions contains options for LLM queries.
type QueryOptions struct {
	MaxTokens    int     `json:"max_tokens"`
	Temperature  float64 `json:"temperature"`
	Model        string  `json:"model"`
	SystemPrompt string  `json:"system_prompt"`
}

// LLMResponse represents a response from an LLM provider.
type LLMResponse struct {
	Content      string                 `json:"content"`
	Model        string                 `json:"model"`
	TokensUsed   int                    `json:"tokens_used"`
	Metadata     map[string]interface{} `json:"metadata"`
	ResponseTime time.Duration          `json:"response_time"`
}

// ProviderStatus represents the current status of a provider.
type ProviderStatus struct {
	Name         string    `json:"name"`
	Healthy      bool      `json:"healthy"`
	Weight       float64   `json:"weight"`
	RequestCount int64     `json:"request_count"`
	ErrorCount   int64     `json:"error_count"`
	AvgLatency   float64   `json:"avg_latency_ms"`
	LastUsed     time.Time `json:"last_used"`
}
