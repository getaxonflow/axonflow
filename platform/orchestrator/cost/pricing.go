// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
)

// ModelPricing contains pricing per 1K tokens for a model
type ModelPricing struct {
	InputPer1K  float64 `json:"input_per_1k"`
	OutputPer1K float64 `json:"output_per_1k"`
}

// PricingConfig holds pricing information for all providers and models
type PricingConfig struct {
	Providers map[string]map[string]ModelPricing `json:"providers"`
	mu        sync.RWMutex
}

// DefaultPricing contains default pricing for common LLM providers and models
// Prices are per 1K tokens in USD (as of January 2025)
var DefaultPricing = &PricingConfig{
	Providers: map[string]map[string]ModelPricing{
		"anthropic": {
			// Claude 4 models (January 2025)
			"claude-opus-4":           {InputPer1K: 0.015, OutputPer1K: 0.075},
			"claude-opus-4-20250514":  {InputPer1K: 0.015, OutputPer1K: 0.075},
			"claude-sonnet-4":         {InputPer1K: 0.003, OutputPer1K: 0.015},
			"claude-sonnet-4-20250514":{InputPer1K: 0.003, OutputPer1K: 0.015},
			// Claude 3.5 models
			"claude-3-5-sonnet":           {InputPer1K: 0.003, OutputPer1K: 0.015},
			"claude-3-5-sonnet-20241022":  {InputPer1K: 0.003, OutputPer1K: 0.015},
			"claude-3-5-haiku":            {InputPer1K: 0.0008, OutputPer1K: 0.004},
			"claude-3-5-haiku-20241022":   {InputPer1K: 0.0008, OutputPer1K: 0.004},
			// Claude 3 models
			"claude-3-opus":         {InputPer1K: 0.015, OutputPer1K: 0.075},
			"claude-3-opus-20240229":{InputPer1K: 0.015, OutputPer1K: 0.075},
			"claude-3-sonnet":       {InputPer1K: 0.003, OutputPer1K: 0.015},
			"claude-3-haiku":        {InputPer1K: 0.00025, OutputPer1K: 0.00125},
			"claude-3-haiku-20240307":{InputPer1K: 0.00025, OutputPer1K: 0.00125},
			// Default for unknown Anthropic models
			"*": {InputPer1K: 0.003, OutputPer1K: 0.015},
		},
		"openai": {
			// GPT-4o models
			"gpt-4o":          {InputPer1K: 0.0025, OutputPer1K: 0.01},
			"gpt-4o-2024-11-20":{InputPer1K: 0.0025, OutputPer1K: 0.01},
			"gpt-4o-mini":     {InputPer1K: 0.00015, OutputPer1K: 0.0006},
			"gpt-4o-mini-2024-07-18":{InputPer1K: 0.00015, OutputPer1K: 0.0006},
			// GPT-4 Turbo
			"gpt-4-turbo":         {InputPer1K: 0.01, OutputPer1K: 0.03},
			"gpt-4-turbo-preview": {InputPer1K: 0.01, OutputPer1K: 0.03},
			"gpt-4-turbo-2024-04-09":{InputPer1K: 0.01, OutputPer1K: 0.03},
			// GPT-4
			"gpt-4":       {InputPer1K: 0.03, OutputPer1K: 0.06},
			"gpt-4-32k":   {InputPer1K: 0.06, OutputPer1K: 0.12},
			// GPT-3.5
			"gpt-3.5-turbo": {InputPer1K: 0.0005, OutputPer1K: 0.0015},
			"gpt-3.5-turbo-0125":{InputPer1K: 0.0005, OutputPer1K: 0.0015},
			// o1 models (reasoning)
			"o1-preview": {InputPer1K: 0.015, OutputPer1K: 0.06},
			"o1-mini":    {InputPer1K: 0.003, OutputPer1K: 0.012},
			// Default for unknown OpenAI models
			"*": {InputPer1K: 0.01, OutputPer1K: 0.03},
		},
		"google": {
			// Gemini 2.0
			"gemini-2.0-flash":     {InputPer1K: 0.0001, OutputPer1K: 0.0004},
			"gemini-2.0-flash-exp": {InputPer1K: 0.0, OutputPer1K: 0.0}, // Free during preview
			// Gemini 1.5
			"gemini-1.5-pro":       {InputPer1K: 0.00125, OutputPer1K: 0.005},
			"gemini-1.5-pro-002":   {InputPer1K: 0.00125, OutputPer1K: 0.005},
			"gemini-1.5-flash":     {InputPer1K: 0.000075, OutputPer1K: 0.0003},
			"gemini-1.5-flash-002": {InputPer1K: 0.000075, OutputPer1K: 0.0003},
			"gemini-1.5-flash-8b":  {InputPer1K: 0.0000375, OutputPer1K: 0.00015},
			// Gemini 1.0
			"gemini-pro":      {InputPer1K: 0.0005, OutputPer1K: 0.0015},
			"gemini-1.0-pro":  {InputPer1K: 0.0005, OutputPer1K: 0.0015},
			// Default
			"*": {InputPer1K: 0.001, OutputPer1K: 0.004},
		},
		"azure": {
			// Azure OpenAI uses same pricing as OpenAI
			"gpt-4o":          {InputPer1K: 0.0025, OutputPer1K: 0.01},
			"gpt-4o-mini":     {InputPer1K: 0.00015, OutputPer1K: 0.0006},
			"gpt-4-turbo":     {InputPer1K: 0.01, OutputPer1K: 0.03},
			"gpt-4":           {InputPer1K: 0.03, OutputPer1K: 0.06},
			"gpt-35-turbo":    {InputPer1K: 0.0005, OutputPer1K: 0.0015},
			"*": {InputPer1K: 0.01, OutputPer1K: 0.03},
		},
		"bedrock": {
			// Claude on Bedrock
			"anthropic.claude-3-opus-20240229-v1:0":   {InputPer1K: 0.015, OutputPer1K: 0.075},
			"anthropic.claude-3-sonnet-20240229-v1:0": {InputPer1K: 0.003, OutputPer1K: 0.015},
			"anthropic.claude-3-haiku-20240307-v1:0":  {InputPer1K: 0.00025, OutputPer1K: 0.00125},
			"anthropic.claude-3-5-sonnet-20241022-v2:0":{InputPer1K: 0.003, OutputPer1K: 0.015},
			// Titan models
			"amazon.titan-text-express-v1": {InputPer1K: 0.0002, OutputPer1K: 0.0006},
			"amazon.titan-text-lite-v1":    {InputPer1K: 0.00015, OutputPer1K: 0.0002},
			// Meta Llama
			"meta.llama3-8b-instruct-v1:0":  {InputPer1K: 0.0003, OutputPer1K: 0.0006},
			"meta.llama3-70b-instruct-v1:0": {InputPer1K: 0.00265, OutputPer1K: 0.0035},
			"*": {InputPer1K: 0.003, OutputPer1K: 0.015},
		},
		"ollama": {
			// Self-hosted = free (compute cost not tracked here)
			"*": {InputPer1K: 0, OutputPer1K: 0},
		},
		"local": {
			// Local models = free
			"*": {InputPer1K: 0, OutputPer1K: 0},
		},
		"cohere": {
			"command-r-plus":  {InputPer1K: 0.003, OutputPer1K: 0.015},
			"command-r":       {InputPer1K: 0.0005, OutputPer1K: 0.0015},
			"command":         {InputPer1K: 0.001, OutputPer1K: 0.002},
			"*": {InputPer1K: 0.001, OutputPer1K: 0.002},
		},
		"mistral": {
			"mistral-large-latest":   {InputPer1K: 0.002, OutputPer1K: 0.006},
			"mistral-medium-latest":  {InputPer1K: 0.00265, OutputPer1K: 0.008},
			"mistral-small-latest":   {InputPer1K: 0.001, OutputPer1K: 0.003},
			"mistral-7b-instruct":    {InputPer1K: 0.00025, OutputPer1K: 0.00025},
			"mixtral-8x7b-instruct":  {InputPer1K: 0.0007, OutputPer1K: 0.0007},
			"*": {InputPer1K: 0.002, OutputPer1K: 0.006},
		},
	},
}

// NewPricingConfig creates a new pricing configuration with defaults
func NewPricingConfig() *PricingConfig {
	return &PricingConfig{
		Providers: copyProviders(DefaultPricing.Providers),
	}
}

// LoadPricingFromEnv loads custom pricing from AXONFLOW_PRICING_CONFIG env var
func LoadPricingFromEnv() *PricingConfig {
	config := NewPricingConfig()

	pricingJSON := os.Getenv("AXONFLOW_PRICING_CONFIG")
	if pricingJSON != "" {
		var custom PricingConfig
		if err := json.Unmarshal([]byte(pricingJSON), &custom); err == nil {
			// Merge custom pricing with defaults
			for provider, models := range custom.Providers {
				if config.Providers[provider] == nil {
					config.Providers[provider] = make(map[string]ModelPricing)
				}
				for model, pricing := range models {
					config.Providers[provider][model] = pricing
				}
			}
		}
	}

	return config
}

// LoadPricingFromFile loads pricing from a JSON file
func LoadPricingFromFile(path string) (*PricingConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := NewPricingConfig()
	var custom PricingConfig
	if err := json.Unmarshal(data, &custom); err != nil {
		return nil, err
	}

	// Merge custom pricing with defaults
	for provider, models := range custom.Providers {
		if config.Providers[provider] == nil {
			config.Providers[provider] = make(map[string]ModelPricing)
		}
		for model, pricing := range models {
			config.Providers[provider][model] = pricing
		}
	}

	return config, nil
}

// CalculateCost calculates the cost for a request based on tokens and model
func (p *PricingConfig) CalculateCost(provider, model string, tokensIn, tokensOut int) float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Normalize provider name
	provider = strings.ToLower(provider)

	providerPricing, ok := p.Providers[provider]
	if !ok {
		return 0
	}

	// Try exact model match first
	modelPricing, ok := providerPricing[model]
	if !ok {
		// Try normalized model name
		modelPricing, ok = providerPricing[strings.ToLower(model)]
		if !ok {
			// Fall back to wildcard
			modelPricing, ok = providerPricing["*"]
			if !ok {
				return 0
			}
		}
	}

	inputCost := float64(tokensIn) / 1000.0 * modelPricing.InputPer1K
	outputCost := float64(tokensOut) / 1000.0 * modelPricing.OutputPer1K

	return inputCost + outputCost
}

// GetModelPricing returns pricing for a specific model
func (p *PricingConfig) GetModelPricing(provider, model string) (ModelPricing, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	provider = strings.ToLower(provider)

	providerPricing, ok := p.Providers[provider]
	if !ok {
		return ModelPricing{}, false
	}

	pricing, ok := providerPricing[model]
	if !ok {
		pricing, ok = providerPricing["*"]
	}

	return pricing, ok
}

// SetModelPricing sets pricing for a specific model
func (p *PricingConfig) SetModelPricing(provider, model string, pricing ModelPricing) {
	p.mu.Lock()
	defer p.mu.Unlock()

	provider = strings.ToLower(provider)

	if p.Providers[provider] == nil {
		p.Providers[provider] = make(map[string]ModelPricing)
	}
	p.Providers[provider][model] = pricing
}

// ListProviders returns all configured providers
func (p *PricingConfig) ListProviders() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	providers := make([]string, 0, len(p.Providers))
	for provider := range p.Providers {
		providers = append(providers, provider)
	}
	return providers
}

// ListModels returns all configured models for a provider
func (p *PricingConfig) ListModels(provider string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	provider = strings.ToLower(provider)

	providerPricing, ok := p.Providers[provider]
	if !ok {
		return nil
	}

	models := make([]string, 0, len(providerPricing))
	for model := range providerPricing {
		if model != "*" {
			models = append(models, model)
		}
	}
	return models
}

// EstimateCost estimates cost for a request (before execution)
func (p *PricingConfig) EstimateCost(provider, model string, estimatedTokensIn, estimatedTokensOut int) float64 {
	return p.CalculateCost(provider, model, estimatedTokensIn, estimatedTokensOut)
}

func copyProviders(src map[string]map[string]ModelPricing) map[string]map[string]ModelPricing {
	dst := make(map[string]map[string]ModelPricing)
	for provider, models := range src {
		dst[provider] = make(map[string]ModelPricing)
		for model, pricing := range models {
			dst[provider][model] = pricing
		}
	}
	return dst
}
