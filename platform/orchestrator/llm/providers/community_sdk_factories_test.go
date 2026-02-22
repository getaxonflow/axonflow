// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"axonflow/platform/orchestrator/llm"
)

func TestSDKFactories_CreateAnthropicProvider(t *testing.T) {
	provider, err := NewAnthropicProviderFactory(llm.ProviderConfig{
		Name:   "anthropic-sdk",
		Type:   llm.ProviderTypeAnthropic,
		APIKey: "test-key",
	})
	if err != nil {
		t.Fatalf("NewAnthropicProviderFactory() error = %v", err)
	}
	if provider.Type() != llm.ProviderTypeAnthropic {
		t.Fatalf("Type() = %v, want %v", provider.Type(), llm.ProviderTypeAnthropic)
	}
	if provider.Name() != "anthropic-sdk" {
		t.Fatalf("Name() = %q, want %q", provider.Name(), "anthropic-sdk")
	}
}

func TestSDKFactories_CreateGeminiProvider(t *testing.T) {
	provider, err := NewGeminiProviderFactory(llm.ProviderConfig{
		Name:   "gemini-sdk",
		Type:   llm.ProviderTypeGemini,
		APIKey: "test-key",
	})
	if err != nil {
		t.Fatalf("NewGeminiProviderFactory() error = %v", err)
	}
	if provider.Type() != llm.ProviderTypeGemini {
		t.Fatalf("Type() = %v, want %v", provider.Type(), llm.ProviderTypeGemini)
	}
}

func TestSDKFactories_CreateAzureProvider(t *testing.T) {
	provider, err := NewAzureOpenAIProviderFactory(llm.ProviderConfig{
		Name:     "azure-sdk",
		Type:     llm.ProviderTypeAzureOpenAI,
		APIKey:   "test-key",
		Endpoint: "https://example.openai.azure.com",
		Model:    "gpt-4o-mini",
	})
	if err != nil {
		t.Fatalf("NewAzureOpenAIProviderFactory() error = %v", err)
	}
	if provider.Type() != llm.ProviderTypeAzureOpenAI {
		t.Fatalf("Type() = %v, want %v", provider.Type(), llm.ProviderTypeAzureOpenAI)
	}
}

func TestSDKFactories_CreateOllamaProvider(t *testing.T) {
	provider, err := NewOllamaProviderFactory(llm.ProviderConfig{
		Name:     "ollama-sdk",
		Type:     llm.ProviderTypeOllama,
		Endpoint: "http://localhost:11434",
		Model:    "llama3.2:latest",
	})
	if err != nil {
		t.Fatalf("NewOllamaProviderFactory() error = %v", err)
	}
	if provider.Type() != llm.ProviderTypeOllama {
		t.Fatalf("Type() = %v, want %v", provider.Type(), llm.ProviderTypeOllama)
	}
}
