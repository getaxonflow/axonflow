//go:build enterprise

// Copyright 2025 AxonFlow
// Licensed under the Elastic License 2.0 (ELv2)
// Enterprise features - not available in Community distribution

package llmadapters

import (
	"errors"
	"testing"

	"axonflow/platform/orchestrator/llm"
)

func TestNewBedrockProviderFactory_Success(t *testing.T) {
	config := llm.ProviderConfig{
		Name:   "test-bedrock",
		Type:   llm.ProviderTypeBedrock,
		Region: "us-east-1",
		Model:  "anthropic.claude-sonnet-4-20250514-v1:0",
	}

	provider, err := NewBedrockProviderFactory(config)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if provider == nil {
		t.Fatal("expected non-nil provider")
	}

	if provider.Name() != "test-bedrock" {
		t.Errorf("expected name 'test-bedrock', got '%s'", provider.Name())
	}

	if provider.Type() != llm.ProviderTypeBedrock {
		t.Errorf("expected type 'bedrock', got '%s'", provider.Type())
	}
}

func TestNewBedrockProviderFactory_MissingRegion(t *testing.T) {
	config := llm.ProviderConfig{
		Name:  "test-bedrock",
		Type:  llm.ProviderTypeBedrock,
		Model: "anthropic.claude-sonnet-4-20250514-v1:0",
		// Region is missing
	}

	_, err := NewBedrockProviderFactory(config)
	if err == nil {
		t.Fatal("expected error for missing region")
	}

	var factoryErr *llm.FactoryError
	if !errors.As(err, &factoryErr) {
		t.Fatalf("expected FactoryError, got %T", err)
	}

	if factoryErr.Code != llm.ErrFactoryInvalidConfig {
		t.Errorf("expected error code %q, got %q", llm.ErrFactoryInvalidConfig, factoryErr.Code)
	}
}

func TestNewBedrockProviderFactory_RegionFromSettings(t *testing.T) {
	config := llm.ProviderConfig{
		Name: "test-bedrock",
		Type: llm.ProviderTypeBedrock,
		Settings: map[string]interface{}{
			"region": "eu-central-1",
			"model":  "anthropic.claude-haiku-4-5-20251001-v1:0",
		},
	}

	provider, err := NewBedrockProviderFactory(config)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if provider == nil {
		t.Fatal("expected non-nil provider")
	}

	// Verify the adapter was created (can't access internal state directly)
	if provider.Type() != llm.ProviderTypeBedrock {
		t.Errorf("expected type 'bedrock', got '%s'", provider.Type())
	}
}

func TestNewBedrockProviderFactory_DefaultModel(t *testing.T) {
	config := llm.ProviderConfig{
		Name:   "test-bedrock",
		Type:   llm.ProviderTypeBedrock,
		Region: "us-west-2",
		// Model is not specified - should use default
	}

	provider, err := NewBedrockProviderFactory(config)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestNewBedrockProviderFactory_NilSettings(t *testing.T) {
	// Test that nil Settings doesn't cause panic
	config := llm.ProviderConfig{
		Name:     "test-bedrock",
		Type:     llm.ProviderTypeBedrock,
		Region:   "us-east-1",
		Model:    "anthropic.claude-sonnet-4-20250514-v1:0",
		Settings: nil, // Explicitly nil
	}

	provider, err := NewBedrockProviderFactory(config)
	if err != nil {
		t.Fatalf("expected no error with nil Settings, got: %v", err)
	}

	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestNewBedrockProviderFactory_ModelFamily(t *testing.T) {
	config := llm.ProviderConfig{
		Name:   "test-bedrock",
		Type:   llm.ProviderTypeBedrock,
		Region: "us-east-1",
		Model:  "custom.model.id",
		Settings: map[string]interface{}{
			"model_family": "anthropic",
		},
	}

	provider, err := NewBedrockProviderFactory(config)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestBedrockFactoryRegistration(t *testing.T) {
	// Verify that the factory is registered
	if !llm.HasFactory(llm.ProviderTypeBedrock) {
		t.Error("expected Bedrock factory to be registered")
	}

	// Verify we can get the factory
	factory := llm.GetFactory(llm.ProviderTypeBedrock)
	if factory == nil {
		t.Error("expected non-nil factory function")
	}
}

func TestBedrockProviderImplementsInterface(t *testing.T) {
	config := llm.ProviderConfig{
		Name:   "interface-test",
		Type:   llm.ProviderTypeBedrock,
		Region: "us-east-1",
	}

	provider, err := NewBedrockProviderFactory(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Verify interface compliance
	var _ llm.Provider = provider
}
