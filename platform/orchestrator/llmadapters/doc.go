//go:build enterprise

// Copyright 2025 AxonFlow
// Licensed under the Elastic License 2.0 (ELv2)
// Enterprise features - not available in Community distribution

// Package llmadapters provides adapter implementations that bridge enterprise LLM providers
// with the unified Community llm.Provider interface.
//
// # Overview
//
// This package enables enterprise providers (Bedrock, Ollama) to be used with the new
// pluggable provider system while maintaining backward compatibility with existing
// enterprise implementations.
//
// # Architecture
//
// The adapters sit between two type systems:
//   - Community types: axonflow/platform/orchestrator/llm (CompletionRequest, CompletionResponse, Provider interface)
//   - EE types: The enterprise provider implementations with their own request/response types
//
// Each adapter:
//   - Converts request types from Community format to EE format
//   - Calls the underlying enterprise provider
//   - Converts response types from EE format to Community format
//   - Implements health checking, capabilities, and cost estimation
//
// # Available Adapters
//
//   - BedrockAdapter: Adapts AWS Bedrock provider for the unified interface
//   - OllamaAdapter: Adapts self-hosted Ollama provider for the unified interface
//
// # Usage
//
// Create an adapter and register it with the provider registry:
//
//	import (
//	    "axonflow/ee/platform/orchestrator/llmadapters"
//	    "axonflow/platform/orchestrator/llm"
//	)
//
//	adapter, err := llmadapters.NewBedrockAdapter(llmadapters.BedrockAdapterConfig{
//	    Name:   "bedrock-primary",
//	    Region: "us-east-1",
//	    Model:  "anthropic.claude-sonnet-4-20250514-v1:0",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// The adapter implements llm.Provider
//	var provider llm.Provider = adapter
//
// # License Requirements
//
// These adapters are part of the Enterprise edition:
//   - Bedrock: Requires Enterprise license tier
//   - Ollama: Requires Enterprise license tier
//
// See platform/orchestrator/llm/license_gating.go for tier requirements.
//
// # Module Structure Note
//
// This package is intentionally placed in ee/platform/orchestrator/llmadapters
// (not ee/platform/orchestrator/llm/adapters) to avoid module path conflicts.
// The ee/platform/orchestrator/llm directory has its own go.mod with the same
// module path as the Community package.
package llmadapters
