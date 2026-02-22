// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"
)

func TestFromAgentConfigFile_NilInput(t *testing.T) {
	result := FromAgentConfigFile(nil, "file")
	if result != nil {
		t.Errorf("Expected nil for nil input, got %+v", result)
	}
}

func TestFromAgentConfigFile_BasicMapping(t *testing.T) {
	config := &AgentConfigFile{
		Metadata: AgentMetadata{
			Name:        "test-agent",
			Domain:      "ecommerce",
			Description: "Test agent for ecommerce",
		},
		Spec: AgentConfigSpec{
			Execution: ExecutionConfig{
				DefaultMode:      "auto",
				MaxParallelTasks: 5,
				TimeoutSeconds:   300,
			},
			Agents: []AgentDef{
				{
					Name:        "product-search",
					Description: "Search products",
					Type:        "llm-call",
					LLM: &LLMAgentConfig{
						Provider:    "openai",
						Model:       "gpt-4",
						Temperature: 0.7,
						MaxTokens:   1000,
					},
				},
			},
		},
	}

	result := FromAgentConfigFile(config, "file")
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.ID != "test-agent" {
		t.Errorf("Expected ID 'test-agent', got %q", result.ID)
	}
	if result.Name != "test-agent" {
		t.Errorf("Expected Name 'test-agent', got %q", result.Name)
	}
	if result.Domain != "ecommerce" {
		t.Errorf("Expected Domain 'ecommerce', got %q", result.Domain)
	}
	if result.Description != "Test agent for ecommerce" {
		t.Errorf("Expected Description 'Test agent for ecommerce', got %q", result.Description)
	}
	if result.Source != "file" {
		t.Errorf("Expected Source 'file', got %q", result.Source)
	}
	if !result.IsActive {
		t.Error("Expected IsActive to be true for file-based configs")
	}
	if result.Spec == nil {
		t.Error("Expected Spec to be non-nil")
	}
}

func TestFromAgentConfigFile_DatabaseSource(t *testing.T) {
	config := &AgentConfigFile{
		Metadata: AgentMetadata{
			Name:   "db-agent",
			Domain: "finance",
		},
		Spec: AgentConfigSpec{
			Agents: []AgentDef{
				{
					Name: "query-executor",
					Type: "connector-call",
					Connector: &ConnectorRef{
						Name:      "postgres",
						Operation: "query",
					},
				},
			},
		},
	}

	result := FromAgentConfigFile(config, "database")
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Source != "database" {
		t.Errorf("Expected Source 'database', got %q", result.Source)
	}
}

func TestFromAgentConfigFile_IDUsesMetadataName(t *testing.T) {
	config := &AgentConfigFile{
		Metadata: AgentMetadata{
			Name:   "my-custom-agent",
			Domain: "healthcare",
		},
		Spec: AgentConfigSpec{
			Agents: []AgentDef{
				{
					Name: "agent-1",
					Type: "llm-call",
					LLM: &LLMAgentConfig{
						Provider: "anthropic",
						Model:    "claude-sonnet-4",
					},
				},
			},
		},
	}

	result := FromAgentConfigFile(config, "file")
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// ID should be the metadata name, not the spec agent name
	if result.ID != "my-custom-agent" {
		t.Errorf("Expected ID to match metadata.name 'my-custom-agent', got %q", result.ID)
	}
}

func TestFromAgentConfigFile_IsAlwaysActive(t *testing.T) {
	config := &AgentConfigFile{
		Metadata: AgentMetadata{
			Name:   "active-agent",
			Domain: "general",
		},
		Spec: AgentConfigSpec{
			Agents: []AgentDef{
				{
					Name: "agent-1",
					Type: "llm-call",
					LLM: &LLMAgentConfig{
						Provider: "openai",
						Model:    "gpt-4",
					},
				},
			},
		},
	}

	result := FromAgentConfigFile(config, "file")
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if !result.IsActive {
		t.Error("File-based configs should always be active")
	}
}

func TestFromAgentConfigFile_SpecPointsToConfigSpec(t *testing.T) {
	config := &AgentConfigFile{
		Metadata: AgentMetadata{
			Name:   "spec-test",
			Domain: "testing",
		},
		Spec: AgentConfigSpec{
			Execution: ExecutionConfig{
				DefaultMode:      "parallel",
				MaxParallelTasks: 10,
				TimeoutSeconds:   600,
				Hints:            "Test hints",
			},
			Agents: []AgentDef{
				{
					Name: "agent-1",
					Type: "llm-call",
					LLM: &LLMAgentConfig{
						Provider: "openai",
						Model:    "gpt-4",
					},
				},
			},
		},
	}

	result := FromAgentConfigFile(config, "file")
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Spec == nil {
		t.Fatal("Spec should not be nil")
	}
	if result.Spec.Execution.DefaultMode != "parallel" {
		t.Errorf("Expected Spec.Execution.DefaultMode 'parallel', got %q", result.Spec.Execution.DefaultMode)
	}
	if result.Spec.Execution.MaxParallelTasks != 10 {
		t.Errorf("Expected Spec.Execution.MaxParallelTasks 10, got %d", result.Spec.Execution.MaxParallelTasks)
	}
	if len(result.Spec.Agents) != 1 {
		t.Errorf("Expected 1 agent in spec, got %d", len(result.Spec.Agents))
	}
}

func TestFromAgentConfigFile_EmptyDescription(t *testing.T) {
	config := &AgentConfigFile{
		Metadata: AgentMetadata{
			Name:   "no-desc-agent",
			Domain: "general",
			// Description intentionally left empty
		},
		Spec: AgentConfigSpec{
			Agents: []AgentDef{
				{
					Name: "agent-1",
					Type: "llm-call",
					LLM: &LLMAgentConfig{
						Provider: "openai",
						Model:    "gpt-4",
					},
				},
			},
		},
	}

	result := FromAgentConfigFile(config, "file")
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Description != "" {
		t.Errorf("Expected empty description, got %q", result.Description)
	}
}

func TestFromAgentConfigFile_TimestampsAreNil(t *testing.T) {
	config := &AgentConfigFile{
		Metadata: AgentMetadata{
			Name:   "ts-test",
			Domain: "general",
		},
		Spec: AgentConfigSpec{
			Agents: []AgentDef{
				{
					Name: "agent-1",
					Type: "llm-call",
					LLM: &LLMAgentConfig{
						Provider: "openai",
						Model:    "gpt-4",
					},
				},
			},
		},
	}

	result := FromAgentConfigFile(config, "file")
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// File-based configs don't have timestamps set
	if result.CreatedAt != nil {
		t.Errorf("Expected nil CreatedAt, got %v", result.CreatedAt)
	}
	if result.UpdatedAt != nil {
		t.Errorf("Expected nil UpdatedAt, got %v", result.UpdatedAt)
	}
}

func TestFromAgentConfigFile_VersionIsZero(t *testing.T) {
	config := &AgentConfigFile{
		Metadata: AgentMetadata{
			Name:   "version-test",
			Domain: "general",
		},
		Spec: AgentConfigSpec{
			Agents: []AgentDef{
				{
					Name: "agent-1",
					Type: "llm-call",
					LLM: &LLMAgentConfig{
						Provider: "openai",
						Model:    "gpt-4",
					},
				},
			},
		},
	}

	result := FromAgentConfigFile(config, "file")
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Version should be the zero value since it's not set from file
	if result.Version != 0 {
		t.Errorf("Expected Version 0, got %d", result.Version)
	}
}

// Test default pagination constants
func TestAgentPaginationDefaults(t *testing.T) {
	if DefaultAgentPage != 1 {
		t.Errorf("Expected DefaultAgentPage=1, got %d", DefaultAgentPage)
	}
	if DefaultAgentPageSize != 20 {
		t.Errorf("Expected DefaultAgentPageSize=20, got %d", DefaultAgentPageSize)
	}
	if MaxAgentPageSize != 100 {
		t.Errorf("Expected MaxAgentPageSize=100, got %d", MaxAgentPageSize)
	}
}

func TestAgentPaginationDefaults_PageSizeWithinMax(t *testing.T) {
	if DefaultAgentPageSize > MaxAgentPageSize {
		t.Errorf("DefaultAgentPageSize (%d) exceeds MaxAgentPageSize (%d)", DefaultAgentPageSize, MaxAgentPageSize)
	}
}
