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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestRegistry creates a registry with test data
func createTestRegistry() *AgentRegistry {
	registry := NewAgentRegistry()

	// Register travel domain
	travelConfig := &AgentConfigFile{
		APIVersion: "axonflow.io/v1",
		Kind:       "AgentConfig",
		Metadata: AgentMetadata{
			Name:        "travel-domain",
			Domain:      "travel",
			Description: "Travel planning agents",
		},
		Spec: AgentConfigSpec{
			Execution: GetDefaultExecutionConfig(),
			Agents: []AgentDef{
				{
					Name:        "flight-search",
					Description: "Searches for flights",
					Type:        "connector-call",
					Connector: &ConnectorRef{
						Name:      "amadeus-travel",
						Operation: "query",
					},
				},
				{
					Name:        "hotel-search",
					Description: "Searches for hotels",
					Type:        "connector-call",
					Connector: &ConnectorRef{
						Name:      "amadeus-travel",
						Operation: "query",
					},
				},
			},
			Routing: []RoutingRule{
				{Pattern: "flight|fly", Agent: "flight-search", Priority: 10},
				{Pattern: "hotel|stay", Agent: "hotel-search", Priority: 10},
			},
		},
	}
	_ = registry.RegisterConfig(travelConfig)

	// Register healthcare domain
	healthcareConfig := &AgentConfigFile{
		APIVersion: "axonflow.io/v1",
		Kind:       "AgentConfig",
		Metadata: AgentMetadata{
			Name:        "healthcare-domain",
			Domain:      "healthcare",
			Description: "Healthcare agents",
		},
		Spec: AgentConfigSpec{
			Execution: GetDefaultExecutionConfig(),
			Agents: []AgentDef{
				{
					Name:           "patient-lookup",
					Description:    "Looks up patient information",
					Type:           "llm-call",
					PromptTemplate: "Look up patient: {{.query}}",
				},
			},
			Routing: []RoutingRule{
				{Pattern: "patient|medical", Agent: "patient-lookup", Priority: 10},
			},
		},
	}
	_ = registry.RegisterConfig(healthcareConfig)

	return registry
}

func TestAgentsAPIHandler_ListAgents(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	w := httptest.NewRecorder()

	handler.handleAgents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response AgentListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Should have agents from both domains
	assert.GreaterOrEqual(t, len(response.Agents), 3)
	assert.Equal(t, len(response.Agents), response.Pagination.TotalItems)
}

func TestAgentsAPIHandler_ListAgents_WithDomainFilter(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents?domain=travel", nil)
	w := httptest.NewRecorder()

	handler.handleAgents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response AgentListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Should only have travel agents
	assert.Equal(t, 2, len(response.Agents))
	for _, agent := range response.Agents {
		assert.Equal(t, "travel", agent.Domain)
	}
}

func TestAgentsAPIHandler_ListAgents_Pagination(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents?page=1&page_size=2", nil)
	w := httptest.NewRecorder()

	handler.handleAgents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response AgentListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.LessOrEqual(t, len(response.Agents), 2)
	assert.Equal(t, 1, response.Pagination.Page)
	assert.Equal(t, 2, response.Pagination.PageSize)
}

func TestAgentsAPIHandler_GetAgent(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/flight-search", nil)
	w := httptest.NewRecorder()

	handler.handleAgentByID(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response AgentResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotNil(t, response.Agent)
	assert.Equal(t, "flight-search", response.Agent.Name)
	assert.Equal(t, "travel", response.Agent.Domain)
}

func TestAgentsAPIHandler_GetAgent_NotFound(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/nonexistent-agent", nil)
	w := httptest.NewRecorder()

	handler.handleAgentByID(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response AgentAPIError
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "NOT_FOUND", response.Error.Code)
}

func TestAgentsAPIHandler_GetAgent_EmptyID(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/", nil)
	w := httptest.NewRecorder()

	handler.handleAgentByID(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAgentsAPIHandler_ListAgentsByDomain(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/domain/travel", nil)
	w := httptest.NewRecorder()

	handler.handleAgentsByDomain(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response AgentListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, 2, len(response.Agents))
	for _, agent := range response.Agents {
		assert.Equal(t, "travel", agent.Domain)
	}
}

func TestAgentsAPIHandler_ListAgentsByDomain_NotFound(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/domain/nonexistent", nil)
	w := httptest.NewRecorder()

	handler.handleAgentsByDomain(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAgentsAPIHandler_ListAgentsByDomain_EmptyDomain(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/domain/", nil)
	w := httptest.NewRecorder()

	handler.handleAgentsByDomain(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAgentsAPIHandler_ValidateConfig_Valid(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	reqBody := ValidateAgentConfigRequest{
		Name:   "valid-agent",
		Domain: "test",
		Config: AgentConfigSpec{
			Execution: GetDefaultExecutionConfig(),
			Agents: []AgentDef{
				{
					Name:        "test-agent",
					Description: "A test agent",
					Type:        "llm-call",
					LLM: &LLMAgentConfig{
						Provider:    "anthropic",
						Model:       "claude-3-sonnet",
						Temperature: 0.7,
					},
				},
			},
			Routing: []RoutingRule{
				{Pattern: "test.*", Agent: "test-agent", Priority: 10},
			},
		},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleValidate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ValidateAgentConfigResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response.Valid)
	assert.Empty(t, response.Errors)
	assert.Contains(t, response.Summary, "valid")
}

func TestAgentsAPIHandler_ValidateConfig_Invalid(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	tests := []struct {
		name         string
		req          ValidateAgentConfigRequest
		expectErrors int
	}{
		{
			name: "empty agents",
			req: ValidateAgentConfigRequest{
				Name: "valid-name",
				Config: AgentConfigSpec{
					Agents: []AgentDef{},
				},
			},
			expectErrors: 1,
		},
		{
			name: "invalid name format",
			req: ValidateAgentConfigRequest{
				Name: "Invalid_NAME",
				Config: AgentConfigSpec{
					Agents: []AgentDef{
						{
							Name: "agent",
							Type: "llm-call",
							LLM: &LLMAgentConfig{
								Provider: "anthropic",
								Model:    "claude-3-sonnet",
							},
						},
					},
				},
			},
			expectErrors: 1,
		},
		{
			name: "invalid agent type",
			req: ValidateAgentConfigRequest{
				Name: "valid-name",
				Config: AgentConfigSpec{
					Agents: []AgentDef{
						{Name: "agent", Type: "invalid-type"},
					},
				},
			},
			expectErrors: 1,
		},
		{
			name: "missing llm config for llm-call",
			req: ValidateAgentConfigRequest{
				Name: "valid-name",
				Config: AgentConfigSpec{
					Agents: []AgentDef{
						{Name: "agent", Type: "llm-call"},
					},
				},
			},
			expectErrors: 1,
		},
		{
			name: "missing connector config for connector-call",
			req: ValidateAgentConfigRequest{
				Name: "valid-name",
				Config: AgentConfigSpec{
					Agents: []AgentDef{
						{Name: "agent", Type: "connector-call"},
					},
				},
			},
			expectErrors: 1,
		},
		{
			name: "routing references unknown agent",
			req: ValidateAgentConfigRequest{
				Name: "valid-name",
				Config: AgentConfigSpec{
					Agents: []AgentDef{
						{
							Name: "real-agent",
							Type: "llm-call",
							LLM: &LLMAgentConfig{
								Provider: "anthropic",
								Model:    "claude-3-sonnet",
							},
						},
					},
					Routing: []RoutingRule{
						{Pattern: "test.*", Agent: "unknown-agent"},
					},
				},
			},
			expectErrors: 1,
		},
		{
			name: "invalid regex pattern",
			req: ValidateAgentConfigRequest{
				Name: "valid-name",
				Config: AgentConfigSpec{
					Agents: []AgentDef{
						{
							Name: "agent",
							Type: "llm-call",
							LLM: &LLMAgentConfig{
								Provider: "anthropic",
								Model:    "claude-3-sonnet",
							},
						},
					},
					Routing: []RoutingRule{
						{Pattern: "[invalid", Agent: "agent"},
					},
				},
			},
			expectErrors: 1,
		},
		{
			name: "duplicate agent names",
			req: ValidateAgentConfigRequest{
				Name: "valid-name",
				Config: AgentConfigSpec{
					Agents: []AgentDef{
						{
							Name: "duplicate",
							Type: "llm-call",
							LLM: &LLMAgentConfig{
								Provider: "anthropic",
								Model:    "claude-3-sonnet",
							},
						},
						{
							Name: "duplicate",
							Type: "llm-call",
							LLM: &LLMAgentConfig{
								Provider: "anthropic",
								Model:    "claude-3-sonnet",
							},
						},
					},
				},
			},
			expectErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/validate", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.handleValidate(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			var response ValidateAgentConfigResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.False(t, response.Valid)
			assert.GreaterOrEqual(t, len(response.Errors), tt.expectErrors)
		})
	}
}

func TestAgentsAPIHandler_ValidateConfig_InvalidJSON(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/validate", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleValidate(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response AgentAPIError
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "INVALID_JSON", response.Error.Code)
}

func TestAgentsAPIHandler_MethodNotAllowed(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	tests := []struct {
		name    string
		method  string
		path    string
		handler func(w http.ResponseWriter, r *http.Request)
	}{
		{"POST to list", http.MethodPost, "/api/v1/agents", handler.handleAgents},
		{"PUT to list", http.MethodPut, "/api/v1/agents", handler.handleAgents},
		{"DELETE to list", http.MethodDelete, "/api/v1/agents", handler.handleAgents},
		{"POST to agent", http.MethodPost, "/api/v1/agents/test", handler.handleAgentByID},
		{"GET to validate", http.MethodGet, "/api/v1/agents/validate", handler.handleValidate},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			tt.handler(w, req)

			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
		})
	}
}

func TestAgentsAPIHandler_CORS(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/agents", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()

	handler.handleAgents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestIsValidAgentIdentifier(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"valid-name", true},
		{"valid_name", true},
		{"validname123", true},
		{"valid-name-123", true},
		{"a", true},
		{"123valid", true},
		{"", false},
		{"-invalid", false},
		{"_invalid", false},
		{"Invalid", false},
		{"INVALID", false},
		{"invalid name", false},
		{"invalid.name", false},
		{"invalid@name", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isValidAgentIdentifier(tt.input)
			assert.Equal(t, tt.expected, result, "isValidAgentIdentifier(%q)", tt.input)
		})
	}
}

func TestAgentsAPIHandler_RegisterRoutes(t *testing.T) {
	registry := createTestRegistry()
	handler := NewAgentsAPIHandler(registry)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Verify routes are registered by making requests
	tests := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/api/v1/agents", http.StatusOK},
		{http.MethodGet, "/api/v1/agents/flight-search", http.StatusOK},
		{http.MethodGet, "/api/v1/agents/domain/travel", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)

			assert.Equal(t, tt.status, w.Code)
		})
	}
}

func TestFromAgentConfigFile(t *testing.T) {
	config := &AgentConfigFile{
		APIVersion: "axonflow.io/v1",
		Kind:       "AgentConfig",
		Metadata: AgentMetadata{
			Name:        "test-config",
			Domain:      "test",
			Description: "Test configuration",
		},
		Spec: AgentConfigSpec{
			Execution: GetDefaultExecutionConfig(),
			Agents: []AgentDef{
				{
					Name: "test-agent",
					Type: "llm-call",
				},
			},
		},
	}

	resource := FromAgentConfigFile(config, "file")

	assert.NotNil(t, resource)
	assert.Equal(t, "test-config", resource.ID)
	assert.Equal(t, "test-config", resource.Name)
	assert.Equal(t, "test", resource.Domain)
	assert.Equal(t, "Test configuration", resource.Description)
	assert.True(t, resource.IsActive)
	assert.Equal(t, "file", resource.Source)
	assert.NotNil(t, resource.Spec)
}

func TestFromAgentConfigFile_Nil(t *testing.T) {
	resource := FromAgentConfigFile(nil, "file")
	assert.Nil(t, resource)
}
