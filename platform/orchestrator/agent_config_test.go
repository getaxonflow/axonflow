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
	"os"
	"path/filepath"
	"testing"
	"time"
)

// validTravelConfig is a valid agent configuration for testing
const validTravelConfig = `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: travel-domain
  domain: travel
  description: "Travel planning agents"
spec:
  execution:
    default_mode: parallel
    max_parallel_tasks: 5
    timeout_seconds: 300
    hints: "Travel planning typically involves independent research tasks that can be parallelized."
  agents:
    - name: flight_search
      description: "Searches for available flights"
      type: llm-call
      llm:
        provider: anthropic
        model: claude-3-sonnet
        temperature: 0.3
        max_tokens: 2000
      prompt_template: "Search for flights from {{.origin}} to {{.destination}} on {{.date}}"
    - name: hotel_search
      description: "Searches for available hotels"
      type: connector-call
      connector:
        name: amadeus-travel
        operation: query
      parameters:
        max_results: 10
  routing:
    - pattern: "flight.*search|search.*flight"
      agent: flight_search
      priority: 10
    - pattern: "hotel.*search|search.*hotel"
      agent: hotel_search
      connector: amadeus-travel
      priority: 10
  synthesis:
    enabled: true
    prompt_template: "Combine flight and hotel results into a complete travel plan."
`

func TestParseAgentConfig_ValidConfig(t *testing.T) {
	config, err := ParseAgentConfig([]byte(validTravelConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify metadata
	if config.Metadata.Name != "travel-domain" {
		t.Errorf("expected name 'travel-domain', got '%s'", config.Metadata.Name)
	}
	if config.Metadata.Domain != "travel" {
		t.Errorf("expected domain 'travel', got '%s'", config.Metadata.Domain)
	}

	// Verify execution config
	if config.Spec.Execution.DefaultMode != "parallel" {
		t.Errorf("expected default_mode 'parallel', got '%s'", config.Spec.Execution.DefaultMode)
	}
	if config.Spec.Execution.MaxParallelTasks != 5 {
		t.Errorf("expected max_parallel_tasks 5, got %d", config.Spec.Execution.MaxParallelTasks)
	}

	// Verify agents
	if len(config.Spec.Agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(config.Spec.Agents))
	}

	// Verify first agent (LLM call)
	flightAgent := config.Spec.Agents[0]
	if flightAgent.Name != "flight_search" {
		t.Errorf("expected agent name 'flight_search', got '%s'", flightAgent.Name)
	}
	if flightAgent.Type != "llm-call" {
		t.Errorf("expected type 'llm-call', got '%s'", flightAgent.Type)
	}
	if flightAgent.LLM.Provider != "anthropic" {
		t.Errorf("expected provider 'anthropic', got '%s'", flightAgent.LLM.Provider)
	}

	// Verify second agent (connector call)
	hotelAgent := config.Spec.Agents[1]
	if hotelAgent.Type != "connector-call" {
		t.Errorf("expected type 'connector-call', got '%s'", hotelAgent.Type)
	}
	if hotelAgent.Connector.Name != "amadeus-travel" {
		t.Errorf("expected connector 'amadeus-travel', got '%s'", hotelAgent.Connector.Name)
	}

	// Verify routing
	if len(config.Spec.Routing) != 2 {
		t.Errorf("expected 2 routing rules, got %d", len(config.Spec.Routing))
	}

	// Verify synthesis
	if !config.Spec.Synthesis.Enabled {
		t.Error("expected synthesis to be enabled")
	}
}

func TestParseAgentConfig_InvalidYAML(t *testing.T) {
	invalidYAML := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: [invalid yaml
`
	_, err := ParseAgentConfig([]byte(invalidYAML))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestParseAgentConfig_InvalidAPIVersion(t *testing.T) {
	config := `
apiVersion: kubernetes.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for invalid apiVersion")
	}
}

func TestParseAgentConfig_InvalidKind(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: Workflow
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for invalid kind")
	}
}

func TestParseAgentConfig_MissingName(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for missing name")
	}
}

func TestParseAgentConfig_MissingDomain(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for missing domain")
	}
}

func TestParseAgentConfig_InvalidAgentName(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: "Invalid Name!"
      type: llm-call
      prompt_template: "test"
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for invalid agent name")
	}
}

func TestParseAgentConfig_InvalidAgentType(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: invalid-type
      prompt_template: "test"
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for invalid agent type")
	}
}

func TestParseAgentConfig_LLMCallWithoutConfig(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for llm-call without llm config or prompt_template")
	}
}

func TestParseAgentConfig_ConnectorCallWithoutConnector(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: connector-call
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for connector-call without connector config")
	}
}

func TestParseAgentConfig_DuplicateAgentNames(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
    - name: test_agent
      type: llm-call
      prompt_template: "test2"
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for duplicate agent names")
	}
}

func TestParseAgentConfig_InvalidRegex(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
  routing:
    - pattern: "[invalid(regex"
      agent: test_agent
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestParseAgentConfig_RoutingToNonexistentAgent(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
  routing:
    - pattern: "test.*"
      agent: nonexistent_agent
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for routing to nonexistent agent")
	}
}

func TestParseAgentConfig_InvalidExecutionMode(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution:
    default_mode: invalid_mode
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for invalid execution mode")
	}
}

func TestParseAgentConfig_NegativeMaxParallelTasks(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution:
    max_parallel_tasks: -1
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for negative max_parallel_tasks")
	}
}

func TestParseAgentConfig_NegativeTimeout(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution:
    timeout_seconds: -1
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for negative timeout")
	}
}

func TestParseAgentConfig_InvalidTemperature(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      llm:
        provider: openai
        model: gpt-4
        temperature: 5.0
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for invalid temperature")
	}
}

func TestParseAgentConfig_NegativeMaxTokens(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      llm:
        provider: openai
        model: gpt-4
        max_tokens: -100
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for negative max_tokens")
	}
}

func TestParseAgentConfig_MissingLLMProvider(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      llm:
        model: gpt-4
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for missing LLM provider")
	}
}

func TestParseAgentConfig_MissingLLMModel(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      llm:
        provider: openai
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for missing LLM model")
	}
}

func TestParseAgentConfig_MissingConnectorName(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: connector-call
      connector:
        operation: query
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for missing connector name")
	}
}

func TestParseAgentConfig_MissingConnectorOperation(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: connector-call
      connector:
        name: postgres
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for missing connector operation")
	}
}

func TestParseAgentConfig_NoAgents(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents: []
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for no agents")
	}
}

func TestParseAgentConfig_EmptyRoutingPattern(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
  routing:
    - pattern: ""
      agent: test_agent
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for empty routing pattern")
	}
}

func TestParseAgentConfig_EmptyRoutingAgent(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
  routing:
    - pattern: "test.*"
      agent: ""
`
	_, err := ParseAgentConfig([]byte(config))
	if err == nil {
		t.Error("expected error for empty routing agent")
	}
}

func TestLoadAgentConfig_FileNotFound(t *testing.T) {
	_, err := LoadAgentConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadAgentConfig_ValidFile(t *testing.T) {
	// Create temp directory and file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	err := os.WriteFile(configPath, []byte(validTravelConfig), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	config, err := LoadAgentConfig(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.Metadata.Name != "travel-domain" {
		t.Errorf("expected name 'travel-domain', got '%s'", config.Metadata.Name)
	}
}

func TestCompileRoutingRules(t *testing.T) {
	config, err := ParseAgentConfig([]byte(validTravelConfig))
	if err != nil {
		t.Fatalf("unexpected error parsing config: %v", err)
	}

	rules, err := CompileRoutingRules(config)
	if err != nil {
		t.Fatalf("unexpected error compiling rules: %v", err)
	}

	if len(rules) != 2 {
		t.Errorf("expected 2 compiled rules, got %d", len(rules))
	}

	// Test pattern matching
	if !rules[0].Pattern.MatchString("flight search for Paris") {
		t.Error("expected pattern to match 'flight search for Paris'")
	}

	if !rules[1].Pattern.MatchString("search for hotel") {
		t.Error("expected pattern to match 'search for hotel'")
	}
}

func TestCompileRoutingRules_NilConfig(t *testing.T) {
	_, err := CompileRoutingRules(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestCompileRoutingRules_Priority(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: agent_low
      type: llm-call
      prompt_template: "test"
    - name: agent_high
      type: llm-call
      prompt_template: "test"
  routing:
    - pattern: "test.*"
      agent: agent_low
      priority: 1
    - pattern: "test.*"
      agent: agent_high
      priority: 10
`
	cfg, err := ParseAgentConfig([]byte(config))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rules, err := CompileRoutingRules(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Higher priority should be first
	if rules[0].Rule.Agent != "agent_high" {
		t.Errorf("expected agent_high first (priority 10), got %s", rules[0].Rule.Agent)
	}
	if rules[1].Rule.Agent != "agent_low" {
		t.Errorf("expected agent_low second (priority 1), got %s", rules[1].Rule.Agent)
	}
}

func TestValidateAgentConfig_Nil(t *testing.T) {
	err := ValidateAgentConfig(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestGetDefaultExecutionConfig(t *testing.T) {
	config := GetDefaultExecutionConfig()

	if config.DefaultMode != "auto" {
		t.Errorf("expected default mode 'auto', got '%s'", config.DefaultMode)
	}
	if config.MaxParallelTasks != 5 {
		t.Errorf("expected max_parallel_tasks 5, got %d", config.MaxParallelTasks)
	}
	if config.TimeoutSeconds != 300 {
		t.Errorf("expected timeout_seconds 300, got %d", config.TimeoutSeconds)
	}
}

func TestExecutionConfig_GetDefaultTimeout(t *testing.T) {
	tests := []struct {
		name     string
		timeout  int
		expected time.Duration
	}{
		{"positive", 60, 60 * time.Second},
		{"zero", 0, 5 * time.Minute},
		{"negative", -1, 5 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ExecutionConfig{TimeoutSeconds: tt.timeout}
			if got := config.GetDefaultTimeout(); got != tt.expected {
				t.Errorf("GetDefaultTimeout() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecutionConfig_IsParallel(t *testing.T) {
	tests := []struct {
		mode     string
		expected bool
	}{
		{"parallel", true},
		{"sequential", false},
		{"auto", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			config := &ExecutionConfig{DefaultMode: tt.mode}
			if got := config.IsParallel(); got != tt.expected {
				t.Errorf("IsParallel() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecutionConfig_IsSequential(t *testing.T) {
	tests := []struct {
		mode     string
		expected bool
	}{
		{"sequential", true},
		{"parallel", false},
		{"auto", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			config := &ExecutionConfig{DefaultMode: tt.mode}
			if got := config.IsSequential(); got != tt.expected {
				t.Errorf("IsSequential() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAgentConfigFile_ToDomainTemplate(t *testing.T) {
	config, err := ParseAgentConfig([]byte(validTravelConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	template := config.ToDomainTemplate()

	if template.Domain != "travel" {
		t.Errorf("expected domain 'travel', got '%s'", template.Domain)
	}

	if len(template.CommonTasks) != 2 {
		t.Errorf("expected 2 common tasks, got %d", len(template.CommonTasks))
	}

	if template.CommonTasks[0] != "flight_search" {
		t.Errorf("expected first task 'flight_search', got '%s'", template.CommonTasks[0])
	}
}

func TestAgentConfigFile_GetAgent(t *testing.T) {
	config, err := ParseAgentConfig([]byte(validTravelConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test existing agent
	agent, found := config.GetAgent("flight_search")
	if !found {
		t.Error("expected to find flight_search agent")
	}
	if agent.Name != "flight_search" {
		t.Errorf("expected agent name 'flight_search', got '%s'", agent.Name)
	}

	// Test non-existent agent
	_, found = config.GetAgent("nonexistent")
	if found {
		t.Error("did not expect to find nonexistent agent")
	}
}

func TestAgentConfigFile_GetSynthesisPrompt(t *testing.T) {
	config, err := ParseAgentConfig([]byte(validTravelConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	prompt := config.GetSynthesisPrompt()
	if prompt == "" {
		t.Error("expected non-empty synthesis prompt")
	}
	if prompt != "Combine flight and hotel results into a complete travel plan." {
		t.Errorf("unexpected synthesis prompt: %s", prompt)
	}
}

func TestAgentConfigFile_GetSynthesisPrompt_Disabled(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
  routing: []
  synthesis:
    enabled: false
    prompt_template: "should not be returned"
`
	cfg, err := ParseAgentConfig([]byte(config))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	prompt := cfg.GetSynthesisPrompt()
	if prompt != "" {
		t.Errorf("expected empty synthesis prompt when disabled, got '%s'", prompt)
	}
}

func TestIsValidIdentifier(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"valid-name", true},
		{"valid_name", true},
		{"valid123", true},
		{"a", true},
		{"abc-def_123", true},
		{"-invalid", false},
		{"_invalid", false},
		{"Invalid", false},
		{"INVALID", false},
		{"invalid name", false},
		{"invalid.name", false},
		{"", false},
		{"a-", true}, // trailing hyphen is allowed
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isValidIdentifier(tt.input); got != tt.expected {
				t.Errorf("isValidIdentifier(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestValidateRegexPattern_DangerousPattern(t *testing.T) {
	// This test documents that we check for dangerous patterns
	// Note: Our simple check may not catch all ReDoS patterns
	tests := []struct {
		pattern string
		valid   bool
	}{
		{"simple.*pattern", true},
		{"flight|hotel|car", true},
		{"^[a-z]+$", true},
		{"test(a+)+", false}, // Nested quantifier
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			err := validateRegexPattern(tt.pattern)
			if tt.valid && err != nil {
				t.Errorf("expected pattern %q to be valid, got error: %v", tt.pattern, err)
			}
			if !tt.valid && err == nil {
				t.Errorf("expected pattern %q to be invalid, but it was accepted", tt.pattern)
			}
		})
	}
}

func TestValidateRegexPattern_TooLong(t *testing.T) {
	longPattern := ""
	for i := 0; i < 1001; i++ {
		longPattern += "a"
	}

	err := validateRegexPattern(longPattern)
	if err == nil {
		t.Error("expected error for pattern exceeding 1000 characters")
	}
}

func TestParseAgentConfig_ValidMetadataNameWithNumbers(t *testing.T) {
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: domain-v2
  domain: test
spec:
  execution: {}
  agents:
    - name: agent1
      type: llm-call
      prompt_template: "test"
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err != nil {
		t.Errorf("unexpected error for valid name with numbers: %v", err)
	}
}

func TestParseAgentConfig_EmptyExecutionMode(t *testing.T) {
	// Empty execution mode should be allowed (defaults to auto)
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution: {}
  agents:
    - name: test_agent
      type: llm-call
      prompt_template: "test"
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err != nil {
		t.Errorf("unexpected error for empty execution mode: %v", err)
	}
}

func TestParseAgentConfig_ZeroValues(t *testing.T) {
	// Zero values for optional numeric fields should be allowed
	config := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: test
  domain: test
spec:
  execution:
    max_parallel_tasks: 0
    timeout_seconds: 0
  agents:
    - name: test_agent
      type: llm-call
      llm:
        provider: openai
        model: gpt-4
        temperature: 0
        max_tokens: 0
  routing: []
`
	_, err := ParseAgentConfig([]byte(config))
	if err != nil {
		t.Errorf("unexpected error for zero values: %v", err)
	}
}

func TestParseAgentConfig_Healthcare(t *testing.T) {
	healthcareConfig := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: healthcare-domain
  domain: healthcare
  description: "Healthcare diagnostic agents"
spec:
  execution:
    default_mode: sequential
    max_parallel_tasks: 2
    timeout_seconds: 600
    hints: "Medical diagnosis requires sequential analysis."
  agents:
    - name: symptom_analyzer
      description: "Analyzes patient symptoms"
      type: llm-call
      llm:
        provider: anthropic
        model: claude-3-sonnet
        temperature: 0.2
        max_tokens: 3000
      prompt_template: |
        Analyze symptoms: {{.symptoms}}
        Medical history: {{.history}}
    - name: patient_db_query
      description: "Queries patient database"
      type: connector-call
      connector:
        name: postgres
        operation: query
      parameters:
        query_template: "SELECT * FROM patients WHERE id = {{.patient_id}}"
  routing:
    - pattern: "symptom.*analysis|analyze.*symptom"
      agent: symptom_analyzer
      priority: 10
    - pattern: "patient.*record|medical.*history"
      agent: patient_db_query
      connector: postgres
      priority: 5
  synthesis:
    enabled: true
    prompt_template: |
      Create a diagnostic report from:
      Symptom Analysis: {{.symptom_analysis}}
      Patient History: {{.patient_history}}
`
	config, err := ParseAgentConfig([]byte(healthcareConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.Metadata.Domain != "healthcare" {
		t.Errorf("expected domain 'healthcare', got '%s'", config.Metadata.Domain)
	}

	if config.Spec.Execution.DefaultMode != "sequential" {
		t.Errorf("expected sequential mode for healthcare, got '%s'", config.Spec.Execution.DefaultMode)
	}
}

func TestParseAgentConfig_Finance(t *testing.T) {
	financeConfig := `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: finance-domain
  domain: finance
  description: "Financial analysis agents"
spec:
  execution:
    default_mode: parallel
    max_parallel_tasks: 10
    timeout_seconds: 120
    hints: "Financial analysis involves parallel data gathering followed by synthesis."
  agents:
    - name: market_data
      description: "Fetches market data"
      type: connector-call
      connector:
        name: market-data-api
        operation: query
    - name: sentiment_analyzer
      description: "Analyzes news sentiment"
      type: llm-call
      llm:
        provider: openai
        model: gpt-4-turbo
        temperature: 0.1
      prompt_template: "Analyze sentiment: {{.news}}"
  routing:
    - pattern: "market.*data|stock.*price"
      agent: market_data
    - pattern: "sentiment|news.*analysis"
      agent: sentiment_analyzer
  synthesis:
    enabled: true
    prompt_template: "Create investment recommendation based on market data and sentiment."
`
	config, err := ParseAgentConfig([]byte(financeConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.Metadata.Domain != "finance" {
		t.Errorf("expected domain 'finance', got '%s'", config.Metadata.Domain)
	}

	if config.Spec.Execution.MaxParallelTasks != 10 {
		t.Errorf("expected max_parallel_tasks 10, got %d", config.Spec.Execution.MaxParallelTasks)
	}
}
