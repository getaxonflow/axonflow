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
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// AgentConfigFile represents a complete agent configuration file
// following the Kubernetes-style apiVersion/kind pattern
type AgentConfigFile struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   AgentMetadata   `yaml:"metadata"`
	Spec       AgentConfigSpec `yaml:"spec"`
}

// AgentMetadata contains identification and description for the agent config
type AgentMetadata struct {
	Name        string `yaml:"name"`
	Domain      string `yaml:"domain"`
	Description string `yaml:"description"`
}

// AgentConfigSpec defines the complete specification for a domain's agents
type AgentConfigSpec struct {
	Execution ExecutionConfig `yaml:"execution"`
	Agents    []AgentDef      `yaml:"agents"`
	Routing   []RoutingRule   `yaml:"routing"`
	Synthesis SynthesisConfig `yaml:"synthesis"`
}

// ExecutionConfig provides hints for the planning engine
type ExecutionConfig struct {
	DefaultMode      string `yaml:"default_mode"`       // sequential, parallel, auto
	MaxParallelTasks int    `yaml:"max_parallel_tasks"` // Maximum concurrent tasks
	TimeoutSeconds   int    `yaml:"timeout_seconds"`    // Default timeout for operations
	Hints            string `yaml:"hints"`              // Natural language hints for the planner
}

// AgentDef defines a single agent within a configuration
type AgentDef struct {
	Name           string             `yaml:"name"`
	Description    string             `yaml:"description"`
	Type           string             `yaml:"type"` // llm-call, connector-call
	LLM            *LLMAgentConfig    `yaml:"llm,omitempty"`
	Connector      *ConnectorRef      `yaml:"connector,omitempty"`
	PromptTemplate string             `yaml:"prompt_template,omitempty"`
	Parameters     map[string]any     `yaml:"parameters,omitempty"`
}

// LLMAgentConfig specifies LLM settings for an agent
type LLMAgentConfig struct {
	Provider    string  `yaml:"provider"`    // anthropic, openai, bedrock
	Model       string  `yaml:"model"`       // claude-3-sonnet, gpt-4-turbo, etc.
	Temperature float64 `yaml:"temperature"` // 0.0 - 1.0
	MaxTokens   int     `yaml:"max_tokens"`  // Maximum response tokens
}

// ConnectorRef references an MCP connector for data access
type ConnectorRef struct {
	Name      string `yaml:"name"`      // Connector name (postgres, amadeus-travel, etc.)
	Operation string `yaml:"operation"` // query, mutation, etc.
}

// RoutingRule maps task descriptions to agents via regex patterns
type RoutingRule struct {
	Pattern   string `yaml:"pattern"`             // Regex pattern to match task descriptions
	Agent     string `yaml:"agent"`               // Agent name to route to
	Connector string `yaml:"connector,omitempty"` // Optional connector for connector-call types
	Priority  int    `yaml:"priority,omitempty"`  // Higher priority rules match first
}

// SynthesisConfig defines how results are combined
type SynthesisConfig struct {
	Enabled        bool   `yaml:"enabled"`
	PromptTemplate string `yaml:"prompt_template"`
}

// CompiledRoutingRule is a routing rule with pre-compiled regex
type CompiledRoutingRule struct {
	Rule    RoutingRule
	Pattern *regexp.Regexp
	Domain  string // Domain this rule belongs to (set during registry loading)
}

// Configuration constants
const (
	// MaxLLMTemperature is the maximum allowed temperature for LLM calls
	MaxLLMTemperature = 2.0

	// MaxPatternLength is the maximum allowed length for routing patterns (ReDoS prevention)
	MaxPatternLength = 1000

	// DefaultMaxParallelTasks is the default number of concurrent tasks
	DefaultMaxParallelTasks = 5

	// DefaultTimeoutSeconds is the default timeout for agent operations
	DefaultTimeoutSeconds = 300

	// DefaultExecutionMode is the default execution strategy
	DefaultExecutionMode = "auto"
)

// ValidAgentTypes lists the allowed agent types
var ValidAgentTypes = map[string]bool{
	"llm-call":       true,
	"connector-call": true,
}

// ValidExecutionModes lists the allowed execution modes
var ValidExecutionModes = map[string]bool{
	"sequential": true,
	"parallel":   true,
	"auto":       true,
}

// LoadAgentConfig loads and parses an agent configuration file
func LoadAgentConfig(path string) (*AgentConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	return ParseAgentConfig(data)
}

// ParseAgentConfig parses YAML data into an AgentConfigFile
func ParseAgentConfig(data []byte) (*AgentConfigFile, error) {
	var config AgentConfigFile
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Validate the configuration
	if err := ValidateAgentConfig(&config); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return &config, nil
}

// ValidateAgentConfig validates an agent configuration for correctness
func ValidateAgentConfig(config *AgentConfigFile) error {
	if config == nil {
		return fmt.Errorf("config is nil")
	}

	// Validate API version and kind
	if !strings.HasPrefix(config.APIVersion, "axonflow.io/") {
		return fmt.Errorf("invalid apiVersion: must start with 'axonflow.io/', got '%s'", config.APIVersion)
	}

	if config.Kind != "AgentConfig" {
		return fmt.Errorf("invalid kind: expected 'AgentConfig', got '%s'", config.Kind)
	}

	// Validate metadata
	if err := validateMetadata(&config.Metadata); err != nil {
		return fmt.Errorf("metadata validation failed: %w", err)
	}

	// Validate spec
	if err := validateSpec(&config.Spec); err != nil {
		return fmt.Errorf("spec validation failed: %w", err)
	}

	return nil
}

// validateMetadata validates the metadata section
func validateMetadata(metadata *AgentMetadata) error {
	if metadata.Name == "" {
		return fmt.Errorf("name is required")
	}

	if metadata.Domain == "" {
		return fmt.Errorf("domain is required")
	}

	// Validate name format (lowercase alphanumeric with hyphens)
	if !isValidIdentifier(metadata.Name) {
		return fmt.Errorf("name '%s' is invalid: must be lowercase alphanumeric with hyphens", metadata.Name)
	}

	return nil
}

// validateSpec validates the spec section
func validateSpec(spec *AgentConfigSpec) error {
	// Validate execution config
	if err := validateExecutionConfig(&spec.Execution); err != nil {
		return fmt.Errorf("execution config invalid: %w", err)
	}

	// Validate agents
	if len(spec.Agents) == 0 {
		return fmt.Errorf("at least one agent is required")
	}

	agentNames := make(map[string]bool)
	for i, agent := range spec.Agents {
		if err := validateAgent(&agent, i); err != nil {
			return fmt.Errorf("agent %d (%s) invalid: %w", i, agent.Name, err)
		}

		if agentNames[agent.Name] {
			return fmt.Errorf("duplicate agent name: %s", agent.Name)
		}
		agentNames[agent.Name] = true
	}

	// Validate routing rules
	for i, rule := range spec.Routing {
		if err := validateRoutingRule(&rule, i, agentNames); err != nil {
			return fmt.Errorf("routing rule %d invalid: %w", i, err)
		}
	}

	return nil
}

// validateExecutionConfig validates execution configuration
func validateExecutionConfig(config *ExecutionConfig) error {
	// Default mode validation (allow empty for default)
	if config.DefaultMode != "" && !ValidExecutionModes[config.DefaultMode] {
		return fmt.Errorf("invalid default_mode '%s': must be one of sequential, parallel, auto", config.DefaultMode)
	}

	// Validate max_parallel_tasks
	if config.MaxParallelTasks < 0 {
		return fmt.Errorf("max_parallel_tasks cannot be negative")
	}

	// Validate timeout
	if config.TimeoutSeconds < 0 {
		return fmt.Errorf("timeout_seconds cannot be negative")
	}

	return nil
}

// validateAgent validates a single agent definition
func validateAgent(agent *AgentDef, index int) error {
	if agent.Name == "" {
		return fmt.Errorf("name is required")
	}

	if !isValidIdentifier(agent.Name) {
		return fmt.Errorf("name '%s' is invalid: must be lowercase alphanumeric with hyphens and underscores", agent.Name)
	}

	if agent.Type == "" {
		return fmt.Errorf("type is required")
	}

	if !ValidAgentTypes[agent.Type] {
		return fmt.Errorf("invalid type '%s': must be one of llm-call, connector-call", agent.Type)
	}

	// Type-specific validation
	switch agent.Type {
	case "llm-call":
		if agent.LLM == nil && agent.PromptTemplate == "" {
			return fmt.Errorf("llm-call agent requires llm config or prompt_template")
		}
		if agent.LLM != nil {
			if err := validateLLMConfig(agent.LLM); err != nil {
				return fmt.Errorf("llm config invalid: %w", err)
			}
		}
	case "connector-call":
		if agent.Connector == nil {
			return fmt.Errorf("connector-call agent requires connector config")
		}
		if err := validateConnectorRef(agent.Connector); err != nil {
			return fmt.Errorf("connector config invalid: %w", err)
		}
	}

	return nil
}

// validateLLMConfig validates LLM configuration
func validateLLMConfig(llm *LLMAgentConfig) error {
	if llm.Provider == "" {
		return fmt.Errorf("provider is required")
	}

	if llm.Model == "" {
		return fmt.Errorf("model is required")
	}

	// Temperature validation
	if llm.Temperature < 0 || llm.Temperature > MaxLLMTemperature {
		return fmt.Errorf("temperature must be between 0 and %.1f", MaxLLMTemperature)
	}

	// MaxTokens validation
	if llm.MaxTokens < 0 {
		return fmt.Errorf("max_tokens cannot be negative")
	}

	return nil
}

// validateConnectorRef validates connector reference
func validateConnectorRef(conn *ConnectorRef) error {
	if conn.Name == "" {
		return fmt.Errorf("name is required")
	}

	if conn.Operation == "" {
		return fmt.Errorf("operation is required")
	}

	return nil
}

// validateRoutingRule validates a routing rule
func validateRoutingRule(rule *RoutingRule, index int, validAgents map[string]bool) error {
	if rule.Pattern == "" {
		return fmt.Errorf("pattern is required")
	}

	// Validate regex pattern (check for ReDoS vulnerability)
	if err := validateRegexPattern(rule.Pattern); err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	if rule.Agent == "" {
		return fmt.Errorf("agent is required")
	}

	// Check that agent exists
	if !validAgents[rule.Agent] {
		return fmt.Errorf("agent '%s' not found in agents list", rule.Agent)
	}

	return nil
}

// validateRegexPattern validates a regex pattern and checks for complexity
func validateRegexPattern(pattern string) error {
	// Check for potentially dangerous patterns (ReDoS prevention)
	// Patterns with nested quantifiers are dangerous: (a+)+, (a*)*
	dangerousPatterns := []string{
		`\([^)]*[+*][^)]*\)[+*]`, // Nested quantifiers like (a+)+
	}

	for _, dangerous := range dangerousPatterns {
		re := regexp.MustCompile(dangerous)
		if re.MatchString(pattern) {
			return fmt.Errorf("pattern contains potentially dangerous nested quantifiers")
		}
	}

	// Try to compile the pattern with a timeout simulation
	_, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex: %w", err)
	}

	// Check pattern length (prevent overly complex patterns)
	if len(pattern) > MaxPatternLength {
		return fmt.Errorf("pattern too long: max %d characters", MaxPatternLength)
	}

	return nil
}

// isValidIdentifier checks if a string is a valid identifier
// (lowercase alphanumeric with hyphens and underscores)
func isValidIdentifier(s string) bool {
	if s == "" {
		return false
	}

	for i, c := range s {
		if c >= 'a' && c <= 'z' {
			continue
		}
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '-' || c == '_' {
			// Cannot start with hyphen or underscore
			if i == 0 {
				return false
			}
			continue
		}
		return false
	}

	return true
}

// CompileRoutingRules compiles all routing rules in a config
func CompileRoutingRules(config *AgentConfigFile) ([]CompiledRoutingRule, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	rules := make([]CompiledRoutingRule, 0, len(config.Spec.Routing))

	for i, rule := range config.Spec.Routing {
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile pattern for rule %d: %w", i, err)
		}

		rules = append(rules, CompiledRoutingRule{
			Rule:    rule,
			Pattern: compiled,
		})
	}

	// Sort by priority (higher priority first) - O(n log n)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Rule.Priority > rules[j].Rule.Priority
	})

	return rules, nil
}

// GetDefaultExecutionConfig returns a default execution configuration
func GetDefaultExecutionConfig() ExecutionConfig {
	return ExecutionConfig{
		DefaultMode:      DefaultExecutionMode,
		MaxParallelTasks: DefaultMaxParallelTasks,
		TimeoutSeconds:   DefaultTimeoutSeconds,
		Hints:            "Analyze the query to determine logical task breakdown and dependencies.",
	}
}

// GetDefaultTimeout returns the configured timeout as a time.Duration
func (c *ExecutionConfig) GetDefaultTimeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return 5 * time.Minute // Default 5 minutes
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// IsParallel returns true if the default execution mode is parallel
func (c *ExecutionConfig) IsParallel() bool {
	return c.DefaultMode == "parallel"
}

// IsSequential returns true if the default execution mode is sequential
func (c *ExecutionConfig) IsSequential() bool {
	return c.DefaultMode == "sequential"
}

// ToDomainTemplate converts an AgentConfigFile to a legacy DomainTemplate
// This provides backward compatibility during migration
func (c *AgentConfigFile) ToDomainTemplate() *DomainTemplate {
	commonTasks := make([]string, 0, len(c.Spec.Agents))
	for _, agent := range c.Spec.Agents {
		commonTasks = append(commonTasks, agent.Name)
	}

	return &DomainTemplate{
		Domain:      c.Metadata.Domain,
		CommonTasks: commonTasks,
		Hints:       c.Spec.Execution.Hints,
	}
}

// GetAgent returns an agent definition by name
func (c *AgentConfigFile) GetAgent(name string) (*AgentDef, bool) {
	for i := range c.Spec.Agents {
		if c.Spec.Agents[i].Name == name {
			return &c.Spec.Agents[i], true
		}
	}
	return nil, false
}

// GetSynthesisPrompt returns the synthesis prompt template
func (c *AgentConfigFile) GetSynthesisPrompt() string {
	if c.Spec.Synthesis.Enabled && c.Spec.Synthesis.PromptTemplate != "" {
		return c.Spec.Synthesis.PromptTemplate
	}
	return ""
}
