// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
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
	"sync"
	"testing"
	"time"
)

// Test YAML configs for registry tests
const testTravelConfig = `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: travel-config
  domain: travel
  description: "Travel planning agents"
spec:
  execution:
    default_mode: parallel
    max_parallel_tasks: 5
    timeout_seconds: 300
    hints: "Travel tasks can be parallelized."
  agents:
    - name: flight_search
      description: "Searches for flights"
      type: llm-call
      llm:
        provider: anthropic
        model: claude-3-sonnet
        temperature: 0.3
      prompt_template: "Search for flights"
    - name: hotel_search
      description: "Searches for hotels"
      type: connector-call
      connector:
        name: amadeus-travel
        operation: query
  routing:
    - pattern: "flight|fly"
      agent: flight_search
      priority: 10
    - pattern: "hotel|accommodation"
      agent: hotel_search
      priority: 10
  synthesis:
    enabled: true
    prompt_template: "Create complete travel plan."
`

const testHealthcareConfig = `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: healthcare-config
  domain: healthcare
  description: "Healthcare agents"
spec:
  execution:
    default_mode: sequential
    max_parallel_tasks: 2
    timeout_seconds: 600
    hints: "Medical analysis requires sequential processing."
  agents:
    - name: symptom_analyzer
      description: "Analyzes symptoms"
      type: llm-call
      llm:
        provider: anthropic
        model: claude-3-sonnet
        temperature: 0.2
      prompt_template: "Analyze symptoms"
  routing:
    - pattern: "symptom|diagnos"
      agent: symptom_analyzer
      priority: 5
  synthesis:
    enabled: true
    prompt_template: "Create diagnostic report."
`

const testGenericConfig = `
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: generic-config
  domain: generic
  description: "Generic fallback agents"
spec:
  execution:
    default_mode: auto
    max_parallel_tasks: 3
    timeout_seconds: 300
    hints: "Analyze task to determine approach."
  agents:
    - name: general_assistant
      description: "General purpose assistant"
      type: llm-call
      llm:
        provider: openai
        model: gpt-4
        temperature: 0.5
      prompt_template: "Help with task"
  routing:
    - pattern: ".*"
      agent: general_assistant
      priority: 1
  synthesis:
    enabled: false
`

func setupTestDirectory(t *testing.T, configs map[string]string) string {
	tmpDir := t.TempDir()

	for name, content := range configs {
		path := filepath.Join(tmpDir, name+".yaml")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write test config %s: %v", name, err)
		}
	}

	return tmpDir
}

// mustWriteFile writes a file and fails the test if there's an error
func mustWriteFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("failed to write file %s: %v", path, err)
	}
}

// mustLoadDirectory loads configs from directory and fails the test if there's an error
func mustLoadDirectory(t *testing.T, registry *AgentRegistry, dir string) {
	t.Helper()
	if err := registry.LoadFromDirectory(dir); err != nil {
		t.Fatalf("failed to load directory %s: %v", dir, err)
	}
}

func TestNewAgentRegistry(t *testing.T) {
	registry := NewAgentRegistry()

	if registry == nil {
		t.Fatal("expected non-nil registry")
	}

	if registry.defaultDomain != "generic" {
		t.Errorf("expected default domain 'generic', got '%s'", registry.defaultDomain)
	}

	if !registry.IsEmpty() {
		t.Error("expected empty registry")
	}
}

func TestAgentRegistry_LoadFromDirectory(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel":     testTravelConfig,
		"healthcare": testHealthcareConfig,
	})

	registry := NewAgentRegistry()
	err := registry.LoadFromDirectory(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check domains were loaded
	domains := registry.ListDomains()
	if len(domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(domains))
	}

	// Check travel config
	travelConfig, err := registry.GetConfig("travel")
	if err != nil {
		t.Errorf("failed to get travel config: %v", err)
	}
	if travelConfig.Metadata.Name != "travel-config" {
		t.Errorf("expected travel config name 'travel-config', got '%s'", travelConfig.Metadata.Name)
	}

	// Check agents
	agents := registry.ListAgents()
	if len(agents) < 3 {
		t.Errorf("expected at least 3 agents, got %d", len(agents))
	}
}

func TestAgentRegistry_LoadFromDirectory_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	registry := NewAgentRegistry()
	err := registry.LoadFromDirectory(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error for empty directory: %v", err)
	}

	if !registry.IsEmpty() {
		t.Error("expected empty registry for empty directory")
	}
}

func TestAgentRegistry_LoadFromDirectory_NotExists(t *testing.T) {
	registry := NewAgentRegistry()
	err := registry.LoadFromDirectory("/nonexistent/directory")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestAgentRegistry_LoadFromDirectory_EmptyPath(t *testing.T) {
	registry := NewAgentRegistry()
	err := registry.LoadFromDirectory("")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestAgentRegistry_LoadFromDirectory_FileNotDir(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "file.yaml")
	mustWriteFile(t, tmpFile, []byte("test"))

	registry := NewAgentRegistry()
	err := registry.LoadFromDirectory(tmpFile)
	if err == nil {
		t.Error("expected error for file path")
	}
}

func TestAgentRegistry_LoadFromDirectory_DuplicateDomain(t *testing.T) {
	tmpDir := t.TempDir()

	// Write two configs with same domain
	travel1 := filepath.Join(tmpDir, "travel1.yaml")
	travel2 := filepath.Join(tmpDir, "travel2.yaml")

	mustWriteFile(t, travel1, []byte(testTravelConfig))
	mustWriteFile(t, travel2, []byte(testTravelConfig))

	registry := NewAgentRegistry()
	err := registry.LoadFromDirectory(tmpDir)
	if err == nil {
		t.Error("expected error for duplicate domain")
	}
}

func TestAgentRegistry_LoadFromDirectory_InvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()

	invalidConfig := `
apiVersion: invalid
kind: AgentConfig
metadata:
  name: test
`
	configPath := filepath.Join(tmpDir, "invalid.yaml")
	mustWriteFile(t, configPath, []byte(invalidConfig))

	registry := NewAgentRegistry()
	err := registry.LoadFromDirectory(tmpDir)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestAgentRegistry_GetConfig(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	// Test existing domain
	config, err := registry.GetConfig("travel")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if config.Metadata.Domain != "travel" {
		t.Errorf("expected domain 'travel', got '%s'", config.Metadata.Domain)
	}

	// Test non-existent domain
	_, err = registry.GetConfig("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent domain")
	}
}

func TestAgentRegistry_GetConfigOrDefault(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel":  testTravelConfig,
		"generic": testGenericConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	// Test existing domain
	config := registry.GetConfigOrDefault("travel")
	if config == nil {
		t.Fatal("expected non-nil config")
	}
	if config.Metadata.Domain != "travel" {
		t.Errorf("expected domain 'travel', got '%s'", config.Metadata.Domain)
	}

	// Test fallback to generic
	config = registry.GetConfigOrDefault("nonexistent")
	if config == nil {
		t.Fatal("expected non-nil config (fallback)")
	}
	if config.Metadata.Domain != "generic" {
		t.Errorf("expected fallback domain 'generic', got '%s'", config.Metadata.Domain)
	}
}

func TestAgentRegistry_GetConfigOrDefault_NoFallback(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	// No generic domain loaded
	config := registry.GetConfigOrDefault("nonexistent")
	if config != nil {
		t.Error("expected nil when no fallback exists")
	}
}

func TestAgentRegistry_GetAgent(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	// Test by simple name
	agent, err := registry.GetAgent("flight_search")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if agent.Name != "flight_search" {
		t.Errorf("expected agent 'flight_search', got '%s'", agent.Name)
	}

	// Test by qualified name
	agent, err = registry.GetAgent("travel/flight_search")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if agent.Name != "flight_search" {
		t.Errorf("expected agent 'flight_search', got '%s'", agent.Name)
	}

	// Test nonexistent
	_, err = registry.GetAgent("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent agent")
	}
}

func TestAgentRegistry_GetAgentFromDomain(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	// Test existing agent
	agent, err := registry.GetAgentFromDomain("travel", "flight_search")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if agent.Name != "flight_search" {
		t.Errorf("expected agent 'flight_search', got '%s'", agent.Name)
	}

	// Test nonexistent domain
	_, err = registry.GetAgentFromDomain("nonexistent", "flight_search")
	if err == nil {
		t.Error("expected error for nonexistent domain")
	}

	// Test nonexistent agent in domain
	_, err = registry.GetAgentFromDomain("travel", "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent agent")
	}
}

func TestAgentRegistry_RouteTask(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel":     testTravelConfig,
		"healthcare": testHealthcareConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	tests := []struct {
		task          string
		expectedAgent string
		expectError   bool
	}{
		{"search for flights to Paris", "flight_search", false},
		{"find hotel in Barcelona", "hotel_search", false},
		{"analyze patient symptoms", "symptom_analyzer", false},
		{"diagnose condition", "symptom_analyzer", false},
		{"completely unmatched query", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.task, func(t *testing.T) {
			agent, _, err := registry.RouteTask(tt.task)
			if tt.expectError {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if agent.Name != tt.expectedAgent {
				t.Errorf("expected agent '%s', got '%s'", tt.expectedAgent, agent.Name)
			}
		})
	}
}

func TestAgentRegistry_RouteTaskWithFallback(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel":  testTravelConfig,
		"generic": testGenericConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	// Test direct match
	agent, domain, err := registry.RouteTaskWithFallback("search for flights", "generic")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if agent.Name != "flight_search" {
		t.Errorf("expected 'flight_search', got '%s'", agent.Name)
	}
	if domain != "travel" {
		t.Errorf("expected domain 'travel', got '%s'", domain)
	}

	// Test fallback
	agent, _, err = registry.RouteTaskWithFallback("completely random query xyz", "generic")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if agent.Name != "general_assistant" {
		t.Errorf("expected fallback agent 'general_assistant', got '%s'", agent.Name)
	}
}

func TestAgentRegistry_RouteTaskWithFallback_NoFallback(t *testing.T) {
	registry := NewAgentRegistry()

	_, _, err := registry.RouteTaskWithFallback("test query", "generic")
	if err == nil {
		t.Error("expected error when no fallback available")
	}
}

func TestAgentRegistry_ListDomains(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel":     testTravelConfig,
		"healthcare": testHealthcareConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	domains := registry.ListDomains()
	if len(domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(domains))
	}

	// Should be sorted
	if domains[0] != "healthcare" || domains[1] != "travel" {
		t.Errorf("domains not sorted: %v", domains)
	}
}

func TestAgentRegistry_ListAgents(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	agents := registry.ListAgents()
	if len(agents) < 2 {
		t.Errorf("expected at least 2 agents, got %d", len(agents))
	}
}

func TestAgentRegistry_ListAgentsInDomain(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	agents, err := registry.ListAgentsInDomain("travel")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}

	// Test nonexistent domain
	_, err = registry.ListAgentsInDomain("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent domain")
	}
}

func TestAgentRegistry_Reload(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	initialCount := registry.Stats().ReloadCount

	// Add a new config
	healthcarePath := filepath.Join(tmpDir, "healthcare.yaml")
	mustWriteFile(t, healthcarePath, []byte(testHealthcareConfig))

	// Reload
	err := registry.Reload()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Check new domain loaded
	if !registry.HasDomain("healthcare") {
		t.Error("expected healthcare domain after reload")
	}

	// Check reload count increased
	if registry.Stats().ReloadCount <= initialCount {
		t.Error("expected reload count to increase")
	}
}

func TestAgentRegistry_Reload_NoDirectory(t *testing.T) {
	registry := NewAgentRegistry()

	err := registry.Reload()
	if err == nil {
		t.Error("expected error when no directory set")
	}
}

func TestAgentRegistry_SetDefaultDomain(t *testing.T) {
	registry := NewAgentRegistry()

	registry.SetDefaultDomain("custom")
	if registry.GetDefaultDomain() != "custom" {
		t.Errorf("expected default domain 'custom', got '%s'", registry.GetDefaultDomain())
	}
}

func TestAgentRegistry_Stats(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel":     testTravelConfig,
		"healthcare": testHealthcareConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	stats := registry.Stats()

	if stats.DomainCount != 2 {
		t.Errorf("expected 2 domains, got %d", stats.DomainCount)
	}

	if stats.AgentCount < 3 {
		t.Errorf("expected at least 3 agents, got %d", stats.AgentCount)
	}

	if stats.RoutingRules < 3 {
		t.Errorf("expected at least 3 routing rules, got %d", stats.RoutingRules)
	}

	if stats.ConfigDir != tmpDir {
		t.Errorf("expected config dir '%s', got '%s'", tmpDir, stats.ConfigDir)
	}

	if stats.LastReload.IsZero() {
		t.Error("expected non-zero last reload time")
	}
}

func TestAgentRegistry_HasDomain(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	if !registry.HasDomain("travel") {
		t.Error("expected HasDomain to return true for 'travel'")
	}

	if registry.HasDomain("nonexistent") {
		t.Error("expected HasDomain to return false for 'nonexistent'")
	}
}

func TestAgentRegistry_HasAgent(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	if !registry.HasAgent("flight_search") {
		t.Error("expected HasAgent to return true for 'flight_search'")
	}

	if registry.HasAgent("nonexistent") {
		t.Error("expected HasAgent to return false for 'nonexistent'")
	}
}

func TestAgentRegistry_GetDomainTemplate(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	template, err := registry.GetDomainTemplate("travel")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if template.Domain != "travel" {
		t.Errorf("expected domain 'travel', got '%s'", template.Domain)
	}

	if len(template.CommonTasks) != 2 {
		t.Errorf("expected 2 common tasks, got %d", len(template.CommonTasks))
	}

	// Test nonexistent
	_, err = registry.GetDomainTemplate("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent domain")
	}
}

func TestAgentRegistry_GetDomainTemplateOrDefault(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	// Test existing
	template := registry.GetDomainTemplateOrDefault("travel")
	if template.Domain != "travel" {
		t.Errorf("expected domain 'travel', got '%s'", template.Domain)
	}

	// Test fallback (no generic loaded, so returns hardcoded)
	template = registry.GetDomainTemplateOrDefault("nonexistent")
	if template.Domain != "generic" {
		t.Errorf("expected fallback domain 'generic', got '%s'", template.Domain)
	}
}

func TestAgentRegistry_GetSynthesisPrompt(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	prompt := registry.GetSynthesisPrompt("travel")
	if prompt != "Create complete travel plan." {
		t.Errorf("unexpected synthesis prompt: %s", prompt)
	}

	// Test nonexistent (should return empty)
	prompt = registry.GetSynthesisPrompt("nonexistent")
	if prompt != "" {
		t.Errorf("expected empty prompt for nonexistent domain, got '%s'", prompt)
	}
}

func TestAgentRegistry_GetExecutionConfig(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	config := registry.GetExecutionConfig("travel")
	if config.DefaultMode != "parallel" {
		t.Errorf("expected default_mode 'parallel', got '%s'", config.DefaultMode)
	}

	// Test nonexistent (should return default)
	config = registry.GetExecutionConfig("nonexistent")
	if config.DefaultMode != "auto" {
		t.Errorf("expected default mode 'auto', got '%s'", config.DefaultMode)
	}
}

func TestAgentRegistry_Clear(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	if registry.IsEmpty() {
		t.Error("expected non-empty registry before clear")
	}

	registry.Clear()

	if !registry.IsEmpty() {
		t.Error("expected empty registry after clear")
	}
}

func TestAgentRegistry_RegisterConfig(t *testing.T) {
	registry := NewAgentRegistry()

	config, _ := ParseAgentConfig([]byte(testTravelConfig))
	err := registry.RegisterConfig(config)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !registry.HasDomain("travel") {
		t.Error("expected travel domain after register")
	}

	if !registry.HasAgent("flight_search") {
		t.Error("expected flight_search agent after register")
	}
}

func TestAgentRegistry_RegisterConfig_Nil(t *testing.T) {
	registry := NewAgentRegistry()

	err := registry.RegisterConfig(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestAgentRegistry_UnregisterDomain(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel":     testTravelConfig,
		"healthcare": testHealthcareConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	err := registry.UnregisterDomain("travel")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if registry.HasDomain("travel") {
		t.Error("expected travel domain to be removed")
	}

	if registry.HasDomain("healthcare") != true {
		t.Error("expected healthcare domain to remain")
	}

	// Test nonexistent
	err = registry.UnregisterDomain("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent domain")
	}
}

func TestAgentRegistry_ConcurrentAccess(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel":     testTravelConfig,
		"healthcare": testHealthcareConfig,
		"generic":    testGenericConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := registry.GetConfig("travel")
			if err != nil {
				errCh <- err
			}
		}()
	}

	// Concurrent agent lookups
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := registry.GetAgent("flight_search")
			if err != nil {
				errCh <- err
			}
		}()
	}

	// Concurrent routing
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = registry.RouteTask("search for flights")
		}()
	}

	// Concurrent stats
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.Stats()
		}()
	}

	// Concurrent reloads
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.Reload()
		}()
	}

	wg.Wait()
	close(errCh)

	// Check for errors
	var errors []error
	for err := range errCh {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		t.Errorf("concurrent access errors: %v", errors)
	}
}

func TestAgentRegistry_RoutingPriority(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel":  testTravelConfig,
		"generic": testGenericConfig,
	})

	registry := NewAgentRegistry()
	mustLoadDirectory(t, registry, tmpDir)

	// "fly" should match travel (priority 10) not generic (priority 1)
	agent, domain, err := registry.RouteTask("I want to fly somewhere")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if domain != "travel" {
		t.Errorf("expected travel domain (higher priority), got '%s'", domain)
	}

	if agent.Name != "flight_search" {
		t.Errorf("expected flight_search agent, got '%s'", agent.Name)
	}
}

func TestAgentRegistry_IsEmpty(t *testing.T) {
	registry := NewAgentRegistry()

	if !registry.IsEmpty() {
		t.Error("expected new registry to be empty")
	}

	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})
	mustLoadDirectory(t, registry, tmpDir)

	if registry.IsEmpty() {
		t.Error("expected registry to be non-empty after loading")
	}
}

func TestAgentRegistry_LastReload(t *testing.T) {
	tmpDir := setupTestDirectory(t, map[string]string{
		"travel": testTravelConfig,
	})

	registry := NewAgentRegistry()
	beforeLoad := time.Now()

	mustLoadDirectory(t, registry, tmpDir)

	afterLoad := time.Now()
	stats := registry.Stats()

	if stats.LastReload.Before(beforeLoad) || stats.LastReload.After(afterLoad) {
		t.Errorf("last reload time %v not within expected range [%v, %v]",
			stats.LastReload, beforeLoad, afterLoad)
	}
}

func TestAgentRegistry_findYAMLFiles_SkipsSubdirectories(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a config in root
	rootConfig := filepath.Join(tmpDir, "root.yaml")
	mustWriteFile(t, rootConfig, []byte(testTravelConfig))

	// Create a subdirectory with config (should be skipped)
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}
	subConfig := filepath.Join(subDir, "sub.yaml")
	mustWriteFile(t, subConfig, []byte(testHealthcareConfig))

	registry := NewAgentRegistry()
	err := registry.LoadFromDirectory(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have travel domain (root), not healthcare (subdir)
	domains := registry.ListDomains()
	if len(domains) != 1 {
		t.Errorf("expected 1 domain, got %d: %v", len(domains), domains)
	}

	if !registry.HasDomain("travel") {
		t.Error("expected travel domain")
	}

	if registry.HasDomain("healthcare") {
		t.Error("should not have healthcare from subdirectory")
	}
}

// TestAgentRegistry_LoadRealConfigs tests loading the actual config files
// This is an integration test that verifies the shipped configs are valid
func TestAgentRegistry_LoadRealConfigs(t *testing.T) {
	// Try to load the real config files from the agents directory
	configDir := "./agents"

	// Check if the directory exists (it might not in CI without the files)
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		t.Skip("agents directory not found - skipping real config test")
	}

	registry := NewAgentRegistry()
	err := registry.LoadFromDirectory(configDir)
	if err != nil {
		t.Fatalf("failed to load real configs: %v", err)
	}

	// Verify expected domains are loaded
	expectedDomains := []string{"travel", "healthcare", "finance", "generic"}
	for _, domain := range expectedDomains {
		if !registry.HasDomain(domain) {
			t.Errorf("expected domain '%s' not found", domain)
		}
	}

	// Verify travel domain has expected agents
	travelConfig, err := registry.GetConfig("travel")
	if err != nil {
		t.Errorf("failed to get travel config: %v", err)
	}
	if len(travelConfig.Spec.Agents) == 0 {
		t.Error("travel config has no agents")
	}

	// Verify routing works
	agent, domain, err := registry.RouteTask("I need to book a flight to Paris")
	if err != nil {
		t.Errorf("routing failed: %v", err)
	}
	if domain != "travel" {
		t.Errorf("expected travel domain for flight query, got '%s'", domain)
	}
	if agent == nil {
		t.Error("expected agent for flight query")
	}

	// Verify healthcare routing
	_, domain, err = registry.RouteTask("Patient presenting with symptoms of fever")
	if err != nil {
		t.Errorf("routing failed: %v", err)
	}
	if domain != "healthcare" {
		t.Errorf("expected healthcare domain for symptom query, got '%s'", domain)
	}

	// Verify finance routing
	_, domain, err = registry.RouteTask("Analyze the market trends for AAPL stock")
	if err != nil {
		t.Errorf("routing failed: %v", err)
	}
	if domain != "finance" {
		t.Errorf("expected finance domain for market query, got '%s'", domain)
	}

	// Log stats for visibility
	stats := registry.Stats()
	t.Logf("Loaded %d domains with %d agents and %d routing rules",
		stats.DomainCount, stats.AgentCount, stats.RoutingRules)
}
