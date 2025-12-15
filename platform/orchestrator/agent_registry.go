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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AgentRegistry manages agent configurations with thread-safe access
// and supports hot reload for development environments.
//
// MAP 0.8: Supports hybrid mode with both file and database sources.
// Database-sourced configurations take priority over file-based ones.
type AgentRegistry struct {
	configs          map[string]*AgentConfigFile // domain -> config
	agents           map[string]*AgentDef        // agent_name -> definition
	routing          []CompiledRoutingRule       // Pre-compiled regex rules
	configDir        string                      // Directory containing config files
	mu               sync.RWMutex                // Protects configs, agents, routing
	lastReload       time.Time                   // Last reload timestamp
	reloadCount      int64                       // Atomic counter for reload operations
	defaultDomain    string                      // Fallback domain when no match

	// MAP 0.8: Database integration fields
	dbSource         DatabaseAgentSource         // Database source for hybrid mode
	orgID            string                      // Organization ID for database queries
	mode             RegistryMode                // Operating mode (file/database/hybrid)
	dbSourcedDomains map[string]bool             // Tracks which domains came from DB
}

// RegistryStats provides statistics about the registry
type RegistryStats struct {
	DomainCount   int       `json:"domain_count"`
	AgentCount    int       `json:"agent_count"`
	RoutingRules  int       `json:"routing_rules"`
	ConfigDir     string    `json:"config_dir"`
	LastReload    time.Time `json:"last_reload"`
	ReloadCount   int64     `json:"reload_count"`
	DefaultDomain string    `json:"default_domain"`
}

// NewAgentRegistry creates a new agent registry instance
func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		configs:          make(map[string]*AgentConfigFile),
		agents:           make(map[string]*AgentDef),
		routing:          make([]CompiledRoutingRule, 0),
		defaultDomain:    "generic",
		mode:             RegistryModeFile, // Default to file mode
		dbSourcedDomains: make(map[string]bool),
	}
}

// LoadFromDirectory loads all YAML agent configurations from a directory
func (r *AgentRegistry) LoadFromDirectory(dir string) error {
	return r.LoadFromDirectoryWithContext(context.Background(), dir)
}

// LoadFromDirectoryWithContext loads configurations with context support for cancellation/timeout
func (r *AgentRegistry) LoadFromDirectoryWithContext(ctx context.Context, dir string) error {
	// Check for cancellation before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if dir == "" {
		return fmt.Errorf("directory path cannot be empty")
	}

	// Check if directory exists
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("directory does not exist: %s", dir)
		}
		return fmt.Errorf("failed to access directory %s: %w", dir, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", dir)
	}

	// Find all YAML files
	files, err := r.findYAMLFiles(dir)
	if err != nil {
		return fmt.Errorf("failed to scan directory: %w", err)
	}

	if len(files) == 0 {
		// Empty directory is valid - registry will have no configs
		r.mu.Lock()
		r.configDir = dir
		r.configs = make(map[string]*AgentConfigFile)
		r.agents = make(map[string]*AgentDef)
		r.routing = make([]CompiledRoutingRule, 0)
		r.lastReload = time.Now()
		atomic.AddInt64(&r.reloadCount, 1)
		r.mu.Unlock()
		return nil
	}

	// Load each config file
	newConfigs := make(map[string]*AgentConfigFile)
	newAgents := make(map[string]*AgentDef)
	var allRules []CompiledRoutingRule

	for _, file := range files {
		// Check for context cancellation between file loads
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		config, err := LoadAgentConfig(file)
		if err != nil {
			return fmt.Errorf("failed to load config %s: %w", file, err)
		}

		domain := config.Metadata.Domain
		if _, exists := newConfigs[domain]; exists {
			return fmt.Errorf("duplicate domain '%s' found in %s", domain, file)
		}

		newConfigs[domain] = config

		// Index all agents
		for i := range config.Spec.Agents {
			agent := &config.Spec.Agents[i]
			// Use qualified name: domain/agent_name to avoid collisions
			qualifiedName := fmt.Sprintf("%s/%s", domain, agent.Name)
			newAgents[qualifiedName] = agent
			// Also index by simple name for backward compatibility
			if _, exists := newAgents[agent.Name]; !exists {
				newAgents[agent.Name] = agent
			}
		}

		// Compile routing rules
		rules, err := CompileRoutingRules(config)
		if err != nil {
			return fmt.Errorf("failed to compile routing rules for %s: %w", file, err)
		}

		// Tag rules with domain
		for i := range rules {
			rules[i].Domain = domain
		}

		allRules = append(allRules, rules...)
	}

	// Sort all rules by priority (higher first)
	sort.Slice(allRules, func(i, j int) bool {
		return allRules[i].Rule.Priority > allRules[j].Rule.Priority
	})

	// Atomic swap
	r.mu.Lock()
	r.configDir = dir
	r.configs = newConfigs
	r.agents = newAgents
	r.routing = allRules
	r.lastReload = time.Now()
	atomic.AddInt64(&r.reloadCount, 1)
	r.mu.Unlock()

	return nil
}

// findYAMLFiles returns all YAML files in a directory
func (r *AgentRegistry) findYAMLFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip subdirectories (only load from top-level)
		if info.IsDir() && path != dir {
			return filepath.SkipDir
		}

		// Match YAML files
		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yaml" || ext == ".yml" {
				files = append(files, path)
			}
		}

		return nil
	})

	return files, err
}

// GetConfig returns the configuration for a specific domain
func (r *AgentRegistry) GetConfig(domain string) (*AgentConfigFile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	config, exists := r.configs[domain]
	if !exists {
		return nil, fmt.Errorf("configuration not found for domain: %s", domain)
	}

	return config, nil
}

// GetConfigOrDefault returns the configuration for a domain, falling back to default
func (r *AgentRegistry) GetConfigOrDefault(domain string) *AgentConfigFile {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if config, exists := r.configs[domain]; exists {
		return config
	}

	if config, exists := r.configs[r.defaultDomain]; exists {
		return config
	}

	return nil
}

// GetAgent returns an agent definition by name
// Supports both simple names and qualified names (domain/agent)
func (r *AgentRegistry) GetAgent(name string) (*AgentDef, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	agent, exists := r.agents[name]
	if !exists {
		return nil, fmt.Errorf("agent not found: %s", name)
	}

	return agent, nil
}

// GetAgentFromDomain returns an agent definition from a specific domain
func (r *AgentRegistry) GetAgentFromDomain(domain, agentName string) (*AgentDef, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	config, exists := r.configs[domain]
	if !exists {
		return nil, fmt.Errorf("domain not found: %s", domain)
	}

	agent, found := config.GetAgent(agentName)
	if !found {
		return nil, fmt.Errorf("agent '%s' not found in domain '%s'", agentName, domain)
	}

	return agent, nil
}

// RouteTask matches a task description to an agent using routing rules
// Returns the agent definition and the matched domain
func (r *AgentRegistry) RouteTask(taskDescription string) (*AgentDef, string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	taskLower := strings.ToLower(taskDescription)

	for _, rule := range r.routing {
		if rule.Pattern.MatchString(taskLower) {
			// Get the domain from the routing rule
			domain := rule.Domain

			// Find the agent using qualified name (domain/agent)
			qualifiedName := fmt.Sprintf("%s/%s", domain, rule.Rule.Agent)
			if agent, exists := r.agents[qualifiedName]; exists {
				return agent, domain, nil
			}

			// Fallback to simple name lookup
			if agent, exists := r.agents[rule.Rule.Agent]; exists {
				return agent, domain, nil
			}
		}
	}

	return nil, "", fmt.Errorf("no routing rule matches task: %s", taskDescription)
}

// RouteTaskWithFallback tries to route a task, falling back to a default agent
func (r *AgentRegistry) RouteTaskWithFallback(taskDescription string, fallbackDomain string) (*AgentDef, string, error) {
	agent, domain, err := r.RouteTask(taskDescription)
	if err == nil {
		return agent, domain, nil
	}

	// Try fallback domain
	r.mu.RLock()
	defer r.mu.RUnlock()

	config, exists := r.configs[fallbackDomain]
	if !exists {
		config, exists = r.configs[r.defaultDomain]
	}

	if !exists || len(config.Spec.Agents) == 0 {
		return nil, "", fmt.Errorf("no fallback agent available: %w", err)
	}

	// Return first agent in fallback domain
	return &config.Spec.Agents[0], config.Metadata.Domain, nil
}

// ListDomains returns all registered domains
func (r *AgentRegistry) ListDomains() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	domains := make([]string, 0, len(r.configs))
	for domain := range r.configs {
		domains = append(domains, domain)
	}

	sort.Strings(domains)
	return domains
}

// ListAgents returns all registered agents
func (r *AgentRegistry) ListAgents() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	agents := make([]string, 0, len(r.agents))
	for name := range r.agents {
		agents = append(agents, name)
	}

	sort.Strings(agents)
	return agents
}

// ListAgentsInDomain returns all agents in a specific domain
func (r *AgentRegistry) ListAgentsInDomain(domain string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	config, exists := r.configs[domain]
	if !exists {
		return nil, fmt.Errorf("domain not found: %s", domain)
	}

	agents := make([]string, 0, len(config.Spec.Agents))
	for _, agent := range config.Spec.Agents {
		agents = append(agents, agent.Name)
	}

	return agents, nil
}

// Reload reloads all configurations from the configured directory
// This is safe for concurrent access - uses atomic swap
func (r *AgentRegistry) Reload() error {
	return r.ReloadWithContext(context.Background())
}

// ReloadWithContext reloads configurations with context support for cancellation/timeout
func (r *AgentRegistry) ReloadWithContext(ctx context.Context) error {
	// Check for cancellation before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	r.mu.RLock()
	configDir := r.configDir
	r.mu.RUnlock()

	if configDir == "" {
		return fmt.Errorf("no configuration directory set - call LoadFromDirectory first")
	}

	return r.LoadFromDirectoryWithContext(ctx, configDir)
}

// SetDefaultDomain sets the fallback domain for routing
func (r *AgentRegistry) SetDefaultDomain(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultDomain = domain
}

// GetDefaultDomain returns the current fallback domain
func (r *AgentRegistry) GetDefaultDomain() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultDomain
}

// Stats returns current registry statistics
func (r *AgentRegistry) Stats() RegistryStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return RegistryStats{
		DomainCount:   len(r.configs),
		AgentCount:    len(r.agents),
		RoutingRules:  len(r.routing),
		ConfigDir:     r.configDir,
		LastReload:    r.lastReload,
		ReloadCount:   atomic.LoadInt64(&r.reloadCount),
		DefaultDomain: r.defaultDomain,
	}
}

// HasDomain checks if a domain is registered
func (r *AgentRegistry) HasDomain(domain string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.configs[domain]
	return exists
}

// HasAgent checks if an agent is registered
func (r *AgentRegistry) HasAgent(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.agents[name]
	return exists
}

// GetDomainTemplate returns a legacy DomainTemplate for backward compatibility
func (r *AgentRegistry) GetDomainTemplate(domain string) (*DomainTemplate, error) {
	config, err := r.GetConfig(domain)
	if err != nil {
		return nil, err
	}
	return config.ToDomainTemplate(), nil
}

// GetDomainTemplateOrDefault returns a DomainTemplate, falling back to default
func (r *AgentRegistry) GetDomainTemplateOrDefault(domain string) *DomainTemplate {
	config := r.GetConfigOrDefault(domain)
	if config == nil {
		// Return hardcoded generic template as absolute fallback
		return &DomainTemplate{
			Domain:      "generic",
			CommonTasks: []string{"task-1", "task-2", "task-3"},
			Hints:       "Analyze the query to determine logical task breakdown and dependencies.",
		}
	}
	return config.ToDomainTemplate()
}

// GetSynthesisPrompt returns the synthesis prompt for a domain
func (r *AgentRegistry) GetSynthesisPrompt(domain string) string {
	config := r.GetConfigOrDefault(domain)
	if config == nil {
		return ""
	}
	return config.GetSynthesisPrompt()
}

// GetExecutionConfig returns the execution configuration for a domain
func (r *AgentRegistry) GetExecutionConfig(domain string) *ExecutionConfig {
	config := r.GetConfigOrDefault(domain)
	if config == nil {
		defaultConfig := GetDefaultExecutionConfig()
		return &defaultConfig
	}
	return &config.Spec.Execution
}

// IsEmpty returns true if the registry has no configurations loaded
func (r *AgentRegistry) IsEmpty() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.configs) == 0
}

// Clear removes all configurations from the registry
func (r *AgentRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.configs = make(map[string]*AgentConfigFile)
	r.agents = make(map[string]*AgentDef)
	r.routing = make([]CompiledRoutingRule, 0)
	r.configDir = ""
}

// RegisterConfig manually registers a configuration (useful for testing)
func (r *AgentRegistry) RegisterConfig(config *AgentConfigFile) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	if err := ValidateAgentConfig(config); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	domain := config.Metadata.Domain
	r.configs[domain] = config

	// Index agents
	for i := range config.Spec.Agents {
		agent := &config.Spec.Agents[i]
		qualifiedName := fmt.Sprintf("%s/%s", domain, agent.Name)
		r.agents[qualifiedName] = agent
		if _, exists := r.agents[agent.Name]; !exists {
			r.agents[agent.Name] = agent
		}
	}

	// Compile and add routing rules
	rules, err := CompileRoutingRules(config)
	if err != nil {
		return fmt.Errorf("failed to compile routing rules: %w", err)
	}

	for i := range rules {
		rules[i].Domain = domain
	}

	r.routing = append(r.routing, rules...)

	// Re-sort by priority
	sort.Slice(r.routing, func(i, j int) bool {
		return r.routing[i].Rule.Priority > r.routing[j].Rule.Priority
	})

	r.lastReload = time.Now()
	atomic.AddInt64(&r.reloadCount, 1)

	return nil
}

// UnregisterDomain removes a domain from the registry
func (r *AgentRegistry) UnregisterDomain(domain string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	config, exists := r.configs[domain]
	if !exists {
		return fmt.Errorf("domain not found: %s", domain)
	}

	// Remove agents - use index-based iteration to get correct pointers
	for i := range config.Spec.Agents {
		agent := &config.Spec.Agents[i]
		qualifiedName := fmt.Sprintf("%s/%s", domain, agent.Name)
		delete(r.agents, qualifiedName)
		// Only remove simple name if it points to this domain's agent
		if existingAgent, ok := r.agents[agent.Name]; ok && existingAgent == agent {
			delete(r.agents, agent.Name)
		}
	}

	// Remove routing rules for this domain
	newRouting := make([]CompiledRoutingRule, 0, len(r.routing))
	for _, rule := range r.routing {
		if rule.Domain != domain {
			newRouting = append(newRouting, rule)
		}
	}
	r.routing = newRouting

	// Remove config
	delete(r.configs, domain)

	return nil
}
