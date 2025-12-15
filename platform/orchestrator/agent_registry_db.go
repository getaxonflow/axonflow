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
	"log"
	"sort"
	"sync/atomic"
	"time"
)

// DatabaseAgentSource defines the interface for loading agents from a database.
// This interface is implemented by the enterprise agents package.
type DatabaseAgentSource interface {
	// ListActiveAgents returns all active agent configurations for an organization
	ListActiveAgents(ctx context.Context, orgID string) ([]*AgentConfigFile, error)

	// GetAgentByName returns an agent by name for an organization
	GetAgentByName(ctx context.Context, orgID, name string) (*AgentConfigFile, error)
}

// RegistryMode defines how the registry sources agent configurations
type RegistryMode string

const (
	// RegistryModeFile loads agents only from YAML files
	RegistryModeFile RegistryMode = "file"

	// RegistryModeDatabase loads agents only from the database
	RegistryModeDatabase RegistryMode = "database"

	// RegistryModeHybrid loads from both, with database configs taking priority
	RegistryModeHybrid RegistryMode = "hybrid"
)

// RegistryMode defines how the registry sources agent configurations.
// It can be file-only, database-only, or hybrid (both sources with DB priority).

// SetDatabaseSource sets the database source for hybrid mode.
// Database-backed agents take priority over file-based agents.
func (r *AgentRegistry) SetDatabaseSource(source DatabaseAgentSource, orgID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dbSource = source
	r.orgID = orgID
	r.mode = RegistryModeHybrid
}

// SetMode sets the registry operating mode
func (r *AgentRegistry) SetMode(mode RegistryMode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mode = mode
}

// GetMode returns the current registry mode
func (r *AgentRegistry) GetMode() RegistryMode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.mode == "" {
		return RegistryModeFile
	}
	return r.mode
}

// LoadFromDatabase loads agent configurations from the database source.
// This replaces any existing database-sourced configurations while preserving file-based ones.
// When a database config uses the same domain as a file config, the database config takes priority.
func (r *AgentRegistry) LoadFromDatabase(ctx context.Context) error {
	// Check for context cancellation before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	r.mu.RLock()
	dbSource := r.dbSource
	orgID := r.orgID
	r.mu.RUnlock()

	if dbSource == nil {
		return fmt.Errorf("database source not configured")
	}

	if orgID == "" {
		return fmt.Errorf("organization ID not set")
	}

	// Load agents from database
	dbConfigs, err := dbSource.ListActiveAgents(ctx, orgID)
	if err != nil {
		return fmt.Errorf("failed to load agents from database: %w", err)
	}

	// Process and merge with existing file-based configs
	r.mu.Lock()
	defer r.mu.Unlock()

	// Re-check dbSource and orgID after acquiring write lock to prevent TOCTOU race
	// If configuration changed while we were loading, we still proceed with the loaded data
	// since it came from a valid source at the time of the call
	if r.dbSource != dbSource || r.orgID != orgID {
		log.Printf("[AgentRegistry] Database source changed during load, proceeding with originally loaded data")
	}

	if len(dbConfigs) == 0 {
		log.Printf("[AgentRegistry] No database configs found for org=%s", orgID)
		// Still need to clear any previously loaded DB configs
		r.clearDBSourcedConfigs()
		return nil
	}

	// Clear existing DB-sourced configs and their agents
	r.clearDBSourcedConfigs()

	// Add database configs
	loadedCount := 0
	for _, config := range dbConfigs {
		if err := ValidateAgentConfig(config); err != nil {
			log.Printf("[AgentRegistry] Skipping invalid DB config %s: %v", config.Metadata.Name, err)
			continue
		}

		domain := config.Metadata.Domain

		// If a file-based config exists for this domain, remove its agents first
		if existingConfig, exists := r.configs[domain]; exists && !r.dbSourcedDomains[domain] {
			r.removeAgentsForConfig(existingConfig, domain)
		}

		// Database configs override file-based configs
		r.configs[domain] = config
		r.dbSourcedDomains[domain] = true

		// Index agents from this config
		r.indexAgentsForConfig(config, domain)
		loadedCount++
	}

	// Recompile all routing rules
	if err := r.recompileRoutingRules(); err != nil {
		return fmt.Errorf("failed to compile routing rules: %w", err)
	}

	r.lastReload = time.Now()
	atomic.AddInt64(&r.reloadCount, 1)

	log.Printf("[AgentRegistry] Loaded %d database configs for org=%s", loadedCount, orgID)
	return nil
}

// clearDBSourcedConfigs removes all database-sourced configs and their agents.
// Must be called with mutex held.
func (r *AgentRegistry) clearDBSourcedConfigs() {
	for domain := range r.dbSourcedDomains {
		if config, exists := r.configs[domain]; exists {
			r.removeAgentsForConfig(config, domain)
			delete(r.configs, domain)
		}
	}
	r.dbSourcedDomains = make(map[string]bool)
}

// removeAgentsForConfig removes all agents indexed from a specific config.
// Must be called with mutex held.
func (r *AgentRegistry) removeAgentsForConfig(config *AgentConfigFile, domain string) {
	for i := range config.Spec.Agents {
		agent := &config.Spec.Agents[i]
		qualifiedName := fmt.Sprintf("%s/%s", domain, agent.Name)
		delete(r.agents, qualifiedName)

		// Only remove simple name if it points to this specific agent
		if existingAgent, ok := r.agents[agent.Name]; ok && existingAgent == agent {
			delete(r.agents, agent.Name)
		}
	}
}

// indexAgentsForConfig adds all agents from a config to the index.
// Must be called with mutex held.
func (r *AgentRegistry) indexAgentsForConfig(config *AgentConfigFile, domain string) {
	for i := range config.Spec.Agents {
		agent := &config.Spec.Agents[i]
		qualifiedName := fmt.Sprintf("%s/%s", domain, agent.Name)
		r.agents[qualifiedName] = agent

		// For simple name lookup, only add if not already present (first-come wins)
		// This maintains consistency with file-based loading behavior
		if _, exists := r.agents[agent.Name]; !exists {
			r.agents[agent.Name] = agent
		}
	}
}

// LoadHybrid loads from both file and database sources, with database taking priority.
func (r *AgentRegistry) LoadHybrid(ctx context.Context, configDir string) error {
	// First load file-based configs
	if configDir != "" {
		if err := r.LoadFromDirectoryWithContext(ctx, configDir); err != nil {
			log.Printf("[AgentRegistry] Warning: failed to load file configs from %s: %v", configDir, err)
			// Continue - database configs might still work
		}
	}

	// Then load and merge database configs (these take priority)
	r.mu.RLock()
	dbSource := r.dbSource
	r.mu.RUnlock()

	if dbSource != nil {
		if err := r.LoadFromDatabase(ctx); err != nil {
			log.Printf("[AgentRegistry] Warning: failed to load database configs: %v", err)
			// Continue with file configs only
		}
	}

	return nil
}

// recompileRoutingRules recompiles all routing rules from current configs.
// Must be called with mutex held.
func (r *AgentRegistry) recompileRoutingRules() error {
	var allRules []CompiledRoutingRule

	for domain, config := range r.configs {
		rules, err := CompileRoutingRules(config)
		if err != nil {
			return fmt.Errorf("failed to compile rules for domain %s: %w", domain, err)
		}

		for i := range rules {
			rules[i].Domain = domain
		}

		allRules = append(allRules, rules...)
	}

	// Sort by priority
	sort.Slice(allRules, func(i, j int) bool {
		return allRules[i].Rule.Priority > allRules[j].Rule.Priority
	})

	r.routing = allRules
	return nil
}

// ReloadFromDatabase triggers a reload of database-sourced configurations.
// This is called after database mutations to refresh the in-memory cache.
func (r *AgentRegistry) ReloadFromDatabase(ctx context.Context) error {
	r.mu.RLock()
	mode := r.mode
	r.mu.RUnlock()

	switch mode {
	case RegistryModeDatabase:
		return r.LoadFromDatabase(ctx)
	case RegistryModeHybrid:
		r.mu.RLock()
		configDir := r.configDir
		r.mu.RUnlock()
		return r.LoadHybrid(ctx, configDir)
	default:
		// File mode - no database reload needed
		return nil
	}
}

// IsDBSourced returns true if a domain's config came from the database.
func (r *AgentRegistry) IsDBSourced(domain string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.dbSourcedDomains[domain]
}

// GetConfigSource returns the source of a domain's configuration.
func (r *AgentRegistry) GetConfigSource(domain string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dbSourcedDomains[domain] {
		return "database"
	}
	if _, exists := r.configs[domain]; exists {
		return "file"
	}
	return ""
}

// HybridStats provides statistics about hybrid mode operation,
// extending RegistryStats with source breakdown information.
type HybridStats struct {
	RegistryStats
	// DBSourcedDomains is the count of domains loaded from the database
	DBSourcedDomains int `json:"db_sourced_domains"`
	// FileSourcedDomains is the count of domains loaded from YAML files
	FileSourcedDomains int `json:"file_sourced_domains"`
	// Mode is the current registry operating mode (file/database/hybrid)
	Mode string `json:"mode"`
	// OrgID is the organization ID used for database queries (empty in file mode)
	OrgID string `json:"org_id,omitempty"`
}

// HybridStats returns statistics including source breakdown.
func (r *AgentRegistry) HybridStats() HybridStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	dbCount := len(r.dbSourcedDomains)
	fileCount := len(r.configs) - dbCount

	return HybridStats{
		RegistryStats: RegistryStats{
			DomainCount:   len(r.configs),
			AgentCount:    len(r.agents),
			RoutingRules:  len(r.routing),
			ConfigDir:     r.configDir,
			LastReload:    r.lastReload,
			ReloadCount:   atomic.LoadInt64(&r.reloadCount),
			DefaultDomain: r.defaultDomain,
		},
		DBSourcedDomains:  dbCount,
		FileSourcedDomains: fileCount,
		Mode:              string(r.mode),
		OrgID:             r.orgID,
	}
}
