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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockDatabaseAgentSource implements DatabaseAgentSource for testing
type MockDatabaseAgentSource struct {
	agents []*AgentConfigFile
	err    error
}

func (m *MockDatabaseAgentSource) ListActiveAgents(ctx context.Context, orgID string) ([]*AgentConfigFile, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.agents, nil
}

func (m *MockDatabaseAgentSource) GetAgentByName(ctx context.Context, orgID, name string) (*AgentConfigFile, error) {
	if m.err != nil {
		return nil, m.err
	}
	for _, agent := range m.agents {
		if agent.Metadata.Name == name {
			return agent, nil
		}
	}
	return nil, nil
}

func createTestDBConfig(name, domain string) *AgentConfigFile {
	return &AgentConfigFile{
		APIVersion: "axonflow.io/v1",
		Kind:       "AgentConfig",
		Metadata: AgentMetadata{
			Name:        name,
			Domain:      domain,
			Description: "Test config from DB",
		},
		Spec: AgentConfigSpec{
			Execution: GetDefaultExecutionConfig(),
			Agents: []AgentDef{
				{
					Name:           "db-agent",
					Description:    "Agent from database",
					Type:           "llm-call",
					PromptTemplate: "Test prompt",
				},
			},
			Routing: []RoutingRule{
				{Pattern: "db.*", Agent: "db-agent", Priority: 20},
			},
		},
	}
}

func TestAgentRegistry_SetDatabaseSource(t *testing.T) {
	registry := NewAgentRegistry()
	mockSource := &MockDatabaseAgentSource{}
	orgID := "org-123"

	registry.SetDatabaseSource(mockSource, orgID)

	assert.Equal(t, RegistryModeHybrid, registry.GetMode())
}

func TestAgentRegistry_SetMode(t *testing.T) {
	registry := NewAgentRegistry()

	registry.SetMode(RegistryModeDatabase)
	assert.Equal(t, RegistryModeDatabase, registry.GetMode())

	registry.SetMode(RegistryModeHybrid)
	assert.Equal(t, RegistryModeHybrid, registry.GetMode())

	registry.SetMode(RegistryModeFile)
	assert.Equal(t, RegistryModeFile, registry.GetMode())
}

func TestAgentRegistry_LoadFromDatabase(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	dbConfigs := []*AgentConfigFile{
		createTestDBConfig("db-travel", "travel"),
		createTestDBConfig("db-healthcare", "healthcare"),
	}

	mockSource := &MockDatabaseAgentSource{agents: dbConfigs}
	registry.SetDatabaseSource(mockSource, "org-123")

	err := registry.LoadFromDatabase(ctx)
	require.NoError(t, err)

	// Verify configs were loaded
	assert.True(t, registry.HasDomain("travel"))
	assert.True(t, registry.HasDomain("healthcare"))

	// Verify agents are accessible
	assert.True(t, registry.HasAgent("db-agent"))
	assert.True(t, registry.HasAgent("travel/db-agent"))
	assert.True(t, registry.HasAgent("healthcare/db-agent"))

	// Verify source tracking
	assert.True(t, registry.IsDBSourced("travel"))
	assert.True(t, registry.IsDBSourced("healthcare"))
	assert.Equal(t, "database", registry.GetConfigSource("travel"))
}

func TestAgentRegistry_LoadFromDatabase_NoSource(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	err := registry.LoadFromDatabase(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database source not configured")
}

func TestAgentRegistry_LoadFromDatabase_NoOrgID(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	mockSource := &MockDatabaseAgentSource{}
	// Set source with empty orgID using the public API
	registry.SetDatabaseSource(mockSource, "")

	err := registry.LoadFromDatabase(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "organization ID not set")
}

func TestAgentRegistry_HybridMode_DBOverridesFile(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	// Register a file-based config for travel
	fileConfig := &AgentConfigFile{
		APIVersion: "axonflow.io/v1",
		Kind:       "AgentConfig",
		Metadata: AgentMetadata{
			Name:        "file-travel",
			Domain:      "travel",
			Description: "File-based travel config",
		},
		Spec: AgentConfigSpec{
			Execution: GetDefaultExecutionConfig(),
			Agents: []AgentDef{
				{
					Name:           "file-agent",
					Type:           "llm-call",
					PromptTemplate: "File prompt",
				},
			},
			Routing: []RoutingRule{
				{Pattern: "file.*", Agent: "file-agent", Priority: 10},
			},
		},
	}
	err := registry.RegisterConfig(fileConfig)
	require.NoError(t, err)

	// Verify file config is loaded
	assert.True(t, registry.HasAgent("file-agent"))
	assert.False(t, registry.IsDBSourced("travel"))

	// Now load DB config for same domain
	dbConfig := createTestDBConfig("db-travel", "travel")
	mockSource := &MockDatabaseAgentSource{agents: []*AgentConfigFile{dbConfig}}
	registry.SetDatabaseSource(mockSource, "org-123")

	err = registry.LoadFromDatabase(ctx)
	require.NoError(t, err)

	// Verify DB config overrides file config
	assert.True(t, registry.HasAgent("db-agent"))
	assert.True(t, registry.IsDBSourced("travel"))

	// File agent should still be accessible due to simple name lookup,
	// but the travel domain now has DB config
	config, err := registry.GetConfig("travel")
	require.NoError(t, err)
	assert.Equal(t, "db-travel", config.Metadata.Name)
}

func TestAgentRegistry_HybridStats(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	// Register file config
	fileConfig := &AgentConfigFile{
		APIVersion: "axonflow.io/v1",
		Kind:       "AgentConfig",
		Metadata: AgentMetadata{
			Name:   "file-generic",
			Domain: "generic",
		},
		Spec: AgentConfigSpec{
			Execution: GetDefaultExecutionConfig(),
			Agents: []AgentDef{
				{
					Name:           "generic-agent",
					Type:           "llm-call",
					PromptTemplate: "Generic",
				},
			},
			Routing: []RoutingRule{
				{Pattern: ".*", Agent: "generic-agent"},
			},
		},
	}
	_ = registry.RegisterConfig(fileConfig)

	// Register DB config
	dbConfig := createTestDBConfig("db-travel", "travel")
	mockSource := &MockDatabaseAgentSource{agents: []*AgentConfigFile{dbConfig}}
	registry.SetDatabaseSource(mockSource, "org-123")
	_ = registry.LoadFromDatabase(ctx)

	stats := registry.HybridStats()

	assert.Equal(t, 2, stats.DomainCount)
	assert.Equal(t, 1, stats.DBSourcedDomains)
	assert.Equal(t, 1, stats.FileSourcedDomains)
	assert.Equal(t, "hybrid", stats.Mode)
	assert.Equal(t, "org-123", stats.OrgID)
}

func TestAgentRegistry_ReloadFromDatabase(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	dbConfigs := []*AgentConfigFile{
		createTestDBConfig("db-travel", "travel"),
	}

	mockSource := &MockDatabaseAgentSource{agents: dbConfigs}
	registry.SetDatabaseSource(mockSource, "org-123")

	err := registry.LoadFromDatabase(ctx)
	require.NoError(t, err)

	initialReloadCount := registry.Stats().ReloadCount

	// Update mock data
	mockSource.agents = append(mockSource.agents, createTestDBConfig("db-healthcare", "healthcare"))

	// Reload
	err = registry.ReloadFromDatabase(ctx)
	require.NoError(t, err)

	// Verify new config was loaded
	assert.True(t, registry.HasDomain("healthcare"))
	assert.Greater(t, registry.Stats().ReloadCount, initialReloadCount)
}

func TestAgentRegistry_ReloadFromDatabase_FileMode(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	// File mode - reload should be no-op
	registry.SetMode(RegistryModeFile)

	err := registry.ReloadFromDatabase(ctx)
	require.NoError(t, err) // Should not error in file mode
}

func TestAgentRegistry_GetConfigSource(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	// Register file config
	fileConfig := &AgentConfigFile{
		APIVersion: "axonflow.io/v1",
		Kind:       "AgentConfig",
		Metadata: AgentMetadata{
			Name:   "file-generic",
			Domain: "generic",
		},
		Spec: AgentConfigSpec{
			Execution: GetDefaultExecutionConfig(),
			Agents: []AgentDef{
				{
					Name:           "generic-agent",
					Type:           "llm-call",
					PromptTemplate: "Generic",
				},
			},
			Routing: []RoutingRule{
				{Pattern: ".*", Agent: "generic-agent"},
			},
		},
	}
	_ = registry.RegisterConfig(fileConfig)

	// Register DB config
	dbConfig := createTestDBConfig("db-travel", "travel")
	mockSource := &MockDatabaseAgentSource{agents: []*AgentConfigFile{dbConfig}}
	registry.SetDatabaseSource(mockSource, "org-123")
	_ = registry.LoadFromDatabase(ctx)

	assert.Equal(t, "file", registry.GetConfigSource("generic"))
	assert.Equal(t, "database", registry.GetConfigSource("travel"))
	assert.Equal(t, "", registry.GetConfigSource("nonexistent"))
}

func TestAgentRegistry_DBRouting(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	// Create DB config with high priority routing
	dbConfig := &AgentConfigFile{
		APIVersion: "axonflow.io/v1",
		Kind:       "AgentConfig",
		Metadata: AgentMetadata{
			Name:   "db-travel",
			Domain: "travel",
		},
		Spec: AgentConfigSpec{
			Execution: GetDefaultExecutionConfig(),
			Agents: []AgentDef{
				{
					Name:           "flight-agent",
					Type:           "llm-call",
					PromptTemplate: "Find flights",
				},
				{
					Name:           "hotel-agent",
					Type:           "llm-call",
					PromptTemplate: "Find hotels",
				},
			},
			Routing: []RoutingRule{
				{Pattern: "flight|fly|airplane", Agent: "flight-agent", Priority: 20},
				{Pattern: "hotel|stay|accommodation", Agent: "hotel-agent", Priority: 20},
			},
		},
	}

	mockSource := &MockDatabaseAgentSource{agents: []*AgentConfigFile{dbConfig}}
	registry.SetDatabaseSource(mockSource, "org-123")
	_ = registry.LoadFromDatabase(ctx)

	// Test routing
	agent, domain, err := registry.RouteTask("find a flight to Paris")
	require.NoError(t, err)
	assert.Equal(t, "flight-agent", agent.Name)
	assert.Equal(t, "travel", domain)

	agent, domain, err = registry.RouteTask("book a hotel in London")
	require.NoError(t, err)
	assert.Equal(t, "hotel-agent", agent.Name)
	assert.Equal(t, "travel", domain)
}

func TestAgentRegistry_EmptyDBConfigs(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	mockSource := &MockDatabaseAgentSource{agents: []*AgentConfigFile{}}
	registry.SetDatabaseSource(mockSource, "org-123")

	err := registry.LoadFromDatabase(ctx)
	require.NoError(t, err) // Should not error on empty configs

	stats := registry.HybridStats()
	assert.Equal(t, 0, stats.DBSourcedDomains)
}

func TestAgentRegistry_LoadFromDatabase_Error(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	mockSource := &MockDatabaseAgentSource{
		err: fmt.Errorf("connection refused"),
	}
	registry.SetDatabaseSource(mockSource, "org-123")

	err := registry.LoadFromDatabase(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load agents from database")
	assert.Contains(t, err.Error(), "connection refused")
}

func TestAgentRegistry_LoadFromDatabase_ContextCancellation(t *testing.T) {
	registry := NewAgentRegistry()

	// Create an already cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mockSource := &MockDatabaseAgentSource{}
	registry.SetDatabaseSource(mockSource, "org-123")

	err := registry.LoadFromDatabase(ctx)
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestAgentRegistry_LoadFromDatabase_ClearsOldDBConfigs(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	// First load: one config
	mockSource := &MockDatabaseAgentSource{
		agents: []*AgentConfigFile{
			createTestDBConfig("db-travel", "travel"),
		},
	}
	registry.SetDatabaseSource(mockSource, "org-123")
	err := registry.LoadFromDatabase(ctx)
	require.NoError(t, err)

	assert.True(t, registry.HasDomain("travel"))
	assert.Equal(t, 1, registry.HybridStats().DBSourcedDomains)

	// Second load: different config (simulates DB change)
	mockSource.agents = []*AgentConfigFile{
		createTestDBConfig("db-healthcare", "healthcare"),
	}

	err = registry.LoadFromDatabase(ctx)
	require.NoError(t, err)

	// Old travel domain should be gone, new healthcare should exist
	assert.False(t, registry.HasDomain("travel"))
	assert.True(t, registry.HasDomain("healthcare"))
	assert.Equal(t, 1, registry.HybridStats().DBSourcedDomains)
}

func TestAgentRegistry_DBOverridesFile_AgentCleanup(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	// Register a file-based config with unique agent name
	fileConfig := &AgentConfigFile{
		APIVersion: "axonflow.io/v1",
		Kind:       "AgentConfig",
		Metadata: AgentMetadata{
			Name:   "file-travel",
			Domain: "travel",
		},
		Spec: AgentConfigSpec{
			Execution: GetDefaultExecutionConfig(),
			Agents: []AgentDef{
				{
					Name:           "file-only-agent",
					Type:           "llm-call",
					PromptTemplate: "File prompt",
				},
			},
			Routing: []RoutingRule{
				{Pattern: "file.*", Agent: "file-only-agent", Priority: 10},
			},
		},
	}
	err := registry.RegisterConfig(fileConfig)
	require.NoError(t, err)

	// Verify file agent exists
	assert.True(t, registry.HasAgent("file-only-agent"))
	assert.True(t, registry.HasAgent("travel/file-only-agent"))

	// Now load DB config for same domain with different agent
	dbConfig := createTestDBConfig("db-travel", "travel")
	mockSource := &MockDatabaseAgentSource{agents: []*AgentConfigFile{dbConfig}}
	registry.SetDatabaseSource(mockSource, "org-123")

	err = registry.LoadFromDatabase(ctx)
	require.NoError(t, err)

	// DB agent should exist
	assert.True(t, registry.HasAgent("db-agent"))
	assert.True(t, registry.HasAgent("travel/db-agent"))

	// File agent's qualified name should be removed (domain was overridden)
	assert.False(t, registry.HasAgent("travel/file-only-agent"))
}
