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

package agent

import (
	"fmt"
	"log"
	"sync"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/cassandra"
	httpconnector "axonflow/platform/connectors/http"
	"axonflow/platform/connectors/mongodb"
	"axonflow/platform/connectors/mysql"
	"axonflow/platform/connectors/postgres"
	"axonflow/platform/connectors/redis"
)

// ConnectorCreator is a function that creates a new connector instance.
type ConnectorCreator func() base.Connector

// ConnectorFactoryRegistry holds registered connector creators.
// It provides a central registry for creating connector instances by type.
type ConnectorFactoryRegistry struct {
	mu       sync.RWMutex
	creators map[string]ConnectorCreator
	logger   *log.Logger
}

// defaultConnectorFactory is the global connector factory instance.
var defaultConnectorFactory *ConnectorFactoryRegistry
var defaultConnectorFactoryOnce sync.Once

// GetDefaultConnectorFactory returns the singleton ConnectorFactoryRegistry.
// It initializes the factory with all Community connectors on first call.
func GetDefaultConnectorFactory() *ConnectorFactoryRegistry {
	defaultConnectorFactoryOnce.Do(func() {
		defaultConnectorFactory = NewConnectorFactoryRegistry()
		defaultConnectorFactory.RegisterCommunityConnectors()
	})
	return defaultConnectorFactory
}

// NewConnectorFactoryRegistry creates a new empty connector factory.
func NewConnectorFactoryRegistry() *ConnectorFactoryRegistry {
	return &ConnectorFactoryRegistry{
		creators: make(map[string]ConnectorCreator),
		logger:   log.New(log.Writer(), "[CONNECTOR_FACTORY] ", log.LstdFlags),
	}
}

// Register adds a connector creator to the factory.
// Returns an error if the type is already registered.
func (f *ConnectorFactoryRegistry) Register(connectorType string, creator ConnectorCreator) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !IsValidConnectorType(connectorType) {
		return fmt.Errorf("unknown connector type: %s", connectorType)
	}

	if _, exists := f.creators[connectorType]; exists {
		return fmt.Errorf("connector type '%s' already registered", connectorType)
	}

	f.creators[connectorType] = creator
	f.logger.Printf("Registered connector creator for type: %s", connectorType)
	return nil
}

// RegisterOrReplace adds or replaces a connector creator.
// This is useful for testing or replacing default implementations.
func (f *ConnectorFactoryRegistry) RegisterOrReplace(connectorType string, creator ConnectorCreator) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.creators[connectorType] = creator
	f.logger.Printf("Registered/replaced connector creator for type: %s", connectorType)
}

// Create instantiates a new connector of the given type.
// Returns an error if the type is not registered.
func (f *ConnectorFactoryRegistry) Create(connectorType string) (base.Connector, error) {
	f.mu.RLock()
	creator, exists := f.creators[connectorType]
	f.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no creator registered for connector type: %s", connectorType)
	}

	connector := creator()
	f.logger.Printf("Created connector instance for type: %s", connectorType)
	return connector, nil
}

// IsRegistered checks if a connector type has a creator registered.
func (f *ConnectorFactoryRegistry) IsRegistered(connectorType string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, exists := f.creators[connectorType]
	return exists
}

// RegisteredTypes returns a list of all registered connector types.
func (f *ConnectorFactoryRegistry) RegisteredTypes() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	types := make([]string, 0, len(f.creators))
	for t := range f.creators {
		types = append(types, t)
	}
	return types
}

// Count returns the number of registered connector types.
func (f *ConnectorFactoryRegistry) Count() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.creators)
}

// Clear removes all registered creators.
// Useful for testing.
func (f *ConnectorFactoryRegistry) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creators = make(map[string]ConnectorCreator)
}

// RegisterCommunityConnectors registers all Community connector creators.
// These are the connectors available in the Community version.
func (f *ConnectorFactoryRegistry) RegisterCommunityConnectors() {
	f.logger.Println("Registering Community connectors...")

	// Database connectors
	f.RegisterOrReplace(ConnectorPostgres, func() base.Connector {
		return postgres.NewPostgresConnector()
	})

	f.RegisterOrReplace(ConnectorMySQL, func() base.Connector {
		return mysql.NewMySQLConnector()
	})

	f.RegisterOrReplace(ConnectorMongoDB, func() base.Connector {
		return mongodb.NewMongoDBConnector()
	})

	f.RegisterOrReplace(ConnectorCassandra, func() base.Connector {
		return cassandra.NewCassandraConnector()
	})

	f.RegisterOrReplace(ConnectorRedis, func() base.Connector {
		return redis.NewRedisConnector()
	})

	// HTTP connector (generic API access)
	f.RegisterOrReplace(ConnectorHTTP, func() base.Connector {
		return httpconnector.NewHTTPConnector()
	})

	f.logger.Printf("Registered %d Community connectors", f.Count())
}

// DefaultConnectorFactory returns a ConnectorFactory function for use with TenantConnectorRegistry.
// This adapts the ConnectorFactoryRegistry to the ConnectorFactory type expected by the registry.
func DefaultConnectorFactory() ConnectorFactory {
	factory := GetDefaultConnectorFactory()

	return func(connectorType string) (base.Connector, error) {
		return factory.Create(connectorType)
	}
}

// CreateConnectorFactory creates a ConnectorFactory function from a ConnectorFactoryRegistry.
// This allows customization of which connectors are available.
func CreateConnectorFactory(registry *ConnectorFactoryRegistry) ConnectorFactory {
	return func(connectorType string) (base.Connector, error) {
		return registry.Create(connectorType)
	}
}
