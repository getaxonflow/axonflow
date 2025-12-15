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

/*
Package registry provides a thread-safe registry for managing MCP connectors
in AxonFlow.

# Overview

The Registry is the central management point for all MCP connectors. It handles:

  - Connector registration and lifecycle management
  - Lazy loading of connectors from PostgreSQL storage
  - Multi-tenant isolation and access control
  - Health checking across all registered connectors
  - Automatic synchronization across Orchestrator replicas

# Creating a Registry

For in-memory storage (development):

	registry := NewRegistry()

For persistent storage (production):

	registry, err := NewRegistryWithStorage(databaseURL)
	if err != nil {
	    log.Fatal(err)
	}

# Registering Connectors

Register a connector with its configuration:

	config := &base.ConnectorConfig{
	    Name:          "sales-postgres",
	    Type:          "postgres",
	    ConnectionURL: "postgres://...",
	    TenantID:      "tenant-123",
	    Timeout:       5 * time.Second,
	}

	err := registry.Register("sales-postgres", postgresConnector, config)

# Using Connectors

Retrieve and use a registered connector:

	connector, err := registry.Get("sales-postgres")
	if err != nil {
	    return err
	}

	result, err := connector.Query(ctx, &base.Query{
	    Statement: "SELECT * FROM customers",
	})

# Multi-Tenant Access Control

The registry enforces tenant isolation:

	// Check if tenant can access a connector
	err := registry.ValidateTenantAccess("sales-postgres", "tenant-123")
	if err != nil {
	    return err // Access denied
	}

	// List all connectors for a tenant
	connectors := registry.GetConnectorsByTenant("tenant-123")

# Lazy Loading

With PostgreSQL storage, connectors are loaded on first access:

	// Set up factory for lazy loading
	registry.SetFactory(func(connectorType string) (base.Connector, error) {
	    switch connectorType {
	    case "postgres":
	        return postgres.New(), nil
	    case "cassandra":
	        return cassandra.New(), nil
	    default:
	        return nil, fmt.Errorf("unknown connector type: %s", connectorType)
	    }
	})

	// Connector is loaded and connected on first Get()
	connector, err := registry.Get("delayed-connector")

# Synchronization Across Replicas

In multi-replica deployments, start periodic reload:

	ctx := context.Background()
	registry.StartPeriodicReload(ctx, 30*time.Second)

This ensures connectors registered by one replica are available to others.

# Health Checking

Check health of all registered connectors:

	health := registry.HealthCheck(ctx)
	for name, status := range health {
	    if !status.Healthy {
	        log.Printf("Connector %s unhealthy: %s", name, status.Error)
	    }
	}

# Graceful Shutdown

Disconnect all connectors on shutdown:

	registry.DisconnectAll(ctx)

# Thread Safety

The Registry is safe for concurrent use. All methods use sync.RWMutex
for proper synchronization. Multiple goroutines can register, retrieve,
and query connectors simultaneously.
*/
package registry
