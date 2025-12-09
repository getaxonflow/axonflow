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

package agent

import (
	"context"
	"sync"
	"testing"

	"axonflow/platform/connectors/base"
)

// factoryMockConnector implements base.Connector for factory tests
type factoryMockConnector struct {
	connectorType string
}

func (m *factoryMockConnector) Connect(ctx context.Context, cfg *base.ConnectorConfig) error {
	return nil
}
func (m *factoryMockConnector) Disconnect(ctx context.Context) error { return nil }
func (m *factoryMockConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{Healthy: true}, nil
}
func (m *factoryMockConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	return &base.QueryResult{}, nil
}
func (m *factoryMockConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return &base.CommandResult{}, nil
}
func (m *factoryMockConnector) Name() string           { return "mock" }
func (m *factoryMockConnector) Type() string           { return m.connectorType }
func (m *factoryMockConnector) Version() string        { return "1.0.0" }
func (m *factoryMockConnector) Capabilities() []string { return []string{"query"} }

func TestNewConnectorFactoryRegistry(t *testing.T) {
	factory := NewConnectorFactoryRegistry()

	if factory == nil {
		t.Fatal("Expected non-nil factory")
	}

	if factory.creators == nil {
		t.Error("Expected creators map to be initialized")
	}

	if factory.Count() != 0 {
		t.Errorf("Expected 0 creators, got %d", factory.Count())
	}
}

func TestConnectorFactoryRegistry_Register(t *testing.T) {
	factory := NewConnectorFactoryRegistry()

	// Register a valid connector type
	err := factory.Register(ConnectorPostgres, func() base.Connector {
		return &factoryMockConnector{connectorType: "postgres"}
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !factory.IsRegistered(ConnectorPostgres) {
		t.Error("Expected postgres to be registered")
	}

	// Try to register the same type again (should fail)
	err = factory.Register(ConnectorPostgres, func() base.Connector {
		return &factoryMockConnector{connectorType: "postgres"}
	})

	if err == nil {
		t.Error("Expected error when registering duplicate type")
	}
}

func TestConnectorFactoryRegistry_Register_InvalidType(t *testing.T) {
	factory := NewConnectorFactoryRegistry()

	err := factory.Register("invalid_type", func() base.Connector {
		return &factoryMockConnector{}
	})

	if err == nil {
		t.Error("Expected error for invalid connector type")
	}
}

func TestConnectorFactoryRegistry_RegisterOrReplace(t *testing.T) {
	factory := NewConnectorFactoryRegistry()

	// First registration
	factory.RegisterOrReplace(ConnectorPostgres, func() base.Connector {
		return &factoryMockConnector{connectorType: "postgres-v1"}
	})

	conn1, _ := factory.Create(ConnectorPostgres)
	if conn1.Type() != "postgres-v1" {
		t.Errorf("Expected type 'postgres-v1', got '%s'", conn1.Type())
	}

	// Replace
	factory.RegisterOrReplace(ConnectorPostgres, func() base.Connector {
		return &factoryMockConnector{connectorType: "postgres-v2"}
	})

	conn2, _ := factory.Create(ConnectorPostgres)
	if conn2.Type() != "postgres-v2" {
		t.Errorf("Expected type 'postgres-v2', got '%s'", conn2.Type())
	}
}

func TestConnectorFactoryRegistry_Create(t *testing.T) {
	factory := NewConnectorFactoryRegistry()

	factory.RegisterOrReplace(ConnectorMySQL, func() base.Connector {
		return &factoryMockConnector{connectorType: "mysql"}
	})

	// Create registered type
	conn, err := factory.Create(ConnectorMySQL)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if conn == nil {
		t.Fatal("Expected non-nil connector")
	}
	if conn.Type() != "mysql" {
		t.Errorf("Expected type 'mysql', got '%s'", conn.Type())
	}

	// Try to create unregistered type
	_, err = factory.Create(ConnectorMongoDB)
	if err == nil {
		t.Error("Expected error for unregistered type")
	}
}

func TestConnectorFactoryRegistry_IsRegistered(t *testing.T) {
	factory := NewConnectorFactoryRegistry()

	if factory.IsRegistered(ConnectorPostgres) {
		t.Error("Expected postgres to not be registered initially")
	}

	factory.RegisterOrReplace(ConnectorPostgres, func() base.Connector {
		return &factoryMockConnector{}
	})

	if !factory.IsRegistered(ConnectorPostgres) {
		t.Error("Expected postgres to be registered after registration")
	}
}

func TestConnectorFactoryRegistry_RegisteredTypes(t *testing.T) {
	factory := NewConnectorFactoryRegistry()

	factory.RegisterOrReplace(ConnectorPostgres, func() base.Connector {
		return &factoryMockConnector{}
	})
	factory.RegisterOrReplace(ConnectorMySQL, func() base.Connector {
		return &factoryMockConnector{}
	})

	types := factory.RegisteredTypes()

	if len(types) != 2 {
		t.Errorf("Expected 2 types, got %d", len(types))
	}

	// Check both types are present
	found := make(map[string]bool)
	for _, ct := range types {
		found[ct] = true
	}
	if !found[ConnectorPostgres] || !found[ConnectorMySQL] {
		t.Errorf("Expected postgres and mysql, got %v", types)
	}
}

func TestConnectorFactoryRegistry_Count(t *testing.T) {
	factory := NewConnectorFactoryRegistry()

	if factory.Count() != 0 {
		t.Errorf("Expected 0 initially, got %d", factory.Count())
	}

	factory.RegisterOrReplace(ConnectorPostgres, func() base.Connector {
		return &factoryMockConnector{}
	})

	if factory.Count() != 1 {
		t.Errorf("Expected 1 after registration, got %d", factory.Count())
	}
}

func TestConnectorFactoryRegistry_Clear(t *testing.T) {
	factory := NewConnectorFactoryRegistry()

	factory.RegisterOrReplace(ConnectorPostgres, func() base.Connector {
		return &factoryMockConnector{}
	})
	factory.RegisterOrReplace(ConnectorMySQL, func() base.Connector {
		return &factoryMockConnector{}
	})

	if factory.Count() != 2 {
		t.Errorf("Expected 2 before clear, got %d", factory.Count())
	}

	factory.Clear()

	if factory.Count() != 0 {
		t.Errorf("Expected 0 after clear, got %d", factory.Count())
	}
}

func TestConnectorFactoryRegistry_RegisterOSSConnectors(t *testing.T) {
	factory := NewConnectorFactoryRegistry()
	factory.RegisterOSSConnectors()

	// OSS connectors: postgres, mysql, mongodb, cassandra, redis, http
	expectedOSSConnectors := []string{
		ConnectorPostgres,
		ConnectorMySQL,
		ConnectorMongoDB,
		ConnectorCassandra,
		ConnectorRedis,
		ConnectorHTTP,
	}

	for _, ct := range expectedOSSConnectors {
		if !factory.IsRegistered(ct) {
			t.Errorf("Expected OSS connector '%s' to be registered", ct)
		}
	}

	// Verify we can create each one
	for _, ct := range expectedOSSConnectors {
		conn, err := factory.Create(ct)
		if err != nil {
			t.Errorf("Failed to create '%s' connector: %v", ct, err)
			continue
		}
		if conn == nil {
			t.Errorf("Expected non-nil connector for '%s'", ct)
		}
	}
}

func TestGetDefaultConnectorFactory(t *testing.T) {
	factory := GetDefaultConnectorFactory()

	if factory == nil {
		t.Fatal("Expected non-nil default factory")
	}

	// Should have OSS connectors registered
	if factory.Count() < 6 {
		t.Errorf("Expected at least 6 OSS connectors, got %d", factory.Count())
	}

	// Verify singleton behavior
	factory2 := GetDefaultConnectorFactory()
	if factory != factory2 {
		t.Error("Expected same factory instance (singleton)")
	}
}

func TestDefaultConnectorFactory(t *testing.T) {
	factory := DefaultConnectorFactory()

	if factory == nil {
		t.Fatal("Expected non-nil factory function")
	}

	// Test creating a postgres connector
	conn, err := factory(ConnectorPostgres)
	if err != nil {
		t.Fatalf("Expected no error creating postgres, got: %v", err)
	}
	if conn == nil {
		t.Fatal("Expected non-nil connector")
	}
	if conn.Type() != "postgres" {
		t.Errorf("Expected type 'postgres', got '%s'", conn.Type())
	}
}

func TestCreateConnectorFactory(t *testing.T) {
	registry := NewConnectorFactoryRegistry()
	registry.RegisterOrReplace(ConnectorRedis, func() base.Connector {
		return &factoryMockConnector{connectorType: "custom-redis"}
	})

	factory := CreateConnectorFactory(registry)

	conn, err := factory(ConnectorRedis)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if conn.Type() != "custom-redis" {
		t.Errorf("Expected type 'custom-redis', got '%s'", conn.Type())
	}
}

func TestConnectorFactoryRegistry_ConcurrentAccess(t *testing.T) {
	factory := NewConnectorFactoryRegistry()

	var wg sync.WaitGroup

	// Concurrent registrations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			connType := ValidConnectorTypes[idx%len(ValidConnectorTypes)]
			factory.RegisterOrReplace(connType, func() base.Connector {
				return &factoryMockConnector{connectorType: connType}
			})
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = factory.RegisteredTypes()
			_ = factory.Count()
			factory.IsRegistered(ConnectorPostgres)
		}()
	}

	// Concurrent creates
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			connType := ValidConnectorTypes[idx%len(ValidConnectorTypes)]
			_, _ = factory.Create(connType)
		}(i)
	}

	wg.Wait()

	// Test passes if no deadlocks or panics
}
