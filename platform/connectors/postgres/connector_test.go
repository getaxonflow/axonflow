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

package postgres

import (
	"context"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

func TestNewPostgresConnector(t *testing.T) {
	conn := NewPostgresConnector()
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
	if conn.logger == nil {
		t.Error("expected logger to be initialized")
	}
}

func TestPostgresConnector_Name(t *testing.T) {
	conn := NewPostgresConnector()

	// Without config
	if got := conn.Name(); got != "postgres" {
		t.Errorf("Name() without config = %q, want %q", got, "postgres")
	}

	// With config
	conn.config = &base.ConnectorConfig{
		Name: "my-postgres",
	}
	if got := conn.Name(); got != "my-postgres" {
		t.Errorf("Name() with config = %q, want %q", got, "my-postgres")
	}
}

func TestPostgresConnector_Type(t *testing.T) {
	conn := NewPostgresConnector()
	if got := conn.Type(); got != "postgres" {
		t.Errorf("Type() = %q, want %q", got, "postgres")
	}
}

func TestPostgresConnector_Version(t *testing.T) {
	conn := NewPostgresConnector()
	if got := conn.Version(); got != "1.0.0" {
		t.Errorf("Version() = %q, want %q", got, "1.0.0")
	}
}

func TestPostgresConnector_Capabilities(t *testing.T) {
	conn := NewPostgresConnector()
	caps := conn.Capabilities()

	if len(caps) == 0 {
		t.Fatal("expected non-empty capabilities")
	}

	expected := []string{"query", "execute", "transactions", "prepared_statements", "connection_pooling"}
	for _, e := range expected {
		found := false
		for _, c := range caps {
			if c == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected capability %q not found", e)
		}
	}
}

func TestPostgresConnector_Disconnect_NilDB(t *testing.T) {
	conn := NewPostgresConnector()

	// Disconnect without connecting first should not error
	ctx := context.Background()
	err := conn.Disconnect(ctx)
	if err != nil {
		t.Errorf("Disconnect with nil db should not error: %v", err)
	}
}

func TestPostgresConnector_HealthCheck_NilDB(t *testing.T) {
	conn := NewPostgresConnector()

	ctx := context.Background()
	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status with nil db")
	}
	if status.Error != "database not connected" {
		t.Errorf("expected error message 'database not connected', got %q", status.Error)
	}
}

func TestPostgresConnector_Query_NilDB(t *testing.T) {
	conn := NewPostgresConnector()
	conn.config = &base.ConnectorConfig{Name: "test"}

	ctx := context.Background()
	query := &base.Query{
		Statement: "SELECT 1",
	}

	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error when querying with nil db")
	}
}

func TestPostgresConnector_Execute_NilDB(t *testing.T) {
	conn := NewPostgresConnector()
	conn.config = &base.ConnectorConfig{Name: "test"}

	ctx := context.Background()
	cmd := &base.Command{
		Action:    "INSERT",
		Statement: "INSERT INTO test VALUES (1)",
	}

	_, err := conn.Execute(ctx, cmd)
	if err == nil {
		t.Error("expected error when executing with nil db")
	}
}

func TestPostgresConnector_buildArgs(t *testing.T) {
	conn := NewPostgresConnector()

	// Empty params
	args, err := conn.buildArgs(nil)
	if err != nil {
		t.Errorf("unexpected error with nil params: %v", err)
	}
	if args != nil {
		t.Errorf("expected nil args for nil params, got %v", args)
	}

	// Empty map
	args, err = conn.buildArgs(map[string]interface{}{})
	if err != nil {
		t.Errorf("unexpected error with empty map: %v", err)
	}
	if args != nil {
		t.Errorf("expected nil args for empty map, got %v", args)
	}

	// With params
	params := map[string]interface{}{
		"id":   1,
		"name": "test",
	}
	args, err = conn.buildArgs(params)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(args) != 2 {
		t.Errorf("expected 2 args, got %d", len(args))
	}
}

func TestPostgresConnector_Connect_InvalidURL(t *testing.T) {
	conn := NewPostgresConnector()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	config := &base.ConnectorConfig{
		Name:          "test-pg",
		Type:          "postgres",
		ConnectionURL: "postgres://invalid:password@localhost:99999/nonexistent",
		Timeout:       100 * time.Millisecond,
		Options:       map[string]interface{}{},
	}

	err := conn.Connect(ctx, config)
	if err == nil {
		// If we somehow connected, make sure to disconnect
		conn.Disconnect(ctx)
		t.Skip("Unexpectedly connected (PostgreSQL may be running locally)")
	}
	// Error is expected - connection should fail
}

func TestPostgresConnector_Connect_WithOptions(t *testing.T) {
	conn := NewPostgresConnector()

	config := &base.ConnectorConfig{
		Name:          "test-pg",
		Type:          "postgres",
		ConnectionURL: "postgres://localhost:5432/test", // Won't actually connect
		Timeout:       100 * time.Millisecond,
		Options: map[string]interface{}{
			"max_open_conns":    10,
			"max_idle_conns":    2,
			"conn_max_lifetime": "10m",
		},
	}

	// This will fail to connect (no DB), but options should be parsed
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := conn.Connect(ctx, config)
	// Error is expected - we just want to verify options parsing doesn't panic
	if err == nil {
		conn.Disconnect(ctx)
	}
}
