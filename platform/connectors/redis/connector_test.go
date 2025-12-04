// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package redis

import (
	"context"
	"testing"

	"axonflow/platform/connectors/base"
)

func TestNewRedisConnector(t *testing.T) {
	conn := NewRedisConnector()
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
	if conn.logger == nil {
		t.Error("expected logger to be initialized")
	}
}

func TestRedisConnector_Name(t *testing.T) {
	conn := NewRedisConnector()

	// Without config
	if got := conn.Name(); got != "redis-connector" {
		t.Errorf("Name() = %q, want %q", got, "redis-connector")
	}

	// With config
	conn.config = &base.ConnectorConfig{Name: "my-redis"}
	if got := conn.Name(); got != "my-redis" {
		t.Errorf("Name() = %q, want %q", got, "my-redis")
	}
}

func TestRedisConnector_Type(t *testing.T) {
	conn := NewRedisConnector()
	if got := conn.Type(); got != "redis" {
		t.Errorf("Type() = %q, want %q", got, "redis")
	}
}

func TestRedisConnector_Version(t *testing.T) {
	conn := NewRedisConnector()
	if got := conn.Version(); got != "0.2.0" {
		t.Errorf("Version() = %q, want %q", got, "0.2.0")
	}
}

func TestRedisConnector_Capabilities(t *testing.T) {
	conn := NewRedisConnector()
	caps := conn.Capabilities()

	expected := []string{"query", "execute", "cache", "kv-store"}
	if len(caps) != len(expected) {
		t.Errorf("expected %d capabilities, got %d", len(expected), len(caps))
	}
	for i, c := range caps {
		if c != expected[i] {
			t.Errorf("capability %d: got %q, want %q", i, c, expected[i])
		}
	}
}

func TestRedisConnector_Disconnect_NilClient(t *testing.T) {
	conn := NewRedisConnector()
	ctx := context.Background()

	err := conn.Disconnect(ctx)
	if err != nil {
		t.Errorf("Disconnect with nil client should not error: %v", err)
	}
}

func TestRedisConnector_HealthCheck_NilClient(t *testing.T) {
	conn := NewRedisConnector()
	ctx := context.Background()

	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status with nil client")
	}
	if status.Error != "client not connected" {
		t.Errorf("expected error 'client not connected', got %q", status.Error)
	}
}

func TestRedisConnector_Query_NilClient(t *testing.T) {
	conn := NewRedisConnector()
	conn.config = &base.ConnectorConfig{Name: "test"}
	ctx := context.Background()

	query := &base.Query{Statement: "GET"}
	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error when querying with nil client")
	}
}

func TestRedisConnector_Execute_NilClient(t *testing.T) {
	conn := NewRedisConnector()
	conn.config = &base.ConnectorConfig{Name: "test"}
	ctx := context.Background()

	cmd := &base.Command{Action: "SET"}
	_, err := conn.Execute(ctx, cmd)
	if err == nil {
		t.Error("expected error when executing with nil client")
	}
}

func TestRedisConnector_Query_UnsupportedOperation(t *testing.T) {
	conn := NewRedisConnector()
	conn.config = &base.ConnectorConfig{Name: "test"}
	// Simulate connected state but nil client - will fail on operation
	ctx := context.Background()

	query := &base.Query{Statement: "INVALID"}
	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error for nil client")
	}
}

func TestRedisConnector_Execute_UnsupportedAction(t *testing.T) {
	conn := NewRedisConnector()
	conn.config = &base.ConnectorConfig{Name: "test"}
	ctx := context.Background()

	cmd := &base.Command{Action: "INVALID"}
	_, err := conn.Execute(ctx, cmd)
	if err == nil {
		t.Error("expected error for nil client")
	}
}
