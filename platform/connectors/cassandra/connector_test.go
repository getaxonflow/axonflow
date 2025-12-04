// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cassandra

import (
	"context"
	"testing"

	"axonflow/platform/connectors/base"
)

func TestNewCassandraConnector(t *testing.T) {
	conn := NewCassandraConnector()
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
	if conn.logger == nil {
		t.Error("expected logger to be initialized")
	}
}

func TestCassandraConnector_Name(t *testing.T) {
	conn := NewCassandraConnector()

	// Without config
	if got := conn.Name(); got != "cassandra" {
		t.Errorf("Name() = %q, want %q", got, "cassandra")
	}

	// With config
	conn.config = &base.ConnectorConfig{Name: "my-cassandra"}
	if got := conn.Name(); got != "my-cassandra" {
		t.Errorf("Name() = %q, want %q", got, "my-cassandra")
	}
}

func TestCassandraConnector_Type(t *testing.T) {
	conn := NewCassandraConnector()
	if got := conn.Type(); got != "cassandra" {
		t.Errorf("Type() = %q, want %q", got, "cassandra")
	}
}

func TestCassandraConnector_Version(t *testing.T) {
	conn := NewCassandraConnector()
	if got := conn.Version(); got != "1.0.0" {
		t.Errorf("Version() = %q, want %q", got, "1.0.0")
	}
}

func TestCassandraConnector_Capabilities(t *testing.T) {
	conn := NewCassandraConnector()
	caps := conn.Capabilities()

	if len(caps) == 0 {
		t.Fatal("expected non-empty capabilities")
	}

	expected := []string{"query", "execute", "batch_operations", "consistency_levels", "token_aware_routing"}
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

func TestCassandraConnector_Disconnect_NilSession(t *testing.T) {
	conn := NewCassandraConnector()
	ctx := context.Background()

	err := conn.Disconnect(ctx)
	if err != nil {
		t.Errorf("Disconnect with nil session should not error: %v", err)
	}
}

func TestCassandraConnector_HealthCheck_NilSession(t *testing.T) {
	conn := NewCassandraConnector()
	ctx := context.Background()

	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status with nil session")
	}
	if status.Error != "session not connected" {
		t.Errorf("expected error 'session not connected', got %q", status.Error)
	}
}

func TestCassandraConnector_Query_NilSession(t *testing.T) {
	conn := NewCassandraConnector()
	conn.config = &base.ConnectorConfig{Name: "test"}
	ctx := context.Background()

	query := &base.Query{Statement: "SELECT * FROM test"}
	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error when querying with nil session")
	}
}

func TestCassandraConnector_Execute_NilSession(t *testing.T) {
	conn := NewCassandraConnector()
	conn.config = &base.ConnectorConfig{Name: "test"}
	ctx := context.Background()

	cmd := &base.Command{Action: "INSERT", Statement: "INSERT INTO test VALUES (?)"}
	_, err := conn.Execute(ctx, cmd)
	if err == nil {
		t.Error("expected error when executing with nil session")
	}
}

func TestParseConnectionURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		hosts    []string
		keyspace string
		wantErr  bool
	}{
		{
			name:     "single host",
			url:      "cassandra://localhost:9042/mykeyspace",
			hosts:    []string{"localhost:9042"},
			keyspace: "mykeyspace",
			wantErr:  false,
		},
		{
			name:     "multiple hosts",
			url:      "cassandra://host1:9042,host2:9042/keyspace",
			hosts:    []string{"host1:9042", "host2:9042"},
			keyspace: "keyspace",
			wantErr:  false,
		},
		{
			name:    "missing keyspace",
			url:     "cassandra://localhost:9042",
			wantErr: true,
		},
		{
			name:     "empty hosts string",
			url:      "cassandra:///keyspace",
			hosts:    []string{""},
			keyspace: "keyspace",
			wantErr:  false, // Note: current impl allows empty host string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts, keyspace, err := parseConnectionURL(tt.url)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(hosts) != len(tt.hosts) {
				t.Errorf("expected %d hosts, got %d", len(tt.hosts), len(hosts))
			}
			if keyspace != tt.keyspace {
				t.Errorf("expected keyspace %q, got %q", tt.keyspace, keyspace)
			}
		})
	}
}

func TestParseConsistency(t *testing.T) {
	tests := []struct {
		level    string
		expected string
	}{
		{"ANY", "ANY"},
		{"ONE", "ONE"},
		{"TWO", "TWO"},
		{"THREE", "THREE"},
		{"QUORUM", "QUORUM"},
		{"ALL", "ALL"},
		{"LOCAL_QUORUM", "LOCAL_QUORUM"},
		{"EACH_QUORUM", "EACH_QUORUM"},
		{"LOCAL_ONE", "LOCAL_ONE"},
		{"unknown", "QUORUM"}, // default
		{"one", "ONE"},        // case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			got := parseConsistency(tt.level)
			if got.String() != tt.expected {
				t.Errorf("parseConsistency(%q) = %v, want %v", tt.level, got.String(), tt.expected)
			}
		})
	}
}
