// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package snowflake

import (
	"context"
	"testing"

	"axonflow/platform/connectors/base"
)

func TestNewSnowflakeConnector(t *testing.T) {
	conn := NewSnowflakeConnector()
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestSnowflakeConnector_Connect(t *testing.T) {
	conn := NewSnowflakeConnector()
	ctx := context.Background()
	config := &base.ConnectorConfig{Name: "test", Type: "snowflake"}
	err := conn.Connect(ctx, config)
	if err == nil {
		t.Error("expected error for OSS stub")
	}
}

func TestSnowflakeConnector_Disconnect(t *testing.T) {
	conn := NewSnowflakeConnector()
	ctx := context.Background()
	err := conn.Disconnect(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSnowflakeConnector_HealthCheck(t *testing.T) {
	conn := NewSnowflakeConnector()
	ctx := context.Background()
	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status for OSS stub")
	}
}

func TestSnowflakeConnector_Query(t *testing.T) {
	conn := NewSnowflakeConnector()
	ctx := context.Background()
	query := &base.Query{Statement: "query"}
	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error for OSS stub")
	}
}

func TestSnowflakeConnector_Execute(t *testing.T) {
	conn := NewSnowflakeConnector()
	ctx := context.Background()
	cmd := &base.Command{Action: "execute"}
	_, err := conn.Execute(ctx, cmd)
	if err == nil {
		t.Error("expected error for OSS stub")
	}
}

func TestSnowflakeConnector_Name(t *testing.T) {
	conn := NewSnowflakeConnector()
	if got := conn.Name(); got != "snowflake" {
		t.Errorf("Name() = %q, want %q", got, "snowflake")
	}
	conn.config = &base.ConnectorConfig{Name: "custom"}
	if got := conn.Name(); got != "custom" {
		t.Errorf("Name() = %q, want %q", got, "custom")
	}
}

func TestSnowflakeConnector_Type(t *testing.T) {
	conn := NewSnowflakeConnector()
	if got := conn.Type(); got != "snowflake" {
		t.Errorf("Type() = %q, want %q", got, "snowflake")
	}
}

func TestSnowflakeConnector_Version(t *testing.T) {
	conn := NewSnowflakeConnector()
	if got := conn.Version(); got != "oss-stub" {
		t.Errorf("Version() = %q, want %q", got, "oss-stub")
	}
}

func TestSnowflakeConnector_Capabilities(t *testing.T) {
	conn := NewSnowflakeConnector()
	caps := conn.Capabilities()
	if len(caps) != 0 {
		t.Errorf("expected empty capabilities, got %v", caps)
	}
}
