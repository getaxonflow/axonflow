// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package amadeus

import (
	"context"
	"testing"

	"axonflow/platform/connectors/base"
)

func TestNewAmadeusConnector(t *testing.T) {
	conn := NewAmadeusConnector()
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestAmadeusConnector_Connect(t *testing.T) {
	conn := NewAmadeusConnector()
	ctx := context.Background()
	config := &base.ConnectorConfig{Name: "test", Type: "amadeus"}
	err := conn.Connect(ctx, config)
	if err == nil {
		t.Error("expected error for OSS stub")
	}
}

func TestAmadeusConnector_Disconnect(t *testing.T) {
	conn := NewAmadeusConnector()
	ctx := context.Background()
	err := conn.Disconnect(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAmadeusConnector_HealthCheck(t *testing.T) {
	conn := NewAmadeusConnector()
	ctx := context.Background()
	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status for OSS stub")
	}
}

func TestAmadeusConnector_Query(t *testing.T) {
	conn := NewAmadeusConnector()
	ctx := context.Background()
	query := &base.Query{Statement: "query"}
	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error for OSS stub")
	}
}

func TestAmadeusConnector_Execute(t *testing.T) {
	conn := NewAmadeusConnector()
	ctx := context.Background()
	cmd := &base.Command{Action: "execute"}
	_, err := conn.Execute(ctx, cmd)
	if err == nil {
		t.Error("expected error for OSS stub")
	}
}

func TestAmadeusConnector_Name(t *testing.T) {
	conn := NewAmadeusConnector()
	if got := conn.Name(); got != "amadeus" {
		t.Errorf("Name() = %q, want %q", got, "amadeus")
	}
	conn.config = &base.ConnectorConfig{Name: "custom"}
	if got := conn.Name(); got != "custom" {
		t.Errorf("Name() = %q, want %q", got, "custom")
	}
}

func TestAmadeusConnector_Type(t *testing.T) {
	conn := NewAmadeusConnector()
	if got := conn.Type(); got != "amadeus" {
		t.Errorf("Type() = %q, want %q", got, "amadeus")
	}
}

func TestAmadeusConnector_Version(t *testing.T) {
	conn := NewAmadeusConnector()
	if got := conn.Version(); got != "oss-stub" {
		t.Errorf("Version() = %q, want %q", got, "oss-stub")
	}
}

func TestAmadeusConnector_Capabilities(t *testing.T) {
	conn := NewAmadeusConnector()
	caps := conn.Capabilities()
	if len(caps) != 0 {
		t.Errorf("expected empty capabilities, got %v", caps)
	}
}
