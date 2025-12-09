// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package salesforce

import (
	"context"
	"testing"

	"axonflow/platform/connectors/base"
)

func TestNewSalesforceConnector(t *testing.T) {
	conn := NewSalesforceConnector()
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestSalesforceConnector_Connect(t *testing.T) {
	conn := NewSalesforceConnector()
	ctx := context.Background()
	config := &base.ConnectorConfig{Name: "test", Type: "salesforce"}
	err := conn.Connect(ctx, config)
	if err == nil {
		t.Error("expected error for OSS stub")
	}
}

func TestSalesforceConnector_Disconnect(t *testing.T) {
	conn := NewSalesforceConnector()
	ctx := context.Background()
	err := conn.Disconnect(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSalesforceConnector_HealthCheck(t *testing.T) {
	conn := NewSalesforceConnector()
	ctx := context.Background()
	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status for OSS stub")
	}
}

func TestSalesforceConnector_Query(t *testing.T) {
	conn := NewSalesforceConnector()
	ctx := context.Background()
	query := &base.Query{Statement: "query"}
	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error for OSS stub")
	}
}

func TestSalesforceConnector_Execute(t *testing.T) {
	conn := NewSalesforceConnector()
	ctx := context.Background()
	cmd := &base.Command{Action: "execute"}
	_, err := conn.Execute(ctx, cmd)
	if err == nil {
		t.Error("expected error for OSS stub")
	}
}

func TestSalesforceConnector_Name(t *testing.T) {
	conn := NewSalesforceConnector()
	if got := conn.Name(); got != "salesforce" {
		t.Errorf("Name() = %q, want %q", got, "salesforce")
	}
	conn.config = &base.ConnectorConfig{Name: "custom"}
	if got := conn.Name(); got != "custom" {
		t.Errorf("Name() = %q, want %q", got, "custom")
	}
}

func TestSalesforceConnector_Type(t *testing.T) {
	conn := NewSalesforceConnector()
	if got := conn.Type(); got != "salesforce" {
		t.Errorf("Type() = %q, want %q", got, "salesforce")
	}
}

func TestSalesforceConnector_Version(t *testing.T) {
	conn := NewSalesforceConnector()
	if got := conn.Version(); got != "oss-stub" {
		t.Errorf("Version() = %q, want %q", got, "oss-stub")
	}
}

func TestSalesforceConnector_Capabilities(t *testing.T) {
	conn := NewSalesforceConnector()
	caps := conn.Capabilities()
	if len(caps) != 0 {
		t.Errorf("expected empty capabilities, got %v", caps)
	}
}
