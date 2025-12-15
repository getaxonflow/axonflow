// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package hubspot

import (
	"context"
	"errors"
	"testing"

	"axonflow/platform/connectors/base"
)

func TestNewHubSpotConnector(t *testing.T) {
	c := NewHubSpotConnector()
	if c == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestHubSpotConnector_Connect_ReturnsEnterpriseError(t *testing.T) {
	c := NewHubSpotConnector()
	err := c.Connect(context.Background(), &base.ConnectorConfig{Name: "test"})
	if !errors.Is(err, ErrEnterpriseFeature) {
		t.Errorf("expected ErrEnterpriseFeature, got %v", err)
	}
}

func TestHubSpotConnector_Query_ReturnsEnterpriseError(t *testing.T) {
	c := NewHubSpotConnector()
	_, err := c.Query(context.Background(), &base.Query{})
	if !errors.Is(err, ErrEnterpriseFeature) {
		t.Errorf("expected ErrEnterpriseFeature, got %v", err)
	}
}

func TestHubSpotConnector_Execute_ReturnsEnterpriseError(t *testing.T) {
	c := NewHubSpotConnector()
	_, err := c.Execute(context.Background(), &base.Command{})
	if !errors.Is(err, ErrEnterpriseFeature) {
		t.Errorf("expected ErrEnterpriseFeature, got %v", err)
	}
}

func TestHubSpotConnector_Disconnect_NoError(t *testing.T) {
	c := NewHubSpotConnector()
	err := c.Disconnect(context.Background())
	if err != nil {
		t.Errorf("expected no error on disconnect, got %v", err)
	}
}

func TestHubSpotConnector_HealthCheck_Unhealthy(t *testing.T) {
	c := NewHubSpotConnector()
	status, err := c.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status for community stub")
	}
}

func TestHubSpotConnector_Metadata(t *testing.T) {
	c := NewHubSpotConnector()
	if c.Type() != "hubspot" {
		t.Errorf("expected type hubspot, got %s", c.Type())
	}
	if c.Version() != "community-stub" {
		t.Errorf("expected version community-stub, got %s", c.Version())
	}
	if len(c.Capabilities()) != 0 {
		t.Errorf("expected empty capabilities, got %v", c.Capabilities())
	}
}

func TestHubSpotConnector_Name(t *testing.T) {
	c := NewHubSpotConnector()
	// Before Connect, name should be default
	if c.Name() != "hubspot" {
		t.Errorf("expected default name hubspot, got %s", c.Name())
	}
	// After Connect attempt, name should be from config
	_ = c.Connect(context.Background(), &base.ConnectorConfig{Name: "my-hubspot"})
	if c.Name() != "my-hubspot" {
		t.Errorf("expected name my-hubspot, got %s", c.Name())
	}
}
