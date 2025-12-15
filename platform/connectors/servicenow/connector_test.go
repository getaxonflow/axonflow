// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package servicenow

import (
	"context"
	"errors"
	"testing"

	"axonflow/platform/connectors/base"
)

func TestNewServiceNowConnector(t *testing.T) {
	c := NewServiceNowConnector()
	if c == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestServiceNowConnector_Connect_ReturnsEnterpriseError(t *testing.T) {
	c := NewServiceNowConnector()
	err := c.Connect(context.Background(), &base.ConnectorConfig{Name: "test"})
	if !errors.Is(err, ErrEnterpriseFeature) {
		t.Errorf("expected ErrEnterpriseFeature, got %v", err)
	}
}

func TestServiceNowConnector_Query_ReturnsEnterpriseError(t *testing.T) {
	c := NewServiceNowConnector()
	_, err := c.Query(context.Background(), &base.Query{})
	if !errors.Is(err, ErrEnterpriseFeature) {
		t.Errorf("expected ErrEnterpriseFeature, got %v", err)
	}
}

func TestServiceNowConnector_Execute_ReturnsEnterpriseError(t *testing.T) {
	c := NewServiceNowConnector()
	_, err := c.Execute(context.Background(), &base.Command{})
	if !errors.Is(err, ErrEnterpriseFeature) {
		t.Errorf("expected ErrEnterpriseFeature, got %v", err)
	}
}

func TestServiceNowConnector_Disconnect_NoError(t *testing.T) {
	c := NewServiceNowConnector()
	err := c.Disconnect(context.Background())
	if err != nil {
		t.Errorf("expected no error on disconnect, got %v", err)
	}
}

func TestServiceNowConnector_HealthCheck_Unhealthy(t *testing.T) {
	c := NewServiceNowConnector()
	status, err := c.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status for community stub")
	}
}

func TestServiceNowConnector_Metadata(t *testing.T) {
	c := NewServiceNowConnector()
	if c.Type() != "servicenow" {
		t.Errorf("expected type servicenow, got %s", c.Type())
	}
	if c.Version() != "community-stub" {
		t.Errorf("expected version community-stub, got %s", c.Version())
	}
	if len(c.Capabilities()) != 0 {
		t.Errorf("expected empty capabilities, got %v", c.Capabilities())
	}
}

func TestServiceNowConnector_Name(t *testing.T) {
	c := NewServiceNowConnector()
	// Before Connect, name should be default
	if c.Name() != "servicenow" {
		t.Errorf("expected default name servicenow, got %s", c.Name())
	}
	// After Connect attempt, name should be from config
	_ = c.Connect(context.Background(), &base.ConnectorConfig{Name: "my-servicenow"})
	if c.Name() != "my-servicenow" {
		t.Errorf("expected name my-servicenow, got %s", c.Name())
	}
}
