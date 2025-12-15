// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package jira

import (
	"context"
	"errors"
	"testing"

	"axonflow/platform/connectors/base"
)

func TestNewJiraConnector(t *testing.T) {
	c := NewJiraConnector()
	if c == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestJiraConnector_Connect_ReturnsEnterpriseError(t *testing.T) {
	c := NewJiraConnector()
	err := c.Connect(context.Background(), &base.ConnectorConfig{Name: "test"})
	if !errors.Is(err, ErrEnterpriseFeature) {
		t.Errorf("expected ErrEnterpriseFeature, got %v", err)
	}
}

func TestJiraConnector_Query_ReturnsEnterpriseError(t *testing.T) {
	c := NewJiraConnector()
	_, err := c.Query(context.Background(), &base.Query{})
	if !errors.Is(err, ErrEnterpriseFeature) {
		t.Errorf("expected ErrEnterpriseFeature, got %v", err)
	}
}

func TestJiraConnector_Execute_ReturnsEnterpriseError(t *testing.T) {
	c := NewJiraConnector()
	_, err := c.Execute(context.Background(), &base.Command{})
	if !errors.Is(err, ErrEnterpriseFeature) {
		t.Errorf("expected ErrEnterpriseFeature, got %v", err)
	}
}

func TestJiraConnector_Disconnect_NoError(t *testing.T) {
	c := NewJiraConnector()
	err := c.Disconnect(context.Background())
	if err != nil {
		t.Errorf("expected no error on disconnect, got %v", err)
	}
}

func TestJiraConnector_HealthCheck_Unhealthy(t *testing.T) {
	c := NewJiraConnector()
	status, err := c.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status for community stub")
	}
}

func TestJiraConnector_Metadata(t *testing.T) {
	c := NewJiraConnector()
	if c.Type() != "jira" {
		t.Errorf("expected type jira, got %s", c.Type())
	}
	if c.Version() != "community-stub" {
		t.Errorf("expected version community-stub, got %s", c.Version())
	}
	if len(c.Capabilities()) != 0 {
		t.Errorf("expected empty capabilities, got %v", c.Capabilities())
	}
}

func TestJiraConnector_Name(t *testing.T) {
	c := NewJiraConnector()
	// Before Connect, name should be default
	if c.Name() != "jira" {
		t.Errorf("expected default name jira, got %s", c.Name())
	}
	// After Connect attempt, name should be from config
	_ = c.Connect(context.Background(), &base.ConnectorConfig{Name: "my-jira"})
	if c.Name() != "my-jira" {
		t.Errorf("expected name my-jira, got %s", c.Name())
	}
}
