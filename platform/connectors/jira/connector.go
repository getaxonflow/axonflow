// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package jira provides the Jira project management connector.
// This is the Community Edition stub - the full Jira connector is an enterprise feature.
package jira

import (
	"context"
	"errors"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/sdk"
)

// ErrEnterpriseFeature is returned when attempting to use enterprise-only features
var ErrEnterpriseFeature = errors.New("jira connector is an enterprise feature - contact sales@getaxonflow.com")

// JiraConnector is the Community stub for the Jira connector.
// The full implementation is available in the enterprise edition.
type JiraConnector struct {
	sdk.BaseConnector
	config *base.ConnectorConfig
}

// NewJiraConnector creates a new Jira connector instance.
// Community stub: Returns a stub that will error on Connect().
func NewJiraConnector() *JiraConnector {
	conn := &JiraConnector{}
	conn.BaseConnector = *sdk.NewBaseConnector("jira")
	conn.SetVersion("community-stub")
	conn.SetCapabilities([]string{})
	return conn
}

// Connect establishes a connection to Jira API.
// Community stub: Always returns ErrEnterpriseFeature.
func (c *JiraConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	if config == nil {
		return base.NewConnectorError("jira", "Connect", "config is required", nil)
	}
	c.config = config
	if config.Type == "" {
		config.Type = "jira"
	}
	_ = c.BaseConnector.Connect(ctx, config)
	return base.NewConnectorError(config.Name, "Connect", "jira connector requires enterprise license", ErrEnterpriseFeature)
}

// Disconnect closes the connection.
// Community stub: No-op.
func (c *JiraConnector) Disconnect(ctx context.Context) error {
	return nil
}

// HealthCheck verifies the API is accessible.
// Community stub: Returns unhealthy status indicating enterprise feature.
func (c *JiraConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{
		Healthy: false,
		Error:   "jira connector is an enterprise feature",
	}, nil
}

// Query executes a read operation (JQL query).
// Community stub: Always returns ErrEnterpriseFeature.
func (c *JiraConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	return nil, ErrEnterpriseFeature
}

// Execute executes a write operation (create/update issue).
// Community stub: Always returns ErrEnterpriseFeature.
func (c *JiraConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return nil, ErrEnterpriseFeature
}

// Name returns the connector instance name.
func (c *JiraConnector) Name() string {
	if c.config != nil {
		return c.config.Name
	}
	return "jira"
}

// Capabilities returns the list of capabilities.
// Community stub: Returns empty list (no capabilities in Community mode).
func (c *JiraConnector) Capabilities() []string {
	return []string{}
}
