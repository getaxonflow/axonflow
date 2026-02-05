// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package hubspot provides the HubSpot CRM connector.
// This is the Community Edition stub - the full HubSpot connector is an enterprise feature.
package hubspot

import (
	"context"
	"errors"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/sdk"
)

// ErrEnterpriseFeature is returned when attempting to use enterprise-only features
var ErrEnterpriseFeature = errors.New("hubspot connector is an enterprise feature - contact sales@getaxonflow.com")

// HubSpotConnector is the Community stub for the HubSpot CRM connector.
// The full implementation is available in the enterprise edition.
type HubSpotConnector struct {
	sdk.BaseConnector
	config *base.ConnectorConfig
}

// NewHubSpotConnector creates a new HubSpot connector instance.
// Community stub: Returns a stub that will error on Connect().
func NewHubSpotConnector() *HubSpotConnector {
	conn := &HubSpotConnector{}
	conn.BaseConnector = *sdk.NewBaseConnector("hubspot")
	conn.SetVersion("community-stub")
	conn.SetCapabilities([]string{})
	return conn
}

// Connect establishes a connection to HubSpot API.
// Community stub: Always returns ErrEnterpriseFeature.
func (c *HubSpotConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	if config == nil {
		return base.NewConnectorError("hubspot", "Connect", "config is required", nil)
	}
	c.config = config
	if config.Type == "" {
		config.Type = "hubspot"
	}
	_ = c.BaseConnector.Connect(ctx, config)
	return base.NewConnectorError(config.Name, "Connect", "hubspot connector requires enterprise license", ErrEnterpriseFeature)
}

// Disconnect closes the connection.
// Community stub: No-op.
func (c *HubSpotConnector) Disconnect(ctx context.Context) error {
	return nil
}

// HealthCheck verifies the API is accessible.
// Community stub: Returns unhealthy status indicating enterprise feature.
func (c *HubSpotConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{
		Healthy: false,
		Error:   "hubspot connector is an enterprise feature",
	}, nil
}

// Query executes a read operation.
// Community stub: Always returns ErrEnterpriseFeature.
func (c *HubSpotConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	return nil, ErrEnterpriseFeature
}

// Execute executes a write operation.
// Community stub: Always returns ErrEnterpriseFeature.
func (c *HubSpotConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return nil, ErrEnterpriseFeature
}

// Name returns the connector instance name.
func (c *HubSpotConnector) Name() string {
	if c.config != nil {
		return c.config.Name
	}
	return "hubspot"
}

// Capabilities returns the list of capabilities.
// Community stub: Returns empty list (no capabilities in Community mode).
func (c *HubSpotConnector) Capabilities() []string {
	return []string{}
}
