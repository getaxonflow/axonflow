// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package servicenow provides the ServiceNow ITSM connector.
// This is the Community Edition stub - the full ServiceNow connector is an enterprise feature.
package servicenow

import (
	"context"
	"errors"

	"axonflow/platform/connectors/base"
)

// ErrEnterpriseFeature is returned when attempting to use enterprise-only features
var ErrEnterpriseFeature = errors.New("servicenow connector is an enterprise feature - contact sales@getaxonflow.com")

// ServiceNowConnector is the Community stub for the ServiceNow ITSM connector.
// The full implementation is available in the enterprise edition.
type ServiceNowConnector struct {
	config *base.ConnectorConfig
}

// NewServiceNowConnector creates a new ServiceNow connector instance.
// Community stub: Returns a stub that will error on Connect().
func NewServiceNowConnector() *ServiceNowConnector {
	return &ServiceNowConnector{}
}

// Connect establishes a connection to ServiceNow API.
// Community stub: Always returns ErrEnterpriseFeature.
func (c *ServiceNowConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config
	return ErrEnterpriseFeature
}

// Disconnect closes the connection.
// Community stub: No-op.
func (c *ServiceNowConnector) Disconnect(ctx context.Context) error {
	return nil
}

// HealthCheck verifies the API is accessible.
// Community stub: Returns unhealthy status indicating enterprise feature.
func (c *ServiceNowConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{
		Healthy: false,
		Error:   "servicenow connector is an enterprise feature",
	}, nil
}

// Query executes a read operation (table query).
// Community stub: Always returns ErrEnterpriseFeature.
func (c *ServiceNowConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	return nil, ErrEnterpriseFeature
}

// Execute executes a write operation (create/update record).
// Community stub: Always returns ErrEnterpriseFeature.
func (c *ServiceNowConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return nil, ErrEnterpriseFeature
}

// Name returns the connector instance name.
func (c *ServiceNowConnector) Name() string {
	if c.config != nil {
		return c.config.Name
	}
	return "servicenow"
}

// Type returns the connector type.
func (c *ServiceNowConnector) Type() string {
	return "servicenow"
}

// Version returns the connector version.
func (c *ServiceNowConnector) Version() string {
	return "community-stub"
}

// Capabilities returns the list of capabilities.
// Community stub: Returns empty list (no capabilities in Community mode).
func (c *ServiceNowConnector) Capabilities() []string {
	return []string{}
}
