// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package salesforce provides the Salesforce CRM connector.
// This is the OSS stub - the full Salesforce connector is an enterprise feature.
package salesforce

import (
	"context"
	"errors"

	"axonflow/platform/connectors/base"
)

// ErrEnterpriseFeature is returned when attempting to use enterprise-only features
var ErrEnterpriseFeature = errors.New("salesforce connector is an enterprise feature - contact sales@getaxonflow.com")

// SalesforceConnector is the OSS stub for the Salesforce CRM connector.
// The full implementation is available in the enterprise edition.
type SalesforceConnector struct {
	config *base.ConnectorConfig
}

// NewSalesforceConnector creates a new Salesforce connector instance.
// OSS stub: Returns a stub that will error on Connect().
func NewSalesforceConnector() *SalesforceConnector {
	return &SalesforceConnector{}
}

// Connect establishes a connection to Salesforce API.
// OSS stub: Always returns ErrEnterpriseFeature.
func (c *SalesforceConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config
	return base.NewConnectorError(config.Name, "Connect", "salesforce connector requires enterprise license", ErrEnterpriseFeature)
}

// Disconnect closes the connection.
// OSS stub: No-op.
func (c *SalesforceConnector) Disconnect(ctx context.Context) error {
	return nil
}

// HealthCheck verifies the API is accessible.
// OSS stub: Returns unhealthy status indicating enterprise feature.
func (c *SalesforceConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{
		Healthy: false,
		Error:   "salesforce connector is an enterprise feature",
	}, nil
}

// Query executes a read operation (SOQL query).
// OSS stub: Always returns ErrEnterpriseFeature.
func (c *SalesforceConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	return nil, base.NewConnectorError("salesforce", "Query", "salesforce connector requires enterprise license", ErrEnterpriseFeature)
}

// Execute executes a write operation (create/update/delete).
// OSS stub: Always returns ErrEnterpriseFeature.
func (c *SalesforceConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return nil, base.NewConnectorError("salesforce", "Execute", "salesforce connector requires enterprise license", ErrEnterpriseFeature)
}

// Name returns the connector instance name.
func (c *SalesforceConnector) Name() string {
	if c.config != nil {
		return c.config.Name
	}
	return "salesforce"
}

// Type returns the connector type.
func (c *SalesforceConnector) Type() string {
	return "salesforce"
}

// Version returns the connector version.
func (c *SalesforceConnector) Version() string {
	return "oss-stub"
}

// Capabilities returns the list of capabilities.
// OSS stub: Returns empty list (no capabilities in OSS mode).
func (c *SalesforceConnector) Capabilities() []string {
	return []string{}
}
