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

// Package amadeus provides the Amadeus Travel API connector.
// This is the OSS stub - the full Amadeus connector is an enterprise feature.
package amadeus

import (
	"context"
	"errors"

	"axonflow/platform/connectors/base"
)

// ErrEnterpriseFeature is returned when attempting to use enterprise-only features
var ErrEnterpriseFeature = errors.New("amadeus connector is an enterprise feature - contact sales@getaxonflow.com")

// AmadeusConnector is the OSS stub for the Amadeus Travel API connector.
// The full implementation is available in the enterprise edition.
type AmadeusConnector struct {
	config *base.ConnectorConfig
}

// NewAmadeusConnector creates a new Amadeus connector instance.
// OSS stub: Returns a stub that will error on Connect().
func NewAmadeusConnector() *AmadeusConnector {
	return &AmadeusConnector{}
}

// Connect establishes a connection to Amadeus API.
// OSS stub: Always returns ErrEnterpriseFeature.
func (c *AmadeusConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config
	return base.NewConnectorError(config.Name, "Connect", "amadeus connector requires enterprise license", ErrEnterpriseFeature)
}

// Disconnect closes the connection.
// OSS stub: No-op.
func (c *AmadeusConnector) Disconnect(ctx context.Context) error {
	return nil
}

// HealthCheck verifies the API is accessible.
// OSS stub: Returns unhealthy status indicating enterprise feature.
func (c *AmadeusConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{
		Healthy: false,
		Error:   "amadeus connector is an enterprise feature",
	}, nil
}

// Query executes a read operation.
// OSS stub: Always returns ErrEnterpriseFeature.
func (c *AmadeusConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	return nil, base.NewConnectorError("amadeus", "Query", "amadeus connector requires enterprise license", ErrEnterpriseFeature)
}

// Execute executes a write operation.
// OSS stub: Always returns ErrEnterpriseFeature.
func (c *AmadeusConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return nil, base.NewConnectorError("amadeus", "Execute", "amadeus connector requires enterprise license", ErrEnterpriseFeature)
}

// Name returns the connector instance name.
func (c *AmadeusConnector) Name() string {
	if c.config != nil {
		return c.config.Name
	}
	return "amadeus"
}

// Type returns the connector type.
func (c *AmadeusConnector) Type() string {
	return "amadeus"
}

// Version returns the connector version.
func (c *AmadeusConnector) Version() string {
	return "oss-stub"
}

// Capabilities returns the list of capabilities.
// OSS stub: Returns empty list (no capabilities in OSS mode).
func (c *AmadeusConnector) Capabilities() []string {
	return []string{}
}
