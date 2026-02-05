// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package salesforce provides the Salesforce CRM connector.
// This is the Community stub - the full Salesforce connector is an enterprise feature.
package salesforce

import (
	"context"
	"errors"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/sdk"
)

// ErrEnterpriseFeature is returned when attempting to use enterprise-only features
var ErrEnterpriseFeature = errors.New("salesforce connector is an enterprise feature - contact sales@getaxonflow.com")

// SalesforceConnector is the Community stub for the Salesforce CRM connector.
// The full implementation is available in the enterprise edition.
type SalesforceConnector struct {
	sdk.BaseConnector
	config *base.ConnectorConfig
}

// NewSalesforceConnector creates a new Salesforce connector instance.
// Community stub: Returns a stub that will error on Connect().
func NewSalesforceConnector() *SalesforceConnector {
	conn := &SalesforceConnector{}
	conn.BaseConnector = *sdk.NewBaseConnector("salesforce")
	conn.SetVersion("community-stub")
	conn.SetCapabilities([]string{})
	return conn
}

// Connect establishes a connection to Salesforce API.
// Community stub: Always returns ErrEnterpriseFeature.
func (c *SalesforceConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	if config == nil {
		return base.NewConnectorError("salesforce", "Connect", "config is required", nil)
	}
	c.config = config
	if config.Type == "" {
		config.Type = "salesforce"
	}
	_ = c.BaseConnector.Connect(ctx, config)
	return base.NewConnectorError(config.Name, "Connect", "salesforce connector requires enterprise license", ErrEnterpriseFeature)
}

// Disconnect closes the connection.
// Community stub: No-op.
func (c *SalesforceConnector) Disconnect(ctx context.Context) error {
	return nil
}

// HealthCheck verifies the API is accessible.
// Community stub: Returns unhealthy status indicating enterprise feature.
func (c *SalesforceConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{
		Healthy: false,
		Error:   "salesforce connector is an enterprise feature",
	}, nil
}

// Query executes a read operation (SOQL query).
// Community stub: Always returns ErrEnterpriseFeature.
func (c *SalesforceConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	return nil, base.NewConnectorError("salesforce", "Query", "salesforce connector requires enterprise license", ErrEnterpriseFeature)
}

// Execute executes a write operation (create/update/delete).
// Community stub: Always returns ErrEnterpriseFeature.
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
