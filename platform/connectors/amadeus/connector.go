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

// Package amadeus provides the Amadeus Travel API connector.
// This is the Community stub - the full Amadeus connector is an enterprise feature.
package amadeus

import (
	"context"
	"errors"

	"axonflow/platform/connectors/base"
)

// ErrEnterpriseFeature is returned when attempting to use enterprise-only features
var ErrEnterpriseFeature = errors.New("amadeus connector is an enterprise feature - contact sales@getaxonflow.com")

// AmadeusConnector is the Community stub for the Amadeus Travel API connector.
// The full implementation is available in the enterprise edition.
type AmadeusConnector struct {
	config *base.ConnectorConfig
}

// NewAmadeusConnector creates a new Amadeus connector instance.
// Community stub: Returns a stub that will error on Connect().
func NewAmadeusConnector() *AmadeusConnector {
	return &AmadeusConnector{}
}

// Connect establishes a connection to Amadeus API.
// Community stub: Always returns ErrEnterpriseFeature.
func (c *AmadeusConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config
	return base.NewConnectorError(config.Name, "Connect", "amadeus connector requires enterprise license", ErrEnterpriseFeature)
}

// Disconnect closes the connection.
// Community stub: No-op.
func (c *AmadeusConnector) Disconnect(ctx context.Context) error {
	return nil
}

// HealthCheck verifies the API is accessible.
// Community stub: Returns unhealthy status indicating enterprise feature.
func (c *AmadeusConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{
		Healthy: false,
		Error:   "amadeus connector is an enterprise feature",
	}, nil
}

// Query executes a read operation.
// Community stub: Always returns ErrEnterpriseFeature.
func (c *AmadeusConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	return nil, base.NewConnectorError("amadeus", "Query", "amadeus connector requires enterprise license", ErrEnterpriseFeature)
}

// Execute executes a write operation.
// Community stub: Always returns ErrEnterpriseFeature.
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
	return "community-stub"
}

// Capabilities returns the list of capabilities.
// Community stub: Returns empty list (no capabilities in Community mode).
func (c *AmadeusConnector) Capabilities() []string {
	return []string{}
}
