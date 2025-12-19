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

// Package snowflake provides the Snowflake data warehouse connector.
// This is the Community stub - the full Snowflake connector is an enterprise feature.
package snowflake

import (
	"context"
	"errors"

	"axonflow/platform/connectors/base"
)

// ErrEnterpriseFeature is returned when attempting to use enterprise-only features
var ErrEnterpriseFeature = errors.New("snowflake connector is an enterprise feature - contact sales@getaxonflow.com")

// SnowflakeConnector is the Community stub for the Snowflake data warehouse connector.
// The full implementation is available in the enterprise edition.
type SnowflakeConnector struct {
	config *base.ConnectorConfig
}

// NewSnowflakeConnector creates a new Snowflake connector instance.
// Community stub: Returns a stub that will error on Connect().
func NewSnowflakeConnector() *SnowflakeConnector {
	return &SnowflakeConnector{}
}

// Connect establishes a connection to Snowflake.
// Community stub: Always returns ErrEnterpriseFeature.
func (c *SnowflakeConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config
	return base.NewConnectorError(config.Name, "Connect", "snowflake connector requires enterprise license", ErrEnterpriseFeature)
}

// Disconnect closes the connection.
// Community stub: No-op.
func (c *SnowflakeConnector) Disconnect(ctx context.Context) error {
	return nil
}

// HealthCheck verifies the connection is valid.
// Community stub: Returns unhealthy status indicating enterprise feature.
func (c *SnowflakeConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{
		Healthy: false,
		Error:   "snowflake connector is an enterprise feature",
	}, nil
}

// Query executes a SQL query against Snowflake.
// Community stub: Always returns ErrEnterpriseFeature.
func (c *SnowflakeConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	return nil, base.NewConnectorError("snowflake", "Query", "snowflake connector requires enterprise license", ErrEnterpriseFeature)
}

// Execute executes a SQL statement (INSERT, UPDATE, DELETE).
// Community stub: Always returns ErrEnterpriseFeature.
func (c *SnowflakeConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return nil, base.NewConnectorError("snowflake", "Execute", "snowflake connector requires enterprise license", ErrEnterpriseFeature)
}

// Name returns the connector instance name.
func (c *SnowflakeConnector) Name() string {
	if c.config != nil {
		return c.config.Name
	}
	return "snowflake"
}

// Type returns the connector type.
func (c *SnowflakeConnector) Type() string {
	return "snowflake"
}

// Version returns the connector version.
func (c *SnowflakeConnector) Version() string {
	return "community-stub"
}

// Capabilities returns the list of capabilities.
// Community stub: Returns empty list (no capabilities in Community mode).
func (c *SnowflakeConnector) Capabilities() []string {
	return []string{}
}
