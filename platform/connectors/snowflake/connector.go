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
	"axonflow/platform/connectors/sdk"
)

// ErrEnterpriseFeature is returned when attempting to use enterprise-only features
var ErrEnterpriseFeature = errors.New("snowflake connector is an enterprise feature - contact sales@getaxonflow.com")

// SnowflakeConnector is the Community stub for the Snowflake data warehouse connector.
// The full implementation is available in the enterprise edition.
type SnowflakeConnector struct {
	sdk.BaseConnector
	config *base.ConnectorConfig
}

// NewSnowflakeConnector creates a new Snowflake connector instance.
// Community stub: Returns a stub that will error on Connect().
func NewSnowflakeConnector() *SnowflakeConnector {
	conn := &SnowflakeConnector{}
	conn.BaseConnector = *sdk.NewBaseConnector("snowflake")
	conn.SetVersion("community-stub")
	conn.SetCapabilities([]string{})
	return conn
}

// Connect establishes a connection to Snowflake.
// Community stub: Always returns ErrEnterpriseFeature.
func (c *SnowflakeConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	if config == nil {
		return base.NewConnectorError("snowflake", "Connect", "config is required", nil)
	}
	c.config = config
	if config.Type == "" {
		config.Type = "snowflake"
	}
	_ = c.BaseConnector.Connect(ctx, config)
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
//
// Read-only posture coverage boundary (#2733): Snowflake supports read-only
// transactions and could adopt the same database-enforced backstop the
// PostgreSQL connector uses for the base.Query.ReadOnly flag. That is not yet
// implemented in the enterprise connector, so read-only posture for Snowflake
// is currently enforced only by the upstream MCP gate's statement-verb check.
// Documented follow-up to #2733, not a silent gap.
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
