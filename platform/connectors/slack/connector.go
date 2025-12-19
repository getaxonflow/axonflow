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

// Package slack provides the Slack messaging connector.
// This is the Community stub - the full Slack connector is an enterprise feature.
package slack

import (
	"context"
	"errors"

	"axonflow/platform/connectors/base"
)

// ErrEnterpriseFeature is returned when attempting to use enterprise-only features
var ErrEnterpriseFeature = errors.New("slack connector is an enterprise feature - contact sales@getaxonflow.com")

// SlackConnector is the Community stub for the Slack messaging connector.
// The full implementation is available in the enterprise edition.
type SlackConnector struct {
	config *base.ConnectorConfig
}

// NewSlackConnector creates a new Slack connector instance.
// Community stub: Returns a stub that will error on Connect().
func NewSlackConnector() *SlackConnector {
	return &SlackConnector{}
}

// Connect establishes a connection to Slack API.
// Community stub: Always returns ErrEnterpriseFeature.
func (c *SlackConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config
	return base.NewConnectorError(config.Name, "Connect", "slack connector requires enterprise license", ErrEnterpriseFeature)
}

// Disconnect closes the connection.
// Community stub: No-op.
func (c *SlackConnector) Disconnect(ctx context.Context) error {
	return nil
}

// HealthCheck verifies the API is accessible.
// Community stub: Returns unhealthy status indicating enterprise feature.
func (c *SlackConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{
		Healthy: false,
		Error:   "slack connector is an enterprise feature",
	}, nil
}

// Query executes a read operation (list channels, users, messages).
// Community stub: Always returns ErrEnterpriseFeature.
func (c *SlackConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	return nil, base.NewConnectorError("slack", "Query", "slack connector requires enterprise license", ErrEnterpriseFeature)
}

// Execute executes a write operation (send message, create channel).
// Community stub: Always returns ErrEnterpriseFeature.
func (c *SlackConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return nil, base.NewConnectorError("slack", "Execute", "slack connector requires enterprise license", ErrEnterpriseFeature)
}

// Name returns the connector instance name.
func (c *SlackConnector) Name() string {
	if c.config != nil {
		return c.config.Name
	}
	return "slack"
}

// Type returns the connector type.
func (c *SlackConnector) Type() string {
	return "slack"
}

// Version returns the connector version.
func (c *SlackConnector) Version() string {
	return "community-stub"
}

// Capabilities returns the list of capabilities.
// Community stub: Returns empty list (no capabilities in Community mode).
func (c *SlackConnector) Capabilities() []string {
	return []string{}
}
