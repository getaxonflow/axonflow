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

package base

import (
	"context"
	"time"
)

// Connector defines the interface that all MCP connectors must implement
// This follows the Model Context Protocol pattern for Resources and Tools
type Connector interface {
	// Lifecycle Management
	Connect(ctx context.Context, config *ConnectorConfig) error
	Disconnect(ctx context.Context) error
	HealthCheck(ctx context.Context) (*HealthStatus, error)

	// Data Operations (MCP Resources - read-only)
	Query(ctx context.Context, query *Query) (*QueryResult, error)

	// Action Operations (MCP Tools - write operations)
	Execute(ctx context.Context, cmd *Command) (*CommandResult, error)

	// Metadata
	Name() string        // Unique connector instance name
	Type() string        // Connector type (postgres, cassandra, http_api)
	Version() string     // Connector version
	Capabilities() []string // List of capabilities (query, execute, transactions)
}

// ConnectorConfig holds the configuration for a connector instance
type ConnectorConfig struct {
	Name          string                 `json:"name"`           // Unique name for this connector
	Type          string                 `json:"type"`           // Type: postgres, cassandra, http_api
	ConnectionURL string                 `json:"connection_url"` // Connection string (DSN)
	Credentials   map[string]string      `json:"credentials"`    // Username, password, API keys
	Options       map[string]interface{} `json:"options"`        // Connector-specific options
	Timeout       time.Duration          `json:"timeout"`        // Operation timeout (default: 5s)
	MaxRetries    int                    `json:"max_retries"`    // Retry count for transient failures
	TenantID      string                 `json:"tenant_id"`      // For multi-tenancy isolation
}

// Query represents a read operation (MCP Resource pattern)
type Query struct {
	Statement  string                 `json:"statement"`  // SQL, CQL, or API path
	Parameters map[string]interface{} `json:"parameters"` // Query parameters
	Timeout    time.Duration          `json:"timeout"`    // Override default timeout
	Limit      int                    `json:"limit"`      // Result limit (optional)
}

// QueryResult contains the results of a Query operation
type QueryResult struct {
	Rows      []map[string]interface{} `json:"rows"`       // Result rows (key-value maps)
	RowCount  int                      `json:"row_count"`  // Number of rows returned
	Duration  time.Duration            `json:"duration"`   // Query execution time
	Cached    bool                     `json:"cached"`     // Was result served from cache?
	Connector string                   `json:"connector"`  // Connector name that executed query
	Metadata  map[string]interface{}   `json:"metadata,omitempty"` // Additional metadata
}

// Command represents a write operation (MCP Tool pattern)
type Command struct {
	Action     string                 `json:"action"`     // INSERT, UPDATE, DELETE, etc.
	Statement  string                 `json:"statement"`  // SQL, CQL, or API endpoint
	Parameters map[string]interface{} `json:"parameters"` // Command parameters
	Timeout    time.Duration          `json:"timeout"`    // Override default timeout
}

// CommandResult contains the results of a Command execution
type CommandResult struct {
	Success      bool                   `json:"success"`       // Was command successful?
	RowsAffected int                    `json:"rows_affected"` // Number of rows affected
	Duration     time.Duration          `json:"duration"`      // Execution time
	Message      string                 `json:"message"`       // Status message
	Connector    string                 `json:"connector"`     // Connector name
	Metadata     map[string]interface{} `json:"metadata,omitempty"` // Additional metadata
}

// HealthStatus represents the health of a connector
type HealthStatus struct {
	Healthy   bool              `json:"healthy"`   // Overall health status
	Latency   time.Duration     `json:"latency"`   // Connection latency
	Details   map[string]string `json:"details"`   // Additional diagnostic info
	Timestamp time.Time         `json:"timestamp"` // When health check was performed
	Error     string            `json:"error"`     // Error message if unhealthy
}

// ConnectorError represents errors specific to connector operations
type ConnectorError struct {
	ConnectorName string
	Operation     string
	Message       string
	Cause         error
}

func (e *ConnectorError) Error() string {
	if e.Cause != nil {
		return e.ConnectorName + "." + e.Operation + ": " + e.Message + " (cause: " + e.Cause.Error() + ")"
	}
	return e.ConnectorName + "." + e.Operation + ": " + e.Message
}

func (e *ConnectorError) Unwrap() error {
	return e.Cause
}

// NewConnectorError creates a new ConnectorError
func NewConnectorError(connectorName, operation, message string, cause error) *ConnectorError {
	return &ConnectorError{
		ConnectorName: connectorName,
		Operation:     operation,
		Message:       message,
		Cause:         cause,
	}
}
