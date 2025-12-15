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
	"errors"
	"testing"
	"time"
)

func TestConnectorError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ConnectorError
		wantMsg  string
	}{
		{
			name: "with cause",
			err: &ConnectorError{
				ConnectorName: "postgres",
				Operation:     "Query",
				Message:       "connection failed",
				Cause:         errors.New("network timeout"),
			},
			wantMsg: "postgres.Query: connection failed (cause: network timeout)",
		},
		{
			name: "without cause",
			err: &ConnectorError{
				ConnectorName: "cassandra",
				Operation:     "Execute",
				Message:       "write failed",
				Cause:         nil,
			},
			wantMsg: "cassandra.Execute: write failed",
		},
		{
			name: "empty fields",
			err: &ConnectorError{
				ConnectorName: "",
				Operation:     "",
				Message:       "error",
				Cause:         nil,
			},
			wantMsg: ".: error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tt.wantMsg)
			}
		})
	}
}

func TestConnectorError_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := &ConnectorError{
		ConnectorName: "postgres",
		Operation:     "Connect",
		Message:       "failed",
		Cause:         cause,
	}

	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}

	// Test nil cause
	errNoCause := &ConnectorError{
		ConnectorName: "postgres",
		Operation:     "Connect",
		Message:       "failed",
		Cause:         nil,
	}
	if errNoCause.Unwrap() != nil {
		t.Error("Unwrap() should return nil when Cause is nil")
	}
}

func TestNewConnectorError(t *testing.T) {
	cause := errors.New("original error")
	err := NewConnectorError("my-connector", "Query", "operation failed", cause)

	if err.ConnectorName != "my-connector" {
		t.Errorf("ConnectorName = %q, want %q", err.ConnectorName, "my-connector")
	}
	if err.Operation != "Query" {
		t.Errorf("Operation = %q, want %q", err.Operation, "Query")
	}
	if err.Message != "operation failed" {
		t.Errorf("Message = %q, want %q", err.Message, "operation failed")
	}
	if err.Cause != cause {
		t.Errorf("Cause = %v, want %v", err.Cause, cause)
	}
}

func TestNewConnectorError_NilCause(t *testing.T) {
	err := NewConnectorError("connector", "op", "msg", nil)
	if err.Cause != nil {
		t.Error("expected nil cause")
	}
}

func TestConnectorError_ErrorsIs(t *testing.T) {
	cause := errors.New("specific error")
	err := NewConnectorError("postgres", "Query", "failed", cause)

	// Test errors.Is works with wrapped error
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the wrapped cause")
	}
}

func TestConnectorConfig(t *testing.T) {
	config := &ConnectorConfig{
		Name:          "my-postgres",
		Type:          "postgres",
		ConnectionURL: "postgres://localhost:5432/db",
		Credentials: map[string]string{
			"username": "user",
			"password": "pass",
		},
		Options: map[string]interface{}{
			"max_conns": 10,
			"ssl_mode":  "require",
		},
		Timeout:    30 * time.Second,
		MaxRetries: 5,
		TenantID:   "tenant-123",
	}

	if config.Name != "my-postgres" {
		t.Errorf("Name = %q, want %q", config.Name, "my-postgres")
	}
	if config.Type != "postgres" {
		t.Errorf("Type = %q, want %q", config.Type, "postgres")
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want %v", config.Timeout, 30*time.Second)
	}
	if config.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want %d", config.MaxRetries, 5)
	}
	if config.TenantID != "tenant-123" {
		t.Errorf("TenantID = %q, want %q", config.TenantID, "tenant-123")
	}
}

func TestQuery(t *testing.T) {
	query := &Query{
		Statement: "SELECT * FROM users WHERE id = $1",
		Parameters: map[string]interface{}{
			"id": 123,
		},
		Timeout: 10 * time.Second,
		Limit:   100,
	}

	if query.Statement != "SELECT * FROM users WHERE id = $1" {
		t.Errorf("Statement incorrect")
	}
	if query.Parameters["id"] != 123 {
		t.Errorf("Parameters[id] = %v, want %v", query.Parameters["id"], 123)
	}
	if query.Limit != 100 {
		t.Errorf("Limit = %d, want %d", query.Limit, 100)
	}
}

func TestQueryResult(t *testing.T) {
	result := &QueryResult{
		Rows: []map[string]interface{}{
			{"id": 1, "name": "Alice"},
			{"id": 2, "name": "Bob"},
		},
		RowCount:  2,
		Duration:  50 * time.Millisecond,
		Cached:    true,
		Connector: "my-postgres",
	}

	if result.RowCount != 2 {
		t.Errorf("RowCount = %d, want %d", result.RowCount, 2)
	}
	if !result.Cached {
		t.Error("expected Cached to be true")
	}
	if result.Connector != "my-postgres" {
		t.Errorf("Connector = %q, want %q", result.Connector, "my-postgres")
	}
}

func TestCommand(t *testing.T) {
	cmd := &Command{
		Action:    "INSERT",
		Statement: "INSERT INTO users (name) VALUES ($1)",
		Parameters: map[string]interface{}{
			"name": "Charlie",
		},
		Timeout: 5 * time.Second,
	}

	if cmd.Action != "INSERT" {
		t.Errorf("Action = %q, want %q", cmd.Action, "INSERT")
	}
	if cmd.Statement != "INSERT INTO users (name) VALUES ($1)" {
		t.Errorf("Statement incorrect")
	}
}

func TestCommandResult(t *testing.T) {
	result := &CommandResult{
		Success:      true,
		RowsAffected: 5,
		Duration:     100 * time.Millisecond,
		Message:      "5 rows inserted",
		Connector:    "my-postgres",
	}

	if !result.Success {
		t.Error("expected Success to be true")
	}
	if result.RowsAffected != 5 {
		t.Errorf("RowsAffected = %d, want %d", result.RowsAffected, 5)
	}
	if result.Message != "5 rows inserted" {
		t.Errorf("Message = %q, want %q", result.Message, "5 rows inserted")
	}
}

func TestHealthStatus(t *testing.T) {
	now := time.Now()
	status := &HealthStatus{
		Healthy:   true,
		Latency:   10 * time.Millisecond,
		Details:   map[string]string{"version": "14.1"},
		Timestamp: now,
		Error:     "",
	}

	if !status.Healthy {
		t.Error("expected Healthy to be true")
	}
	if status.Latency != 10*time.Millisecond {
		t.Errorf("Latency = %v, want %v", status.Latency, 10*time.Millisecond)
	}
	if status.Details["version"] != "14.1" {
		t.Errorf("Details[version] = %q, want %q", status.Details["version"], "14.1")
	}
	if status.Error != "" {
		t.Errorf("Error = %q, want empty", status.Error)
	}

	// Test unhealthy status
	unhealthy := &HealthStatus{
		Healthy:   false,
		Error:     "connection refused",
		Timestamp: now,
	}

	if unhealthy.Healthy {
		t.Error("expected Healthy to be false")
	}
	if unhealthy.Error != "connection refused" {
		t.Errorf("Error = %q, want %q", unhealthy.Error, "connection refused")
	}
}
