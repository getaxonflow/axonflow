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

package postgres

import (
	"context"
	"testing"
	"time"

	"axonflow/platform/connectors/base"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestNewPostgresConnector(t *testing.T) {
	conn := NewPostgresConnector()
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
	if conn.logger == nil {
		t.Error("expected logger to be initialized")
	}
}

func TestPostgresConnector_Name(t *testing.T) {
	conn := NewPostgresConnector()

	// Without config
	if got := conn.Name(); got != "postgres" {
		t.Errorf("Name() without config = %q, want %q", got, "postgres")
	}

	// With config
	conn.config = &base.ConnectorConfig{
		Name: "my-postgres",
	}
	if got := conn.Name(); got != "my-postgres" {
		t.Errorf("Name() with config = %q, want %q", got, "my-postgres")
	}
}

func TestPostgresConnector_Type(t *testing.T) {
	conn := NewPostgresConnector()
	if got := conn.Type(); got != "postgres" {
		t.Errorf("Type() = %q, want %q", got, "postgres")
	}
}

func TestPostgresConnector_Version(t *testing.T) {
	conn := NewPostgresConnector()
	if got := conn.Version(); got != "1.0.0" {
		t.Errorf("Version() = %q, want %q", got, "1.0.0")
	}
}

func TestPostgresConnector_Capabilities(t *testing.T) {
	conn := NewPostgresConnector()
	caps := conn.Capabilities()

	if len(caps) == 0 {
		t.Fatal("expected non-empty capabilities")
	}

	expected := []string{"query", "execute", "transactions", "prepared_statements", "connection_pooling"}
	for _, e := range expected {
		found := false
		for _, c := range caps {
			if c == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected capability %q not found", e)
		}
	}
}

func TestPostgresConnector_Disconnect_NilDB(t *testing.T) {
	conn := NewPostgresConnector()

	// Disconnect without connecting first should not error
	ctx := context.Background()
	err := conn.Disconnect(ctx)
	if err != nil {
		t.Errorf("Disconnect with nil db should not error: %v", err)
	}
}

func TestPostgresConnector_HealthCheck_NilDB(t *testing.T) {
	conn := NewPostgresConnector()

	ctx := context.Background()
	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status with nil db")
	}
	if status.Error != "database not connected" {
		t.Errorf("expected error message 'database not connected', got %q", status.Error)
	}
}

func TestPostgresConnector_Query_NilDB(t *testing.T) {
	conn := NewPostgresConnector()
	conn.config = &base.ConnectorConfig{Name: "test"}

	ctx := context.Background()
	query := &base.Query{
		Statement: "SELECT 1",
	}

	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error when querying with nil db")
	}
}

func TestPostgresConnector_Execute_NilDB(t *testing.T) {
	conn := NewPostgresConnector()
	conn.config = &base.ConnectorConfig{Name: "test"}

	ctx := context.Background()
	cmd := &base.Command{
		Action:    "INSERT",
		Statement: "INSERT INTO test VALUES (1)",
	}

	_, err := conn.Execute(ctx, cmd)
	if err == nil {
		t.Error("expected error when executing with nil db")
	}
}

func TestPostgresConnector_buildArgs(t *testing.T) {
	conn := NewPostgresConnector()

	// Empty params
	args, err := conn.buildArgs(nil)
	if err != nil {
		t.Errorf("unexpected error with nil params: %v", err)
	}
	if args != nil {
		t.Errorf("expected nil args for nil params, got %v", args)
	}

	// Empty map
	args, err = conn.buildArgs(map[string]interface{}{})
	if err != nil {
		t.Errorf("unexpected error with empty map: %v", err)
	}
	if args != nil {
		t.Errorf("expected nil args for empty map, got %v", args)
	}

	// With params
	params := map[string]interface{}{
		"id":   1,
		"name": "test",
	}
	args, err = conn.buildArgs(params)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(args) != 2 {
		t.Errorf("expected 2 args, got %d", len(args))
	}
}

func TestPostgresConnector_Connect_InvalidURL(t *testing.T) {
	conn := NewPostgresConnector()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	config := &base.ConnectorConfig{
		Name:          "test-pg",
		Type:          "postgres",
		ConnectionURL: "postgres://invalid:password@localhost:99999/nonexistent",
		Timeout:       100 * time.Millisecond,
		Options:       map[string]interface{}{},
	}

	err := conn.Connect(ctx, config)
	if err == nil {
		// If we somehow connected, make sure to disconnect
		conn.Disconnect(ctx)
		t.Skip("Unexpectedly connected (PostgreSQL may be running locally)")
	}
	// Error is expected - connection should fail
}

func TestPostgresConnector_Connect_WithOptions(t *testing.T) {
	conn := NewPostgresConnector()

	config := &base.ConnectorConfig{
		Name:          "test-pg",
		Type:          "postgres",
		ConnectionURL: "postgres://localhost:5432/test", // Won't actually connect
		Timeout:       100 * time.Millisecond,
		Options: map[string]interface{}{
			"max_open_conns":    10,
			"max_idle_conns":    2,
			"conn_max_lifetime": "10m",
		},
	}

	// This will fail to connect (no DB), but options should be parsed
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := conn.Connect(ctx, config)
	// Error is expected - we just want to verify options parsing doesn't panic
	if err == nil {
		conn.Disconnect(ctx)
	}
}

func TestPostgresConnector_QueryWithParameters(t *testing.T) {
	conn := NewPostgresConnector()
	conn.config = &base.ConnectorConfig{
		Name:    "test",
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	query := &base.Query{
		Statement: "SELECT * FROM users WHERE id = $1",
		Parameters: map[string]interface{}{
			"id": 1,
		},
		Limit:   10,
		Timeout: 0, // Use config timeout
	}

	// Should fail because db is nil
	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error when querying with nil db")
	}
}

func TestPostgresConnector_ExecuteWithParameters(t *testing.T) {
	conn := NewPostgresConnector()
	conn.config = &base.ConnectorConfig{
		Name:    "test",
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	cmd := &base.Command{
		Action:    "UPDATE",
		Statement: "UPDATE users SET name = $1 WHERE id = $2",
		Parameters: map[string]interface{}{
			"name": "John",
			"id":   1,
		},
		Timeout: 0, // Use config timeout
	}

	// Should fail because db is nil
	_, err := conn.Execute(ctx, cmd)
	if err == nil {
		t.Error("expected error when executing with nil db")
	}
}

func TestPostgresConnector_ConfigOptions_EmptyName(t *testing.T) {
	conn := NewPostgresConnector()

	// Test with nil config
	name := conn.Name()
	if name != "postgres" {
		t.Errorf("expected default name 'postgres', got '%s'", name)
	}

	// Test with empty config
	conn.config = &base.ConnectorConfig{}
	name = conn.Name()
	if name != "" {
		t.Errorf("expected empty name, got '%s'", name)
	}
}

func TestPostgresConnector_buildArgs_VariousTypes(t *testing.T) {
	conn := NewPostgresConnector()

	tests := []struct {
		name   string
		params map[string]interface{}
		count  int
	}{
		{
			name:   "nil params",
			params: nil,
			count:  0,
		},
		{
			name:   "empty map",
			params: map[string]interface{}{},
			count:  0,
		},
		{
			name: "single int",
			params: map[string]interface{}{
				"id": 1,
			},
			count: 1,
		},
		{
			name: "single string",
			params: map[string]interface{}{
				"name": "test",
			},
			count: 1,
		},
		{
			name: "multiple types",
			params: map[string]interface{}{
				"id":     1,
				"name":   "test",
				"active": true,
				"score":  3.14,
			},
			count: 4,
		},
		{
			name: "with nil value",
			params: map[string]interface{}{
				"id":   1,
				"name": nil,
			},
			count: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args, err := conn.buildArgs(tc.params)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.count == 0 {
				if args != nil {
					t.Errorf("expected nil args, got %v", args)
				}
			} else {
				if len(args) != tc.count {
					t.Errorf("expected %d args, got %d", tc.count, len(args))
				}
			}
		})
	}
}

func TestPostgresConnector_Connect_InvalidConnectionString(t *testing.T) {
	conn := NewPostgresConnector()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Test with various invalid connection strings
	tests := []struct {
		name string
		url  string
	}{
		{
			name: "missing host",
			url:  "postgres://:5432/test",
		},
		{
			name: "invalid port",
			url:  "postgres://localhost:invalid/test",
		},
		{
			name: "empty string",
			url:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &base.ConnectorConfig{
				Name:          "test-pg",
				Type:          "postgres",
				ConnectionURL: tc.url,
				Timeout:       100 * time.Millisecond,
			}

			err := conn.Connect(ctx, config)
			// Connection should fail
			if err == nil {
				conn.Disconnect(ctx)
				t.Skip("Unexpectedly connected")
			}
		})
	}
}

func TestPostgresConnector_Connect_OptionsWithInvalidDuration(t *testing.T) {
	conn := NewPostgresConnector()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	config := &base.ConnectorConfig{
		Name:          "test-pg",
		Type:          "postgres",
		ConnectionURL: "postgres://localhost:5432/test",
		Timeout:       100 * time.Millisecond,
		Options: map[string]interface{}{
			"max_open_conns":    10,
			"max_idle_conns":    2,
			"conn_max_lifetime": "invalid-duration",
		},
	}

	// This will fail to connect (no DB), but should not panic on invalid duration
	err := conn.Connect(ctx, config)
	if err == nil {
		conn.Disconnect(ctx)
	}
}

func TestPostgresConnector_QueryWithTimeout(t *testing.T) {
	conn := NewPostgresConnector()
	conn.config = &base.ConnectorConfig{
		Name:    "test",
		Timeout: 1 * time.Second,
	}

	ctx := context.Background()
	query := &base.Query{
		Statement: "SELECT * FROM users",
		Timeout:   500 * time.Millisecond, // Override config timeout
	}

	// Should fail because db is nil
	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error when querying with nil db")
	}
}

func TestPostgresConnector_ExecuteWithTimeout(t *testing.T) {
	conn := NewPostgresConnector()
	conn.config = &base.ConnectorConfig{
		Name:    "test",
		Timeout: 1 * time.Second,
	}

	ctx := context.Background()
	cmd := &base.Command{
		Action:    "DELETE",
		Statement: "DELETE FROM users WHERE id = $1",
		Parameters: map[string]interface{}{
			"id": 1,
		},
		Timeout: 500 * time.Millisecond, // Override config timeout
	}

	// Should fail because db is nil
	_, err := conn.Execute(ctx, cmd)
	if err == nil {
		t.Error("expected error when executing with nil db")
	}
}

// Integration test - skipped without PostgreSQL
func TestPostgresConnector_Integration(t *testing.T) {
	dbURL := "postgres://test_user:test_password@localhost:5432/test_db?sslmode=disable"

	// Skip integration tests if no PostgreSQL is available
	t.Skip("Skipping integration test - requires PostgreSQL")

	conn := NewPostgresConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:          "test-postgres",
		Type:          "postgres",
		ConnectionURL: dbURL,
		Timeout:       5 * time.Second,
		Options: map[string]interface{}{
			"max_open_conns": 5,
			"max_idle_conns": 2,
		},
	}

	err := conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Disconnect(ctx)

	// Test health check
	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("health check error: %v", err)
	}
	if !status.Healthy {
		t.Errorf("expected healthy status, got error: %s", status.Error)
	}
}

func TestPostgresConnector_Query_WithMock(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	conn := NewPostgresConnector()
	conn.db = db
	conn.config = &base.ConnectorConfig{
		Name:    "test-postgres",
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()

	// Set up expected query
	rows := sqlmock.NewRows([]string{"id", "name", "email"}).
		AddRow(1, "John Doe", "john@example.com").
		AddRow(2, "Jane Doe", "jane@example.com")

	mock.ExpectQuery("SELECT id, name, email FROM users").WillReturnRows(rows)

	query := &base.Query{
		Statement:  "SELECT id, name, email FROM users",
		Parameters: nil,
		Limit:      0,
		Timeout:    0,
	}

	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.RowCount != 2 {
		t.Errorf("expected 2 rows, got %d", result.RowCount)
	}

	if result.Connector != "test-postgres" {
		t.Errorf("expected connector 'test-postgres', got '%s'", result.Connector)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestPostgresConnector_Query_WithLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	conn := NewPostgresConnector()
	conn.db = db
	conn.config = &base.ConnectorConfig{
		Name:    "test-postgres",
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()

	// Return 5 rows but limit to 2
	rows := sqlmock.NewRows([]string{"id"}).
		AddRow(1).
		AddRow(2).
		AddRow(3).
		AddRow(4).
		AddRow(5)

	mock.ExpectQuery("SELECT id FROM users").WillReturnRows(rows)

	query := &base.Query{
		Statement: "SELECT id FROM users",
		Limit:     2,
	}

	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.RowCount != 2 {
		t.Errorf("expected 2 rows (limited), got %d", result.RowCount)
	}
}

func TestPostgresConnector_Query_WithParameters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	conn := NewPostgresConnector()
	conn.db = db
	conn.config = &base.ConnectorConfig{
		Name:    "test-postgres",
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()

	rows := sqlmock.NewRows([]string{"id", "name"}).
		AddRow(1, "John")

	mock.ExpectQuery("SELECT").WithArgs(1).WillReturnRows(rows)

	query := &base.Query{
		Statement: "SELECT id, name FROM users WHERE id = $1",
		Parameters: map[string]interface{}{
			"id": 1,
		},
	}

	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.RowCount != 1 {
		t.Errorf("expected 1 row, got %d", result.RowCount)
	}
}

func TestPostgresConnector_Execute_WithMock(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	conn := NewPostgresConnector()
	conn.db = db
	conn.config = &base.ConnectorConfig{
		Name:    "test-postgres",
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()

	// Use AnyArg() since map iteration order is not guaranteed
	mock.ExpectExec("INSERT INTO users").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	cmd := &base.Command{
		Action:    "INSERT",
		Statement: "INSERT INTO users (name, email) VALUES ($1, $2)",
		Parameters: map[string]interface{}{
			"name":  "John",
			"email": "john@example.com",
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Success {
		t.Error("expected success")
	}

	if result.RowsAffected != 1 {
		t.Errorf("expected 1 row affected, got %d", result.RowsAffected)
	}

	if result.Connector != "test-postgres" {
		t.Errorf("expected connector 'test-postgres', got '%s'", result.Connector)
	}
}

func TestPostgresConnector_Execute_Update(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	conn := NewPostgresConnector()
	conn.db = db
	conn.config = &base.ConnectorConfig{
		Name:    "test-postgres",
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()

	// Use AnyArg() since map iteration order is not guaranteed
	mock.ExpectExec("UPDATE users SET").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	cmd := &base.Command{
		Action:    "UPDATE",
		Statement: "UPDATE users SET name = $1 WHERE id = $2",
		Parameters: map[string]interface{}{
			"name": "NewName",
			"id":   1,
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Success {
		t.Error("expected success")
	}
}

func TestPostgresConnector_HealthCheck_WithMock(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	conn := NewPostgresConnector()
	conn.db = db
	conn.config = &base.ConnectorConfig{
		Name: "test-postgres",
	}

	ctx := context.Background()

	mock.ExpectPing()

	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !status.Healthy {
		t.Errorf("expected healthy status, got error: %s", status.Error)
	}

	// Check that details are populated
	if status.Details == nil {
		t.Error("expected details to be populated")
	}
}

func TestPostgresConnector_Disconnect_WithMock(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}

	conn := NewPostgresConnector()
	conn.db = db
	conn.config = &base.ConnectorConfig{
		Name: "test-postgres",
	}

	ctx := context.Background()

	mock.ExpectClose()

	err = conn.Disconnect(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPostgresConnector_Query_ByteConversion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	conn := NewPostgresConnector()
	conn.db = db
	conn.config = &base.ConnectorConfig{
		Name:    "test-postgres",
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()

	// Test with byte array value (simulates text fields)
	rows := sqlmock.NewRows([]string{"data"}).
		AddRow([]byte("hello world"))

	mock.ExpectQuery("SELECT data FROM test").WillReturnRows(rows)

	query := &base.Query{
		Statement: "SELECT data FROM test",
	}

	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.RowCount != 1 {
		t.Errorf("expected 1 row, got %d", result.RowCount)
	}

	// Check that byte array was converted to string
	if val, ok := result.Rows[0]["data"].(string); !ok || val != "hello world" {
		t.Errorf("expected string 'hello world', got %v", result.Rows[0]["data"])
	}
}
