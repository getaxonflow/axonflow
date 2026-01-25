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

package mysql

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

// getTestDSN returns the MySQL DSN for testing
// Set MYSQL_TEST_DSN environment variable for integration tests
func getTestDSN() string {
	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		// Default DSN for local testing with Docker
		dsn = "root:testpassword@tcp(localhost:3306)/testdb?parseTime=true"
	}
	return dsn
}

func skipIfNoMySQL(t *testing.T) *MySQLConnector {
	dsn := getTestDSN()

	// Try to connect
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Skipf("MySQL not available: %v", err)
		return nil
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		t.Skipf("MySQL not available: %v", err)
		return nil
	}

	c := NewMySQLConnector()
	err = c.Connect(context.Background(), &base.ConnectorConfig{
		Name:          "test-mysql",
		ConnectionURL: dsn,
		Timeout:       30 * time.Second,
	})
	if err != nil {
		t.Skipf("Failed to connect: %v", err)
		return nil
	}

	return c
}

func TestNewMySQLConnector(t *testing.T) {
	c := NewMySQLConnector()
	if c == nil {
		t.Fatal("NewMySQLConnector returned nil")
	}
	if c.logger == nil {
		t.Error("expected logger to be initialized")
	}
}

func TestMySQLConnector_Metadata(t *testing.T) {
	c := NewMySQLConnector()

	if c.Type() != "mysql" {
		t.Errorf("Type() = %s, want mysql", c.Type())
	}
	if c.Version() != "1.0.0" {
		t.Errorf("Version() = %s, want 1.0.0", c.Version())
	}
	if c.Name() != "mysql" {
		t.Errorf("Name() = %s, want mysql", c.Name())
	}

	caps := c.Capabilities()
	expectedCaps := []string{
		"query",
		"execute",
		"transactions",
		"prepared_statements",
		"connection_pooling",
		"last_insert_id",
	}
	if len(caps) != len(expectedCaps) {
		t.Errorf("Capabilities() length = %d, want %d", len(caps), len(expectedCaps))
	}
}

func TestMySQLConnector_BuildDSN(t *testing.T) {
	c := NewMySQLConnector()

	tests := []struct {
		name    string
		config  *base.ConnectorConfig
		wantErr bool
	}{
		{
			name: "full connection URL",
			config: &base.ConnectorConfig{
				Name:          "test",
				ConnectionURL: "user:pass@tcp(localhost:3306)/testdb?parseTime=true",
			},
			wantErr: false,
		},
		{
			name: "build from options",
			config: &base.ConnectorConfig{
				Name: "test",
				Options: map[string]interface{}{
					"host":     "localhost",
					"port":     float64(3306),
					"database": "testdb",
				},
				Credentials: map[string]string{
					"username": "user",
					"password": "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "missing database",
			config: &base.ConnectorConfig{
				Name: "test",
				Options: map[string]interface{}{
					"host": "localhost",
				},
				Credentials: map[string]string{
					"username": "user",
					"password": "pass",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dsn, err := c.buildDSN(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildDSN() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && dsn == "" {
				t.Error("buildDSN() returned empty DSN")
			}
		})
	}
}

func TestMySQLConnector_BuildArgs(t *testing.T) {
	c := NewMySQLConnector()

	tests := []struct {
		name         string
		statement    string
		params       map[string]interface{}
		wantLen      int
		wantStmt     string
		wantErr      bool
	}{
		{
			name:      "empty params",
			statement: "SELECT * FROM users",
			params:    nil,
			wantLen:   0,
			wantStmt:  "SELECT * FROM users",
			wantErr:   false,
		},
		{
			name:      "named parameters",
			statement: "SELECT * FROM users WHERE id = :id AND name = :name",
			params: map[string]interface{}{
				"id":   1,
				"name": "test",
			},
			wantLen:  2,
			wantStmt: "SELECT * FROM users WHERE id = ? AND name = ?",
			wantErr:  false,
		},
		{
			name:      "numeric keys",
			statement: "SELECT * FROM users WHERE id = ? AND name = ?",
			params: map[string]interface{}{
				"0": 1,
				"1": "test",
			},
			wantLen:  2,
			wantStmt: "SELECT * FROM users WHERE id = ? AND name = ?",
			wantErr:  false,
		},
		{
			name:      "missing named parameter",
			statement: "SELECT * FROM users WHERE id = :id AND name = :name",
			params: map[string]interface{}{
				"id": 1,
			},
			wantLen: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt, args, err := c.buildArgs(tt.statement, tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if len(args) != tt.wantLen {
					t.Errorf("buildArgs() returned %d args, want %d", len(args), tt.wantLen)
				}
				if stmt != tt.wantStmt {
					t.Errorf("buildArgs() returned stmt %q, want %q", stmt, tt.wantStmt)
				}
			}
		})
	}
}

func TestMySQLConnector_Connect_InvalidDSN(t *testing.T) {
	c := NewMySQLConnector()

	err := c.Connect(context.Background(), &base.ConnectorConfig{
		Name:          "test-mysql",
		ConnectionURL: "invalid:invalid@tcp(invalid:3306)/invalid",
		Timeout:       1 * time.Second,
	})

	if err == nil {
		c.Disconnect(context.Background())
		t.Error("expected error for invalid DSN")
	}
}

func TestMySQLConnector_DisconnectWithoutConnect(t *testing.T) {
	c := NewMySQLConnector()

	// Should not error when disconnecting without connecting
	err := c.Disconnect(context.Background())
	if err != nil {
		t.Errorf("Disconnect() error = %v, want nil", err)
	}
}

func TestMySQLConnector_QueryWithoutConnect(t *testing.T) {
	c := NewMySQLConnector()

	_, err := c.Query(context.Background(), &base.Query{
		Statement: "SELECT 1",
	})

	if err == nil {
		t.Error("expected error when querying without connection")
	}
}

func TestMySQLConnector_ExecuteWithoutConnect(t *testing.T) {
	c := NewMySQLConnector()

	_, err := c.Execute(context.Background(), &base.Command{
		Action:    "INSERT",
		Statement: "INSERT INTO test VALUES (1)",
	})

	if err == nil {
		t.Error("expected error when executing without connection")
	}
}

func TestMySQLConnector_HealthCheckWithoutConnect(t *testing.T) {
	c := NewMySQLConnector()

	status, err := c.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("HealthCheck() error = %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status when not connected")
	}
}

func TestMySQLConnector_BeginTxWithoutConnect(t *testing.T) {
	c := NewMySQLConnector()

	_, err := c.BeginTx(context.Background(), nil)
	if err == nil {
		t.Error("expected error when calling BeginTx without connection")
	}
}

func TestMySQLConnector_PrepareWithoutConnect(t *testing.T) {
	c := NewMySQLConnector()

	_, err := c.Prepare(context.Background(), "SELECT 1")
	if err == nil {
		t.Error("expected error when calling Prepare without connection")
	}
}

func TestMySQLConnector_NameWithConfig(t *testing.T) {
	c := NewMySQLConnector()

	// Without config, should return default
	if c.Name() != "mysql" {
		t.Errorf("Name() = %s, want mysql", c.Name())
	}

	// With config, should return config name
	c.config = &base.ConnectorConfig{Name: "my-mysql-db"}
	if c.Name() != "my-mysql-db" {
		t.Errorf("Name() = %s, want my-mysql-db", c.Name())
	}

	// With empty config name, should return empty
	c.config = &base.ConnectorConfig{Name: ""}
	if c.Name() != "" {
		t.Errorf("Name() = %s, want empty", c.Name())
	}
}

func TestMySQLConnector_BuildDSN_MoreCases(t *testing.T) {
	c := NewMySQLConnector()

	tests := []struct {
		name    string
		config  *base.ConnectorConfig
		wantErr bool
	}{
		{
			name: "with socket option",
			config: &base.ConnectorConfig{
				Name: "test",
				Options: map[string]interface{}{
					"socket":   "/var/run/mysqld/mysqld.sock",
					"database": "testdb",
				},
				Credentials: map[string]string{
					"username": "user",
					"password": "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "with charset option",
			config: &base.ConnectorConfig{
				Name: "test",
				Options: map[string]interface{}{
					"host":     "localhost",
					"port":     float64(3306),
					"database": "testdb",
					"charset":  "utf8mb4",
				},
				Credentials: map[string]string{
					"username": "user",
					"password": "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "with tls option",
			config: &base.ConnectorConfig{
				Name: "test",
				Options: map[string]interface{}{
					"host":     "localhost",
					"port":     float64(3306),
					"database": "testdb",
					"tls":      "skip-verify",
				},
				Credentials: map[string]string{
					"username": "user",
					"password": "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "with collation option",
			config: &base.ConnectorConfig{
				Name: "test",
				Options: map[string]interface{}{
					"host":      "localhost",
					"port":      float64(3306),
					"database":  "testdb",
					"collation": "utf8mb4_unicode_ci",
				},
				Credentials: map[string]string{
					"username": "user",
					"password": "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "missing username allowed",
			config: &base.ConnectorConfig{
				Name: "test",
				Options: map[string]interface{}{
					"host":     "localhost",
					"database": "testdb",
				},
				Credentials: map[string]string{
					"password": "pass",
				},
			},
			wantErr: false, // MySQL allows connections without username
		},
		{
			name: "empty config",
			config: &base.ConnectorConfig{
				Name: "test",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dsn, err := c.buildDSN(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildDSN() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && dsn == "" {
				t.Error("buildDSN() returned empty DSN")
			}
		})
	}
}

func TestMySQLConnector_BuildArgs_MoreCases(t *testing.T) {
	c := NewMySQLConnector()

	tests := []struct {
		name      string
		statement string
		params    map[string]interface{}
		wantLen   int
		wantErr   bool
	}{
		{
			name:      "multiple same named parameters",
			statement: "SELECT * FROM users WHERE id = :id OR parent_id = :id",
			params: map[string]interface{}{
				"id": 42,
			},
			wantLen: 2, // :id appears twice
			wantErr: false,
		},
		{
			name:      "special characters in values",
			statement: "INSERT INTO logs (message) VALUES (:msg)",
			params: map[string]interface{}{
				"msg": "Error: 'connection failed' at \"localhost\"",
			},
			wantLen: 1,
			wantErr: false,
		},
		{
			name:      "nil value",
			statement: "UPDATE users SET deleted_at = :deleted WHERE id = :id",
			params: map[string]interface{}{
				"deleted": nil,
				"id":      1,
			},
			wantLen: 2,
			wantErr: false,
		},
		{
			name:      "time value",
			statement: "SELECT * FROM events WHERE created_at > :since",
			params: map[string]interface{}{
				"since": time.Now(),
			},
			wantLen: 1,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, args, err := c.buildArgs(tt.statement, tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(args) != tt.wantLen {
				t.Errorf("buildArgs() returned %d args, want %d", len(args), tt.wantLen)
			}
		})
	}
}

func TestMySQLConnector_Connect_BuildDSNError(t *testing.T) {
	c := NewMySQLConnector()

	// Config that will fail buildDSN
	err := c.Connect(context.Background(), &base.ConnectorConfig{
		Name: "test",
		// No connection URL and no options to build DSN from
	})

	if err == nil {
		t.Error("expected error when buildDSN fails")
	}
}

func TestMySQLConnector_ValidateAndEnhanceDSN(t *testing.T) {
	c := NewMySQLConnector()

	tests := []struct {
		name       string
		dsn        string
		config     *base.ConnectorConfig
		wantResult string
		wantErr    bool
	}{
		{
			name: "adds parseTime when not present",
			dsn:  "user:pass@tcp(localhost:3306)/testdb",
			config: &base.ConnectorConfig{
				Name: "test",
			},
			wantResult: "user:pass@tcp(localhost:3306)/testdb?parseTime=true",
			wantErr:    false,
		},
		{
			name: "appends parseTime with & when params exist",
			dsn:  "user:pass@tcp(localhost:3306)/testdb?charset=utf8mb4",
			config: &base.ConnectorConfig{
				Name: "test",
			},
			wantResult: "user:pass@tcp(localhost:3306)/testdb?charset=utf8mb4&parseTime=true",
			wantErr:    false,
		},
		{
			name: "does not duplicate parseTime",
			dsn:  "user:pass@tcp(localhost:3306)/testdb?parseTime=true",
			config: &base.ConnectorConfig{
				Name: "test",
			},
			wantResult: "user:pass@tcp(localhost:3306)/testdb?parseTime=true",
			wantErr:    false,
		},
		{
			name: "adds credentials when not in DSN",
			dsn:  "tcp(localhost:3306)/testdb",
			config: &base.ConnectorConfig{
				Name: "test",
				Credentials: map[string]string{
					"username": "admin",
					"password": "secret",
				},
			},
			wantResult: "admin:secret@tcp(localhost:3306)/testdb?parseTime=true",
			wantErr:    false,
		},
		{
			name: "does not add credentials when already present",
			dsn:  "existinguser:existingpass@tcp(localhost:3306)/testdb",
			config: &base.ConnectorConfig{
				Name: "test",
				Credentials: map[string]string{
					"username": "admin",
					"password": "secret",
				},
			},
			wantResult: "existinguser:existingpass@tcp(localhost:3306)/testdb?parseTime=true",
			wantErr:    false,
		},
		{
			name: "empty credentials does not add @",
			dsn:  "tcp(localhost:3306)/testdb",
			config: &base.ConnectorConfig{
				Name:        "test",
				Credentials: map[string]string{},
			},
			wantResult: "tcp(localhost:3306)/testdb?parseTime=true",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := c.validateAndEnhanceDSN(tt.dsn, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAndEnhanceDSN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.wantResult {
				t.Errorf("validateAndEnhanceDSN() = %q, want %q", result, tt.wantResult)
			}
		})
	}
}

func TestMySQLConnector_Disconnect_NilDB(t *testing.T) {
	c := NewMySQLConnector()
	// db is nil by default

	err := c.Disconnect(context.Background())
	if err != nil {
		t.Errorf("Disconnect() with nil db should not error: %v", err)
	}
}

func TestMySQLConnector_HealthCheck_NilDB(t *testing.T) {
	c := NewMySQLConnector()
	c.config = &base.ConnectorConfig{Name: "test"}
	// db is nil by default

	status, err := c.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("HealthCheck() unexpected error: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status with nil db")
	}
	if status.Error != "database not connected" {
		t.Errorf("expected error 'database not connected', got %q", status.Error)
	}
}

func TestMySQLConnector_Query_NilDB(t *testing.T) {
	c := NewMySQLConnector()
	c.config = &base.ConnectorConfig{Name: "test"}

	query := &base.Query{
		Statement: "SELECT * FROM users",
	}

	_, err := c.Query(context.Background(), query)
	if err == nil {
		t.Error("expected error when querying with nil db")
	}
}

func TestMySQLConnector_Execute_NilDB(t *testing.T) {
	c := NewMySQLConnector()
	c.config = &base.ConnectorConfig{Name: "test"}

	cmd := &base.Command{
		Action:    "INSERT",
		Statement: "INSERT INTO users (name) VALUES (:name)",
		Parameters: map[string]interface{}{
			"name": "test",
		},
	}

	_, err := c.Execute(context.Background(), cmd)
	if err == nil {
		t.Error("expected error when executing with nil db")
	}
}

// Integration tests - run with actual MySQL
func TestMySQLConnector_Integration_Connect(t *testing.T) {
	c := skipIfNoMySQL(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	// Connection should succeed
	if c.db == nil {
		t.Error("expected db to be initialized")
	}
}

func TestMySQLConnector_Integration_HealthCheck(t *testing.T) {
	c := skipIfNoMySQL(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	status, err := c.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("HealthCheck() error = %v", err)
	}
	if !status.Healthy {
		t.Errorf("expected healthy status, got error: %s", status.Error)
	}
	if status.Details["mysql_version"] == "" {
		t.Error("expected mysql_version in details")
	}
}

func TestMySQLConnector_Integration_Query(t *testing.T) {
	c := skipIfNoMySQL(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	// Create test table
	_, err := c.Execute(context.Background(), &base.Command{
		Action:    "CREATE",
		Statement: "CREATE TABLE IF NOT EXISTS connector_test (id INT PRIMARY KEY, name VARCHAR(255))",
	})
	if err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	// Clean up test data
	defer func() {
		c.Execute(context.Background(), &base.Command{
			Action:    "DROP",
			Statement: "DROP TABLE IF EXISTS connector_test",
		})
	}()

	// Insert test data
	_, err = c.Execute(context.Background(), &base.Command{
		Action:    "INSERT",
		Statement: "INSERT INTO connector_test (id, name) VALUES (?, ?)",
		Parameters: map[string]interface{}{
			"0": 1,
			"1": "Alice",
		},
	})
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	// Query the data
	result, err := c.Query(context.Background(), &base.Query{
		Statement: "SELECT id, name FROM connector_test WHERE id = ?",
		Parameters: map[string]interface{}{
			"0": 1,
		},
	})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	if result.RowCount != 1 {
		t.Errorf("expected 1 row, got %d", result.RowCount)
	}
	if result.Rows[0]["name"] != "Alice" {
		t.Errorf("expected name 'Alice', got '%v'", result.Rows[0]["name"])
	}
}

func TestMySQLConnector_Integration_Execute(t *testing.T) {
	c := skipIfNoMySQL(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	// Create test table
	_, err := c.Execute(context.Background(), &base.Command{
		Action:    "CREATE",
		Statement: "CREATE TABLE IF NOT EXISTS execute_test (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255))",
	})
	if err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	defer func() {
		c.Execute(context.Background(), &base.Command{
			Action:    "DROP",
			Statement: "DROP TABLE IF EXISTS execute_test",
		})
	}()

	// Test INSERT
	result, err := c.Execute(context.Background(), &base.Command{
		Action:    "INSERT",
		Statement: "INSERT INTO execute_test (name) VALUES (?)",
		Parameters: map[string]interface{}{
			"0": "Bob",
		},
	})
	if err != nil {
		t.Fatalf("INSERT failed: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Errorf("expected 1 row affected, got %d", result.RowsAffected)
	}

	// Test UPDATE
	result, err = c.Execute(context.Background(), &base.Command{
		Action:    "UPDATE",
		Statement: "UPDATE execute_test SET name = ? WHERE name = ?",
		Parameters: map[string]interface{}{
			"0": "Bob Updated",
			"1": "Bob",
		},
	})
	if err != nil {
		t.Fatalf("UPDATE failed: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Errorf("expected 1 row affected, got %d", result.RowsAffected)
	}

	// Test DELETE
	result, err = c.Execute(context.Background(), &base.Command{
		Action:    "DELETE",
		Statement: "DELETE FROM execute_test WHERE name = ?",
		Parameters: map[string]interface{}{
			"0": "Bob Updated",
		},
	})
	if err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}
	if result.RowsAffected != 1 {
		t.Errorf("expected 1 row affected, got %d", result.RowsAffected)
	}
}

func TestMySQLConnector_Integration_Transaction(t *testing.T) {
	c := skipIfNoMySQL(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	// Create test table
	_, err := c.Execute(context.Background(), &base.Command{
		Action:    "CREATE",
		Statement: "CREATE TABLE IF NOT EXISTS tx_test (id INT PRIMARY KEY, value INT)",
	})
	if err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	defer func() {
		c.Execute(context.Background(), &base.Command{
			Action:    "DROP",
			Statement: "DROP TABLE IF EXISTS tx_test",
		})
	}()

	// Start transaction
	ctx := context.Background()
	tx, err := c.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx() error = %v", err)
	}

	// Insert within transaction
	_, err = tx.ExecContext(ctx, "INSERT INTO tx_test (id, value) VALUES (1, 100)")
	if err != nil {
		tx.Rollback()
		t.Fatalf("INSERT in transaction failed: %v", err)
	}

	// Commit
	err = tx.Commit()
	if err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	// Verify data was committed
	result, err := c.Query(ctx, &base.Query{
		Statement: "SELECT value FROM tx_test WHERE id = 1",
	})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if result.RowCount != 1 {
		t.Errorf("expected 1 row, got %d", result.RowCount)
	}
}

func TestMySQLConnector_Integration_QueryTimeout(t *testing.T) {
	c := skipIfNoMySQL(t)
	if c == nil {
		return
	}
	defer c.Disconnect(context.Background())

	// Very short timeout should fail for complex query
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	_, err := c.Query(ctx, &base.Query{
		Statement: "SELECT SLEEP(1)",
	})

	// Should error due to timeout
	if err == nil {
		t.Error("expected timeout error")
	}
}
