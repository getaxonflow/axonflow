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
