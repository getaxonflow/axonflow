// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

// Integration tests for PostgresConnector
// These tests require DATABASE_URL to be set

func getTestDBURL(t *testing.T) string {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}
	return dbURL
}

func TestPostgresConnector_Integration_Connect(t *testing.T) {
	dbURL := getTestDBURL(t)

	conn := NewPostgresConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:          "test_postgres_integration",
		Type:          "postgres",
		ConnectionURL: dbURL,
		TenantID:      "test_tenant",
		Timeout:       30 * time.Second,
		MaxRetries:    3,
	}

	err := conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Verify connection
	if conn.Name() != "test_postgres_integration" {
		t.Errorf("Name() = %q, want %q", conn.Name(), "test_postgres_integration")
	}

	// Disconnect
	err = conn.Disconnect(ctx)
	if err != nil {
		t.Errorf("Disconnect failed: %v", err)
	}
}

func TestPostgresConnector_Integration_HealthCheck(t *testing.T) {
	dbURL := getTestDBURL(t)

	conn := NewPostgresConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:          "test_postgres_health",
		Type:          "postgres",
		ConnectionURL: dbURL,
		TenantID:      "test_tenant",
		Timeout:       30 * time.Second,
	}

	err := conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer conn.Disconnect(ctx)

	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}

	if !status.Healthy {
		t.Errorf("Expected healthy status, got unhealthy: %s", status.Error)
	}

	if status.Latency <= 0 {
		t.Error("Expected positive latency")
	}
}

func TestPostgresConnector_Integration_Query(t *testing.T) {
	dbURL := getTestDBURL(t)

	conn := NewPostgresConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:          "test_postgres_query",
		Type:          "postgres",
		ConnectionURL: dbURL,
		TenantID:      "test_tenant",
		Timeout:       30 * time.Second,
	}

	err := conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer conn.Disconnect(ctx)

	// Simple query that should work on any Postgres
	query := &base.Query{
		Statement: "SELECT 1 AS one, 'hello' AS greeting",
	}

	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if result.RowCount != 1 {
		t.Errorf("Expected 1 row, got %d", result.RowCount)
	}

	if len(result.Rows) != 1 {
		t.Fatalf("Expected 1 row in results, got %d", len(result.Rows))
	}

	// Check column values
	row := result.Rows[0]
	if row["one"] != int64(1) && row["one"] != int32(1) && row["one"] != 1 {
		t.Errorf("Expected one=1, got %v (type %T)", row["one"], row["one"])
	}
	if row["greeting"] != "hello" {
		t.Errorf("Expected greeting='hello', got %v", row["greeting"])
	}
}

func TestPostgresConnector_Integration_QueryWithParameters(t *testing.T) {
	dbURL := getTestDBURL(t)

	conn := NewPostgresConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:          "test_postgres_params",
		Type:          "postgres",
		ConnectionURL: dbURL,
		TenantID:      "test_tenant",
		Timeout:       30 * time.Second,
	}

	err := conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer conn.Disconnect(ctx)

	// Query with parameters
	query := &base.Query{
		Statement: "SELECT $1::int + $2::int AS sum",
		Parameters: map[string]interface{}{
			"1": 5,
			"2": 3,
		},
	}

	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if result.RowCount != 1 {
		t.Errorf("Expected 1 row, got %d", result.RowCount)
	}
}

func TestPostgresConnector_Integration_Execute_CreateTable(t *testing.T) {
	dbURL := getTestDBURL(t)

	conn := NewPostgresConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:          "test_postgres_execute",
		Type:          "postgres",
		ConnectionURL: dbURL,
		TenantID:      "test_tenant",
		Timeout:       30 * time.Second,
	}

	err := conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	timestamp := time.Now().Format("20060102150405")
	tableName := "test_table_" + timestamp

	// Create table
	createCmd := &base.Command{
		Action: "CREATE",
		Statement: `CREATE TABLE IF NOT EXISTS ` + tableName + ` (
			id SERIAL PRIMARY KEY,
			name VARCHAR(255),
			created_at TIMESTAMP DEFAULT NOW()
		)`,
	}

	result, err := conn.Execute(ctx, createCmd)
	if err != nil {
		t.Fatalf("Execute CREATE TABLE failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success=true, got false: %s", result.Message)
	}

	// Cleanup - drop table before disconnect
	dropCmd := &base.Command{
		Action:    "DROP",
		Statement: "DROP TABLE IF EXISTS " + tableName,
	}
	_, _ = conn.Execute(ctx, dropCmd)

	// Disconnect at the end
	if err := conn.Disconnect(ctx); err != nil {
		t.Errorf("Disconnect failed: %v", err)
	}
}

func TestPostgresConnector_Integration_Execute_InsertAndDelete(t *testing.T) {
	dbURL := getTestDBURL(t)

	conn := NewPostgresConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:          "test_postgres_insert",
		Type:          "postgres",
		ConnectionURL: dbURL,
		TenantID:      "test_tenant",
		Timeout:       30 * time.Second,
	}

	err := conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	timestamp := time.Now().Format("20060102150405")
	tableName := "test_insert_" + timestamp

	// Create table first
	createCmd := &base.Command{
		Action:    "CREATE",
		Statement: `CREATE TABLE ` + tableName + ` (id INT, name VARCHAR(255))`,
	}
	_, err = conn.Execute(ctx, createCmd)
	if err != nil {
		t.Fatalf("Create table failed: %v", err)
	}

	// Insert data
	insertCmd := &base.Command{
		Action:    "INSERT",
		Statement: `INSERT INTO ` + tableName + ` (id, name) VALUES (1, 'test_user')`,
	}

	result, err := conn.Execute(ctx, insertCmd)
	if err != nil {
		t.Fatalf("Execute INSERT failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success=true for INSERT")
	}
	if result.RowsAffected != 1 {
		t.Errorf("Expected RowsAffected=1, got %d", result.RowsAffected)
	}

	// Verify insert
	query := &base.Query{
		Statement: `SELECT name FROM ` + tableName + ` WHERE id = 1`,
	}
	queryResult, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if queryResult.RowCount != 1 {
		t.Errorf("Expected 1 row, got %d", queryResult.RowCount)
	}

	// Delete data
	deleteCmd := &base.Command{
		Action:    "DELETE",
		Statement: `DELETE FROM ` + tableName + ` WHERE id = 1`,
	}

	result, err = conn.Execute(ctx, deleteCmd)
	if err != nil {
		t.Fatalf("Execute DELETE failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success=true for DELETE")
	}
	if result.RowsAffected != 1 {
		t.Errorf("Expected RowsAffected=1 for DELETE, got %d", result.RowsAffected)
	}

	// Cleanup - drop table before disconnect
	dropCmd := &base.Command{
		Action:    "DROP",
		Statement: "DROP TABLE IF EXISTS " + tableName,
	}
	_, _ = conn.Execute(ctx, dropCmd)

	if err := conn.Disconnect(ctx); err != nil {
		t.Errorf("Disconnect failed: %v", err)
	}
}

func TestPostgresConnector_Integration_QueryError(t *testing.T) {
	dbURL := getTestDBURL(t)

	conn := NewPostgresConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:          "test_postgres_error",
		Type:          "postgres",
		ConnectionURL: dbURL,
		TenantID:      "test_tenant",
		Timeout:       30 * time.Second,
	}

	err := conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer conn.Disconnect(ctx)

	// Invalid query
	query := &base.Query{
		Statement: "SELECT * FROM nonexistent_table_xyz123",
	}

	_, err = conn.Query(ctx, query)
	if err == nil {
		t.Error("Expected error for invalid table")
	}
}

func TestPostgresConnector_Integration_Transaction(t *testing.T) {
	dbURL := getTestDBURL(t)

	conn := NewPostgresConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:          "test_postgres_tx",
		Type:          "postgres",
		ConnectionURL: dbURL,
		TenantID:      "test_tenant",
		Timeout:       30 * time.Second,
	}

	err := conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	timestamp := time.Now().Format("20060102150405")
	tableName := "test_tx_" + timestamp

	// Create table
	createCmd := &base.Command{
		Action:    "CREATE",
		Statement: `CREATE TABLE ` + tableName + ` (id INT PRIMARY KEY, value INT)`,
	}
	_, err = conn.Execute(ctx, createCmd)
	if err != nil {
		t.Fatalf("Create table failed: %v", err)
	}

	// Insert data (auto-commit mode - each statement is its own transaction)
	insertCmd := &base.Command{
		Action:    "INSERT",
		Statement: `INSERT INTO ` + tableName + ` (id, value) VALUES (1, 100)`,
	}
	_, err = conn.Execute(ctx, insertCmd)
	if err != nil {
		t.Fatalf("INSERT failed: %v", err)
	}

	// Verify data persisted
	query := &base.Query{
		Statement: `SELECT value FROM ` + tableName + ` WHERE id = 1`,
	}
	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if result.RowCount != 1 {
		t.Errorf("Expected 1 row after insert, got %d", result.RowCount)
	}

	// Update data
	updateCmd := &base.Command{
		Action:    "UPDATE",
		Statement: `UPDATE ` + tableName + ` SET value = 200 WHERE id = 1`,
	}
	updateResult, err := conn.Execute(ctx, updateCmd)
	if err != nil {
		t.Fatalf("UPDATE failed: %v", err)
	}
	if updateResult.RowsAffected != 1 {
		t.Errorf("Expected RowsAffected=1 for UPDATE, got %d", updateResult.RowsAffected)
	}

	// Verify update persisted
	result, err = conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query after update failed: %v", err)
	}
	if result.RowCount != 1 {
		t.Errorf("Expected 1 row after update, got %d", result.RowCount)
	}

	// Cleanup - drop table before disconnect
	dropCmd := &base.Command{
		Action:    "DROP",
		Statement: "DROP TABLE IF EXISTS " + tableName,
	}
	_, _ = conn.Execute(ctx, dropCmd)

	if err := conn.Disconnect(ctx); err != nil {
		t.Errorf("Disconnect failed: %v", err)
	}
}

func TestPostgresConnector_Integration_MultipleConnections(t *testing.T) {
	dbURL := getTestDBURL(t)
	ctx := context.Background()

	// Create multiple connectors
	conn1 := NewPostgresConnector()
	conn2 := NewPostgresConnector()

	config1 := &base.ConnectorConfig{
		Name:          "test_postgres_multi_1",
		Type:          "postgres",
		ConnectionURL: dbURL,
		TenantID:      "tenant1",
		Timeout:       30 * time.Second,
	}

	config2 := &base.ConnectorConfig{
		Name:          "test_postgres_multi_2",
		Type:          "postgres",
		ConnectionURL: dbURL,
		TenantID:      "tenant2",
		Timeout:       30 * time.Second,
	}

	// Connect both
	err := conn1.Connect(ctx, config1)
	if err != nil {
		t.Fatalf("Connect conn1 failed: %v", err)
	}
	defer conn1.Disconnect(ctx)

	err = conn2.Connect(ctx, config2)
	if err != nil {
		t.Fatalf("Connect conn2 failed: %v", err)
	}
	defer conn2.Disconnect(ctx)

	// Both should be healthy
	status1, err := conn1.HealthCheck(ctx)
	if err != nil || !status1.Healthy {
		t.Error("Expected conn1 to be healthy")
	}

	status2, err := conn2.HealthCheck(ctx)
	if err != nil || !status2.Healthy {
		t.Error("Expected conn2 to be healthy")
	}

	// Both should work independently
	query := &base.Query{Statement: "SELECT 1"}
	_, err = conn1.Query(ctx, query)
	if err != nil {
		t.Errorf("conn1 query failed: %v", err)
	}
	_, err = conn2.Query(ctx, query)
	if err != nil {
		t.Errorf("conn2 query failed: %v", err)
	}
}
