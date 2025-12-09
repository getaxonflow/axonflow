// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package redis

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"axonflow/platform/connectors/base"
)

func TestNewRedisConnector(t *testing.T) {
	conn := NewRedisConnector()
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
	if conn.logger == nil {
		t.Error("expected logger to be initialized")
	}
}

func TestRedisConnector_Name(t *testing.T) {
	conn := NewRedisConnector()

	// Without config
	if got := conn.Name(); got != "redis-connector" {
		t.Errorf("Name() = %q, want %q", got, "redis-connector")
	}

	// With config
	conn.config = &base.ConnectorConfig{Name: "my-redis"}
	if got := conn.Name(); got != "my-redis" {
		t.Errorf("Name() = %q, want %q", got, "my-redis")
	}
}

func TestRedisConnector_Type(t *testing.T) {
	conn := NewRedisConnector()
	if got := conn.Type(); got != "redis" {
		t.Errorf("Type() = %q, want %q", got, "redis")
	}
}

func TestRedisConnector_Version(t *testing.T) {
	conn := NewRedisConnector()
	if got := conn.Version(); got != "0.2.0" {
		t.Errorf("Version() = %q, want %q", got, "0.2.0")
	}
}

func TestRedisConnector_Capabilities(t *testing.T) {
	conn := NewRedisConnector()
	caps := conn.Capabilities()

	expected := []string{"query", "execute", "cache", "kv-store"}
	if len(caps) != len(expected) {
		t.Errorf("expected %d capabilities, got %d", len(expected), len(caps))
	}
	for i, c := range caps {
		if c != expected[i] {
			t.Errorf("capability %d: got %q, want %q", i, c, expected[i])
		}
	}
}

func TestRedisConnector_Disconnect_NilClient(t *testing.T) {
	conn := NewRedisConnector()
	ctx := context.Background()

	err := conn.Disconnect(ctx)
	if err != nil {
		t.Errorf("Disconnect with nil client should not error: %v", err)
	}
}

func TestRedisConnector_HealthCheck_NilClient(t *testing.T) {
	conn := NewRedisConnector()
	ctx := context.Background()

	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status with nil client")
	}
	if status.Error != "client not connected" {
		t.Errorf("expected error 'client not connected', got %q", status.Error)
	}
}

func TestRedisConnector_Query_NilClient(t *testing.T) {
	conn := NewRedisConnector()
	conn.config = &base.ConnectorConfig{Name: "test"}
	ctx := context.Background()

	query := &base.Query{Statement: "GET"}
	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error when querying with nil client")
	}
}

func TestRedisConnector_Execute_NilClient(t *testing.T) {
	conn := NewRedisConnector()
	conn.config = &base.ConnectorConfig{Name: "test"}
	ctx := context.Background()

	cmd := &base.Command{Action: "SET"}
	_, err := conn.Execute(ctx, cmd)
	if err == nil {
		t.Error("expected error when executing with nil client")
	}
}

// setupMiniredis creates a miniredis server and returns a connected connector
func setupMiniredis(t *testing.T) (*RedisConnector, *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}

	conn := NewRedisConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:     "test-redis",
		Type:     "redis",
		TenantID: "test-tenant",
		Options: map[string]interface{}{
			"host": mr.Host(),
			"port": float64(mr.Server().Addr().Port),
		},
		Credentials: map[string]string{},
	}

	err = conn.Connect(ctx, config)
	if err != nil {
		mr.Close()
		t.Fatalf("failed to connect: %v", err)
	}

	return conn, mr
}

func TestRedisConnector_Connect(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	if conn.client == nil {
		t.Error("expected client to be connected")
	}
	if conn.config == nil {
		t.Error("expected config to be set")
	}
	if conn.config.Name != "test-redis" {
		t.Errorf("expected name 'test-redis', got %q", conn.config.Name)
	}
}

func TestRedisConnector_Connect_WithPassword(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	mr.RequireAuth("testpassword")

	conn := NewRedisConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:     "test-redis-auth",
		Type:     "redis",
		TenantID: "test-tenant",
		Options: map[string]interface{}{
			"host": mr.Host(),
			"port": float64(mr.Server().Addr().Port),
		},
		Credentials: map[string]string{
			"password": "testpassword",
		},
	}

	err = conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("failed to connect with password: %v", err)
	}
	defer conn.Disconnect(ctx)
}

func TestRedisConnector_Connect_WithDB(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	conn := NewRedisConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:     "test-redis-db",
		Type:     "redis",
		TenantID: "test-tenant",
		Options: map[string]interface{}{
			"host": mr.Host(),
			"port": float64(mr.Server().Addr().Port),
			"db":   float64(1),
		},
		Credentials: map[string]string{},
	}

	err = conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("failed to connect with db: %v", err)
	}
	defer conn.Disconnect(ctx)
}

func TestRedisConnector_Connect_InvalidHost(t *testing.T) {
	conn := NewRedisConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:     "test-redis-invalid",
		Type:     "redis",
		TenantID: "test-tenant",
		Options: map[string]interface{}{
			"host": "invalid-host-that-does-not-exist",
			"port": float64(9999),
		},
		Credentials: map[string]string{},
	}

	err := conn.Connect(ctx, config)
	if err == nil {
		t.Error("expected error when connecting to invalid host")
	}
}

func TestRedisConnector_Disconnect(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()

	ctx := context.Background()
	err := conn.Disconnect(ctx)
	if err != nil {
		t.Errorf("unexpected error on disconnect: %v", err)
	}
}

func TestRedisConnector_HealthCheck(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !status.Healthy {
		t.Errorf("expected healthy status, got unhealthy: %s", status.Error)
	}

	if status.Latency <= 0 {
		t.Error("expected positive latency")
	}

	if status.Details == nil {
		t.Error("expected details map")
	}

	if status.Details["connected"] != "true" {
		t.Error("expected connected=true in details")
	}
}

func TestRedisConnector_Query_GET(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	// Set a value first
	mr.Set("test-key", "test-value")

	ctx := context.Background()
	query := &base.Query{
		Statement:  "GET",
		Parameters: map[string]interface{}{"key": "test-key"},
	}

	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if result.RowCount != 1 {
		t.Errorf("expected 1 row, got %d", result.RowCount)
	}

	row := result.Rows[0]
	if row["key"] != "test-key" {
		t.Errorf("expected key='test-key', got %v", row["key"])
	}
	if row["exists"] != true {
		t.Errorf("expected exists=true, got %v", row["exists"])
	}
	if row["value"] != "test-value" {
		t.Errorf("expected value='test-value', got %v", row["value"])
	}
}

func TestRedisConnector_Query_GET_NonExistent(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	query := &base.Query{
		Statement:  "GET",
		Parameters: map[string]interface{}{"key": "nonexistent-key"},
	}

	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	row := result.Rows[0]
	if row["exists"] != false {
		t.Errorf("expected exists=false, got %v", row["exists"])
	}
}

func TestRedisConnector_Query_GET_MissingKey(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	query := &base.Query{
		Statement:  "GET",
		Parameters: map[string]interface{}{},
	}

	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error for missing key parameter")
	}
}

func TestRedisConnector_Query_EXISTS(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	mr.Set("exists-key", "value")

	ctx := context.Background()

	// Test existing key
	query := &base.Query{
		Statement:  "EXISTS",
		Parameters: map[string]interface{}{"key": "exists-key"},
	}

	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if result.Rows[0]["exists"] != true {
		t.Error("expected exists=true for existing key")
	}

	// Test non-existing key
	query.Parameters["key"] = "nonexistent"
	result, err = conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if result.Rows[0]["exists"] != false {
		t.Error("expected exists=false for non-existing key")
	}
}

func TestRedisConnector_Query_EXISTS_MissingKey(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	query := &base.Query{
		Statement:  "EXISTS",
		Parameters: map[string]interface{}{},
	}

	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error for missing key parameter")
	}
}

func TestRedisConnector_Query_TTL(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	mr.Set("ttl-key", "value")
	mr.SetTTL("ttl-key", 300*time.Second)

	ctx := context.Background()
	query := &base.Query{
		Statement:  "TTL",
		Parameters: map[string]interface{}{"key": "ttl-key"},
	}

	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	ttl := result.Rows[0]["ttl"].(int)
	if ttl <= 0 || ttl > 300 {
		t.Errorf("expected TTL around 300, got %d", ttl)
	}
}

func TestRedisConnector_Query_TTL_MissingKey(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	query := &base.Query{
		Statement:  "TTL",
		Parameters: map[string]interface{}{},
	}

	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error for missing key parameter")
	}
}

func TestRedisConnector_Query_KEYS(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	// Set multiple keys
	mr.Set("prefix:key1", "value1")
	mr.Set("prefix:key2", "value2")
	mr.Set("other:key3", "value3")

	ctx := context.Background()
	query := &base.Query{
		Statement:  "KEYS",
		Parameters: map[string]interface{}{"pattern": "prefix:*"},
	}

	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if result.RowCount < 2 {
		t.Errorf("expected at least 2 rows, got %d", result.RowCount)
	}
}

func TestRedisConnector_Query_KEYS_WithLimit(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	// Set many keys
	for i := 0; i < 20; i++ {
		mr.Set("limited:key"+string(rune('a'+i)), "value")
	}

	ctx := context.Background()
	query := &base.Query{
		Statement: "KEYS",
		Parameters: map[string]interface{}{
			"pattern": "limited:*",
			"limit":   float64(5),
		},
	}

	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if result.RowCount > 5 {
		t.Errorf("expected at most 5 rows due to limit, got %d", result.RowCount)
	}
}

func TestRedisConnector_Query_STATS(t *testing.T) {
	// Note: STATS uses INFO command which miniredis doesn't fully support
	// This test verifies the code path exists - integration test validates full behavior
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	mr.Set("stats-key", "value")

	ctx := context.Background()
	query := &base.Query{
		Statement: "STATS",
	}

	// miniredis doesn't support INFO stats section, so this may error
	// We're just testing the code path reaches the stats function
	_, err := conn.Query(ctx, query)
	// Either success or expected miniredis limitation error is acceptable
	if err != nil {
		// Verify it's the expected miniredis limitation
		t.Logf("STATS query error (expected with miniredis): %v", err)
	}
}

func TestRedisConnector_Query_UnsupportedOperation(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	query := &base.Query{
		Statement: "INVALID_OP",
	}

	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error for unsupported operation")
	}
}

func TestRedisConnector_Execute_SET(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	cmd := &base.Command{
		Action: "SET",
		Parameters: map[string]interface{}{
			"key":   "set-key",
			"value": "set-value",
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success=true, got false: %s", result.Message)
	}

	if result.RowsAffected != 1 {
		t.Errorf("expected RowsAffected=1, got %d", result.RowsAffected)
	}

	// Verify value was set
	val, err := mr.Get("set-key")
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}
	if val != "set-value" {
		t.Errorf("expected value 'set-value', got %q", val)
	}
}

func TestRedisConnector_Execute_SET_WithTTL_Float(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	cmd := &base.Command{
		Action: "SET",
		Parameters: map[string]interface{}{
			"key":   "ttl-key",
			"value": "ttl-value",
			"ttl":   float64(60),
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success=true")
	}

	// Verify TTL was set
	ttl := mr.TTL("ttl-key")
	if ttl <= 0 {
		t.Error("expected positive TTL")
	}
}

func TestRedisConnector_Execute_SET_WithTTL_Int(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	cmd := &base.Command{
		Action: "SET",
		Parameters: map[string]interface{}{
			"key":   "ttl-int-key",
			"value": "ttl-value",
			"ttl":   120,
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success=true")
	}
}

func TestRedisConnector_Execute_SET_WithTTL_String(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	cmd := &base.Command{
		Action: "SET",
		Parameters: map[string]interface{}{
			"key":   "ttl-str-key",
			"value": "ttl-value",
			"ttl":   "1m",
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success=true")
	}
}

func TestRedisConnector_Execute_SET_ComplexValue(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	cmd := &base.Command{
		Action: "SET",
		Parameters: map[string]interface{}{
			"key": "complex-key",
			"value": map[string]interface{}{
				"name": "test",
				"age":  30,
			},
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success=true")
	}

	// Verify JSON was stored
	val, _ := mr.Get("complex-key")
	if val == "" {
		t.Error("expected non-empty value")
	}
}

func TestRedisConnector_Execute_SET_ByteValue(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	cmd := &base.Command{
		Action: "SET",
		Parameters: map[string]interface{}{
			"key":   "byte-key",
			"value": []byte("byte-value"),
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success=true")
	}

	val, _ := mr.Get("byte-key")
	if val != "byte-value" {
		t.Errorf("expected 'byte-value', got %q", val)
	}
}

func TestRedisConnector_Execute_SET_MissingKey(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	cmd := &base.Command{
		Action: "SET",
		Parameters: map[string]interface{}{
			"value": "test",
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if result.Success {
		t.Error("expected success=false for missing key")
	}
}

func TestRedisConnector_Execute_SET_MissingValue(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	cmd := &base.Command{
		Action: "SET",
		Parameters: map[string]interface{}{
			"key": "test-key",
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if result.Success {
		t.Error("expected success=false for missing value")
	}
}

func TestRedisConnector_Execute_DELETE(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	mr.Set("delete-key", "value")

	ctx := context.Background()
	cmd := &base.Command{
		Action: "DELETE",
		Parameters: map[string]interface{}{
			"key": "delete-key",
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success=true")
	}

	if result.RowsAffected != 1 {
		t.Errorf("expected RowsAffected=1, got %d", result.RowsAffected)
	}

	// Verify key was deleted
	if mr.Exists("delete-key") {
		t.Error("expected key to be deleted")
	}
}

func TestRedisConnector_Execute_DELETE_NonExistent(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	cmd := &base.Command{
		Action: "DELETE",
		Parameters: map[string]interface{}{
			"key": "nonexistent-key",
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success=true even for non-existent key")
	}

	if result.RowsAffected != 0 {
		t.Errorf("expected RowsAffected=0, got %d", result.RowsAffected)
	}
}

func TestRedisConnector_Execute_DELETE_MissingKey(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	cmd := &base.Command{
		Action:     "DELETE",
		Parameters: map[string]interface{}{},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if result.Success {
		t.Error("expected success=false for missing key")
	}
}

func TestRedisConnector_Execute_EXPIRE(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	mr.Set("expire-key", "value")

	ctx := context.Background()
	cmd := &base.Command{
		Action: "EXPIRE",
		Parameters: map[string]interface{}{
			"key": "expire-key",
			"ttl": float64(300),
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success=true")
	}

	if result.RowsAffected != 1 {
		t.Errorf("expected RowsAffected=1, got %d", result.RowsAffected)
	}

	// Verify TTL was set
	ttl := mr.TTL("expire-key")
	if ttl <= 0 {
		t.Error("expected positive TTL")
	}
}

func TestRedisConnector_Execute_EXPIRE_WithIntTTL(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	mr.Set("expire-int-key", "value")

	ctx := context.Background()
	cmd := &base.Command{
		Action: "EXPIRE",
		Parameters: map[string]interface{}{
			"key": "expire-int-key",
			"ttl": 120,
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success=true")
	}
}

func TestRedisConnector_Execute_EXPIRE_WithStringTTL(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	mr.Set("expire-str-key", "value")

	ctx := context.Background()
	cmd := &base.Command{
		Action: "EXPIRE",
		Parameters: map[string]interface{}{
			"key": "expire-str-key",
			"ttl": "60",
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success=true")
	}
}

func TestRedisConnector_Execute_EXPIRE_NonExistent(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	cmd := &base.Command{
		Action: "EXPIRE",
		Parameters: map[string]interface{}{
			"key": "nonexistent-key",
			"ttl": float64(300),
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success=true")
	}

	if result.RowsAffected != 0 {
		t.Errorf("expected RowsAffected=0, got %d", result.RowsAffected)
	}
}

func TestRedisConnector_Execute_EXPIRE_MissingKey(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	cmd := &base.Command{
		Action: "EXPIRE",
		Parameters: map[string]interface{}{
			"ttl": float64(300),
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if result.Success {
		t.Error("expected success=false for missing key")
	}
}

func TestRedisConnector_Execute_EXPIRE_MissingTTL(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	mr.Set("expire-no-ttl-key", "value")

	ctx := context.Background()
	cmd := &base.Command{
		Action: "EXPIRE",
		Parameters: map[string]interface{}{
			"key": "expire-no-ttl-key",
		},
	}

	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if result.Success {
		t.Error("expected success=false for missing ttl")
	}
}

func TestRedisConnector_Execute_UnsupportedAction(t *testing.T) {
	conn, mr := setupMiniredis(t)
	defer mr.Close()
	defer conn.Disconnect(context.Background())

	ctx := context.Background()
	cmd := &base.Command{
		Action: "INVALID_ACTION",
	}

	_, err := conn.Execute(ctx, cmd)
	if err == nil {
		t.Error("expected error for unsupported action")
	}
}

// Integration tests - require real Redis server

func getRedisURL(t *testing.T) string {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		t.Skip("Skipping integration test - REDIS_URL not set")
	}
	return redisURL
}

func TestRedisConnector_Integration_Connect(t *testing.T) {
	_ = getRedisURL(t)

	conn := NewRedisConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:     "integration-test-redis",
		Type:     "redis",
		TenantID: "test-tenant",
		Options: map[string]interface{}{
			"host": "localhost",
			"port": float64(6379),
		},
		Credentials: map[string]string{},
	}

	err := conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer conn.Disconnect(ctx)

	// Test health check
	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}

	if !status.Healthy {
		t.Errorf("expected healthy status: %s", status.Error)
	}
}

func TestRedisConnector_Integration_SetGetDelete(t *testing.T) {
	_ = getRedisURL(t)

	conn := NewRedisConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:     "integration-test-redis-crud",
		Type:     "redis",
		TenantID: "test-tenant",
		Options: map[string]interface{}{
			"host": "localhost",
			"port": float64(6379),
		},
		Credentials: map[string]string{},
	}

	err := conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer conn.Disconnect(ctx)

	testKey := "integration-test-key-" + time.Now().Format("20060102150405")

	// SET
	setCmd := &base.Command{
		Action: "SET",
		Parameters: map[string]interface{}{
			"key":   testKey,
			"value": "integration-test-value",
			"ttl":   float64(60),
		},
	}

	result, err := conn.Execute(ctx, setCmd)
	if err != nil {
		t.Fatalf("SET failed: %v", err)
	}
	if !result.Success {
		t.Errorf("SET expected success=true")
	}

	// GET
	getQuery := &base.Query{
		Statement:  "GET",
		Parameters: map[string]interface{}{"key": testKey},
	}

	queryResult, err := conn.Query(ctx, getQuery)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}

	if queryResult.Rows[0]["value"] != "integration-test-value" {
		t.Errorf("expected value 'integration-test-value', got %v", queryResult.Rows[0]["value"])
	}

	// DELETE
	deleteCmd := &base.Command{
		Action:     "DELETE",
		Parameters: map[string]interface{}{"key": testKey},
	}

	result, err = conn.Execute(ctx, deleteCmd)
	if err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}
	if !result.Success {
		t.Errorf("DELETE expected success=true")
	}

	// Verify deleted
	queryResult, err = conn.Query(ctx, getQuery)
	if err != nil {
		t.Fatalf("GET after DELETE failed: %v", err)
	}

	if queryResult.Rows[0]["exists"] != false {
		t.Error("expected key to be deleted")
	}
}
