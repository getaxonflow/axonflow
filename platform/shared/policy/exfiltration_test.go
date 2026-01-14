// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"os"
	"testing"
)

func TestDefaultExfiltrationLimits(t *testing.T) {
	limits := DefaultExfiltrationLimits()

	if limits.MaxRowsPerQuery != 10000 {
		t.Errorf("expected MaxRowsPerQuery=10000, got %d", limits.MaxRowsPerQuery)
	}
	if limits.MaxBytesPerQuery != 10*1024*1024 {
		t.Errorf("expected MaxBytesPerQuery=10MB, got %d", limits.MaxBytesPerQuery)
	}
	if !limits.Enabled {
		t.Error("expected Enabled=true by default")
	}
}

func TestNewExfiltrationChecker(t *testing.T) {
	limits := ExfiltrationLimits{
		MaxRowsPerQuery:  5000,
		MaxBytesPerQuery: 5 * 1024 * 1024,
		Enabled:          true,
	}

	checker := NewExfiltrationChecker(limits)
	if checker == nil {
		t.Fatal("expected non-nil checker")
	}

	got := checker.GetLimits()
	if got.MaxRowsPerQuery != 5000 {
		t.Errorf("expected MaxRowsPerQuery=5000, got %d", got.MaxRowsPerQuery)
	}
	if got.MaxBytesPerQuery != 5*1024*1024 {
		t.Errorf("expected MaxBytesPerQuery=5MB, got %d", got.MaxBytesPerQuery)
	}
}

func TestExfiltrationChecker_RowLimitExceeded(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  100,
		MaxBytesPerQuery: 10 * 1024 * 1024,
		Enabled:          true,
	})

	ctx := context.Background()
	result := checker.Check(ctx, 150, nil) // 150 rows, limit is 100

	if !result.Exceeded {
		t.Error("expected Exceeded=true for row limit violation")
	}
	if result.LimitType != "rows" {
		t.Errorf("expected LimitType=rows, got %s", result.LimitType)
	}
	if result.ActualValue != 150 {
		t.Errorf("expected ActualValue=150, got %d", result.ActualValue)
	}
	if result.LimitValue != 100 {
		t.Errorf("expected LimitValue=100, got %d", result.LimitValue)
	}
	if result.BlockReason == "" {
		t.Error("expected non-empty BlockReason")
	}
}

func TestExfiltrationChecker_RowLimitNotExceeded(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  100,
		MaxBytesPerQuery: 10 * 1024 * 1024,
		Enabled:          true,
	})

	ctx := context.Background()
	result := checker.Check(ctx, 50, nil) // 50 rows, limit is 100

	if result.Exceeded {
		t.Error("expected Exceeded=false when under row limit")
	}
	if result.LimitType != "" {
		t.Errorf("expected empty LimitType, got %s", result.LimitType)
	}
}

func TestExfiltrationChecker_RowLimitExactlyAtLimit(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  100,
		MaxBytesPerQuery: 0, // Disabled
		Enabled:          true,
	})

	ctx := context.Background()
	result := checker.Check(ctx, 100, nil) // Exactly at limit

	if result.Exceeded {
		t.Error("expected Exceeded=false when exactly at row limit")
	}
}

func TestExfiltrationChecker_ByteLimitExceeded(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  0,    // Disabled
		MaxBytesPerQuery: 1000, // 1KB limit
		Enabled:          true,
	})

	// Create data that exceeds 1KB
	largeData := []map[string]interface{}{
		{"data": string(make([]byte, 2000))}, // 2KB string
	}

	ctx := context.Background()
	result := checker.Check(ctx, 1, largeData)

	if !result.Exceeded {
		t.Error("expected Exceeded=true for byte limit violation")
	}
	if result.LimitType != "bytes" {
		t.Errorf("expected LimitType=bytes, got %s", result.LimitType)
	}
	if result.ActualValue <= 1000 {
		t.Errorf("expected ActualValue>1000, got %d", result.ActualValue)
	}
	if result.LimitValue != 1000 {
		t.Errorf("expected LimitValue=1000, got %d", result.LimitValue)
	}
}

func TestExfiltrationChecker_ByteLimitNotExceeded(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  0,      // Disabled
		MaxBytesPerQuery: 100000, // 100KB limit
		Enabled:          true,
	})

	// Create small data
	smallData := []map[string]interface{}{
		{"name": "test", "value": 123},
	}

	ctx := context.Background()
	result := checker.Check(ctx, 1, smallData)

	if result.Exceeded {
		t.Error("expected Exceeded=false when under byte limit")
	}
}

func TestExfiltrationChecker_BothLimitsRowFirst(t *testing.T) {
	// When both limits could be exceeded, row limit is checked first
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  10,
		MaxBytesPerQuery: 100, // Very small
		Enabled:          true,
	})

	// Data that exceeds both limits
	largeData := []map[string]interface{}{
		{"data": string(make([]byte, 200))},
	}

	ctx := context.Background()
	result := checker.Check(ctx, 100, largeData) // 100 rows, limit is 10

	if !result.Exceeded {
		t.Error("expected Exceeded=true")
	}
	// Row limit should be checked first
	if result.LimitType != "rows" {
		t.Errorf("expected LimitType=rows (checked first), got %s", result.LimitType)
	}
}

func TestExfiltrationChecker_Disabled(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  10,
		MaxBytesPerQuery: 100,
		Enabled:          false, // Disabled
	})

	// Create data that would exceed both limits if enabled
	largeData := []map[string]interface{}{
		{"data": string(make([]byte, 200))},
	}

	ctx := context.Background()
	result := checker.Check(ctx, 100, largeData)

	if result.Exceeded {
		t.Error("expected Exceeded=false when checker is disabled")
	}
}

func TestExfiltrationChecker_ZeroRowLimit(t *testing.T) {
	// Zero means unlimited
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  0, // Unlimited
		MaxBytesPerQuery: 10 * 1024 * 1024,
		Enabled:          true,
	})

	ctx := context.Background()
	result := checker.Check(ctx, 1000000, nil) // 1 million rows

	if result.Exceeded {
		t.Error("expected Exceeded=false when row limit is 0 (unlimited)")
	}
}

func TestExfiltrationChecker_ZeroByteLimit(t *testing.T) {
	// Zero means unlimited
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  10000,
		MaxBytesPerQuery: 0, // Unlimited
		Enabled:          true,
	})

	largeData := []map[string]interface{}{
		{"data": string(make([]byte, 100*1024*1024))}, // 100MB
	}

	ctx := context.Background()
	result := checker.Check(ctx, 1, largeData)

	if result.Exceeded {
		t.Error("expected Exceeded=false when byte limit is 0 (unlimited)")
	}
}

func TestExfiltrationChecker_EmptyData(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  100,
		MaxBytesPerQuery: 1000,
		Enabled:          true,
	})

	ctx := context.Background()

	// Test with nil data
	result := checker.Check(ctx, 0, nil)
	if result.Exceeded {
		t.Error("expected Exceeded=false for empty data with nil")
	}

	// Test with empty slice
	result = checker.Check(ctx, 0, []map[string]interface{}{})
	if result.Exceeded {
		t.Error("expected Exceeded=false for empty slice")
	}
}

func TestExfiltrationChecker_ZeroRows(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  100,
		MaxBytesPerQuery: 1000,
		Enabled:          true,
	})

	ctx := context.Background()
	result := checker.Check(ctx, 0, nil)

	if result.Exceeded {
		t.Error("expected Exceeded=false for zero rows")
	}
}

func TestExfiltrationChecker_CheckWithInfo(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  100,
		MaxBytesPerQuery: 10000,
		Enabled:          true,
	})

	data := []map[string]interface{}{
		{"id": 1, "name": "test"},
	}

	ctx := context.Background()
	result, info := checker.CheckWithInfo(ctx, 50, data)

	// Check result
	if result.Exceeded {
		t.Error("expected Exceeded=false")
	}

	// Check info
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if info.RowsReturned != 50 {
		t.Errorf("expected RowsReturned=50, got %d", info.RowsReturned)
	}
	if info.RowLimit != 100 {
		t.Errorf("expected RowLimit=100, got %d", info.RowLimit)
	}
	if info.ByteLimit != 10000 {
		t.Errorf("expected ByteLimit=10000, got %d", info.ByteLimit)
	}
	if !info.WithinLimits {
		t.Error("expected WithinLimits=true")
	}
	if info.BytesReturned == 0 {
		t.Error("expected BytesReturned > 0")
	}
}

func TestExfiltrationChecker_CheckWithInfo_Exceeded(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  10,
		MaxBytesPerQuery: 10000,
		Enabled:          true,
	})

	ctx := context.Background()
	result, info := checker.CheckWithInfo(ctx, 100, nil)

	if !result.Exceeded {
		t.Error("expected Exceeded=true")
	}
	if info.WithinLimits {
		t.Error("expected WithinLimits=false")
	}
}

func TestExfiltrationChecker_UpdateLimits(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  100,
		MaxBytesPerQuery: 1000,
		Enabled:          true,
	})

	// Update limits
	checker.UpdateLimits(ExfiltrationLimits{
		MaxRowsPerQuery:  200,
		MaxBytesPerQuery: 2000,
		Enabled:          false,
	})

	limits := checker.GetLimits()
	if limits.MaxRowsPerQuery != 200 {
		t.Errorf("expected MaxRowsPerQuery=200, got %d", limits.MaxRowsPerQuery)
	}
	if limits.MaxBytesPerQuery != 2000 {
		t.Errorf("expected MaxBytesPerQuery=2000, got %d", limits.MaxBytesPerQuery)
	}
	if limits.Enabled {
		t.Error("expected Enabled=false")
	}
}

func TestExfiltrationChecker_IsEnabled(t *testing.T) {
	checkerEnabled := NewExfiltrationChecker(ExfiltrationLimits{
		Enabled: true,
	})
	if !checkerEnabled.IsEnabled() {
		t.Error("expected IsEnabled=true")
	}

	checkerDisabled := NewExfiltrationChecker(ExfiltrationLimits{
		Enabled: false,
	})
	if checkerDisabled.IsEnabled() {
		t.Error("expected IsEnabled=false")
	}
}

func TestExfiltrationChecker_DataSizeCalculation_String(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  0,
		MaxBytesPerQuery: 100,
		Enabled:          true,
	})

	ctx := context.Background()

	// Test with string data
	stringData := string(make([]byte, 200))
	result := checker.Check(ctx, 0, stringData)

	if !result.Exceeded {
		t.Error("expected Exceeded=true for string exceeding byte limit")
	}
	if result.LimitType != "bytes" {
		t.Errorf("expected LimitType=bytes, got %s", result.LimitType)
	}
}

func TestExfiltrationChecker_DataSizeCalculation_Bytes(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  0,
		MaxBytesPerQuery: 100,
		Enabled:          true,
	})

	ctx := context.Background()

	// Test with byte slice
	byteData := make([]byte, 200)
	result := checker.Check(ctx, 0, byteData)

	if !result.Exceeded {
		t.Error("expected Exceeded=true for bytes exceeding byte limit")
	}
}

func TestExfiltrationChecker_DataSizeCalculation_Map(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  0,
		MaxBytesPerQuery: 50,
		Enabled:          true,
	})

	ctx := context.Background()

	// Test with single map
	mapData := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
		"key3": string(make([]byte, 100)),
	}
	result := checker.Check(ctx, 0, mapData)

	if !result.Exceeded {
		t.Error("expected Exceeded=true for map exceeding byte limit")
	}
}

func TestNewExfiltrationCheckerFromEnv(t *testing.T) {
	// Save original env vars
	origRows := os.Getenv("MCP_MAX_ROWS_PER_QUERY")
	origBytes := os.Getenv("MCP_MAX_BYTES_PER_QUERY")
	origEnabled := os.Getenv("MCP_EXFILTRATION_ENABLED")

	// Cleanup after test
	defer func() {
		if origRows != "" {
			os.Setenv("MCP_MAX_ROWS_PER_QUERY", origRows)
		} else {
			os.Unsetenv("MCP_MAX_ROWS_PER_QUERY")
		}
		if origBytes != "" {
			os.Setenv("MCP_MAX_BYTES_PER_QUERY", origBytes)
		} else {
			os.Unsetenv("MCP_MAX_BYTES_PER_QUERY")
		}
		if origEnabled != "" {
			os.Setenv("MCP_EXFILTRATION_ENABLED", origEnabled)
		} else {
			os.Unsetenv("MCP_EXFILTRATION_ENABLED")
		}
	}()

	// Test with custom env vars
	os.Setenv("MCP_MAX_ROWS_PER_QUERY", "5000")
	os.Setenv("MCP_MAX_BYTES_PER_QUERY", "5242880")
	os.Setenv("MCP_EXFILTRATION_ENABLED", "true")

	checker := NewExfiltrationCheckerFromEnv()
	limits := checker.GetLimits()

	if limits.MaxRowsPerQuery != 5000 {
		t.Errorf("expected MaxRowsPerQuery=5000, got %d", limits.MaxRowsPerQuery)
	}
	if limits.MaxBytesPerQuery != 5242880 {
		t.Errorf("expected MaxBytesPerQuery=5242880, got %d", limits.MaxBytesPerQuery)
	}
	if !limits.Enabled {
		t.Error("expected Enabled=true")
	}
}

func TestNewExfiltrationCheckerFromEnv_Disabled(t *testing.T) {
	// Save and restore
	origEnabled := os.Getenv("MCP_EXFILTRATION_ENABLED")
	defer func() {
		if origEnabled != "" {
			os.Setenv("MCP_EXFILTRATION_ENABLED", origEnabled)
		} else {
			os.Unsetenv("MCP_EXFILTRATION_ENABLED")
		}
	}()

	os.Setenv("MCP_EXFILTRATION_ENABLED", "false")

	checker := NewExfiltrationCheckerFromEnv()
	if checker.IsEnabled() {
		t.Error("expected checker to be disabled")
	}
}

func TestNewExfiltrationCheckerFromEnv_InvalidValues(t *testing.T) {
	// Save and restore
	origRows := os.Getenv("MCP_MAX_ROWS_PER_QUERY")
	origBytes := os.Getenv("MCP_MAX_BYTES_PER_QUERY")
	defer func() {
		if origRows != "" {
			os.Setenv("MCP_MAX_ROWS_PER_QUERY", origRows)
		} else {
			os.Unsetenv("MCP_MAX_ROWS_PER_QUERY")
		}
		if origBytes != "" {
			os.Setenv("MCP_MAX_BYTES_PER_QUERY", origBytes)
		} else {
			os.Unsetenv("MCP_MAX_BYTES_PER_QUERY")
		}
	}()

	// Set invalid values - should use defaults
	os.Setenv("MCP_MAX_ROWS_PER_QUERY", "not-a-number")
	os.Setenv("MCP_MAX_BYTES_PER_QUERY", "invalid")

	checker := NewExfiltrationCheckerFromEnv()
	limits := checker.GetLimits()

	// Should use defaults
	if limits.MaxRowsPerQuery != 10000 {
		t.Errorf("expected default MaxRowsPerQuery=10000, got %d", limits.MaxRowsPerQuery)
	}
	if limits.MaxBytesPerQuery != 10*1024*1024 {
		t.Errorf("expected default MaxBytesPerQuery, got %d", limits.MaxBytesPerQuery)
	}
}

func TestGlobalExfiltrationChecker(t *testing.T) {
	// Reset global state
	ResetGlobalExfiltrationChecker()

	// Should be nil initially
	if GetGlobalExfiltrationChecker() != nil {
		t.Error("expected nil before initialization")
	}

	// Initialize with specific limits
	limits := ExfiltrationLimits{
		MaxRowsPerQuery:  500,
		MaxBytesPerQuery: 5000,
		Enabled:          true,
	}
	InitGlobalExfiltrationCheckerWithLimits(limits)

	checker := GetGlobalExfiltrationChecker()
	if checker == nil {
		t.Fatal("expected non-nil checker after initialization")
	}

	got := checker.GetLimits()
	if got.MaxRowsPerQuery != 500 {
		t.Errorf("expected MaxRowsPerQuery=500, got %d", got.MaxRowsPerQuery)
	}

	// Test SetGlobalExfiltrationChecker
	newChecker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery: 999,
	})
	SetGlobalExfiltrationChecker(newChecker)

	if GetGlobalExfiltrationChecker().GetLimits().MaxRowsPerQuery != 999 {
		t.Error("expected SetGlobalExfiltrationChecker to work")
	}

	// Cleanup
	ResetGlobalExfiltrationChecker()
}

func TestExfiltrationChecker_ConcurrentAccess(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  100,
		MaxBytesPerQuery: 10000,
		Enabled:          true,
	})

	ctx := context.Background()
	done := make(chan bool)

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = checker.Check(ctx, 50, nil)
				_ = checker.GetLimits()
				_ = checker.IsEnabled()
			}
			done <- true
		}()
	}

	// Concurrent writes
	for i := 0; i < 5; i++ {
		go func(n int) {
			for j := 0; j < 20; j++ {
				checker.UpdateLimits(ExfiltrationLimits{
					MaxRowsPerQuery: n * 100,
					Enabled:         true,
				})
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 15; i++ {
		<-done
	}

	// Should not panic or deadlock
}

func TestInitGlobalExfiltrationChecker(t *testing.T) {
	// Save and restore
	origRows := os.Getenv("MCP_MAX_ROWS_PER_QUERY")
	origBytes := os.Getenv("MCP_MAX_BYTES_PER_QUERY")
	origEnabled := os.Getenv("MCP_EXFILTRATION_ENABLED")
	defer func() {
		if origRows != "" {
			os.Setenv("MCP_MAX_ROWS_PER_QUERY", origRows)
		} else {
			os.Unsetenv("MCP_MAX_ROWS_PER_QUERY")
		}
		if origBytes != "" {
			os.Setenv("MCP_MAX_BYTES_PER_QUERY", origBytes)
		} else {
			os.Unsetenv("MCP_MAX_BYTES_PER_QUERY")
		}
		if origEnabled != "" {
			os.Setenv("MCP_EXFILTRATION_ENABLED", origEnabled)
		} else {
			os.Unsetenv("MCP_EXFILTRATION_ENABLED")
		}
		ResetGlobalExfiltrationChecker()
	}()

	// Reset first
	ResetGlobalExfiltrationChecker()

	// Set env vars
	os.Setenv("MCP_MAX_ROWS_PER_QUERY", "7500")
	os.Setenv("MCP_EXFILTRATION_ENABLED", "true")

	// Initialize
	InitGlobalExfiltrationChecker()

	checker := GetGlobalExfiltrationChecker()
	if checker == nil {
		t.Fatal("expected non-nil checker")
	}

	limits := checker.GetLimits()
	if limits.MaxRowsPerQuery != 7500 {
		t.Errorf("expected MaxRowsPerQuery=7500 from env, got %d", limits.MaxRowsPerQuery)
	}

	// Call again - should be idempotent
	InitGlobalExfiltrationChecker()
	checker2 := GetGlobalExfiltrationChecker()
	if checker2 != checker {
		t.Error("expected same checker instance on repeated init")
	}
}

func TestExfiltrationChecker_DataSizeCalculation_NestedMap(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  0,
		MaxBytesPerQuery: 100,
		Enabled:          true,
	})

	ctx := context.Background()

	// Test with nested map structure
	nestedData := map[string]interface{}{
		"outer": map[string]interface{}{
			"inner": map[string]interface{}{
				"deep": string(make([]byte, 200)),
			},
		},
	}
	result := checker.Check(ctx, 0, nestedData)

	if !result.Exceeded {
		t.Error("expected Exceeded=true for nested map exceeding byte limit")
	}
}

func TestExfiltrationChecker_DataSizeCalculation_RowsWithMaps(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  0,
		MaxBytesPerQuery: 50,
		Enabled:          true,
	})

	ctx := context.Background()

	// Test with rows containing nested structures
	rowData := []map[string]interface{}{
		{
			"id":   1,
			"meta": map[string]interface{}{"key": string(make([]byte, 100))},
		},
	}
	result := checker.Check(ctx, 1, rowData)

	if !result.Exceeded {
		t.Error("expected Exceeded=true for rows with nested maps exceeding byte limit")
	}
}

func TestExfiltrationChecker_DataSizeCalculation_ArrayInMap(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  0,
		MaxBytesPerQuery: 50,
		Enabled:          true,
	})

	ctx := context.Background()

	// Test with array inside map
	data := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{"data": string(make([]byte, 100))},
		},
	}
	result := checker.Check(ctx, 0, data)

	if !result.Exceeded {
		t.Error("expected Exceeded=true for array in map exceeding byte limit")
	}
}

func TestExfiltrationChecker_DataSizeCalculation_VariousTypes(t *testing.T) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  0,
		MaxBytesPerQuery: 1000000, // Large enough
		Enabled:          true,
	})

	ctx := context.Background()

	// Test with various value types
	data := map[string]interface{}{
		"int":     42,
		"int32":   int32(42),
		"int64":   int64(42),
		"float32": float32(3.14),
		"float64": float64(3.14159),
		"bool":    true,
		"nil":     nil,
		"string":  "hello",
		"bytes":   []byte("world"),
	}

	result, info := checker.CheckWithInfo(ctx, 0, data)

	if result.Exceeded {
		t.Error("expected Exceeded=false for small mixed-type data")
	}
	if info.BytesReturned == 0 {
		t.Error("expected BytesReturned > 0")
	}
}

// Benchmark tests for performance validation
func BenchmarkExfiltrationChecker_Check(b *testing.B) {
	checker := NewExfiltrationChecker(DefaultExfiltrationLimits())
	ctx := context.Background()
	data := []map[string]interface{}{
		{"id": 1, "name": "test", "email": "test@example.com"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.Check(ctx, 100, data)
	}
}

func BenchmarkExfiltrationChecker_CheckWithInfo(b *testing.B) {
	checker := NewExfiltrationChecker(DefaultExfiltrationLimits())
	ctx := context.Background()
	data := []map[string]interface{}{
		{"id": 1, "name": "test", "email": "test@example.com"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.CheckWithInfo(ctx, 100, data)
	}
}

func BenchmarkExfiltrationChecker_DataSizeCalculation_LargeData(b *testing.B) {
	checker := NewExfiltrationChecker(ExfiltrationLimits{
		MaxRowsPerQuery:  0,
		MaxBytesPerQuery: 100 * 1024 * 1024, // 100MB
		Enabled:          true,
	})
	ctx := context.Background()

	// Create larger dataset
	data := make([]map[string]interface{}, 1000)
	for i := 0; i < 1000; i++ {
		data[i] = map[string]interface{}{
			"id":      i,
			"name":    "test user name",
			"email":   "test@example.com",
			"address": "123 Test Street, Test City, TC 12345",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.Check(ctx, 1000, data)
	}
}
