// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
)

// ExfiltrationChecker validates MCP responses against data extraction limits.
// It prevents large-scale data exfiltration through row count and data volume limits.
//
// Thread Safety: All methods are safe for concurrent use.
//
// Usage:
//
//	checker := NewExfiltrationChecker(DefaultExfiltrationLimits())
//	result := checker.Check(ctx, rowCount, responseData)
//	if result.Exceeded {
//	    // Block the response
//	}
type ExfiltrationChecker struct {
	limits ExfiltrationLimits
	mu     sync.RWMutex
}

// NewExfiltrationChecker creates a new exfiltration checker with the given limits.
func NewExfiltrationChecker(limits ExfiltrationLimits) *ExfiltrationChecker {
	return &ExfiltrationChecker{
		limits: limits,
	}
}

// NewExfiltrationCheckerFromEnv creates an ExfiltrationChecker configured from environment variables.
//
// Environment variables:
//   - MCP_MAX_ROWS_PER_QUERY: Maximum rows per query (default: 10000)
//   - MCP_MAX_BYTES_PER_QUERY: Maximum bytes per response (default: 10485760)
//   - MCP_EXFILTRATION_ENABLED: Enable/disable checks (default: true)
func NewExfiltrationCheckerFromEnv() *ExfiltrationChecker {
	limits := DefaultExfiltrationLimits()

	// Parse MCP_MAX_ROWS_PER_QUERY
	if val := os.Getenv("MCP_MAX_ROWS_PER_QUERY"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil && parsed >= 0 {
			limits.MaxRowsPerQuery = parsed
		} else {
			log.Printf("[ExfiltrationChecker] Invalid MCP_MAX_ROWS_PER_QUERY value: %s, using default", val)
		}
	}

	// Parse MCP_MAX_BYTES_PER_QUERY
	if val := os.Getenv("MCP_MAX_BYTES_PER_QUERY"); val != "" {
		if parsed, err := strconv.ParseInt(val, 10, 64); err == nil && parsed >= 0 {
			limits.MaxBytesPerQuery = parsed
		} else {
			log.Printf("[ExfiltrationChecker] Invalid MCP_MAX_BYTES_PER_QUERY value: %s, using default", val)
		}
	}

	// Parse MCP_EXFILTRATION_ENABLED
	if val := os.Getenv("MCP_EXFILTRATION_ENABLED"); val != "" {
		limits.Enabled = val == "true" || val == "1" || val == "yes"
	}

	log.Printf("[ExfiltrationChecker] Initialized: enabled=%v, maxRows=%d, maxBytes=%d",
		limits.Enabled, limits.MaxRowsPerQuery, limits.MaxBytesPerQuery)

	return NewExfiltrationChecker(limits)
}

// Check validates row count and data size against configured limits.
// Returns an ExfiltrationResult indicating whether limits were exceeded.
//
// Parameters:
//   - ctx: Context for cancellation (currently unused, reserved for future metrics)
//   - rowCount: Number of rows in the response
//   - data: Response data for size calculation (can be nil for row-only checks)
//
// The data parameter is used to calculate approximate response size. It accepts:
//   - []map[string]interface{}: Database rows
//   - map[string]interface{}: Single JSON object
//   - string: Raw string data
//   - []byte: Raw byte data
func (c *ExfiltrationChecker) Check(ctx context.Context, rowCount int, data interface{}) *ExfiltrationResult {
	c.mu.RLock()
	limits := c.limits
	c.mu.RUnlock()

	// If disabled, always return success
	if !limits.Enabled {
		return &ExfiltrationResult{
			Exceeded: false,
		}
	}

	// Check row count limit
	if limits.MaxRowsPerQuery > 0 && rowCount > limits.MaxRowsPerQuery {
		return &ExfiltrationResult{
			Exceeded:    true,
			LimitType:   "rows",
			ActualValue: int64(rowCount),
			LimitValue:  int64(limits.MaxRowsPerQuery),
			BlockReason: fmt.Sprintf("Row count limit exceeded: %d rows returned, limit is %d",
				rowCount, limits.MaxRowsPerQuery),
		}
	}

	// Check data volume limit
	if limits.MaxBytesPerQuery > 0 && data != nil {
		dataSize := c.calculateDataSize(data)
		if dataSize > limits.MaxBytesPerQuery {
			return &ExfiltrationResult{
				Exceeded:    true,
				LimitType:   "bytes",
				ActualValue: dataSize,
				LimitValue:  limits.MaxBytesPerQuery,
				BlockReason: fmt.Sprintf("Data volume limit exceeded: %d bytes returned, limit is %d",
					dataSize, limits.MaxBytesPerQuery),
			}
		}
	}

	return &ExfiltrationResult{
		Exceeded: false,
	}
}

// CheckWithInfo performs an exfiltration check and returns detailed info for API responses.
// This method is used when you need both the check result and the info for PolicyInfo.
func (c *ExfiltrationChecker) CheckWithInfo(ctx context.Context, rowCount int, data interface{}) (*ExfiltrationResult, *ExfiltrationCheckInfo) {
	c.mu.RLock()
	limits := c.limits
	c.mu.RUnlock()

	// Calculate data size
	var dataSize int64
	if data != nil {
		dataSize = c.calculateDataSize(data)
	}

	// Build info structure (always, regardless of enabled state)
	info := &ExfiltrationCheckInfo{
		RowsReturned:  int64(rowCount),
		RowLimit:      limits.MaxRowsPerQuery,
		BytesReturned: dataSize,
		ByteLimit:     limits.MaxBytesPerQuery,
		WithinLimits:  true, // Will be updated if exceeded
	}

	// Perform the check
	result := c.Check(ctx, rowCount, data)

	// Update info based on result
	if result.Exceeded {
		info.WithinLimits = false
	}

	return result, info
}

// GetLimits returns the current exfiltration limits.
// Returns a copy to prevent external modification.
func (c *ExfiltrationChecker) GetLimits() ExfiltrationLimits {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.limits
}

// UpdateLimits updates the exfiltration limits.
// Thread-safe; takes effect immediately for subsequent checks.
func (c *ExfiltrationChecker) UpdateLimits(limits ExfiltrationLimits) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.limits = limits
	log.Printf("[ExfiltrationChecker] Limits updated: enabled=%v, maxRows=%d, maxBytes=%d",
		limits.Enabled, limits.MaxRowsPerQuery, limits.MaxBytesPerQuery)
}

// IsEnabled returns whether exfiltration checking is enabled.
func (c *ExfiltrationChecker) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.limits.Enabled
}

// calculateDataSize estimates the size of data in bytes.
// Uses JSON serialization for accurate size estimation.
func (c *ExfiltrationChecker) calculateDataSize(data interface{}) int64 {
	switch v := data.(type) {
	case []byte:
		return int64(len(v))
	case string:
		return int64(len(v))
	case []map[string]interface{}, map[string]interface{}:
		// JSON serialize for accurate size
		if jsonBytes, err := json.Marshal(v); err == nil {
			return int64(len(jsonBytes))
		}
		// Fallback: estimate based on structure
		return c.estimateStructureSize(v)
	default:
		// Try JSON serialization for unknown types
		if jsonBytes, err := json.Marshal(v); err == nil {
			return int64(len(jsonBytes))
		}
		return 0
	}
}

// estimateStructureSize provides a rough estimate without JSON serialization.
// Used as fallback when JSON marshaling fails.
func (c *ExfiltrationChecker) estimateStructureSize(data interface{}) int64 {
	var size int64

	switch v := data.(type) {
	case []map[string]interface{}:
		for _, row := range v {
			size += c.estimateMapSize(row)
		}
	case map[string]interface{}:
		size = c.estimateMapSize(v)
	}

	return size
}

// estimateMapSize estimates the size of a map in bytes.
func (c *ExfiltrationChecker) estimateMapSize(m map[string]interface{}) int64 {
	var size int64
	for k, v := range m {
		size += int64(len(k)) // Key size
		size += 4             // Overhead for key-value structure

		switch val := v.(type) {
		case string:
			size += int64(len(val))
		case []byte:
			size += int64(len(val))
		case int, int32, int64, float32, float64:
			size += 8
		case bool:
			size += 1
		case nil:
			size += 4
		case map[string]interface{}:
			size += c.estimateMapSize(val)
		case []interface{}:
			for _, item := range val {
				if m, ok := item.(map[string]interface{}); ok {
					size += c.estimateMapSize(m)
				} else {
					size += 16 // Generic estimate
				}
			}
		default:
			size += 16 // Generic estimate
		}
	}
	return size
}

// =============================================================================
// Global ExfiltrationChecker Instance (Singleton Pattern)
// =============================================================================

var (
	globalExfiltrationChecker   *ExfiltrationChecker
	globalExfiltrationCheckerMu sync.RWMutex
)

// InitGlobalExfiltrationChecker initializes the global exfiltration checker.
// This should be called once during application startup.
// If not called, GetGlobalExfiltrationChecker returns nil (exfiltration checks disabled).
func InitGlobalExfiltrationChecker() {
	globalExfiltrationCheckerMu.Lock()
	defer globalExfiltrationCheckerMu.Unlock()

	if globalExfiltrationChecker == nil {
		globalExfiltrationChecker = NewExfiltrationCheckerFromEnv()
	}
}

// InitGlobalExfiltrationCheckerWithLimits initializes with specific limits (for testing).
func InitGlobalExfiltrationCheckerWithLimits(limits ExfiltrationLimits) {
	globalExfiltrationCheckerMu.Lock()
	defer globalExfiltrationCheckerMu.Unlock()

	globalExfiltrationChecker = NewExfiltrationChecker(limits)
}

// GetGlobalExfiltrationChecker returns the global exfiltration checker.
// Returns nil if not initialized (exfiltration checks are skipped).
func GetGlobalExfiltrationChecker() *ExfiltrationChecker {
	globalExfiltrationCheckerMu.RLock()
	defer globalExfiltrationCheckerMu.RUnlock()
	return globalExfiltrationChecker
}

// SetGlobalExfiltrationChecker sets the global exfiltration checker (for testing).
func SetGlobalExfiltrationChecker(checker *ExfiltrationChecker) {
	globalExfiltrationCheckerMu.Lock()
	defer globalExfiltrationCheckerMu.Unlock()
	globalExfiltrationChecker = checker
}

// ResetGlobalExfiltrationChecker resets the global checker (for testing).
func ResetGlobalExfiltrationChecker() {
	globalExfiltrationCheckerMu.Lock()
	defer globalExfiltrationCheckerMu.Unlock()
	globalExfiltrationChecker = nil
}
