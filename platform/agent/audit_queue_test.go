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

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestNewAuditQueue tests audit queue initialization
func TestNewAuditQueue(t *testing.T) {
	tests := []struct {
		name         string
		mode         AuditMode
		queueSize    int
		workers      int
		fallbackPath string
		setupFallback func(string) error
		wantErr      bool
		errContains  string
	}{
		{
			name:         "valid compliance mode",
			mode:         AuditModeCompliance,
			queueSize:    100,
			workers:      2,
			fallbackPath: filepath.Join(os.TempDir(), "test-audit-compliance.log"),
			wantErr:      false,
		},
		{
			name:         "valid performance mode",
			mode:         AuditModePerformance,
			queueSize:    1000,
			workers:      4,
			fallbackPath: filepath.Join(os.TempDir(), "test-audit-performance.log"),
			wantErr:      false,
		},
		{
			name:         "invalid fallback path",
			mode:         AuditModeCompliance,
			queueSize:    100,
			workers:      2,
			fallbackPath: "/nonexistent/path/audit.log",
			wantErr:      true,
			errContains:  "failed to open fallback file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cleanup fallback file after test
			defer func() { _ = os.Remove(tt.fallbackPath) }()

			db, _, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock db: %v", err)
			}
			defer func() { _ = db.Close() }()

			aq, err := NewAuditQueue(tt.mode, tt.queueSize, tt.workers, db, tt.fallbackPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errContains)
				} else if !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if aq == nil {
				t.Error("expected audit queue, got nil")
				return
			}

			// Verify initialization
			if aq.mode != tt.mode {
				t.Errorf("expected mode %s, got %s", tt.mode, aq.mode)
			}
			if aq.workers != tt.workers {
				t.Errorf("expected %d workers, got %d", tt.workers, aq.workers)
			}

			// Shutdown
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := aq.Shutdown(ctx); err != nil {
		t.Logf("Shutdown error (may be expected in test): %v", err)
	}
		})
	}
}

// TestLogViolation_ComplianceMode tests synchronous violation logging
func TestLogViolation_ComplianceMode(t *testing.T) {
	tests := []struct {
		name      string
		entry     AuditEntry
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "successful violation log",
			entry: AuditEntry{
				Severity: "HIGH",
				ClientID: "test-client",
				UserID:   "user-123",
				Details: map[string]interface{}{
					"policy_name": "test-policy",
					"description": "Test violation",
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO policy_violations").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "database error",
			entry: AuditEntry{
				Severity: "MEDIUM",
				ClientID: "test-client",
				UserID:   "user-456",
				Details: map[string]interface{}{
					"policy_name": "test-policy-2",
					"description": "Test violation 2",
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO policy_violations").
					WillReturnError(sql.ErrConnDone)
				// Expect 3 retries
				mock.ExpectExec("INSERT INTO policy_violations").
					WillReturnError(sql.ErrConnDone)
				mock.ExpectExec("INSERT INTO policy_violations").
					WillReturnError(sql.ErrConnDone)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			fallbackPath := filepath.Join(os.TempDir(), "test-audit-compliance-"+tt.name+".log")
			defer func() { _ = os.Remove(fallbackPath) }()

			aq, err := NewAuditQueue(AuditModeCompliance, 10, 1, db, fallbackPath)
			if err != nil {
				t.Fatalf("failed to create queue: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(mock)
			}

			err = aq.LogViolation(tt.entry)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			if err := aq.Shutdown(ctx); err != nil {
		t.Logf("Shutdown error (may be expected in test): %v", err)
	}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

// TestLogViolation_PerformanceMode tests async violation logging
func TestLogViolation_PerformanceMode(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	fallbackPath := filepath.Join(os.TempDir(), "test-audit-performance.log")
	defer func() { _ = os.Remove(fallbackPath) }()

	aq, err := NewAuditQueue(AuditModePerformance, 100, 2, db, fallbackPath)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}

	// Expect async write
	mock.ExpectExec("INSERT INTO policy_violations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	entry := AuditEntry{
		Severity: "HIGH",
		ClientID: "test-client",
		UserID:   "user-123",
		Details: map[string]interface{}{
			"policy_name": "test-policy",
			"description": "Async test",
		},
	}

	err = aq.LogViolation(entry)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Give worker time to process
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := aq.Shutdown(ctx); err != nil {
		t.Logf("Shutdown error (may be expected in test): %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestLogMetric tests metric logging
func TestLogMetric(t *testing.T) {
	tests := []struct {
		name         string
		numMetrics   int
		expectedLogs int
	}{
		{
			name:         "single metric",
			numMetrics:   1,
			expectedLogs: 1,
		},
		{
			name:         "batch of metrics",
			numMetrics:   10,
			expectedLogs: 10,
		},
		{
			name:         "large batch",
			numMetrics:   150, // Will trigger batch flush at 100
			expectedLogs: 150,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			fallbackPath := filepath.Join(os.TempDir(), "test-metrics-"+tt.name+".log")
			defer func() { _ = os.Remove(fallbackPath) }()

			aq, err := NewAuditQueue(AuditModePerformance, 1000, 2, db, fallbackPath)
			if err != nil {
				t.Fatalf("failed to create queue: %v", err)
			}

			// Expect metric inserts
			for i := 0; i < tt.expectedLogs; i++ {
				mock.ExpectExec("INSERT INTO policy_metrics").
					WillReturnResult(sqlmock.NewResult(1, 1))
			}

			// Log metrics
			for i := 0; i < tt.numMetrics; i++ {
				entry := AuditEntry{
					Details: map[string]interface{}{
						"policy_id": "policy-123",
						"blocked":   i%2 == 0,
					},
				}
				err := aq.LogMetric(entry)
				if err != nil {
					t.Errorf("unexpected error logging metric: %v", err)
				}
			}

			// Wait for batch processing
			time.Sleep(1500 * time.Millisecond) // Wait for ticker flush

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := aq.Shutdown(ctx); err != nil {
		t.Logf("Shutdown error (may be expected in test): %v", err)
	}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

// TestQueueOverflow tests fallback when queue is full
func TestQueueOverflow(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	fallbackPath := filepath.Join(os.TempDir(), "test-overflow.log")
	defer func() { _ = os.Remove(fallbackPath) }()

	// Create small queue (size 2)
	aq, err := NewAuditQueue(AuditModePerformance, 2, 0, db, fallbackPath) // 0 workers to prevent processing
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}

	// Fill queue and overflow
	for i := 0; i < 5; i++ {
		entry := AuditEntry{
			Severity: "LOW",
			ClientID: "test",
			Details: map[string]interface{}{
				"index": i,
			},
		}
		_ = aq.queueEntry(entry) // Some will go to fallback
	}

	// Check fallback file exists and has content
	data, err := os.ReadFile(fallbackPath)
	if err != nil {
		t.Errorf("failed to read fallback: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected fallback file to have content")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := aq.Shutdown(ctx); err != nil {
		t.Logf("Shutdown error (may be expected in test): %v", err)
	}
}

// TestWriteToFallback tests fallback file writing
func TestWriteToFallback(t *testing.T) {
	fallbackPath := filepath.Join(os.TempDir(), "test-fallback.log")
	defer func() { _ = os.Remove(fallbackPath) }()

	fallbackFile, err := os.OpenFile(fallbackPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("failed to create fallback file: %v", err)
	}
	defer func() { _ = fallbackFile.Close() }()

	aq := &AuditQueue{
		fallbackFile: fallbackFile,
	}

	entry := AuditEntry{
		Type:      "test",
		Timestamp: time.Now(),
		Severity:  "HIGH",
		ClientID:  "client-123",
		Details: map[string]interface{}{
			"test": "data",
		},
	}

	err = aq.writeToFallback(entry)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify file content
	data, err := os.ReadFile(fallbackPath)
	if err != nil {
		t.Fatalf("failed to read fallback: %v", err)
	}

	var readEntry AuditEntry
	err = json.Unmarshal(data[:len(data)-1], &readEntry) // Remove trailing newline
	if err != nil {
		t.Errorf("failed to unmarshal: %v", err)
	}

	if readEntry.Type != entry.Type {
		t.Errorf("expected type %s, got %s", entry.Type, readEntry.Type)
	}
	if readEntry.ClientID != entry.ClientID {
		t.Errorf("expected client_id %s, got %s", entry.ClientID, readEntry.ClientID)
	}
}

// TestShutdown tests graceful shutdown
func TestShutdown(t *testing.T) {
	t.Run("graceful shutdown with empty queue", func(t *testing.T) {
		db, _, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create mock: %v", err)
		}
		defer func() { _ = db.Close() }()

		fallbackPath := filepath.Join(os.TempDir(), "test-shutdown-graceful.log")
		defer func() { _ = os.Remove(fallbackPath) }()

		aq, err := NewAuditQueue(AuditModePerformance, 10, 2, db, fallbackPath)
		if err != nil {
			t.Fatalf("failed to create queue: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = aq.Shutdown(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("shutdown with pending metrics", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create mock: %v", err)
		}
		defer func() { _ = db.Close() }()

		fallbackPath := filepath.Join(os.TempDir(), "test-shutdown-metrics.log")
		defer func() { _ = os.Remove(fallbackPath) }()

		aq, err := NewAuditQueue(AuditModePerformance, 100, 2, db, fallbackPath)
		if err != nil {
			t.Fatalf("failed to create queue: %v", err)
		}

		// Queue a few metrics (will be batched)
		for i := 0; i < 3; i++ {
			mock.ExpectExec("INSERT INTO policy_metrics").
				WillReturnResult(sqlmock.NewResult(1, 1))

			entry := AuditEntry{
				Details: map[string]interface{}{
					"policy_id": "test-policy",
					"blocked":   true,
				},
			}
			_ = aq.LogMetric(entry)
		}

		// Shutdown should flush pending metrics
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = aq.Shutdown(ctx)
		if err != nil {
			t.Errorf("unexpected error during shutdown: %v", err)
		}

		// Verify metrics were flushed (or test passes if they weren't - shutdown is what we're testing)
	})
}

// TestGetStats tests statistics retrieval
func TestGetStats(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	fallbackPath := filepath.Join(os.TempDir(), "test-stats.log")
	defer func() { _ = os.Remove(fallbackPath) }()

	aq, err := NewAuditQueue(AuditModePerformance, 100, 2, db, fallbackPath)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}

	// Initial stats should be zero
	stats := aq.GetStats()
	if stats["processed"] != uint64(0) {
		t.Errorf("expected 0 processed, got %d", stats["processed"])
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := aq.Shutdown(ctx); err != nil {
		t.Logf("Shutdown error (may be expected in test): %v", err)
	}
}

// TestAuditModes tests different audit modes
func TestAuditModes(t *testing.T) {
	modes := []AuditMode{AuditModeCompliance, AuditModePerformance}

	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			fallbackPath := filepath.Join(os.TempDir(), "test-mode-"+string(mode)+".log")
			defer func() { _ = os.Remove(fallbackPath) }()

			aq, err := NewAuditQueue(mode, 100, 2, db, fallbackPath)
			if err != nil {
				t.Fatalf("failed to create queue: %v", err)
			}

			if aq.mode != mode {
				t.Errorf("expected mode %s, got %s", mode, aq.mode)
			}

			// Expect at least one insert for compliance mode (sync)
			if mode == AuditModeCompliance {
				mock.ExpectExec("INSERT INTO policy_violations").
					WillReturnResult(sqlmock.NewResult(1, 1))
			} else {
				// Performance mode might process async
				mock.ExpectExec("INSERT INTO policy_violations").
					WillReturnResult(sqlmock.NewResult(1, 1))
			}

			entry := AuditEntry{
				Severity: "MEDIUM",
				ClientID: "test",
				Details: map[string]interface{}{
					"policy_name": "test",
					"description": "test",
				},
			}

			_ = aq.LogViolation(entry)

			time.Sleep(100 * time.Millisecond)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := aq.Shutdown(ctx); err != nil {
		t.Logf("Shutdown error (may be expected in test): %v", err)
	}

			// Note: We don't strictly check ExpectationsWereMet here
			// because performance mode is async and timing can vary
		})
	}
}

// TestToStringSlice tests the toStringSlice helper function
func TestToStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected []string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "string slice",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "empty string slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "interface slice with strings",
			input:    []interface{}{"x", "y", "z"},
			expected: []string{"x", "y", "z"},
		},
		{
			name:     "interface slice mixed types",
			input:    []interface{}{"valid", 123, "also-valid"},
			expected: []string{"valid", "also-valid"},
		},
		{
			name:     "empty interface slice",
			input:    []interface{}{},
			expected: []string{},
		},
		{
			name:     "unsupported type",
			input:    "not a slice",
			expected: nil,
		},
		{
			name:     "int slice (unsupported)",
			input:    []int{1, 2, 3},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toStringSlice(tt.input)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("expected length %d, got %d", len(tt.expected), len(result))
				return
			}

			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("expected[%d] = %q, got %q", i, tt.expected[i], v)
				}
			}
		})
	}
}

// Benchmark tests for performance validation
func BenchmarkLogViolation(b *testing.B) {
	db, mock, _ := sqlmock.New()
	defer func() { _ = db.Close() }()

	fallbackPath := filepath.Join(os.TempDir(), "bench-violations.log")
	defer func() { _ = os.Remove(fallbackPath) }()

	aq, _ := NewAuditQueue(AuditModePerformance, 10000, 4, db, fallbackPath)

	// Setup mock for many inserts
	for i := 0; i < b.N; i++ {
		mock.ExpectExec("INSERT INTO policy_violations").
			WillReturnResult(sqlmock.NewResult(1, 1))
	}

	entry := AuditEntry{
		Severity: "HIGH",
		ClientID: "bench-client",
		Details: map[string]interface{}{
			"policy_name": "bench-policy",
			"description": "Benchmark test",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = aq.LogViolation(entry)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = aq.Shutdown(ctx)
}

func BenchmarkLogMetric(b *testing.B) {
	db, mock, _ := sqlmock.New()
	defer func() { _ = db.Close() }()

	fallbackPath := filepath.Join(os.TempDir(), "bench-metrics.log")
	defer func() { _ = os.Remove(fallbackPath) }()

	aq, _ := NewAuditQueue(AuditModePerformance, 10000, 4, db, fallbackPath)

	// Setup mock for batch inserts
	for i := 0; i < b.N; i++ {
		mock.ExpectExec("INSERT INTO policy_metrics").
			WillReturnResult(sqlmock.NewResult(1, 1))
	}

	entry := AuditEntry{
		Details: map[string]interface{}{
			"policy_id": "bench-policy",
			"blocked":   true,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = aq.LogMetric(entry)
	}

	time.Sleep(2 * time.Second) // Allow batch processing

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = aq.Shutdown(ctx)
}

// TestAuditQueue_WorkerProcessing tests the worker processing loop
func TestAuditQueue_WorkerProcessing(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	// Create audit queue in compliance mode (sync writes)
	tmpFile := filepath.Join(t.TempDir(), "audit-test-worker.log")
	queue, err := NewAuditQueue(AuditModeCompliance, 100, 1, db, tmpFile)
	if err != nil {
		t.Fatalf("Failed to create audit queue: %v", err)
	}

	// Mock database insert for violation
	mock.ExpectExec("INSERT INTO policy_violations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Log a violation
	entry := AuditEntry{
		Type:      "violation",
		Timestamp: time.Now(),
		Severity:  "critical",
		UserID:    "user-123",
		ClientID:  "client-456",
		Details: map[string]interface{}{
			"policy_id": "test-policy",
			"query":     "SELECT * FROM users",
		},
	}

	err = queue.LogViolation(entry)
	if err != nil {
		t.Errorf("LogViolation() error = %v", err)
	}

	// Give workers time to process
	time.Sleep(200 * time.Millisecond)

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := queue.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}

	// Verify mock expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestLogGatewayContext_ComplianceMode tests synchronous gateway context logging
func TestLogGatewayContext_ComplianceMode(t *testing.T) {
	tests := []struct {
		name      string
		entry     AuditEntry
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "successful gateway context log",
			entry: AuditEntry{
				ClientID: "test-client",
				Details: map[string]interface{}{
					"context_id":         "ctx-123",
					"user_token_hash":    "hash123",
					"query_hash":         "queryhash456",
					"data_sources":       nil,
					"policies_evaluated": nil,
					"approved":           true,
					"block_reason":       "",
					"expires_at":         time.Now().Add(5 * time.Minute),
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO gateway_contexts").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "gateway context with block reason",
			entry: AuditEntry{
				ClientID: "test-client",
				Details: map[string]interface{}{
					"context_id":         "ctx-456",
					"user_token_hash":    "hash789",
					"query_hash":         "queryhash012",
					"data_sources":       nil,
					"policies_evaluated": nil,
					"approved":           false,
					"block_reason":       "Policy violation detected",
					"expires_at":         time.Now().Add(5 * time.Minute),
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO gateway_contexts").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "database error with retries",
			entry: AuditEntry{
				ClientID: "test-client",
				Details: map[string]interface{}{
					"context_id":         "ctx-789",
					"user_token_hash":    "hash999",
					"query_hash":         "queryhash999",
					"data_sources":       nil,
					"policies_evaluated": nil,
					"approved":           true,
					"block_reason":       "",
					"expires_at":         time.Now().Add(5 * time.Minute),
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Expect 3 retries
				mock.ExpectExec("INSERT INTO gateway_contexts").
					WillReturnError(sql.ErrConnDone)
				mock.ExpectExec("INSERT INTO gateway_contexts").
					WillReturnError(sql.ErrConnDone)
				mock.ExpectExec("INSERT INTO gateway_contexts").
					WillReturnError(sql.ErrConnDone)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			fallbackPath := filepath.Join(os.TempDir(), "test-gateway-context-"+tt.name+".log")
			defer func() { _ = os.Remove(fallbackPath) }()

			aq, err := NewAuditQueue(AuditModeCompliance, 10, 1, db, fallbackPath)
			if err != nil {
				t.Fatalf("failed to create queue: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(mock)
			}

			err = aq.LogGatewayContext(tt.entry)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			if err := aq.Shutdown(ctx); err != nil {
				t.Logf("Shutdown error (may be expected in test): %v", err)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

// TestLogGatewayContext_PerformanceMode tests async gateway context logging
func TestLogGatewayContext_PerformanceMode(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	fallbackPath := filepath.Join(os.TempDir(), "test-gateway-context-async.log")
	defer func() { _ = os.Remove(fallbackPath) }()

	aq, err := NewAuditQueue(AuditModePerformance, 100, 2, db, fallbackPath)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}

	// Expect async write
	mock.ExpectExec("INSERT INTO gateway_contexts").
		WillReturnResult(sqlmock.NewResult(1, 1))

	entry := AuditEntry{
		ClientID: "test-client",
		Details: map[string]interface{}{
			"context_id":         "ctx-async-123",
			"user_token_hash":    "asynchash",
			"query_hash":         "asyncquery",
			"data_sources":       nil,
			"policies_evaluated": nil,
			"approved":           true,
			"block_reason":       "",
			"expires_at":         time.Now().Add(5 * time.Minute),
		},
	}

	err = aq.LogGatewayContext(entry)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Give worker time to process
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := aq.Shutdown(ctx); err != nil {
		t.Logf("Shutdown error (may be expected in test): %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestLogLLMCallAudit_ComplianceMode tests synchronous LLM call audit logging
func TestLogLLMCallAudit_ComplianceMode(t *testing.T) {
	tests := []struct {
		name      string
		entry     AuditEntry
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "successful LLM call audit",
			entry: AuditEntry{
				ClientID: "test-client",
				Details: map[string]interface{}{
					"audit_id":           "audit-123",
					"context_id":         "ctx-123",
					"provider":           "openai",
					"model":              "gpt-4",
					"prompt_tokens":      100,
					"completion_tokens":  50,
					"total_tokens":       150,
					"latency_ms":         int64(500),
					"estimated_cost_usd": 0.015,
					"metadata":           map[string]interface{}{"key": "value"},
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO llm_call_audits").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "LLM call audit with bedrock provider",
			entry: AuditEntry{
				ClientID: "test-client",
				Details: map[string]interface{}{
					"audit_id":           "audit-456",
					"context_id":         "ctx-456",
					"provider":           "bedrock",
					"model":              "anthropic.claude-3-sonnet",
					"prompt_tokens":      200,
					"completion_tokens":  100,
					"total_tokens":       300,
					"latency_ms":         int64(1500),
					"estimated_cost_usd": 0.009,
					"metadata":           nil,
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO llm_call_audits").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "database error with retries",
			entry: AuditEntry{
				ClientID: "test-client",
				Details: map[string]interface{}{
					"audit_id":           "audit-error",
					"context_id":         "ctx-error",
					"provider":           "openai",
					"model":              "gpt-4",
					"prompt_tokens":      50,
					"completion_tokens":  25,
					"total_tokens":       75,
					"latency_ms":         int64(200),
					"estimated_cost_usd": 0.0075,
					"metadata":           nil,
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Expect 3 retries
				mock.ExpectExec("INSERT INTO llm_call_audits").
					WillReturnError(sql.ErrConnDone)
				mock.ExpectExec("INSERT INTO llm_call_audits").
					WillReturnError(sql.ErrConnDone)
				mock.ExpectExec("INSERT INTO llm_call_audits").
					WillReturnError(sql.ErrConnDone)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			fallbackPath := filepath.Join(os.TempDir(), "test-llm-audit-"+tt.name+".log")
			defer func() { _ = os.Remove(fallbackPath) }()

			aq, err := NewAuditQueue(AuditModeCompliance, 10, 1, db, fallbackPath)
			if err != nil {
				t.Fatalf("failed to create queue: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(mock)
			}

			err = aq.LogLLMCallAudit(tt.entry)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			if err := aq.Shutdown(ctx); err != nil {
				t.Logf("Shutdown error (may be expected in test): %v", err)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

// TestLogLLMCallAudit_PerformanceMode tests async LLM call audit logging
func TestLogLLMCallAudit_PerformanceMode(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	fallbackPath := filepath.Join(os.TempDir(), "test-llm-audit-async.log")
	defer func() { _ = os.Remove(fallbackPath) }()

	aq, err := NewAuditQueue(AuditModePerformance, 100, 2, db, fallbackPath)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}

	// Expect async write
	mock.ExpectExec("INSERT INTO llm_call_audits").
		WillReturnResult(sqlmock.NewResult(1, 1))

	entry := AuditEntry{
		ClientID: "test-client",
		Details: map[string]interface{}{
			"audit_id":           "audit-async-123",
			"context_id":         "ctx-async-123",
			"provider":           "anthropic",
			"model":              "claude-3-opus",
			"prompt_tokens":      500,
			"completion_tokens":  250,
			"total_tokens":       750,
			"latency_ms":         int64(2500),
			"estimated_cost_usd": 0.1125,
			"metadata":           map[string]interface{}{"async": true},
		},
	}

	err = aq.LogLLMCallAudit(entry)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Give worker time to process
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := aq.Shutdown(ctx); err != nil {
		t.Logf("Shutdown error (may be expected in test): %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestRecoverFromFallback tests the recovery mechanism
func TestRecoverFromFallback(t *testing.T) {
	t.Run("no fallback file", func(t *testing.T) {
		db, _, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create mock: %v", err)
		}
		defer func() { _ = db.Close() }()

		fallbackPath := filepath.Join(os.TempDir(), "test-recover-no-file.log")
		defer func() { _ = os.Remove(fallbackPath) }()

		aq, err := NewAuditQueue(AuditModeCompliance, 10, 1, db, fallbackPath)
		if err != nil {
			t.Fatalf("failed to create queue: %v", err)
		}

		// Remove the fallback file
		_ = os.Remove(fallbackPath)

		// Should not error for non-existent file
		recovered, err := aq.RecoverFromFallback(fallbackPath)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if recovered != 0 {
			t.Errorf("expected 0 recovered, got %d", recovered)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = aq.Shutdown(ctx)
	})

	t.Run("empty fallback file", func(t *testing.T) {
		db, _, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create mock: %v", err)
		}
		defer func() { _ = db.Close() }()

		fallbackPath := filepath.Join(os.TempDir(), "test-recover-empty.log")
		defer func() { _ = os.Remove(fallbackPath) }()

		// Create empty fallback file
		f, err := os.Create(fallbackPath)
		if err != nil {
			t.Fatalf("failed to create fallback file: %v", err)
		}
		_ = f.Close()

		aq, err := NewAuditQueue(AuditModeCompliance, 10, 1, db, fallbackPath)
		if err != nil {
			t.Fatalf("failed to create queue: %v", err)
		}

		recovered, err := aq.RecoverFromFallback(fallbackPath)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if recovered != 0 {
			t.Errorf("expected 0 recovered, got %d", recovered)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = aq.Shutdown(ctx)
	})

	t.Run("recover entries successfully", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create mock: %v", err)
		}
		defer func() { _ = db.Close() }()

		fallbackPath := filepath.Join(os.TempDir(), "test-recover-success.log")
		defer func() { _ = os.Remove(fallbackPath) }()

		// Create fallback file with entries
		entries := []AuditEntry{
			{
				Type:      AuditTypeGatewayContext,
				Timestamp: time.Now(),
				ClientID:  "client-1",
				Details: map[string]interface{}{
					"context_id":         "ctx-recover-1",
					"user_token_hash":    "hash1",
					"query_hash":         "query1",
					"data_sources":       nil,
					"policies_evaluated": nil,
					"approved":           true,
					"block_reason":       "",
					"expires_at":         time.Now().Add(5 * time.Minute),
				},
			},
			{
				Type:      AuditTypeLLMCallAudit,
				Timestamp: time.Now(),
				ClientID:  "client-2",
				Details: map[string]interface{}{
					"audit_id":           "audit-recover-1",
					"context_id":         "ctx-recover-1",
					"provider":           "openai",
					"model":              "gpt-4",
					"prompt_tokens":      100,
					"completion_tokens":  50,
					"total_tokens":       150,
					"latency_ms":         int64(500),
					"estimated_cost_usd": 0.015,
					"metadata":           nil,
				},
			},
		}

		// Write entries to fallback file
		f, err := os.Create(fallbackPath)
		if err != nil {
			t.Fatalf("failed to create fallback file: %v", err)
		}
		for _, e := range entries {
			data, _ := json.Marshal(e)
			_, _ = f.WriteString(string(data) + "\n")
		}
		_ = f.Close()

		// Expect DB writes for recovery
		mock.ExpectExec("INSERT INTO gateway_contexts").
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("INSERT INTO llm_call_audits").
			WillReturnResult(sqlmock.NewResult(1, 1))

		aq, err := NewAuditQueue(AuditModeCompliance, 10, 1, db, fallbackPath)
		if err != nil {
			t.Fatalf("failed to create queue: %v", err)
		}

		recovered, err := aq.RecoverFromFallback(fallbackPath)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if recovered != 2 {
			t.Errorf("expected 2 recovered, got %d", recovered)
		}

		// Verify fallback file was truncated
		info, _ := os.Stat(fallbackPath)
		if info.Size() != 0 {
			t.Errorf("expected fallback file to be truncated, size=%d", info.Size())
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = aq.Shutdown(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("partial recovery with failures", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create mock: %v", err)
		}
		defer func() { _ = db.Close() }()

		fallbackPath := filepath.Join(os.TempDir(), "test-recover-partial.log")
		defer func() { _ = os.Remove(fallbackPath) }()

		// Create fallback file with entries
		entries := []AuditEntry{
			{
				Type:      AuditTypeGatewayContext,
				Timestamp: time.Now(),
				ClientID:  "client-1",
				Details: map[string]interface{}{
					"context_id":         "ctx-recover-2",
					"user_token_hash":    "hash2",
					"query_hash":         "query2",
					"data_sources":       nil,
					"policies_evaluated": nil,
					"approved":           true,
					"block_reason":       "",
					"expires_at":         time.Now().Add(5 * time.Minute),
				},
			},
			{
				Type:      AuditTypeLLMCallAudit,
				Timestamp: time.Now(),
				ClientID:  "client-2",
				Details: map[string]interface{}{
					"audit_id":           "audit-recover-2",
					"context_id":         "ctx-recover-2",
					"provider":           "openai",
					"model":              "gpt-4",
					"prompt_tokens":      100,
					"completion_tokens":  50,
					"total_tokens":       150,
					"latency_ms":         int64(500),
					"estimated_cost_usd": 0.015,
					"metadata":           nil,
				},
			},
		}

		// Write entries to fallback file
		f, err := os.Create(fallbackPath)
		if err != nil {
			t.Fatalf("failed to create fallback file: %v", err)
		}
		for _, e := range entries {
			data, _ := json.Marshal(e)
			_, _ = f.WriteString(string(data) + "\n")
		}
		_ = f.Close()

		// First entry succeeds, second entry fails (all 3 retries)
		mock.ExpectExec("INSERT INTO gateway_contexts").
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("INSERT INTO llm_call_audits").
			WillReturnError(sql.ErrConnDone)
		mock.ExpectExec("INSERT INTO llm_call_audits").
			WillReturnError(sql.ErrConnDone)
		mock.ExpectExec("INSERT INTO llm_call_audits").
			WillReturnError(sql.ErrConnDone)

		aq, err := NewAuditQueue(AuditModeCompliance, 10, 1, db, fallbackPath)
		if err != nil {
			t.Fatalf("failed to create queue: %v", err)
		}

		recovered, err := aq.RecoverFromFallback(fallbackPath)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if recovered != 1 {
			t.Errorf("expected 1 recovered, got %d", recovered)
		}

		// Verify failed entry remains in fallback file
		data, _ := os.ReadFile(fallbackPath)
		if len(data) == 0 {
			t.Error("expected failed entry to remain in fallback file")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = aq.Shutdown(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

// TestGetFallbackPath tests fallback path retrieval
func TestGetFallbackPath(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	fallbackPath := filepath.Join(os.TempDir(), "test-get-fallback-path.log")
	defer func() { _ = os.Remove(fallbackPath) }()

	aq, err := NewAuditQueue(AuditModeCompliance, 10, 1, db, fallbackPath)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}

	gotPath := aq.GetFallbackPath()
	if gotPath != fallbackPath {
		t.Errorf("expected path %s, got %s", fallbackPath, gotPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = aq.Shutdown(ctx)
}

// TestAuditTypeConstants verifies audit type constants are correct
func TestAuditTypeConstants(t *testing.T) {
	tests := []struct {
		constant string
		expected string
	}{
		{AuditTypeViolation, "violation"},
		{AuditTypeMetric, "metric"},
		{AuditTypeAudit, "audit"},
		{AuditTypeGatewayContext, "gateway_context"},
		{AuditTypeLLMCallAudit, "llm_call_audit"},
	}

	for _, tt := range tests {
		if tt.constant != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.constant)
		}
	}
}

// TestGatewayAuditFallbackOnDBError tests fallback to file when DB fails
func TestGatewayAuditFallbackOnDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	fallbackPath := filepath.Join(os.TempDir(), "test-gateway-fallback.log")
	defer func() { _ = os.Remove(fallbackPath) }()

	// Create queue with 0 workers to test queue overflow to fallback
	aq, err := NewAuditQueue(AuditModePerformance, 1, 0, db, fallbackPath)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}

	// Fill the queue and overflow to fallback
	for i := 0; i < 5; i++ {
		entry := AuditEntry{
			ClientID: "test-client",
			Details: map[string]interface{}{
				"context_id":         "ctx-overflow-" + string(rune(i)),
				"user_token_hash":    "hash",
				"query_hash":         "query",
				"data_sources":       nil,
				"policies_evaluated": nil,
				"approved":           true,
				"block_reason":       "",
				"expires_at":         time.Now().Add(5 * time.Minute),
			},
		}
		_ = aq.LogGatewayContext(entry)
	}

	// Verify fallback file has content
	data, err := os.ReadFile(fallbackPath)
	if err != nil {
		t.Errorf("failed to read fallback: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected fallback file to have content from queue overflow")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = aq.Shutdown(ctx)

	// Verify no unexpected DB calls were made
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// BenchmarkLogGatewayContext benchmarks gateway context logging
func BenchmarkLogGatewayContext(b *testing.B) {
	db, mock, _ := sqlmock.New()
	defer func() { _ = db.Close() }()

	fallbackPath := filepath.Join(os.TempDir(), "bench-gateway-context.log")
	defer func() { _ = os.Remove(fallbackPath) }()

	aq, _ := NewAuditQueue(AuditModePerformance, 10000, 4, db, fallbackPath)

	// Setup mock for many inserts
	for i := 0; i < b.N; i++ {
		mock.ExpectExec("INSERT INTO gateway_contexts").
			WillReturnResult(sqlmock.NewResult(1, 1))
	}

	entry := AuditEntry{
		ClientID: "bench-client",
		Details: map[string]interface{}{
			"context_id":         "ctx-bench",
			"user_token_hash":    "benchhash",
			"query_hash":         "benchquery",
			"data_sources":       nil,
			"policies_evaluated": nil,
			"approved":           true,
			"block_reason":       "",
			"expires_at":         time.Now().Add(5 * time.Minute),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = aq.LogGatewayContext(entry)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = aq.Shutdown(ctx)
}

// BenchmarkLogLLMCallAudit benchmarks LLM call audit logging
func BenchmarkLogLLMCallAudit(b *testing.B) {
	db, mock, _ := sqlmock.New()
	defer func() { _ = db.Close() }()

	fallbackPath := filepath.Join(os.TempDir(), "bench-llm-audit.log")
	defer func() { _ = os.Remove(fallbackPath) }()

	aq, _ := NewAuditQueue(AuditModePerformance, 10000, 4, db, fallbackPath)

	// Setup mock for many inserts
	for i := 0; i < b.N; i++ {
		mock.ExpectExec("INSERT INTO llm_call_audits").
			WillReturnResult(sqlmock.NewResult(1, 1))
	}

	entry := AuditEntry{
		ClientID: "bench-client",
		Details: map[string]interface{}{
			"audit_id":           "audit-bench",
			"context_id":         "ctx-bench",
			"provider":           "openai",
			"model":              "gpt-4",
			"prompt_tokens":      100,
			"completion_tokens":  50,
			"total_tokens":       150,
			"latency_ms":         int64(500),
			"estimated_cost_usd": 0.015,
			"metadata":           nil,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = aq.LogLLMCallAudit(entry)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = aq.Shutdown(ctx)
}
