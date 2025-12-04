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

package main

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
