// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	sharedpolicy "axonflow/platform/shared/policy"
)

// Note: Full handler integration tests require complex mocking of auth, license, and connector
// infrastructure. The audit logging logic is tested through unit tests below and in
// audit_queue_mcp_test.go. Handler integration tests should be run via E2E tests.


// TestExtractMatchedPolicyIDs tests the policy ID extraction helper
func TestExtractMatchedPolicyIDs(t *testing.T) {
	tests := []struct {
		name     string
		matches  []sharedpolicy.PolicyMatch
		expected []string
	}{
		{
			name:     "nil matches returns nil",
			matches:  nil,
			expected: nil,
		},
		{
			name:     "empty matches returns nil",
			matches:  []sharedpolicy.PolicyMatch{},
			expected: nil,
		},
		{
			name: "single match",
			matches: []sharedpolicy.PolicyMatch{
				{PolicyID: "policy-1"},
			},
			expected: []string{"policy-1"},
		},
		{
			name: "multiple matches",
			matches: []sharedpolicy.PolicyMatch{
				{PolicyID: "sqli-001"},
				{PolicyID: "pii-ssn"},
				{PolicyID: "pii-email"},
			},
			expected: []string{"sqli-001", "pii-ssn", "pii-email"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractMatchedPolicyIDs(tt.matches)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("expected %d IDs, got %d", len(tt.expected), len(result))
				return
			}

			for i, id := range result {
				if id != tt.expected[i] {
					t.Errorf("expected ID[%d] = %s, got %s", i, tt.expected[i], id)
				}
			}
		})
	}
}

// TestComputeStatementHash tests the statement hash computation
func TestComputeStatementHash(t *testing.T) {
	tests := []struct {
		name      string
		statement string
		wantEmpty bool
	}{
		{
			name:      "empty statement returns empty hash",
			statement: "",
			wantEmpty: true,
		},
		{
			name:      "non-empty statement returns hash",
			statement: "SELECT * FROM users",
			wantEmpty: false,
		},
		{
			name:      "same statement produces same hash",
			statement: "SELECT id, name FROM users WHERE id = 1",
			wantEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := computeStatementHash(tt.statement)

			if tt.wantEmpty {
				if hash != "" {
					t.Errorf("expected empty hash, got %s", hash)
				}
			} else {
				if hash == "" {
					t.Error("expected non-empty hash, got empty")
				}
				// SHA256 produces 64 character hex string
				if len(hash) != 64 {
					t.Errorf("expected hash length 64, got %d", len(hash))
				}
			}
		})
	}

	// Test that same statement produces same hash
	stmt := "SELECT * FROM users"
	hash1 := computeStatementHash(stmt)
	hash2 := computeStatementHash(stmt)
	if hash1 != hash2 {
		t.Errorf("same statement produced different hashes: %s vs %s", hash1, hash2)
	}

	// Test that different statements produce different hashes
	hash3 := computeStatementHash("SELECT * FROM orders")
	if hash1 == hash3 {
		t.Error("different statements produced same hash")
	}
}

// TestGetMCPAuditQueue tests the audit queue retrieval
func TestGetMCPAuditQueue(t *testing.T) {
	t.Run("nil policy engine returns nil", func(t *testing.T) {
		oldAuditManager := auditManager
		auditManager = nil
		defer func() { auditManager = oldAuditManager }()

		queue := getMCPAuditQueue()
		if queue != nil {
			t.Error("expected nil queue when auditManager is nil")
		}
	})

	t.Run("policy engine with audit queue returns queue", func(t *testing.T) {
		db, _, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create mock db: %v", err)
		}
		defer db.Close()

		fallbackPath := filepath.Join(os.TempDir(), "test-get-audit-queue.log")
		defer os.Remove(fallbackPath)

		auditQueue, _ := NewAuditQueue(AuditModeCompliance, 100, 1, db, fallbackPath)

		oldAuditManager := auditManager
		auditManager = &AuditManager{queue: auditQueue}
		defer func() { auditManager = oldAuditManager }()

		queue := getMCPAuditQueue()
		if queue == nil {
			t.Error("expected non-nil queue")
		}
		if queue != auditQueue {
			t.Error("expected same queue instance")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = auditQueue.Shutdown(ctx)
	})
}

// TestLogMCPQueryAudit_Helper tests the helper function for logging
func TestLogMCPQueryAudit_Helper(t *testing.T) {
	t.Run("nil audit queue logs warning but doesn't panic", func(t *testing.T) {
		oldAuditManager := auditManager
		auditManager = nil
		defer func() { auditManager = oldAuditManager }()

		// Should not panic
		entry := MCPQueryAuditEntry{
			AuditID:       "test-123",
			ConnectorName: "postgres",
			Operation:     "query",
			Success:       true,
		}
		logMCPQueryAudit(entry)
	})

	t.Run("valid audit queue logs entry", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create mock db: %v", err)
		}
		defer db.Close()

		fallbackPath := filepath.Join(os.TempDir(), "test-log-helper.log")
		defer os.Remove(fallbackPath)

		auditQueue, _ := NewAuditQueue(AuditModeCompliance, 100, 1, db, fallbackPath)

		oldAuditManager := auditManager
		auditManager = &AuditManager{queue: auditQueue}
		defer func() { auditManager = oldAuditManager }()

		// Expect the INSERT. v9 Phase 8 B2: WithOrgScope wrap requires
		// BeginTx + set_config + INSERT + Commit.
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("INSERT INTO mcp_query_audits").
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		entry := MCPQueryAuditEntry{
			AuditID:       "test-456",
			TenantID:      "tenant-1",
			OrgID:         "tenant-1",
			ClientID:      "client-1",
			ConnectorName: "postgres",
			Operation:     "query",
			Success:       true,
			DurationMs:    50,
		}
		logMCPQueryAudit(entry)

		// Give time for sync write
		time.Sleep(50 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = auditQueue.Shutdown(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled mock expectations: %v", err)
		}
	})
}

// TestMCPAuditEntry_AllScenarios tests various audit scenarios
func TestMCPAuditEntry_AllScenarios(t *testing.T) {
	scenarios := []struct {
		name  string
		entry MCPQueryAuditEntry
	}{
		{
			name: "successful query",
			entry: MCPQueryAuditEntry{
				AuditID:                  "scenario-success",
				TenantID:                 "tenant-1",
				OrgID:                    "tenant-1",
				ClientID:                 "client-1",
				UserID:                   "user-1",
				ConnectorName:            "postgres",
				Operation:                "query",
				StatementHash:            "hash123",
				RequestPoliciesEvaluated: 5,
				Success:                  true,
				RowCount:                 100,
				DurationMs:               75,
			},
		},
		{
			name: "blocked by SQLi detection",
			entry: MCPQueryAuditEntry{
				AuditID:                  "scenario-sqli",
				TenantID:                 "tenant-1",
				OrgID:                    "tenant-1",
				ClientID:                 "client-1",
				UserID:                   "user-1",
				ConnectorName:            "postgres",
				Operation:                "query",
				StatementHash:            "sqli-hash",
				RequestBlocked:           true,
				RequestBlockReason:       "SQL injection detected: UNION SELECT",
				RequestPoliciesEvaluated: 5,
				RequestMatchedPolicies:   []string{"sqli-001"},
				Success:                  false,
				DurationMs:               5,
			},
		},
		{
			name: "PII redacted in response",
			entry: MCPQueryAuditEntry{
				AuditID:                  "scenario-redaction",
				TenantID:                 "tenant-1",
				OrgID:                    "tenant-1",
				ClientID:                 "client-1",
				UserID:                   "user-1",
				ConnectorName:            "postgres",
				Operation:                "query",
				StatementHash:            "pii-hash",
				RequestPoliciesEvaluated: 8,
				ResponseRedacted:         true,
				ResponseRedactionsCount:  3,
				ResponseRedactedFields:   []string{"$.ssn", "$.email", "$.phone"},
				Success:                  true,
				RowCount:                 50,
				DurationMs:               100,
			},
		},
		{
			name: "exfiltration limit exceeded",
			entry: MCPQueryAuditEntry{
				AuditID:                  "scenario-exfil",
				TenantID:                 "tenant-1",
				OrgID:                    "tenant-1",
				ClientID:                 "client-1",
				UserID:                   "user-1",
				ConnectorName:            "postgres",
				Operation:                "query",
				StatementHash:            "exfil-hash",
				RequestPoliciesEvaluated: 5,
				ExfilRowsReturned:        15000,
				ExfilExceeded:            true,
				ExfilLimitType:           "row_count",
				Success:                  false,
				DurationMs:               500,
			},
		},
		{
			name: "execute INSERT operation",
			entry: MCPQueryAuditEntry{
				AuditID:                  "scenario-insert",
				TenantID:                 "tenant-1",
				OrgID:                    "tenant-1",
				ClientID:                 "client-1",
				UserID:                   "user-1",
				ConnectorName:            "postgres",
				Operation:                "insert",
				StatementHash:            "insert-hash",
				RequestPoliciesEvaluated: 3,
				Success:                  true,
				RowCount:                 1,
				DurationMs:               25,
			},
		},
		{
			name: "execute UPDATE operation",
			entry: MCPQueryAuditEntry{
				AuditID:                  "scenario-update",
				TenantID:                 "tenant-1",
				OrgID:                    "tenant-1",
				ClientID:                 "client-1",
				UserID:                   "user-1",
				ConnectorName:            "postgres",
				Operation:                "update",
				StatementHash:            "update-hash",
				RequestPoliciesEvaluated: 3,
				Success:                  true,
				RowCount:                 5,
				DurationMs:               30,
			},
		},
		{
			name: "execute DELETE operation",
			entry: MCPQueryAuditEntry{
				AuditID:                  "scenario-delete",
				TenantID:                 "tenant-1",
				OrgID:                    "tenant-1",
				ClientID:                 "client-1",
				UserID:                   "user-1",
				ConnectorName:            "postgres",
				Operation:                "delete",
				StatementHash:            "delete-hash",
				RequestPoliciesEvaluated: 3,
				Success:                  true,
				RowCount:                 2,
				DurationMs:               15,
			},
		},
		{
			name: "connection error",
			entry: MCPQueryAuditEntry{
				AuditID:                  "scenario-error",
				TenantID:                 "tenant-1",
				OrgID:                    "tenant-1",
				ClientID:                 "client-1",
				UserID:                   "user-1",
				ConnectorName:            "postgres",
				Operation:                "query",
				StatementHash:            "error-hash",
				RequestPoliciesEvaluated: 0,
				Success:                  false,
				ErrorMessage:             "connection refused",
				DurationMs:               5,
			},
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock db: %v", err)
			}
			defer db.Close()

			fallbackPath := filepath.Join(os.TempDir(), "test-scenario-"+sc.name+".log")
			defer os.Remove(fallbackPath)

			auditQueue, _ := NewAuditQueue(AuditModeCompliance, 100, 1, db, fallbackPath)

			// v9 Phase 8 B2: WithOrgScope wrap requires BeginTx + set_config + INSERT + Commit.
			mock.ExpectBegin()
			mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
				WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectExec("INSERT INTO mcp_query_audits").
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectCommit()

			err = auditQueue.LogMCPQueryAudit(sc.entry)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			_ = auditQueue.Shutdown(ctx)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled mock expectations: %v", err)
			}
		})
	}
}
