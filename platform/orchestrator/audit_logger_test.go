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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestGenerateAuditID verifies audit ID generation
func TestGenerateAuditID(t *testing.T) {
	// Generate multiple IDs
	id1 := generateAuditID()
	id2 := generateAuditID()
	id3 := generateAuditID()

	// Verify IDs are non-empty
	if id1 == "" || id2 == "" || id3 == "" {
		t.Error("Generated audit IDs should not be empty")
	}

	// Verify IDs are unique
	if id1 == id2 || id2 == id3 || id1 == id3 {
		t.Error("Generated audit IDs should be unique")
	}

	// Verify ID format: "audit_<timestamp>_<random8chars>"
	if !strings.HasPrefix(id1, "audit_") {
		t.Errorf("Audit ID should start with 'audit_', got %s", id1)
	}

	// Verify structure: audit_NNNNNNNNNN_RRRRRRRR
	parts := strings.Split(id1, "_")
	if len(parts) != 3 {
		t.Errorf("Audit ID should have 3 parts separated by underscore, got %d parts in %s", len(parts), id1)
	}

	if parts[0] != "audit" {
		t.Errorf("First part should be 'audit', got %s", parts[0])
	}

	// Second part should be timestamp (numeric)
	if len(parts) > 1 {
		for _, c := range parts[1] {
			if c < '0' || c > '9' {
				t.Errorf("Timestamp part should be numeric, got %s", parts[1])
				break
			}
		}
	}

	// Third part should be 8-char random string
	if len(parts) > 2 && len(parts[2]) != 8 {
		t.Errorf("Random part should be 8 characters, got %d in %s", len(parts[2]), parts[2])
	}
}

// TestHashQuery verifies query hashing
func TestHashQuery(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{"Simple query", "What is the weather?"},
		{"Complex query", "Plan a 3-day trip to Paris with moderate budget"},
		{"Query with special chars", "How much is 5 + 3 = ?"},
		{"Empty query", ""},
		{"Long query", strings.Repeat("test query ", 100)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := hashQuery(tt.query)

			// Verify hash is non-empty
			if hash == "" {
				t.Error("Hash should not be empty")
			}

			// Verify same query produces same hash (deterministic)
			hash2 := hashQuery(tt.query)
			if hash != hash2 {
				t.Error("Same query should produce same hash")
			}

			// Verify different query produces different hash (for non-empty)
			if tt.query != "" {
				differentHash := hashQuery(tt.query + "different")
				if hash == differentHash {
					t.Error("Different queries should produce different hashes")
				}
			}

			// Verify hash is hex representation
			for _, c := range hash {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("Hash should contain only hex characters, got %c in %s", c, hash)
				}
			}
		})
	}
}

// TestTruncateResponse verifies response truncation
func TestTruncateResponse(t *testing.T) {
	tests := []struct {
		name     string
		response interface{}
		expectTruncated bool
	}{
		{
			name:     "Short response - no truncation",
			response: "Hello world",
			expectTruncated: false,
		},
		{
			name:     "Long response - truncate with ellipsis",
			response: strings.Repeat("This is a very long response that should be truncated ", 10),
			expectTruncated: true,
		},
		{
			name:     "Empty response",
			response: "",
			expectTruncated: false,
		},
		{
			name:     "Map response",
			response: map[string]string{"key": "value"},
			expectTruncated: false,
		},
		{
			name:     "Large map response",
			response: map[string]string{
				"key1": strings.Repeat("value", 50),
				"key2": strings.Repeat("value", 50),
				"key3": strings.Repeat("value", 50),
			},
			expectTruncated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateResponse(tt.response)

			// Verify result is a string
			if result == "" && tt.response != "" {
				// Empty result only valid for empty input
				t.Error("Expected non-empty result")
			}

			// Verify result never exceeds 200 chars + ellipsis
			maxLen := 203 // 200 + "..."
			if len(result) > maxLen {
				t.Errorf("Result length %d exceeds max length %d", len(result), maxLen)
			}

			// Verify truncation occurred when expected
			if tt.expectTruncated && !strings.HasSuffix(result, "...") {
				t.Error("Expected result to be truncated with ellipsis")
			}
		})
	}
}

// TestCalculateQueryComplexity verifies query complexity calculation
func TestCalculateQueryComplexity(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		expected   string
	}{
		{
			name:     "Simple query - low complexity",
			query:    "Hello",
			expected: "low",
		},
		{
			name:     "Single JOIN - medium complexity",
			query:    "SELECT * FROM users JOIN orders ON users.id = orders.user_id",
			expected: "medium",
		},
		{
			name:     "Multiple JOINs - high complexity",
			query:    "SELECT * FROM a JOIN b ON a.id = b.id JOIN c ON b.id = c.id JOIN d ON c.id = d.id",
			expected: "high",
		},
		{
			name:     "Empty query - low complexity",
			query:    "",
			expected: "low",
		},
		{
			name:     "No JOIN keyword - low complexity",
			query:    "Plan a trip to Paris for 3 days with moderate budget",
			expected: "low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateQueryComplexity(tt.query)

			if result != tt.expected {
				t.Errorf("Expected complexity %q, got %q", tt.expected, result)
			}

			// Verify result is one of the valid values
			validComplexities := map[string]bool{"low": true, "medium": true, "high": true}
			if !validComplexities[result] {
				t.Errorf("Invalid complexity value: %q", result)
			}
		})
	}
}

// TestContainsSensitiveAccess verifies sensitive access detection
func TestContainsSensitiveAccess(t *testing.T) {
	tests := []struct {
		name        string
		query       string
		expectSensitive bool
	}{
		{
			name:        "Contains password keyword",
			query:       "What is my password for the account?",
			expectSensitive: true,
		},
		{
			name:        "Contains social_security keyword (with underscore)",
			query:       "Show me the social_security number",
			expectSensitive: true,
		},
		{
			name:        "Contains credit_card keyword (with underscore)",
			query:       "What is the credit_card number?",
			expectSensitive: true,
		},
		{
			name:        "Contains API key keyword",
			query:       "Get the API key for authentication",
			expectSensitive: true,
		},
		{
			name:        "Normal query - no sensitive keywords",
			query:       "Plan a trip to Paris",
			expectSensitive: false,
		},
		{
			name:        "Contains 'secret' but in different context",
			query:       "Tell me a secret recipe for pasta",
			expectSensitive: true, // Function checks for "secret" keyword
		},
		{
			name:        "Empty query",
			query:       "",
			expectSensitive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsSensitiveAccess(tt.query)

			if result != tt.expectSensitive {
				t.Errorf("Expected sensitive=%v, got %v for query: %q", tt.expectSensitive, result, tt.query)
			}
		})
	}
}

// TestDetectComplianceFlags verifies compliance flag detection
func TestDetectComplianceFlags(t *testing.T) {
	// Create a simple audit logger without database
	logger := &AuditLogger{}

	tests := []struct {
		name          string
		req           OrchestratorRequest
		expectedFlags []string
	}{
		{
			name: "HIPAA relevant - patient query",
			req: OrchestratorRequest{
				Query: "Show me patient records for John Doe",
			},
			expectedFlags: []string{"hipaa_relevant"},
		},
		{
			name: "HIPAA relevant - medical query",
			req: OrchestratorRequest{
				Query: "What are the medical treatments available?",
			},
			expectedFlags: []string{"hipaa_relevant"},
		},
		{
			name: "GDPR applicable - EU tenant",
			req: OrchestratorRequest{
				Query: "Get customer data",
				User: UserContext{
					TenantID: "eu_customer123",
				},
			},
			expectedFlags: []string{"gdpr_applicable"},
		},
		{
			name: "SOX relevant - account query",
			req: OrchestratorRequest{
				Query: "Show account balances",
			},
			expectedFlags: []string{"sox_relevant"},
		},
		{
			name: "SOX relevant - transaction query",
			req: OrchestratorRequest{
				Query: "List all transactions for today",
			},
			expectedFlags: []string{"sox_relevant"},
		},
		{
			name: "PII access - SSN",
			req: OrchestratorRequest{
				Query: "What is the SSN for this user?",
			},
			expectedFlags: []string{"pii_access"},
		},
		{
			name: "PII access - email",
			req: OrchestratorRequest{
				Query: "Show me the email addresses",
			},
			expectedFlags: []string{"pii_access"},
		},
		{
			name: "PII access - phone",
			req: OrchestratorRequest{
				Query: "Get phone numbers from database",
			},
			expectedFlags: []string{"pii_access"},
		},
		{
			name: "Multiple flags - HIPAA + PII",
			req: OrchestratorRequest{
				Query: "Show patient email and medical history",
			},
			expectedFlags: []string{"hipaa_relevant", "pii_access"},
		},
		{
			name: "Multiple flags - GDPR + SOX",
			req: OrchestratorRequest{
				Query: "Get account transactions",
				User: UserContext{
					TenantID: "eu_bank456",
				},
			},
			expectedFlags: []string{"gdpr_applicable", "sox_relevant"},
		},
		{
			name: "No flags - normal query",
			req: OrchestratorRequest{
				Query: "What is the weather today?",
			},
			expectedFlags: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := logger.detectComplianceFlags(tt.req, nil)

			// Verify the number of flags
			if len(result) != len(tt.expectedFlags) {
				t.Errorf("Expected %d flags, got %d: %v", len(tt.expectedFlags), len(result), result)
			}

			// Verify each expected flag is present
			flagsMap := make(map[string]bool)
			for _, flag := range result {
				flagsMap[flag] = true
			}

			for _, expectedFlag := range tt.expectedFlags {
				if !flagsMap[expectedFlag] {
					t.Errorf("Expected flag %q not found in result: %v", expectedFlag, result)
				}
			}
		})
	}
}

// TestBatchWriter_Write verifies batch writing to database
func TestBatchWriter_Write(t *testing.T) {
	tests := []struct {
		name        string
		entries     []*AuditEntry
		setupMock   func(sqlmock.Sqlmock)
		expectError bool
	}{
		{
			name:    "Empty entries - no database operations",
			entries: []*AuditEntry{},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Empty batch still begins and commits transaction
				mock.ExpectBegin()
				mock.ExpectPrepare("INSERT INTO audit_logs")
				mock.ExpectCommit()
			},
			expectError: false,
		},
		{
			name: "Single entry - successful insert",
			entries: []*AuditEntry{
				{
					ID:             "audit_001",
					RequestID:      "req_001",
					Timestamp:      time.Now(),
					UserID:         1,
					UserEmail:      "test@example.com",
					UserRole:       "user",
					ClientID:       "client_001",
					TenantID:       "tenant_001",
					RequestType:    "query",
					Query:          "What is the weather?",
					QueryHash:      "abc123",
					PolicyDecision: "allowed",
					PolicyDetails:  map[string]interface{}{"risk_score": 0.1},
					Provider:       "openai",
					Model:          "gpt-4",
					ResponseTime:   150,
					TokensUsed:     100,
					Cost:           0.005,
					RedactedFields: []string{},
					ErrorMessage:   "",
					ResponseSample: "The weather is sunny",
					ComplianceFlags: []string{"gdpr_applicable"},
					SecurityMetrics: map[string]interface{}{"risk_score": 0.1},
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectPrepare("INSERT INTO audit_logs")
				mock.ExpectExec("INSERT INTO audit_logs").
					WithArgs(
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(),
					).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
			},
			expectError: false,
		},
		{
			name: "Multiple entries - batch insert",
			entries: []*AuditEntry{
				{
					ID:             "audit_002",
					RequestID:      "req_002",
					Timestamp:      time.Now(),
					UserID:         2,
					UserEmail:      "user2@example.com",
					UserRole:       "admin",
					ClientID:       "client_002",
					TenantID:       "tenant_002",
					RequestType:    "mutation",
					Query:          "Update user profile",
					QueryHash:      "def456",
					PolicyDecision: "allowed",
					PolicyDetails:  map[string]interface{}{"risk_score": 0.3},
					Provider:       "anthropic",
					Model:          "claude-3",
					ResponseTime:   200,
					TokensUsed:     150,
					Cost:           0.008,
					RedactedFields: []string{"email"},
					ErrorMessage:   "",
					ResponseSample: "Profile updated",
					ComplianceFlags: []string{},
					SecurityMetrics: map[string]interface{}{"risk_score": 0.3},
				},
				{
					ID:             "audit_003",
					RequestID:      "req_003",
					Timestamp:      time.Now(),
					UserID:         3,
					UserEmail:      "user3@example.com",
					UserRole:       "user",
					ClientID:       "client_003",
					TenantID:       "tenant_003",
					RequestType:    "query",
					Query:          "Get account balance",
					QueryHash:      "ghi789",
					PolicyDecision: "redacted",
					PolicyDetails:  map[string]interface{}{"risk_score": 0.6},
					Provider:       "openai",
					Model:          "gpt-4",
					ResponseTime:   180,
					TokensUsed:     120,
					Cost:           0.006,
					RedactedFields: []string{"account_number"},
					ErrorMessage:   "",
					ResponseSample: "Balance: [REDACTED]",
					ComplianceFlags: []string{"sox_relevant", "pii_access"},
					SecurityMetrics: map[string]interface{}{"risk_score": 0.6},
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectPrepare("INSERT INTO audit_logs")
				// First entry
				mock.ExpectExec("INSERT INTO audit_logs").
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
				// Second entry
				mock.ExpectExec("INSERT INTO audit_logs").
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(2, 1))
				mock.ExpectCommit()
			},
			expectError: false,
		},
		{
			name: "Transaction begin fails",
			entries: []*AuditEntry{
				{
					ID:        "audit_004",
					RequestID: "req_004",
					Timestamp: time.Now(),
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin().WillReturnError(fmt.Errorf("connection failed"))
			},
			expectError: true,
		},
		{
			name: "Prepare statement fails",
			entries: []*AuditEntry{
				{
					ID:        "audit_005",
					RequestID: "req_005",
					Timestamp: time.Now(),
				},
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectPrepare("INSERT INTO audit_logs").
					WillReturnError(fmt.Errorf("prepare failed"))
				mock.ExpectRollback()
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh db and mock for each test
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock DB: %v", err)
			}
			defer func() { _ = db.Close() }()

			// Setup mock expectations
			tt.setupMock(mock)

			// Create batch writer
			writer := &BatchWriter{
				db:        db,
				batchSize: 100,
				entries:   make([]*AuditEntry, 0),
			}

			// Execute write
			err = writer.Write(tt.entries)

			// Verify error expectation
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verify all mock expectations were met
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled mock expectations: %v", err)
			}
		})
	}
}

// TestBatchWriter_NilDatabase verifies batch writer handles nil database gracefully
func TestBatchWriter_NilDatabase(t *testing.T) {
	writer := &BatchWriter{
		db:        nil,
		batchSize: 100,
		entries:   make([]*AuditEntry, 0),
	}

	entries := []*AuditEntry{
		{
			ID:        "audit_001",
			RequestID: "req_001",
			Timestamp: time.Now(),
		},
	}

	// Should not error with nil database (graceful degradation)
	err := writer.Write(entries)
	if err != nil {
		t.Errorf("Expected nil database to be handled gracefully, got error: %v", err)
	}
}

// TestSearchAuditLogs verifies audit log searching
func TestSearchAuditLogs(t *testing.T) {
	tests := []struct {
		name        string
		criteria    interface{}
		setupMock   func(sqlmock.Sqlmock)
		expectCount int
		expectError bool
	}{
		{
			name: "Search by user email",
			criteria: struct {
				UserEmail   string
				ClientID    string
				StartTime   time.Time
				EndTime     time.Time
				RequestType string
				Limit       int
			}{
				UserEmail: "test@example.com",
				Limit:     10,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "request_id", "timestamp", "user_id", "user_email", "user_role",
					"client_id", "tenant_id", "request_type", "query", "policy_decision",
					"policy_details", "provider", "model", "response_time_ms", "tokens_used",
					"cost", "redacted_fields", "error_message", "compliance_flags",
				}).
					AddRow(
						"audit_001", "req_001", time.Now(), 1, "test@example.com", "user",
						"client_001", "tenant_001", "query", "test query", "allowed",
						[]byte(`{"risk_score": 0.1}`), "openai", "gpt-4", 150, 100,
						0.005, []byte(`[]`), "", []byte(`["gdpr_applicable"]`),
					)
				mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE (.+) user_email = (.+) ORDER BY timestamp DESC LIMIT").
					WithArgs("test@example.com").
					WillReturnRows(rows)
			},
			expectCount: 1,
			expectError: false,
		},
		{
			name: "Search by multiple criteria",
			criteria: struct {
				UserEmail   string
				ClientID    string
				StartTime   time.Time
				EndTime     time.Time
				RequestType string
				Limit       int
			}{
				UserEmail:   "admin@example.com",
				ClientID:    "client_002",
				RequestType: "mutation",
				Limit:       5,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "request_id", "timestamp", "user_id", "user_email", "user_role",
					"client_id", "tenant_id", "request_type", "query", "policy_decision",
					"policy_details", "provider", "model", "response_time_ms", "tokens_used",
					"cost", "redacted_fields", "error_message", "compliance_flags",
				}).
					AddRow(
						"audit_002", "req_002", time.Now(), 2, "admin@example.com", "admin",
						"client_002", "tenant_002", "mutation", "update query", "allowed",
						[]byte(`{"risk_score": 0.3}`), "anthropic", "claude-3", 200, 150,
						0.008, []byte(`["email"]`), "", []byte(`[]`),
					).
					AddRow(
						"audit_003", "req_003", time.Now(), 2, "admin@example.com", "admin",
						"client_002", "tenant_002", "mutation", "delete query", "blocked",
						[]byte(`{"risk_score": 0.8}`), "anthropic", "claude-3", 180, 120,
						0.006, []byte(`[]`), "", []byte(`["sox_relevant"]`),
					)
				mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE (.+) user_email = (.+) client_id = (.+) request_type = (.+) ORDER BY timestamp DESC LIMIT").
					WithArgs("admin@example.com", "client_002", "mutation").
					WillReturnRows(rows)
			},
			expectCount: 2,
			expectError: false,
		},
		{
			name: "Search with time range",
			criteria: struct {
				UserEmail   string
				ClientID    string
				StartTime   time.Time
				EndTime     time.Time
				RequestType string
				Limit       int
			}{
				StartTime: time.Now().Add(-24 * time.Hour),
				EndTime:   time.Now(),
				Limit:     100,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "request_id", "timestamp", "user_id", "user_email", "user_role",
					"client_id", "tenant_id", "request_type", "query", "policy_decision",
					"policy_details", "provider", "model", "response_time_ms", "tokens_used",
					"cost", "redacted_fields", "error_message", "compliance_flags",
				})
				mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE (.+) timestamp >= (.+) timestamp <= (.+) ORDER BY timestamp DESC LIMIT").
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(rows)
			},
			expectCount: 0,
			expectError: false,
		},
		{
			name: "Database query fails",
			criteria: struct {
				UserEmail   string
				ClientID    string
				StartTime   time.Time
				EndTime     time.Time
				RequestType string
				Limit       int
			}{
				UserEmail: "error@example.com",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT (.+) FROM audit_logs").
					WithArgs("error@example.com").
					WillReturnError(fmt.Errorf("database error"))
			},
			expectCount: 0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh db and mock for each test
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock DB: %v", err)
			}
			defer func() { _ = db.Close() }()

			logger := &AuditLogger{
				db: db,
			}

			// Setup mock expectations
			tt.setupMock(mock)

			// Execute search
			results, err := logger.SearchAuditLogs(tt.criteria)

			// Verify error expectation
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verify result count
			if !tt.expectError && len(results) != tt.expectCount {
				t.Errorf("Expected %d results, got %d", tt.expectCount, len(results))
			}

			// Verify all mock expectations were met
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled mock expectations: %v", err)
			}
		})
	}
}

// TestSearchAuditLogs_NilDatabase verifies search handles nil database gracefully
func TestSearchAuditLogs_NilDatabase(t *testing.T) {
	logger := &AuditLogger{
		db: nil,
	}

	criteria := struct {
		UserEmail   string
		ClientID    string
		StartTime   time.Time
		EndTime     time.Time
		RequestType string
		Limit       int
	}{
		UserEmail: "test@example.com",
	}

	// Should return empty results without error
	results, err := logger.SearchAuditLogs(criteria)
	if err != nil {
		t.Errorf("Expected nil database to be handled gracefully, got error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("Expected empty results for nil database, got %d results", len(results))
	}
}

// TestAuditLogger_IsHealthy verifies audit logger health check
func TestAuditLogger_IsHealthy(t *testing.T) {
	tests := []struct {
		name           string
		setupDB        func() *sql.DB
		expectHealthy  bool
	}{
		{
			name: "Healthy database connection",
			setupDB: func() *sql.DB {
				db, mock, _ := sqlmock.New(sqlmock.MonitorPingsOption(true))
				mock.ExpectPing().WillReturnError(nil)
				return db
			},
			expectHealthy: true,
		},
		{
			name: "Unhealthy database connection",
			setupDB: func() *sql.DB {
				db, mock, _ := sqlmock.New(sqlmock.MonitorPingsOption(true))
				mock.ExpectPing().WillReturnError(fmt.Errorf("connection timeout"))
				return db
			},
			expectHealthy: false,
		},
		{
			name: "Nil database - always healthy (no-op logger)",
			setupDB: func() *sql.DB {
				return nil
			},
			expectHealthy: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := tt.setupDB()
			if db != nil {
				defer func() { _ = db.Close() }()
			}

			logger := &AuditLogger{
				db: db,
			}

			result := logger.IsHealthy()
			if result != tt.expectHealthy {
				t.Errorf("Expected healthy=%v, got %v", tt.expectHealthy, result)
			}
		})
	}
}

// TestNewAuditLogger_InvalidDatabase verifies logger handles database failures gracefully
func TestNewAuditLogger_InvalidDatabase(t *testing.T) {
	// Test with invalid database URL - should return no-op logger
	logger := NewAuditLogger("invalid-database-url")

	if logger == nil {
		t.Error("NewAuditLogger should not return nil even with invalid database")
	}

	// No-op logger should have shutdown channel
	if logger.shutdownChan == nil {
		t.Error("No-op logger should have shutdown channel")
	}
}

// TestCalculateSecurityMetrics verifies security metrics calculation
func TestCalculateSecurityMetrics(t *testing.T) {
	logger := &AuditLogger{}

	tests := []struct {
		name         string
		req          OrchestratorRequest
		policyResult *PolicyEvaluationResult
		expectedMetrics map[string]interface{}
	}{
		{
			name: "Low complexity, no sensitive access",
			req: OrchestratorRequest{
				Query: "What is the weather?",
			},
			policyResult: &PolicyEvaluationResult{
				RiskScore:       0.1,
				AppliedPolicies: []string{"basic_policy"},
			},
			expectedMetrics: map[string]interface{}{
				"risk_score":       0.1,
				"policies_applied": 1,
				"query_complexity": "low",
				"sensitive_access": false,
			},
		},
		{
			name: "Medium complexity query",
			req: OrchestratorRequest{
				Query: "SELECT * FROM users JOIN orders ON users.id = orders.user_id",
			},
			policyResult: &PolicyEvaluationResult{
				RiskScore:       0.5,
				AppliedPolicies: []string{"data_access", "sql_check"},
			},
			expectedMetrics: map[string]interface{}{
				"risk_score":       0.5,
				"policies_applied": 2,
				"query_complexity": "medium",
				"sensitive_access": false,
			},
		},
		{
			name: "High risk with sensitive access",
			req: OrchestratorRequest{
				Query: "Show me all passwords in the system",
			},
			policyResult: &PolicyEvaluationResult{
				RiskScore:       0.9,
				AppliedPolicies: []string{"high_risk", "sensitive_data", "audit_required"},
			},
			expectedMetrics: map[string]interface{}{
				"risk_score":       0.9,
				"policies_applied": 3,
				"query_complexity": "low",
				"sensitive_access": true,
			},
		},
		{
			name: "High complexity query with joins",
			req: OrchestratorRequest{
				Query: "SELECT * FROM a JOIN b ON a.id = b.id JOIN c ON b.id = c.id JOIN d ON c.id = d.id",
			},
			policyResult: &PolicyEvaluationResult{
				RiskScore:       0.6,
				AppliedPolicies: []string{"complex_query", "rate_limit"},
			},
			expectedMetrics: map[string]interface{}{
				"risk_score":       0.6,
				"policies_applied": 2,
				"query_complexity": "high",
				"sensitive_access": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := logger.calculateSecurityMetrics(tt.req, tt.policyResult)

			// Verify all expected metrics are present and correct
			for key, expectedValue := range tt.expectedMetrics {
				actualValue, ok := result[key]
				if !ok {
					t.Errorf("Expected metric %q not found in result", key)
					continue
				}

				if actualValue != expectedValue {
					t.Errorf("Metric %q: expected %v, got %v", key, expectedValue, actualValue)
				}
			}

			// Verify no unexpected metrics
			if len(result) != len(tt.expectedMetrics) {
				t.Errorf("Expected %d metrics, got %d: %v", len(tt.expectedMetrics), len(result), result)
			}
		})
	}
}

// TestLogSuccessfulRequest tests logging successful requests
func TestLogSuccessfulRequest(t *testing.T) {
	logger := &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}

	req := OrchestratorRequest{
		RequestID:   "test-req-123",
		Query:       "Test query",
		RequestType: "test",
		User: UserContext{
			ID:       1,
			Email:    "test@example.com",
			Role:     "user",
			TenantID: "test-tenant",
		},
		Client: ClientContext{
			ID: "test-client",
		},
	}

	policyResult := &PolicyEvaluationResult{
		Allowed:         true,
		RiskScore:       0.3,
		AppliedPolicies: []string{"policy1"},
	}

	providerInfo := &ProviderInfo{
		Provider:       "openai",
		Model:          "gpt-4",
		ResponseTimeMs: 150,
		TokensUsed:     100,
		Cost:           0.005,
	}

	ctx := context.Background()
	entry := logger.LogSuccessfulRequest(ctx, req, "test response", policyResult, providerInfo)

	// Verify entry fields
	if entry.RequestID != "test-req-123" {
		t.Errorf("Expected request ID 'test-req-123', got %q", entry.RequestID)
	}

	if entry.TenantID != "test-tenant" {
		t.Errorf("Expected tenant ID 'test-tenant', got %q", entry.TenantID)
	}

	if entry.Provider != "openai" {
		t.Errorf("Expected provider 'openai', got %q", entry.Provider)
	}

	if entry.PolicyDecision != "allowed" {
		t.Errorf("Expected policy decision 'allowed', got %q", entry.PolicyDecision)
	}

	// Verify entry was queued
	select {
	case queuedEntry := <-logger.auditQueue:
		if queuedEntry.RequestID != entry.RequestID {
			t.Error("Queued entry does not match returned entry")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Entry was not queued")
	}
}

// TestLogBlockedRequest tests logging blocked requests
func TestLogBlockedRequest(t *testing.T) {
	logger := &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}

	req := OrchestratorRequest{
		RequestID:   "test-req-blocked",
		Query:       "Blocked query",
		RequestType: "test",
		User: UserContext{
			ID:       2,
			Email:    "blocked@example.com",
			Role:     "restricted",
			TenantID: "test-tenant",
		},
		Client: ClientContext{
			ID: "test-client",
		},
	}

	policyResult := &PolicyEvaluationResult{
		Allowed:         false,
		RiskScore:       0.9,
		AppliedPolicies: []string{"block_policy"},
	}

	// LogBlockedRequest doesn't return a value, just enqueues
	ctx := context.Background()
	logger.LogBlockedRequest(ctx, req, policyResult)

	// Verify entry was queued
	select {
	case entry := <-logger.auditQueue:
		if entry.PolicyDecision != "blocked" {
			t.Errorf("Expected policy decision 'blocked', got %q", entry.PolicyDecision)
		}
		if entry.RequestID != "test-req-blocked" {
			t.Errorf("Expected request ID 'test-req-blocked', got %q", entry.RequestID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Entry was not queued")
	}
}

// TestLogFailedRequest tests logging failed requests
func TestLogFailedRequest(t *testing.T) {
	logger := &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}

	req := OrchestratorRequest{
		RequestID:   "test-req-failed",
		Query:       "Failed query",
		RequestType: "test",
		User: UserContext{
			ID:       3,
			Email:    "user@example.com",
			Role:     "user",
			TenantID: "test-tenant",
		},
		Client: ClientContext{
			ID: "test-client",
		},
	}

	err := fmt.Errorf("API request failed: timeout")

	// LogFailedRequest doesn't return a value, just enqueues
	ctx := context.Background()
	logger.LogFailedRequest(ctx, req, err)

	// Verify entry was queued
	select {
	case entry := <-logger.auditQueue:
		if entry.PolicyDecision != "error" {
			t.Errorf("Expected policy decision 'error', got %q", entry.PolicyDecision)
		}
		if entry.ErrorMessage != err.Error() {
			t.Errorf("Expected error message %q, got %q", err.Error(), entry.ErrorMessage)
		}
		if entry.RequestID != "test-req-failed" {
			t.Errorf("Expected request ID 'test-req-failed', got %q", entry.RequestID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Entry was not queued")
	}
}

// TestBatchWriter_Add tests adding entries to batch writer
func TestBatchWriter_Add(t *testing.T) {
	// Test with nil database - it still adds to batch, just won't flush to DB
	bw := NewBatchWriter(nil, 10)

	entry := &AuditEntry{
		ID:        "test-1",
		RequestID: "req-1",
		Timestamp: time.Now(),
	}

	// Should not panic with nil database
	bw.Add(entry)

	// Verify entry was added to batch (it batches even with nil db)
	bw.mu.Lock()
	count := len(bw.entries)
	bw.mu.Unlock()

	if count != 1 {
		t.Errorf("Expected 1 entry in batch writer, got %d", count)
	}
}

// TestEnqueueEntry tests the enqueueEntry method
func TestEnqueueEntry(t *testing.T) {
	tests := []struct {
		name          string
		queueSize     int
		entriesToAdd  int
		expectDropped bool
	}{
		{
			name:          "normal queueing",
			queueSize:     100,
			entriesToAdd:  10,
			expectDropped: false,
		},
		{
			name:          "queue full - entries dropped",
			queueSize:     2,
			entriesToAdd:  5,
			expectDropped: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &AuditLogger{
				auditQueue:   make(chan *AuditEntry, tt.queueSize),
				shutdownChan: make(chan struct{}),
			}

			// Add entries
			for i := 0; i < tt.entriesToAdd; i++ {
				entry := &AuditEntry{
					ID:        fmt.Sprintf("entry-%d", i),
					RequestID: fmt.Sprintf("req-%d", i),
					Timestamp: time.Now(),
				}
				logger.enqueueEntry(entry)
			}

			// Check how many were actually queued
			queuedCount := len(logger.auditQueue)

			if tt.expectDropped {
				if queuedCount >= tt.entriesToAdd {
					t.Errorf("Expected some entries to be dropped, but all %d were queued", queuedCount)
				}
			} else {
				if queuedCount != tt.entriesToAdd {
					t.Errorf("Expected %d entries to be queued, got %d", tt.entriesToAdd, queuedCount)
				}
			}
		})
	}
}

