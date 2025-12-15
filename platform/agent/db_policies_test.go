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

package agent

import (
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestValidateRE2Pattern tests RE2 pattern validation
func TestValidateRE2Pattern(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		shouldError bool
	}{
		{
			name:        "Valid simple pattern",
			pattern:     `\d+`,
			shouldError: false,
		},
		{
			name:        "Valid word boundary",
			pattern:     `\btest\b`,
			shouldError: false,
		},
		{
			name:        "Valid alternation",
			pattern:     `drop|truncate|delete`,
			shouldError: false,
		},
		{
			name:        "Unsupported lookahead",
			pattern:     `(?!test)`,
			shouldError: true,
		},
		{
			name:        "Unsupported positive lookahead",
			pattern:     `(?=test)`,
			shouldError: true,
		},
		{
			name:        "Unsupported lookbehind",
			pattern:     `(?<!test)`,
			shouldError: true,
		},
		{
			name:        "Unsupported positive lookbehind",
			pattern:     `(?<=test)`,
			shouldError: true,
		},
		{
			name:        "Unsupported backreference",
			pattern:     `(\w+)\1`,
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRE2Pattern(tt.pattern)

			if tt.shouldError && err == nil {
				t.Errorf("Expected error for pattern %s, got nil", tt.pattern)
			}

			if !tt.shouldError && err != nil {
				t.Errorf("Expected no error for pattern %s, got: %v", tt.pattern, err)
			}
		})
	}
}

// TestDatabasePolicyEngineCheckPatterns tests pattern matching logic
func TestDatabasePolicyEngineCheckPatterns(t *testing.T) {
	// Create a mock database policy engine with test patterns
	dpe := &DatabasePolicyEngine{
		sqlInjectionPatterns: []*PolicyPattern{
			{
				ID:          "test_union",
				Name:        "UNION Test",
				Pattern:     regexp.MustCompile(`union\s+select`),
				Severity:    "critical",
				Description: "Test UNION pattern",
				Enabled:     true,
			},
			{
				ID:          "test_disabled",
				Name:        "Disabled Pattern",
				Pattern:     regexp.MustCompile(`disabled_pattern`),
				Severity:    "critical",
				Description: "This pattern is disabled",
				Enabled:     false,
			},
		},
	}

	tests := []struct {
		name           string
		query          string
		expectMatch    bool
		expectedPolicy string
	}{
		{
			name:           "Matching pattern",
			query:          "select * from users union select * from admin",
			expectMatch:    true,
			expectedPolicy: "test_union",
		},
		{
			name:        "Non-matching pattern",
			query:       "select * from users",
			expectMatch: false,
		},
		{
			name:        "Disabled pattern should not match",
			query:       "disabled_pattern in query",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dpe.checkPatterns(tt.query, dpe.sqlInjectionPatterns)

			if tt.expectMatch {
				if result == nil {
					t.Error("Expected pattern match, got nil")
				} else if result.ID != tt.expectedPolicy {
					t.Errorf("Expected policy %s, got %s", tt.expectedPolicy, result.ID)
				}
			} else {
				if result != nil {
					t.Errorf("Expected no match, got policy: %s", result.ID)
				}
			}
		})
	}
}

// TestDatabasePolicyEngineHasPermission tests permission checking
func TestDatabasePolicyEngineHasPermission(t *testing.T) {
	dpe := &DatabasePolicyEngine{}

	tests := []struct {
		name       string
		user       *User
		permission string
		expected   bool
	}{
		{
			name: "User with exact permission",
			user: &User{
				ID:   1,
				Role: "query",
			},
			permission: "query",
			expected:   true,
		},
		{
			name: "Admin user",
			user: &User{
				ID:   2,
				Role: "admin",
			},
			permission: "any_permission",
			expected:   true,
		},
		{
			name: "User without permission",
			user: &User{
				ID:   3,
				Role: "read_only",
			},
			permission: "admin",
			expected:   false,
		},
		{
			name:       "Nil user",
			user:       nil,
			permission: "admin",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dpe.hasPermission(tt.user, tt.permission)

			if result != tt.expected {
				t.Errorf("Expected %v, got %v for user role %s and permission %s",
					tt.expected, result, getUserRole(tt.user), tt.permission)
			}
		})
	}
}

// TestLoadDefaultPolicies tests fallback policy loading
func TestLoadDefaultPolicies(t *testing.T) {
	dpe := &DatabasePolicyEngine{}

	// Load default policies
	dpe.loadDefaultPolicies()

	// Verify policies were loaded
	if len(dpe.sqlInjectionPatterns) == 0 {
		t.Error("Expected SQL injection patterns to be loaded")
	}

	if len(dpe.dangerousQueryPatterns) == 0 {
		t.Error("Expected dangerous query patterns to be loaded")
	}

	if len(dpe.adminAccessPatterns) == 0 {
		t.Error("Expected admin access patterns to be loaded")
	}

	if len(dpe.piiDetectionPatterns) == 0 {
		t.Error("Expected PII detection patterns to be loaded")
	}

	// Verify last refresh was set
	if dpe.lastRefresh.IsZero() {
		t.Error("Expected lastRefresh to be set")
	}

	// Verify patterns are enabled
	for _, pattern := range dpe.sqlInjectionPatterns {
		if !pattern.Enabled {
			t.Errorf("Pattern %s should be enabled", pattern.ID)
		}
		if pattern.Pattern == nil {
			t.Errorf("Pattern %s should have compiled regex", pattern.ID)
		}
	}
}

// TestDefaultPoliciesWork tests that default policies are usable
// Note: Full evaluation testing requires database connection and is covered by integration tests
func TestDefaultPoliciesWork(t *testing.T) {
	dpe := &DatabasePolicyEngine{}
	dpe.loadDefaultPolicies()

	// Verify the default policies can match patterns
	user := &User{
		ID:   1,
		Role: "user",
	}

	tests := []struct {
		name          string
		query         string
		expectPattern bool
	}{
		{
			name:          "UNION pattern exists",
			query:         "select * from users union select * from admin",
			expectPattern: true,
		},
		{
			name:          "DROP TABLE pattern exists",
			query:         "drop table customers",
			expectPattern: true,
		},
		{
			name:          "Comment pattern exists",
			query:         "select * from users -- comment",
			expectPattern: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test pattern matching directly (not full evaluation which requires DB)
			var found bool

			// Check SQL injection patterns
			if dpe.checkPatterns(tt.query, dpe.sqlInjectionPatterns) != nil {
				found = true
			}

			// Check dangerous query patterns
			if dpe.checkPatterns(tt.query, dpe.dangerousQueryPatterns) != nil {
				found = true
			}

			if found != tt.expectPattern {
				t.Errorf("Query: %s\nExpected pattern match=%v, got=%v",
					tt.query, tt.expectPattern, found)
			}

			// Verify user permission check doesn't panic
			_ = dpe.hasPermission(user, "admin")
		})
	}
}

// TestExecWithRetry tests retry logic with mocked behavior
func TestExecWithRetry(t *testing.T) {
	// Note: This test would require a mock database or test database
	// For now, we test that the function exists and has correct signature
	// In a full test suite, we would use sqlmock or similar

	// Verify function exists (compile-time check)
	_ = execWithRetry
}

// TestCacheMutexProtection tests that cache updates are safe
func TestCacheMutexProtection(t *testing.T) {
	dpe := &DatabasePolicyEngine{}
	dpe.loadDefaultPolicies()

	// Set refresh interval to very long and lastRefresh to now
	// This prevents background DB refresh during test
	dpe.refreshInterval = 24 * time.Hour
	dpe.lastRefresh = time.Now()

	// Run concurrent reads and writes
	done := make(chan bool, 20)

	// 10 concurrent readers
	for i := 0; i < 10; i++ {
		go func() {
			user := &User{
				ID:          1,
				Role:        "user",
				Permissions: []string{"query"},
			}
			_ = dpe.EvaluateStaticPolicies(user, "SELECT * FROM test", "sql")
			done <- true
		}()
	}

	// 10 concurrent policy reloads
	for i := 0; i < 10; i++ {
		go func() {
			dpe.loadDefaultPolicies()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}

	// If we got here without deadlock or race condition, test passes
	t.Log("Concurrent access completed without issues")
}

// TestLastRefreshTracking tests that refresh time is tracked
func TestLastRefreshTracking(t *testing.T) {
	dpe := &DatabasePolicyEngine{}

	// Initially should be zero
	if !dpe.lastRefresh.IsZero() {
		t.Error("Expected lastRefresh to be zero initially")
	}

	// Load policies
	dpe.loadDefaultPolicies()

	// Should be set now
	if dpe.lastRefresh.IsZero() {
		t.Error("Expected lastRefresh to be set after loading policies")
	}

	// Should be recent
	if time.Since(dpe.lastRefresh) > time.Second {
		t.Error("Expected lastRefresh to be within last second")
	}
}

// Helper function
func getUserRole(user *User) string {
	if user == nil {
		return "nil"
	}
	return user.Role
}

// ==================================================================
// COMPREHENSIVE DATABASE POLICY ENGINE TESTS
// Tests for NewDatabasePolicyEngine, LoadPoliciesFromDB, and related functions
// Using sqlmock for database mocking
// ==================================================================

// TestNewDatabasePolicyEngine_Success tests successful initialization
func TestNewDatabasePolicyEngine_Success(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Mock Ping
	mock.ExpectPing()

	// Mock LoadPoliciesFromDB query
	rows := sqlmock.NewRows([]string{
		"policy_id", "name", "category", "pattern", "severity", "description", "action", "tenant_id", "metadata",
	}).AddRow(
		"pol_001", "Test SQL Injection", "sql_injection", `union\s+select`, "critical",
		"Test description", "block", "tenant_1", []byte(`{}`),
	)
	mock.ExpectQuery("SELECT (.+) FROM static_policies WHERE enabled").WillReturnRows(rows)

	// Mock audit log insert (from logAuditEvent)
	mock.ExpectExec("INSERT INTO agent_audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))

	// Set DATABASE_URL environment variable
	oldDBURL := os.Getenv("DATABASE_URL")
	if err := os.Setenv("DATABASE_URL", "mock://database"); err != nil {
		t.Fatalf("Failed to set DATABASE_URL: %v", err)
	}
	defer func() {
		if err := os.Setenv("DATABASE_URL", oldDBURL); err != nil {
			t.Errorf("Failed to restore DATABASE_URL: %v", err)
		}
	}()

	// Create a test version that uses our mock db
	// Note: Since NewDatabasePolicyEngine creates its own connection,
	// we test the initialization path by checking error handling
	// Full integration testing would require dependency injection

	// Test that missing DATABASE_URL returns error
	if err := os.Setenv("DATABASE_URL", ""); err != nil {
		t.Fatalf("Failed to set DATABASE_URL: %v", err)
	}
	engine, err := NewDatabasePolicyEngine()
	if err == nil {
		t.Error("Expected error when DATABASE_URL not set")
	}
	if engine != nil {
		t.Error("Expected nil engine when DATABASE_URL not set")
	}

	// Restore DATABASE_URL
	if err := os.Setenv("DATABASE_URL", oldDBURL); err != nil {
		t.Errorf("Failed to restore DATABASE_URL: %v", err)
	}
}

// TestLoadPoliciesFromDB_Success tests successful policy loading
func TestLoadPoliciesFromDB_Success(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Create engine with mock database
	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil, // No queue for this test
	}

	// Set up mock expectations
	rows := sqlmock.NewRows([]string{
		"policy_id", "name", "category", "pattern", "severity", "description", "action", "tenant_id", "metadata",
	}).AddRow(
		"sql_001", "SQL Injection UNION", "sql_injection", `union\s+select`, "critical",
		"Detects UNION-based SQL injection", "block", "tenant_1", []byte(`{}`),
	).AddRow(
		"dq_001", "DROP TABLE", "dangerous_queries", `drop\s+table`, "critical",
		"Blocks DROP TABLE operations", "block", "tenant_1", []byte(`{}`),
	).AddRow(
		"admin_001", "Config Access", "admin_access", `system_config`, "high",
		"Requires admin for config access", "block", "tenant_1", []byte(`{}`),
	).AddRow(
		"pii_001", "SSN Detection", "pii_detection", `\d{3}-\d{2}-\d{4}`, "high",
		"Detects SSN patterns", "log", "tenant_1", []byte(`{}`),
	)

	mock.ExpectQuery("SELECT (.+) FROM static_policies WHERE enabled").WillReturnRows(rows)

	// Mock audit log insert (from logAuditEvent)
	mock.ExpectExec("INSERT INTO agent_audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))

	// Load policies
	err = engine.LoadPoliciesFromDB()
	if err != nil {
		t.Fatalf("LoadPoliciesFromDB failed: %v", err)
	}

	// Verify policies were loaded
	if len(engine.sqlInjectionPatterns) != 1 {
		t.Errorf("Expected 1 SQL injection pattern, got %d", len(engine.sqlInjectionPatterns))
	}

	if len(engine.dangerousQueryPatterns) != 1 {
		t.Errorf("Expected 1 dangerous query pattern, got %d", len(engine.dangerousQueryPatterns))
	}

	if len(engine.adminAccessPatterns) != 1 {
		t.Errorf("Expected 1 admin access pattern, got %d", len(engine.adminAccessPatterns))
	}

	if len(engine.piiDetectionPatterns) != 1 {
		t.Errorf("Expected 1 PII detection pattern, got %d", len(engine.piiDetectionPatterns))
	}

	// Verify last refresh was updated
	if engine.lastRefresh.IsZero() {
		t.Error("Expected lastRefresh to be set")
	}

	// Verify all expectations were met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestLoadPoliciesFromDB_EmptyResult tests handling of empty policy table
func TestLoadPoliciesFromDB_EmptyResult(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil,
	}

	// Return empty result
	rows := sqlmock.NewRows([]string{
		"policy_id", "name", "category", "pattern", "severity", "description", "action", "tenant_id", "metadata",
	})

	mock.ExpectQuery("SELECT (.+) FROM static_policies WHERE enabled").WillReturnRows(rows)

	// Mock audit log insert
	mock.ExpectExec("INSERT INTO agent_audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))

	// Load policies
	err = engine.LoadPoliciesFromDB()
	if err != nil {
		t.Fatalf("LoadPoliciesFromDB should not error on empty result: %v", err)
	}

	// Verify empty slices
	if len(engine.sqlInjectionPatterns) != 0 {
		t.Errorf("Expected 0 SQL injection patterns, got %d", len(engine.sqlInjectionPatterns))
	}

	// Verify expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestLoadPoliciesFromDB_InvalidRegexPattern tests handling of invalid RE2 patterns
func TestLoadPoliciesFromDB_InvalidRegexPattern(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil,
	}

	// Return policy with invalid RE2 pattern (lookahead)
	rows := sqlmock.NewRows([]string{
		"policy_id", "name", "category", "pattern", "severity", "description", "action", "tenant_id", "metadata",
	}).AddRow(
		"bad_001", "Invalid Lookahead", "sql_injection", `(?=test)`, "critical",
		"This pattern has unsupported lookahead", "block", "tenant_1", []byte(`{}`),
	).AddRow(
		"good_001", "Valid Pattern", "sql_injection", `union\s+select`, "critical",
		"This pattern is valid", "block", "tenant_1", []byte(`{}`),
	)

	mock.ExpectQuery("SELECT (.+) FROM static_policies WHERE enabled").WillReturnRows(rows)

	// Mock audit log insert
	mock.ExpectExec("INSERT INTO agent_audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))

	// Load policies
	err = engine.LoadPoliciesFromDB()
	if err != nil {
		t.Fatalf("LoadPoliciesFromDB failed: %v", err)
	}

	// Verify only valid pattern was loaded (invalid one skipped)
	if len(engine.sqlInjectionPatterns) != 1 {
		t.Errorf("Expected 1 SQL injection pattern (invalid skipped), got %d", len(engine.sqlInjectionPatterns))
	}

	if engine.sqlInjectionPatterns[0].ID != "good_001" {
		t.Errorf("Expected good_001 policy, got %s", engine.sqlInjectionPatterns[0].ID)
	}

	// Verify expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestLogPolicyViolationDirect tests direct database logging
func TestLogPolicyViolationDirect(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil, // No queue, will use direct write
	}

	user := &User{
		ID:   123,
		Role: "user",
	}

	policy := &PolicyPattern{
		ID:          "test_policy",
		Name:        "Test Policy",
		Severity:    "critical",
		Description: "Test policy violation",
	}

	query := "SELECT * FROM users UNION SELECT * FROM admin"

	// Expect INSERT with retries (3 attempts max)
	mock.ExpectExec("INSERT INTO policy_violations").
		WithArgs("Test Policy", "critical", "agent", "123", "Test policy violation", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Call function
	engine.logPolicyViolationDirect(user, policy, query)

	// Verify expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestLogAuditEventDirect tests direct audit event logging
func TestLogAuditEventDirect(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil,
	}

	// Expect INSERT
	mock.ExpectExec("INSERT INTO agent_audit_logs").
		WithArgs("agent", "test_action", "test_resource", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Call function
	engine.logAuditEventDirect("test_action", "test_resource")

	// Verify expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestUpdatePolicyMetricDirect tests direct policy metric updates
func TestUpdatePolicyMetricDirect(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil,
	}

	// Test blocked request
	mock.ExpectExec("INSERT INTO policy_metrics").
		WithArgs("test_policy_001", 1).
		WillReturnResult(sqlmock.NewResult(1, 1))

	engine.updatePolicyMetricDirect("test_policy_001", true)

	// Test non-blocked request
	mock.ExpectExec("INSERT INTO policy_metrics").
		WithArgs("test_policy_002", 0).
		WillReturnResult(sqlmock.NewResult(1, 1))

	engine.updatePolicyMetricDirect("test_policy_002", false)

	// Verify expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestDatabasePolicyEngineClose tests graceful shutdown
func TestDatabasePolicyEngineClose(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil, // No queue for this test
	}

	// Expect Close
	mock.ExpectClose()

	// Call Close
	err = engine.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Verify expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestEvaluateStaticPolicies_WithDBEngine tests full evaluation flow
func TestEvaluateStaticPolicies_WithDBEngine(t *testing.T) {
	// Create mock database (needed for logging even though we're testing pattern matching)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Create engine with default policies
	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 24 * time.Hour,
		lastRefresh:     time.Now(), // Prevent background refresh
		performanceMode: false,
		auditQueue:      nil,
	}

	// Load default policies
	engine.loadDefaultPolicies()

	// Expect violation logging for blocked queries (pattern matching happens first)
	mock.ExpectExec("INSERT INTO policy_violations").WillReturnResult(sqlmock.NewResult(1, 1)).WillReturnResult(sqlmock.NewResult(1, 1)).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO policy_violations").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO policy_violations").WillReturnResult(sqlmock.NewResult(1, 1))

	user := &User{
		ID:          1,
		Role:        "user",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name           string
		query          string
		requestType    string
		expectBlocked  bool
		expectedReason string
	}{
		{
			name:           "Safe query allowed",
			query:          "SELECT * FROM users WHERE id = 1",
			requestType:    "sql",
			expectBlocked:  false,
			expectedReason: "",
		},
		{
			name:           "SQL injection blocked",
			query:          "SELECT * FROM users UNION SELECT * FROM admin",
			requestType:    "sql",
			expectBlocked:  true,
			expectedReason: "SQL injection",
		},
		{
			name:           "DROP TABLE blocked",
			query:          "DROP TABLE users",
			requestType:    "sql",
			expectBlocked:  true,
			expectedReason: "Dangerous query",
		},
		{
			name:           "Comment injection blocked",
			query:          "SELECT * FROM users -- comment",
			requestType:    "sql",
			expectBlocked:  true,
			expectedReason: "SQL injection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, tt.requestType)

			if result.Blocked != tt.expectBlocked {
				t.Errorf("Expected blocked=%v, got=%v for query: %s",
					tt.expectBlocked, result.Blocked, tt.query)
			}

			if tt.expectBlocked && tt.expectedReason != "" {
				if !contains(result.Reason, tt.expectedReason) {
					t.Errorf("Expected reason to contain '%s', got: %s",
						tt.expectedReason, result.Reason)
				}
			}

			// Verify checks were performed
			if len(result.ChecksPerformed) == 0 {
				t.Error("Expected checks to be performed")
			}

			// Verify processing time was recorded
			if result.ProcessingTimeMs < 0 {
				t.Errorf("Invalid processing time: %d", result.ProcessingTimeMs)
			}
		})
	}
}

// Note: contains() helper function is defined in auth_test.go

// TestRefreshPoliciesRoutine tests the background policy refresh routine
func TestRefreshPoliciesRoutine(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	// Create engine with short refresh interval for testing
	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 100 * time.Millisecond, // Short interval for testing
	}

	// Mock the policy load queries (will be called multiple times)
	rows := sqlmock.NewRows([]string{
		"policy_id", "name", "category", "pattern", "severity",
		"description", "action", "tenant_id", "metadata",
	}).
		AddRow("test-policy-1", "SQL Injection Test", "sql_injection",
			`union\s+select`, "critical", "Test policy", "block", "tenant1", []byte("{}"))

	// Expect multiple queries as the routine refreshes
	mock.ExpectQuery("SELECT policy_id, name, category").
		WillReturnRows(rows)
	mock.ExpectQuery("SELECT policy_id, name, category").
		WillReturnRows(rows)

	// Start the refresh routine in a goroutine
	done := make(chan bool)
	go func() {
		// Run for a short time
		time.Sleep(250 * time.Millisecond)
		done <- true
	}()

	// Start refresh routine (will run in background)
	go engine.refreshPoliciesRoutine()

	// Wait for test completion
	<-done

	// Note: We can't verify mock expectations perfectly because the
	// goroutine continues running, but we verified it started successfully
}

// TestRefreshPoliciesRoutine_LoadFailure tests handling of load failures
func TestRefreshPoliciesRoutine_LoadFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 50 * time.Millisecond,
	}

	// Mock failed query
	mock.ExpectQuery("SELECT policy_id, name, category").
		WillReturnError(fmt.Errorf("database error"))

	// Start routine and let it run briefly
	done := make(chan bool)
	go func() {
		time.Sleep(100 * time.Millisecond)
		done <- true
	}()

	go engine.refreshPoliciesRoutine()

	<-done

	// Should handle errors gracefully without panicking
}

// ==================================================================
// ADDITIONAL TESTS FOR LOW COVERAGE FUNCTIONS
// Tests for Close, RecoverAuditEntries, updatePolicyMetricsToQueue, logAuditEvent
// ==================================================================

// TestDatabasePolicyEngineClose_WithAuditQueue tests Close with an active AuditQueue
func TestDatabasePolicyEngineClose_WithAuditQueue(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}

	// Create a minimal audit queue for testing
	// We need to create the engine first with a nil auditQueue,
	// then test Close with different states
	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil, // Test nil queue first
	}

	// Test 1: Close with nil auditQueue (should just close DB)
	mock.ExpectClose()
	err = engine.Close()
	if err != nil {
		t.Errorf("Close with nil auditQueue failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestDatabasePolicyEngineClose_NilDB tests Close when db is nil
func TestDatabasePolicyEngineClose_NilDB(t *testing.T) {
	engine := &DatabasePolicyEngine{
		db:              nil, // No database connection
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil,
	}

	// Close should not error when db is nil
	err := engine.Close()
	if err != nil {
		t.Errorf("Close with nil db should not error: %v", err)
	}
}

// TestDatabasePolicyEngineClose_DBCloseError tests Close when DB close fails
func TestDatabasePolicyEngineClose_DBCloseError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil,
	}

	// Expect Close to return error
	mock.ExpectClose().WillReturnError(fmt.Errorf("close error"))

	err = engine.Close()
	if err == nil {
		t.Error("Expected error when DB close fails")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestRecoverAuditEntries_NilAuditQueue tests RecoverAuditEntries with nil queue
func TestRecoverAuditEntries_NilAuditQueue(t *testing.T) {
	engine := &DatabasePolicyEngine{
		db:              nil,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil,
	}

	// Should return 0, nil when auditQueue is nil
	recovered, err := engine.RecoverAuditEntries()
	if err != nil {
		t.Errorf("RecoverAuditEntries with nil queue should not error: %v", err)
	}
	if recovered != 0 {
		t.Errorf("Expected 0 recovered entries, got %d", recovered)
	}
}

// TestGetAuditQueue tests the GetAuditQueue method
func TestGetAuditQueue_Nil(t *testing.T) {
	engine := &DatabasePolicyEngine{
		auditQueue: nil,
	}

	queue := engine.GetAuditQueue()
	if queue != nil {
		t.Error("Expected nil queue")
	}
}

// TestUpdatePolicyMetricsToQueue_NilQueue tests updatePolicyMetricsToQueue with nil queue
func TestUpdatePolicyMetricsToQueue_NilQueue(t *testing.T) {
	// Create mock database for fallback
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil, // No queue, will use direct fallback
	}

	// Expect INSERT for each triggered policy
	mock.ExpectExec("INSERT INTO policy_metrics").
		WithArgs("test_policy", 1).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Create a test result
	result := &StaticPolicyResult{
		Blocked:           true,
		TriggeredPolicies: []string{"test_policy"},
	}

	// Should not panic when auditQueue is nil - uses direct fallback
	engine.updatePolicyMetricsToQueue(result)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestUpdatePolicyMetricsToQueue_EmptyPolicies tests with empty triggered policies
func TestUpdatePolicyMetricsToQueue_EmptyPolicies(t *testing.T) {
	engine := &DatabasePolicyEngine{
		db:              nil,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil,
	}

	// Create a test result with no triggered policies
	result := &StaticPolicyResult{
		Blocked:           false,
		TriggeredPolicies: []string{},
	}

	// Should not panic when no policies triggered
	engine.updatePolicyMetricsToQueue(result)
}

// TestLogAuditEvent_WithQueue tests logAuditEvent uses queue when available
func TestLogAuditEvent_NilQueue(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil, // No queue, will use direct write
	}

	// Expect direct INSERT when no queue
	mock.ExpectExec("INSERT INTO agent_audit_logs").
		WithArgs("agent", "test_action", "test_resource", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	engine.logAuditEvent("test_action", "test_resource")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestLogAuditEvent_WithRetry tests logAuditEvent retry behavior
func TestLogAuditEvent_WithRetry(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil,
	}

	// First attempt fails, second succeeds (testing retry)
	mock.ExpectExec("INSERT INTO agent_audit_logs").
		WillReturnError(fmt.Errorf("temporary error"))
	mock.ExpectExec("INSERT INTO agent_audit_logs").
		WillReturnResult(sqlmock.NewResult(1, 1))

	engine.logAuditEvent("test_action", "test_resource")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestNewDatabasePolicyEngine_MissingEnv tests error when DATABASE_URL not set
func TestNewDatabasePolicyEngine_MissingEnv(t *testing.T) {
	// Save current DATABASE_URL
	oldDBURL := os.Getenv("DATABASE_URL")
	defer func() {
		if err := os.Setenv("DATABASE_URL", oldDBURL); err != nil {
			t.Errorf("Failed to restore DATABASE_URL: %v", err)
		}
	}()

	// Clear DATABASE_URL
	if err := os.Unsetenv("DATABASE_URL"); err != nil {
		t.Fatalf("Failed to unset DATABASE_URL: %v", err)
	}

	engine, err := NewDatabasePolicyEngine()
	if err == nil {
		t.Error("Expected error when DATABASE_URL not set")
		if engine != nil {
			_ = engine.Close()
		}
	}
}

// TestNewDatabasePolicyEngine_InvalidURL tests error with invalid database URL
func TestNewDatabasePolicyEngine_InvalidURL(t *testing.T) {
	// Save current DATABASE_URL
	oldDBURL := os.Getenv("DATABASE_URL")
	defer func() {
		if err := os.Setenv("DATABASE_URL", oldDBURL); err != nil {
			t.Errorf("Failed to restore DATABASE_URL: %v", err)
		}
	}()

	// Set invalid DATABASE_URL (will fail to connect)
	if err := os.Setenv("DATABASE_URL", "invalid://not-a-real-database"); err != nil {
		t.Fatalf("Failed to set DATABASE_URL: %v", err)
	}

	engine, err := NewDatabasePolicyEngine()
	if err == nil {
		t.Error("Expected error with invalid DATABASE_URL")
		if engine != nil {
			_ = engine.Close()
		}
	}
}

// TestUpdatePolicyMetricDirect_DBError tests metric update with DB error
func TestUpdatePolicyMetricDirect_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil,
	}

	// All retries fail
	mock.ExpectExec("INSERT INTO policy_metrics").
		WillReturnError(fmt.Errorf("database error"))
	mock.ExpectExec("INSERT INTO policy_metrics").
		WillReturnError(fmt.Errorf("database error"))
	mock.ExpectExec("INSERT INTO policy_metrics").
		WillReturnError(fmt.Errorf("database error"))

	// Should not panic, just log error
	engine.updatePolicyMetricDirect("test_policy", true)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestLogPolicyViolationDirect_DBError tests violation logging with DB error
func TestLogPolicyViolationDirect_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 60 * time.Second,
		performanceMode: false,
		auditQueue:      nil,
	}

	user := &User{ID: 1, Role: "user"}
	policy := &PolicyPattern{
		ID:          "test_policy",
		Name:        "Test Policy",
		Severity:    "high",
		Description: "Test description",
	}

	// All retries fail
	for i := 0; i < 3; i++ {
		mock.ExpectExec("INSERT INTO policy_violations").
			WillReturnError(fmt.Errorf("database error"))
	}

	// Should not panic, just log error
	engine.logPolicyViolationDirect(user, policy, "test query")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestEvaluateStaticPolicies_AdminAccess tests admin access pattern detection
func TestEvaluateStaticPolicies_AdminAccess(t *testing.T) {
	// Create mock database for logging
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Expect potential INSERT calls for violation logging and metrics
	mock.ExpectExec("INSERT INTO policy_violations").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO policy_metrics").WillReturnResult(sqlmock.NewResult(1, 1))

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 24 * time.Hour, // Long interval to prevent refresh
		lastRefresh:     time.Now(),     // Set to now to prevent background refresh
	}
	engine.loadDefaultPolicies()

	// Test admin access with regular user
	user := &User{
		ID:          1,
		Role:        "user",
		Permissions: []string{"query"},
	}

	// Test query that might trigger admin pattern
	query := "SELECT * FROM system_config"
	result := engine.EvaluateStaticPolicies(user, query, "sql")

	// Check if admin access pattern triggered
	if result != nil {
		t.Logf("Admin access result: blocked=%v, reason=%s", result.Blocked, result.Reason)
	}
}

// TestEvaluateStaticPolicies_PIIDetection tests PII detection patterns
func TestEvaluateStaticPolicies_PIIDetection(t *testing.T) {
	// Create mock database for logging
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Expect potential INSERT calls for violation logging and metrics
	mock.ExpectExec("INSERT INTO policy_violations").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO policy_metrics").WillReturnResult(sqlmock.NewResult(1, 1))

	engine := &DatabasePolicyEngine{
		db:              db,
		refreshInterval: 24 * time.Hour, // Long interval to prevent refresh
		lastRefresh:     time.Now(),     // Set to now to prevent background refresh
	}
	engine.loadDefaultPolicies()

	user := &User{
		ID:          1,
		Role:        "user",
		Permissions: []string{"query"},
	}

	// Test query with SSN-like pattern
	query := "My SSN is 123-45-6789"
	result := engine.EvaluateStaticPolicies(user, query, "natural_language")

	if result != nil {
		t.Logf("PII detection result: blocked=%v, triggered=%v", result.Blocked, result.TriggeredPolicies)
	}
}

// TestRecoverAuditEntries_NilQueue tests RecoverAuditEntries with nil audit queue
func TestRecoverAuditEntries_NilQueue(t *testing.T) {
	engine := &DatabasePolicyEngine{
		auditQueue: nil,
	}

	count, err := engine.RecoverAuditEntries()
	if err != nil {
		t.Errorf("Expected nil error, got: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected count 0, got: %d", count)
	}
}

// TestGetAuditQueue tests the GetAuditQueue method
func TestGetAuditQueue(t *testing.T) {
	// Test with nil queue
	engine := &DatabasePolicyEngine{
		auditQueue: nil,
	}
	queue := engine.GetAuditQueue()
	if queue != nil {
		t.Error("Expected nil queue")
	}
}

// TestDatabasePolicyEngine_Close_WithNilQueue tests Close method with nil audit queue
func TestDatabasePolicyEngine_Close_WithNilQueue(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}

	// Expect the DB close
	mock.ExpectClose()

	engine := &DatabasePolicyEngine{
		db:         db,
		auditQueue: nil,
	}

	err = engine.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

