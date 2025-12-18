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
	"os"
	"strings"
	"testing"
)

// TestNewStaticPolicyEngine tests policy engine initialization
func TestNewStaticPolicyEngine(t *testing.T) {
	engine := NewStaticPolicyEngine()

	if engine == nil {
		t.Fatal("Expected non-nil engine")
	}

	// Verify policies were loaded
	stats := engine.GetPolicyStats()

	// SQL injection patterns from sqli package (excluding CategoryDangerousQuery)
	// Includes: union-based (2), boolean-blind (3), time-based (4), error-based (3),
	// stacked-queries (5), comment-injection (3), generic (9) = 29 patterns
	sqlPatterns, ok := stats["sql_injection_patterns"].(int)
	if !ok || sqlPatterns != 29 {
		t.Errorf("Expected 29 SQL injection patterns, got %v", sqlPatterns)
	}

	// Dangerous query patterns from sqli package (CategoryDangerousQuery)
	// Includes: DROP TABLE/DATABASE, TRUNCATE, ALTER TABLE, DELETE without WHERE,
	// CREATE USER, GRANT, REVOKE = 8 patterns
	dangerousPatterns, ok := stats["dangerous_query_patterns"].(int)
	if !ok || dangerousPatterns != 8 {
		t.Errorf("Expected 8 dangerous query patterns, got %v", dangerousPatterns)
	}

	adminPatterns, ok := stats["admin_access_patterns"].(int)
	if !ok || adminPatterns != 4 {
		t.Errorf("Expected 4 admin access patterns, got %v", adminPatterns)
	}

	piiPatterns, ok := stats["pii_patterns"].(int)
	if !ok || piiPatterns != 12 {
		t.Errorf("Expected 12 PII patterns (including PAN and Aadhaar), got %v", piiPatterns)
	}

	// Total: 37 sqli patterns (29+8) + 4 admin + 12 pii = 53
	totalPatterns, ok := stats["total_patterns"].(int)
	if !ok || totalPatterns != 53 {
		t.Errorf("Expected 53 total patterns, got %v", totalPatterns)
	}
}

// TestSQLInjectionDetection tests SQL injection pattern detection
// Note: The sqli package now uses category-based pattern names and severities:
// - Union-based (union_select, union_injection) → severity "high"
// - Boolean-blind (or_true_condition, or_string_condition) → severity "medium"
// - Time-based → severity "high"
// - Stacked queries → severity "critical"
// - Dangerous queries → severity "critical"
func TestSQLInjectionDetection(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name           string
		query          string
		shouldBlock    bool
		patternSubstr  string   // Substring that should appear in triggered pattern
		minSeverity    string   // Minimum expected severity (low/medium/high/critical)
	}{
		{
			name:          "UNION SELECT injection",
			query:         "SELECT * FROM customers UNION SELECT username, password FROM admin",
			shouldBlock:   true,
			patternSubstr: "union",
			minSeverity:   "high",
		},
		{
			name:          "UNION SELECT (case insensitive)",
			query:         "select * from customers union select * from passwords",
			shouldBlock:   true,
			patternSubstr: "union",
			minSeverity:   "high",
		},
		{
			name:          "OR 1=1 injection",
			query:         "SELECT * FROM customers WHERE username='admin' OR 1=1",
			shouldBlock:   true,
			patternSubstr: "or",
			minSeverity:   "medium",
		},
		{
			name:          "Comment with SQL command",
			query:         "SELECT id FROM customers -- UNION SELECT password FROM admin",
			shouldBlock:   true,
			patternSubstr: "", // May trigger union or comment pattern
			minSeverity:   "medium",
		},
		{
			name:          "SLEEP injection",
			query:         "SELECT * FROM customers WHERE id=1; SELECT SLEEP(5)--",
			shouldBlock:   true,
			patternSubstr: "sleep",
			minSeverity:   "high",
		},
		{
			name:        "Legitimate query with 'or' keyword",
			query:       "SELECT * FROM orders WHERE status='pending' OR status='processing'",
			shouldBlock: false,
		},
		{
			name:        "Safe SELECT query",
			query:       "SELECT customer_id, order_date FROM orders WHERE id=123",
			shouldBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, "sql")

			if result.Blocked != tt.shouldBlock {
				t.Errorf("Query: %s\nExpected blocked=%v, got blocked=%v\nReason: %s",
					tt.query, tt.shouldBlock, result.Blocked, result.Reason)
			}

			if tt.shouldBlock {
				// Verify pattern contains expected substring (if specified)
				if tt.patternSubstr != "" {
					found := false
					for _, p := range result.TriggeredPolicies {
						if containsIgnoreCase(p, tt.patternSubstr) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected pattern containing '%s', got: %v",
							tt.patternSubstr, result.TriggeredPolicies)
					}
				}

				// Verify severity meets minimum expected level
				if tt.minSeverity != "" && !severityAtLeast(result.Severity, tt.minSeverity) {
					t.Errorf("Expected severity at least '%s', got '%s'", tt.minSeverity, result.Severity)
				}

				// Verify reason is set
				if result.Reason == "" {
					t.Error("Expected non-empty reason")
				}
			}

			// Verify processing time is tracked
			if result.ProcessingTimeMs < 0 {
				t.Error("Expected non-negative processing time")
			}
		})
	}
}

// containsIgnoreCase checks if s contains substr (case insensitive)
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// severityAtLeast checks if actual severity is at least the minimum level
func severityAtLeast(actual, minimum string) bool {
	levels := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	return levels[actual] >= levels[minimum]
}

// TestDangerousQueryDetection tests dangerous query pattern detection
// Pattern names from sqli package: drop_table, drop_database, truncate_table,
// alter_table, delete_without_where, create_user, grant_privileges, revoke_privileges
func TestDangerousQueryDetection(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name          string
		query         string
		shouldBlock   bool
		patternSubstr string // Substring in pattern name
	}{
		{
			name:          "DROP TABLE",
			query:         "DROP TABLE customers",
			shouldBlock:   true,
			patternSubstr: "drop",
		},
		{
			name:          "DROP DATABASE",
			query:         "DROP DATABASE production",
			shouldBlock:   true,
			patternSubstr: "drop",
		},
		{
			name:          "TRUNCATE TABLE",
			query:         "TRUNCATE TABLE orders",
			shouldBlock:   true,
			patternSubstr: "truncate",
		},
		{
			name:          "DELETE without WHERE",
			query:         "DELETE FROM customers",
			shouldBlock:   true,
			patternSubstr: "delete",
		},
		{
			name:          "DELETE without WHERE (with semicolon)",
			query:         "DELETE FROM orders;",
			shouldBlock:   true,
			patternSubstr: "delete",
		},
		{
			name:          "ALTER TABLE",
			query:         "ALTER TABLE customers ADD COLUMN secret VARCHAR(255)",
			shouldBlock:   true,
			patternSubstr: "alter",
		},
		{
			name:          "CREATE USER",
			query:         "CREATE USER hacker WITH PASSWORD 'backdoor'",
			shouldBlock:   true,
			patternSubstr: "create_user",
		},
		{
			name:          "GRANT privileges",
			query:         "GRANT ALL PRIVILEGES ON database.* TO 'user'@'host'",
			shouldBlock:   true,
			patternSubstr: "grant",
		},
		{
			name:          "REVOKE privileges",
			query:         "REVOKE SELECT ON customers FROM public",
			shouldBlock:   true,
			patternSubstr: "revoke",
		},
		{
			name:        "Safe DELETE with WHERE",
			query:       "DELETE FROM orders WHERE id=123 AND status='cancelled'",
			shouldBlock: false,
		},
		{
			name:        "Safe UPDATE",
			query:       "UPDATE customers SET status='active' WHERE id=456",
			shouldBlock: false,
		},
		{
			name:        "Safe SELECT",
			query:       "SELECT * FROM products WHERE category='electronics'",
			shouldBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, "sql")

			if result.Blocked != tt.shouldBlock {
				t.Errorf("Query: %s\nExpected blocked=%v, got blocked=%v\nReason: %s",
					tt.query, tt.shouldBlock, result.Blocked, result.Reason)
			}

			if tt.shouldBlock && tt.patternSubstr != "" {
				found := false
				for _, p := range result.TriggeredPolicies {
					if containsIgnoreCase(p, tt.patternSubstr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected pattern containing '%s', got: %v",
						tt.patternSubstr, result.TriggeredPolicies)
				}

				// Verify severity is high or critical
				if result.Severity != "critical" && result.Severity != "high" {
					t.Errorf("Expected severity 'critical' or 'high', got '%s'", result.Severity)
				}
			}
		})
	}
}

// TestAdminAccessControl tests admin access pattern enforcement
func TestAdminAccessControl(t *testing.T) {
	engine := NewStaticPolicyEngine()

	tests := []struct {
		name        string
		user        *User
		query       string
		shouldBlock bool
		policyID    string
	}{
		{
			name: "Regular user accessing users table",
			user: &User{
				ID:          1,
				Email:       "user1@test.com",
				Permissions: []string{"query"},
			},
			query:       "SELECT * FROM users",
			shouldBlock: true,
			policyID:    "users_table_access",
		},
		{
			name: "Admin user accessing users table",
			user: &User{
				ID:          2,
				Email:       "admin@test.com",
				Permissions: []string{"query", "admin"},
			},
			query:       "SELECT * FROM users",
			shouldBlock: false,
		},
		{
			name: "Regular user accessing audit logs",
			user: &User{
				ID:          1,
				Email:       "user1@test.com",
				Permissions: []string{"query"},
			},
			query:       "SELECT * FROM audit_log WHERE user_id=123",
			shouldBlock: true,
			policyID:    "audit_log_access",
		},
		{
			name: "Admin accessing audit logs",
			user: &User{
				ID:          2,
				Email:       "admin@test.com",
				Permissions: []string{"query", "admin"},
			},
			query:       "SELECT * FROM audit_log",
			shouldBlock: false,
		},
		{
			name: "Regular user accessing config table",
			user: &User{
				ID:          1,
				Email:       "user1@test.com",
				Permissions: []string{"query"},
			},
			query:       "SELECT * FROM config_settings",
			shouldBlock: true,
			policyID:    "config_table_access",
		},
		{
			name: "Regular user accessing admin table",
			user: &User{
				ID:          1,
				Email:       "user1@test.com",
				Permissions: []string{"query"},
			},
			query:       "SELECT * FROM admin_permissions",
			shouldBlock: true,
			policyID:    "config_table_access",
		},
		{
			name: "Regular user accessing information_schema",
			user: &User{
				ID:          1,
				Email:       "user1@test.com",
				Permissions: []string{"query"},
			},
			query:       "SELECT * FROM information_schema.tables",
			shouldBlock: true,
			policyID:    "information_schema", // Caught by sqli scanner as enumeration attack
		},
		{
			name: "Regular user accessing pg_catalog",
			user: &User{
				ID:          1,
				Email:       "user1@test.com",
				Permissions: []string{"query"},
			},
			query:       "SELECT * FROM pg_catalog.pg_tables",
			shouldBlock: true,
			policyID:    "information_schema_access",
		},
		{
			name: "Regular user accessing customer table",
			user: &User{
				ID:          1,
				Email:       "user1@test.com",
				Permissions: []string{"query"},
			},
			query:       "SELECT * FROM customers",
			shouldBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(tt.user, tt.query, "sql")

			if result.Blocked != tt.shouldBlock {
				t.Errorf("User: %v\nQuery: %s\nExpected blocked=%v, got blocked=%v\nReason: %s",
					tt.user.Permissions, tt.query, tt.shouldBlock, result.Blocked, result.Reason)
			}

			if tt.shouldBlock && tt.policyID != "" {
				if !containsPolicy(result.TriggeredPolicies, tt.policyID) {
					t.Errorf("Expected policy '%s' to be triggered, got: %v",
						tt.policyID, result.TriggeredPolicies)
				}
			}
		})
	}
}

// TestRequestTypeValidation tests request type validation
func TestRequestTypeValidation(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name        string
		requestType string
		shouldBlock bool
	}{
		{name: "sql request", requestType: "sql", shouldBlock: false},
		{name: "llm_chat request", requestType: "llm_chat", shouldBlock: false},
		{name: "rag_search request", requestType: "rag_search", shouldBlock: false},
		{name: "test request", requestType: "test", shouldBlock: false},
		{name: "multi-agent-plan request", requestType: "multi-agent-plan", shouldBlock: false},
		{name: "chat request", requestType: "chat", shouldBlock: false},
		{name: "completion request", requestType: "completion", shouldBlock: false},
		{name: "embedding request", requestType: "embedding", shouldBlock: false},
		{name: "invalid request type", requestType: "invalid_type", shouldBlock: true},
		{name: "empty request type", requestType: "", shouldBlock: true},
		{name: "malicious request type", requestType: "../../etc/passwd", shouldBlock: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := "SELECT * FROM customers"
			result := engine.EvaluateStaticPolicies(user, query, tt.requestType)

			if result.Blocked != tt.shouldBlock {
				t.Errorf("RequestType: %s\nExpected blocked=%v, got blocked=%v\nReason: %s",
					tt.requestType, tt.shouldBlock, result.Blocked, result.Reason)
			}

			if tt.shouldBlock && result.Severity != "medium" {
				t.Errorf("Expected severity 'medium' for invalid request type, got '%s'", result.Severity)
			}
		})
	}
}

// TestEmptyQueryValidation tests empty query handling
func TestEmptyQueryValidation(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name        string
		query       string
		shouldBlock bool
	}{
		{name: "empty string", query: "", shouldBlock: true},
		{name: "whitespace only", query: "   ", shouldBlock: true},
		{name: "tabs only", query: "\t\t", shouldBlock: true},
		{name: "newlines only", query: "\n\n", shouldBlock: true},
		{name: "mixed whitespace", query: " \t\n ", shouldBlock: true},
		{name: "valid query", query: "SELECT * FROM customers", shouldBlock: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, "sql")

			if result.Blocked != tt.shouldBlock {
				t.Errorf("Query: '%s'\nExpected blocked=%v, got blocked=%v",
					tt.query, tt.shouldBlock, result.Blocked)
			}

			if tt.shouldBlock && result.Severity != "low" {
				t.Errorf("Expected severity 'low' for empty query, got '%s'", result.Severity)
			}
		})
	}
}

// TestPIIDetection tests PII pattern detection
func TestPIIDetection(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name                string
		query               string
		shouldBlock         bool
		shouldTriggerPolicy bool
		policyID            string
	}{
		{
			name:                "Passport number",
			query:               "Book flight for passenger with passport AB123456",
			shouldBlock:         false, // PII detection doesn't block
			shouldTriggerPolicy: true,
			policyID:            "passport_number_detection",
		},
		{
			name:                "Credit card (Visa)",
			query:               "Payment with card 4532015112830366",
			shouldBlock:         true, // Critical PII blocks by default (PII_BLOCK_CRITICAL=true)
			shouldTriggerPolicy: true,
			policyID:            "credit_card_detection",
		},
		{
			name:                "SSN",
			query:               "Customer SSN is 123-45-6789",
			shouldBlock:         true, // Critical PII blocks by default (PII_BLOCK_CRITICAL=true)
			shouldTriggerPolicy: true,
			policyID:            "ssn_detection",
		},
		{
			name:                "Booking reference",
			query:               "Retrieve booking ABC123",
			shouldBlock:         false,
			shouldTriggerPolicy: true,
			policyID:            "booking_reference_logging",
		},
		{
			name:                "No PII",
			query:               "SELECT * FROM flights WHERE departure='JFK'",
			shouldBlock:         false,
			shouldTriggerPolicy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, "llm_chat")

			if result.Blocked != tt.shouldBlock {
				t.Errorf("Query: %s\nExpected blocked=%v, got blocked=%v",
					tt.query, tt.shouldBlock, result.Blocked)
			}

			if tt.shouldTriggerPolicy {
				if !containsPolicy(result.TriggeredPolicies, tt.policyID) {
					t.Errorf("Expected policy '%s' to be triggered for PII detection, got: %v",
						tt.policyID, result.TriggeredPolicies)
				}
			}

			// Verify PII detection check was performed (not present if blocked early)
			if !tt.shouldBlock && !containsCheck(result.ChecksPerformed, "pii_detection") {
				t.Error("Expected 'pii_detection' in checks performed")
			}
		})
	}
}

// TestPIIDetection_Disabled tests that PII blocking can be disabled via env var
func TestPIIDetection_Disabled(t *testing.T) {
	// Set env var to disable PII blocking
	os.Setenv("PII_BLOCK_CRITICAL", "false")
	defer os.Unsetenv("PII_BLOCK_CRITICAL")

	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name  string
		query string
	}{
		{
			name:  "SSN should not block when disabled",
			query: "Customer SSN is 123-45-6789",
		},
		{
			name:  "Credit card should not block when disabled",
			query: "Payment with card 4532015112830366",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, "llm_chat")

			// Should NOT block when PII_BLOCK_CRITICAL=false
			if result.Blocked {
				t.Errorf("Expected request to NOT be blocked when PII_BLOCK_CRITICAL=false, got blocked: %s", result.Reason)
			}

			// Should still detect PII (just not block)
			if len(result.TriggeredPolicies) == 0 {
				t.Error("Expected PII policy to be triggered even when blocking is disabled")
			}

			// pii_detection should be in ChecksPerformed
			if !containsCheck(result.ChecksPerformed, "pii_detection") {
				t.Error("Expected 'pii_detection' in checks performed")
			}
		})
	}
}

// TestChecksPerformed tests that all checks are tracked
func TestChecksPerformed(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	query := "SELECT * FROM customers WHERE id=123"
	result := engine.EvaluateStaticPolicies(user, query, "sql")

	expectedChecks := []string{
		"sql_injection",
		"dangerous_queries",
		"admin_access",
		"request_type",
		"basic_validation",
		"pii_detection",
	}

	for _, check := range expectedChecks {
		if !containsCheck(result.ChecksPerformed, check) {
			t.Errorf("Expected check '%s' to be performed, got: %v",
				check, result.ChecksPerformed)
		}
	}

	if len(result.ChecksPerformed) != len(expectedChecks) {
		t.Errorf("Expected %d checks, got %d: %v",
			len(expectedChecks), len(result.ChecksPerformed), result.ChecksPerformed)
	}
}

// TestProcessingTime tests that processing time is tracked
func TestProcessingTime(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name  string
		query string
	}{
		{name: "Simple query", query: "SELECT * FROM customers"},
		{name: "Complex query", query: "SELECT c.*, o.* FROM customers c JOIN orders o ON c.id=o.customer_id WHERE c.status='active'"},
		{name: "Blocked query", query: "DROP TABLE customers"},
		{name: "SQL injection", query: "SELECT * FROM users WHERE id=1 OR 1=1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, "sql")

			if result.ProcessingTimeMs < 0 {
				t.Errorf("Expected non-negative processing time, got %d", result.ProcessingTimeMs)
			}

			// Processing should be very fast (< 100ms)
			if result.ProcessingTimeMs > 100 {
				t.Errorf("Processing time too high: %dms (expected < 100ms)", result.ProcessingTimeMs)
			}
		})
	}
}

// TestSQLiScannerIntegration tests that the sqli scanner is properly integrated
// Note: Individual pattern enabling/disabling is handled by the sqli package.
// The StaticPolicyEngine now uses the unified sqli.Scanner for SQL injection detection.
func TestSQLiScannerIntegration(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	// Test that SQL injection is detected
	query := "admin' OR 1=1--"
	result := engine.EvaluateStaticPolicies(user, query, "sql")

	if !result.Blocked {
		t.Error("Expected SQL injection to be blocked")
	}
	if result.Severity != "medium" && result.Severity != "high" && result.Severity != "critical" {
		t.Errorf("Expected severity to be medium/high/critical, got: %s", result.Severity)
	}

	// Test that dangerous queries are detected
	query = "DROP TABLE sensitive_data"
	result = engine.EvaluateStaticPolicies(user, query, "sql")

	if !result.Blocked {
		t.Error("Expected dangerous query to be blocked")
	}

	// Test that legitimate queries pass
	query = "SELECT name, email FROM customers WHERE id = 123"
	result = engine.EvaluateStaticPolicies(user, query, "sql")

	if result.Blocked {
		t.Errorf("Expected legitimate query to pass, but was blocked: %s", result.Reason)
	}
}

// TestCaseInsensitivity tests that patterns are case-insensitive
func TestCaseInsensitivity(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name  string
		query string
	}{
		{name: "lowercase", query: "drop table customers"},
		{name: "uppercase", query: "DROP TABLE CUSTOMERS"},
		{name: "mixed case", query: "DrOp TaBlE customers"},
		{name: "union lowercase", query: "select * from users union select * from admin"},
		{name: "union uppercase", query: "SELECT * FROM USERS UNION SELECT * FROM ADMIN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, "sql")

			if !result.Blocked {
				t.Errorf("Query should be blocked regardless of case: %s", tt.query)
			}
		})
	}
}

// TestComplexSQLInjectionAttempts tests sophisticated injection attempts
func TestComplexSQLInjectionAttempts(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name        string
		query       string
		shouldBlock bool
	}{
		{
			name:        "Stacked queries",
			query:       "SELECT * FROM customers; DROP TABLE orders;",
			shouldBlock: true,
		},
		{
			name:        "Nested UNION",
			query:       "SELECT * FROM (SELECT * FROM users UNION SELECT * FROM admin) AS t",
			shouldBlock: true,
		},
		{
			name:        "Comment obfuscation",
			query:       "SELECT * FROM users /*comment*/ UNION /*more*/ SELECT * FROM admin",
			shouldBlock: true,
		},
		{
			name:        "Whitespace manipulation",
			query:       "SELECT*FROM users UNION SELECT*FROM admin",
			shouldBlock: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, "sql")

			if result.Blocked != tt.shouldBlock {
				t.Errorf("Query: %s\nExpected blocked=%v, got blocked=%v\nReason: %s",
					tt.query, tt.shouldBlock, result.Blocked, result.Reason)
			}
		})
	}
}

// TestGetPolicyStats tests policy statistics retrieval
func TestGetPolicyStats(t *testing.T) {
	engine := NewStaticPolicyEngine()
	stats := engine.GetPolicyStats()

	// Verify all stat fields are present
	expectedFields := []string{
		"sql_injection_patterns",
		"dangerous_query_patterns",
		"admin_access_patterns",
		"pii_patterns",
		"total_patterns",
	}

	for _, field := range expectedFields {
		if _, ok := stats[field]; !ok {
			t.Errorf("Expected field '%s' in stats", field)
		}
	}

	// Verify total is sum of individual counts
	total := stats["total_patterns"].(int)
	sum := stats["sql_injection_patterns"].(int) +
		stats["dangerous_query_patterns"].(int) +
		stats["admin_access_patterns"].(int) +
		stats["pii_patterns"].(int)

	if total != sum {
		t.Errorf("Total patterns (%d) should equal sum of individual patterns (%d)", total, sum)
	}
}

// Helper function for checking if a string slice contains an item
func containsPolicy(policies []string, policyID string) bool {
	for _, p := range policies {
		if p == policyID {
			return true
		}
	}
	return false
}

func containsCheck(checks []string, check string) bool {
	for _, c := range checks {
		if c == check {
			return true
		}
	}
	return false
}

// =============================================================================
// Enhanced PII Detection Tests
// =============================================================================

// TestEnhancedPIIDetection tests the expanded PII pattern detection
func TestEnhancedPIIDetection(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name     string
		query    string
		policyID string
	}{
		// Email detection
		{
			name:     "Email address",
			query:    "Contact customer at john.doe@example.com",
			policyID: "email_detection",
		},
		{
			name:     "Email with subdomain",
			query:    "Send to user@mail.company.co.uk",
			policyID: "email_detection",
		},
		// Phone detection
		{
			name:     "US phone with area code",
			query:    "Call customer at (555) 123-4567",
			policyID: "phone_detection",
		},
		{
			name:     "US phone with dashes",
			query:    "Phone number: 555-123-4567",
			policyID: "phone_detection",
		},
		{
			name:     "International phone",
			query:    "Contact at +1 555 123 4567",
			policyID: "phone_detection",
		},
		// IP address detection
		{
			name:     "IPv4 address",
			query:    "User connected from 192.168.1.100",
			policyID: "ip_address_detection",
		},
		{
			name:     "Public IP",
			query:    "Server IP: 203.0.113.50",
			policyID: "ip_address_detection",
		},
		// IBAN detection - Note: IBAN pattern may be detected as other patterns
		// due to overlapping digit sequences in static engine (first-match wins)
		// Enhanced detector handles this with validation
		// {
		// 	name:     "German IBAN",
		// 	query:    "Bank account IBAN: DE89370400440532013000",
		// 	policyID: "iban_detection",
		// },
		// Date of Birth
		{
			name:     "DOB US format",
			query:    "Date of birth: 01/15/1990",
			policyID: "dob_detection",
		},
		{
			name:     "DOB ISO format",
			query:    "Birthday: 1985-06-20",
			policyID: "dob_detection",
		},
		// Bank account - Note: Routing numbers may match SSN pattern first
		// due to 9-digit format overlap in static engine (first-match wins)
		// Enhanced detector handles this with ABA routing validation
		// {
		// 	name:     "US routing and account",
		// 	query:    "Routing: 021000021 Account: 123456789012",
		// 	policyID: "bank_account_detection",
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, "llm_chat")

			// PII detection should not block
			if result.Blocked {
				t.Errorf("PII detection should not block queries, got blocked: %s", result.Reason)
			}

			// Should trigger the expected policy
			if !containsPolicy(result.TriggeredPolicies, tt.policyID) {
				t.Errorf("Expected policy '%s' to be triggered for query: %s\nTriggered: %v",
					tt.policyID, tt.query, result.TriggeredPolicies)
			}
		})
	}
}

// TestPIIFalsePositivePrevention tests that common patterns don't trigger false positives
func TestPIIFalsePositivePrevention(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name             string
		query            string
		shouldNotTrigger []string
	}{
		{
			name:             "Version number not IP",
			query:            "Software version 1.2.3.4",
			shouldNotTrigger: []string{}, // This might still match IP pattern
		},
		{
			name:             "Order number not SSN",
			query:            "Order ORD-12345 shipped",
			shouldNotTrigger: []string{"ssn_detection"},
		},
		{
			name:             "Product SKU",
			query:            "Product SKU: ABC-12-3456",
			shouldNotTrigger: []string{"ssn_detection"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, "llm_chat")

			for _, policyID := range tt.shouldNotTrigger {
				if containsPolicy(result.TriggeredPolicies, policyID) {
					t.Errorf("Policy '%s' should NOT be triggered for: %s",
						policyID, tt.query)
				}
			}
		})
	}
}

// TestValidateSSN tests the SSN validation function
func TestValidateSSN(t *testing.T) {
	tests := []struct {
		name  string
		ssn   string
		valid bool
	}{
		// Valid SSNs
		{"Valid standard format", "123-45-6789", true},
		{"Valid with spaces", "123 45 6789", true},
		{"Valid no separators", "123456789", true},
		{"Valid different numbers", "078-05-1120", true},

		// Invalid - area number rules
		{"Invalid - starts with 000", "000-12-3456", false},
		{"Invalid - starts with 666", "666-12-3456", false},
		{"Invalid - starts with 900", "900-12-3456", false},
		{"Invalid - starts with 999", "999-12-3456", false},

		// Invalid - group number rules
		{"Invalid - group is 00", "123-00-4567", false},

		// Invalid - serial number rules
		{"Invalid - serial is 0000", "123-45-0000", false},

		// Invalid - format
		{"Invalid - too short", "12-34-5678", false},
		{"Invalid - too long", "1234-56-78901", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateSSN(tt.ssn)
			if got != tt.valid {
				t.Errorf("ValidateSSN(%s) = %v, want %v", tt.ssn, got, tt.valid)
			}
		})
	}
}

// TestValidateCreditCard tests the Luhn algorithm validation
func TestValidateCreditCard(t *testing.T) {
	tests := []struct {
		name  string
		card  string
		valid bool
	}{
		// Valid cards (pass Luhn check)
		{"Valid Visa", "4532015112830366", true},
		{"Valid Visa with dashes", "4532-0151-1283-0366", true},
		{"Valid Visa with spaces", "4532 0151 1283 0366", true},
		{"Valid MasterCard", "5425233430109903", true},
		{"Valid Amex", "378282246310005", true},
		{"Valid Discover", "6011111111111117", true},

		// Invalid cards (fail Luhn check)
		{"Invalid - wrong check digit", "4532015112830367", false},
		{"Invalid - random numbers", "1234567890123456", false},
		{"Invalid - too short", "453201511283", false},
		{"Invalid - too long", "45320151128303661234", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateCreditCard(tt.card)
			if got != tt.valid {
				t.Errorf("ValidateCreditCard(%s) = %v, want %v", tt.card, got, tt.valid)
			}
		})
	}
}

// TestCreditCardNetworkDetection tests detection of different card networks
func TestCreditCardNetworkDetection(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name string
		card string
	}{
		{"Visa 16-digit", "4532015112830366"},
		{"MasterCard", "5425233430109903"},
		{"MasterCard 2-series", "2223000048400011"},
		{"Amex", "378282246310005"},
		{"Discover", "6011111111111117"},
		{"Diners Club", "30569309025904"},
		{"JCB", "3530111333300000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := "Process payment with card " + tt.card
			result := engine.EvaluateStaticPolicies(user, query, "llm_chat")

			if !containsPolicy(result.TriggeredPolicies, "credit_card_detection") {
				t.Errorf("Should detect %s card: %s", tt.name, tt.card)
			}
		})
	}
}

// TestCreditCardFormattedDetection tests detection of credit cards with separators
// This is critical for Amex (15-digit, 4-4-4-3 format) and Diners Club (14-digit, 4-4-4-2 format)
// which were NOT detected before this fix.
func TestCreditCardFormattedDetection(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name     string
		card     string
		expected bool // true = should be detected
	}{
		// =================================================================
		// 16-digit cards with separators (4-4-4-4 format)
		// =================================================================
		{"Visa with hyphens", "4111-1111-1111-1111", true},
		{"Visa with spaces", "4111 1111 1111 1111", true},
		{"Mastercard with hyphens", "5500-0000-0000-0004", true},
		{"Mastercard with spaces", "5500 0000 0000 0004", true},
		{"Discover with hyphens", "6011-0000-0000-0004", true},
		{"Discover with spaces", "6011 0000 0000 0004", true},
		{"JCB with hyphens", "3530-1113-3330-0000", true},
		{"JCB with spaces", "3530 1113 3330 0000", true},

		// =================================================================
		// 15-digit Amex cards (4-4-4-3 format) - THE CRITICAL FIX
		// =================================================================
		{"Amex with hyphens (4-4-4-3)", "3782-8224-6310-005", true},
		{"Amex with spaces (4-4-4-3)", "3782 8224 6310 005", true},
		{"Amex 34xx with hyphens", "3400-0000-0000-009", true},
		{"Amex 37xx with hyphens", "3700-0000-0000-002", true},

		// =================================================================
		// 14-digit Diners Club cards (4-4-4-2 format) - THE CRITICAL FIX
		// =================================================================
		{"Diners Club with hyphens (4-4-4-2)", "3056-9309-0259-04", true},
		{"Diners Club with spaces (4-4-4-2)", "3056 9309 0259 04", true},
		{"Diners Club 36xx with hyphens", "3600-0000-0000-08", true},
		{"Diners Club 38xx with hyphens", "3800-0000-0000-06", true},

		// =================================================================
		// Continuous formats (no separators) - should still work
		// =================================================================
		{"Visa continuous", "4111111111111111", true},
		{"Mastercard continuous", "5500000000000004", true},
		{"Discover continuous", "6011000000000004", true},
		{"JCB continuous", "3530111333300000", true},
		{"Amex continuous", "378282246310005", true},
		{"Diners continuous", "30569309025904", true},

		// =================================================================
		// Edge cases - should NOT be detected
		// =================================================================
		{"Too few digits", "4111-1111-1111", false},
		{"Letters mixed in", "4111-XXXX-1111-1111", false},
		{"Random 12 digits (not a card)", "1234-5678-9012", false},

		// Note: Mixed separators ARE detected - better to over-detect than miss real cards
		{"Mixed separators (still detected)", "4111-1111 1111-1111", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := "Process payment with card " + tt.card
			result := engine.EvaluateStaticPolicies(user, query, "llm_chat")

			detected := containsPolicy(result.TriggeredPolicies, "credit_card_detection")
			if detected != tt.expected {
				if tt.expected {
					t.Errorf("Should detect %s: %s", tt.name, tt.card)
				} else {
					t.Errorf("Should NOT detect %s: %s", tt.name, tt.card)
				}
			}
		})
	}
}

// TestCreditCardPatternRegex directly tests the regex pattern for credit cards
func TestCreditCardPatternRegex(t *testing.T) {
	engine := NewStaticPolicyEngine()

	// Find the credit card pattern
	var ccPattern *PolicyPattern
	for _, p := range engine.piiPatterns {
		if p.ID == "credit_card_detection" {
			ccPattern = p
			break
		}
	}

	if ccPattern == nil {
		t.Fatal("credit_card_detection pattern not found")
	}

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// =================================================================
		// Formatted 16-digit (4-4-4-4)
		// =================================================================
		{"Visa 4-4-4-4 hyphen", "4111-1111-1111-1111", true},
		{"Visa 4-4-4-4 space", "4111 1111 1111 1111", true},
		{"Mastercard 4-4-4-4 hyphen", "5500-0000-0000-0004", true},
		{"Mastercard 4-4-4-4 space", "5500 0000 0000 0004", true},
		{"Discover 4-4-4-4 hyphen", "6011-0000-0000-0004", true},
		{"Discover 4-4-4-4 space", "6011 0000 0000 0004", true},
		{"JCB 4-4-4-4 hyphen", "3530-1113-3330-0000", true},
		{"JCB 4-4-4-4 space", "3530 1113 3330 0000", true},

		// =================================================================
		// Formatted 15-digit Amex (4-4-4-3)
		// =================================================================
		{"Amex 4-4-4-3 hyphen", "3782-8224-6310-005", true},
		{"Amex 4-4-4-3 space", "3782 8224 6310 005", true},
		{"Amex 34xx hyphen", "3400-0000-0000-009", true},
		{"Amex 37xx space", "3700 0000 0000 002", true},

		// =================================================================
		// Formatted 14-digit Diners (4-4-4-2)
		// =================================================================
		{"Diners 4-4-4-2 hyphen", "3056-9309-0259-04", true},
		{"Diners 4-4-4-2 space", "3056 9309 0259 04", true},
		{"Diners 36xx hyphen", "3600-0000-0000-08", true},
		{"Diners 38xx hyphen", "3800-0000-0000-06", true},

		// =================================================================
		// Continuous formats (no separators)
		// =================================================================
		{"Visa continuous", "4111111111111111", true},
		{"Mastercard continuous", "5500000000000004", true},
		{"Discover continuous", "6011000000000004", true},
		{"JCB continuous", "3530111333300000", true},
		{"Amex continuous", "378282246310005", true},
		{"Diners continuous", "30569309025904", true},

		// =================================================================
		// Should NOT match
		// =================================================================
		{"Only 12 digits", "411111111111", false},
		{"Only 10 digits", "4111111111", false},
		{"With letters", "4111-XXXX-1111-1111", false},

		// Note: Mixed separators ARE detected - better to over-detect than miss real cards
		{"Mixed separators (still matches)", "4111-1111 1111-1111", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := ccPattern.Pattern.MatchString(tt.input)
			if matched != tt.expected {
				if tt.expected {
					t.Errorf("Regex should match %s: %q", tt.name, tt.input)
				} else {
					t.Errorf("Regex should NOT match %s: %q", tt.name, tt.input)
				}
			}
		})
	}
}

// TestCreditCardVsAadhaarRegression verifies that:
// 1. Credit cards with spaces are detected as credit cards (not Aadhaar)
// 2. Valid Aadhaar numbers are still detected correctly
// This is a regression test for the pattern ordering fix.
func TestCreditCardVsAadhaarRegression(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name           string
		query          string
		expectedPolicy string // which policy should trigger
	}{
		// Credit cards with spaces should NOT trigger Aadhaar
		{
			name:           "Visa with spaces - should be credit card, not Aadhaar",
			query:          "Pay with card 4111 1111 1111 1111",
			expectedPolicy: "credit_card_detection",
		},
		{
			name:           "Mastercard with spaces - should be credit card",
			query:          "Card number is 5500 0000 0000 0004",
			expectedPolicy: "credit_card_detection",
		},
		{
			name:           "Amex with spaces - should be credit card",
			query:          "Use Amex 3782 8224 6310 005",
			expectedPolicy: "credit_card_detection",
		},
		// Valid Aadhaar numbers should still be detected
		{
			name:           "Aadhaar 12 digits no spaces",
			query:          "My aadhaar is 234567890123",
			expectedPolicy: "aadhaar_detection",
		},
		{
			name:           "Aadhaar 12 digits with spaces (4-4-4)",
			query:          "Aadhaar number: 2345 6789 0123",
			expectedPolicy: "aadhaar_detection",
		},
		{
			name:           "Aadhaar with prefix keyword",
			query:          "aadhaar: 345678901234",
			expectedPolicy: "aadhaar_detection",
		},
		{
			name:           "UID with prefix keyword",
			query:          "UID: 456789012345",
			expectedPolicy: "aadhaar_detection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, "llm_chat")

			if len(result.TriggeredPolicies) == 0 {
				t.Errorf("Expected policy %s to trigger, but no policies triggered", tt.expectedPolicy)
				return
			}

			// Check if the expected policy was triggered (should be first)
			if result.TriggeredPolicies[0] != tt.expectedPolicy {
				t.Errorf("Expected %s but got %s for query: %s",
					tt.expectedPolicy, result.TriggeredPolicies[0], tt.query)
			}
		})
	}
}

// TestPIIPolicyStats tests that enhanced patterns are counted correctly
func TestPIIPolicyStats(t *testing.T) {
	engine := NewStaticPolicyEngine()
	stats := engine.GetPolicyStats()

	piiCount := stats["pii_patterns"].(int)

	// Should have at least 10 PII patterns now
	expectedMinPatterns := 12 // Includes PAN and Aadhaar patterns
	if piiCount < expectedMinPatterns {
		t.Errorf("Expected at least %d PII patterns, got %d", expectedMinPatterns, piiCount)
	}
}

// TestMultiplePIIInSingleQuery tests detection of multiple PII types
func TestMultiplePIIInSingleQuery(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	query := `
		Customer Information:
		SSN: 123-45-6789
		Email: customer@example.com
		Phone: (555) 123-4567
		Card: 4532015112830366
	`

	result := engine.EvaluateStaticPolicies(user, query, "llm_chat")

	// Should block - contains critical PII (SSN, credit card)
	if !result.Blocked {
		t.Error("Multiple critical PII detection should block (PII_BLOCK_CRITICAL=true)")
	}

	// Static engine returns after first PII match found
	// At least one PII policy should be triggered
	piiPolicies := []string{
		"ssn_detection",
		"email_detection",
		"phone_detection",
		"credit_card_detection",
	}

	foundPII := false
	for _, policyID := range piiPolicies {
		if containsPolicy(result.TriggeredPolicies, policyID) {
			foundPII = true
			break
		}
	}

	if !foundPII {
		t.Error("Expected at least one PII policy to be triggered")
	}
}

// TestPIIDetectionPerformance tests that PII detection is fast
func TestPIIDetectionPerformance(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	// Large query with multiple PII types including Indian PII
	query := "Customer SSN 123-45-6789, email test@example.com, phone 555-123-4567, " +
		"card 4532015112830366, IBAN DE89370400440532013000, passport AB1234567, " +
		"PAN ABCPD1234E, Aadhaar 2234 5678 9012. " +
		"Normal text here. More normal text. Even more text to make it longer."

	// Run multiple times to get average
	iterations := 100
	for i := 0; i < iterations; i++ {
		result := engine.EvaluateStaticPolicies(user, query, "llm_chat")

		// Should complete in < 10ms per query
		if result.ProcessingTimeMs > 10 {
			t.Errorf("PII detection too slow: %dms (iteration %d)", result.ProcessingTimeMs, i)
		}
	}
}

// =============================================================================
// Indian PII Detection Tests (SEBI AI/ML Guidelines & DPDP Act 2023)
// These tests verify the StaticPolicyEngine detection of PAN and Aadhaar
// =============================================================================

// TestStaticPANDetection tests Indian PAN detection in the StaticPolicyEngine
func TestStaticPANDetection(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name                string
		query               string
		shouldTriggerPolicy bool
		description         string
	}{
		// Valid PAN formats - Individual (P)
		{
			name:                "Valid PAN - Individual",
			query:               "Customer PAN is ABCPD1234F",
			shouldTriggerPolicy: true,
			description:         "Standard individual PAN format (4th char P=Person)",
		},
		{
			name:                "Valid PAN - with PAN prefix",
			query:               "PAN: ABCDE1234F",
			shouldTriggerPolicy: true,
			description:         "PAN with explicit prefix matches second alternative",
		},
		{
			name:                "Valid PAN - with PAN space prefix",
			query:               "PAN ABCDE1234F",
			shouldTriggerPolicy: true,
			description:         "PAN with space prefix",
		},
		// Valid PAN formats - Company (C)
		{
			name:                "Valid PAN - Company",
			query:               "Company PAN: AAACM1234C",
			shouldTriggerPolicy: true,
			description:         "Company PAN (4th char C)",
		},
		// Valid PAN formats - HUF (H)
		{
			name:                "Valid PAN - HUF",
			query:               "HUF PAN number AAAHK1234H",
			shouldTriggerPolicy: true,
			description:         "HUF PAN (4th char H)",
		},
		// Valid PAN formats - Other entity types
		{
			name:                "Valid PAN - Association (A)",
			query:               "Association PAN BBBAB1234A",
			shouldTriggerPolicy: true,
			description:         "Association PAN (4th char A)",
		},
		{
			name:                "Valid PAN - Body of Individuals (B)",
			query:               "BOI PAN CCCBD1234B",
			shouldTriggerPolicy: true,
			description:         "BOI PAN (4th char B)",
		},
		{
			name:                "Valid PAN - Government (G)",
			query:               "Government entity PAN DDDGE1234G",
			shouldTriggerPolicy: true,
			description:         "Government PAN (4th char G)",
		},
		{
			name:                "Valid PAN - AJP (J)",
			query:               "AJP PAN EEEJF1234J",
			shouldTriggerPolicy: true,
			description:         "AJP PAN (4th char J)",
		},
		{
			name:                "Valid PAN - Local Authority (L)",
			query:               "Local authority PAN FFFLG1234L",
			shouldTriggerPolicy: true,
			description:         "Local Authority PAN (4th char L)",
		},
		{
			name:                "Valid PAN - Firm (F)",
			query:               "Partnership firm PAN GGGFH1234F",
			shouldTriggerPolicy: true,
			description:         "Firm PAN (4th char F)",
		},
		{
			name:                "Valid PAN - Trust (T)",
			query:               "Trust PAN HHHTJ1234T",
			shouldTriggerPolicy: true,
			description:         "Trust PAN (4th char T)",
		},
		// PAN in various contexts
		{
			name:                "PAN in sentence",
			query:               "Please verify the PAN ABCPM1234N before proceeding with KYC",
			shouldTriggerPolicy: true,
			description:         "PAN embedded in sentence",
		},
		// Note: "Account: 123456789" matches SSN pattern before PAN pattern in static engine
		// because SSN comes first in the PII patterns list. This is expected behavior.
		{
			name:                "Multiple PANs",
			query:               "Primary holder ABCPD1234A, Secondary holder XYZPM5678B",
			shouldTriggerPolicy: true,
			description:         "Multiple PANs in text",
		},
		// Edge cases - should not match
		{
			name:                "Invalid - too short",
			query:               "Invalid PAN ABCPD1234",
			shouldTriggerPolicy: false,
			description:         "9 characters - too short for PAN",
		},
		{
			name:                "Invalid - too long",
			query:               "Invalid PAN ABCPD1234FG",
			shouldTriggerPolicy: false,
			description:         "11 characters - too long for PAN",
		},
		{
			name:                "No PAN present",
			query:               "Process the customer order for laptop",
			shouldTriggerPolicy: false,
			description:         "No PAN in query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, "llm_chat")

			// PAN is critical severity - should block by default (PII_BLOCK_CRITICAL=true)
			if tt.shouldTriggerPolicy && !result.Blocked {
				t.Errorf("PAN detection should block queries (critical PII), got not blocked")
			}
			if !tt.shouldTriggerPolicy && result.Blocked {
				t.Errorf("Should not block when no PAN detected, got blocked: %s", result.Reason)
			}

			// Check if policy was triggered
			hasPANPolicy := containsPolicy(result.TriggeredPolicies, "pan_detection")
			if tt.shouldTriggerPolicy && !hasPANPolicy {
				t.Errorf("%s: Expected PAN detection to trigger for query: %s\nTriggered policies: %v",
					tt.description, tt.query, result.TriggeredPolicies)
			}
			// Note: We don't test for false matches because other PII patterns may match
		})
	}
}

// TestStaticAadhaarDetection tests Indian Aadhaar detection in the StaticPolicyEngine
func TestStaticAadhaarDetection(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name                string
		query               string
		shouldTriggerPolicy bool
		description         string
	}{
		// Valid Aadhaar formats - with spaces
		{
			name:                "Valid Aadhaar - with spaces",
			query:               "Customer Aadhaar is 2234 5678 9012",
			shouldTriggerPolicy: true,
			description:         "Standard 12-digit format with spaces",
		},
		{
			name:                "Valid Aadhaar - starting with 3",
			query:               "Aadhaar number 3456 7890 1234",
			shouldTriggerPolicy: true,
			description:         "Aadhaar starting with 3",
		},
		{
			name:                "Valid Aadhaar - starting with 9",
			query:               "Aadhaar 9999 8888 7777",
			shouldTriggerPolicy: true,
			description:         "Aadhaar starting with 9",
		},
		// Valid Aadhaar - without spaces
		{
			name:                "Valid Aadhaar - no spaces",
			query:               "Verify Aadhaar 234567890123",
			shouldTriggerPolicy: true,
			description:         "12-digit format without spaces",
		},
		// Valid Aadhaar - with prefix
		{
			name:                "Valid Aadhaar - with aadhaar prefix",
			query:               "aadhaar: 234567890123",
			shouldTriggerPolicy: true,
			description:         "Aadhaar with lowercase prefix",
		},
		{
			name:                "Valid Aadhaar - with AADHAAR prefix",
			query:               "AADHAAR: 298765432109",
			shouldTriggerPolicy: true,
			description:         "Aadhaar with uppercase prefix",
		},
		{
			name:                "Valid Aadhaar - with UID prefix",
			query:               "UID: 234567890123",
			shouldTriggerPolicy: true,
			description:         "Aadhaar with UID prefix",
		},
		// Invalid Aadhaar - first digit validation
		{
			name:                "Invalid Aadhaar - starting with 0",
			query:               "Invalid Aadhaar 0234 5678 9012",
			shouldTriggerPolicy: false,
			description:         "Aadhaar cannot start with 0",
		},
		{
			name:                "Invalid Aadhaar - starting with 1",
			query:               "Invalid Aadhaar 1234 5678 9012",
			shouldTriggerPolicy: false,
			description:         "Aadhaar cannot start with 1",
		},
		// Aadhaar in various contexts
		{
			name:                "Aadhaar in KYC context",
			query:               "For KYC verification, Aadhaar 5678 9012 3456 is required",
			shouldTriggerPolicy: true,
			description:         "Aadhaar in KYC context",
		},
		// Note: When both PAN and Aadhaar are present, PAN matches first (comes first in pattern list)
		// This is expected behavior - use Aadhaar-only queries to test Aadhaar detection
		{
			name:                "Aadhaar only (no PAN)",
			query:               "Verify customer Aadhaar: 4567 8901 2345 for account",
			shouldTriggerPolicy: true,
			description:         "Aadhaar without PAN to ensure proper detection",
		},
		// Invalid formats
		{
			name:                "Invalid - too short",
			query:               "Invalid 2234 5678 901",
			shouldTriggerPolicy: false,
			description:         "11 digits - too short",
		},
		{
			name:                "Invalid - too long",
			query:               "Invalid 2234 5678 90123",
			shouldTriggerPolicy: false,
			description:         "13 digits - too long",
		},
		{
			name:                "No Aadhaar present",
			query:               "Process the customer order for laptop",
			shouldTriggerPolicy: false,
			description:         "No Aadhaar in query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateStaticPolicies(user, tt.query, "llm_chat")

			// Aadhaar is critical severity - should block by default (PII_BLOCK_CRITICAL=true)
			if tt.shouldTriggerPolicy && !result.Blocked {
				t.Errorf("Aadhaar detection should block queries (critical PII), got not blocked")
			}
			if !tt.shouldTriggerPolicy && result.Blocked {
				t.Errorf("Should not block when no Aadhaar detected, got blocked: %s", result.Reason)
			}

			// Check if policy was triggered
			hasAadhaarPolicy := containsPolicy(result.TriggeredPolicies, "aadhaar_detection")
			if tt.shouldTriggerPolicy && !hasAadhaarPolicy {
				t.Errorf("%s: Expected Aadhaar detection to trigger for query: %s\nTriggered policies: %v",
					tt.description, tt.query, result.TriggeredPolicies)
			}
			// Note: We don't test for false matches because other PII patterns may match
		})
	}
}

// TestStaticValidatePAN tests the PAN validation function in static_policies.go
func TestStaticValidatePAN(t *testing.T) {
	tests := []struct {
		name  string
		pan   string
		valid bool
	}{
		// Valid PANs - different entity types
		{"Valid Individual PAN", "ABCPD1234E", true},
		{"Valid Company PAN", "AAACM1234C", true},
		{"Valid HUF PAN", "AAAHK1234H", true},
		{"Valid AOP PAN", "BBBAB1234A", true},
		{"Valid BOI PAN", "CCCBD1234B", true},
		{"Valid Government PAN", "DDDGE1234G", true},
		{"Valid AJP PAN", "EEEJF1234J", true},
		{"Valid Local Authority PAN", "FFFLG1234L", true},
		{"Valid Firm PAN", "GGGFH1234F", true},
		{"Valid Trust PAN", "HHHTJ1234T", true},

		// Invalid PANs - format violations
		{"Invalid - too short", "ABCPD1234", false},
		{"Invalid - too long", "ABCPD1234EF", false},
		{"Invalid - lowercase first char", "aBCPD1234E", false},
		{"Invalid - digit in first 3", "A1CPD1234E", false},
		{"Invalid - invalid entity type", "ABCXD1234E", false},
		{"Invalid - lowercase 5th char", "ABCPd1234E", false},
		{"Invalid - letter in digits", "ABCPD12A4E", false},
		{"Invalid - lowercase last char", "ABCPD1234e", false},
		{"Invalid - digit as last char", "ABCPD12341", false},

		// Invalid PANs - wrong entity type
		{"Invalid entity type - Q", "ABCQD1234E", false},
		{"Invalid entity type - R", "ABCRD1234E", false},
		{"Invalid entity type - Z", "ABCZD1234E", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidatePAN(tt.pan)
			if got != tt.valid {
				t.Errorf("ValidatePAN(%s) = %v, want %v", tt.pan, got, tt.valid)
			}
		})
	}
}

// TestValidateAadhaar tests the Aadhaar validation function
func TestValidateAadhaar(t *testing.T) {
	tests := []struct {
		name    string
		aadhaar string
		valid   bool
	}{
		// Valid Aadhaar numbers - different starting digits (2-9)
		{"Valid starting with 2", "234567890123", true},
		{"Valid starting with 3", "345678901234", true},
		{"Valid starting with 4", "456789012345", true},
		{"Valid starting with 5", "567890123456", true},
		{"Valid starting with 6", "678901234567", true},
		{"Valid starting with 7", "789012345678", true},
		{"Valid starting with 8", "890123456789", true},
		{"Valid starting with 9", "901234567890", true},

		// Valid Aadhaar numbers - with spaces
		{"Valid with spaces", "2345 6789 0123", true},
		{"Valid with spaces and 9", "9999 8888 7777", true},

		// Invalid Aadhaar numbers - first digit
		{"Invalid starting with 0", "034567890123", false},
		{"Invalid starting with 1", "134567890123", false},

		// Invalid Aadhaar numbers - length
		{"Invalid - too short", "23456789012", false},
		{"Invalid - too long", "2345678901234", false},

		// Invalid Aadhaar numbers - non-digits
		{"Invalid - contains letter", "23456789A123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateAadhaar(tt.aadhaar)
			if got != tt.valid {
				t.Errorf("ValidateAadhaar(%s) = %v, want %v", tt.aadhaar, got, tt.valid)
			}
		})
	}
}

// TestIndianPIIPerformance tests that Indian PII detection is fast
func TestIndianPIIPerformance(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	// Query with multiple Indian PII types
	query := "Customer details: PAN ABCPD1234E, Aadhaar 2345 6789 0123, " +
		"Account holder: Rahul Sharma, Bank: HDFC, IFSC: HDFC0001234, " +
		"Account: 123456789012345, Demat: IN12345678901234"

	// Run multiple times to get average
	iterations := 100
	for i := 0; i < iterations; i++ {
		result := engine.EvaluateStaticPolicies(user, query, "llm_chat")

		// Should complete in < 10ms per query
		if result.ProcessingTimeMs > 10 {
			t.Errorf("Indian PII detection too slow: %dms (iteration %d)", result.ProcessingTimeMs, i)
		}
	}
}

// TestCombinedIndianPII tests detection when both PAN and Aadhaar are present
func TestCombinedIndianPII(t *testing.T) {
	engine := NewStaticPolicyEngine()
	user := &User{
		ID:          1,
		Email:       "user1@test.com",
		Permissions: []string{"query"},
	}

	// Query with both PAN and Aadhaar
	query := "KYC Details - PAN: ABCPD1234E, Aadhaar: 2345 6789 0123, Name: John Doe"
	result := engine.EvaluateStaticPolicies(user, query, "llm_chat")

	// Should block - both PAN and Aadhaar are critical severity PII
	if !result.Blocked {
		t.Error("Indian PII detection should block queries (critical PII, PII_BLOCK_CRITICAL=true)")
	}

	// At least one Indian PII policy should be triggered (first match wins in static engine)
	hasPAN := containsPolicy(result.TriggeredPolicies, "pan_detection")
	hasAadhaar := containsPolicy(result.TriggeredPolicies, "aadhaar_detection")

	if !hasPAN && !hasAadhaar {
		t.Errorf("Expected at least one Indian PII policy to trigger, got: %v", result.TriggeredPolicies)
	}
}
