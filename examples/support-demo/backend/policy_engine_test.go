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

package main

import (
	"context"
	"regexp"
	"testing"
)

// TestNewPolicyEngine verifies that a new policy engine is created with default rules
func TestNewPolicyEngine(t *testing.T) {
	engine := NewPolicyEngine()

	if engine == nil {
		t.Fatal("NewPolicyEngine returned nil")
	}

	// Verify default policies are loaded
	if len(engine.policies) == 0 {
		t.Error("Expected default policies to be loaded, got 0")
	}

	// Verify default DLP rules are loaded
	if len(engine.dlpRules) == 0 {
		t.Error("Expected default DLP rules to be loaded, got 0")
	}

	// Verify default blocked queries are loaded
	if len(engine.blockedQueries) == 0 {
		t.Error("Expected default blocked queries to be loaded, got 0")
	}
}

// TestEvaluateQuery_BlockedQueries tests that dangerous queries are blocked
func TestEvaluateQuery_BlockedQueries(t *testing.T) {
	engine := NewPolicyEngine()
	ctx := context.Background()
	user := User{
		Email:       "test@example.com",
		Role:        "agent",
		Permissions: []string{"query"},
	}

	tests := []struct {
		name        string
		query       string
		shouldBlock bool
		description string
	}{
		{
			name:        "DROP TABLE should be blocked",
			query:       "DROP TABLE users",
			shouldBlock: true,
			description: "SQL injection: DROP TABLE",
		},
		{
			name:        "TRUNCATE TABLE should be blocked",
			query:       "TRUNCATE TABLE customers",
			shouldBlock: true,
			description: "SQL injection: TRUNCATE",
		},
		{
			name:        "DELETE without WHERE should be blocked",
			query:       "DELETE FROM customers;",
			shouldBlock: true,
			description: "SQL injection: DELETE ALL",
		},
		{
			name:        "UNION SELECT should be blocked",
			query:       "SELECT * FROM users UNION SELECT * FROM passwords",
			shouldBlock: true,
			description: "SQL injection: UNION",
		},
		{
			name:        "Safe SELECT should be allowed",
			query:       "Show me all open tickets",
			shouldBlock: false,
			description: "Safe natural language query",
		},
		{
			name:        "Information schema access blocked",
			query:       "SELECT * FROM information_schema.tables",
			shouldBlock: true,
			description: "System schema access attempt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateQuery(ctx, user, tt.query, "natural_language")

			if tt.shouldBlock && result.Allowed {
				t.Errorf("Expected query to be blocked: %s", tt.description)
			}
			if !tt.shouldBlock && !result.Allowed {
				t.Errorf("Expected query to be allowed: %s, blocked by: %v", tt.description, result.BlockedBy)
			}
		})
	}
}

// TestEvaluateDLPRules tests PII detection patterns
func TestEvaluateDLPRules(t *testing.T) {
	engine := NewPolicyEngine()
	user := User{Email: "test@example.com"}

	tests := []struct {
		name           string
		text           string
		expectedTypes  []string
		shouldDetect   bool
	}{
		{
			name:          "Detect SSN",
			text:          "Customer SSN is 123-45-6789",
			expectedTypes: []string{"ssn"},
			shouldDetect:  true,
		},
		{
			name:          "Detect credit card",
			text:          "Card number: 4111-1111-1111-1111",
			expectedTypes: []string{"credit_card"},
			shouldDetect:  true,
		},
		{
			name:          "Detect phone number",
			text:          "Call me at 555-123-4567",
			expectedTypes: []string{"phone"},
			shouldDetect:  true,
		},
		{
			name:          "Detect email",
			text:          "Contact user@example.com for support",
			expectedTypes: []string{"email"},
			shouldDetect:  true,
		},
		{
			name:          "Detect API key",
			text:          "API key: sk-1234567890abcdefghijklmnopqrstuv",
			expectedTypes: []string{"api_key"},
			shouldDetect:  true,
		},
		{
			name:          "No PII in text",
			text:          "This is a normal customer inquiry about products",
			expectedTypes: []string{},
			shouldDetect:  false,
		},
		{
			name:          "Multiple PII types",
			text:          "SSN: 123-45-6789, Card: 4111-1111-1111-1111",
			expectedTypes: []string{"ssn", "credit_card"},
			shouldDetect:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := engine.evaluateDLPRules(tt.text, user)

			if tt.shouldDetect && len(results) == 0 {
				t.Errorf("Expected to detect PII but got no results")
			}
			if !tt.shouldDetect && len(results) > 0 {
				t.Errorf("Expected no PII but detected: %v", results)
			}

			if tt.shouldDetect {
				// Check that expected types are detected
				detectedTypes := make(map[string]bool)
				for _, r := range results {
					detectedTypes[r.DataType] = true
				}
				for _, expected := range tt.expectedTypes {
					if !detectedTypes[expected] {
						t.Errorf("Expected to detect %s but didn't", expected)
					}
				}
			}
		})
	}
}

// TestRedactSensitiveData tests PII redaction based on user permissions
func TestRedactSensitiveData(t *testing.T) {
	engine := NewPolicyEngine()

	tests := []struct {
		name           string
		text           string
		user           User
		shouldRedact   bool
		expectedOutput string
	}{
		{
			name: "Agent cannot see SSN",
			text: "Customer SSN: 123-45-6789",
			user: User{
				Role:        "agent",
				Permissions: []string{"query"},
			},
			shouldRedact:   true,
			expectedOutput: "Customer SSN: [REDACTED_SSN]",
		},
		{
			name: "Manager can see SSN with read_pii permission",
			text: "Customer SSN: 123-45-6789",
			user: User{
				Role:        "manager",
				Permissions: []string{"read_pii"},
			},
			shouldRedact:   false,
			expectedOutput: "Customer SSN: 123-45-6789",
		},
		{
			name: "Admin can see all PII",
			text: "SSN: 123-45-6789, Card: 4111-1111-1111-1111",
			user: User{
				Role:        "admin",
				Permissions: []string{"admin", "read_pii"},
			},
			shouldRedact:   false,
			expectedOutput: "SSN: 123-45-6789, Card: 4111-1111-1111-1111",
		},
		{
			name: "Agent sees redacted credit card",
			text: "Payment card: 4111-1111-1111-1111",
			user: User{
				Role:        "agent",
				Permissions: []string{"query"},
			},
			shouldRedact:   true,
			expectedOutput: "Payment card: [REDACTED_CARD]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redacted, detectedTypes := engine.RedactSensitiveData(tt.text, tt.user)

			if len(detectedTypes) == 0 {
				t.Error("Expected PII to be detected")
			}

			if tt.shouldRedact && redacted == tt.text {
				t.Error("Expected text to be redacted but it wasn't")
			}
			if !tt.shouldRedact && redacted != tt.text {
				t.Errorf("Expected text to remain unchanged but got: %s", redacted)
			}
		})
	}
}

// TestCanUserSeePII tests permission checks for PII visibility
func TestCanUserSeePII(t *testing.T) {
	engine := NewPolicyEngine()

	tests := []struct {
		name     string
		user     User
		dataType string
		canSee   bool
	}{
		{
			name:     "Agent without permissions cannot see SSN",
			user:     User{Permissions: []string{"query"}},
			dataType: "ssn",
			canSee:   false,
		},
		{
			name:     "User with read_ssn can see SSN",
			user:     User{Permissions: []string{"read_ssn"}},
			dataType: "ssn",
			canSee:   true,
		},
		{
			name:     "User with read_pii can see all PII",
			user:     User{Permissions: []string{"read_pii"}},
			dataType: "ssn",
			canSee:   true,
		},
		{
			name:     "User with read_financial can see credit cards",
			user:     User{Permissions: []string{"read_financial"}},
			dataType: "credit_card",
			canSee:   true,
		},
		{
			name:     "Admin can see medical records",
			user:     User{Permissions: []string{"admin"}},
			dataType: "medical_record",
			canSee:   true,
		},
		{
			name:     "Agent cannot see medical records",
			user:     User{Permissions: []string{"query"}},
			dataType: "medical_record",
			canSee:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.canUserSeePII(tt.user, tt.dataType)
			if result != tt.canSee {
				t.Errorf("canUserSeePII() = %v, want %v", result, tt.canSee)
			}
		})
	}
}

// TestMatchStringCondition tests string matching operators
func TestMatchStringCondition(t *testing.T) {
	engine := NewPolicyEngine()

	tests := []struct {
		name     string
		value    string
		operator string
		condVal  interface{}
		expected bool
	}{
		{
			name:     "equals - match",
			value:    "admin",
			operator: "equals",
			condVal:  "admin",
			expected: true,
		},
		{
			name:     "equals - no match",
			value:    "user",
			operator: "equals",
			condVal:  "admin",
			expected: false,
		},
		{
			name:     "contains - match",
			value:    "support_team",
			operator: "contains",
			condVal:  "support",
			expected: true,
		},
		{
			name:     "contains - no match",
			value:    "engineering",
			operator: "contains",
			condVal:  "support",
			expected: false,
		},
		{
			name:     "not_equals - match",
			value:    "user",
			operator: "not_equals",
			condVal:  "admin",
			expected: true,
		},
		{
			name:     "not_equals - no match",
			value:    "admin",
			operator: "not_equals",
			condVal:  "admin",
			expected: false,
		},
		{
			name:     "matches - regex match",
			value:    "agent_123",
			operator: "matches",
			condVal:  "agent_\\d+",
			expected: true,
		},
		{
			name:     "matches - regex no match",
			value:    "manager_abc",
			operator: "matches",
			condVal:  "agent_\\d+",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.matchStringCondition(tt.value, tt.operator, tt.condVal)
			if result != tt.expected {
				t.Errorf("matchStringCondition(%s, %s, %v) = %v, want %v",
					tt.value, tt.operator, tt.condVal, result, tt.expected)
			}
		})
	}
}

// TestCheckBlockedQueries tests blocked query pattern matching
func TestCheckBlockedQueries(t *testing.T) {
	engine := NewPolicyEngine()

	tests := []struct {
		name    string
		query   string
		blocked bool
	}{
		{"DROP TABLE blocked", "drop table users", true},
		{"TRUNCATE blocked", "truncate table customers", true},
		{"ALTER TABLE blocked", "alter table users add column", true},
		{"CREATE USER blocked", "create user hacker", true},
		{"GRANT blocked", "grant all privileges to user", true},
		{"Safe SELECT allowed", "select * from tickets where status = 'open'", false},
		{"Natural language allowed", "Show me recent support tickets", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := engine.checkBlockedQueries(tt.query)
			isBlocked := rule != nil

			if isBlocked != tt.blocked {
				t.Errorf("checkBlockedQueries(%q) blocked=%v, want %v", tt.query, isBlocked, tt.blocked)
			}
		})
	}
}

// TestContainsPII tests PII detection helper
func TestContainsPII(t *testing.T) {
	engine := NewPolicyEngine()

	tests := []struct {
		name        string
		text        string
		containsPII bool
	}{
		{"SSN detected", "My SSN is 123-45-6789", true},
		{"Credit card detected", "Card 4111-1111-1111-1111", true},
		{"Phone detected", "Call 555-123-4567", true},
		{"No PII", "Hello, how can I help you today?", false},
		{"Product name not PII", "Order #12345 for Widget Pro", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.containsPII(tt.text)
			if result != tt.containsPII {
				t.Errorf("containsPII(%q) = %v, want %v", tt.text, result, tt.containsPII)
			}
		})
	}
}

// TestPolicyEvaluationWithViolations tests that violations are properly recorded
func TestPolicyEvaluationWithViolations(t *testing.T) {
	engine := NewPolicyEngine()
	ctx := context.Background()

	// Test with a query that should trigger a violation
	user := User{
		Email:       "test@example.com",
		Role:        "agent",
		Permissions: []string{"query"},
	}

	// This should trigger the SQL injection prevention
	result := engine.EvaluateQuery(ctx, user, "DROP TABLE users", "sql_query")

	if len(result.Violations) == 0 {
		t.Error("Expected violations to be recorded for blocked query")
	}

	if len(result.BlockedBy) == 0 {
		t.Error("Expected BlockedBy to contain the blocking rule ID")
	}

	// Verify violation has required fields
	for _, v := range result.Violations {
		if v.ID == "" {
			t.Error("Violation ID should not be empty")
		}
		if v.UserEmail != user.Email {
			t.Errorf("Violation user email = %s, want %s", v.UserEmail, user.Email)
		}
		if v.Timestamp.IsZero() {
			t.Error("Violation timestamp should not be zero")
		}
	}
}

// TestDLPRulePatterns tests that DLP regex patterns are valid
func TestDLPRulePatterns(t *testing.T) {
	engine := NewPolicyEngine()

	for _, rule := range engine.dlpRules {
		t.Run(rule.Name, func(t *testing.T) {
			if rule.Pattern == nil {
				t.Errorf("Rule %s has nil pattern", rule.ID)
			}

			// Verify pattern compiles
			_, err := regexp.Compile(rule.PatternStr)
			if err != nil {
				t.Errorf("Rule %s pattern failed to compile: %v", rule.ID, err)
			}

			// Verify rule has required fields
			if rule.ID == "" {
				t.Error("Rule ID should not be empty")
			}
			if rule.DataType == "" {
				t.Error("Rule DataType should not be empty")
			}
			if rule.RedactWith == "" {
				t.Error("Rule RedactWith should not be empty")
			}
		})
	}
}

// TestBlockedQueryPatterns tests that blocked query regex patterns are valid
func TestBlockedQueryPatterns(t *testing.T) {
	engine := NewPolicyEngine()

	for _, rule := range engine.blockedQueries {
		t.Run(rule.Name, func(t *testing.T) {
			if rule.Pattern == nil {
				t.Errorf("Rule %s has nil pattern", rule.ID)
			}

			// Verify pattern compiles
			_, err := regexp.Compile(rule.PatternStr)
			if err != nil {
				t.Errorf("Rule %s pattern failed to compile: %v", rule.ID, err)
			}

			// Verify rule has required fields
			if rule.ID == "" {
				t.Error("Rule ID should not be empty")
			}
			if rule.Reason == "" {
				t.Error("Rule Reason should not be empty")
			}
		})
	}
}
