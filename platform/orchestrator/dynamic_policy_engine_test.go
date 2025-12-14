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

package orchestrator

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestNewDynamicPolicyEngine tests engine initialization
func TestNewDynamicPolicyEngine(t *testing.T) {
	engine := NewDynamicPolicyEngine()

	if engine == nil {
		t.Fatal("Expected non-nil engine")
	}

	if engine.riskCalculator == nil {
		t.Error("Expected risk calculator to be initialized")
	}

	if engine.cache == nil {
		t.Error("Expected cache to be initialized")
	}

	if len(engine.policies) == 0 {
		t.Error("Expected default policies to be loaded")
	}

	if !engine.IsHealthy() {
		t.Error("Expected engine to be healthy after initialization")
	}
}

// TestLoadDefaultDynamicPolicies tests default policy loading
func TestLoadDefaultDynamicPolicies(t *testing.T) {
	policies := loadDefaultDynamicPolicies()

	if len(policies) == 0 {
		t.Fatal("Expected default policies to be loaded")
	}

	// Verify all policies have required fields
	for _, policy := range policies {
		if policy.ID == "" {
			t.Error("Policy should have ID")
		}

		if policy.Name == "" {
			t.Error("Policy should have name")
		}

		if len(policy.Conditions) == 0 {
			t.Error("Policy should have conditions")
		}

		if len(policy.Actions) == 0 {
			t.Error("Policy should have actions")
		}

		if !policy.Enabled {
			t.Errorf("Default policy %s should be enabled", policy.ID)
		}
	}

	// Verify specific policies exist
	expectedPolicies := map[string]bool{
		"pol_high_risk_block":           false,
		"pol_sensitive_data_control":    false,
		"pol_hipaa_compliance":          false,
		"pol_financial_data_protection": false,
		"pol_tenant_isolation":          false,
	}

	for _, policy := range policies {
		if _, exists := expectedPolicies[policy.ID]; exists {
			expectedPolicies[policy.ID] = true
		}
	}

	for policyID, found := range expectedPolicies {
		if !found {
			t.Errorf("Expected default policy %s not found", policyID)
		}
	}
}

// TestEvaluateCondition tests condition evaluation logic
func TestEvaluateCondition(t *testing.T) {
	engine := &DynamicPolicyEngine{
		riskCalculator: NewRiskCalculator(),
	}

	tests := []struct {
		name      string
		condition PolicyCondition
		req       OrchestratorRequest
		result    *PolicyEvaluationResult
		expected  bool
	}{
		{
			name: "Contains operator - match",
			condition: PolicyCondition{
				Field:    "query",
				Operator: "contains",
				Value:    "SELECT",
			},
			req: OrchestratorRequest{
				Query: "SELECT * FROM users",
			},
			result:   &PolicyEvaluationResult{},
			expected: true,
		},
		{
			name: "Contains operator - no match",
			condition: PolicyCondition{
				Field:    "query",
				Operator: "contains",
				Value:    "DELETE",
			},
			req: OrchestratorRequest{
				Query: "SELECT * FROM users",
			},
			result:   &PolicyEvaluationResult{},
			expected: false,
		},
		{
			name: "Equals operator - match",
			condition: PolicyCondition{
				Field:    "user.role",
				Operator: "equals",
				Value:    "admin",
			},
			req: OrchestratorRequest{
				User: UserContext{Role: "admin"},
			},
			result:   &PolicyEvaluationResult{},
			expected: true,
		},
		{
			name: "Equals operator - no match",
			condition: PolicyCondition{
				Field:    "user.role",
				Operator: "equals",
				Value:    "admin",
			},
			req: OrchestratorRequest{
				User: UserContext{Role: "user"},
			},
			result:   &PolicyEvaluationResult{},
			expected: false,
		},
		{
			name: "Not equals operator",
			condition: PolicyCondition{
				Field:    "user.role",
				Operator: "not_equals",
				Value:    "admin",
			},
			req: OrchestratorRequest{
				User: UserContext{Role: "user"},
			},
			result:   &PolicyEvaluationResult{},
			expected: true,
		},
		{
			name: "Greater than operator - true",
			condition: PolicyCondition{
				Field:    "risk_score",
				Operator: "greater_than",
				Value:    0.5,
			},
			req:      OrchestratorRequest{},
			result:   &PolicyEvaluationResult{RiskScore: 0.8},
			expected: true,
		},
		{
			name: "Greater than operator - false",
			condition: PolicyCondition{
				Field:    "risk_score",
				Operator: "greater_than",
				Value:    0.9,
			},
			req:      OrchestratorRequest{},
			result:   &PolicyEvaluationResult{RiskScore: 0.5},
			expected: false,
		},
		{
			name: "Less than operator - true",
			condition: PolicyCondition{
				Field:    "risk_score",
				Operator: "less_than",
				Value:    0.5,
			},
			req:      OrchestratorRequest{},
			result:   &PolicyEvaluationResult{RiskScore: 0.3},
			expected: true,
		},
		{
			name: "Regex operator - match",
			condition: PolicyCondition{
				Field:    "query",
				Operator: "regex",
				Value:    "(?i)(DROP|DELETE|TRUNCATE)",
			},
			req: OrchestratorRequest{
				Query: "DROP TABLE users",
			},
			result:   &PolicyEvaluationResult{},
			expected: true,
		},
		{
			name: "Regex operator - no match",
			condition: PolicyCondition{
				Field:    "query",
				Operator: "regex",
				Value:    "(?i)(DROP|DELETE|TRUNCATE)",
			},
			req: OrchestratorRequest{
				Query: "SELECT * FROM users",
			},
			result:   &PolicyEvaluationResult{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.req, tt.result)

			if result != tt.expected {
				t.Errorf("Expected %v, got %v for condition %+v", tt.expected, result, tt.condition)
			}
		})
	}
}

// TestGetFieldValue tests field value extraction
func TestGetFieldValue(t *testing.T) {
	engine := &DynamicPolicyEngine{}

	tests := []struct {
		name     string
		field    string
		req      OrchestratorRequest
		result   *PolicyEvaluationResult
		expected interface{}
	}{
		{
			name:  "Query field",
			field: "query",
			req: OrchestratorRequest{
				Query: "SELECT * FROM test",
			},
			result:   &PolicyEvaluationResult{},
			expected: "SELECT * FROM test",
		},
		{
			name:  "Request type field",
			field: "request_type",
			req: OrchestratorRequest{
				RequestType: "sql",
			},
			result:   &PolicyEvaluationResult{},
			expected: "sql",
		},
		{
			name:  "User role field",
			field: "user.role",
			req: OrchestratorRequest{
				User: UserContext{Role: "admin"},
			},
			result:   &PolicyEvaluationResult{},
			expected: "admin",
		},
		{
			name:  "User email field",
			field: "user.email",
			req: OrchestratorRequest{
				User: UserContext{Email: "user@example.com"},
			},
			result:   &PolicyEvaluationResult{},
			expected: "user@example.com",
		},
		{
			name:  "User tenant_id field",
			field: "user.tenant_id",
			req: OrchestratorRequest{
				User: UserContext{TenantID: "tenant-123"},
			},
			result:   &PolicyEvaluationResult{},
			expected: "tenant-123",
		},
		{
			name:  "Client ID field",
			field: "client.id",
			req: OrchestratorRequest{
				Client: ClientContext{ID: "client-456"},
			},
			result:   &PolicyEvaluationResult{},
			expected: "client-456",
		},
		{
			name:  "Client name field",
			field: "client.name",
			req: OrchestratorRequest{
				Client: ClientContext{Name: "Test Client"},
			},
			result:   &PolicyEvaluationResult{},
			expected: "Test Client",
		},
		{
			name:     "Risk score field",
			field:    "risk_score",
			req:      OrchestratorRequest{},
			result:   &PolicyEvaluationResult{RiskScore: 0.75},
			expected: 0.75,
		},
		{
			name:  "Context field",
			field: "context.industry",
			req: OrchestratorRequest{
				Context: map[string]interface{}{
					"industry": "healthcare",
				},
			},
			result:   &PolicyEvaluationResult{},
			expected: "healthcare",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.getFieldValue(tt.field, tt.req, tt.result)

			if result != tt.expected {
				t.Errorf("Expected %v, got %v for field %s", tt.expected, result, tt.field)
			}
		})
	}
}

// TestApplyPolicyAction tests policy action application
func TestApplyPolicyAction(t *testing.T) {
	engine := &DynamicPolicyEngine{}
	ctx := context.Background()

	tests := []struct {
		name           string
		action         PolicyAction
		req            OrchestratorRequest
		initialResult  *PolicyEvaluationResult
		expectedAllowed bool
		expectedActions int
	}{
		{
			name: "Block action",
			action: PolicyAction{
				Type: "block",
				Config: map[string]interface{}{
					"reason": "Test block",
				},
			},
			req:             OrchestratorRequest{},
			initialResult:   &PolicyEvaluationResult{Allowed: true, RequiredActions: []string{}},
			expectedAllowed: false,
			expectedActions: 1,
		},
		{
			name: "Redact action",
			action: PolicyAction{
				Type: "redact",
				Config: map[string]interface{}{
					"fields": []string{"salary", "ssn"},
				},
			},
			req:             OrchestratorRequest{},
			initialResult:   &PolicyEvaluationResult{Allowed: true, RequiredActions: []string{}},
			expectedAllowed: true,
			expectedActions: 1,
		},
		{
			name: "Modify risk action",
			action: PolicyAction{
				Type: "modify_risk",
				Config: map[string]interface{}{
					"modifier": 1.5,
				},
			},
			req:             OrchestratorRequest{},
			initialResult:   &PolicyEvaluationResult{Allowed: true, RiskScore: 0.5, RequiredActions: []string{}},
			expectedAllowed: true,
			expectedActions: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.initialResult
			engine.applyPolicyAction(ctx, tt.action, tt.req, result)

			if result.Allowed != tt.expectedAllowed {
				t.Errorf("Expected Allowed=%v, got %v", tt.expectedAllowed, result.Allowed)
			}

			if len(result.RequiredActions) != tt.expectedActions {
				t.Errorf("Expected %d actions, got %d", tt.expectedActions, len(result.RequiredActions))
			}

			// Verify modify_risk actually modifies the score
			if tt.action.Type == "modify_risk" {
				expectedScore := 0.5 * 1.5
				if result.RiskScore != expectedScore {
					t.Errorf("Expected risk score %v, got %v", expectedScore, result.RiskScore)
				}
			}
		})
	}
}

// TestGetApplicablePolicies tests policy filtering
func TestGetApplicablePolicies(t *testing.T) {
	engine := &DynamicPolicyEngine{
		policies: []DynamicPolicy{
			{
				ID:       "pol_enabled",
				Name:     "Enabled Policy",
				Enabled:  true,
				TenantID: "",
			},
			{
				ID:       "pol_disabled",
				Name:     "Disabled Policy",
				Enabled:  false,
				TenantID: "",
			},
			{
				ID:       "pol_tenant_a",
				Name:     "Tenant A Policy",
				Enabled:  true,
				TenantID: "tenant-a",
			},
			{
				ID:       "pol_tenant_b",
				Name:     "Tenant B Policy",
				Enabled:  true,
				TenantID: "tenant-b",
			},
		},
	}

	tests := []struct {
		name          string
		req           OrchestratorRequest
		expectedCount int
		expectedIDs   []string
	}{
		{
			name: "No tenant - get global policies only",
			req: OrchestratorRequest{
				User: UserContext{TenantID: ""},
			},
			expectedCount: 1,
			expectedIDs:   []string{"pol_enabled"},
		},
		{
			name: "Tenant A - get global + tenant A policies",
			req: OrchestratorRequest{
				User: UserContext{TenantID: "tenant-a"},
			},
			expectedCount: 2,
			expectedIDs:   []string{"pol_enabled", "pol_tenant_a"},
		},
		{
			name: "Tenant B - get global + tenant B policies",
			req: OrchestratorRequest{
				User: UserContext{TenantID: "tenant-b"},
			},
			expectedCount: 2,
			expectedIDs:   []string{"pol_enabled", "pol_tenant_b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applicable := engine.getApplicablePolicies(tt.req)

			if len(applicable) != tt.expectedCount {
				t.Errorf("Expected %d policies, got %d", tt.expectedCount, len(applicable))
			}

			// Verify expected policies are present
			for _, expectedID := range tt.expectedIDs {
				found := false
				for _, policy := range applicable {
					if policy.ID == expectedID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected policy %s not found in applicable policies", expectedID)
				}
			}
		})
	}
}

// TestCalculateRiskScore tests risk score calculation
func TestCalculateRiskScore(t *testing.T) {
	calculator := NewRiskCalculator()

	tests := []struct {
		name         string
		req          OrchestratorRequest
		expectedMin  float64
		expectedMax  float64
		shouldBeZero bool
	}{
		{
			name: "Simple SELECT query",
			req: OrchestratorRequest{
				Query: "SELECT id, name FROM users WHERE id = 1",
				User:  UserContext{Role: "user"},
			},
			shouldBeZero: true,
		},
		{
			name: "SQL injection pattern - UNION",
			req: OrchestratorRequest{
				Query: "SELECT * FROM users UNION SELECT * FROM admin",
				User:  UserContext{Role: "user"},
			},
			expectedMin: 0.9,
			expectedMax: 1.0,
		},
		{
			name: "SQL injection pattern - DROP TABLE",
			req: OrchestratorRequest{
				Query: "DROP TABLE users",
				User:  UserContext{Role: "user"},
			},
			expectedMin: 0.9,
			expectedMax: 1.0,
		},
		{
			name: "Admin query",
			req: OrchestratorRequest{
				Query: "SELECT id, name FROM users",
				User:  UserContext{Role: "admin"},
			},
			expectedMin: 0.5,
			expectedMax: 0.5,
		},
		{
			name: "Large result set query",
			req: OrchestratorRequest{
				Query: "SELECT * FROM users",
				User:  UserContext{Role: "user"},
			},
			expectedMin: 0.3,
			expectedMax: 0.3,
		},
		{
			name: "Sensitive keyword - password",
			req: OrchestratorRequest{
				Query: "SELECT password FROM users",
				User:  UserContext{Role: "user"},
			},
			// Sensitive data keywords (password, secret, key, token) use sensitive_data weight (0.7)
			// SQL injection patterns use sql_injection weight (0.9) via unified sqli scanner
			expectedMin: 0.7,
			expectedMax: 0.7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := calculator.CalculateRiskScore(tt.req)

			if tt.shouldBeZero {
				if score != 0.0 {
					t.Errorf("Expected risk score 0.0, got %v", score)
				}
			} else {
				if score < tt.expectedMin || score > tt.expectedMax {
					t.Errorf("Expected risk score between %v and %v, got %v",
						tt.expectedMin, tt.expectedMax, score)
				}
			}

			// Score should always be normalized to 0-1
			if score < 0.0 || score > 1.0 {
				t.Errorf("Risk score should be between 0 and 1, got %v", score)
			}
		})
	}
}

// TestPolicyCache tests cache operations
func TestPolicyCache(t *testing.T) {
	cache := NewPolicyCache(5 * time.Minute)

	// Test Set and Get
	testKey := "test-key"
	testValue := &PolicyEvaluationResult{
		Allowed:   false,
		RiskScore: 0.9,
	}

	cache.Set(testKey, testValue)

	retrieved, found := cache.Get(testKey)
	if !found {
		t.Error("Expected to find cached value")
	}

	if retrieved != testValue {
		t.Error("Retrieved value does not match stored value")
	}

	// Test Get non-existent key
	_, found = cache.Get("non-existent-key")
	if found {
		t.Error("Should not find non-existent key")
	}
}

// TestUtilityFunctions tests utility functions
func TestCompareNumeric(t *testing.T) {
	tests := []struct {
		name     string
		a        interface{}
		b        interface{}
		operator string
		expected bool
	}{
		{"Greater than - true", 10, 5, ">", true},
		{"Greater than - false", 5, 10, ">", false},
		{"Less than - true", 5, 10, "<", true},
		{"Less than - false", 10, 5, "<", false},
		{"Greater or equal - true (greater)", 10, 5, ">=", true},
		{"Greater or equal - true (equal)", 10, 10, ">=", true},
		{"Less or equal - true (less)", 5, 10, "<=", true},
		{"Less or equal - true (equal)", 10, 10, "<=", true},
		{"Float comparison", 3.5, 2.1, ">", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareNumeric(tt.a, tt.b, tt.operator)
			if result != tt.expected {
				t.Errorf("compareNumeric(%v, %v, %s) = %v, expected %v",
					tt.a, tt.b, tt.operator, result, tt.expected)
			}
		})
	}
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected float64
		shouldOk bool
	}{
		{"float64", float64(3.14), 3.14, true},
		{"float32", float32(2.5), 2.5, true},
		{"int", int(42), 42.0, true},
		{"int64", int64(100), 100.0, true},
		{"string - invalid", "not a number", 0, false},
		{"nil - invalid", nil, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := toFloat64(tt.input)
			if ok != tt.shouldOk {
				t.Errorf("toFloat64(%v) ok = %v, expected %v", tt.input, ok, tt.shouldOk)
			}
			if ok && result != tt.expected {
				t.Errorf("toFloat64(%v) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMatchRegex(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		pattern  string
		expected bool
	}{
		{"Simple match", "hello world", "world", true},
		{"No match", "hello world", "goodbye", false},
		{"Case insensitive match", "Hello World", "(?i)world", true},
		{"Pattern with special chars", "user@example.com", `\w+@\w+\.\w+`, true},
		{"Invalid regex - returns false", "any text", `[invalid(regex`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchRegex(tt.text, tt.pattern)
			if result != tt.expected {
				t.Errorf("matchRegex(%q, %q) = %v, expected %v",
					tt.text, tt.pattern, result, tt.expected)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		slice    interface{}
		item     interface{}
		expected bool
	}{
		{"String slice - contains", []string{"apple", "banana", "cherry"}, "banana", true},
		{"String slice - not contains", []string{"apple", "banana", "cherry"}, "grape", false},
		{"Interface slice - contains", []interface{}{"a", "b", "c"}, "b", true},
		{"Interface slice - not contains", []interface{}{"a", "b", "c"}, "d", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.slice, tt.item)
			if result != tt.expected {
				t.Errorf("contains(%v, %v) = %v, expected %v",
					tt.slice, tt.item, result, tt.expected)
			}
		})
	}
}

// TestListActivePolicies tests active policy listing
func TestListActivePolicies(t *testing.T) {
	engine := &DynamicPolicyEngine{
		policies: []DynamicPolicy{
			{ID: "pol_1", Name: "Policy 1", Enabled: true},
			{ID: "pol_2", Name: "Policy 2", Enabled: false},
			{ID: "pol_3", Name: "Policy 3", Enabled: true},
		},
	}

	active := engine.ListActivePolicies()

	if len(active) != 2 {
		t.Errorf("Expected 2 active policies, got %d", len(active))
	}

	for _, policy := range active {
		if !policy.Enabled {
			t.Errorf("Policy %s should be enabled", policy.ID)
		}
	}
}

// TestIsHealthy tests health check
func TestIsHealthy(t *testing.T) {
	tests := []struct {
		name     string
		policies []DynamicPolicy
		expected bool
	}{
		{
			name:     "Healthy - has policies",
			policies: []DynamicPolicy{{ID: "pol_1", Name: "Test"}},
			expected: true,
		},
		{
			name:     "Unhealthy - no policies",
			policies: []DynamicPolicy{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := &DynamicPolicyEngine{
				policies: tt.policies,
			}

			result := engine.IsHealthy()
			if result != tt.expected {
				t.Errorf("Expected IsHealthy=%v, got %v", tt.expected, result)
			}
		})
	}
}

// TestGenerateCacheKey tests cache key generation
func TestGenerateCacheKey(t *testing.T) {
	engine := &DynamicPolicyEngine{}

	req1 := OrchestratorRequest{
		User:        UserContext{Email: "user@test.com", Role: "user"},
		RequestType: "sql",
		Query:       "SELECT * FROM test",
	}

	req2 := OrchestratorRequest{
		User:        UserContext{Email: "user@test.com", Role: "user"},
		RequestType: "sql",
		Query:       "SELECT * FROM test",
	}

	req3 := OrchestratorRequest{
		User:        UserContext{Email: "user@test.com", Role: "admin"},
		RequestType: "sql",
		Query:       "SELECT * FROM test",
	}

	key1 := engine.generateCacheKey(req1)
	key2 := engine.generateCacheKey(req2)
	key3 := engine.generateCacheKey(req3)

	// Same requests should generate same keys
	if key1 != key2 {
		t.Error("Same requests should generate same cache keys")
	}

	// Different requests should generate different keys
	if key1 == key3 {
		t.Error("Different requests should generate different cache keys")
	}
}

// TestEvaluatePolicy tests full policy evaluation
func TestEvaluatePolicy(t *testing.T) {
	engine := &DynamicPolicyEngine{
		riskCalculator: NewRiskCalculator(),
	}
	ctx := context.Background()

	tests := []struct {
		name     string
		policy   DynamicPolicy
		req      OrchestratorRequest
		expected bool
	}{
		{
			name: "All conditions met",
			policy: DynamicPolicy{
				ID:   "test_policy",
				Name: "Test Policy",
				Conditions: []PolicyCondition{
					{Field: "query", Operator: "contains", Value: "SELECT"},
					{Field: "user.role", Operator: "equals", Value: "user"},
				},
			},
			req: OrchestratorRequest{
				Query: "SELECT * FROM users",
				User:  UserContext{Role: "user"},
			},
			expected: true,
		},
		{
			name: "One condition not met",
			policy: DynamicPolicy{
				ID:   "test_policy",
				Name: "Test Policy",
				Conditions: []PolicyCondition{
					{Field: "query", Operator: "contains", Value: "SELECT"},
					{Field: "user.role", Operator: "equals", Value: "admin"},
				},
			},
			req: OrchestratorRequest{
				Query: "SELECT * FROM users",
				User:  UserContext{Role: "user"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &PolicyEvaluationResult{}
			matched := engine.evaluatePolicy(ctx, tt.policy, tt.req, result)

			if matched != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, matched)
			}
		})
	}
}

// TestLoadPoliciesFromDB tests database policy loading
func TestLoadPoliciesFromDB(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(sqlmock.Sqlmock)
		expectError   bool
		expectCount   int
	}{
		{
			name: "Successfully load policies from database",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "description", "policy_type",
					"conditions", "actions", "priority", "enabled", "tenant_id",
					"created_at", "updated_at",
				}).
					AddRow(
						"1", "policy_001", "Block SQL Injection", "Blocks SQL injection attempts",
						"security",
						[]byte(`[{"field": "risk_score", "operator": "greater_than", "value": 0.8}]`),
						[]byte(`[{"type": "block", "config": {"reason": "SQL injection detected"}}]`),
						100, true, sql.NullString{String: "tenant1", Valid: true},
						time.Now(), time.Now(),
					).
					AddRow(
						"2", "policy_002", "Redact PII", "Redacts personally identifiable information",
						"privacy",
						[]byte(`[{"field": "query", "operator": "contains", "value": "email"}]`),
						[]byte(`[{"type": "redact", "config": {"fields": ["email", "ssn"]}}]`),
						90, true, sql.NullString{Valid: false},
						time.Now(), time.Now(),
					)

				mock.ExpectQuery("SELECT (.+) FROM dynamic_policies WHERE enabled = true").
					WillReturnRows(rows)

				// Expect audit log insert after successful load
				mock.ExpectExec("INSERT INTO orchestrator_audit_logs").
					WithArgs("orchestrator", "dynamic_policy_refresh", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectError: false,
			expectCount: 2,
		},
		{
			name: "Database query fails",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT (.+) FROM dynamic_policies").
					WillReturnError(fmt.Errorf("connection timeout"))
			},
			expectError: true,
			expectCount: 0,
		},
		{
			name: "Empty result set - loads only defaults",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "description", "policy_type",
					"conditions", "actions", "priority", "enabled", "tenant_id",
					"created_at", "updated_at",
				})

				mock.ExpectQuery("SELECT (.+) FROM dynamic_policies WHERE enabled = true").
					WillReturnRows(rows)
			},
			expectError: false,
			expectCount: 0,
		},
		{
			name: "Skip malformed JSON in conditions",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "description", "policy_type",
					"conditions", "actions", "priority", "enabled", "tenant_id",
					"created_at", "updated_at",
				}).
					AddRow(
						"3", "policy_003", "Bad Policy", "Has invalid JSON",
						"security",
						[]byte(`{invalid json}`),
						[]byte(`{"action": "block"}`),
						50, true, sql.NullString{Valid: false},
						time.Now(), time.Now(),
					)

				mock.ExpectQuery("SELECT (.+) FROM dynamic_policies WHERE enabled = true").
					WillReturnRows(rows)
			},
			expectError: false,
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh mock database for each test
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock DB: %v", err)
			}
			defer func() { _ = db.Close() }()

			// Setup mock expectations
			tt.setupMock(mock)

			// Create engine with mock DB
			engine := &DynamicPolicyEngine{
				db:          db,
				dbAvailable: true,
				policies:    []DynamicPolicy{},
			}

			// Execute
			err = engine.loadPoliciesFromDB()

			// Verify error expectation
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verify policy count (excluding defaults)
			if !tt.expectError {
				defaultCount := len(loadDefaultDynamicPolicies())
				actualDBPolicies := len(engine.policies) - defaultCount
				if actualDBPolicies != tt.expectCount {
					t.Errorf("Expected %d policies from DB, got %d", tt.expectCount, actualDBPolicies)
				}
			}

			// Verify all mock expectations were met
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled mock expectations: %v", err)
			}
		})
	}
}

// TestLoadPoliciesFromDB_NilDatabase tests nil database handling
func TestLoadPoliciesFromDB_NilDatabase(t *testing.T) {
	engine := &DynamicPolicyEngine{
		db:          nil,
		dbAvailable: false,
	}

	err := engine.loadPoliciesFromDB()
	if err == nil {
		t.Error("Expected error with nil database")
	}
	if err.Error() != "database not available" {
		t.Errorf("Expected 'database not available' error, got: %v", err)
	}
}

// TestLogAuditEvent tests audit event logging
func TestLogAuditEvent(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(sqlmock.Sqlmock)
		expectError bool
	}{
		{
			name: "Successfully log audit event",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO orchestrator_audit_logs").
					WithArgs("orchestrator", "policy_reload", "Reloaded 10 policies", sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectError: false,
		},
		{
			name: "Database insert fails - should not panic",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO orchestrator_audit_logs").
					WillReturnError(fmt.Errorf("insert failed"))
			},
			expectError: false, // Function logs error but doesn't return it
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh mock database for each test
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock DB: %v", err)
			}
			defer func() { _ = db.Close() }()

			// Setup mock expectations
			tt.setupMock(mock)

			// Create engine with mock DB
			engine := &DynamicPolicyEngine{
				db:          db,
				dbAvailable: true,
			}

			// Execute - should not panic even on error
			engine.logAuditEvent("policy_reload", "Reloaded 10 policies")

			// Verify all mock expectations were met
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled mock expectations: %v", err)
			}
		})
	}
}

// TestLogAuditEvent_NilDatabase tests nil database handling
func TestLogAuditEvent_NilDatabase(t *testing.T) {
	engine := &DynamicPolicyEngine{
		db:          nil,
		dbAvailable: false,
	}

	// Should not panic with nil database
	engine.logAuditEvent("test_action", "test details")
}

// TestGetTenantSpecificPolicies tests tenant-specific policy filtering
func TestGetTenantSpecificPolicies(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(sqlmock.Sqlmock, *DynamicPolicyEngine)
		tenantID      string
		expectCount   int
		expectQuery   bool
	}{
		{
			name: "Successfully filter tenant policies",
			setupMock: func(mock sqlmock.Sqlmock, engine *DynamicPolicyEngine) {
				// Mock the COUNT query
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

				// Add test policies to engine
				engine.policies = []DynamicPolicy{
					{ID: "policy-1", TenantID: "tenant-1", Name: "Policy 1"},
					{ID: "policy-2", TenantID: "tenant-2", Name: "Policy 2"},
					{ID: "policy-3", TenantID: "tenant-1", Name: "Policy 3"},
				}
			},
			tenantID:    "tenant-1",
			expectCount: 2,
			expectQuery: true,
		},
		{
			name: "No policies for tenant",
			setupMock: func(mock sqlmock.Sqlmock, engine *DynamicPolicyEngine) {
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
					WithArgs("tenant-999").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

				engine.policies = []DynamicPolicy{
					{ID: "policy-1", TenantID: "tenant-1", Name: "Policy 1"},
				}
			},
			tenantID:    "tenant-999",
			expectCount: 0,
			expectQuery: true,
		},
		{
			name: "Database query fails - returns filtered policies anyway",
			setupMock: func(mock sqlmock.Sqlmock, engine *DynamicPolicyEngine) {
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
					WithArgs("tenant-1").
					WillReturnError(fmt.Errorf("query failed"))

				engine.policies = []DynamicPolicy{
					{ID: "policy-1", TenantID: "tenant-1", Name: "Policy 1"},
				}
			},
			tenantID:    "tenant-1",
			expectCount: 1,
			expectQuery: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh mock database
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock DB: %v", err)
			}
			defer func() { _ = db.Close() }()

			// Create engine with mock DB
			engine := &DynamicPolicyEngine{
				db:          db,
				dbAvailable: true,
			}

			// Setup mock expectations and policies
			tt.setupMock(mock, engine)

			// Execute
			tenantPolicies := engine.getTenantSpecificPolicies(tt.tenantID)

			// Verify count
			if len(tenantPolicies) != tt.expectCount {
				t.Errorf("Expected %d tenant policies, got %d", tt.expectCount, len(tenantPolicies))
			}

			// Verify all policies belong to the tenant
			for _, p := range tenantPolicies {
				if p.TenantID != tt.tenantID {
					t.Errorf("Policy %s has wrong tenant: %s, expected %s", p.ID, p.TenantID, tt.tenantID)
				}
			}

			// Verify mock expectations
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled mock expectations: %v", err)
			}
		})
	}
}

// TestGetTenantSpecificPolicies_NilDatabase tests nil database handling
func TestGetTenantSpecificPolicies_NilDatabase(t *testing.T) {
	engine := &DynamicPolicyEngine{
		db:          nil,
		dbAvailable: false,
	}

	result := engine.getTenantSpecificPolicies("tenant-1")
	if result != nil {
		t.Error("Expected nil result when database is not available")
	}
}

// TestLogPolicyHit tests policy metrics logging
func TestLogPolicyHit(t *testing.T) {
	tests := []struct {
		name        string
		policyID    string
		userID      string
		allowed     bool
		setupMock   func(sqlmock.Sqlmock)
		expectError bool
	}{
		{
			name:     "Successfully log policy hit - allowed",
			policyID: "policy-001",
			userID:   "user-123",
			allowed:  true,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO policy_metrics").
					WithArgs("policy-001", 0). // blockCount = 0 for allowed
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectError: false,
		},
		{
			name:     "Successfully log policy hit - blocked",
			policyID: "policy-002",
			userID:   "user-456",
			allowed:  false,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO policy_metrics").
					WithArgs("policy-002", 1). // blockCount = 1 for blocked
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectError: false,
		},
		{
			name:     "Database insert fails - should not panic",
			policyID: "policy-003",
			userID:   "user-789",
			allowed:  true,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO policy_metrics").
					WillReturnError(fmt.Errorf("insert failed"))
			},
			expectError: false, // Function logs error but doesn't return it
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh mock database
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock DB: %v", err)
			}
			defer func() { _ = db.Close() }()

			// Setup mock expectations
			tt.setupMock(mock)

			// Create engine with mock DB
			engine := &DynamicPolicyEngine{
				db:          db,
				dbAvailable: true,
			}

			// Execute - should not panic even on error
			engine.logPolicyHit(tt.policyID, tt.userID, tt.allowed)

			// Verify all mock expectations were met
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled mock expectations: %v", err)
			}
		})
	}
}

// TestLogPolicyHit_NilDatabase tests nil database handling
func TestLogPolicyHit_NilDatabase(t *testing.T) {
	engine := &DynamicPolicyEngine{
		db:          nil,
		dbAvailable: false,
	}

	// Should not panic with nil database
	engine.logPolicyHit("policy-001", "user-123", true)
}

// TestGetFieldValue_AdditionalCases tests additional field value extraction cases
func TestGetFieldValue_AdditionalCases(t *testing.T) {
	engine := &DynamicPolicyEngine{}

	req := OrchestratorRequest{
		Query:       "test query",
		RequestType: "query",
		User: UserContext{
			Role:        "admin",
			Email:       "test@example.com",
			TenantID:    "tenant-123",
			Permissions: []string{"read", "write"},
		},
		Client: ClientContext{
			ID:   "client-1",
			Name: "Test Client",
		},
		Context: map[string]interface{}{
			"env": "production",
		},
	}

	result := &PolicyEvaluationResult{
		RiskScore: 75.5,
	}

	tests := []struct {
		name     string
		field    string
		expected interface{}
	}{
		{
			name:     "user.email",
			field:    "user.email",
			expected: "test@example.com",
		},
		{
			name:     "user.tenant_id",
			field:    "user.tenant_id",
			expected: "tenant-123",
		},
		{
			name:     "client.id",
			field:    "client.id",
			expected: "client-1",
		},
		{
			name:     "client.name",
			field:    "client.name",
			expected: "Test Client",
		},
		{
			name:     "context key",
			field:    "context.env",
			expected: "production",
		},
		{
			name:     "unknown field",
			field:    "unknown_field",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.getFieldValue(tt.field, req, result)
			if got != tt.expected {
				t.Errorf("getFieldValue(%s) = %v, want %v", tt.field, got, tt.expected)
			}
		})
	}
}

// TestEvaluateCondition_AdditionalOperators tests additional condition evaluation operators
func TestEvaluateCondition_AdditionalOperators(t *testing.T) {
	engine := &DynamicPolicyEngine{}

	req := OrchestratorRequest{
		Query:       "show me the customer passwords",
		RequestType: "query",
		User: UserContext{
			Role: "user",
		},
	}
	result := &PolicyEvaluationResult{
		RiskScore: 50,
	}

	tests := []struct {
		name      string
		condition PolicyCondition
		expected  bool
	}{
		{
			name: "not_equals - match",
			condition: PolicyCondition{
				Field:    "user.role",
				Operator: "not_equals",
				Value:    "admin",
			},
			expected: true,
		},
		{
			name: "not_equals - no match",
			condition: PolicyCondition{
				Field:    "user.role",
				Operator: "not_equals",
				Value:    "user",
			},
			expected: false,
		},
		{
			name: "greater_than - match",
			condition: PolicyCondition{
				Field:    "risk_score",
				Operator: "greater_than",
				Value:    float64(40),
			},
			expected: true,
		},
		{
			name: "greater_than - no match",
			condition: PolicyCondition{
				Field:    "risk_score",
				Operator: "greater_than",
				Value:    float64(60),
			},
			expected: false,
		},
		{
			name: "less_than - match",
			condition: PolicyCondition{
				Field:    "risk_score",
				Operator: "less_than",
				Value:    float64(60),
			},
			expected: true,
		},
		{
			name: "regex - match",
			condition: PolicyCondition{
				Field:    "query",
				Operator: "regex",
				Value:    "password[s]?",
			},
			expected: true,
		},
		{
			name: "regex - invalid pattern",
			condition: PolicyCondition{
				Field:    "query",
				Operator: "regex",
				Value:    "[invalid",
			},
			expected: false,
		},
		{
			name: "in - match",
			condition: PolicyCondition{
				Field:    "request_type",
				Operator: "in",
				Value:    []interface{}{"query", "mutation"},
			},
			expected: true,
		},
		{
			name: "in - no match",
			condition: PolicyCondition{
				Field:    "request_type",
				Operator: "in",
				Value:    []interface{}{"delete", "admin"},
			},
			expected: false,
		},
		{
			name: "unknown operator",
			condition: PolicyCondition{
				Field:    "query",
				Operator: "unknown_op",
				Value:    "test",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.evaluateCondition(tt.condition, req, result)
			if got != tt.expected {
				t.Errorf("evaluateCondition() = %v, want %v", got, tt.expected)
			}
		})
	}
}
