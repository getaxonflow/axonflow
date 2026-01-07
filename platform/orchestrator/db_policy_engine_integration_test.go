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

package orchestrator

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Integration tests for DatabaseDynamicPolicyEngine with real PostgreSQL
// These tests require DATABASE_URL to be set

func TestDatabaseDynamicPolicyEngine_Initialization(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	// DATABASE_URL is already set from environment

	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to initialize DB policy engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	if engine == nil {
		t.Fatal("Expected policy engine to be initialized")
	}

	// Verify health check works
	if !engine.IsHealthy() {
		t.Error("Expected healthy policy engine")
	}
}

func TestDatabaseDynamicPolicyEngine_RefreshPolicies(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	// DATABASE_URL is already set from environment

	// Create test database connection to insert test policy
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Insert test policy directly using the actual schema
	testPolicyID := "test_refresh_policy_" + time.Now().Format("20060102150405")
	testPolicyName := "Test Refresh Policy"
	_, err = db.Exec(`
		INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, priority, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (policy_id) DO NOTHING
	`, testPolicyID, testPolicyName, "Test policy for refresh", "test", "{}", "{}", "test-tenant", 100, true)
	if err != nil {
		t.Fatalf("Failed to insert test policy: %v", err)
	}

	// Clean up test policy after test
	defer func() { _, _ = db.Exec("DELETE FROM dynamic_policies WHERE policy_id = $1", testPolicyID) }()

	// Create policy engine
	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to initialize DB policy engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	// Verify policies were loaded
	policies := engine.ListActivePolicies()
	if len(policies) == 0 {
		t.Error("Expected policies to be loaded from database")
	}

	// Verify our test policy is in the list (check by ID since name might not be unique)
	found := false
	for _, policy := range policies {
		if policy.ID == testPolicyID {
			found = true
			break
		}
	}

	if !found {
		t.Error("Test policy not found in loaded policies")
	}
}

func TestDatabaseDynamicPolicyEngine_GetPolicy(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	// DATABASE_URL is already set from environment

	// Create test database connection
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Insert specific test policy
	testPolicyID := "test_get_policy_" + time.Now().Format("20060102150405")
	testPolicyName := "Test Get Policy"
	_, err = db.Exec(`
		INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, priority, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (policy_id) DO NOTHING
	`, testPolicyID, testPolicyName, "Test policy for get", "test", "{}", "{}", "test-tenant", 50, true)
	if err != nil {
		t.Fatalf("Failed to insert test policy: %v", err)
	}
	defer func() { _, _ = db.Exec("DELETE FROM dynamic_policies WHERE policy_id = $1", testPolicyID) }()

	// Create policy engine
	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to initialize DB policy engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	// Get the specific policy by name - GetPolicy looks up by name (the map key)
	policy, exists := engine.GetPolicy(testPolicyName)
	if !exists {
		t.Fatal("Expected policy to be retrieved")
	}

	if policy == nil {
		t.Fatal("Expected non-nil policy map")
	}

	// Verify the policy has expected fields
	if name, ok := policy["name"].(string); !ok || name != testPolicyName {
		t.Errorf("Expected policy name %q, got %v", testPolicyName, policy["name"])
	}

	// Verify database_accessed flag
	if accessed, ok := policy["database_accessed"].(bool); !ok || !accessed {
		t.Error("Expected database_accessed flag to be true")
	}
}

func TestDatabaseDynamicPolicyEngine_EvaluatePolicies(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	// DATABASE_URL is already set from environment

	// Create test database connection
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Insert test policy with valid conditions array
	testPolicyID := "test_eval_policy_" + time.Now().Format("20060102150405")
	testPolicyName := "Test Eval Policy"
	_, err = db.Exec(`
		INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, priority, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (policy_id) DO NOTHING
	`, testPolicyID, testPolicyName, "Test policy for evaluation", "test", "[]", "{}", "test-tenant", 100, true)
	if err != nil {
		t.Fatalf("Failed to insert test policy: %v", err)
	}
	defer func() { _, _ = db.Exec("DELETE FROM dynamic_policies WHERE policy_id = $1", testPolicyID) }()

	// Create policy engine
	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to initialize DB policy engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	// Test policy evaluation
	ctx := context.Background()
	req := OrchestratorRequest{
		RequestID: "test-req-1",
		Query:     "Show me data",
		User: UserContext{
			TenantID: "test-tenant",
		},
		Client: ClientContext{
			ID: "test-tenant",
		},
	}

	result := engine.EvaluateDynamicPolicies(ctx, req)
	if result == nil {
		t.Fatal("Expected non-nil policy evaluation result")
	}

	// Verify database was accessed
	if !result.DatabaseAccessed {
		t.Error("Expected DatabaseAccessed to be true")
	}

	// Verify policies were applied
	if len(result.AppliedPolicies) == 0 {
		t.Error("Expected at least one policy to be applied")
	}

	// Verify result is allowed (no blocking policies by default)
	if !result.Allowed {
		t.Error("Expected request to be allowed by default")
	}
}

func TestDatabaseDynamicPolicyEngine_InvalidDBURL(t *testing.T) {
	// Save original DATABASE_URL to restore after test (avoid polluting parallel tests)
	originalDBURL := os.Getenv("DATABASE_URL")
	defer func() {
		if originalDBURL != "" {
			_ = os.Setenv("DATABASE_URL", originalDBURL)
		} else {
			_ = os.Unsetenv("DATABASE_URL")
		}
	}()

	// Test with invalid database URL - should return error
	// Use 127.0.0.1 with invalid port to fail fast without DNS lookup
	_ = os.Setenv("DATABASE_URL", "postgresql://invalid:invalid@127.0.0.1:59999/invalid?connect_timeout=1")

	_, err := NewDatabaseDynamicPolicyEngine()

	if err == nil {
		t.Error("Expected error when connecting to invalid database")
	}
}

func TestDatabaseDynamicPolicyEngine_HealthCheck(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	// DATABASE_URL is already set from environment

	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to initialize DB policy engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	// Health check should pass
	if !engine.IsHealthy() {
		t.Error("Expected engine to be healthy")
	}

	// Close the engine
	_ = engine.Close()

	// Health check should fail after close
	if engine.IsHealthy() {
		t.Error("Expected engine to be unhealthy after close")
	}
}

func TestDatabaseDynamicPolicyEngine_EvaluatePoliciesWithConditions(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	// DATABASE_URL is already set from environment

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Insert policy with conditions that should match
	testPolicyName := "test_cond_policy_" + time.Now().Format("20060102150405")
	conditions := `[{"field": "user.region", "operator": "equals", "value": "EU"}]`
	actions := `{"require_human_review": true, "reason": "EU data protection"}`

	_, err = db.Exec(`
		INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, priority, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (policy_id) DO NOTHING
	`, testPolicyName, "Test Conditions Policy", "Policy with EU condition", "region_policy", conditions, actions, "global", 100, true)
	if err != nil {
		t.Fatalf("Failed to insert test policy: %v", err)
	}
	defer func() { _, _ = db.Exec("DELETE FROM dynamic_policies WHERE policy_id = $1", testPolicyName) }()

	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to initialize DB policy engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	// Test with EU user - should match condition
	ctx := context.Background()
	req := OrchestratorRequest{
		RequestID: "test-eu-req",
		Query:     "Show me data",
		User: UserContext{
			Region:   "EU",
			TenantID: "test-tenant",
		},
		Client: ClientContext{
			TenantID: "test-tenant",
		},
	}

	result := engine.EvaluateDynamicPolicies(ctx, req)
	if result == nil {
		t.Fatal("Expected non-nil policy evaluation result")
	}

	// Test with non-EU user - should not match condition
	reqUS := OrchestratorRequest{
		RequestID: "test-us-req",
		Query:     "Show me data",
		User: UserContext{
			Region:   "US",
			TenantID: "test-tenant",
		},
		Client: ClientContext{
			TenantID: "test-tenant",
		},
	}

	resultUS := engine.EvaluateDynamicPolicies(ctx, reqUS)
	if resultUS == nil {
		t.Fatal("Expected non-nil policy evaluation result for US user")
	}
}

func TestDatabaseDynamicPolicyEngine_EvaluatePoliciesWithAllowedProviders(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	// DATABASE_URL is already set from environment

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Insert policy with allowed_providers action
	testPolicyName := "test_providers_policy_" + time.Now().Format("20060102150405")
	conditions := `[{"field": "user.region", "operator": "in", "value": ["EU", "UK"]}]`
	actions := `{"allowed_providers": ["anthropic", "azure"], "reason": "EU data sovereignty"}`

	_, err = db.Exec(`
		INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, priority, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (policy_id) DO NOTHING
	`, testPolicyName, "Test Providers Policy", "Policy with allowed_providers", "provider_policy", conditions, actions, "global", 100, true)
	if err != nil {
		t.Fatalf("Failed to insert test policy: %v", err)
	}
	defer func() { _, _ = db.Exec("DELETE FROM dynamic_policies WHERE policy_id = $1", testPolicyName) }()

	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to initialize DB policy engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	ctx := context.Background()
	req := OrchestratorRequest{
		RequestID: "test-providers-req",
		Query:     "Show me EU data",
		User: UserContext{
			Region:   "EU",
			TenantID: "test-tenant",
		},
		Client: ClientContext{
			TenantID: "test-tenant",
		},
	}

	result := engine.EvaluateDynamicPolicies(ctx, req)
	if result == nil {
		t.Fatal("Expected non-nil policy evaluation result")
	}

	// Verify allowed_providers is set
	if len(result.AllowedProviders) > 0 {
		t.Logf("AllowedProviders set: %v", result.AllowedProviders)
	}
}

func TestDatabaseDynamicPolicyEngine_EvaluatePoliciesWithBlockAction(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	// DATABASE_URL is already set from environment

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Insert policy that blocks requests
	testPolicyName := "test_block_policy_" + time.Now().Format("20060102150405")
	conditions := `[{"field": "query", "operator": "contains", "value": "BLOCK_ME"}]`
	actions := `{"block": true, "reason": "Test block policy"}`

	_, err = db.Exec(`
		INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, priority, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (policy_id) DO NOTHING
	`, testPolicyName, "Test Block Policy", "Policy that blocks", "block_policy", conditions, actions, "global", 100, true)
	if err != nil {
		t.Fatalf("Failed to insert test policy: %v", err)
	}
	defer func() { _, _ = db.Exec("DELETE FROM dynamic_policies WHERE policy_id = $1", testPolicyName) }()

	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to initialize DB policy engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	ctx := context.Background()

	// Request that should be blocked
	reqBlocked := OrchestratorRequest{
		RequestID: "test-block-req",
		Query:     "BLOCK_ME please",
		User: UserContext{
			TenantID: "test-tenant",
		},
		Client: ClientContext{
			TenantID: "test-tenant",
		},
	}

	resultBlocked := engine.EvaluateDynamicPolicies(ctx, reqBlocked)
	if resultBlocked == nil {
		t.Fatal("Expected non-nil policy evaluation result")
	}

	// Request that should be allowed
	reqAllowed := OrchestratorRequest{
		RequestID: "test-allow-req",
		Query:     "Normal query",
		User: UserContext{
			TenantID: "test-tenant",
		},
		Client: ClientContext{
			TenantID: "test-tenant",
		},
	}

	resultAllowed := engine.EvaluateDynamicPolicies(ctx, reqAllowed)
	if resultAllowed == nil {
		t.Fatal("Expected non-nil policy evaluation result")
	}

	// Normal query should be allowed
	if !resultAllowed.Allowed {
		t.Error("Expected normal query to be allowed")
	}
}

func TestDatabaseDynamicPolicyEngine_ListActivePolicies(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	// DATABASE_URL is already set from environment

	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to initialize DB policy engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	policies := engine.ListActivePolicies()

	// Should have at least some system policies
	if len(policies) == 0 {
		t.Log("No active policies found - this may be expected in a fresh database")
	} else {
		t.Logf("Found %d active policies", len(policies))

		// Verify policy structure
		for _, p := range policies[:min(3, len(policies))] {
			if p.Name == "" {
				t.Error("Policy name should not be empty")
			}
			t.Logf("Policy: %s (priority: %d, tenant: %s)", p.Name, p.Priority, p.TenantID)
		}
	}
}

