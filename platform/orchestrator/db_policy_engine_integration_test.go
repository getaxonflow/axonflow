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

	// Set DATABASE_URL for NewDatabaseDynamicPolicyEngine() which reads from env
	_ = os.Setenv("DATABASE_URL", dbURL)
	defer func() { _ = os.Unsetenv("DATABASE_URL") }()

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

	// Set DATABASE_URL for NewDatabaseDynamicPolicyEngine() which reads from env
	_ = os.Setenv("DATABASE_URL", dbURL)
	defer func() { _ = os.Unsetenv("DATABASE_URL") }()

	// Create test database connection to insert test policy
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Insert test policy directly using the actual schema
	testPolicyName := "test_refresh_policy_" + time.Now().Format("20060102150405")
	_, err = db.Exec(`
		INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, priority, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (policy_id) DO NOTHING
	`, testPolicyName, "Test Refresh Policy", "Test policy for refresh", "test", "{}", "{}", "test-tenant", 100, true)
	if err != nil {
		t.Fatalf("Failed to insert test policy: %v", err)
	}

	// Clean up test policy after test
	defer func() { _, _ = db.Exec("DELETE FROM dynamic_policies WHERE policy_id = $1", testPolicyName) }()

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

	// Verify our test policy is in the list
	found := false
	for _, policy := range policies {
		if policy.Name == testPolicyName {
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

	// Set DATABASE_URL for NewDatabaseDynamicPolicyEngine() which reads from env
	_ = os.Setenv("DATABASE_URL", dbURL)
	defer func() { _ = os.Unsetenv("DATABASE_URL") }()

	// Create test database connection
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Insert specific test policy
	testPolicyName := "test_get_policy_" + time.Now().Format("20060102150405")
	_, err = db.Exec(`
		INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, priority, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (policy_id) DO NOTHING
	`, testPolicyName, "Test Get Policy", "Test policy for get", "test", "{}", "{}", "test-tenant", 50, true)
	if err != nil {
		t.Fatalf("Failed to insert test policy: %v", err)
	}
	defer func() { _, _ = db.Exec("DELETE FROM dynamic_policies WHERE policy_id = $1", testPolicyName) }()

	// Create policy engine
	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to initialize DB policy engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	// Get the specific policy - GetPolicy returns (map[string]interface{}, bool)
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

	// Set DATABASE_URL for NewDatabaseDynamicPolicyEngine() which reads from env
	_ = os.Setenv("DATABASE_URL", dbURL)
	defer func() { _ = os.Unsetenv("DATABASE_URL") }()

	// Create test database connection
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Insert test policy
	testPolicyName := "test_eval_policy_" + time.Now().Format("20060102150405")
	_, err = db.Exec(`
		INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, priority, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (policy_id) DO NOTHING
	`, testPolicyName, "Test Eval Policy", "Test policy for evaluation", "test", "{}", "{}", "test-tenant", 100, true)
	if err != nil {
		t.Fatalf("Failed to insert test policy: %v", err)
	}
	defer func() { _, _ = db.Exec("DELETE FROM dynamic_policies WHERE policy_id = $1", testPolicyName) }()

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
	// Test with invalid database URL - should return error
	_ = os.Setenv("DATABASE_URL", "postgresql://invalid:invalid@nonexistent:5432/invalid")
	defer func() { _ = os.Unsetenv("DATABASE_URL") }()

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

	// Set DATABASE_URL for NewDatabaseDynamicPolicyEngine() which reads from env
	_ = os.Setenv("DATABASE_URL", dbURL)
	defer func() { _ = os.Unsetenv("DATABASE_URL") }()

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
