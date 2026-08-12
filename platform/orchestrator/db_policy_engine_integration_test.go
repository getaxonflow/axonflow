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

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
)

// Integration tests for DatabaseDynamicPolicyEngine with real PostgreSQL
// Uses testcontainers if DATABASE_URL is not set

// setupTestDBEnv ensures DATABASE_URL is set, using testcontainers if needed.
// Returns a cleanup function to restore the original value.
//
// v9 Brief 11.5 / Session 20: NewDatabaseDynamicPolicyEngine now routes
// through agent.OpenAppRoleConnection. The testcontainer's master role
// (test_user) is NOT axonflow_app_role, so we pin AXONFLOW_DB_USE_APP_ROLE=false
// in this fixture to disable the helper's role assertion and let the
// constructor connect as test_user. Tests that exercise the app-role wire
// itself live in main_pool_app_role_test.go.
func setupTestDBEnv(t *testing.T) func() {
	t.Helper()

	originalURL := os.Getenv("DATABASE_URL")
	originalUseAppRole, useAppRoleWasSet := os.LookupEnv("AXONFLOW_DB_USE_APP_ROLE")
	os.Setenv("AXONFLOW_DB_USE_APP_ROLE", "false")
	restoreGate := func() {
		if useAppRoleWasSet {
			os.Setenv("AXONFLOW_DB_USE_APP_ROLE", originalUseAppRole)
		} else {
			os.Unsetenv("AXONFLOW_DB_USE_APP_ROLE")
		}
	}

	if originalURL != "" {
		// DATABASE_URL already set, nothing to do
		return restoreGate
	}

	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, dbPolicyEngineSchema())

	os.Setenv("DATABASE_URL", pg.URL)
	return func() {
		if originalURL != "" {
			os.Setenv("DATABASE_URL", originalURL)
		} else {
			os.Unsetenv("DATABASE_URL")
		}
		restoreGate()
	}
}

// dbPolicyEngineSchema returns the schema needed for policy engine tests.
//
// Includes Plugin Batch 1 (ADR-044) columns: id (UUID), risk_level,
// allow_override. These are populated in-memory by the engine's
// refreshPolicies SELECT and consumed downstream by override enforcement.
func dbPolicyEngineSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS dynamic_policies (
			id UUID NOT NULL DEFAULT gen_random_uuid(),
			policy_id VARCHAR(36) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			policy_type VARCHAR(50) NOT NULL,
			category VARCHAR(50) DEFAULT '',
			tier VARCHAR(50) DEFAULT 'tenant',
			conditions JSONB NOT NULL DEFAULT '[]',
			actions JSONB NOT NULL DEFAULT '[]',
			-- Production (migrations/core/010_policy_tables.sql) declares this
			-- NULLABLE with DEFAULT 'global'. The fixture used to say NOT NULL,
			-- which made the NULL-tenant row — the one refreshPolicies maps to
			-- the 'default' apply-to-all sentinel — impossible to reproduce in
			-- tests, hiding an entire tenant-scoping shape (#3059).
			-- migrations/core/155 additionally forbids the empty string; mirror
			-- that here so the fixture cannot accept a row production rejects.
			tenant_id VARCHAR(255) DEFAULT 'global'
				CONSTRAINT dynamic_policies_tenant_id_not_empty CHECK (tenant_id IS NULL OR tenant_id <> ''),
			-- ADR-060 (#2989 P3b) / migration 159: nullable, orthogonal to
			-- tenant_id. NULL (the default here) reproduces every pre-P3b row.
			segment_id VARCHAR(255),
			priority INTEGER DEFAULT 0,
			enabled BOOLEAN DEFAULT true,
			risk_level VARCHAR(20) DEFAULT 'medium',
			allow_override BOOLEAN DEFAULT false,
			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
		)
	`
}

func TestDatabaseDynamicPolicyEngine_Initialization(t *testing.T) {
	cleanup := setupTestDBEnv(t)
	defer cleanup()

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
	cleanup := setupTestDBEnv(t)
	defer cleanup()

	dbURL := os.Getenv("DATABASE_URL")

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

// TestDatabaseDynamicPolicyEngine_ListActivePoliciesForTenant_RealPostgres is
// the #3059 regression that a hand-built cache fixture cannot give us: it
// drives the REAL refreshPolicies path (SQL row → cache entry → _metadata) and
// asserts the scoped list against rows that Postgres, not the test, shaped.
//
// The first cut of the #3059 fix passed its fixture tests while still leaking,
// because the fixture never reproduced the row shapes refreshPolicies actually
// emits. This test seeds all four through real SQL — tenant A, tenant B,
// 'global', and a NULL tenant (which refreshPolicies maps to the 'default'
// sentinel) — and asserts on the owning tenant_id of every returned row.
func TestDatabaseDynamicPolicyEngine_ListActivePoliciesForTenant_RealPostgres(t *testing.T) {
	cleanup := setupTestDBEnv(t)
	defer cleanup()

	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	suffix := time.Now().Format("20060102150405.000000")
	tenantA := "3059-tenant-a-" + suffix
	tenantB := "3059-tenant-b-" + suffix

	// A distinctive condition value on tenant B's policy: proprietary regexes
	// are exactly what the pre-fix endpoint disclosed cross-tenant.
	seed := []struct {
		id       string
		name     string
		tenant   interface{} // string or nil (SQL NULL → "default" sentinel)
		condJSON string
	}{
		{"3059-a-" + suffix, "tenant A policy", tenantA, `[{"field":"q","operator":"regex","value":"AAA"}]`},
		{"3059-b-" + suffix, "tenant B policy", tenantB, `[{"field":"q","operator":"regex","value":"VICTIM-PROPRIETARY-[0-9]{9}"}]`},
		{"3059-g-" + suffix, "global policy", "global", `[{"field":"q","operator":"regex","value":"GGG"}]`},
		{"3059-n-" + suffix, "null tenant policy", nil, `[{"field":"q","operator":"regex","value":"NNN"}]`},
	}
	for _, s := range seed {
		_, err = db.Exec(`
			INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, priority, enabled)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (policy_id) DO NOTHING
		`, s.id, s.name, "#3059 scope fixture", "test", s.condJSON, "[]", s.tenant, 100, true)
		if err != nil {
			t.Fatalf("Failed to insert %s: %v", s.id, err)
		}
		defer func(id string) { _, _ = db.Exec("DELETE FROM dynamic_policies WHERE policy_id = $1", id) }(s.id)
	}

	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to initialize DB policy engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	// VACUITY CONTROL: tenant B's row must be in the deployment-wide cache
	// that refreshPolicies just loaded. Without this, "B is absent from A's
	// list" could just mean the seed never loaded.
	rawHasB := false
	for _, p := range engine.ListActivePolicies() {
		if p.ID == "3059-b-"+suffix {
			rawHasB = true
		}
	}
	if !rawHasB {
		t.Fatal("vacuity control failed: tenant B's policy is not in the raw cross-tenant cache; the assertions below would be vacuous")
	}

	scoped := engine.ListActivePoliciesForTenant(tenantA, nil)

	sawOwn, sawGlobal, sawDefault := false, false, false
	for _, p := range scoped {
		if p.TenantID == tenantB {
			t.Errorf("SECURITY: tenant A's scoped list contains a policy owned by tenant B (id=%s name=%s conditions=%+v)",
				p.ID, p.Name, p.Conditions)
		}
		switch p.TenantID {
		case tenantA:
			sawOwn = true
		case "global":
			sawGlobal = true
		case "default":
			sawDefault = true
		}
	}
	if !sawOwn {
		t.Error("tenant A's scoped list is missing tenant A's own policy")
	}
	if !sawGlobal {
		t.Error("tenant A's scoped list is missing the 'global' baseline policy")
	}
	if !sawDefault {
		t.Error("tenant A's scoped list is missing the NULL-tenant ('default') policy")
	}

	// Mirror check: tenant B still sees its own row (scoping is per-caller,
	// not a blanket suppression).
	scopedB := engine.ListActivePoliciesForTenant(tenantB, nil)
	foundBForB := false
	for _, p := range scopedB {
		if p.ID == "3059-b-"+suffix {
			foundBForB = true
		}
		if p.TenantID == tenantA {
			t.Errorf("SECURITY: tenant B's scoped list contains tenant A's policy (id=%s)", p.ID)
		}
	}
	if !foundBForB {
		t.Error("tenant B's scoped list is missing tenant B's own policy")
	}
}

// TestDBCachedPolicyListEnforceParity_RealPostgres pins the invariant that
// #3059's first cut asserted but did not hold: for every row shape that can
// reach the cache, "listed to tenant X" and "enforced for tenant X" must be
// the SAME decision. Both sides now call dbCachedPolicyAppliesToTenant, so the
// test is a guard against anyone re-introducing a second, parallel predicate.
func TestDBCachedPolicyListEnforceParity_RealPostgres(t *testing.T) {
	cleanup := setupTestDBEnv(t)
	defer cleanup()

	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	suffix := time.Now().Format("20060102150405.000000")
	caller := "3059-parity-caller-" + suffix
	other := "3059-parity-other-" + suffix

	rows := []struct {
		id     string
		tenant interface{}
	}{
		{"3059-p-own-" + suffix, caller},
		{"3059-p-other-" + suffix, other},
		{"3059-p-global-" + suffix, "global"},
		{"3059-p-null-" + suffix, nil},
	}
	for _, rw := range rows {
		_, err = db.Exec(`
			INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, priority, enabled)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (policy_id) DO NOTHING
		`, rw.id, rw.id, "#3059 parity fixture", "test", "[]", "[]", rw.tenant, 100, true)
		if err != nil {
			t.Fatalf("Failed to insert %s: %v", rw.id, err)
		}
		defer func(id string) { _, _ = db.Exec("DELETE FROM dynamic_policies WHERE policy_id = $1", id) }(rw.id)
	}

	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to initialize DB policy engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	listed := map[string]bool{}
	for _, p := range engine.ListActivePoliciesForTenant(caller, nil) {
		listed[p.ID] = true
	}

	// Enforcement side: ask the same choke point over the same cache entries.
	engine.mu.RLock()
	cacheSnapshot := make(map[string]interface{}, len(engine.policies))
	for k, v := range engine.policies {
		cacheSnapshot[k] = v
	}
	engine.mu.RUnlock()

	checked := 0
	for _, rw := range rows {
		entry, ok := cacheSnapshot[rw.id]
		if !ok {
			t.Fatalf("vacuity control failed: %s never reached the cache; parity below would be vacuous", rw.id)
		}
		policyMap, ok := entry.(map[string]interface{})
		if !ok {
			t.Fatalf("cache entry for %s is not a map", rw.id)
		}
		enforced := dbCachedPolicyAppliesToTenant(policyMap, caller, nil, rw.id)
		if enforced != listed[rw.id] {
			t.Errorf("list/enforce DIVERGENCE for %s (tenant=%v): enforced=%v listed=%v",
				rw.id, rw.tenant, enforced, listed[rw.id])
		}
		checked++
	}
	if checked != len(rows) {
		t.Fatalf("checked %d row shapes, want %d", checked, len(rows))
	}

	// The other tenant's row must be on the NOT-listed, NOT-enforced side.
	if listed["3059-p-other-"+suffix] {
		t.Error("SECURITY: another tenant's policy was listed to the caller")
	}
}

func TestDatabaseDynamicPolicyEngine_GetPolicy(t *testing.T) {
	cleanup := setupTestDBEnv(t)
	defer cleanup()

	dbURL := os.Getenv("DATABASE_URL")

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
	cleanup := setupTestDBEnv(t)
	defer cleanup()

	dbURL := os.Getenv("DATABASE_URL")

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
	cleanup := setupTestDBEnv(t)
	defer cleanup()

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
	cleanup := setupTestDBEnv(t)
	defer cleanup()

	dbURL := os.Getenv("DATABASE_URL")

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
	cleanup := setupTestDBEnv(t)
	defer cleanup()

	dbURL := os.Getenv("DATABASE_URL")

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
	cleanup := setupTestDBEnv(t)
	defer cleanup()

	dbURL := os.Getenv("DATABASE_URL")

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
	cleanup := setupTestDBEnv(t)
	defer cleanup()

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
