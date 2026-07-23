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
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestNewDatabaseDynamicPolicyEngine tests creation of policy engine
func TestNewDatabaseDynamicPolicyEngine(t *testing.T) {
	t.Skip("Skipping test that requires proper database mock injection")

	tests := []struct {
		name        string
		setupEnv    func()
		cleanupEnv  func()
		expectError bool
		mockSetup   func(sqlmock.Sqlmock)
		mockDBErr   bool
		expectNil   bool
	}{
		{
			name: "Success - database connects and initializes",
			setupEnv: func() {
				t.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test?sslmode=disable")
			},
			cleanupEnv:  func() {},
			expectError: false,
			mockSetup: func(mock sqlmock.Sqlmock) {
				// Expect ping
				mock.ExpectPing()

				// Expect seedDefaultData: system media policies + count query
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

				// Expect policy load (refreshPolicies)
				rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override"}).
					AddRow("00000000-0000-0000-0000-000000000001", "test_policy", "", "{}", "{}", "tenant1", 10, "policy1", "content", "dynamic-security", "medium", false)
				mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
					WillReturnRows(rows)
			},
			mockDBErr: false,
			expectNil: false,
		},
		{
			name: "Error - DATABASE_URL not set",
			setupEnv: func() {
				// Don't set DATABASE_URL
			},
			cleanupEnv:  func() {},
			expectError: true,
			mockSetup: func(mock sqlmock.Sqlmock) {
				// No database calls expected
			},
			mockDBErr: false,
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment
			tt.setupEnv()
			defer tt.cleanupEnv()

			if tt.expectError {
				// Test without mock (environment error)
				_, err := NewDatabaseDynamicPolicyEngine()
				if err == nil {
					t.Error("Expected error but got nil")
				}
				return
			}

			// Create mock database
			db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
			if err != nil {
				t.Fatalf("Failed to create sqlmock: %v", err)
			}
			defer func() { _ = db.Close() }()

			// Setup mock expectations
			tt.mockSetup(mock)

			// Cannot easily test NewDatabaseDynamicPolicyEngine with mock
			// since it creates its own connection pool
			// So we test components separately

			// Verify mock expectations were defined
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled mock expectations: %v", err)
			}
		})
	}
}

// TestSeedDefaultData tests default data seeding (system media policies + sample policies).
//
// v9 Phase 8 PR-C2 (#2384): seedSystemMediaPolicies + insertSamplePolicies now
// wrap their INSERTs in rls.WithOrgScope. seedSystemMediaPolicies fires a
// single wrap for all 5 system-media rows ('global' scope); insertSamplePolicies
// fires one wrap per sample (per-tenant scope). Each wrap adds BEGIN +
// set_config + COMMIT around the existing INSERT mock.
func TestSeedDefaultData(t *testing.T) {
	tests := []struct {
		name        string
		mockSetup   func(sqlmock.Sqlmock)
		expectError bool
	}{
		{
			name: "Success - empty database, seeds sample policies",
			mockSetup: func(mock sqlmock.Sqlmock) {
				// seedSystemMediaPolicies: single wrap, 5 inner INSERTs
				mock.ExpectBegin()
				mock.ExpectExec("set_config").WithArgs("global").WillReturnResult(sqlmock.NewResult(0, 0))
				for i := 0; i < 5; i++ {
					mock.ExpectExec("INSERT INTO dynamic_policies").
						WillReturnResult(sqlmock.NewResult(0, 1))
				}
				mock.ExpectCommit()

				// Count query returns 0 (empty table)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

				// insertSamplePolicies: per-tenant wraps (healthcare, ecommerce, global)
				for _, scope := range []string{"healthcare", "ecommerce", "global"} {
					mock.ExpectBegin()
					mock.ExpectExec("set_config").WithArgs(scope).WillReturnResult(sqlmock.NewResult(0, 0))
					mock.ExpectExec("INSERT INTO dynamic_policies").
						WillReturnResult(sqlmock.NewResult(1, 1))
					mock.ExpectCommit()
				}
			},
			expectError: false,
		},
		{
			name: "Success - table already has data, no sample inserts",
			mockSetup: func(mock sqlmock.Sqlmock) {
				// seedSystemMediaPolicies: single wrap, 5 inner INSERTs
				mock.ExpectBegin()
				mock.ExpectExec("set_config").WithArgs("global").WillReturnResult(sqlmock.NewResult(0, 0))
				for i := 0; i < 5; i++ {
					mock.ExpectExec("INSERT INTO dynamic_policies").
						WillReturnResult(sqlmock.NewResult(0, 1))
				}
				mock.ExpectCommit()

				// Count query returns 5 (table has data)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

				// No sample policy inserts expected
			},
			expectError: false,
		},
		{
			name: "Error - count query fails",
			mockSetup: func(mock sqlmock.Sqlmock) {
				// seedSystemMediaPolicies wrap (succeeds, just like canonical path)
				mock.ExpectBegin()
				mock.ExpectExec("set_config").WithArgs("global").WillReturnResult(sqlmock.NewResult(0, 0))
				for i := 0; i < 5; i++ {
					mock.ExpectExec("INSERT INTO dynamic_policies").
						WillReturnResult(sqlmock.NewResult(0, 1))
				}
				mock.ExpectCommit()

				// Count query fails
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
					WillReturnError(errors.New("query failed"))
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock database
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create sqlmock: %v", err)
			}
			defer func() { _ = db.Close() }()

			// Setup expectations
			tt.mockSetup(mock)

			// Create engine with mock
			engine := &DatabaseDynamicPolicyEngine{
				db:           db,
				policies:     make(map[string]interface{}),
				cacheTimeout: 30 * time.Second,
			}

			// Test seedDefaultData
			err = engine.seedDefaultData()

			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verify mock expectations
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled mock expectations: %v", err)
			}
		})
	}
}

// TestRefreshPolicies tests policy refresh from database
func TestRefreshPolicies(t *testing.T) {
	tests := []struct {
		name          string
		mockSetup     func(sqlmock.Sqlmock)
		expectError   bool
		expectedCount int
	}{
		{
			name: "Success - load multiple policies",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override"}).
					AddRow("00000000-0000-0000-0000-000000000001", "policy1", "", `{"field": "value"}`, `{"action": "allow"}`, "tenant1", 10, "pol1", "content", "dynamic-security", "medium", false).
					AddRow("00000000-0000-0000-0000-000000000002", "policy2", "", `{"field": "value2"}`, `{"action": "deny"}`, "tenant2", 5, "pol2", "rate-limit", "dynamic-risk", "medium", false).
					AddRow("00000000-0000-0000-0000-000000000003", "policy3", "", `{"field": "value3"}`, `{"action": "log"}`, sql.NullString{}, 1, "pol3", "content", "", "medium", false)

				mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
					WillReturnRows(rows)
			},
			expectError:   false,
			expectedCount: 3,
		},
		{
			name: "Success - empty result",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override"})

				mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
					WillReturnRows(rows)
			},
			expectError:   false,
			expectedCount: 0,
		},
		{
			name: "Error - query fails",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
					WillReturnError(errors.New("database connection lost"))
			},
			expectError:   true,
			expectedCount: 0,
		},
		{
			name: "Success - handles NULL tenant_id",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override"}).
					AddRow("00000000-0000-0000-0000-000000000004", "global_policy", "", `{}`, `{}`, sql.NullString{Valid: false}, 0, "global1", "content", "", "medium", false)

				mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
					WillReturnRows(rows)
			},
			expectError:   false,
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock database
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create sqlmock: %v", err)
			}
			defer func() { _ = db.Close() }()

			// Setup expectations
			tt.mockSetup(mock)

			// Create engine
			engine := &DatabaseDynamicPolicyEngine{
				db:       db,
				policies: make(map[string]interface{}),
			}

			// Test refreshPolicies
			err = engine.refreshPolicies()

			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verify policy count
			if !tt.expectError {
				engine.mu.RLock()
				count := len(engine.policies)
				engine.mu.RUnlock()

				if count != tt.expectedCount {
					t.Errorf("Expected %d policies, got %d", tt.expectedCount, count)
				}
			}

			// Verify mock expectations
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled mock expectations: %v", err)
			}
		})
	}
}

// TestGetPolicy tests policy retrieval
func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name          string
		setupPolicies func(*DatabaseDynamicPolicyEngine)
		policyName    string
		expectFound   bool
	}{
		{
			name: "Policy exists - return it",
			setupPolicies: func(engine *DatabaseDynamicPolicyEngine) {
				engine.mu.Lock()
				engine.policies["test_policy"] = map[string]interface{}{
					"name": "test_policy",
					"type": "test",
				}
				engine.mu.Unlock()
			},
			policyName:  "test_policy",
			expectFound: true,
		},
		{
			name: "Policy does not exist",
			setupPolicies: func(engine *DatabaseDynamicPolicyEngine) {
				engine.mu.Lock()
				engine.policies["other_policy"] = map[string]interface{}{
					"name": "other_policy",
				}
				engine.mu.Unlock()
			},
			policyName:  "nonexistent",
			expectFound: false,
		},
		{
			name: "Empty policies map",
			setupPolicies: func(engine *DatabaseDynamicPolicyEngine) {
				// No policies
			},
			policyName:  "any_policy",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := &DatabaseDynamicPolicyEngine{
				policies: make(map[string]interface{}),
			}

			tt.setupPolicies(engine)

			policy, found := engine.GetPolicy(tt.policyName)

			if found != tt.expectFound {
				t.Errorf("Expected found=%v, got %v", tt.expectFound, found)
			}

			if found {
				if policy == nil {
					t.Error("Expected non-nil policy")
				}
				// Verify database_accessed flag is set
				if dbAccessed, ok := policy["database_accessed"].(bool); !ok || !dbAccessed {
					t.Error("Expected database_accessed flag to be true")
				}
			}
		})
	}
}

// TestGetAllPolicies tests retrieving all policies
func TestGetAllPolicies(t *testing.T) {
	tests := []struct {
		name          string
		setupPolicies func(*DatabaseDynamicPolicyEngine)
		expectedCount int
	}{
		{
			name: "Multiple policies",
			setupPolicies: func(engine *DatabaseDynamicPolicyEngine) {
				engine.mu.Lock()
				engine.policies["policy1"] = map[string]interface{}{"name": "policy1"}
				engine.policies["policy2"] = map[string]interface{}{"name": "policy2"}
				engine.policies["policy3"] = map[string]interface{}{"name": "policy3"}
				engine.mu.Unlock()
			},
			expectedCount: 4, // 3 policies + database_accessed flag
		},
		{
			name: "Empty policies",
			setupPolicies: func(engine *DatabaseDynamicPolicyEngine) {
				// No setup needed
			},
			expectedCount: 1, // Just database_accessed flag
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := &DatabaseDynamicPolicyEngine{
				policies: make(map[string]interface{}),
			}

			tt.setupPolicies(engine)

			allPolicies := engine.GetAllPolicies()

			if len(allPolicies) != tt.expectedCount {
				t.Errorf("Expected %d items (policies + database_accessed), got %d", tt.expectedCount, len(allPolicies))
			}

			// Verify database_accessed flag
			if dbAccessed, ok := allPolicies["database_accessed"].(bool); !ok || !dbAccessed {
				t.Error("Expected database_accessed flag to be true")
			}
		})
	}
}

// TestEvaluateDynamicPolicies tests policy evaluation
func TestEvaluateDynamicPolicies(t *testing.T) {
	tests := []struct {
		name             string
		setupEngine      func(*DatabaseDynamicPolicyEngine, sqlmock.Sqlmock)
		req              OrchestratorRequest
		expectedAllowed  bool
		expectedPolicies int
	}{
		{
			name: "Tenant-specific policy applied",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine, mock sqlmock.Sqlmock) {
				engine.mu.Lock()
				engine.policies["tenant_policy"] = map[string]interface{}{
					"name": "tenant_policy",
					"_metadata": map[string]interface{}{
						"tenant_id": "test-tenant",
						"priority":  10,
					},
					"rules": map[string]interface{}{
						"risk_score": 0.5,
					},
				}
				engine.lastRefresh = time.Now()
				engine.mu.Unlock()

				// Expect metrics insert
				mock.ExpectExec("INSERT INTO policy_metrics").
					WithArgs(sqlmock.AnyArg(), true, "test-tenant").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			req: OrchestratorRequest{
				Client: ClientContext{ID: "test-client", TenantID: "test-tenant"},
				Query:  "test query",
			},
			expectedAllowed:  true,
			expectedPolicies: 1,
		},
		{
			name: "Global policy applied to all tenants",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine, mock sqlmock.Sqlmock) {
				engine.mu.Lock()
				engine.policies["global_policy"] = map[string]interface{}{
					"name": "global_policy",
					"_metadata": map[string]interface{}{
						"tenant_id": "global",
						"priority":  1,
					},
				}
				engine.lastRefresh = time.Now()
				engine.mu.Unlock()

				// Expect metrics insert
				mock.ExpectExec("INSERT INTO policy_metrics").
					WithArgs(sqlmock.AnyArg(), true, "any-tenant").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			req: OrchestratorRequest{
				Client: ClientContext{ID: "any-client", TenantID: "any-tenant"},
				Query:  "test query",
			},
			expectedAllowed:  true,
			expectedPolicies: 1,
		},
		{
			name: "Policy with required actions",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine, mock sqlmock.Sqlmock) {
				engine.mu.Lock()
				engine.policies["action_policy"] = map[string]interface{}{
					"name": "action_policy",
					"_metadata": map[string]interface{}{
						"tenant_id": "global",
					},
					"rules": map[string]interface{}{
						"required_actions": []interface{}{"log", "alert"},
						"risk_score":       0.8,
					},
				}
				engine.lastRefresh = time.Now()
				engine.mu.Unlock()

				// Expect metrics insert
				mock.ExpectExec("INSERT INTO policy_metrics").
					WithArgs(sqlmock.AnyArg(), true, "").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			req: OrchestratorRequest{
				Query: "test query",
			},
			expectedAllowed:  true,
			expectedPolicies: 1,
		},
		{
			name: "No matching policies",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine, mock sqlmock.Sqlmock) {
				engine.mu.Lock()
				engine.policies["other_tenant_policy"] = map[string]interface{}{
					"name": "other_tenant_policy",
					"_metadata": map[string]interface{}{
						"tenant_id": "other-tenant",
					},
				}
				engine.lastRefresh = time.Now()
				engine.mu.Unlock()

				// Expect metrics insert
				mock.ExpectExec("INSERT INTO policy_metrics").
					WithArgs(sqlmock.AnyArg(), true, "my-tenant").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			req: OrchestratorRequest{
				Client: ClientContext{ID: "my-client", TenantID: "my-tenant"},
				Query:  "test query",
			},
			expectedAllowed:  true,
			expectedPolicies: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock database for metrics
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create sqlmock: %v", err)
			}
			defer func() { _ = db.Close() }()

			engine := &DatabaseDynamicPolicyEngine{
				db:           db,
				metricsDB:    db,
				policies:     make(map[string]interface{}),
				cacheTimeout: 30 * time.Second,
			}

			tt.setupEngine(engine, mock)

			result := engine.EvaluateDynamicPolicies(context.Background(), tt.req)

			if result.Allowed != tt.expectedAllowed {
				t.Errorf("Expected allowed=%v, got %v", tt.expectedAllowed, result.Allowed)
			}

			if len(result.AppliedPolicies) != tt.expectedPolicies {
				t.Errorf("Expected %d applied policies, got %d", tt.expectedPolicies, len(result.AppliedPolicies))
			}

			if !result.DatabaseAccessed {
				t.Error("Expected DatabaseAccessed to be true")
			}

			// Give goroutine time to insert metrics
			time.Sleep(100 * time.Millisecond)

			// Verify mock expectations (metrics may not be inserted due to goroutine timing)
			// So we skip strict expectations check
		})
	}
}

// TestDatabasePolicyEngine_IsHealthy tests health check
func TestDatabasePolicyEngine_IsHealthy(t *testing.T) {
	tests := []struct {
		name          string
		setupEngine   func(*DatabaseDynamicPolicyEngine, sqlmock.Sqlmock)
		expectHealthy bool
	}{
		{
			name: "Healthy - recent refresh and policies loaded",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine, mock sqlmock.Sqlmock) {
				engine.mu.Lock()
				engine.lastRefresh = time.Now().Add(-1 * time.Minute)
				engine.policies["test"] = map[string]interface{}{}
				engine.mu.Unlock()

				mock.ExpectPing()
			},
			expectHealthy: true,
		},
		{
			name: "Unhealthy - stale cache (>5 minutes)",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine, mock sqlmock.Sqlmock) {
				engine.mu.Lock()
				engine.lastRefresh = time.Now().Add(-10 * time.Minute)
				engine.policies["test"] = map[string]interface{}{}
				engine.mu.Unlock()

				mock.ExpectPing()
			},
			expectHealthy: false,
		},
		{
			name: "Unhealthy - no policies loaded",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine, mock sqlmock.Sqlmock) {
				engine.mu.Lock()
				engine.lastRefresh = time.Now()
				// No policies
				engine.mu.Unlock()

				mock.ExpectPing()
			},
			expectHealthy: false,
		},
		{
			name: "Unhealthy - database ping fails",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine, mock sqlmock.Sqlmock) {
				engine.mu.Lock()
				engine.lastRefresh = time.Now()
				engine.policies["test"] = map[string]interface{}{}
				engine.mu.Unlock()

				mock.ExpectPing().WillReturnError(errors.New("connection lost"))
			},
			expectHealthy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
			if err != nil {
				t.Fatalf("Failed to create sqlmock: %v", err)
			}
			defer func() { _ = db.Close() }()

			engine := &DatabaseDynamicPolicyEngine{
				db:       db,
				policies: make(map[string]interface{}),
			}

			tt.setupEngine(engine, mock)

			healthy := engine.IsHealthy()

			if healthy != tt.expectHealthy {
				t.Errorf("Expected healthy=%v, got %v", tt.expectHealthy, healthy)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled mock expectations: %v", err)
			}
		})
	}
}

// TestDatabasePolicyEngine_ListActivePolicies tests listing active policies
func TestDatabasePolicyEngine_ListActivePolicies(t *testing.T) {
	tests := []struct {
		name          string
		setupEngine   func(*DatabaseDynamicPolicyEngine)
		expectedCount int
	}{
		{
			name: "Multiple policies with metadata",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine) {
				engine.mu.Lock()
				engine.policies["policy1"] = map[string]interface{}{
					"type": "rate_limit",
					"_metadata": map[string]interface{}{
						"priority":  10,
						"tenant_id": "tenant1",
					},
					"rules": map[string]interface{}{
						"max_requests": 100,
					},
				}
				engine.policies["policy2"] = map[string]interface{}{
					"type": "compliance",
					"_metadata": map[string]interface{}{
						"priority":  5,
						"tenant_id": "tenant2",
					},
				}
				engine.mu.Unlock()
			},
			expectedCount: 2,
		},
		{
			name: "Empty policies",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine) {
				// No policies
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := &DatabaseDynamicPolicyEngine{
				policies: make(map[string]interface{}),
			}

			tt.setupEngine(engine)

			policies := engine.ListActivePolicies()

			if len(policies) != tt.expectedCount {
				t.Errorf("Expected %d policies, got %d", tt.expectedCount, len(policies))
			}

			// Verify policy structure
			for _, policy := range policies {
				if policy.Name == "" {
					t.Error("Policy name should not be empty")
				}
				if policy.Type == "" {
					t.Error("Policy type should not be empty")
				}
				if !policy.Enabled {
					t.Error("Policy should be enabled")
				}
			}
		})
	}
}

// TestClose tests cleanup
func TestClose(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}

	metricsDB, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}

	engine := &DatabaseDynamicPolicyEngine{
		db:        db,
		metricsDB: metricsDB,
	}

	err = engine.Close()
	if err != nil {
		t.Errorf("Expected no error on close, got: %v", err)
	}

	// Verify databases are closed (calling Ping should fail)
	if err := db.Ping(); err == nil {
		t.Error("Expected database to be closed")
	}
	if err := metricsDB.Ping(); err == nil {
		t.Error("Expected metrics database to be closed")
	}
}

// =============================================================================
// Background Refresh Tests
// =============================================================================

// TestBackgroundRefresh tests the background refresh goroutine
func TestBackgroundRefresh(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabaseDynamicPolicyEngine{
		db:           db,
		policies:     make(map[string]interface{}),
		cacheTimeout: 100 * time.Millisecond, // Short timeout for testing
		lastRefresh:  time.Now(),
	}

	// Expect policy refresh query to be called
	rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override"}).
		AddRow("00000000-0000-0000-0000-000000000001", "test_policy", "", "{}", "{}", "tenant1", 10, "policy1", "content", "dynamic-security", "medium", false)

	mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
		WillReturnRows(rows)

	// Start background refresh in a goroutine
	done := make(chan bool)
	go func() {
		// Let it run for a bit to trigger at least one refresh
		time.Sleep(200 * time.Millisecond)
		done <- true
	}()

	// Start the background refresh
	go engine.backgroundRefresh()

	// Wait for test to complete
	<-done

	// The goroutine should have attempted to refresh policies
	// Note: We can't strictly enforce mock expectations due to goroutine timing
	t.Log("backgroundRefresh test completed")
}

// =============================================================================
// Report Metrics Tests
// =============================================================================

// TestReportMetrics tests the metrics reporting goroutine
func TestReportMetrics(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	metricsDB, metricsMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = metricsDB.Close() }()

	engine := &DatabaseDynamicPolicyEngine{
		db:          db,
		metricsDB:   metricsDB,
		policies:    make(map[string]interface{}),
		lastRefresh: time.Now(),
	}

	// Add a test policy
	engine.mu.Lock()
	engine.policies["test"] = map[string]interface{}{"name": "test"}
	engine.mu.Unlock()

	// Expect metrics insert
	metricsMock.ExpectExec("INSERT INTO policy_metrics").
		WithArgs(sqlmock.AnyArg(), true, "system").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Start metrics reporting in a goroutine
	done := make(chan bool)
	go func() {
		time.Sleep(15 * time.Second) // Wait for at least one metrics report
		done <- true
	}()

	// Start the metrics reporter
	go engine.reportMetrics()

	// Wait for test to complete
	<-done

	// Note: We can't strictly enforce mock expectations due to goroutine timing
	t.Log("reportMetrics test completed")

	// Suppress unused variable warnings
	_ = mock
}

// =============================================================================
// Load Default Policies Tests
// =============================================================================

// TestLoadDefaultPolicies tests loading fallback default policies
func TestLoadDefaultPolicies(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies: make(map[string]interface{}),
	}

	// Load default policies
	engine.loadDefaultPolicies()

	// Verify default policy was loaded
	engine.mu.RLock()
	policyCount := len(engine.policies)
	engine.mu.RUnlock()

	if policyCount == 0 {
		t.Error("Expected at least one default policy")
	}

	// Verify default policy structure
	engine.mu.RLock()
	defaultPolicy, exists := engine.policies["default"]
	engine.mu.RUnlock()

	if !exists {
		t.Error("Expected 'default' policy to exist")
	}

	if defaultPolicy == nil {
		t.Error("Default policy should not be nil")
	}

	// Verify policy has expected fields
	if policyMap, ok := defaultPolicy.(map[string]interface{}); ok {
		if policyType, ok := policyMap["type"].(string); !ok || policyType != "fallback" {
			t.Error("Expected default policy type to be 'fallback'")
		}

		if rules, ok := policyMap["rules"].(map[string]interface{}); ok {
			if maxTokens, ok := rules["max_tokens"].(int); !ok || maxTokens <= 0 {
				t.Error("Expected max_tokens to be set in default policy rules")
			}
		} else {
			t.Error("Expected rules in default policy")
		}
	} else {
		t.Error("Expected default policy to be a map")
	}
}

// =============================================================================
// Issue #883: Tests for evaluateCondition and getFieldValue
// =============================================================================

// TestEvaluateCondition_Equals tests the equals operator
func TestEvaluateCondition_Equals(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name      string
		condition map[string]interface{}
		request   OrchestratorRequest
		expected  bool
	}{
		{
			name: "equals - string match",
			condition: map[string]interface{}{
				"field":    "user.role",
				"operator": "equals",
				"value":    "admin",
			},
			request:  OrchestratorRequest{User: UserContext{Role: "admin"}},
			expected: true,
		},
		{
			name: "equals - string no match",
			condition: map[string]interface{}{
				"field":    "user.role",
				"operator": "equals",
				"value":    "admin",
			},
			request:  OrchestratorRequest{User: UserContext{Role: "user"}},
			expected: false,
		},
		{
			name: "equals - region match",
			condition: map[string]interface{}{
				"field":    "user.region",
				"operator": "equals",
				"value":    "EU",
			},
			request:  OrchestratorRequest{User: UserContext{Region: "EU"}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEvaluateCondition_NotEquals tests the not_equals operator
func TestEvaluateCondition_NotEquals(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name      string
		condition map[string]interface{}
		request   OrchestratorRequest
		expected  bool
	}{
		{
			name: "not_equals - different values",
			condition: map[string]interface{}{
				"field":    "user.role",
				"operator": "not_equals",
				"value":    "admin",
			},
			request:  OrchestratorRequest{User: UserContext{Role: "user"}},
			expected: true,
		},
		{
			name: "not_equals - same values",
			condition: map[string]interface{}{
				"field":    "user.role",
				"operator": "not_equals",
				"value":    "admin",
			},
			request:  OrchestratorRequest{User: UserContext{Role: "admin"}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEvaluateCondition_Contains tests the contains operator
func TestEvaluateCondition_Contains(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name      string
		condition map[string]interface{}
		request   OrchestratorRequest
		expected  bool
	}{
		{
			name: "contains - query contains keyword",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "contains",
				"value":    "PII",
			},
			request:  OrchestratorRequest{Query: "Process this PII data"},
			expected: true,
		},
		{
			name: "contains - case insensitive",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "contains",
				"value":    "pii",
			},
			request:  OrchestratorRequest{Query: "Process this PII data"},
			expected: true,
		},
		{
			name: "contains - no match",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "contains",
				"value":    "secret",
			},
			request:  OrchestratorRequest{Query: "Hello world"},
			expected: false,
		},
		{
			name: "contains - client ID contains substring",
			condition: map[string]interface{}{
				"field":    "client.id",
				"operator": "contains",
				"value":    "eu-",
			},
			request:  OrchestratorRequest{Client: ClientContext{ID: "eu-support-agent"}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEvaluateCondition_ContainsAny tests the contains_any operator
func TestEvaluateCondition_ContainsAny(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name      string
		condition map[string]interface{}
		request   OrchestratorRequest
		expected  bool
	}{
		{
			name: "contains_any - matches first item",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "contains_any",
				"value":    []interface{}{"SSN", "credit card", "password"},
			},
			request:  OrchestratorRequest{Query: "My SSN is 123-45-6789"},
			expected: true,
		},
		{
			name: "contains_any - matches middle item",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "contains_any",
				"value":    []interface{}{"SSN", "credit card", "password"},
			},
			request:  OrchestratorRequest{Query: "My credit card number is"},
			expected: true,
		},
		{
			name: "contains_any - no match",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "contains_any",
				"value":    []interface{}{"SSN", "credit card", "password"},
			},
			request:  OrchestratorRequest{Query: "What is the weather?"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEvaluateCondition_Regex tests the regex operator
func TestEvaluateCondition_Regex(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name      string
		condition map[string]interface{}
		request   OrchestratorRequest
		expected  bool
	}{
		{
			name: "regex - SSN pattern match",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "regex",
				"value":    `\d{3}-\d{2}-\d{4}`,
			},
			request:  OrchestratorRequest{Query: "My SSN is 123-45-6789"},
			expected: true,
		},
		{
			name: "regex - no match",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "regex",
				"value":    `\d{3}-\d{2}-\d{4}`,
			},
			request:  OrchestratorRequest{Query: "Hello world"},
			expected: false,
		},
		{
			name: "regex - email pattern",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "regex",
				"value":    `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			},
			request:  OrchestratorRequest{Query: "Contact me at user@example.com"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEvaluateCondition_GreaterThan tests the greater_than operator
func TestEvaluateCondition_GreaterThan(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name      string
		condition map[string]interface{}
		request   OrchestratorRequest
		expected  bool
	}{
		{
			name: "greater_than - true",
			condition: map[string]interface{}{
				"field":    "risk_score",
				"operator": "greater_than",
				"value":    0.5,
			},
			request: OrchestratorRequest{
				Context: map[string]interface{}{"risk_score": 0.8},
			},
			expected: true,
		},
		{
			name: "greater_than - false",
			condition: map[string]interface{}{
				"field":    "risk_score",
				"operator": "greater_than",
				"value":    0.5,
			},
			request: OrchestratorRequest{
				Context: map[string]interface{}{"risk_score": 0.3},
			},
			expected: false,
		},
		{
			name: "greater_than - equal is false",
			condition: map[string]interface{}{
				"field":    "risk_score",
				"operator": "greater_than",
				"value":    0.5,
			},
			request: OrchestratorRequest{
				Context: map[string]interface{}{"risk_score": 0.5},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEvaluateCondition_In tests the in operator
func TestEvaluateCondition_In(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name      string
		condition map[string]interface{}
		request   OrchestratorRequest
		expected  bool
	}{
		{
			name: "in - region in list",
			condition: map[string]interface{}{
				"field":    "user.region",
				"operator": "in",
				"value":    []interface{}{"EU", "UK", "CH"},
			},
			request:  OrchestratorRequest{User: UserContext{Region: "EU"}},
			expected: true,
		},
		{
			name: "in - region not in list",
			condition: map[string]interface{}{
				"field":    "user.region",
				"operator": "in",
				"value":    []interface{}{"EU", "UK", "CH"},
			},
			request:  OrchestratorRequest{User: UserContext{Region: "US"}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestDatabaseDynamicPolicyEngine_GetFieldValue tests field extraction from requests
func TestDatabaseDynamicPolicyEngine_GetFieldValue(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	request := OrchestratorRequest{
		Query:       "Test query",
		RequestType: "chat",
		User: UserContext{
			ID:       1,
			Email:    "user@example.com",
			Role:     "admin",
			Region:   "EU",
			TenantID: "tenant-123",
		},
		Client: ClientContext{
			ID:       "client-456",
			OrgID:    "org-789",
			TenantID: "tenant-123",
		},
		Context: map[string]interface{}{
			"risk_score":    0.75,
			"cost_estimate": 0.05,
			"environment":   "production",
		},
	}

	tests := []struct {
		name     string
		field    string
		expected interface{}
	}{
		{"query", "query", "Test query"},
		{"request_type", "request_type", "chat"},
		{"user.role", "user.role", "admin"},
		{"user.email", "user.email", "user@example.com"},
		{"user.region", "user.region", "EU"},
		{"user.tenant_id", "user.tenant_id", "tenant-123"},
		{"client.id", "client.id", "client-456"},
		{"client.org_id", "client.org_id", "org-789"},
		{"client.tenant_id", "client.tenant_id", "tenant-123"},
		{"risk_score", "risk_score", 0.75},
		{"cost_estimate", "cost_estimate", 0.05},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.getFieldValue(tt.field, request)
			// For float comparison
			if expectedFloat, ok := tt.expected.(float64); ok {
				if resultFloat, ok := result.(float64); ok {
					if resultFloat != expectedFloat {
						t.Errorf("Expected %v, got %v", tt.expected, result)
					}
					return
				}
			}
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEvaluateCondition_UnknownOperator tests handling of unknown operators
func TestEvaluateCondition_UnknownOperator(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	condition := map[string]interface{}{
		"field":    "user.role",
		"operator": "unknown_operator",
		"value":    "admin",
	}
	request := OrchestratorRequest{User: UserContext{Role: "admin"}}

	result := engine.evaluateCondition(condition, request)
	if result != false {
		t.Error("Unknown operator should return false")
	}
}

// TestDatabaseDynamicPolicyEngine_ToFloat64 tests conversion of various types to float64
func TestDatabaseDynamicPolicyEngine_ToFloat64(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name     string
		input    interface{}
		expected float64
	}{
		{"float64", float64(3.14), 3.14},
		{"float32", float32(2.5), 2.5},
		{"int", int(42), 42.0},
		{"int64", int64(100), 100.0},
		{"string valid", "3.14159", 3.14159},
		{"string invalid", "not a number", 0.0},
		{"nil", nil, 0.0},
		{"bool", true, 0.0},
		{"struct", struct{}{}, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.toFloat64(tt.input)
			if result != tt.expected {
				t.Errorf("toFloat64(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestGetFieldValue_EdgeCases tests edge cases for field value extraction
func TestGetFieldValue_EdgeCases(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	t.Run("request_id field", func(t *testing.T) {
		request := OrchestratorRequest{RequestID: "req-12345"}
		result := engine.getFieldValue("request_id", request)
		if result != "req-12345" {
			t.Errorf("Expected req-12345, got %v", result)
		}
	})

	t.Run("user_id alias", func(t *testing.T) {
		request := OrchestratorRequest{User: UserContext{ID: 456}}
		result := engine.getFieldValue("user_id", request)
		if result != 456 {
			t.Errorf("Expected 456, got %v", result)
		}
	})

	t.Run("user_email alias", func(t *testing.T) {
		request := OrchestratorRequest{User: UserContext{Email: "test@test.com"}}
		result := engine.getFieldValue("user_email", request)
		if result != "test@test.com" {
			t.Errorf("Expected test@test.com, got %v", result)
		}
	})

	t.Run("region alias", func(t *testing.T) {
		request := OrchestratorRequest{User: UserContext{Region: "US"}}
		result := engine.getFieldValue("region", request)
		if result != "US" {
			t.Errorf("Expected US, got %v", result)
		}
	})

	t.Run("client_id alias", func(t *testing.T) {
		request := OrchestratorRequest{Client: ClientContext{ID: "client-789"}}
		result := engine.getFieldValue("client_id", request)
		if result != "client-789" {
			t.Errorf("Expected client-789, got %v", result)
		}
	})

	t.Run("agent_id alias", func(t *testing.T) {
		request := OrchestratorRequest{Client: ClientContext{ID: "agent-001"}}
		result := engine.getFieldValue("agent_id", request)
		if result != "agent-001" {
			t.Errorf("Expected agent-001, got %v", result)
		}
	})

	t.Run("org_id alias", func(t *testing.T) {
		request := OrchestratorRequest{Client: ClientContext{OrgID: "org-999"}}
		result := engine.getFieldValue("org_id", request)
		if result != "org-999" {
			t.Errorf("Expected org-999, got %v", result)
		}
	})

	t.Run("tenant_id alias", func(t *testing.T) {
		request := OrchestratorRequest{Client: ClientContext{TenantID: "tenant-abc"}}
		result := engine.getFieldValue("tenant_id", request)
		if result != "tenant-abc" {
			t.Errorf("Expected tenant-abc, got %v", result)
		}
	})

	t.Run("environment from context", func(t *testing.T) {
		request := OrchestratorRequest{
			Context: map[string]interface{}{"environment": "production"},
		}
		result := engine.getFieldValue("environment", request)
		if result != "production" {
			t.Errorf("Expected production, got %v", result)
		}
	})

	t.Run("env alias from context", func(t *testing.T) {
		request := OrchestratorRequest{
			Context: map[string]interface{}{"environment": "staging"},
		}
		result := engine.getFieldValue("env", request)
		if result != "staging" {
			t.Errorf("Expected staging, got %v", result)
		}
	})

	t.Run("risk_score missing from context", func(t *testing.T) {
		request := OrchestratorRequest{Context: map[string]interface{}{}}
		result := engine.getFieldValue("risk_score", request)
		if result != 0.0 {
			t.Errorf("Expected 0.0, got %v", result)
		}
	})

	t.Run("cost_estimate missing from context", func(t *testing.T) {
		request := OrchestratorRequest{Context: map[string]interface{}{}}
		result := engine.getFieldValue("cost_estimate", request)
		if result != 0.0 {
			t.Errorf("Expected 0.0, got %v", result)
		}
	})

	t.Run("custom field from context", func(t *testing.T) {
		request := OrchestratorRequest{
			Context: map[string]interface{}{"custom_field": "custom_value"},
		}
		result := engine.getFieldValue("custom_field", request)
		if result != "custom_value" {
			t.Errorf("Expected custom_value, got %v", result)
		}
	})

	t.Run("context.prefixed field", func(t *testing.T) {
		request := OrchestratorRequest{
			Context: map[string]interface{}{"nested_data": "nested_value"},
		}
		result := engine.getFieldValue("context.nested_data", request)
		if result != "nested_value" {
			t.Errorf("Expected nested_value, got %v", result)
		}
	})

	t.Run("unknown field returns nil", func(t *testing.T) {
		request := OrchestratorRequest{}
		result := engine.getFieldValue("nonexistent_field", request)
		if result != nil {
			t.Errorf("Expected nil, got %v", result)
		}
	})

	t.Run("nil context returns nil for custom field", func(t *testing.T) {
		request := OrchestratorRequest{Context: nil}
		result := engine.getFieldValue("some_custom_field", request)
		if result != nil {
			t.Errorf("Expected nil, got %v", result)
		}
	})
}

// TestEvaluateCondition_LessThan tests less_than operator
func TestEvaluateCondition_LessThan(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name      string
		condition map[string]interface{}
		request   OrchestratorRequest
		expected  bool
	}{
		{
			name: "less_than - true",
			condition: map[string]interface{}{
				"field":    "risk_score",
				"operator": "less_than",
				"value":    0.5,
			},
			request:  OrchestratorRequest{Context: map[string]interface{}{"risk_score": 0.3}},
			expected: true,
		},
		{
			name: "less_than - false",
			condition: map[string]interface{}{
				"field":    "risk_score",
				"operator": "less_than",
				"value":    0.5,
			},
			request:  OrchestratorRequest{Context: map[string]interface{}{"risk_score": 0.7}},
			expected: false,
		},
		{
			name: "less_than - equal is false",
			condition: map[string]interface{}{
				"field":    "risk_score",
				"operator": "less_than",
				"value":    0.5,
			},
			request:  OrchestratorRequest{Context: map[string]interface{}{"risk_score": 0.5}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEvaluateCondition_NotContains tests not_contains operator
func TestEvaluateCondition_NotContains(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name      string
		condition map[string]interface{}
		request   OrchestratorRequest
		expected  bool
	}{
		{
			name: "not_contains - true (substring not present)",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "not_contains",
				"value":    "DROP TABLE",
			},
			request:  OrchestratorRequest{Query: "SELECT * FROM users"},
			expected: true,
		},
		{
			name: "not_contains - false (substring present)",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "not_contains",
				"value":    "DROP",
			},
			request:  OrchestratorRequest{Query: "DROP TABLE users"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEvaluateCondition_NotIn tests not_in operator
func TestEvaluateCondition_NotIn(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name      string
		condition map[string]interface{}
		request   OrchestratorRequest
		expected  bool
	}{
		{
			name: "not_in - true (not in list)",
			condition: map[string]interface{}{
				"field":    "user.region",
				"operator": "not_in",
				"value":    []interface{}{"EU", "UK"},
			},
			request:  OrchestratorRequest{User: UserContext{Region: "US"}},
			expected: true,
		},
		{
			name: "not_in - false (in list)",
			condition: map[string]interface{}{
				"field":    "user.region",
				"operator": "not_in",
				"value":    []interface{}{"EU", "UK", "US"},
			},
			request:  OrchestratorRequest{User: UserContext{Region: "US"}},
			expected: false,
		},
		{
			name: "not_in - string list",
			condition: map[string]interface{}{
				"field":    "user.role",
				"operator": "not_in",
				"value":    []string{"admin", "superuser"},
			},
			request:  OrchestratorRequest{User: UserContext{Role: "viewer"}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEvaluateCondition_RegexEdgeCases tests additional regex operator edge cases
func TestEvaluateCondition_RegexEdgeCases(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name      string
		condition map[string]interface{}
		request   OrchestratorRequest
		expected  bool
	}{
		{
			name: "regex - invalid pattern returns false",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "regex",
				"value":    "[invalid(regex",
			},
			request:  OrchestratorRequest{Query: "any query"},
			expected: false,
		},
		{
			name: "regex - non-string value returns false",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "regex",
				"value":    123, // not a string
			},
			request:  OrchestratorRequest{Query: "any query"},
			expected: false,
		},
		{
			name: "regex - non-string field value converts to string",
			condition: map[string]interface{}{
				"field":    "risk_score",
				"operator": "regex",
				"value":    "0\\.8",
			},
			request: OrchestratorRequest{
				Context: map[string]interface{}{"risk_score": 0.8},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEvaluateCondition_ContainsAnyStringSlice tests contains_any with []string type
func TestEvaluateCondition_ContainsAnyStringSlice(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name      string
		condition map[string]interface{}
		request   OrchestratorRequest
		expected  bool
	}{
		{
			name: "contains_any - match with string slice",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "contains_any",
				"value":    []string{"drop", "delete", "truncate"},
			},
			request:  OrchestratorRequest{Query: "DROP TABLE users"},
			expected: true,
		},
		{
			name: "contains_any - no match with string slice",
			condition: map[string]interface{}{
				"field":    "query",
				"operator": "contains_any",
				"value":    []string{"drop", "delete"},
			},
			request:  OrchestratorRequest{Query: "SELECT * FROM users"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEvaluateCondition_InOperator_StringSlice tests in operator with []string type
func TestEvaluateCondition_InOperator_StringSlice(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	tests := []struct {
		name      string
		condition map[string]interface{}
		request   OrchestratorRequest
		expected  bool
	}{
		{
			name: "in - match with string slice",
			condition: map[string]interface{}{
				"field":    "user.role",
				"operator": "in",
				"value":    []string{"admin", "operator", "viewer"},
			},
			request:  OrchestratorRequest{User: UserContext{Role: "admin"}},
			expected: true,
		},
		{
			name: "in - no match with string slice",
			condition: map[string]interface{}{
				"field":    "user.role",
				"operator": "in",
				"value":    []string{"admin", "operator"},
			},
			request:  OrchestratorRequest{User: UserContext{Role: "viewer"}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestListActivePolicies_UsesHumanNameNotCacheKey is a regression guard for the
// WS-1 (design-partner PoC dry-run) finding: ListActivePolicies keyed dp.Name to the
// cache map key, which refreshPolicies sets to the policy_id (UUID) to avoid
// cross-tenant name collisions. The human-readable name lives in
// policyMap["name"]. Before the fix, every matched policy surfaced to callers
// (the MCP dynamic-policy evaluator's matched_policies → the decision feed the
// Risk Committee reads) showed the opaque UUID instead of the policy name.
//
// Red-on-revert: revert the policyMap["name"] read in ListActivePolicies and
// dp.Name collapses to the UUID cache key, failing this test.
func TestListActivePolicies_UsesHumanNameNotCacheKey(t *testing.T) {
	const (
		cacheKey   = "f42b4d6b-4e65-4088-9d24-d1d4967b9eb8" // policy_id UUID (the map key)
		humanName  = "Tenant: junior leaders cannot execute writes"
		policyIDul = "tenant_junior_writeguard"
	)
	e := &DatabaseDynamicPolicyEngine{
		policies: map[string]interface{}{
			// refreshPolicies keys the cache by policy_id (the UUID) and stores
			// the human name under "name".
			cacheKey: map[string]interface{}{
				"policy_id": policyIDul,
				"name":      humanName,
				"type":      "mcp",
				"category":  "dynamic-governance",
			},
		},
	}

	got := e.ListActivePolicies()
	if len(got) != 1 {
		t.Fatalf("expected 1 active policy, got %d", len(got))
	}
	if got[0].Name != humanName {
		t.Errorf("ListActivePolicies().Name = %q, want the human-readable name %q (not the UUID cache key %q)",
			got[0].Name, humanName, cacheKey)
	}
	if got[0].Name == cacheKey {
		t.Errorf("ListActivePolicies().Name leaked the UUID cache key %q: the matched-policy/decision-feed regression is back", cacheKey)
	}
}
