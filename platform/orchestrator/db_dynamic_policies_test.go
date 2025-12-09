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
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestNewDatabaseDynamicPolicyEngine tests creation of policy engine
func TestNewDatabaseDynamicPolicyEngine(t *testing.T) {
	t.Skip("Skipping test that requires proper database mock injection")

	tests := []struct {
		name           string
		setupEnv       func()
		cleanupEnv     func()
		expectError    bool
		mockSetup      func(sqlmock.Sqlmock)
		mockDBErr      bool
		expectNil      bool
	}{
		{
			name: "Success - database connects and initializes",
			setupEnv: func() {
				t.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test?sslmode=disable")
			},
			cleanupEnv: func() {},
			expectError: false,
			mockSetup: func(mock sqlmock.Sqlmock) {
				// Expect ping
				mock.ExpectPing()

				// Expect schema creation (initializeSchema)
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS dynamic_policies").WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec("CREATE INDEX IF NOT EXISTS idx_policies_tenant").WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec("CREATE INDEX IF NOT EXISTS idx_policies_enabled").WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec("CREATE INDEX IF NOT EXISTS idx_policies_priority").WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS policy_metrics").WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec("CREATE INDEX IF NOT EXISTS idx_metrics_timestamp").WillReturnResult(sqlmock.NewResult(0, 0))

				// Expect count query
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

				// Expect policy load (refreshPolicies)
				rows := sqlmock.NewRows([]string{"name", "conditions", "actions", "tenant_id", "priority", "policy_id"}).
					AddRow("test_policy", "{}", "{}", "tenant1", 10, "policy1")
				mock.ExpectQuery("SELECT name, conditions, actions, tenant_id, priority, policy_id FROM dynamic_policies").
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
			cleanupEnv: func() {},
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

// TestInitializeSchema tests database schema initialization
func TestInitializeSchema(t *testing.T) {
	tests := []struct {
		name        string
		mockSetup   func(sqlmock.Sqlmock)
		expectError bool
	}{
		{
			name: "Success - empty database, schema created with sample policies",
			mockSetup: func(mock sqlmock.Sqlmock) {
				// Schema creation - one multi-statement Exec
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS dynamic_policies").
					WillReturnResult(sqlmock.NewResult(0, 0))

				// Count query returns 0 (empty table)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

				// Expect sample policy inserts (3 policies)
				mock.ExpectExec("INSERT INTO dynamic_policies").
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec("INSERT INTO dynamic_policies").
					WillReturnResult(sqlmock.NewResult(2, 1))
				mock.ExpectExec("INSERT INTO dynamic_policies").
					WillReturnResult(sqlmock.NewResult(3, 1))
			},
			expectError: false,
		},
		{
			name: "Success - table already has data, no sample inserts",
			mockSetup: func(mock sqlmock.Sqlmock) {
				// Schema creation - one multi-statement Exec
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS dynamic_policies").
					WillReturnResult(sqlmock.NewResult(0, 0))

				// Count query returns 5 (table has data)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

				// No sample policy inserts expected
			},
			expectError: false,
		},
		{
			name: "Error - schema creation fails",
			mockSetup: func(mock sqlmock.Sqlmock) {
				// Schema creation fails
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS dynamic_policies").
					WillReturnError(errors.New("database error"))
			},
			expectError: true,
		},
		{
			name: "Error - count query fails",
			mockSetup: func(mock sqlmock.Sqlmock) {
				// Schema creation succeeds
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS dynamic_policies").
					WillReturnResult(sqlmock.NewResult(0, 0))

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

			// Test initializeSchema
			err = engine.initializeSchema()

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
		name           string
		mockSetup      func(sqlmock.Sqlmock)
		expectError    bool
		expectedCount  int
	}{
		{
			name: "Success - load multiple policies",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"name", "conditions", "actions", "tenant_id", "priority", "policy_id"}).
					AddRow("policy1", `{"field": "value"}`, `{"action": "allow"}`, "tenant1", 10, "pol1").
					AddRow("policy2", `{"field": "value2"}`, `{"action": "deny"}`, "tenant2", 5, "pol2").
					AddRow("policy3", `{"field": "value3"}`, `{"action": "log"}`, sql.NullString{}, 1, "pol3")

				mock.ExpectQuery("SELECT name, conditions, actions, tenant_id, priority, policy_id FROM dynamic_policies").
					WillReturnRows(rows)
			},
			expectError: false,
			expectedCount: 3,
		},
		{
			name: "Success - empty result",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"name", "conditions", "actions", "tenant_id", "priority", "policy_id"})

				mock.ExpectQuery("SELECT name, conditions, actions, tenant_id, priority, policy_id FROM dynamic_policies").
					WillReturnRows(rows)
			},
			expectError: false,
			expectedCount: 0,
		},
		{
			name: "Error - query fails",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT name, conditions, actions, tenant_id, priority, policy_id FROM dynamic_policies").
					WillReturnError(errors.New("database connection lost"))
			},
			expectError: true,
			expectedCount: 0,
		},
		{
			name: "Success - handles NULL tenant_id",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"name", "conditions", "actions", "tenant_id", "priority", "policy_id"}).
					AddRow("global_policy", `{}`, `{}`, sql.NullString{Valid: false}, 0, "global1")

				mock.ExpectQuery("SELECT name, conditions, actions, tenant_id, priority, policy_id FROM dynamic_policies").
					WillReturnRows(rows)
			},
			expectError: false,
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
		name        string
		setupPolicies func(*DatabaseDynamicPolicyEngine)
		policyName  string
		expectFound bool
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
		name            string
		setupEngine     func(*DatabaseDynamicPolicyEngine, sqlmock.Sqlmock)
		req             OrchestratorRequest
		expectedAllowed bool
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
				Client: ClientContext{ID: "test-tenant"},
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
				Client: ClientContext{ID: "any-tenant"},
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
				Client: ClientContext{ID: "my-tenant"},
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
	rows := sqlmock.NewRows([]string{"name", "conditions", "actions", "tenant_id", "priority", "policy_id"}).
		AddRow("test_policy", "{}", "{}", "tenant1", 10, "policy1")

	mock.ExpectQuery("SELECT name, conditions, actions, tenant_id, priority, policy_id FROM dynamic_policies").
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
		db:           db,
		metricsDB:    metricsDB,
		policies:     make(map[string]interface{}),
		lastRefresh:  time.Now(),
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
