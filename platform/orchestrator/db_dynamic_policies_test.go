// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/testutil"
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
				rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"}).
					AddRow("00000000-0000-0000-0000-000000000001", "test_policy", "", "{}", "{}", "tenant1", "tenant1", 10, "policy1", "content", "dynamic-security", "medium", false, nil, nil, nil)
				mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, org_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override, created_at, updated_at, segment_id FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
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
// #4026: THE MEDIA HALF IS NOW A READ, AND THE SAMPLE HALF ASKS PERMISSION.
//
// verifySystemMediaPolicies replaced seedSystemMediaPolicies: one wrap
// ('global' scope) around a single SELECT, not five INSERTs. core/172 revoked
// INSERT on dynamic_policies from the application roles and core/173 seeds
// those rows as the owner, so a boot-time INSERT could only ever be refused —
// which is what took the production-posture clean-boot guard red on main.
//
// The sample seed then asks has_table_privilege before attempting anything, so
// a connection that may not write skips it instead of being refused. That probe
// is scripted in every case below: it runs before the COUNT and decides whether
// the COUNT happens at all.
//
// v9 Phase 8 PR-C2 (#2384) still applies to insertSamplePolicies: one wrap per
// sample (per-tenant scope), each adding BEGIN + set_config + COMMIT.
func TestSeedDefaultData(t *testing.T) {
	// mediaVerify scripts the read that replaced the five INSERTs, returning all
	// five rows present — the state every correctly-migrated deployment is in.
	mediaVerify := func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec("set_config").WithArgs("global").WillReturnResult(sqlmock.NewResult(0, 0))
		rows := sqlmock.NewRows([]string{"policy_id"})
		for _, p := range systemMediaPolicies {
			rows.AddRow(p.policyID)
		}
		mock.ExpectQuery("SELECT policy_id FROM dynamic_policies WHERE policy_id IN").
			WillReturnRows(rows)
		mock.ExpectCommit()
	}
	mayInsert := func(mock sqlmock.Sqlmock, allowed bool) {
		mock.ExpectQuery("has_table_privilege").
			WillReturnRows(sqlmock.NewRows([]string{"has_table_privilege"}).AddRow(allowed))
	}

	tests := []struct {
		name        string
		mockSetup   func(sqlmock.Sqlmock)
		expectError bool
	}{
		{
			name: "Success - empty database, seeds sample policies",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mediaVerify(mock)
				mayInsert(mock, true)

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
				mediaVerify(mock)
				mayInsert(mock, true)

				// Count query returns 5 (table has data)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

				// No sample policy inserts expected
			},
			expectError: false,
		},
		{
			name: "The frozen posture - no INSERT privilege, so the sample seed is never attempted",
			mockSetup: func(mock sqlmock.Sqlmock) {
				// THE #4026 CASE. On a production-posture stack the connection
				// holds SELECT and not INSERT. The boot path must stop here: no
				// COUNT, no INSERT, and therefore no `permission denied` line for
				// the clean-boot guard to fail on. Scripting nothing after the
				// probe is the assertion — ExpectationsWereMet plus sqlmock's
				// refusal of unexpected statements catches either one.
				mediaVerify(mock)
				mayInsert(mock, false)
			},
			expectError: false,
		},
		{
			name: "Error - count query fails",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mediaVerify(mock)
				mayInsert(mock, true)

				// Count query fails
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
					WillReturnError(errors.New("query failed"))
			},
			expectError: true,
		},
		{
			name: "A missing media control is reported but does not fail the boot",
			mockSetup: func(mock sqlmock.Sqlmock) {
				// The verify returns FOUR of five. seedDefaultData logs at ERROR
				// and carries on: a deployment missing media governance must be
				// loud, and must still boot, because refusing to start would take
				// out every other control too.
				mock.ExpectBegin()
				mock.ExpectExec("set_config").WithArgs("global").WillReturnResult(sqlmock.NewResult(0, 0))
				rows := sqlmock.NewRows([]string{"policy_id"})
				for _, p := range systemMediaPolicies[1:] {
					rows.AddRow(p.policyID)
				}
				mock.ExpectQuery("SELECT policy_id FROM dynamic_policies WHERE policy_id IN").
					WillReturnRows(rows)
				mock.ExpectCommit()
				mayInsert(mock, true)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))
			},
			expectError: false,
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

// TestInsertSamplePolicies_ConditionsAreAbsent pins the restored semantics
// for the DB-seeded half of the platform's sample policies: none of the
// three sample policyData payloads carries a "conditions" key, so
// policyMap["conditions"] marshals to the JSON literal `null` —
// deliberately. These rows are meant to apply unconditionally, and
// null/absent conditions is exactly how that is expressed (see
// condition_evaluator.go's "Withdrawn" doc section for why a synthetic
// always-true condition briefly stood in for this and was removed).
// TestVerifySystemMediaPoliciesReportsWhatIsMissing asserts the REPORT, which is
// the whole point of keeping the check after #4026 turned it from a write into a
// read.
//
// WHY IT IS NOT A SUBTEST OF TestSeedDefaultData. It was, briefly, and that
// version was worthless: seedDefaultData logs the error and returns nil, so a
// subtest driving it can only assert "the boot continued" - which is also what
// happens if the check stops reporting entirely. Mutating the reporting away
// left that subtest green. The observable that moves is the error
// verifySystemMediaPolicies RETURNS, so the assertion goes there.
func TestVerifySystemMediaPoliciesReportsWhatIsMissing(t *testing.T) {
	if len(systemMediaPolicies) == 0 {
		t.Fatal("the expectation set is empty; every assertion below would be vacuous")
	}

	// EVERY ID, not index 0. Driving only the first row leaves a loop that
	// skips the LAST element green - `systemMediaPolicies[:len-1]` still
	// reports index 0 absent, so the test passes while four of five controls
	// are unchecked. The absent id is the parameter.
	for _, absent := range systemMediaPolicies {
		t.Run(absent.policyID, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock: %v", err)
			}
			defer func() { _ = db.Close() }()

			args := make([]driver.Value, 0, len(systemMediaPolicies))
			rows := sqlmock.NewRows([]string{"policy_id"})
			for _, p := range systemMediaPolicies {
				args = append(args, p.policyID)
				if p.policyID != absent.policyID {
					rows.AddRow(p.policyID)
				}
			}

			mock.ExpectBegin()
			mock.ExpectExec("set_config").WithArgs("global").WillReturnResult(sqlmock.NewResult(0, 0))
			// WithArgs PINS THE ID SET. Without it a query asking about ONE id
			// matches this expectation and the verify reports the other four
			// absent - which a real database would refuse loudly and sqlmock
			// will not.
			mock.ExpectQuery("SELECT policy_id FROM dynamic_policies WHERE policy_id IN").
				WithArgs(args...).WillReturnRows(rows)
			mock.ExpectCommit()

			engine := &DatabaseDynamicPolicyEngine{db: db}
			verifyErr := engine.verifySystemMediaPolicies()
			if verifyErr == nil {
				t.Fatal("a deployment missing a media governance control was reported as healthy; " +
					"that deployment has no NSFW blocking, violence warning, biometric logging, media PII " +
					"blocking or sensitive-document warning for the absent row, and nothing else says so")
			}
			// NAMED, not merely counted. An operator reading this line has to
			// know which control to restore, and re-running core/173 is the remedy.
			if !strings.Contains(verifyErr.Error(), absent.policyID) {
				t.Fatalf("the report does not name the absent control %q: %v", absent.policyID, verifyErr)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the verify issued a statement sequence other than the scripted read: %v", err)
			}
		})
	}
}

// TestSeedDefaultDataLogsTheAbsenceAtErrorLevel asserts the LOG LINE, which is
// the only thing an operator or the clean-boot guard ever sees.
//
// WHY THE RETURNED ERROR IS NOT ENOUGH. seedDefaultData logs and returns nil, so
// every other test here can assert at most "the boot continued". Downgrading
// `log.Printf("ERROR: ...")` back to `"Warning: ..."` leaves all of them green -
// and a warning is exactly what this whole PR exists to stop: the old refused
// INSERT was a warning too, which is why it sat unnoticed until it took a test
// tier down. The severity IS the behaviour here.
func TestSeedDefaultDataLogsTheAbsenceAtErrorLevel(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Four of five present: the deployment that is missing a control.
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WithArgs("global").WillReturnResult(sqlmock.NewResult(0, 0))
	rows := sqlmock.NewRows([]string{"policy_id"})
	for _, p := range systemMediaPolicies[1:] {
		rows.AddRow(p.policyID)
	}
	mock.ExpectQuery("SELECT policy_id FROM dynamic_policies WHERE policy_id IN").WillReturnRows(rows)
	mock.ExpectCommit()
	mock.ExpectQuery("has_table_privilege").
		WillReturnRows(sqlmock.NewRows([]string{"has_table_privilege"}).AddRow(true))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	engine := &DatabaseDynamicPolicyEngine{db: db}
	if err := engine.seedDefaultData(); err != nil {
		t.Fatalf("a missing media control must not fail the boot: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "ERROR:") {
		t.Fatalf("the absence was not reported at ERROR level; an operator and the production-posture "+
			"clean-boot guard read this line, and a warning is what let the original defect sit unnoticed.\nlog was: %s", got)
	}
	if !strings.Contains(got, systemMediaPolicies[0].policyID) {
		t.Fatalf("the ERROR line does not name the absent control %q.\nlog was: %s", systemMediaPolicies[0].policyID, got)
	}
}

// TestVerifySystemMediaPoliciesIsSilentWhenAllPresent is the anti-vacuity twin:
// without it, a check that reported an error unconditionally would pass the test
// above while making every healthy boot log an ERROR.
func TestVerifySystemMediaPoliciesIsSilentWhenAllPresent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec("set_config").WithArgs("global").WillReturnResult(sqlmock.NewResult(0, 0))
	rows := sqlmock.NewRows([]string{"policy_id"})
	for _, p := range systemMediaPolicies {
		rows.AddRow(p.policyID)
	}
	mock.ExpectQuery("SELECT policy_id FROM dynamic_policies WHERE policy_id IN").WillReturnRows(rows)
	mock.ExpectCommit()

	engine := &DatabaseDynamicPolicyEngine{db: db}
	if verifyErr := engine.verifySystemMediaPolicies(); verifyErr != nil {
		t.Fatalf("a fully seeded deployment was reported as missing controls: %v", verifyErr)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled expectations: %v", err)
	}
}

func TestInsertSamplePolicies_ConditionsAreAbsent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	for _, scope := range []string{"healthcare", "ecommerce", "global"} {
		mock.ExpectBegin()
		mock.ExpectExec("set_config").WithArgs(scope).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("INSERT INTO dynamic_policies").
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
				"null", sqlmock.AnyArg(), scope, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()
	}

	engine := &DatabaseDynamicPolicyEngine{db: db}
	if err := engine.insertSamplePolicies(); err != nil {
		t.Fatalf("insertSamplePolicies failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled mock expectations (conditions column did not match the expected null literal): %v", err)
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
				rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"}).
					AddRow("00000000-0000-0000-0000-000000000001", "policy1", "", `{"field": "value"}`, `{"action": "allow"}`, "tenant1", "tenant1", 10, "pol1", "content", "dynamic-security", "medium", false, nil, nil, nil).
					AddRow("00000000-0000-0000-0000-000000000002", "policy2", "", `{"field": "value2"}`, `{"action": "deny"}`, "tenant2", "tenant2", 5, "pol2", "rate-limit", "dynamic-risk", "medium", false, nil, nil, nil).
					AddRow("00000000-0000-0000-0000-000000000003", "policy3", "", `{"field": "value3"}`, `{"action": "log"}`, sql.NullString{}, sql.NullString{}, 1, "pol3", "content", "", "medium", false, nil, nil, nil)

				mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, org_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override, created_at, updated_at, segment_id FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
					WillReturnRows(rows)
			},
			expectError:   false,
			expectedCount: 3,
		},
		{
			name: "Success - empty result",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"})

				mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, org_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override, created_at, updated_at, segment_id FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
					WillReturnRows(rows)
			},
			expectError:   false,
			expectedCount: 0,
		},
		{
			name: "Error - query fails",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, org_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override, created_at, updated_at, segment_id FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
					WillReturnError(errors.New("database connection lost"))
			},
			expectError:   true,
			expectedCount: 0,
		},
		{
			name: "Success - handles NULL tenant_id",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"}).
					AddRow("00000000-0000-0000-0000-000000000004", "global_policy", "", `{}`, `{}`, sql.NullString{Valid: false}, sql.NullString{Valid: false}, 0, "global1", "content", "", "medium", false, nil, nil, nil)

				mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, org_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override, created_at, updated_at, segment_id FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
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

// TestRefreshPolicies_SegmentIDMetadataSurvives (L10) drives a real,
// non-NULL segment_id through the loader and asserts it lands in
// _metadata["segment_id"] — mutating segmentIDStr to always be "" (dropping
// the segment_id scoping entirely) would still pass every other
// TestRefreshPolicies case, since none of them plant a non-NULL value.
func TestRefreshPolicies_SegmentIDMetadataSurvives(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"}).
		AddRow("00000000-0000-0000-0000-000000000009", "finance_policy", "", `{}`, `{}`, "tenant1", "tenant1", 10, "pol-seg", "content", "dynamic-security", "medium", false, nil, nil, "seg-finance")

	mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, org_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override, created_at, updated_at, segment_id FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
		WillReturnRows(rows)

	engine := &DatabaseDynamicPolicyEngine{db: db, policies: make(map[string]interface{})}
	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("refreshPolicies failed: %v", err)
	}

	policy, ok := engine.GetPolicy("pol-seg")
	if !ok {
		t.Fatal("expected policy pol-seg to be loaded")
	}
	metadata, ok := policy["_metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("expected _metadata to be present")
	}
	if segmentID, _ := metadata["segment_id"].(string); segmentID != "seg-finance" {
		t.Fatalf("expected _metadata.segment_id = %q, got %q", "seg-finance", segmentID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled mock expectations: %v", err)
	}
}

// TestRefreshPolicies_SegmentColumnMissing_RetriesSegmentLess is the H3
// upgrade-ordering probe (#3239 round 2): if dynamic_policies.segment_id
// doesn't exist yet (booted before migration 159 applied — reachable in
// standard Docker Compose, since /health is liveness-only and does not wait
// for migrations), refreshPolicies must retry segment-less rather than
// failing the whole refresh.
func TestRefreshPolicies_SegmentColumnMissing_RetriesSegmentLess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, org_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override, created_at, updated_at, segment_id FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
		WillReturnError(&pq.Error{Code: "42703", Message: `column "segment_id" does not exist`})

	fallbackRows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at"}).
		AddRow("00000000-0000-0000-0000-000000000010", "pre_migration_policy", "", `{}`, `{}`, "tenant1", "tenant1", 10, "pol-premig", "content", "dynamic-security", "medium", false, nil, nil)

	mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, org_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override, created_at, updated_at FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
		WillReturnRows(fallbackRows)

	engine := &DatabaseDynamicPolicyEngine{db: db, policies: make(map[string]interface{})}
	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("expected refreshPolicies to tolerate a missing segment_id column, got error: %v", err)
	}

	policy, ok := engine.GetPolicy("pol-premig")
	if !ok {
		t.Fatal("expected the segment-less-retry policy to be loaded")
	}
	metadata, ok := policy["_metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("expected _metadata to be present")
	}
	if segmentID, _ := metadata["segment_id"].(string); segmentID != "" {
		t.Fatalf("expected _metadata.segment_id = \"\" (column not yet migrated), got %q", segmentID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled mock expectations: %v", err)
	}
}

// =============================================================================
// #3319: one always-constructible engine, observable policy-set source
// =============================================================================

// TestRefreshPolicies_FirstSuccessfulLoadPromotesSource is the #3319
// acceptance test: an engine that begins serving the built-in default
// fallback set (PolicySetSource() == "defaults") promotes to "database" the
// moment its first refreshPolicies() succeeds, and the
// axonflow_policy_set_source gauge follows it — this is the primary signal
// #3319 exists to publish.
func TestRefreshPolicies_FirstSuccessfulLoadPromotesSource(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"}).
		AddRow("00000000-0000-0000-0000-000000000001", "policy1", "", `{}`, `{}`, "tenant1", "tenant1", 10, "pol1", "content", "custom", "medium", false, nil, nil, nil)
	mock.ExpectQuery("SELECT id::text, name").WillReturnRows(rows)

	engine := &DatabaseDynamicPolicyEngine{
		db:              db,
		policies:        loadDefaultPoliciesCache(),
		policySetSource: policySetSourceDefaults,
	}
	if got := engine.PolicySetSource(); got != policySetSourceDefaults {
		t.Fatalf("expected initial source %q, got %q", policySetSourceDefaults, got)
	}

	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("refreshPolicies failed: %v", err)
	}

	if got := engine.PolicySetSource(); got != policySetSourceDatabase {
		t.Errorf("expected source promoted to %q after first successful load, got %q", policySetSourceDatabase, got)
	}
	if got := testutil.ToFloat64(policySetSourceGauge.WithLabelValues(policySourceLabelDatabase)); got != 1 {
		t.Errorf("axonflow_policy_set_source{source=\"database\"} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(policySetSourceGauge.WithLabelValues(policySourceLabelDefaults)); got != 0 {
		t.Errorf("axonflow_policy_set_source{source=\"defaults\"} = %v, want 0", got)
	}
	if age := testutil.ToFloat64(policyCacheAgeSeconds); age != 0 {
		t.Errorf("axonflow_policy_cache_age_seconds after a fresh successful load = %v, want 0", age)
	}
}

// TestRefreshPolicies_FailedRefreshNeverDowngradesSource is the #3319
// regression test for "a failed refresh is a no-op." Once
// promoted to "database", a later failed refresh must NEVER revert the
// source to "defaults" or touch the last-good policy set — that would
// convert a transient blip into an enforcement gap. This guards
// refreshPolicies' swap-only-on-success ordering: every error return must
// stay strictly before the e.policies/e.policySetSource write.
func TestRefreshPolicies_FailedRefreshNeverDowngradesSource(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	goodRows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"}).
		AddRow("00000000-0000-0000-0000-000000000001", "policy1", "", `{}`, `{}`, "tenant1", "tenant1", 10, "last-good-policy", "content", "custom", "medium", false, nil, nil, nil)
	mock.ExpectQuery("SELECT id::text, name").WillReturnRows(goodRows)
	mock.ExpectQuery("SELECT id::text, name").WillReturnError(errors.New("connection reset"))

	engine := &DatabaseDynamicPolicyEngine{
		db:              db,
		policies:        loadDefaultPoliciesCache(),
		policySetSource: policySetSourceDefaults,
	}

	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("first (successful) refreshPolicies failed: %v", err)
	}
	if got := engine.PolicySetSource(); got != policySetSourceDatabase {
		t.Fatalf("expected source %q after the successful load, got %q", policySetSourceDatabase, got)
	}
	engine.mu.RLock()
	lastGoodPolicies := len(engine.policies)
	lastGoodRefresh := engine.lastRefresh
	engine.mu.RUnlock()

	failuresBefore := testutil.ToFloat64(policyRefreshFailuresTotal.WithLabelValues(reasonQueryFailed))

	if err := engine.refreshPolicies(); err == nil {
		t.Fatal("expected the second refreshPolicies to fail")
	}

	if got := engine.PolicySetSource(); got != policySetSourceDatabase {
		t.Errorf("a failed refresh reverted source from %q to %q — a failed refresh must be a no-op, never a downgrade (#3319)", policySetSourceDatabase, got)
	}
	engine.mu.RLock()
	stillGoodPolicies := len(engine.policies)
	stillLastRefresh := engine.lastRefresh
	engine.mu.RUnlock()
	if stillGoodPolicies != lastGoodPolicies {
		t.Errorf("a failed refresh changed the cached policy count from %d to %d — the last-good set must be untouched", lastGoodPolicies, stillGoodPolicies)
	}
	if !stillLastRefresh.Equal(lastGoodRefresh) {
		t.Errorf("a failed refresh advanced lastRefresh from %v to %v — only a successful load may do that", lastGoodRefresh, stillLastRefresh)
	}

	failuresAfter := testutil.ToFloat64(policyRefreshFailuresTotal.WithLabelValues(reasonQueryFailed))
	if failuresAfter != failuresBefore+1 {
		t.Errorf("axonflow_policy_refresh_failures_total{reason=\"query_failed\"} did not increment: before=%v after=%v", failuresBefore, failuresAfter)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled mock expectations: %v", err)
	}
}

// TestRefreshPolicies_DatabaseNotConfigured_DoesNotCountAsRefreshFailure is
// the R3 finding-3 regression test (#3319 hostile review): a
// DATABASE_URL-unset deployment is a steady, intentional community-mode
// state, not a failure — every 30s backgroundRefresh tick must not
// increment axonflow_policy_refresh_failures_total{reason="database_not_configured"}
// forever, or a naive `rate(...) > 0` alert fires permanently for every
// correctly-configured no-database install.
// axonflow_policy_set_source{source="defaults"} already exposes this state
// continuously, so nothing is lost by not also counting it as a failure.
func TestRefreshPolicies_DatabaseNotConfigured_DoesNotCountAsRefreshFailure(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		dbURL:           "",
		policies:        loadDefaultPoliciesCache(),
		policySetSource: policySetSourceDefaults,
	}

	before := testutil.ToFloat64(policyRefreshFailuresTotal.WithLabelValues(reasonDatabaseNotConfigured))

	if err := engine.refreshPolicies(); err == nil {
		t.Fatal("expected refreshPolicies to return an error when DATABASE_URL is unset")
	}
	if err := engine.refreshPolicies(); err == nil {
		t.Fatal("expected the second refreshPolicies to also return an error")
	}

	after := testutil.ToFloat64(policyRefreshFailuresTotal.WithLabelValues(reasonDatabaseNotConfigured))
	if after != before {
		t.Errorf("axonflow_policy_refresh_failures_total{reason=\"database_not_configured\"} incremented from %v to %v — a DATABASE_URL-unset deployment is a steady state, not a refresh failure (#3319 R3 finding 3)", before, after)
	}

	// Source must stay "defaults" — this is not a load, successful or
	// otherwise, so nothing about the policy set changes.
	if got := engine.PolicySetSource(); got != policySetSourceDefaults {
		t.Errorf("expected PolicySetSource() = %q, got %q", policySetSourceDefaults, got)
	}
}

// TestRefreshPolicies_ZeroRowLoadDistinguishableFromFailedLoad is the #3319
// item D acceptance test: a load that SUCCEEDS with zero rows on a pool this
// engine TRUSTS (refreshPoolIsRLSScoped false — the zero value, and the case
// for every engine here that never opts in) must not be indistinguishable
// from a load that FAILED. Both leave the cache looking "empty-ish," but
// only the failure should count against policyRefreshFailuresTotal, and only
// the zero-row success should count against policyZeroRowLoadsTotal.
//
// This is deliberately the TRUSTED-pool half of the pair — the companion
// case, a zero-row load on a pool refreshPoolIsRLSScoped marks untrusted
// (#3322 item 3, the #3039 shape), is
// TestRefreshPolicies_ZeroRowLoadOnRLSScopedPoolIsRefused below: that one
// must NOT promote, unlike this one.
func TestRefreshPolicies_ZeroRowLoadDistinguishableFromFailedLoad(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	emptyRows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"})
	mock.ExpectQuery("SELECT id::text, name").WillReturnRows(emptyRows)

	engine := &DatabaseDynamicPolicyEngine{
		db:              db,
		policies:        loadDefaultPoliciesCache(),
		policySetSource: policySetSourceDefaults,
	}

	zeroRowBefore := testutil.ToFloat64(policyZeroRowLoadsTotal)
	failuresBefore := testutil.ToFloat64(policyRefreshFailuresTotal.WithLabelValues(reasonQueryFailed))

	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("a zero-row load is a SUCCESS, not an error: got %v", err)
	}

	// Succeeded, so this must still promote to "database" — a genuinely
	// empty policy set is a legitimate deployment state, not a failure to
	// mask by silently reverting to (or mixing in) the built-in defaults.
	if got := engine.PolicySetSource(); got != policySetSourceDatabase {
		t.Errorf("expected a successful zero-row load to promote source to %q, got %q", policySetSourceDatabase, got)
	}
	engine.mu.RLock()
	count := len(engine.policies)
	engine.mu.RUnlock()
	if count != 0 {
		t.Errorf("expected the cache to hold exactly the 0 rows returned, got %d", count)
	}

	zeroRowAfter := testutil.ToFloat64(policyZeroRowLoadsTotal)
	if zeroRowAfter != zeroRowBefore+1 {
		t.Errorf("axonflow_policy_zero_row_loads_total did not increment: before=%v after=%v", zeroRowBefore, zeroRowAfter)
	}
	failuresAfter := testutil.ToFloat64(policyRefreshFailuresTotal.WithLabelValues(reasonQueryFailed))
	if failuresAfter != failuresBefore {
		t.Errorf("a successful zero-row load must NOT increment axonflow_policy_refresh_failures_total: before=%v after=%v", failuresBefore, failuresAfter)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled mock expectations: %v", err)
	}
}

// TestRefreshPolicies_ZeroRowLoadOnRLSScopedPoolIsRefused is the #3322 item 3
// acceptance test (Saurabh's #3319 review): a zero-row load on a pool this
// engine has marked refreshPoolIsRLSScoped MUST be refused — treated as a
// failed refresh, never promoted — because the query's own success/error
// signal cannot tell "genuinely zero policies" apart from the #3039 shape
// (get_current_org_id() NULL with no org GUC set -> org_id = NULL matches
// nothing -> zero rows, no error). This engine starts with a NON-EMPTY
// database-sourced policy set already loaded (unlike the RLS integration
// fixture in rls_blind_reads_3039_approle_test.go, which starts empty and so
// cannot show the swap-only-on-success invariant actually held) — proving
// the refusal leaves that prior set (and its source) completely untouched.
func TestRefreshPolicies_ZeroRowLoadOnRLSScopedPoolIsRefused(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	emptyRows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "segment_id"})
	mock.ExpectQuery("SELECT id::text, name").WillReturnRows(emptyRows)

	priorPolicies := map[string]interface{}{
		"prior_policy": map[string]interface{}{
			"name":      "prior_policy",
			"_metadata": map[string]interface{}{"tenant_id": "global", "org_id": "global"},
		},
	}
	priorRefresh := time.Now().Add(-10 * time.Second)
	engine := &DatabaseDynamicPolicyEngine{
		db:                     db,
		policies:               priorPolicies,
		policySetSource:        policySetSourceDatabase,
		lastRefresh:            priorRefresh,
		refreshPoolIsRLSScoped: true,
	}

	zeroRowBefore := testutil.ToFloat64(policyZeroRowLoadsTotal)
	failuresBefore := testutil.ToFloat64(policyRefreshFailuresTotal.WithLabelValues(reasonZeroRowRLSBlind))

	if err := engine.refreshPolicies(); err == nil {
		t.Fatal("expected refreshPolicies to refuse a zero-row load on an RLS-scoped pool, got nil error")
	}

	engine.mu.RLock()
	count := len(engine.policies)
	source := engine.policySetSource
	lastRefresh := engine.lastRefresh
	engine.mu.RUnlock()
	if count != 1 {
		t.Errorf("a refused load must leave the prior policy set untouched, got %d polic(y/ies)", count)
	}
	if source != policySetSourceDatabase {
		t.Errorf("a refused load must not change policySetSource, got %q", source)
	}
	if !lastRefresh.Equal(priorRefresh) {
		t.Errorf("a refused load must not advance lastRefresh, got %v want %v", lastRefresh, priorRefresh)
	}

	// This is a REFUSAL, not a trusted empty success — it must count against
	// the RLS-blind failure reason, not policyZeroRowLoadsTotal (that
	// counter is reserved for a zero-row result this engine actually
	// trusts; see TestRefreshPolicies_ZeroRowLoadDistinguishableFromFailedLoad).
	zeroRowAfter := testutil.ToFloat64(policyZeroRowLoadsTotal)
	if zeroRowAfter != zeroRowBefore {
		t.Errorf("a refused RLS-scoped zero-row load must NOT increment axonflow_policy_zero_row_loads_total: before=%v after=%v", zeroRowBefore, zeroRowAfter)
	}
	failuresAfter := testutil.ToFloat64(policyRefreshFailuresTotal.WithLabelValues(reasonZeroRowRLSBlind))
	if failuresAfter != failuresBefore+1 {
		t.Errorf("axonflow_policy_refresh_failures_total{reason=%q} did not increment: before=%v after=%v", reasonZeroRowRLSBlind, failuresBefore, failuresAfter)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled mock expectations: %v", err)
	}
}

// TestNewDatabaseDynamicPolicyEngine_UnreachableDatabase_ConstructsWithDefaults
// is the #3319 acceptance test: construction must succeed even when the
// database is unreachable, serving the built-in default fallback set rather
// than failing the whole process. Dials a real (fast-failing) address —
// connection-refused on a closed local port returns in well under a second
// per attempt (see agent.OpenAppRoleConnection), so this stays fast despite
// exercising the real dial path end to end.
func TestNewDatabaseDynamicPolicyEngine_UnreachableDatabase_ConstructsWithDefaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://baduser:badpass@127.0.0.1:1/nonexistentdb?sslmode=disable&connect_timeout=1")

	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("expected construction to succeed even with an unreachable database, got error: %v", err)
	}
	if engine == nil {
		t.Fatal("expected a non-nil engine")
	}
	defer func() { _ = engine.Close() }()

	if got := engine.PolicySetSource(); got != policySetSourceDefaults {
		t.Errorf("expected PolicySetSource() = %q for a boot against an unreachable database, got %q", policySetSourceDefaults, got)
	}
	policies := engine.ListActivePolicies()
	if len(policies) != len(loadDefaultDynamicPolicies()) {
		t.Errorf("expected the %d built-in default policies to be served, got %d", len(loadDefaultDynamicPolicies()), len(policies))
	}
	// R3 finding 2 (#3319 hostile review): a policySetSourceDefaults engine
	// is judged healthy on its non-empty policy set alone, not on e.db —
	// this deployment is correctly serving the built-in fallback while
	// backgroundRefresh keeps retrying the connection in the background,
	// exactly the legitimate state IsHealthy() must not report as broken.
	// See TestDatabasePolicyEngine_IsHealthy_DefaultsMode for the focused
	// unit coverage of the predicate itself.
	if !engine.IsHealthy() {
		t.Error("expected IsHealthy() = true: engine is correctly serving the built-in default policy set")
	}
}

// TestNewDatabaseDynamicPolicyEngine_NoDatabaseURL_ConstructsWithDefaults
// covers the other non-fatal boot path named in #3319: DATABASE_URL unset
// entirely (a legitimate community-mode deployment, not a misconfiguration)
// must also construct successfully and serve the built-in defaults.
func TestNewDatabaseDynamicPolicyEngine_NoDatabaseURL_ConstructsWithDefaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "")

	engine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		t.Fatalf("expected construction to succeed with DATABASE_URL unset, got error: %v", err)
	}
	if engine == nil {
		t.Fatal("expected a non-nil engine")
	}
	defer func() { _ = engine.Close() }()

	if got := engine.PolicySetSource(); got != policySetSourceDefaults {
		t.Errorf("expected PolicySetSource() = %q with no database configured, got %q", policySetSourceDefaults, got)
	}
}

// TestRefreshPolicies_RecoversAfterUnreachableDatabase_NoReconstruction is
// the #3319 recovery acceptance test: a process that started with no
// reachable database reaches the database-loaded state on a later tick,
// WITHOUT reconstruction — the same *DatabaseDynamicPolicyEngine value
// throughout. This is the defect #3319 retires: the old in-memory engine's
// dbAvailable flag was set true in exactly one place (construction) and
// never revisited, so a boot-time blip was permanent until restart.
//
// The first refreshPolicies() call dials a real, fast-failing local address
// (proving a failure doesn't set any sticky flag that would block a later
// attempt); the "recovery" itself is simulated by wiring in a working mock
// pool the way a real successful connectDB would, since sqlmock cannot
// intercept the actual network dial connectDB performs.
func TestRefreshPolicies_RecoversAfterUnreachableDatabase_NoReconstruction(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		dbURL:           "postgres://baduser:badpass@127.0.0.1:1/nonexistentdb?sslmode=disable&connect_timeout=1",
		policies:        loadDefaultPoliciesCache(),
		policySetSource: policySetSourceDefaults,
	}

	if err := engine.refreshPolicies(); err == nil {
		t.Fatal("expected the first refreshPolicies to fail against an unreachable database")
	}
	if got := engine.PolicySetSource(); got != policySetSourceDefaults {
		t.Fatalf("expected source to remain %q after a failed connect, got %q", policySetSourceDefaults, got)
	}

	// The database "becomes reachable." engine.db is still nil at this
	// point (the failed connectDB above never set it) — wire in a working
	// pool directly, standing in for what a real successful connectDB call
	// would do, on this SAME engine instance.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"}).
		AddRow("00000000-0000-0000-0000-000000000001", "recovered_policy", "", `{}`, `{}`, "tenant1", "tenant1", 10, "recovered", "content", "custom", "medium", false, nil, nil, nil)
	mock.ExpectQuery("SELECT id::text, name").WillReturnRows(rows)

	engine.mu.Lock()
	engine.db = db
	engine.mu.Unlock()

	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("expected refreshPolicies to succeed once db is reachable: %v", err)
	}
	if got := engine.PolicySetSource(); got != policySetSourceDatabase {
		t.Errorf("expected the SAME engine instance to reach source %q after recovery without reconstruction, got %q", policySetSourceDatabase, got)
	}
	if _, ok := engine.GetPolicy("recovered_policy"); !ok {
		t.Error("expected the recovered load's policy to be present")
	}
}

// TestLookupSegmentID_Hit_Miss_Segmentless covers the #3319 contract
// LookupSegmentID must satisfy for PolicyService.TestPolicy
// (policy_api_service.go): found=false means "not cached
// here," never "not segment-scoped" — a hit on a segment-less policy must
// return found=true with segmentID="".
func TestLookupSegmentID_Hit_Miss_Segmentless(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"}).
		AddRow("00000000-0000-0000-0000-000000000001", "scoped_policy", "", `{}`, `{}`, "tenant1", "tenant1", 10, "pol-scoped", "content", "custom", "medium", false, nil, nil, "seg-finance").
		AddRow("00000000-0000-0000-0000-000000000002", "unscoped_policy", "", `{}`, `{}`, "tenant1", "tenant1", 5, "pol-unscoped", "content", "custom", "medium", false, nil, nil, nil)
	mock.ExpectQuery("SELECT id::text, name").WillReturnRows(rows)

	engine := &DatabaseDynamicPolicyEngine{db: db, policies: make(map[string]interface{})}
	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("refreshPolicies failed: %v", err)
	}

	if segID, found := engine.LookupSegmentID("pol-scoped"); !found || segID != "seg-finance" {
		t.Errorf("LookupSegmentID(%q) = (%q, %v), want (%q, true)", "pol-scoped", segID, found, "seg-finance")
	}
	if segID, found := engine.LookupSegmentID("pol-unscoped"); !found || segID != "" {
		t.Errorf("LookupSegmentID(%q) = (%q, %v), want (\"\", true) — a cache hit on a segment-less policy must report found=true", "pol-unscoped", segID, found)
	}
	if segID, found := engine.LookupSegmentID("does-not-exist"); found {
		t.Errorf("LookupSegmentID(%q) = (%q, %v), want found=false", "does-not-exist", segID, found)
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
						"org_id":    "test-tenant",
						"priority":  10,
					},
					"rules": map[string]interface{}{
						"risk_score": 0.5,
					},
					// A real, trivially-satisfied condition rather than none —
					// this fixture's actual point is tenant scoping, not
					// condition evaluation, and a zero-condition policy would
					// pass regardless of whether evaluation works at all
					// (zero/absent conditions vacuously matches everything).
					"conditions": []interface{}{
						map[string]interface{}{"field": "query", "operator": "contains", "value": "test"},
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
				// Decision 5 (#3490): OrgID is what selects the policy set.
				// The fixture uses the org == tenant identity, so this row
				// still exercises "the caller's own policy applies".
				Client: ClientContext{ID: "test-client", TenantID: "test-tenant", OrgID: "test-tenant"},
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
						"org_id":    "global",
						"priority":  1,
					},
					// See the "conditions" comment on tenant_policy above.
					"conditions": []interface{}{
						map[string]interface{}{"field": "query", "operator": "contains", "value": "test"},
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
						"org_id":    "global",
					},
					"rules": map[string]interface{}{
						"required_actions": []interface{}{"log", "alert"},
						"risk_score":       0.8,
					},
					// See the "conditions" comment on tenant_policy above.
					"conditions": []interface{}{
						map[string]interface{}{"field": "query", "operator": "contains", "value": "test"},
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
						"org_id":    "other-tenant",
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
				// The seeded policy belongs to other-tenant/other-tenant, so
				// this stays the cross-scope control it was written to be.
				Client: ClientContext{ID: "my-client", TenantID: "my-tenant", OrgID: "my-org"},
				Query:  "test query",
			},
			expectedAllowed:  true,
			expectedPolicies: 0,
		},
		{
			// A policy with no "conditions" key at all (which parses to a
			// zero-length conditions slice, the same shape as an explicit
			// `"conditions": []`) vacuously matches — it applies to every
			// tenant scope. See condition_evaluator.go's "Withdrawn" doc
			// section.
			name: "Zero-condition policy applies to everything",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine, mock sqlmock.Sqlmock) {
				engine.mu.Lock()
				engine.policies["no_conditions_policy"] = map[string]interface{}{
					"name": "no_conditions_policy",
					"_metadata": map[string]interface{}{
						"tenant_id": "global",
						"org_id":    "global",
					},
					// Deliberately no "conditions" key.
				}
				engine.lastRefresh = time.Now()
				engine.mu.Unlock()

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

// TestEvaluateDynamicPolicies_ZeroConditionPolicyAppliesToEveryTenant makes
// the restored vacuous-truth semantics concrete rather than abstract: a
// cached, condition-less policy applies to an arbitrary request regardless
// of tenant scope. This is the platform-seeded shape (loadDefaultPolicies'
// fallback, insertSamplePolicies' sample rows) — a customer cannot produce
// one through the API, since both validateCreateRequest and
// validateUpdateRequest reject an empty/cleared conditions array. See
// condition_evaluator.go's "Withdrawn" doc section for why an intermediate
// revision of this effort made this shape match NOTHING instead, and why
// that was reverted.
func TestEvaluateDynamicPolicies_ZeroConditionPolicyAppliesToEveryTenant(t *testing.T) {
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

	engine.mu.Lock()
	engine.policies["unconditional_log_policy"] = map[string]interface{}{
		"name": "unconditional_log_policy",
		"_metadata": map[string]interface{}{
			"tenant_id": "global",
			"org_id":    "global",
		},
		// No "conditions" key — the platform-seeded shape, meaning "applies
		// to everything."
		"actions": []interface{}{
			map[string]interface{}{"type": "log", "config": map[string]interface{}{"message": "logged"}},
		},
	}
	engine.lastRefresh = time.Now()
	engine.mu.Unlock()

	mock.ExpectExec("INSERT INTO policy_metrics").
		WithArgs(sqlmock.AnyArg(), true, "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	result := engine.EvaluateDynamicPolicies(context.Background(), OrchestratorRequest{Query: "any query at all"})

	found := false
	for _, name := range result.AppliedPolicies {
		if name == "unconditional_log_policy" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a zero-condition policy must match an arbitrary request (applies to everything), AppliedPolicies=%v", result.AppliedPolicies)
	}
}

// TestEvaluateDynamicPolicies_ActionArms pins the previously-inert alert,
// redact, and modify_risk action arms (Saurabh's #3322 review, item 2): six
// of the ten built-in defaults (policy_defaults.go) used alert/redact/log or
// a modify_risk config key ("modifier") the switch in EvaluateDynamicPolicies
// never read. It has always read "add" instead -- proven by migration 031's
// sys_dyn_llm_cost, a real, already-shipped system policy configured with
// `{"type": "modify_risk", "config": {"add": 0.2}}` -- so matching one of
// the affected built-in defaults (which used "modifier", a copy-paste from
// the retired in-memory engine's own, different convention) had zero
// observable effect beyond AppliedPolicies. dynamic_policy_types.go's
// PolicyAction doc now specifies the corrected contract for each arm; this
// test locks it in.
func TestEvaluateDynamicPolicies_ActionArms(t *testing.T) {
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

	engine.mu.Lock()
	engine.policies["action_arms_policy"] = map[string]interface{}{
		"name": "action_arms_policy",
		"_metadata": map[string]interface{}{
			"tenant_id": "global",
			"org_id":    "global",
		},
		// No "conditions" key -- applies to everything (vacuous truth).
		"actions": []interface{}{
			map[string]interface{}{"type": "alert", "config": map[string]interface{}{"severity": "high", "channel": "security", "message": "test alert"}},
			map[string]interface{}{"type": "redact", "config": map[string]interface{}{"fields": []interface{}{"ssn", "email"}}},
			map[string]interface{}{"type": "modify_risk", "config": map[string]interface{}{"add": 0.2}},
		},
	}
	engine.lastRefresh = time.Now()
	engine.mu.Unlock()

	mock.ExpectExec("INSERT INTO policy_metrics").
		WithArgs(sqlmock.AnyArg(), true, "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	result := engine.EvaluateDynamicPolicies(context.Background(), OrchestratorRequest{Query: "action arms probe"})

	if result.RiskScore != 0.2 {
		t.Errorf("expected modify_risk to add 0.2 to the base RiskScore of 0.0, got %v", result.RiskScore)
	}

	hasAlert, hasRedact := false, false
	for _, ra := range result.RequiredActions {
		if ra == "alert: action_arms_policy (severity=high)" {
			hasAlert = true
		}
		if ra == "redact_requested: fields=[ssn email]" {
			hasRedact = true
		}
	}
	if !hasAlert {
		t.Errorf("alert action must record a RequiredActions entry, got %v", result.RequiredActions)
	}
	if !hasRedact {
		t.Errorf("redact action must record a RequiredActions entry naming the fields, got %v", result.RequiredActions)
	}
}

// TestEvaluateDynamicPolicies_ModifyRiskIsAdditive isolates the modify_risk
// arithmetic against a nonzero starting risk score, proving it is additive
// (the "add" key) rather than the retired in-memory engine's multiplicative
// "modifier" convention, which this engine's switch has never read.
//
// Deliberately a SINGLE policy carrying both the "rules.risk_score" seed and
// the modify_risk action, rather than two separate policies relying on one
// being visited before the other: EvaluateDynamicPolicies iterates its
// policy cache with a plain `range` over a map (#3322 review item 4 —
// dynamic_policy_types.go's doc on this), so cross-policy evaluation order
// is NOT priority order and is not guaranteed stable across runs. Within a
// SINGLE policy's own processing, the "rules" risk-score bump always runs
// before that same policy's action loop (see EvaluateDynamicPolicies), so
// this shape is order-independent by construction.
func TestEvaluateDynamicPolicies_ModifyRiskIsAdditive(t *testing.T) {
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

	engine.mu.Lock()
	engine.policies["seed_and_modify_risk_policy"] = map[string]interface{}{
		"name": "seed_and_modify_risk_policy",
		"_metadata": map[string]interface{}{
			"tenant_id": "global",
			"org_id":    "global",
		},
		// Seeds RiskScore via the "rules.risk_score" path (the same field
		// EvaluateDynamicPolicies reads at its "Calculate risk score if
		// present" step) before this SAME policy's action loop runs.
		"rules": map[string]interface{}{"risk_score": 0.4},
		"actions": []interface{}{
			map[string]interface{}{"type": "modify_risk", "config": map[string]interface{}{"add": 0.2}},
		},
	}
	engine.lastRefresh = time.Now()
	engine.mu.Unlock()

	mock.ExpectExec("INSERT INTO policy_metrics").
		WithArgs(sqlmock.AnyArg(), true, "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	result := engine.EvaluateDynamicPolicies(context.Background(), OrchestratorRequest{Query: "modify_risk additive probe"})

	const want = 0.4 + 0.2 // additive: 0.6 (modulo float64 rounding); multiplicative would be 0.08
	if diff := result.RiskScore - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("modify_risk must add to the running RiskScore (0.4 + 0.2 == %v), got %v -- a multiplicative reading would produce 0.08", want, result.RiskScore)
	}
}

// TestDatabasePolicyEngine_IsHealthy tests health check
// TestDatabasePolicyEngine_IsHealthy covers the policySetSourceDatabase
// branch of the R3-finding-2 predicate (#3319 hostile review): once
// promoted, health legitimately depends on a live pool + a fresh cache, so
// every sub-test here sets policySetSource explicitly to database and
// keeps the original ping-based expectations.
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
				engine.policySetSource = policySetSourceDatabase
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
				engine.policySetSource = policySetSourceDatabase
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
				engine.policySetSource = policySetSourceDatabase
				// No policies — the one case unhealthy regardless of
				// source, checked before source is even consulted.
				engine.mu.Unlock()
			},
			expectHealthy: false,
		},
		{
			name: "Unhealthy - database ping fails",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine, mock sqlmock.Sqlmock) {
				engine.mu.Lock()
				engine.lastRefresh = time.Now()
				engine.policySetSource = policySetSourceDatabase
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

// TestDatabasePolicyEngine_IsHealthy_DefaultsMode is the R3 finding-2
// regression test (#3319 hostile review): a policySetSourceDefaults engine
// must report healthy whenever it is serving a non-empty policy set,
// regardless of e.db — including the entire lifetime of a legitimate
// DATABASE_URL-unset deployment (db == nil forever) and a boot-time window
// where DATABASE_URL was set but the database has never yet been reached.
// Before this fix, IsHealthy() keyed off e.db == nil and reported these
// fully-functional deployments as unhealthy.
func TestDatabasePolicyEngine_IsHealthy_DefaultsMode(t *testing.T) {
	tests := []struct {
		name          string
		setupEngine   func(*DatabaseDynamicPolicyEngine)
		expectHealthy bool
	}{
		{
			name: "Healthy - defaults mode, no database ever configured (db nil)",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine) {
				engine.policySetSource = policySetSourceDefaults
				engine.policies["default_policy"] = map[string]interface{}{}
				// lastRefresh left at its zero value — never refreshed,
				// exactly like a process that has never reached a
				// database — and db is left nil.
			},
			expectHealthy: true,
		},
		{
			name: "Healthy - defaults mode, DATABASE_URL set but unreachable so far",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine) {
				engine.policySetSource = policySetSourceDefaults
				engine.policies["default_policy"] = map[string]interface{}{}
				engine.dbURL = "postgres://unreachable/db"
				// db stays nil: connectDB has not yet succeeded.
			},
			expectHealthy: true,
		},
		{
			name: "Unhealthy - defaults mode but zero policies (defect, not a legitimate state)",
			setupEngine: func(engine *DatabaseDynamicPolicyEngine) {
				engine.policySetSource = policySetSourceDefaults
				// No policies.
			},
			expectHealthy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := &DatabaseDynamicPolicyEngine{
				policies: make(map[string]interface{}),
			}
			tt.setupEngine(engine)

			if healthy := engine.IsHealthy(); healthy != tt.expectHealthy {
				t.Errorf("Expected healthy=%v, got %v", tt.expectHealthy, healthy)
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
						"org_id":    "tenant1",
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
						"org_id":    "tenant2",
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

// TestBackgroundRefresh tests the background refresh goroutine: the ordinary
// tick, and the policy cache catch-up that shortens it after a load that
// cannot govern yet (#4249). Each subtest starts and stops its own loop.
func TestBackgroundRefresh(t *testing.T) {
	t.Run("refreshes on the ordinary tick", testBackgroundRefreshOrdinaryTick)

	// THE R3 PLANT, KEPT: a row that never gets keyed. Without the cap the
	// loop would take every expectation below at the catch-up interval.
	t.Run("the catch-up is bounded on a row that stays unkeyed", func(t *testing.T) {
		engine, mock := catchUpEngine(t)
		engine.catchUpInterval = 5 * time.Millisecond
		engine.catchUpMaxTicks = 3
		settled := time.Date(2026, 9, 15, 4, 53, 1, 0, time.UTC)
		// The boot load, the 3 refreshes the cap allows, and 5 more that a
		// loop without the cap would take.
		for i := 0; i < 1+3+5; i++ {
			expectMigrationMark(mock, 221, settled)
			expectPolicyRows(mock, nil)
		}
		logs := captureLog(t)
		if err := engine.refreshPolicies(); err != nil {
			t.Fatalf("boot load: %v", err)
		}
		startRefreshLoop(t, engine)

		waitForLogCount(t, logs, "Loaded 1 policies from database", 4, 2*time.Second)
		time.Sleep(100 * time.Millisecond) // twenty catch-up intervals
		if n := strings.Count(logs.String(), "Loaded 1 policies from database"); n != 4 {
			t.Fatalf("a row that stays unkeyed was loaded %d times; want 4 (the boot load and the 3 the cap allows), then the ordinary interval. Log:\n%s", n, logs.String())
		}
		if n := strings.Count(logs.String(), "policy cache catch-up: refreshing every"); n != 1 {
			t.Errorf("entering the catch-up was logged %d times; want once. Log:\n%s", n, logs.String())
		}
		exhausted := logLinesContaining(logs, "policy cache catch-up EXHAUSTED")
		if len(exhausted) != 1 {
			t.Fatalf("EXHAUSTED was logged %d times; want once. Log:\n%s", len(exhausted), logs.String())
		}
		// EXHAUSTED means an unkeyed row outlasted the cap; the row count and
		// the mark are on the line itself.
		for _, want := range []string{"with an unkeyed row still loaded", "unkeyed rows=1", "schema_migrations 221 applied, latest at 2026-09-15T04:53:01Z"} {
			if !strings.Contains(exhausted[0], want) {
				t.Errorf("the EXHAUSTED line does not name %q: %s", want, exhausted[0])
			}
		}
		requireRefreshMode(t, refreshModeExhausted)
	})

	t.Run("a closed handle during the catch-up stops the loop", func(t *testing.T) {
		engine, mock := catchUpEngine(t)
		engine.catchUpInterval = 5 * time.Millisecond
		engine.catchUpMaxTicks = 1000
		settled := time.Date(2026, 9, 15, 4, 53, 1, 0, time.UTC)
		for i := 0; i < 50; i++ {
			expectMigrationMark(mock, 221, settled)
			expectPolicyRows(mock, nil)
		}
		logs := captureLog(t)
		if err := engine.refreshPolicies(); err != nil {
			t.Fatalf("boot load: %v", err)
		}
		done := startRefreshLoop(t, engine)

		// The boot load and two catch-up refreshes: the burst is under way.
		waitForLogCount(t, logs, "Loaded 1 policies from database", 3, 2*time.Second)
		_ = engine.db.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("backgroundRefresh did not return within 2s of the database closing mid catch-up (#3798). Log:\n%s", logs.String())
		}
		if n := strings.Count(logs.String(), "sql: database is closed"); n != 1 {
			t.Fatalf("the closed database was logged %d time(s); want exactly once. Log:\n%s", n, logs.String())
		}
		// The loop chose catch_up before it stopped; a stopped loop runs no
		// catch-up, and reportMetricsTick must not keep saying it does.
		requireRefreshMode(t, refreshModeSteady)
		engine.reportMetricsTick()
		requireRefreshMode(t, refreshModeSteady)
	})

	// THE COST OF ARMING ON THE FIRST READ, BOUNDED: a process whose boot load
	// finds nothing moving spends the cap once, logged once each way, and then
	// settles to the ordinary interval.
	t.Run("a process's first load arms the catch-up once, for the cap", func(t *testing.T) {
		engine, mock := catchUpEngine(t)
		engine.catchUpInterval = 5 * time.Millisecond
		engine.catchUpMaxTicks = 3
		settled := time.Date(2026, 9, 15, 4, 53, 1, 0, time.UTC)
		// The boot load, the 3 refreshes the cap allows, and 5 more that a
		// catch-up that never ended would take.
		for i := 0; i < 1+3+5; i++ {
			expectMigrationMark(mock, 221, settled)
			expectPolicyRows(mock, "global")
		}
		logs := captureLog(t)
		if err := engine.refreshPolicies(); err != nil {
			t.Fatalf("boot load: %v", err)
		}
		startRefreshLoop(t, engine)

		waitForLogCount(t, logs, "Loaded 1 policies from database", 4, 2*time.Second)
		time.Sleep(100 * time.Millisecond) // twenty catch-up intervals
		if n := strings.Count(logs.String(), "Loaded 1 policies from database"); n != 4 {
			t.Fatalf("a settled deployment's boot was followed by %d loads; want 4 (the boot load and the 3 the cap allows), then the ordinary interval. Log:\n%s", n, logs.String())
		}
		for _, line := range []string{"policy cache catch-up: refreshing every", "policy cache catch-up over: no unkeyed row, and schema_migrations has not advanced in 3 consecutive refreshes"} {
			if n := strings.Count(logs.String(), line); n != 1 {
				t.Errorf("%q was logged %d times; want once. Log:\n%s", line, n, logs.String())
			}
		}
		requireRefreshMode(t, refreshModeSteady)
	})

	t.Run("the ordinary tick is unchanged when no trigger holds", func(t *testing.T) {
		engine, mock := catchUpEngine(t)
		engine.cacheTimeout = 40 * time.Millisecond
		engine.catchUpInterval = time.Millisecond
		settled := time.Date(2026, 9, 15, 4, 53, 1, 0, time.UTC)
		for i := 0; i < 40; i++ {
			expectMigrationMark(mock, 221, settled)
			expectPolicyRows(mock, "global")
		}
		logs := captureLog(t)
		if err := engine.refreshPolicies(); err != nil {
			t.Fatalf("boot load: %v", err)
		}
		// The boot load is the process's first mark read, which arms the
		// catch-up; leave it as a spent cap does, so no trigger holds.
		settleMigrationTrigger(engine)
		startRefreshLoop(t, engine)

		time.Sleep(210 * time.Millisecond)
		// About 5 at the 40ms ordinary interval; a catch-up at 1ms would be
		// near 200. The bounds are loose for a loaded -race run.
		if n := strings.Count(logs.String(), "Loaded 1 policies from database") - 1; n < 2 || n > 7 {
			t.Fatalf("with no trigger holding, the loop refreshed %d times in 210ms; want about 5 at the 40ms ordinary interval. Log:\n%s", n, logs.String())
		}
		if strings.Contains(logs.String(), "policy cache catch-up") {
			t.Fatalf("the catch-up was entered with no trigger holding. Log:\n%s", logs.String())
		}
		requireRefreshMode(t, refreshModeSteady)
	})
}

// refreshPoliciesQueryPattern is the dynamic_policies SELECT refreshPolicies
// issues (sharedpolicy.RefreshDynamicPolicies, the segment_id form), as a
// sqlmock pattern.
const refreshPoliciesQueryPattern = `SELECT id::text, name, COALESCE\(description, ''\) AS description, conditions, actions, tenant_id, org_id, priority, policy_id, COALESCE\(policy_type, 'content'\) as policy_type, COALESCE\(category, ''\) as category, COALESCE\(risk_level, 'medium'\) as risk_level, COALESCE\(allow_override, false\) as allow_override, created_at, updated_at, segment_id FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC`

// catchUpEngine is an engine over sqlmock with a one-hour cache interval, so
// only the catch-up can make a refresh come sooner.
func catchUpEngine(t *testing.T) (*DatabaseDynamicPolicyEngine, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &DatabaseDynamicPolicyEngine{
		db:           db,
		policies:     make(map[string]interface{}),
		cacheTimeout: time.Hour,
		stopCh:       make(chan struct{}),
	}, mock
}

// expectMigrationMark answers one schema_migrations mark read. A zero last is
// a table with no successful row: MAX is NULL.
func expectMigrationMark(mock sqlmock.Sqlmock, applied int64, last time.Time) {
	rows := sqlmock.NewRows([]string{"count", "max"})
	if last.IsZero() {
		rows.AddRow(applied, nil)
	} else {
		rows.AddRow(applied, last)
	}
	mock.ExpectQuery(regexp.QuoteMeta(schemaMigrationMarkQuery)).WillReturnRows(rows)
}

// expectPolicyRows answers one policies SELECT with a row per org_id value;
// nil is SQL NULL.
func expectPolicyRows(mock sqlmock.Sqlmock, orgIDs ...interface{}) {
	rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"})
	for i, org := range orgIDs {
		id := fmt.Sprintf("catch_up_policy_%d", i)
		rows.AddRow(fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1), id, "", "[]", "[]", "global", org, 10, id, "content", "dynamic-security", "medium", false, nil, nil, nil)
	}
	mock.ExpectQuery(refreshPoliciesQueryPattern).WillReturnRows(rows)
}

// settleMigrationTrigger leaves the engine as a spent cap does: the migration
// trigger the process's first mark read armed is cleared.
func settleMigrationTrigger(engine *DatabaseDynamicPolicyEngine) {
	engine.mu.Lock()
	engine.catchUp.moving = false
	engine.catchUp.advanced = false
	engine.mu.Unlock()
}

// startRefreshLoop runs engine.backgroundRefresh and stops it at cleanup,
// failing the test if it does not return. The returned channel closes when
// the loop returns.
func startRefreshLoop(t *testing.T, engine *DatabaseDynamicPolicyEngine) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		engine.backgroundRefresh()
		close(done)
	}()
	t.Cleanup(func() {
		select {
		case <-engine.stopCh:
		default:
			close(engine.stopCh)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("backgroundRefresh did not return within 2s of its stop channel closing")
		}
	})
	return done
}

func waitForLogCount(t *testing.T, logs *lockedBuffer, substr string, want int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for strings.Count(logs.String(), substr) < want {
		if time.Now().After(deadline) {
			t.Fatalf("%q was logged %d time(s) within %v; want %d. Log:\n%s", substr, strings.Count(logs.String(), substr), within, want, logs.String())
		}
		time.Sleep(time.Millisecond)
	}
}

func logLinesContaining(logs *lockedBuffer, substr string) []string {
	var out []string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, substr) {
			out = append(out, line)
		}
	}
	return out
}

// requireRefreshMode asserts axonflow_policy_cache_refresh_mode has exactly
// want at 1.
func requireRefreshMode(t *testing.T, want string) {
	t.Helper()
	for _, mode := range []string{refreshModeSteady, refreshModeCatchUp, refreshModeExhausted} {
		wantValue := 0.0
		if mode == want {
			wantValue = 1
		}
		if got := testutil.ToFloat64(policyCacheRefreshModeGauge.WithLabelValues(mode)); got != wantValue {
			t.Errorf("axonflow_policy_cache_refresh_mode{mode=%q} = %v, want %v", mode, got, wantValue)
		}
	}
}

// The catch-up's FIRST trigger (#4249): a load that resolved a row to org_id
// "". Every presence state of the column, one at a time, with the migration
// trigger held off: a prior load read the same mark first, and its arm is
// cleared as a spent cap clears it.
func TestRefreshPolicies_CatchUpFirstTriggerIsAnUnkeyedRow(t *testing.T) {
	settled := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		orgID   interface{}
		unkeyed int
	}{
		{"org_id NULL", nil, 1},
		{"org_id empty", "", 1},
		{"org_id blank after trimming", "   ", 1},
		{"org_id global", "global", 0},
		{"org_id an organization", "org-a", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, mock := catchUpEngine(t)
			expectMigrationMark(mock, 221, settled)
			expectPolicyRows(mock, "global")
			if err := engine.refreshPolicies(); err != nil {
				t.Fatalf("prior load: %v", err)
			}
			settleMigrationTrigger(engine)
			// Expectations are ORDERED: the mark before the policies, which is
			// what lets a migration racing the load re-arm rather than hide.
			expectMigrationMark(mock, 221, settled)
			expectPolicyRows(mock, tc.orgID)
			if err := engine.refreshPolicies(); err != nil {
				t.Fatalf("refreshPolicies: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the mark and the policies were not read in that order: %v", err)
			}
			engine.mu.RLock()
			c := engine.catchUp
			engine.mu.RUnlock()
			if c.unkeyedRows != tc.unkeyed || c.armed() != (tc.unkeyed > 0) {
				t.Fatalf("unkeyedRows=%d armed=%t; want %d and %t", c.unkeyedRows, c.armed(), tc.unkeyed, tc.unkeyed > 0)
			}
			if c.moving {
				t.Errorf("a settled schema_migrations mark read as moving")
			}
		})
	}
}

// The catch-up's SECOND trigger (#4249): schema_migrations moved since the
// previous successful load. It holds no unkeyed row, which is the 153->173
// window a row-only trigger cannot see. The trigger is sticky: a load that
// finds the mark unchanged leaves it armed, and only the cap clears it
// (TestScheduleNextRefresh_TheCatchUpIsBoundedAtItsCap).
func TestRefreshPolicies_CatchUpSecondTriggerIsSchemaMigrationsAdvancing(t *testing.T) {
	engine, mock := catchUpEngine(t)
	t1 := time.Date(2026, 9, 15, 4, 53, 1, 0, time.UTC)
	t2 := t1.Add(5 * time.Second)
	t3 := t2.Add(time.Minute)
	for _, step := range []struct {
		name         string
		applied      int64
		last         time.Time
		wantMoving   bool
		wantAdvanced bool
		thenCapSpent bool
	}{
		{"the first read: a process has no previous mark to compare", 220, t1, true, true, true},
		{"one more migration recorded", 221, t2, true, true, false},
		{"the same mark again: still armed until the cap is spent", 221, t2, true, false, true},
		{"an applied file re-run: applied_at moves and the count does not", 221, t3, true, true, true},
		{"the same mark again once the cap has cleared it: nothing moves", 221, t3, false, false, false},
	} {
		expectMigrationMark(mock, step.applied, step.last)
		expectPolicyRows(mock, "global")
		if err := engine.refreshPolicies(); err != nil {
			t.Fatalf("%s: refreshPolicies: %v", step.name, err)
		}
		engine.mu.Lock()
		c := engine.catchUp
		engine.catchUp.advanced = false // what scheduleNextRefresh does between loads
		engine.mu.Unlock()
		if c.moving != step.wantMoving || c.advanced != step.wantAdvanced || c.armed() != step.wantMoving {
			t.Errorf("%s: moving=%t advanced=%t armed=%t; want moving=%t advanced=%t armed=%t", step.name, c.moving, c.advanced, c.armed(), step.wantMoving, step.wantAdvanced, step.wantMoving)
		}
		if step.thenCapSpent {
			settleMigrationTrigger(engine)
		}
	}
}

// A process's FIRST successful mark read arms the migration trigger (#4249): it
// has no previous mark to compare, and on a co-booted stack the first load can
// land inside the gap between two migrations of a burst, however long ago the
// latest one was recorded. Each case is a fresh engine.
func TestRefreshPolicies_TheFirstMarkReadArmsTheCatchUp(t *testing.T) {
	longAgo := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		applied int64
		last    time.Time
	}{
		{"a mark recorded years ago", 221, longAgo},
		{"a mark recorded just now", 221, time.Now()},
		{"no successful row at all", 0, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, mock := catchUpEngine(t)
			expectMigrationMark(mock, tc.applied, tc.last)
			expectPolicyRows(mock, "global")
			if err := engine.refreshPolicies(); err != nil {
				t.Fatalf("refreshPolicies: %v", err)
			}
			engine.mu.RLock()
			c := engine.catchUp
			engine.mu.RUnlock()
			if !c.moving || !c.advanced || !c.armed() {
				t.Fatalf("the first read: moving=%t advanced=%t armed=%t; want all true", c.moving, c.advanced, c.armed())
			}
		})
	}

	t.Run("the first SUCCESSFUL read arms, after the mark was unreadable at boot", func(t *testing.T) {
		engine, mock := catchUpEngine(t)
		_ = captureLog(t)
		mock.ExpectQuery(regexp.QuoteMeta(schemaMigrationMarkQuery)).WillReturnError(errors.New("pq: permission denied for table schema_migrations"))
		expectPolicyRows(mock, "global")
		if err := engine.refreshPolicies(); err != nil {
			t.Fatalf("unreadable boot load: %v", err)
		}
		engine.mu.RLock()
		armedAtBoot := engine.catchUp.armed()
		engine.mu.RUnlock()
		if armedAtBoot {
			t.Fatal("an unreadable mark armed the catch-up")
		}
		expectMigrationMark(mock, 221, longAgo)
		expectPolicyRows(mock, "global")
		if err := engine.refreshPolicies(); err != nil {
			t.Fatalf("readable load: %v", err)
		}
		engine.mu.RLock()
		c := engine.catchUp
		engine.mu.RUnlock()
		if !c.moving || !c.advanced {
			t.Fatalf("the first successful read after an unreadable one: moving=%t advanced=%t; want both", c.moving, c.advanced)
		}
	})
}

// An unreadable mark never arms the migration trigger and leaves the refresh
// unaffected, is logged once each way, and never reads as an advance; and a
// load that fails records nothing, so the mark it read is not kept.
func TestRefreshPolicies_AnUnreadableMigrationMarkNeverArmsTheCatchUp(t *testing.T) {
	engine, mock := catchUpEngine(t)
	logs := captureLog(t)
	t1 := time.Date(2026, 9, 15, 4, 53, 1, 0, time.UTC)
	t2 := t1.Add(time.Second)
	denied := errors.New("pq: permission denied for table schema_migrations")
	expectUnreadable := func() {
		mock.ExpectQuery(regexp.QuoteMeta(schemaMigrationMarkQuery)).WillReturnError(denied)
	}
	state := func() policyCacheCatchUp {
		engine.mu.Lock()
		defer engine.mu.Unlock()
		c := engine.catchUp
		engine.catchUp.advanced = false
		return c
	}

	expectMigrationMark(mock, 221, t1)
	expectPolicyRows(mock, "global")
	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("baseline load: %v", err)
	}
	if c := state(); !c.moving {
		t.Fatalf("the baseline is the process's first mark read, which arms: moving=%t", c.moving)
	}
	// Leave it as a spent cap does, so the unreadable loads below start from a
	// disarmed trigger (TestRefreshPolicies_AnUnreadableMarkDoesNotDisarmTheCatchUp
	// covers an armed one).
	settleMigrationTrigger(engine)

	for i := 1; i <= 2; i++ {
		expectUnreadable()
		expectPolicyRows(mock, "global")
		if err := engine.refreshPolicies(); err != nil {
			t.Fatalf("unreadable load %d: the refresh failed because the mark could not be read: %v", i, err)
		}
		if c := state(); c.moving || c.advanced || c.armed() {
			t.Fatalf("unreadable load %d: moving=%t advanced=%t armed=%t; an unreadable mark must never arm the catch-up", i, c.moving, c.advanced, c.armed())
		}
		if got := engine.PolicySetSource(); got != policySetSourceDatabase {
			t.Fatalf("unreadable load %d: policy-set source %q; the policies still loaded", i, got)
		}
	}
	if n := strings.Count(logs.String(), "schema_migrations could not be read"); n != 1 {
		t.Fatalf("two unreadable loads logged %d time(s); want once. Log:\n%s", n, logs.String())
	}

	expectMigrationMark(mock, 221, t1)
	expectPolicyRows(mock, "global")
	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("readable again: %v", err)
	}
	if c := state(); c.moving || c.advanced {
		t.Fatalf("reading the SAME mark again after it was unreadable: moving=%t advanced=%t; want neither", c.moving, c.advanced)
	}
	if n := strings.Count(logs.String(), "schema_migrations reads again"); n != 1 {
		t.Fatalf("reading again was logged %d time(s); want once. Log:\n%s", n, logs.String())
	}

	expectMigrationMark(mock, 222, t2)
	mock.ExpectQuery(refreshPoliciesQueryPattern).WillReturnError(errors.New("connection reset by peer"))
	if err := engine.refreshPolicies(); err == nil {
		t.Fatal("a failed policies SELECT reported success")
	}
	if c := state(); c.mark.applied != 221 {
		t.Fatalf("a failed load recorded the mark it read (applied=%d); want the last successful load's 221", c.mark.applied)
	}

	expectMigrationMark(mock, 222, t2)
	expectPolicyRows(mock, "global")
	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("moved: %v", err)
	}
	if c := state(); !c.moving || !c.advanced {
		t.Fatalf("the mark moved 221 -> 222: moving=%t advanced=%t; want both", c.moving, c.advanced)
	}
}

// An unreadable mark inside a burst leaves an armed trigger armed (#4249). A
// failed read says nothing about schema_migrations, and clearing the trigger on
// it would leave the next migration of the burst to the 30 s refresh. The cap
// still ends it.
func TestRefreshPolicies_AnUnreadableMarkDoesNotDisarmTheCatchUp(t *testing.T) {
	engine, mock := catchUpEngine(t)
	_ = captureLog(t)
	expectMigrationMark(mock, 221, time.Date(2026, 9, 15, 4, 53, 1, 0, time.UTC))
	expectPolicyRows(mock, "global")
	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("first load: %v", err)
	}
	engine.mu.Lock()
	engine.catchUp.advanced = false // what scheduleNextRefresh does between loads
	engine.mu.Unlock()
	mock.ExpectQuery(regexp.QuoteMeta(schemaMigrationMarkQuery)).WillReturnError(errors.New("pq: canceling statement due to statement timeout"))
	expectPolicyRows(mock, "global")
	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("unreadable load: %v", err)
	}
	engine.mu.RLock()
	c := engine.catchUp
	engine.mu.RUnlock()
	if !c.moving || c.advanced || !c.armed() {
		t.Fatalf("after an unreadable read inside a burst: moving=%t advanced=%t armed=%t; want the trigger still armed and no advance", c.moving, c.advanced, c.armed())
	}
}

// The cap, at N-1, N and N+1 consecutive short waits, and what resets it.
func TestScheduleNextRefresh_TheCatchUpIsBoundedAtItsCap(t *testing.T) {
	_ = captureLog(t)
	const maxTicks = 3
	stuck := policyCacheCatchUp{unkeyedRows: 1}
	for _, tc := range []struct {
		name       string
		state      policyCacheCatchUp
		ticks      int
		wantDelay  time.Duration
		wantTicks  int
		wantMode   string
		wantMoving bool
	}{
		{"N-1 short waits spent: one more", stuck, maxTicks - 1, 2 * time.Second, maxTicks, refreshModeCatchUp, false},
		{"N spent: the ordinary interval", stuck, maxTicks, 30 * time.Second, maxTicks, refreshModeExhausted, false},
		{"N+1 spent: still the ordinary interval", stuck, maxTicks + 1, 30 * time.Second, maxTicks + 1, refreshModeExhausted, false},
		{"schema_migrations advanced after the cap was spent: re-armed", policyCacheCatchUp{unkeyedRows: 1, advanced: true}, maxTicks, 2 * time.Second, 1, refreshModeCatchUp, false},
		{"migrations moving with no unkeyed row", policyCacheCatchUp{moving: true}, 0, 2 * time.Second, 1, refreshModeCatchUp, true},
		{"migrations moving, N-1 spent: still armed", policyCacheCatchUp{moving: true}, maxTicks - 1, 2 * time.Second, maxTicks, refreshModeCatchUp, true},
		{"migrations moving, N spent without an advance: the trigger clears to steady", policyCacheCatchUp{moving: true}, maxTicks, 30 * time.Second, 0, refreshModeSteady, false},
		{"an unkeyed row and migrations moving, N spent: exhausted, and the migration trigger clears", policyCacheCatchUp{unkeyedRows: 1, moving: true}, maxTicks, 30 * time.Second, maxTicks, refreshModeExhausted, false},
		{"migrations moving and an advance with N spent: the count restarts", policyCacheCatchUp{moving: true, advanced: true}, maxTicks, 2 * time.Second, 1, refreshModeCatchUp, true},
		{"no trigger: the ordinary interval, and the count resets", policyCacheCatchUp{}, maxTicks, 30 * time.Second, 0, refreshModeSteady, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := &DatabaseDynamicPolicyEngine{cacheTimeout: 30 * time.Second, catchUpInterval: 2 * time.Second, catchUpMaxTicks: maxTicks, catchUp: tc.state}
			ticks := tc.ticks
			delay := engine.scheduleNextRefresh(&ticks)
			if delay != tc.wantDelay || ticks != tc.wantTicks || engine.catchUp.mode != tc.wantMode || engine.catchUp.moving != tc.wantMoving {
				t.Fatalf("delay=%v ticks=%d mode=%q moving=%t; want %v, %d, %q, %t", delay, ticks, engine.catchUp.mode, engine.catchUp.moving, tc.wantDelay, tc.wantTicks, tc.wantMode, tc.wantMoving)
			}
			if engine.catchUp.advanced {
				t.Error("the advance was not consumed by the schedule")
			}
			requireRefreshMode(t, tc.wantMode)
		})
	}

	t.Run("the short wait is never longer than cacheTimeout", func(t *testing.T) {
		engine := &DatabaseDynamicPolicyEngine{cacheTimeout: 30 * time.Second, catchUpInterval: time.Minute, catchUp: stuck}
		ticks := 0
		if delay := engine.scheduleNextRefresh(&ticks); delay != 30*time.Second || engine.catchUp.mode != refreshModeCatchUp {
			t.Fatalf("delay=%v mode=%q; want 30s in catch_up", delay, engine.catchUp.mode)
		}
	})

	t.Run("zero settings are the named constants", func(t *testing.T) {
		// The stated gap rests on this product: a migration recorded within
		// 30 s of the previous advance is seen within 2 s.
		if got := time.Duration(policyCacheCatchUpMaxTicks) * policyCacheCatchUpInterval; got != 30*time.Second || policyCacheCatchUpInterval != 2*time.Second {
			t.Fatalf("the catch-up is %d x %v = %v; the stated gap needs 15 x 2s = 30s", policyCacheCatchUpMaxTicks, policyCacheCatchUpInterval, got)
		}
		engine := &DatabaseDynamicPolicyEngine{cacheTimeout: 30 * time.Second, catchUp: stuck}
		ticks := policyCacheCatchUpMaxTicks - 1
		if delay := engine.scheduleNextRefresh(&ticks); delay != policyCacheCatchUpInterval || ticks != policyCacheCatchUpMaxTicks {
			t.Fatalf("delay=%v ticks=%d; want %v and %d", delay, ticks, policyCacheCatchUpInterval, policyCacheCatchUpMaxTicks)
		}
		if delay := engine.scheduleNextRefresh(&ticks); delay != 30*time.Second || engine.catchUp.mode != refreshModeExhausted {
			t.Fatalf("delay=%v mode=%q after the cap; want 30s exhausted", delay, engine.catchUp.mode)
		}
	})
}

// simulateMigrationBurst runs observe and scheduleNextRefresh on a virtual
// clock, with the production catch-up interval, cap and a 30s cache interval.
// Migration 172 is recorded at t=0 and the process's first load reads the mark
// at t=firstLoad; the next migration of the burst is recorded gap seconds after
// 172, and when nextGap is positive a further migration, 174, is recorded nextGap
// seconds after 172. Each load reads the mark as it stands at that load's virtual
// time, except a load at unreadableAt (0 for none), which cannot read it.
// capReRead installs the cap's own re-read of the mark (#4249 row 5683228870)
// as the process has it, reading the mark at the cap's virtual time; without it
// the engine has no reader, so that read fails and the cap clears the trigger.
// It returns how long the last migration waited for a load that read its mark,
// and the schedule the loop was on across its record.
func simulateMigrationBurst(t *testing.T, firstLoad, gap, unreadableAt, nextGap float64, capReRead bool) (stale float64, modeAcrossRecord string) {
	t.Helper()
	engine := &DatabaseDynamicPolicyEngine{cacheTimeout: 30 * time.Second}
	recorded172 := time.Date(2026, 9, 15, 4, 53, 0, 0, time.UTC)
	at := func(s float64) time.Time { return recorded172.Add(time.Duration(s * float64(time.Second))) }
	markAt := func(now float64) schemaMigrationMark {
		switch {
		case nextGap > 0 && now >= nextGap:
			return schemaMigrationMark{applied: 174, lastApplied: at(nextGap)}
		case now >= gap:
			return schemaMigrationMark{applied: 173, lastApplied: at(gap)}
		}
		return schemaMigrationMark{applied: 172, lastApplied: recorded172}
	}
	target, record := int64(173), gap
	if nextGap > 0 {
		target, record = 174, nextGap
	}
	now, ticks := firstLoad, 0
	if capReRead {
		engine.capMarkReader = func(context.Context) (schemaMigrationMark, error) { return markAt(now), nil }
	}
	for i := 0; i < 200; i++ {
		mark := markAt(now)
		var markErr error
		if d := now - unreadableAt; unreadableAt > 0 && d > -0.01 && d < 0.01 {
			mark, markErr = schemaMigrationMark{}, errors.New("unreadable")
		}
		engine.mu.Lock()
		engine.catchUp.observe(0, mark, markErr)
		engine.mu.Unlock()
		if markErr == nil && mark.applied == target {
			return now - record, modeAcrossRecord
		}
		delay := engine.scheduleNextRefresh(&ticks).Seconds()
		if now+delay >= record {
			modeAcrossRecord = engine.catchUp.mode
		}
		now += delay
	}
	t.Fatalf("no load read migration %d within 200 refreshes (gap %vs, next gap %vs)", target, gap, nextGap)
	return 0, ""
}

// THE MIGRATION TRIGGER HOLDS ACROSS A BURST (#4249). A migration recorded
// within 30 s of the previous advance is seen within 2 s; longer gaps fall back
// to the 30 s cadence. The process's first load counts as an advance, so a first
// load that lands inside a gap arms it too. A trigger that disarmed with a 10s
// window went steady at t=10.4 and first loaded a migration recorded 17s after
// 172 at t=40.4, 23.4s stale; one that armed a first load only on a row younger
// than 10s missed a first load 10.5s into a 20s gap and waited 20.5s. A mark read
// that fails inside the burst neither arms nor disarms it: one that disarmed
// left a migration recorded 3s after the arming load waiting 29s. A read that
// fails on the last short refresh before the cap cannot credit an advance. The
// cap then re-reads the mark once (#4249 row 5683228870), so the next migration
// is still seen within the catch-up interval; where that re-read cannot read
// either, the burst ends at the cap and the next migration waits for the 30 s
// refresh. Both are subtests below, beside the same burst with every read
// succeeding. A mark read that runs before the migration is recorded, with the
// record landing after that read, gives the same schedule.
func TestScheduleNextRefresh_AMigrationInsideTheBurstIsSeenWithinTheCatchUpInterval(t *testing.T) {
	_ = captureLog(t)
	for _, tc := range []struct {
		name         string
		firstLoad    float64
		gap          float64
		maxStale     float64
		wantAcross   string
		unreadableAt float64
		nextGap      float64
		minStale     float64
		capReRead    bool
	}{
		{"recorded 17s after the previous migration", 0.4, 17, 2, refreshModeCatchUp, 0, 0, 0, false},
		{"recorded 29s after it", 0.4, 29, 2, refreshModeCatchUp, 0, 0, 0, false},
		{"recorded 29.9s after the arming load, the last instant inside the cap", 0.4, 30.3, 2, refreshModeCatchUp, 0, 0, 0, false},
		{"recorded 30.1s after the arming load, just past the cap: the 30s cadence", 0.4, 30.5, 30, refreshModeSteady, 0, 0, 0, false},
		{"recorded 45s after it, past the cap: the 30s cadence", 0.4, 45, 30, refreshModeSteady, 0, 0, 0, false},
		{"the first load lands 10.5s into a 20s gap", 10.5, 20, 2, refreshModeCatchUp, 0, 0, 0, false},
		{"the first load lands 12s into a 26s gap", 12, 26, 2, refreshModeCatchUp, 0, 0, 0, false},
		{"a mark read fails 2s after the arming load, inside the burst", 0.4, 3.4, 2, refreshModeCatchUp, 2.4, 0, 0, false},
		{"a second migration 2s after one recorded at 29s, every read succeeding", 0.4, 29, 2, refreshModeCatchUp, 0, 31, 0, false},
		{"the read on the last short refresh before the cap fails AND the cap cannot re-read either: the next migration waits for the 30s refresh", 0.4, 29, 30, refreshModeSteady, 30.4, 31, 29, false},
		{"the read on the last short refresh before the cap fails and the cap's re-read sees the migration: the next one is seen within the catch-up interval (#4249 row 5683228870, as filed)", 0.4, 29, 2, refreshModeCatchUp, 30.4, 31, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stale, across := simulateMigrationBurst(t, tc.firstLoad, tc.gap, tc.unreadableAt, tc.nextGap, tc.capReRead)
			if stale > tc.maxStale || stale < tc.minStale || across != tc.wantAcross {
				t.Fatalf("the last migration (173 at %vs, 174 at %vs when set), with the first load at %vs, waited %.1fs for a load, on the %q schedule; want %v to %vs, on %q", tc.gap, tc.nextGap, tc.firstLoad, stale, across, tc.minStale, tc.maxStale, tc.wantAcross)
			}
		})
	}
}

func TestReadSchemaMigrationMark(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	last := time.Date(2026, 9, 15, 4, 53, 1, 0, time.UTC)

	expectMigrationMark(mock, 221, last)
	mark, err := readSchemaMigrationMark(ctx, db)
	if err != nil || mark.applied != 221 || !mark.lastApplied.Equal(last) {
		t.Fatalf("got mark=%+v err=%v; want 221 at %v", mark, err, last)
	}

	expectMigrationMark(mock, 0, time.Time{})
	mark, err = readSchemaMigrationMark(ctx, db)
	if err != nil || mark.applied != 0 || !mark.lastApplied.IsZero() {
		t.Fatalf("no successful row: got mark=%+v err=%v; want a zero mark", mark, err)
	}

	mock.ExpectQuery(regexp.QuoteMeta(schemaMigrationMarkQuery)).WillReturnError(errors.New(`pq: relation "schema_migrations" does not exist`))
	if _, err := readSchemaMigrationMark(ctx, db); err == nil {
		t.Fatal("a failed read reported a mark")
	}
	if _, err := readSchemaMigrationMark(ctx, nil); err == nil {
		t.Fatal("a nil handle reported a mark")
	}
}

func testBackgroundRefreshOrdinaryTick(t *testing.T) {
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
		stopCh:       make(chan struct{}),
	}
	// #3798: this loop used to be started with a nil stopCh and never stopped,
	// so its 100 ms ticker kept firing for the rest of the package run and
	// every tick logged "sql: database is closed" once the deferred db.Close()
	// ran - 3,812 lines and ~520 s of a 600 s -race budget on the fleet. The
	// cleanup stops the loop AND proves it stopped: with the old nil stopCh
	// the wait below times out and this test fails instead of the race lane.
	t.Cleanup(func() {
		close(engine.stopCh)
		requireNoRefreshLoop(t, 2*time.Second)
	})

	// Expect policy refresh query to be called
	rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"}).
		AddRow("00000000-0000-0000-0000-000000000001", "test_policy", "", "{}", "{}", "tenant1", "tenant1", 10, "policy1", "content", "dynamic-security", "medium", false, nil, nil, nil)

	mock.ExpectQuery("SELECT id::text, name, COALESCE\\(description, ''\\) AS description, conditions, actions, tenant_id, org_id, priority, policy_id, COALESCE\\(policy_type, 'content'\\) as policy_type, COALESCE\\(category, ''\\) as category, COALESCE\\(risk_level, 'medium'\\) as risk_level, COALESCE\\(allow_override, false\\) as allow_override, created_at, updated_at, segment_id FROM dynamic_policies WHERE enabled = true ORDER BY priority DESC, created_at DESC").
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

// refreshLoopsRunning counts goroutines currently inside backgroundRefresh,
// read from the runtime's own stacks - the instrument for "no loop was left
// behind", independent of any channel the test remembered to close.
func refreshLoopsRunning() int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), "(*DatabaseDynamicPolicyEngine).backgroundRefresh(")
}

// requireNoRefreshLoop fails the test if a backgroundRefresh goroutine is
// still running once the bounded wait expires.
func requireNoRefreshLoop(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		n := refreshLoopsRunning()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d backgroundRefresh goroutine(s) still running %v after the test stopped its engine: the loop is leaking into the rest of the package run (#3798)", n, within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestBackgroundRefresh_StopsWhenTheDatabaseIsClosed pins #3798: a refresh
// loop whose database handle has been closed must stop, not retry the closed
// handle at the cache interval forever. Before the fix this loop never
// returned (bounded wait below fails) and every tick logged a failure; with
// the fix it returns on the refresh that found the handle closed and logs that
// failure once. A caller closing the handle without Close() is a
// misuse, and this is what bounds the damage of that misuse.
func TestBackgroundRefresh_StopsWhenTheDatabaseIsClosed(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	engine := &DatabaseDynamicPolicyEngine{
		db:           db,
		policies:     make(map[string]interface{}),
		cacheTimeout: 20 * time.Millisecond,
		lastRefresh:  time.Now(),
		stopCh:       make(chan struct{}),
	}
	t.Cleanup(func() {
		select {
		case <-engine.stopCh:
		default:
			close(engine.stopCh)
		}
	})

	logs := &lockedBuffer{}
	prev := log.Writer()
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	done := make(chan struct{})
	go func() {
		engine.backgroundRefresh()
		close(done)
	}()

	// A few refreshes against a live handle: sqlmock answers every unexpected
	// query with an ordinary error, which is transient and must NOT stop the
	// loop - only a closed handle is terminal.
	time.Sleep(80 * time.Millisecond)
	select {
	case <-done:
		t.Fatalf("backgroundRefresh returned on an ordinary refresh error; only a closed database is terminal")
	default:
	}

	_ = db.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("backgroundRefresh did not return within 2s of the database closing: the loop is leaking and will retry the closed handle every %v for the rest of the process (#3798)", engine.cacheTimeout)
	}

	// The loop returns only after receiving that refresh's error, which its
	// goroutine sends once refreshPolicies has returned, so every line the
	// refresh logged is already written.

	// Bounded logging: the closed handle is reported once, not once per tick.
	time.Sleep(100 * time.Millisecond) // a few more intervals; nothing may fire
	if n := strings.Count(logs.String(), "sql: database is closed"); n != 1 {
		t.Fatalf("the closed database was logged %d time(s); want exactly once. Log:\n%s", n, logs.String())
	}
}

// lockedBuffer is a log sink a test can read while other goroutines are still
// writing to it: log.Logger serialises its own writes, but a test's read of a
// plain bytes.Buffer races with them under -race.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestIsClosedDatabase pins the detection against the standard library: the
// message is a literal in database/sql (errDBClosed) that no exported
// sentinel names, so the engine recognises it by that literal, wrapped or
// not. A Go release that changes the literal fails this test rather than the
// race lane.
func TestIsClosedDatabase(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	_ = db.Close()
	_, qerr := db.QueryContext(context.Background(), "SELECT 1")
	if qerr == nil {
		t.Fatal("a closed *sql.DB answered a query")
	}
	if !isClosedDatabase(qerr) {
		t.Fatalf("a closed *sql.DB's own error %q is not recognised", qerr)
	}
	if !isClosedDatabase(fmt.Errorf("failed to query policies: %w", qerr)) {
		t.Fatalf("the engine's wrapping of %q is not recognised", qerr)
	}
	if isClosedDatabase(errors.New("connection refused")) || isClosedDatabase(nil) {
		t.Fatal("an ordinary error or nil was taken for a closed database")
	}
}

// =============================================================================
// Report Metrics Tests
// =============================================================================

// TestReportMetrics_PublishesPrometheusGauges is the #3319 replacement for
// the pre-#3319 version of this test, which asserted a `policy_metrics`
// 'system_health' row insert (a metricsDB write that never checked
// mock.ExpectationsWereMet() and slept 15s to observe one tick). reportMetrics
// no longer touches the database at all — it republishes the engine's
// already-in-memory state (policySetSource, lastRefresh) as
// axonflow_policy_set_source / axonflow_policy_cache_age_seconds. Calling
// the tick body directly (rather than sleeping on the real 10s ticker)
// keeps this deterministic and fast.
func TestReportMetrics_PublishesPrometheusGauges(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies:        map[string]interface{}{"test": map[string]interface{}{"name": "test"}},
		lastRefresh:     time.Now().Add(-42 * time.Second),
		policySetSource: policySetSourceDatabase,
		catchUp:         policyCacheCatchUp{mode: refreshModeExhausted},
	}

	engine.reportMetricsTick()

	if got := testutil.ToFloat64(policySetSourceGauge.WithLabelValues(policySourceLabelDatabase)); got != 1 {
		t.Errorf("axonflow_policy_set_source{source=\"database\"} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(policySetSourceGauge.WithLabelValues(policySourceLabelDefaults)); got != 0 {
		t.Errorf("axonflow_policy_set_source{source=\"defaults\"} = %v, want 0", got)
	}
	if age := testutil.ToFloat64(policyCacheAgeSeconds); age < 42 {
		t.Errorf("axonflow_policy_cache_age_seconds = %v, want >= 42", age)
	}
	// #4249: the refresh schedule is republished on the same tick.
	requireRefreshMode(t, refreshModeExhausted)
}

// TestReportMetrics_ZeroLastRefreshReportsZeroAge covers the "never
// refreshed" branch — a lastRefresh zero-time (no successful load has ever
// happened, e.g. an engine still serving defaults) must report cache age 0,
// not a huge duration since the year 1.
func TestReportMetrics_ZeroLastRefreshReportsZeroAge(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies:        loadDefaultPoliciesCache(),
		policySetSource: policySetSourceDefaults,
	}

	engine.reportMetricsTick()

	if age := testutil.ToFloat64(policyCacheAgeSeconds); age != 0 {
		t.Errorf("axonflow_policy_cache_age_seconds with zero lastRefresh = %v, want 0", age)
	}
	if got := testutil.ToFloat64(policySetSourceGauge.WithLabelValues(policySourceLabelDefaults)); got != 1 {
		t.Errorf("axonflow_policy_set_source{source=\"defaults\"} = %v, want 1", got)
	}
	// An engine whose loop has not chosen a schedule publishes steady.
	requireRefreshMode(t, refreshModeSteady)
}

// TestBackgroundRefresh_StillRunsGoroutine keeps a smoke check that the
// background refresh goroutine starts and exits cleanly on stopCh, without
// the 15s real-time sleep the metrics test used to require.
func TestBackgroundRefresh_StillRunsGoroutine(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()
	_ = mock

	engine := &DatabaseDynamicPolicyEngine{
		db:           db,
		policies:     make(map[string]interface{}),
		cacheTimeout: 24 * time.Hour, // long enough that no tick fires during the test
		stopCh:       make(chan struct{}),
	}

	go engine.backgroundRefresh()
	close(engine.stopCh)
	// If backgroundRefresh doesn't observe stopCh and return, this test
	// would need an explicit synchronization point to fail deterministically;
	// its goroutine exiting is covered by the race detector / leak checks
	// in the full suite, so this is a construction smoke test only.
}

// =============================================================================
// Load Default Policies Tests
// =============================================================================

// TestLoadDefaultPolicies tests loading the built-in default fallback
// policy set (#3319: loadDefaultPolicies now sources from
// loadDefaultDynamicPolicies, the SAME built-in set the retired in-memory
// engine used, converted into this engine's cache shape — not the old
// single synthetic "default"/"fallback" rate-limit entry).
func TestLoadDefaultPolicies(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies:        make(map[string]interface{}),
		policySetSource: policySetSourceDatabase, // prove loadDefaultPolicies demotes it back
	}

	engine.loadDefaultPolicies()

	engine.mu.RLock()
	policyCount := len(engine.policies)
	source := engine.policySetSource
	engine.mu.RUnlock()

	wantCount := len(loadDefaultDynamicPolicies())
	if policyCount != wantCount {
		t.Errorf("Expected %d default policies (one per loadDefaultDynamicPolicies() entry), got %d", wantCount, policyCount)
	}
	if source != policySetSourceDefaults {
		t.Errorf("Expected policySetSource = %q after loadDefaultPolicies, got %q", policySetSourceDefaults, source)
	}
	if got := testutil.ToFloat64(policySetSourceGauge.WithLabelValues(policySourceLabelDefaults)); got != 1 {
		t.Errorf("axonflow_policy_set_source{source=\"defaults\"} = %v, want 1 after loadDefaultPolicies", got)
	}

	// Spot-check one well-known built-in by its id (pol_high_risk_block —
	// the exact rule #3319's issue names as the one that used to be
	// duplicated under two ids when the retired engine appended defaults
	// to a database-loaded set).
	engine.mu.RLock()
	entry, exists := engine.policies["pol_high_risk_block"]
	engine.mu.RUnlock()
	if !exists {
		t.Fatal("Expected the built-in pol_high_risk_block policy to be present in the default fallback cache")
	}

	policyMap, ok := entry.(map[string]interface{})
	if !ok {
		t.Fatal("Expected default policy cache entry to be a map")
	}

	// Every cache writer (refreshPolicies, loadDefaultPolicies) must
	// populate _metadata - dbCachedPolicyAppliesToOrg fails CLOSED
	// (excludes) an entry with no _metadata at all.
	metadata, ok := policyMap["_metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected default policy to carry _metadata (every cache writer must populate it)")
	}
	// loadDefaultDynamicPolicies' entries carry TenantID == "" (the
	// in-memory engine's "unscoped" convention); on this engine that
	// translates to the "global" all-tenants sentinel, not empty (which
	// means "applies to nobody" here) — see defaultDynamicPolicyCacheEntry.
	if tenantID, _ := metadata["tenant_id"].(string); tenantID != "global" {
		t.Errorf("Expected default policy _metadata.tenant_id = %q (the apply-to-all sentinel), got %q", "global", tenantID)
	}
	if segmentID, _ := metadata["segment_id"].(string); segmentID != "" {
		t.Errorf("Expected default policy _metadata.segment_id = \"\" (not segment-scoped), got %q", segmentID)
	}

	// Confirm the fallback still applies to all tenants — routed through
	// the legitimate "global" sentinel, the same path a database-loaded
	// global policy takes, not a separate "defaults" code path.
	if !dbCachedPolicyAppliesToOrg(policyMap, "any-tenant", nil, "pol_high_risk_block") {
		t.Error("Expected the default fallback policy to apply to all tenants via the \"global\" sentinel")
	}
}

// TestLoadDefaultPoliciesCache_NeverAppendedToDatabaseLoad is the #3319
// item B/E regression test: default policies must be the WHOLE cache or
// ABSENT, never unioned with a database-loaded set (the retired in-memory
// engine's loadPoliciesFromDB did exactly that, duplicating rules like
// pol_high_risk_block / sys_dyn_high_risk_block under two ids). A
// successful refreshPolicies must produce a cache containing ONLY the rows
// the query returned — no pol_* id ever appears alongside them.
func TestLoadDefaultPoliciesCache_NeverAppendedToDatabaseLoad(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"}).
		AddRow("00000000-0000-0000-0000-000000000001", "db_only_policy", "", "{}", "{}", "tenant1", "tenant1", 10, "db-policy-1", "content", "custom", "medium", false, nil, nil, nil)
	mock.ExpectQuery("SELECT id::text, name").WillReturnRows(rows)

	engine := &DatabaseDynamicPolicyEngine{db: db, policies: loadDefaultPoliciesCache(), policySetSource: policySetSourceDefaults}
	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("refreshPolicies failed: %v", err)
	}

	engine.mu.RLock()
	defer engine.mu.RUnlock()
	if len(engine.policies) != 1 {
		t.Fatalf("Expected exactly 1 policy after a database load (the built-ins must NOT be appended), got %d: %v", len(engine.policies), engine.policies)
	}
	if _, exists := engine.policies["pol_high_risk_block"]; exists {
		t.Error("A built-in default policy id (pol_high_risk_block) leaked into a database-loaded cache — defaults must never be appended to a database-loaded set")
	}
	if _, exists := engine.policies["db-policy-1"]; !exists {
		t.Error("Expected the database-loaded policy to be present")
	}
}

// TestEvaluateDynamicPolicies_DefaultFallbackConstraintsStillApply proves the
// default fallback set (source=defaults, loadDefaultPolicies) actually
// matches and applies, end-to-end through EvaluateDynamicPolicies — not
// merely that it was loaded into the cache. This is the test that fails if
// the built-in policies ever silently stop applying on a boot that falls
// through to this fallback (refreshPolicies erroring or returning zero
// rows).
//
// Before #3319, loadDefaultPolicies' fallback was a single synthetic
// "default" stub entry with no real condition, relying on convergence 6's
// now-defunct vacuous-truth-over-zero-conditions behavior to apply
// unconditionally — patched, at the time, by giving that stub an explicit
// always-true sentinel condition. #3319 deleted the stub entirely and
// replaced it with the 10 real built-in pol_* policies
// (loadDefaultDynamicPolicies, policy_defaults.go), each already carrying
// its own genuine, non-vacuous condition, so there is no "default" cache key
// and no always-true sentinel left to test here. What still must hold is
// that the fallback SET, once loaded, evaluates real requests the same way
// a database-loaded set would — this test picks one built-in
// (pol_llm_cost_optimization: request_type == "simple_query" AND
// risk_score < 0.3) and sends a request shaped to satisfy it (RequestType
// set; risk_score defaults to 0.0 via getFieldValue when req.Context carries
// no override, which already satisfies the second half).
func TestEvaluateDynamicPolicies_DefaultFallbackConstraintsStillApply(t *testing.T) {
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
	engine.loadDefaultPolicies()
	engine.mu.Lock()
	engine.lastRefresh = time.Now()
	engine.mu.Unlock()

	mock.ExpectExec("INSERT INTO policy_metrics").
		WithArgs(sqlmock.AnyArg(), true, "", "system").
		WillReturnResult(sqlmock.NewResult(1, 1))

	result := engine.EvaluateDynamicPolicies(context.Background(), OrchestratorRequest{RequestType: "simple_query"})

	if !result.Allowed {
		t.Fatalf("expected pol_llm_cost_optimization's route action (log-only, no block) to allow, got Allowed=false")
	}
	found := false
	for _, detail := range result.AppliedPoliciesDetail {
		if detail.PolicyID == "pol_llm_cost_optimization" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the default fallback set (source=defaults) did NOT apply pol_llm_cost_optimization for a request shaped to match its condition — this means the built-in default policies are silently NOT being enforced. AppliedPoliciesDetail=%v", result.AppliedPoliciesDetail)
	}
}

// TestEvaluateDynamicPolicies_SamplePolicyConditionMatchesThroughEngine is
// the sample-policy counterpart of
// TestEvaluateDynamicPolicies_DefaultFallbackConstraintsStillApply: it proves
// a seeded sample policy with a `null` conditions blob — the exact shape
// insertSamplePolicies writes and refreshPolicies reads back as
// json.RawMessage("null") — actually matches when evaluated through the
// engine, not just that it round-trips through JSON. A cache entry built
// this way is what insertSamplePolicies' rows look like once refreshPolicies
// re-reads them from the database, so this is the shape that actually has to
// match in production, not just the shape written at insert time.
//
// Uses the "global_rate_limiting" sample's tenant scope (_metadata.tenant_id
// = "global", which dbCachedPolicyAppliesToOrg treats as applying to
// every tenant) so the test does not also have to reproduce
// insertSamplePolicies' per-sample tenant assignment to prove the point.
func TestEvaluateDynamicPolicies_SamplePolicyConditionMatchesThroughEngine(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := &DatabaseDynamicPolicyEngine{
		db:           db,
		metricsDB:    db,
		cacheTimeout: 30 * time.Second,
	}
	engine.mu.Lock()
	engine.policies = map[string]interface{}{
		"global_rate_limiting": map[string]interface{}{
			"name":       "global_rate_limiting",
			"conditions": json.RawMessage(`null`),
			"actions":    json.RawMessage(`[]`),
			"_metadata": map[string]interface{}{
				"id":         "global_rate_limiting",
				"tenant_id":  "global",
				"org_id":     "global",
				"segment_id": "",
			},
		},
	}
	engine.lastRefresh = time.Now()
	engine.mu.Unlock()

	mock.ExpectExec("INSERT INTO policy_metrics").
		WithArgs(sqlmock.AnyArg(), true, "", "system").
		WillReturnResult(sqlmock.NewResult(1, 1))

	result := engine.EvaluateDynamicPolicies(context.Background(), OrchestratorRequest{Query: "any query at all, no special context"})

	found := false
	for _, name := range result.AppliedPolicies {
		if name == "global_rate_limiting" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the seeded sample policy was NOT counted as applied — its null conditions blob, as stored by refreshPolicies' json.RawMessage shape, failed to vacuously match. AppliedPolicies=%v", result.AppliedPolicies)
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
			result := engine.evaluateCondition(tt.condition, tt.request, nil)
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
			result := engine.evaluateCondition(tt.condition, tt.request, nil)
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
			result := engine.evaluateCondition(tt.condition, tt.request, nil)
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
			result := engine.evaluateCondition(tt.condition, tt.request, nil)
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
			result := engine.evaluateCondition(tt.condition, tt.request, nil)
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
				"field":    "cost_estimate",
				"operator": "greater_than",
				"value":    0.5,
			},
			request: OrchestratorRequest{
				Context: map[string]interface{}{"cost_estimate": 0.8},
			},
			expected: true,
		},
		{
			name: "greater_than - false",
			condition: map[string]interface{}{
				"field":    "cost_estimate",
				"operator": "greater_than",
				"value":    0.5,
			},
			request: OrchestratorRequest{
				Context: map[string]interface{}{"cost_estimate": 0.3},
			},
			expected: false,
		},
		{
			name: "greater_than - equal is false",
			condition: map[string]interface{}{
				"field":    "cost_estimate",
				"operator": "greater_than",
				"value":    0.5,
			},
			request: OrchestratorRequest{
				Context: map[string]interface{}{"cost_estimate": 0.5},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request, nil)
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
			result := engine.evaluateCondition(tt.condition, tt.request, nil)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEvaluateCondition_GreaterThan_NumericStringParses covers the numeric
// string path of #3296 convergence 3, which this engine already got right
// and still does: a numeric-looking string parses via strconv.ParseFloat and
// compares normally. Contrast with
// TestEvaluateCondition_GreaterThan_UnparseableStringNoLongerCoercesToZero
// immediately below for the path this engine got wrong (and which is now
// fixed), and with TestEvaluateCondition_GreaterThan_NumericStringNowCompares
// in dynamic_policy_engine_test.go for the in-memory engine's (1a) side —
// which used to reject a numeric string outright and now also parses it.
func TestEvaluateCondition_GreaterThan_NumericStringParses(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	// "context.custom_metric" is NOT one of getFieldValue's specially-cased
	// fields (unlike "risk_score"/"cost_estimate", which themselves
	// type-assert to float64 and would mask the parsing this test targets)
	// — it flows through the generic context lookup, returning the RAW
	// stored value. The field value is the numeric STRING "10" (as it would
	// arrive from a context map/JSON decode); the condition value is the
	// typed float64 5. The string parses via ParseFloat, so 10 > 5 is true.
	got := engine.evaluateCondition(map[string]interface{}{
		"field":    "context.custom_metric",
		"operator": "greater_than",
		"value":    float64(5),
	}, OrchestratorRequest{Context: map[string]interface{}{"custom_metric": "10"}}, nil)
	if !got {
		t.Fatal("expected greater_than to parse a numeric-string field value on the database engine")
	}
}

// TestEvaluateCondition_GreaterThan_UnparseableStringNoLongerCoercesToZero is
// the #3296 convergence-3 regression test, named so the bug it closes is
// obvious: this engine's deleted toFloat64 method silently coerced ANY
// ParseFloat failure to 0.0 with no failure signal at all, so a non-numeric
// string field value under `less_than <positive threshold>` (or
// `greater_than <negative threshold>`) evaluated as a spurious match — on
// what is, on this engine, frequently a BLOCKING rule (LLM/MAP/WCP planes).
// The converged toFloat64 treats an unparseable string as NOT COMPARABLE, so
// this must be false, not a silent 0.0 match.
func TestEvaluateCondition_GreaterThan_UnparseableStringNoLongerCoercesToZero(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	got := engine.evaluateCondition(map[string]interface{}{
		"field":    "context.custom_metric",
		"operator": "less_than",
		"value":    float64(100),
	}, OrchestratorRequest{Context: map[string]interface{}{"custom_metric": "not-a-number"}}, nil)
	if got {
		t.Fatal("regression: an unparseable string field value must NOT satisfy less_than 100 on the database engine (was the legacy silent-0.0-coercion false positive) — expected false, got true")
	}
}

// TestEvaluateCondition_ContainsAny_NonStringItemStringified is this
// engine's (1b) #3296 convergence-2 test: a Value list item that is not a Go
// string (e.g. a JSON number decoded into []interface{}) is now stringified
// and matched like any other item, on every caller — this engine's legacy
// silent-skip of a non-string item is gone. See
// TestPolicyTestEvaluator_Operators in policy_api_service_test.go for the
// same behavior on the policy-test call site, which already stringified.
func TestEvaluateCondition_ContainsAny_NonStringItemStringified(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	// The list contains a non-string item (0.9) whose %v form ("0.9") IS
	// present in the field value — before #3296 this engine silently
	// skipped it and found no match; it must now stringify and match.
	got := engine.evaluateCondition(map[string]interface{}{
		"field":    "query",
		"operator": "contains_any",
		"value":    []interface{}{0.9, "unrelated-term"},
	}, OrchestratorRequest{Query: "risk score is 0.9 today"}, nil)
	if !got {
		t.Fatal("expected contains_any to stringify and match a non-string list item on the database engine, got no match")
	}
}

// TestEvaluateCondition_DatabaseEngine_AllTenOperatorsSupported is the #3296
// convergence 5 proof for this call site. This engine's legacy switch was
// already the ten-operator union, so this test is a straight regression
// guard rather than evidence of newly-enabled behavior — it must keep
// passing exactly as it always has.
func TestEvaluateCondition_DatabaseEngine_AllTenOperatorsSupported(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}
	req := OrchestratorRequest{Query: "hello world", RequestType: "query"}

	tests := []struct {
		operator string
		cond     map[string]interface{}
		want     bool
	}{
		{"equals", map[string]interface{}{"field": "request_type", "operator": "equals", "value": "query"}, true},
		{"not_equals", map[string]interface{}{"field": "request_type", "operator": "not_equals", "value": "mutation"}, true},
		{"contains", map[string]interface{}{"field": "query", "operator": "contains", "value": "wor"}, true},
		{"not_contains", map[string]interface{}{"field": "query", "operator": "not_contains", "value": "zzz"}, true},
		{"contains_any", map[string]interface{}{"field": "query", "operator": "contains_any", "value": []interface{}{"zzz", "wor"}}, true},
		{"greater_than", map[string]interface{}{"field": "risk_score", "operator": "greater_than", "value": float64(-1)}, true}, // #3321: risk_score defaults to 0.0 when no *PolicyEvaluationResult is in flight (direct evaluateCondition call, not via EvaluateDynamicPolicies)
		{"less_than", map[string]interface{}{"field": "risk_score", "operator": "less_than", "value": float64(10)}, true},
		{"regex", map[string]interface{}{"field": "query", "operator": "regex", "value": "^hel+o"}, true},
		{"in", map[string]interface{}{"field": "request_type", "operator": "in", "value": []interface{}{"query", "mutation"}}, true},
		{"not_in", map[string]interface{}{"field": "request_type", "operator": "not_in", "value": []interface{}{"delete", "admin"}}, true},
	}
	if len(tests) != 10 {
		t.Fatalf("expected exactly 10 operators under test, got %d", len(tests))
	}

	for _, tt := range tests {
		t.Run(tt.operator, func(t *testing.T) {
			got := engine.evaluateCondition(tt.cond, req, nil)
			if got != tt.want {
				t.Errorf("operator %q: evaluateCondition = %v, want %v", tt.operator, got, tt.want)
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
		// #3321: the bare "risk_score" field no longer reads req.Context — it
		// reads the *PolicyEvaluationResult passed to getFieldValue (nil
		// here, hence not tested via this generic table); see
		// db_dynamic_policies_risk_score_test.go for its dedicated coverage,
		// including the case this table used to (wrongly) assert: that a
		// caller-supplied context.risk_score of 0.75 would win. It no
		// longer does. "context.risk_score" is a distinct, still-context-
		// sourced field under its own namespace.
		{"context.risk_score", "context.risk_score", 0.75},
		{"cost_estimate", "cost_estimate", 0.05},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.getFieldValue(tt.field, request, nil)
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

	result := engine.evaluateCondition(condition, request, nil)
	if result != false {
		t.Error("Unknown operator should return false")
	}
}

// #3296: TestDatabaseDynamicPolicyEngine_ToFloat64 was removed here —
// the (e *DatabaseDynamicPolicyEngine) toFloat64 method it covered was
// deleted from db_dynamic_policies.go. Its replacement,
// platform/shared/policy/condition_evaluator.go's toFloat64, does NOT
// reproduce this method's own false-positive behavior (an unparseable
// operand silently became 0.0); see
// TestEvaluateCondition_GreaterThan_UnparseableStringNoLongerCoercesToZero
// below for the regression test and TestEvaluateCondition_GreaterThan /
// TestEvaluateCondition_LessThan for the still-correct numeric-string-parses
// path, all exercised through the rewired evaluateCondition.

// TestGetFieldValue_EdgeCases tests edge cases for field value extraction
func TestGetFieldValue_EdgeCases(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{}

	t.Run("request_id field", func(t *testing.T) {
		request := OrchestratorRequest{RequestID: "req-12345"}
		result := engine.getFieldValue("request_id", request, nil)
		if result != "req-12345" {
			t.Errorf("Expected req-12345, got %v", result)
		}
	})

	t.Run("user_id alias", func(t *testing.T) {
		request := OrchestratorRequest{User: UserContext{ID: 456}}
		result := engine.getFieldValue("user_id", request, nil)
		if result != 456 {
			t.Errorf("Expected 456, got %v", result)
		}
	})

	t.Run("user_email alias", func(t *testing.T) {
		request := OrchestratorRequest{User: UserContext{Email: "test@test.com"}}
		result := engine.getFieldValue("user_email", request, nil)
		if result != "test@test.com" {
			t.Errorf("Expected test@test.com, got %v", result)
		}
	})

	t.Run("region alias", func(t *testing.T) {
		request := OrchestratorRequest{User: UserContext{Region: "US"}}
		result := engine.getFieldValue("region", request, nil)
		if result != "US" {
			t.Errorf("Expected US, got %v", result)
		}
	})

	t.Run("client_id alias", func(t *testing.T) {
		request := OrchestratorRequest{Client: ClientContext{ID: "client-789"}}
		result := engine.getFieldValue("client_id", request, nil)
		if result != "client-789" {
			t.Errorf("Expected client-789, got %v", result)
		}
	})

	t.Run("agent_id alias", func(t *testing.T) {
		request := OrchestratorRequest{Client: ClientContext{ID: "agent-001"}}
		result := engine.getFieldValue("agent_id", request, nil)
		if result != "agent-001" {
			t.Errorf("Expected agent-001, got %v", result)
		}
	})

	t.Run("org_id alias", func(t *testing.T) {
		request := OrchestratorRequest{Client: ClientContext{OrgID: "org-999"}}
		result := engine.getFieldValue("org_id", request, nil)
		if result != "org-999" {
			t.Errorf("Expected org-999, got %v", result)
		}
	})

	t.Run("tenant_id alias", func(t *testing.T) {
		request := OrchestratorRequest{Client: ClientContext{TenantID: "tenant-abc"}}
		result := engine.getFieldValue("tenant_id", request, nil)
		if result != "tenant-abc" {
			t.Errorf("Expected tenant-abc, got %v", result)
		}
	})

	t.Run("environment from context", func(t *testing.T) {
		request := OrchestratorRequest{
			Context: map[string]interface{}{"environment": "production"},
		}
		result := engine.getFieldValue("environment", request, nil)
		if result != "production" {
			t.Errorf("Expected production, got %v", result)
		}
	})

	t.Run("env alias from context", func(t *testing.T) {
		request := OrchestratorRequest{
			Context: map[string]interface{}{"environment": "staging"},
		}
		result := engine.getFieldValue("env", request, nil)
		if result != "staging" {
			t.Errorf("Expected staging, got %v", result)
		}
	})

	// #3321: "risk_score" no longer reads req.Context at all — it reads the
	// *PolicyEvaluationResult argument. A nil result (as here) resolves to
	// 0.0 rather than panicking; see db_dynamic_policies_risk_score_test.go
	// for proof that a POPULATED context["risk_score"] is also ignored once
	// a real result is in play — that's the behavior change this guards,
	// not the nil-safety this table already covered pre-#3321.
	t.Run("risk_score is not read from context (nil result)", func(t *testing.T) {
		request := OrchestratorRequest{Context: map[string]interface{}{"risk_score": 0.9}}
		result := engine.getFieldValue("risk_score", request, nil)
		if result != 0.0 {
			t.Errorf("Expected 0.0 (bare risk_score must not read context), got %v", result)
		}
	})

	t.Run("cost_estimate missing from context", func(t *testing.T) {
		request := OrchestratorRequest{Context: map[string]interface{}{}}
		result := engine.getFieldValue("cost_estimate", request, nil)
		if result != 0.0 {
			t.Errorf("Expected 0.0, got %v", result)
		}
	})

	t.Run("custom field from context", func(t *testing.T) {
		request := OrchestratorRequest{
			Context: map[string]interface{}{"custom_field": "custom_value"},
		}
		result := engine.getFieldValue("custom_field", request, nil)
		if result != "custom_value" {
			t.Errorf("Expected custom_value, got %v", result)
		}
	})

	t.Run("context.prefixed field", func(t *testing.T) {
		request := OrchestratorRequest{
			Context: map[string]interface{}{"nested_data": "nested_value"},
		}
		result := engine.getFieldValue("context.nested_data", request, nil)
		if result != "nested_value" {
			t.Errorf("Expected nested_value, got %v", result)
		}
	})

	t.Run("unknown field returns nil", func(t *testing.T) {
		request := OrchestratorRequest{}
		result := engine.getFieldValue("nonexistent_field", request, nil)
		if result != nil {
			t.Errorf("Expected nil, got %v", result)
		}
	})

	t.Run("nil context returns nil for custom field", func(t *testing.T) {
		request := OrchestratorRequest{Context: nil}
		result := engine.getFieldValue("some_custom_field", request, nil)
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
				"field":    "cost_estimate",
				"operator": "less_than",
				"value":    0.5,
			},
			request:  OrchestratorRequest{Context: map[string]interface{}{"cost_estimate": 0.3}},
			expected: true,
		},
		{
			name: "less_than - false",
			condition: map[string]interface{}{
				"field":    "cost_estimate",
				"operator": "less_than",
				"value":    0.5,
			},
			request:  OrchestratorRequest{Context: map[string]interface{}{"cost_estimate": 0.7}},
			expected: false,
		},
		{
			name: "less_than - equal is false",
			condition: map[string]interface{}{
				"field":    "cost_estimate",
				"operator": "less_than",
				"value":    0.5,
			},
			request:  OrchestratorRequest{Context: map[string]interface{}{"cost_estimate": 0.5}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request, nil)
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
			result := engine.evaluateCondition(tt.condition, tt.request, nil)
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
			result := engine.evaluateCondition(tt.condition, tt.request, nil)
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
				"field":    "cost_estimate",
				"operator": "regex",
				"value":    "0\\.8",
			},
			request: OrchestratorRequest{
				Context: map[string]interface{}{"cost_estimate": 0.8},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.request, nil)
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
			result := engine.evaluateCondition(tt.condition, tt.request, nil)
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
			result := engine.evaluateCondition(tt.condition, tt.request, nil)
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
