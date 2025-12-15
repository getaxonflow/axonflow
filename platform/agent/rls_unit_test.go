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
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// ============================================================================
// Unit Tests for RLS functions (using sqlmock, no real database needed)
// ============================================================================

func TestSetRLSContextUnit(t *testing.T) {
	tests := []struct {
		name    string
		orgID   string
		setupMock func(sqlmock.Sqlmock)
		wantErr bool
		errMsg  string
	}{
		{
			name:  "successful RLS context set",
			orgID: "test-org-123",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("SELECT set_org_id\\(\\$1\\)").
					WithArgs("test-org-123").
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
			wantErr: false,
		},
		{
			name:  "empty org_id returns error",
			orgID: "",
			setupMock: func(mock sqlmock.Sqlmock) {
				// No mock needed - should fail before DB call
			},
			wantErr: true,
			errMsg:  "org_id cannot be empty",
		},
		{
			name:  "database error during set",
			orgID: "test-org-456",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("SELECT set_org_id\\(\\$1\\)").
					WithArgs("test-org-456").
					WillReturnError(errors.New("connection lost"))
			},
			wantErr: true,
			errMsg:  "failed to set session variable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)

			ctx := context.Background()
			err = SetRLSContext(ctx, db, tt.orgID)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errMsg)
				} else if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestSetRLSContextNilDB(t *testing.T) {
	ctx := context.Background()
	err := SetRLSContext(ctx, nil, "test-org")
	if err != nil {
		t.Errorf("SetRLSContext with nil DB should return nil, got: %v", err)
	}
}

func TestResetRLSContextUnit(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(sqlmock.Sqlmock)
		wantPanic bool
	}{
		{
			name: "successful reset",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("SELECT reset_org_id\\(\\)").
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
			wantPanic: false,
		},
		{
			name: "database error during reset (non-fatal)",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("SELECT reset_org_id\\(\\)").
					WillReturnError(errors.New("connection lost"))
			},
			wantPanic: false, // Should not panic, just log warning
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)

			ctx := context.Background()

			// ResetRLSContext doesn't return error, just logs
			ResetRLSContext(ctx, db)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestResetRLSContextNilDB(t *testing.T) {
	ctx := context.Background()
	// Should not panic with nil DB
	ResetRLSContext(ctx, nil)
}

func TestWithRLSUnit(t *testing.T) {
	tests := []struct {
		name      string
		orgID     string
		setupMock func(sqlmock.Sqlmock)
		operation func(*sql.DB) error
		wantErr   bool
		errMsg    string
	}{
		{
			name:  "successful operation with RLS",
			orgID: "test-org-789",
			setupMock: func(mock sqlmock.Sqlmock) {
				// Expect SetRLSContext call
				mock.ExpectExec("SELECT set_org_id\\(\\$1\\)").
					WithArgs("test-org-789").
					WillReturnResult(sqlmock.NewResult(0, 0))

				// Expect operation query
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM events").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(42))

				// Expect ResetRLSContext call (cleanup)
				mock.ExpectExec("SELECT reset_org_id\\(\\)").
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
			operation: func(db *sql.DB) error {
				var count int
				return db.QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
			},
			wantErr: false,
		},
		{
			name:  "RLS setup fails",
			orgID: "bad-org",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("SELECT set_org_id\\(\\$1\\)").
					WithArgs("bad-org").
					WillReturnError(errors.New("RLS setup failed"))
			},
			operation: func(db *sql.DB) error {
				return nil // Won't be called
			},
			wantErr: true,
			errMsg:  "failed to set session variable",
		},
		{
			name:  "operation fails but RLS cleanup happens",
			orgID: "test-org-cleanup",
			setupMock: func(mock sqlmock.Sqlmock) {
				// Expect SetRLSContext call
				mock.ExpectExec("SELECT set_org_id\\(\\$1\\)").
					WithArgs("test-org-cleanup").
					WillReturnResult(sqlmock.NewResult(0, 0))

				// Expect ResetRLSContext call (cleanup happens even on error)
				mock.ExpectExec("SELECT reset_org_id\\(\\)").
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
			operation: func(db *sql.DB) error {
				return errors.New("operation failed")
			},
			wantErr: true,
			errMsg:  "operation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)

			ctx := context.Background()
			err = WithRLS(ctx, db, tt.orgID, tt.operation)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errMsg)
				} else if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestGetCurrentOrgIDUnit(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(sqlmock.Sqlmock)
		wantOrgID string
		wantErr   bool
		errMsg    string
	}{
		{
			name: "org_id is set",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"current_setting"}).
					AddRow("healthcare-eu")
				mock.ExpectQuery("SELECT current_setting\\('app.current_org_id', true\\)").
					WillReturnRows(rows)
			},
			wantOrgID: "healthcare-eu",
			wantErr:   false,
		},
		{
			name: "org_id not set (NULL)",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"current_setting"}).
					AddRow(nil)
				mock.ExpectQuery("SELECT current_setting\\('app.current_org_id', true\\)").
					WillReturnRows(rows)
			},
			wantErr: true,
			errMsg:  "org_id not set in session",
		},
		{
			name: "org_id is empty string",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"current_setting"}).
					AddRow("")
				mock.ExpectQuery("SELECT current_setting\\('app.current_org_id', true\\)").
					WillReturnRows(rows)
			},
			wantErr: true,
			errMsg:  "org_id not set in session",
		},
		{
			name: "database error",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT current_setting\\('app.current_org_id', true\\)").
					WillReturnError(errors.New("connection lost"))
			},
			wantErr: true,
			errMsg:  "failed to get current org_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)

			ctx := context.Background()
			orgID, err := GetCurrentOrgID(ctx, db)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errMsg)
				} else if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if orgID != tt.wantOrgID {
					t.Errorf("Expected orgID '%s', got '%s'", tt.wantOrgID, orgID)
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestGetCurrentOrgIDNilDB(t *testing.T) {
	ctx := context.Background()
	_, err := GetCurrentOrgID(ctx, nil)
	if err == nil {
		t.Error("Expected error for nil DB, got nil")
	}
	if !containsString(err.Error(), "database connection is nil") {
		t.Errorf("Expected 'database connection is nil' error, got: %v", err)
	}
}

func TestVerifyRLSActiveUnit(t *testing.T) {
	tests := []struct {
		name      string
		tableName string
		setupMock func(sqlmock.Sqlmock)
		wantActive bool
		wantErr    bool
		errMsg     string
	}{
		{
			name:      "RLS enabled on table",
			tableName: "usage_events",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"rowsecurity"}).AddRow(true)
				mock.ExpectQuery("SELECT COALESCE\\(rowsecurity, false\\)").
					WithArgs("usage_events").
					WillReturnRows(rows)
			},
			wantActive: true,
			wantErr:    false,
		},
		{
			name:      "RLS disabled on table",
			tableName: "config_settings",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"rowsecurity"}).AddRow(false)
				mock.ExpectQuery("SELECT COALESCE\\(rowsecurity, false\\)").
					WithArgs("config_settings").
					WillReturnRows(rows)
			},
			wantActive: false,
			wantErr:    false,
		},
		{
			name:      "table not found",
			tableName: "nonexistent_table",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COALESCE\\(rowsecurity, false\\)").
					WithArgs("nonexistent_table").
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: true,
			errMsg:  "table 'nonexistent_table' not found",
		},
		{
			name:      "database error",
			tableName: "usage_events",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COALESCE\\(rowsecurity, false\\)").
					WithArgs("usage_events").
					WillReturnError(errors.New("connection lost"))
			},
			wantErr: true,
			errMsg:  "failed to check RLS status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)

			ctx := context.Background()
			active, err := VerifyRLSActive(ctx, db, tt.tableName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errMsg)
				} else if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if active != tt.wantActive {
					t.Errorf("Expected active=%v, got %v", tt.wantActive, active)
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestVerifyRLSActiveNilDB(t *testing.T) {
	ctx := context.Background()
	_, err := VerifyRLSActive(ctx, nil, "some_table")
	if err == nil {
		t.Error("Expected error for nil DB, got nil")
	}
	if !containsString(err.Error(), "database connection is nil") {
		t.Errorf("Expected 'database connection is nil' error, got: %v", err)
	}
}

func TestGetRLSStatsUnit(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(sqlmock.Sqlmock)
		wantStats *RLSStats
		wantErr   bool
		errMsg    string
	}{
		{
			name: "successful stats retrieval",
			setupMock: func(mock sqlmock.Sqlmock) {
				// Count tables with RLS
				mock.ExpectQuery("SELECT COUNT\\(\\*\\).*FROM pg_tables.*rowsecurity = true").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

				// Count policies
				mock.ExpectQuery("SELECT COUNT\\(\\*\\).*FROM pg_policies").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(6))

				// Get table names
				tableRows := sqlmock.NewRows([]string{"tablename"}).
					AddRow("usage_events").
					AddRow("agent_heartbeats").
					AddRow("request_logs")
				mock.ExpectQuery("SELECT tablename.*FROM pg_tables.*rowsecurity = true").
					WillReturnRows(tableRows)
			},
			wantStats: &RLSStats{
				TablesWithRLS: 3,
				PolicyCount:   6,
				EnabledTables: []string{"usage_events", "agent_heartbeats", "request_logs"},
			},
			wantErr: false,
		},
		{
			name: "no RLS tables",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COUNT\\(\\*\\).*FROM pg_tables.*rowsecurity = true").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
				mock.ExpectQuery("SELECT COUNT\\(\\*\\).*FROM pg_policies").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
				mock.ExpectQuery("SELECT tablename.*FROM pg_tables.*rowsecurity = true").
					WillReturnRows(sqlmock.NewRows([]string{"tablename"}))
			},
			wantStats: &RLSStats{
				TablesWithRLS: 0,
				PolicyCount:   0,
				EnabledTables: nil,
			},
			wantErr: false,
		},
		{
			name: "error counting tables",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COUNT\\(\\*\\).*FROM pg_tables.*rowsecurity = true").
					WillReturnError(errors.New("connection lost"))
			},
			wantErr: true,
			errMsg:  "failed to count RLS tables",
		},
		{
			name: "error counting policies",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COUNT\\(\\*\\).*FROM pg_tables.*rowsecurity = true").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
				mock.ExpectQuery("SELECT COUNT\\(\\*\\).*FROM pg_policies").
					WillReturnError(errors.New("permission denied"))
			},
			wantErr: true,
			errMsg:  "failed to count policies",
		},
		{
			name: "error querying table names",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COUNT\\(\\*\\).*FROM pg_tables.*rowsecurity = true").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
				mock.ExpectQuery("SELECT COUNT\\(\\*\\).*FROM pg_policies").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(4))
				mock.ExpectQuery("SELECT tablename.*FROM pg_tables.*rowsecurity = true").
					WillReturnError(errors.New("query failed"))
			},
			wantErr: true,
			errMsg:  "failed to query RLS tables",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)

			ctx := context.Background()
			stats, err := GetRLSStats(ctx, db)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errMsg)
				} else if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if stats.TablesWithRLS != tt.wantStats.TablesWithRLS {
					t.Errorf("Expected TablesWithRLS=%d, got %d", tt.wantStats.TablesWithRLS, stats.TablesWithRLS)
				}
				if stats.PolicyCount != tt.wantStats.PolicyCount {
					t.Errorf("Expected PolicyCount=%d, got %d", tt.wantStats.PolicyCount, stats.PolicyCount)
				}
				if len(stats.EnabledTables) != len(tt.wantStats.EnabledTables) {
					t.Errorf("Expected %d tables, got %d", len(tt.wantStats.EnabledTables), len(stats.EnabledTables))
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestGetRLSStatsNilDB(t *testing.T) {
	ctx := context.Background()
	_, err := GetRLSStats(ctx, nil)
	if err == nil {
		t.Error("Expected error for nil DB, got nil")
	}
	if !containsString(err.Error(), "database connection is nil") {
		t.Errorf("Expected 'database connection is nil' error, got: %v", err)
	}
}

func TestRLSHealthCheckUnit(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(sqlmock.Sqlmock)
		wantErr   bool
		errMsg    string
	}{
		{
			name: "all checks pass",
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check helper functions exist (3 functions)
				for _, funcName := range []string{"get_current_org_id", "set_org_id", "reset_org_id"} {
					mock.ExpectQuery("SELECT EXISTS").
						WithArgs(funcName).
						WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
				}

				// Check RLS enabled on critical tables (4 tables)
				for range []string{"usage_events", "agent_heartbeats", "organizations", "user_sessions"} {
					mock.ExpectQuery("SELECT COALESCE\\(rowsecurity, false\\)").
						WillReturnRows(sqlmock.NewRows([]string{"rowsecurity"}).AddRow(true))
				}

				// Get RLS stats
				mock.ExpectQuery("SELECT COUNT\\(\\*\\).*FROM pg_tables.*rowsecurity = true").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(4))
				mock.ExpectQuery("SELECT COUNT\\(\\*\\).*FROM pg_policies").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(8))
				tableRows := sqlmock.NewRows([]string{"tablename"}).
					AddRow("usage_events").
					AddRow("agent_heartbeats").
					AddRow("organizations").
					AddRow("user_sessions")
				mock.ExpectQuery("SELECT tablename.*FROM pg_tables.*rowsecurity = true").
					WillReturnRows(tableRows)
			},
			wantErr: false,
		},
		{
			name: "helper function missing",
			setupMock: func(mock sqlmock.Sqlmock) {
				// First function exists
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs("get_current_org_id").
					WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
				// Second function missing
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs("set_org_id").
					WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
			},
			wantErr: true,
			errMsg:  "RLS helper function 'set_org_id' not found",
		},
		{
			name: "RLS not enabled on critical table",
			setupMock: func(mock sqlmock.Sqlmock) {
				// All functions exist
				for _, funcName := range []string{"get_current_org_id", "set_org_id", "reset_org_id"} {
					mock.ExpectQuery("SELECT EXISTS").
						WithArgs(funcName).
						WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
				}

				// First table has RLS
				mock.ExpectQuery("SELECT COALESCE\\(rowsecurity, false\\)").
					WillReturnRows(sqlmock.NewRows([]string{"rowsecurity"}).AddRow(true))

				// Second table doesn't have RLS
				mock.ExpectQuery("SELECT COALESCE\\(rowsecurity, false\\)").
					WillReturnRows(sqlmock.NewRows([]string{"rowsecurity"}).AddRow(false))
			},
			wantErr: true,
			errMsg:  "RLS not enabled on critical table",
		},
		{
			name: "database error checking functions",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs("get_current_org_id").
					WillReturnError(errors.New("connection lost"))
			},
			wantErr: true,
			errMsg:  "failed to check function 'get_current_org_id'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)

			ctx := context.Background()
			err = RLSHealthCheck(ctx, db)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errMsg)
				} else if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestRLSHealthCheckNilDB(t *testing.T) {
	ctx := context.Background()
	err := RLSHealthCheck(ctx, nil)
	if err == nil {
		t.Error("Expected error for nil DB, got nil")
	}
	if !containsString(err.Error(), "database connection is nil") {
		t.Errorf("Expected 'database connection is nil' error, got: %v", err)
	}
}
