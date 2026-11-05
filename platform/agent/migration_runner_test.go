// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func expectMigrationBootstrap(mock sqlmock.Sqlmock, failSession bool) {
	mock.ExpectQuery("SELECT EXISTS").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS schema_migrations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("DO").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("DO").WillReturnResult(sqlmock.NewResult(0, 0))
	for i := 0; i < 3; i++ {
		if failSession && i == 0 {
			mock.ExpectExec("SELECT set_config").WillReturnError(errors.New("session config refused"))
		} else {
			mock.ExpectExec("SELECT set_config").WillReturnResult(sqlmock.NewResult(0, 0))
		}
	}
}

func TestOpenMigrationDBPinsSessionForMigrationSettings(t *testing.T) {
	db, err := openMigrationDB("postgres://agent:example@127.0.0.1:5432/axonflow?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := db.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("migration pool max open connections = %d, want 1 for session-scoped set_config", got)
	}
}

func TestRunMigrationsRequiresVerifiedLedgerAndFiles(t *testing.T) {
	for _, tc := range []struct {
		name          string
		ledgerInitErr bool
		sessionErr    bool
		ledgerErr     bool
		missingFile   bool
		recordErr     bool
		wantStage     migrationStage
		wantApplied   int
	}{
		{name: "ledger initialization failure", ledgerInitErr: true, wantStage: stageLedgerInit},
		{name: "session variable failure", sessionErr: true, wantStage: stageSessionVars},
		{name: "ledger query failure", ledgerErr: true, wantStage: stageAppliedRead},
		{name: "unreadable selected file", missingFile: true, wantStage: stageFileRead},
		{name: "success row insert failure", recordErr: true, wantStage: stageRecordSuccess},
		{name: "verified success", wantApplied: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if tc.ledgerInitErr {
				mock.ExpectQuery("SELECT EXISTS").WillReturnError(errors.New("ledger schema unavailable"))
			} else {
				expectMigrationBootstrap(mock, tc.sessionErr)
			}
			if tc.ledgerErr {
				mock.ExpectQuery("SELECT version, name").WillReturnError(errors.New("ledger unavailable"))
			} else if !tc.ledgerInitErr && !tc.sessionErr {
				mock.ExpectQuery("SELECT version, name").WillReturnRows(sqlmock.NewRows([]string{"version", "name"}))
			}

			path := filepath.Join(t.TempDir(), "991_test.sql")
			if !tc.missingFile {
				if err := os.WriteFile(path, []byte("SELECT 1"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if !tc.ledgerInitErr && !tc.sessionErr && !tc.ledgerErr && !tc.missingFile {
				mock.ExpectExec("SELECT 1").WillReturnResult(sqlmock.NewResult(0, 0))
				if tc.recordErr {
					mock.ExpectExec("INSERT INTO schema_migrations").WillReturnError(errors.New("ledger write refused"))
				} else {
					mock.ExpectExec("INSERT INTO schema_migrations").WillReturnResult(sqlmock.NewResult(0, 1))
					mock.ExpectQuery("SELECT to_regprocedure").WillReturnRows(sqlmock.NewRows([]string{"present"}).AddRow(false))
				}
			}

			applied, skipped, err := RunMigrations(db, []MigrationFile{{Path: path, Category: "core", Version: "991", Name: "test"}}, MigrationSessionVars{})
			if tc.wantStage == 0 {
				if err != nil || applied != tc.wantApplied || skipped != 0 {
					t.Fatalf("want verified success: applied=%d skipped=%d err=%v", applied, skipped, err)
				}
			} else {
				var me *MigrationError
				if !errors.As(err, &me) || me.stage != tc.wantStage || applied != 0 || skipped != 0 {
					t.Fatalf("want stage %d before readiness: applied=%d skipped=%d err=%v", tc.wantStage, applied, skipped, err)
				}
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestTheBootPathKeepsEveryMigrationFatalMessageByteForByte pins #3894 clause
// (a)'s extraction: the boot migration loop moved from run.go into
// RunMigrations, and each of its failures must still exit with the exact text
// the inline runner and the fatal enforcer wrote. The expected lines are built
// from the OLD format strings, copied verbatim from run.go and
// legacy_policy_read_only.go as they stood at 45116d726.
func TestTheBootPathKeepsEveryMigrationFatalMessageByteForByte(t *testing.T) {
	boom := errors.New("pq: relation \"x\" does not exist")
	const file, category = "107_grafana_database.sql", "core"
	for _, c := range []struct {
		name      string
		err       error
		wantLog   string
		wantFatal string
	}{
		{
			name:      "the Grafana password substitution",
			err:       &MigrationError{stage: stageSubstitute, File: file, Category: category, Err: boom},
			wantFatal: fmt.Sprintf("Migration %s failed: %v", file, boom),
		},
		{
			name:      "a migration's own SQL",
			err:       &MigrationError{stage: stageExec, File: file, Category: category, Err: boom},
			wantLog:   fmt.Sprintf("❌ Migration %s [%s] FAILED: %v", file, category, boom),
			wantFatal: "Database migrations failed. Exiting to prevent incomplete setup.",
		},
		{
			name:      "looking up the #3905 enforcer",
			err:       &MigrationError{stage: stageEnforcerCheck, Err: boom},
			wantFatal: fmt.Sprintf("Failed to check for the legacy-policy read-only enforcer: %v", boom),
		},
		{
			name:      "running the #3905 enforcer",
			err:       &MigrationError{stage: stageEnforce, Err: boom},
			wantFatal: fmt.Sprintf("Failed to enforce the legacy-policy read-only invariant (#3905): %v", boom),
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			gotLog, gotFatal := migrationFailureLines(c.err)
			if gotLog != c.wantLog {
				t.Errorf("log line = %q, want %q", gotLog, c.wantLog)
			}
			if gotFatal != c.wantFatal {
				t.Errorf("fatal line = %q, want %q", gotFatal, c.wantFatal)
			}
			if !errors.Is(c.err, boom) {
				t.Errorf("the MigrationError does not unwrap to the underlying error")
			}
		})
	}
}
