// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"errors"
	"fmt"
	"testing"
)

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
