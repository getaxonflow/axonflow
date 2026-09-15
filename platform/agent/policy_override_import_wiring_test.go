// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestTheBootPathRunsTheOverrideImportAfterTheEnforcer pins the one line that
// runs the once-only import (PRD v11 §1.5). It is a source assertion for the
// reason TestTheMigrationLoopCallsTheLegacyPolicyEnforcer gives: "the agent calls
// it at boot" is a fact about a call graph, and the RealPG test calls
// runPolicyOverrideImport directly, so it passes with this line gone. The call
// must follow the enforcer, which that test pins after the migration loop, so
// the import runs once every migration has applied. Since #3894 the loop and the
// enforcer are RunMigrations, so the import must follow its boot-path call.
func TestTheBootPathRunsTheOverrideImportAfterTheEnforcer(t *testing.T) {
	src, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatalf("reading run.go: %v", err)
	}
	enforcer := regexp.MustCompile(`^\s*if _, _, err := RunMigrations\(migrationDB, migrations, MigrationSessionVars\{\s*$`)
	importer := regexp.MustCompile(`^\s*importPolicyOverrideDrafts\(migrationDB\)\s*$`)
	var enforcerAt, importAt []int
	for i, l := range strings.Split(string(src), "\n") {
		if enforcer.MatchString(l) {
			enforcerAt = append(enforcerAt, i+1)
		}
		if importer.MatchString(l) {
			importAt = append(importAt, i+1)
		}
	}
	if len(enforcerAt) != 1 || len(importAt) != 1 {
		t.Fatalf("run.go calls RunMigrations (the loop and the enforcer) at %v and the import at %v; want exactly one of each", enforcerAt, importAt)
	}
	// Within a few lines after the runner's call, which spans seven lines: inside
	// the same post-migration block.
	const window = 20
	if d := importAt[0] - enforcerAt[0]; d <= 0 || d > window {
		t.Fatalf("run.go:%d calls importPolicyOverrideDrafts(migrationDB) %d line(s) from the enforcer at run.go:%d; "+
			"want it after the enforcer, within %d lines, so every migration has applied when it reads", importAt[0], d, enforcerAt[0], window)
	}
}
