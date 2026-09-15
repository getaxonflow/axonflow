// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestTheMigrationLoopCallsTheLegacyPolicyEnforcer pins the one line the whole
// view-closure fix rests on.
//
// WHY A SOURCE ASSERTION, WHICH IS NORMALLY THE WEAK FORM. Every other property
// in this area is asserted behaviourally against a real database, and that is
// the right instrument for a property the database can answer. This one it
// cannot: "the agent calls the enforcer after its migration loop" is a fact
// about a call graph, and the database sees an identical schema whether the
// call happens at boot or a developer ran it by hand.
//
// The gap this closes was measured rather than imagined. Deleting
// `enforceLegacyPolicyReadOnly(migrationDB)` from run.go leaves:
//
//	go build ./...                       OK
//	go vet ./agent/                      OK
//	the whole RealPG suite               ok
//	the required write-surface guard     PASS
//
// because Go does not complain about an unreferenced package-level function,
// and the RealPG test that exercises the wrapper calls it DIRECTLY rather than
// through Run(). So the load-bearing half of the fix was removable in one line
// with nothing anywhere reporting it - and the consequence is not subtle: a
// fresh in-vpc-banking or travel deployment ships with four of the five
// auto-updatable views over static_policies writable by both application roles.
//
// It asserts POSITION, not just presence. The call has to be inside the block
// that runs after the migration loop completes; a call placed before the loop
// would satisfy a bare grep and would bind a closure that is not yet complete,
// which is the exact defect the boot-time call exists to avoid.
//
// Since #3894 the loop is RunMigrations in migration_helpers.go and the call is
// the enforcer's error core inside it, so this reads that file, and separately
// pins that run.go's boot path calls RunMigrations exactly once.
func TestTheMigrationLoopCallsTheLegacyPolicyEnforcer(t *testing.T) {
	boot, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatalf("reading run.go: %v", err)
	}
	runner := regexp.MustCompile(`^\s*if _, _, err := RunMigrations\(migrationDB, migrations, MigrationSessionVars\{\s*$`)
	var runnerAt []int
	for i, l := range strings.Split(string(boot), "\n") {
		if runner.MatchString(l) {
			runnerAt = append(runnerAt, i+1)
		}
	}
	if len(runnerAt) != 1 {
		t.Fatalf("run.go calls RunMigrations(migrationDB, migrations, ...) at lines %v; want exactly one boot-path call", runnerAt)
	}

	src, err := os.ReadFile("migration_helpers.go")
	if err != nil {
		t.Fatalf("reading migration_helpers.go: %v", err)
	}
	lines := strings.Split(string(src), "\n")

	// The anchor is the log line the migration loop prints when it finishes.
	// It is matched by a pattern rather than by a line number, because a census
	// keyed on a source position is invalidated by anything above it.
	anchor := regexp.MustCompile(`Database migrations completed`)
	call := regexp.MustCompile(`^\s*if err := runLegacyPolicyReadOnlyEnforcer\(db\); err != nil \{\s*$`)

	anchorAt := -1
	for i, l := range lines {
		if anchor.MatchString(l) {
			if anchorAt != -1 {
				t.Fatalf("migration_helpers.go has more than one %q line (%d and %d); this test cannot tell which one the loop ends at",
					"Database migrations completed", anchorAt+1, i+1)
			}
			anchorAt = i
		}
	}
	if anchorAt == -1 {
		t.Fatal("migration_helpers.go no longer logs \"Database migrations completed\", so this test cannot locate the end of the migration loop. " +
			"Re-anchor it rather than deleting it: it is the only thing asserting the enforcer is wired in at all.")
	}

	// Within a window after the anchor, not anywhere in the file.
	const window = 40
	callAt := -1
	for i := anchorAt; i < len(lines) && i < anchorAt+window; i++ {
		if call.MatchString(lines[i]) {
			callAt = i
			break
		}
	}
	if callAt == -1 {
		t.Fatalf("RunMigrations does not call runLegacyPolicyReadOnlyEnforcer(db) within %d lines after the migration loop completes "+
			"(anchor at line %d).\n\n"+
			"That call is what makes migrations/core/174's claim true on a FRESH deployment. Industry migrations are "+
			"numbered 200+ so they run AFTER core, and core/098 arms ALTER DEFAULT PRIVILEGES, so four of the five "+
			"views over static_policies are created after 174 has run and each arrives writable. Without this call they "+
			"stay writable by both application roles and the legacy write path is open.",
			window, anchorAt+1)
	}
	t.Logf("migration_helpers.go:%d calls the enforcer, %d line(s) after the migration loop's completion log at migration_helpers.go:%d; run.go:%d calls RunMigrations",
		callAt+1, callAt-anchorAt, anchorAt+1, runnerAt[0])

	// AND THE BRANCH EXITS. A body that logged and carried on would keep every
	// line above green and boot with the closure open: RunMigrations must
	// return the enforcer's error, and run.go must exit on it (#3894 R3).
	if callAt+1 >= len(lines) || !regexp.MustCompile(`^\s*return applied, skipped, err\s*$`).MatchString(lines[callAt+1]) {
		t.Fatalf("migration_helpers.go:%d: the enforcer's error branch must be `return applied, skipped, err`", callAt+2)
	}
	bootLines := strings.Split(string(boot), "\n")
	exits := false
	for i := runnerAt[0]; i < len(bootLines) && i < runnerAt[0]+8; i++ {
		if regexp.MustCompile(`^\s*fatalMigrationError\(err\)\s*$`).MatchString(bootLines[i]) {
			exits = true
			break
		}
	}
	if !exits {
		t.Fatalf("run.go:%d: RunMigrations' error must exit the boot through fatalMigrationError(err)", runnerAt[0])
	}

	// AND IT IS NOT BEFORE THE LOOP. A call above the anchor would bind a
	// closure the industry migrations have not finished adding to.
	for i := 0; i < anchorAt; i++ {
		if call.MatchString(lines[i]) {
			t.Errorf("migration_helpers.go:%d calls the enforcer BEFORE the migration loop completes (migration_helpers.go:%d). "+
				"At that point the industry views do not exist yet, so the closure it walks is incomplete.", i+1, anchorAt+1)
		}
	}
}
