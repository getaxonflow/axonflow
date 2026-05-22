// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestMigrationKey_DistinguishesSameVersion locks in the composite-key
// contract — files that share a numeric prefix MUST produce distinct
// keys. Before the fix (migration 096 + this helper), both
// 025_decision_chain and 025_hitl_oversight_queue collapsed onto key
// "025" and the second migration was silently dropped on existing
// installs because the first one's row had already claimed the UNIQUE
// version slot in schema_migrations.
func TestMigrationKey_DistinguishesSameVersion(t *testing.T) {
	keyA := migrationKey("025", "decision_chain")
	keyB := migrationKey("025", "hitl_oversight_queue")
	if keyA == keyB {
		t.Fatalf("composite key collision: both produced %q — would re-introduce the v1 dedup bug", keyA)
	}
	// And the same version+name pair MUST be stable across calls.
	if migrationKey("025", "decision_chain") != keyA {
		t.Errorf("migrationKey is not deterministic")
	}
}

// TestGetAppliedMigrations_ReadsCompositeKey proves the runner indexes
// applied migrations by (version, name), not by version alone. The
// post-fix loop in run.go checks `appliedMigrations[migrationKey(v, n)]`,
// so the map MUST be keyed the same way.
func TestGetAppliedMigrations_ReadsCompositeKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	// Two distinct 025_* files plus a 042_* row — the post-fix DB shape.
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT version, name`)).
		WillReturnRows(sqlmock.NewRows([]string{"version", "name"}).
			AddRow("025", "decision_chain").
			AddRow("025", "hitl_oversight_queue").
			AddRow("042", "unified_execution_history"))

	got := getAppliedMigrations(db)

	wantKeys := []string{
		migrationKey("025", "decision_chain"),
		migrationKey("025", "hitl_oversight_queue"),
		migrationKey("042", "unified_execution_history"),
	}
	for _, k := range wantKeys {
		if !got[k] {
			t.Errorf("expected applied[%q] = true, got false", k)
		}
	}
	// A bare-version lookup MUST miss — that's the whole point.
	if got["025"] {
		t.Errorf("appliedMigrations should NOT key on bare version '025' — that's the bug")
	}
	if got["042"] {
		t.Errorf("appliedMigrations should NOT key on bare version '042' — that's the bug")
	}
	if len(got) != 3 {
		t.Errorf("got %d entries, want 3: %+v", len(got), got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// TestGetAppliedMigrations_TolerantOfQueryFailure — if the table is
// missing or unreachable, we return an empty map so the runner re-runs
// every migration (the IF NOT EXISTS guards in each SQL file make that
// safe). Asserts we don't panic and the map is empty + usable.
func TestGetAppliedMigrations_TolerantOfQueryFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT version, name`)).
		WillReturnError(errors.New("relation \"schema_migrations\" does not exist"))

	got := getAppliedMigrations(db)
	if got == nil {
		t.Fatalf("expected non-nil map on query error, got nil")
	}
	if len(got) != 0 {
		t.Errorf("expected empty map on query error, got %d entries", len(got))
	}
}

// TestRecordMigrationSuccess_CompositeConflict verifies the ON CONFLICT
// clause references (version, name), matching the v2 composite UNIQUE
// constraint. If a future change reverts to ON CONFLICT (version), two
// distinct same-version migrations would clobber each other's row.
func TestRecordMigrationSuccess_CompositeConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	// The sqlmock matcher checks the SQL text; assert the composite
	// ON CONFLICT clause is what hits the DB.
	mock.ExpectExec(`ON CONFLICT \(version, name\) DO UPDATE`).
		WithArgs("025", "decision_chain", 17, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	recordMigrationSuccess(db, "025", "025_decision_chain.sql", 17)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("ON CONFLICT clause should reference (version, name): %v", err)
	}
}

// TestRecordMigrationFailure_CompositeConflict — same check for the
// failure path. Without the composite key, a failed 025_a would orphan
// a later 025_b that runs successfully (it would inherit success=false
// because the row's success column would be overwritten by whichever
// migration crashed first).
func TestRecordMigrationFailure_CompositeConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(`ON CONFLICT \(version, name\) DO UPDATE`).
		WithArgs("025", "hitl_oversight_queue", 42, "boom", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	recordMigrationFailure(db, "025", "025_hitl_oversight_queue.sql", errors.New("boom"), 42)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("failure path ON CONFLICT clause should reference (version, name): %v", err)
	}
}

// TestExtractMigrationVersionName_RoundTrip ensures the prefix + name
// helpers split the way the composite key expects. If a future refactor
// breaks the split, the dedup contract silently breaks too.
func TestExtractMigrationVersionName_RoundTrip(t *testing.T) {
	cases := []struct {
		filename    string
		wantVersion string
		wantName    string
	}{
		{"025_decision_chain.sql", "025", "decision_chain"},
		{"025_hitl_oversight_queue.sql", "025", "hitl_oversight_queue"},
		{"042_unified_execution_history.sql", "042", "unified_execution_history"},
		{"085_community_saas_bridge_pg_readonly.sql", "085", "community_saas_bridge_pg_readonly"},
	}
	for _, tc := range cases {
		v := extractMigrationVersion(tc.filename)
		n := extractMigrationName(tc.filename)
		if v != tc.wantVersion {
			t.Errorf("%s → version %q, want %q", tc.filename, v, tc.wantVersion)
		}
		if n != tc.wantName {
			t.Errorf("%s → name %q, want %q", tc.filename, n, tc.wantName)
		}
		if migrationKey(v, n) != migrationKey(tc.wantVersion, tc.wantName) {
			t.Errorf("%s round-trip mismatch: extract→%q, direct→%q",
				tc.filename, migrationKey(v, n), migrationKey(tc.wantVersion, tc.wantName))
		}
	}
}

// TestCoreMigrationDir_HasNoUnresolvableCollisions is the disk-walking
// regression guard. The composite key tolerates
// (025, decision_chain) + (025, hitl_oversight_queue) just fine, but
// (025, decision_chain) appearing TWICE on disk (e.g. via cherry-pick
// across worktrees, or two PRs racing the same name) would silently
// dedup against itself in production. Walk the actual migrations/
// directories and assert no duplicate composite keys exist.
//
// A previous version of this test iterated a hand-coded fixture array
// — that version was tautological because the fixture was hand-curated
// to be distinct. The on-disk walk catches NEW duplicates that the
// author didn't enumerate.
func TestCoreMigrationDir_HasNoUnresolvableCollisions(t *testing.T) {
	// Locate the repo root from THIS test file's path. test file is at
	// platform/agent/<this file>; repo root is two directories up.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed")
	}
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	migrationsRoot := filepath.Join(repoRoot, "migrations")

	// Categories the runner can include for any DEPLOYMENT_MODE. We walk
	// every one — same-key collisions across categories silently dedup
	// too (the composite key is per-file, not per-directory).
	categories := []string{
		"core",
		"enterprise",
		"community-saas",
		filepath.Join("industry", "healthcare"),
		filepath.Join("industry", "banking"),
		filepath.Join("industry", "travel"),
	}

	type origin struct {
		category string
		filename string
	}
	seen := make(map[string]origin)

	for _, cat := range categories {
		dir := filepath.Join(migrationsRoot, cat)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("ReadDir(%s): %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".sql") {
				continue
			}
			if strings.HasSuffix(name, "_down.sql") {
				continue
			}
			version := extractMigrationVersion(name)
			migName := extractMigrationName(name)
			key := migrationKey(version, migName)
			if prior, dup := seen[key]; dup {
				t.Errorf("DUPLICATE composite migration key %q:\n  first:  %s/%s\n  second: %s/%s\nIf both files run, the second silently dedups against the first because (version, name) is identical.",
					key, prior.category, prior.filename, cat, name)
			}
			seen[key] = origin{category: cat, filename: name}
		}
	}

	if len(seen) == 0 {
		t.Fatalf("walked migrations/ and found ZERO .sql files — test path resolution broken: %s", migrationsRoot)
	}
	t.Logf("scanned %d migration files across %d categories — no composite-key collisions", len(seen), len(categories))
}

// knownIntentionalVersionPairs lists same-version-different-name pairs that
// existed BEFORE the composite-key fix (PR #2249) and are tolerated by the
// runner. They are documented historical baggage from before this guard
// existed — the composite (version, name) UNIQUE on schema_migrations makes
// them functionally distinct rows. Any NEW same-version pair lands as an
// accidental collision (one of the v9 epic's three migration-numbering bugs
// — see Epic #2230) and must rename.
//
// Map shape: version → set of acceptable "name" values that may co-occur.
// To pre-approve a new pair would require deleting a row here; CI failure on
// PR open is the prompt to rename rather than allow-list.
var knownIntentionalVersionPairs = map[string]map[string]bool{
	"025": {
		"decision_chain":       true,
		"hitl_oversight_queue": true,
	},
	"042": {
		"singapore_pii_patterns":    true,
		"unified_execution_history": true,
	},
	"059": {
		"dangerous_command_policies":   true,
		"runtime_tables_to_migrations": true,
	},
	"076": {
		"community_saas_recovery_tokens":       true,
		"critical_system_policies_no_override": true,
	},
}

// TestCoreMigrationDir_HasNoVersionDuplicates is the structural cure for the
// migration-numbering bug class that the existing
// TestCoreMigrationDir_HasNoUnresolvableCollisions misses. The existing
// guard catches "same version AND same name" (the 025_decision_chain
// shadowing case from PR #2249). It does NOT catch "same version, different
// name" — which is the class that bit the v9 epic three times: two PRs each
// claiming the next-available number off origin/main without seeing the
// other's branch.
//
// Walked per-directory because cross-category overlaps are intentional (core
// migration 100 + enterprise migration 100 apply under different
// DEPLOYMENT_MODE values; see platform/agent/migration_helpers.go). The
// in-directory overlap is what's accidental.
//
// Pre-existing same-version-different-name pairs that predate the composite
// key fix live in knownIntentionalVersionPairs. Any NEW pair fails this
// test with both filenames named in the message + an Epic #2230 reference
// so the next session sees the context.
func TestCoreMigrationDir_HasNoVersionDuplicates(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed")
	}
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	migrationsRoot := filepath.Join(repoRoot, "migrations")

	categories := []string{
		"core",
		"enterprise",
		"community-saas",
		filepath.Join("industry", "healthcare"),
		filepath.Join("industry", "banking"),
		filepath.Join("industry", "travel"),
	}

	totalFiles := 0
	for _, cat := range categories {
		dir := filepath.Join(migrationsRoot, cat)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("ReadDir(%s): %v", dir, err)
		}

		// version → list of filenames at that version in THIS directory
		byVersion := make(map[string][]string)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".sql") {
				continue
			}
			if strings.HasSuffix(name, "_down.sql") {
				continue
			}
			version := extractMigrationVersion(name)
			byVersion[version] = append(byVersion[version], name)
			totalFiles++
		}

		for version, files := range byVersion {
			if len(files) < 2 {
				continue
			}
			// Sort for stable failure message ordering.
			sort.Strings(files)

			// Tolerate the historical allowlist — but ONLY if every file at
			// this version is in the allowlist. A mix of allowlisted-and-not
			// at the same version is a new collision against a historical
			// pair, which is still bad.
			allowed := knownIntentionalVersionPairs[version]
			allKnown := allowed != nil
			if allKnown {
				for _, f := range files {
					if !allowed[extractMigrationName(f)] {
						allKnown = false
						break
					}
				}
			}
			if allKnown {
				continue
			}

			var lines strings.Builder
			for _, f := range files {
				lines.WriteString("  - ")
				lines.WriteString(cat)
				lines.WriteString("/")
				lines.WriteString(f)
				lines.WriteString("\n")
			}
			t.Errorf("DUPLICATE migration version %q in %s/ — %d files share this prefix:\n%s"+
				"Files in the same migration directory share a version prefix. The composite\n"+
				"(version, name) key in schema_migrations tolerates this at runtime, but apply order\n"+
				"is non-deterministic across runs and the runner cannot reason about dependencies\n"+
				"between same-version files. Rename whichever migration must run LATER to the next\n"+
				"available version.\n"+
				"Context: third migration-numbering bug in the v9 epic — Epic #2230.",
				version, cat, len(files), lines.String())
		}
	}

	if totalFiles == 0 {
		t.Fatalf("walked migrations/ and found ZERO .sql files — test path resolution broken: %s", migrationsRoot)
	}
}
