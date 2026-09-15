// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/registry"
	"axonflow/platform/testutil"
)

// THE MIGRATIONS SEED ONLY THE SHIPPED POLICIES, IN EVERY MODE (#4126 D4b)
//
// The id half of TestDetectorCensusMatchesTheMigratedDatabase, restated on the
// pull-request tier and per deployment mode. The census test compares a
// core-only capture; each mode applies a different migration set, so a row an
// enterprise or industry migration seeds is invisible to it.
// TestMigrationChainAppliesCleanly_RealPostgres already builds a fresh database
// per mode, and holds the ids there to the shipped census, both ways, with no
// exemption: the banking vertical's rows are policy packs since #4141, and
// migration industry/banking/402 retires the rows it once seeded.

// shippedStaticPolicyIDs are the ids the shipped census carries.
func shippedStaticPolicyIDs(t *testing.T) map[string]bool {
	t.Helper()
	rows, err := registry.ShippedCensus()
	if err != nil {
		t.Fatalf("reading the shipped census: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("the shipped census is empty; a comparison against it is not evidence")
	}
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		out[r.PolicyID] = true
	}
	return out
}

// seededPolicyIDs reads every static_policies id a migrated database carries.
func seededPolicyIDs(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.Query(`SELECT policy_id FROM static_policies`)
	if err != nil {
		t.Fatalf("reading static_policies: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scanning static_policies: %v", err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading static_policies: %v", err)
	}
	return out
}

// seededPolicyIDFailures holds every mode's migrated ids to the shipped census,
// both ways. It returns one message per defect, in mode order.
func seededPolicyIDFailures(seeded map[string]map[string]bool, shipped map[string]bool) []string {
	modes := make([]string, 0, len(seeded))
	for mode := range seeded {
		modes = append(modes, mode)
	}
	sort.Strings(modes)
	var failures []string
	for _, mode := range modes {
		ids := seeded[mode]
		var extra, missing []string
		for id := range ids {
			if !shipped[id] {
				extra = append(extra, id)
			}
		}
		for id := range shipped {
			if !ids[id] {
				missing = append(missing, id)
			}
		}
		sort.Strings(extra)
		sort.Strings(missing)
		if len(extra) > 0 {
			failures = append(failures, fmt.Sprintf("DEPLOYMENT_MODE %q: %d static_policies row(s) seeded that the census does not ship: %v. "+
				"A shipped row is in platform/decision/registry/detectors_census.tsv; a pack is a typed document (PRD v11 §1.9)",
				mode, len(extra), extra))
		}
		if len(missing) > 0 {
			failures = append(failures, fmt.Sprintf("DEPLOYMENT_MODE %q: %d census row(s) the chain did not seed: %v", mode, len(missing), missing))
		}
	}
	return failures
}

// assertSeededPolicyIDsAreShipped reports every defect seededPolicyIDFailures finds.
func assertSeededPolicyIDsAreShipped(t *testing.T, seeded map[string]map[string]bool) {
	t.Helper()
	for _, f := range seededPolicyIDFailures(seeded, shippedStaticPolicyIDs(t)) {
		t.Error(f)
	}
}

// The check is proved to red. A migration planted in core, which every mode
// applies, seeds a row the census does not ship; the real chain runs it, and the
// check refuses that row and nothing else. The same ids then drive the other
// direction: a census row a mode did not seed reds too.
func TestTheSeededPolicyIDCheckRedsOnAPlantedMigration_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	source, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	planted := t.TempDir()
	err = filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(planted, rel), 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(planted, rel), b, 0o644)
	})
	if err != nil {
		t.Fatalf("copying the migrations: %v", err)
	}
	// A copy of a shipped row under an id nobody shipped: every column comes
	// from the row, so the plant holds whatever constraints later migrations add.
	plant := `INSERT INTO static_policies
SELECT (jsonb_populate_record(NULL::static_policies,
        to_jsonb(s) || jsonb_build_object('id', uuid_generate_v4(), 'policy_id', 'd4b_planted_row'))).*
FROM static_policies s WHERE s.policy_id = 'sys_dangerous_destructive_fs';
`
	if err := os.WriteFile(filepath.Join(planted, "core", "999_d4b_planted_row.sql"), []byte(plant), 0o644); err != nil {
		t.Fatal(err)
	}

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	t.Setenv("DEPLOYMENT_MODE", "community")
	applyChain(t, pc.DB, planted)
	got := seededPolicyIDs(t, pc.DB)
	shipped := shippedStaticPolicyIDs(t)

	failures := seededPolicyIDFailures(map[string]map[string]bool{"community": got}, shipped)
	if len(failures) != 1 || !strings.Contains(failures[0], `"community"`) || !strings.Contains(failures[0], "[d4b_planted_row]") {
		t.Fatalf("failures for a planted core migration = %q, want exactly one, naming d4b_planted_row in community", failures)
	}

	short := map[string]bool{}
	for id := range shipped {
		if id != "sys_dangerous_destructive_fs" {
			short[id] = true
		}
	}
	if f := seededPolicyIDFailures(map[string]map[string]bool{"community": short}, shipped); len(f) != 1 || !strings.Contains(f[0], "did not seed: [sys_dangerous_destructive_fs]") {
		t.Errorf("with a census row missing from community, failures = %q, want the one that names it", f)
	}
}
