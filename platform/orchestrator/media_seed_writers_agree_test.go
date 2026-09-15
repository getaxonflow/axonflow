// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ONE WRITER AND ONE CHECKER, AND NOTHING HELD THEM EQUAL (#3884, #3957, #4026)
//
// The five `sys_media_*` governance controls are written by
// `migrations/core/173_seed_system_media_policies.sql`, which #3962 added, and
// checked at every boot by `verifySystemMediaPolicies` in this package, whose
// expectation set is the `systemMediaPolicies` table below.
//
// UNTIL #4026 THERE WERE TWO WRITERS. The boot path INSERTed the same five rows
// with `ON CONFLICT (policy_id) DO NOTHING` — idempotent and safe, and exactly
// the configuration where two writers drift: the first to reach a fresh database
// wins and the other's rows are silently discarded. core/172 then made that
// INSERT impossible for the application role, so it became a refused write in
// the boot log rather than a competing writer, and #4026 turned it into a read.
//
// THE EQUALITY STILL MATTERS, FOR A DIFFERENT REASON. The boot check reports at
// ERROR when a row it expects is absent. If its expectation set and the
// migration disagree, that check either shouts about a row the platform never
// seeds or stays silent about one it does — so the two must still be held equal,
// field by field, in both directions.
//
// WHAT THIS TEST USED TO BE, AND WHY IT CHANGED. Until #3962 these rows existed
// in no migration at all, so `platform/decision/registry` carried them as a
// checked-in inventory and this test held that inventory equal to the seeder.
// The inventory is deleted - its own REVISIT WHEN said "on the day a migration
// seeds these rows, this file is the thing to delete" - and the equality that
// still matters is between the two writers that remain.
//
// IT PARSES THE SQL RATHER THAN EXECUTING IT, so it runs on every tier
// including the one with no database. The arm that would execute it,
// `Unit Tests: Enterprise-Tagged + Real-PG`, fires on `merge_group` and
// `workflow_dispatch` only, and master admin-merges - so it effectively never
// runs. A guard that only fires on a trigger our own merge practice bypasses is
// not a guard, which is exactly why this one does not need a database.

// mediaSeedMigration is the migration that seeds the same rows this package's
// boot path does.
const mediaSeedMigration = "migrations/core/173_seed_system_media_policies.sql"

// mediaSeedRow is one row as the migration declares it.
type mediaSeedRow struct {
	policyID    string
	name        string
	description string
	category    string
	conditions  string
	actions     string
	priority    int
	tier        string
	enabled     string
}

func TestTheMediaSeedMigrationAndTheBootSeederWriteTheSameRows(t *testing.T) {
	migration := parseMediaSeedMigration(t)

	// Anti-vacuity in both directions. An empty parse and an emptied seeder
	// each make every loop below compare nothing, and an emptied seeder is one
	// of the two states this test exists to catch.
	if len(migration) == 0 {
		t.Fatal("the migration parsed to zero rows; either its INSERT changed shape or this parse is reading the wrong file")
	}
	if len(systemMediaPolicies) == 0 {
		t.Fatal("the boot seeder writes no policy")
	}

	seeded := map[string]systemMediaPolicy{}
	for _, p := range systemMediaPolicies {
		seeded[p.policyID] = p
	}

	var onlySeeder, onlyMigration []string
	for id := range seeded {
		if _, ok := migration[id]; !ok {
			onlySeeder = append(onlySeeder, id)
		}
	}
	for id := range migration {
		if _, ok := seeded[id]; !ok {
			onlyMigration = append(onlyMigration, id)
		}
	}
	sort.Strings(onlySeeder)
	sort.Strings(onlyMigration)
	if len(onlySeeder) > 0 {
		t.Errorf("%d row(s) the boot seeder writes are absent from %s: %v\n"+
			"A deployment that is migrated and never boots would not have them.", len(onlySeeder), mediaSeedMigration, onlySeeder)
	}
	if len(onlyMigration) > 0 {
		t.Errorf("%d row(s) in %s are not written by the boot seeder: %v\n"+
			"Harmless while the migration reaches the database first, and a divergence the moment either writer changes alone.",
			len(onlyMigration), mediaSeedMigration, onlyMigration)
	}

	// Field by field. A set comparison on identifiers alone would pass while
	// the two writers disagreed about a condition, an action or a category -
	// and the category is read by the compliance-inventory path, so a
	// divergence there is not cosmetic.
	for id, p := range seeded {
		m, ok := migration[id]
		if !ok {
			continue
		}
		eqField(t, id, "name", m.name, p.name)
		eqField(t, id, "description", m.description, p.description)
		eqField(t, id, "category", m.category, p.category)
		eqField(t, id, "priority", strconv.Itoa(m.priority), strconv.Itoa(p.priority))
		eqJSONField(t, id, "conditions", m.conditions, p.conditions)
		eqJSONField(t, id, "actions", m.actions, p.actions)
		// The two literals that decide whether the row is part of the
		// platform's own immutable corpus at all. The seeder sets them as
		// literals in its INSERT rather than carrying them as fields, so they
		// are checked against the migration's rather than against a struct.
		eqField(t, id, "tier", m.tier, "system")
		eqField(t, id, "enabled", m.enabled, "true")
	}
	t.Logf("held %d media control(s) equal between %s and the boot seeder, field by field, in both directions",
		len(seeded), mediaSeedMigration)
}

// mediaSeedTuple matches one VALUES tuple of the migration's INSERT.
//
// It reads POSITIONALLY, which is only safe because parseMediaSeedMigration
// asserts the declared column order first. A migration that reorders its
// columns then fails loudly instead of comparing the wrong two fields.
var mediaSeedTuple = regexp.MustCompile(
	`\('([^']*)', '([^']*)', '([^']*)', '([^']*)', '([^']*)', '([^']*)', ` +
		`'(\[.*?\])'::jsonb, '(\[.*?\])'::jsonb, ` +
		`'([^']*)', '([^']*)', '([^']*)', (\d+), (true|false)`)

// mediaSeedColumns is the column list the positional parse depends on.
var mediaSeedColumns = []string{
	"policy_id", "name", "description", "policy_type", "category", "tier",
	"conditions", "actions", "tenant_id", "client_id", "org_id", "priority", "enabled",
}

func parseMediaSeedMigration(t *testing.T) map[string]mediaSeedRow {
	t.Helper()
	root := repoRootFromOrchestrator(t)
	b, err := os.ReadFile(filepath.Join(root, mediaSeedMigration))
	if err != nil {
		t.Fatalf("reading %s: %v; #3962 added it and this test compares the boot seeder against it", mediaSeedMigration, err)
	}
	flat := strings.Join(strings.Fields(string(b)), " ")

	declared := strings.Join(mediaSeedColumns, ", ")
	if !strings.Contains(flat, declared) {
		t.Fatalf("%s does not declare its columns as %q; the positional parse below would compare the wrong fields",
			mediaSeedMigration, declared)
	}

	out := map[string]mediaSeedRow{}
	for _, m := range mediaSeedTuple.FindAllStringSubmatch(flat, -1) {
		p, err := strconv.Atoi(m[12])
		if err != nil {
			t.Fatalf("%s: priority %q is not a number", m[1], m[12])
		}
		out[m[1]] = mediaSeedRow{
			policyID: m[1], name: m[2], description: m[3], category: m[5], tier: m[6],
			conditions: m[7], actions: m[8], priority: p, enabled: m[13],
		}
	}
	return out
}

func eqField(t *testing.T, id, col, migration, seeder string) {
	t.Helper()
	if migration != seeder {
		t.Errorf("%s: %s is %q in %s and %q in the boot seeder", id, col, migration, mediaSeedMigration, seeder)
	}
}

// eqJSONField compares two JSON documents by VALUE rather than by text: the two
// writers format them differently and a byte comparison would fail on
// whitespace alone, which is a failure nobody can act on.
func eqJSONField(t *testing.T, id, col, migration, seeder string) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal([]byte(migration), &a); err != nil {
		t.Errorf("%s: %s does not parse in %s: %v", id, col, mediaSeedMigration, err)
		return
	}
	if err := json.Unmarshal([]byte(seeder), &b); err != nil {
		t.Errorf("%s: the boot seeder's %s is not valid JSON: %v", id, col, err)
		return
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Errorf("%s: %s differs.\n  migration: %s\n  seeder:    %s", id, col, ja, jb)
	}
}

func repoRootFromOrchestrator(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "migrations", "core")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the repository root from the orchestrator package")
	return ""
}
