// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/testutil"
)

// TestMigration179DeletesOnlyThePristineInertSensitiveDataControl_RealPostgres
// proves core/179 in both directions: it deletes the 010 seed while that seed
// is untouched, and it keeps the row on an edit to ANY column its predicate
// compares.
//
// The keep-cases are the ones that matter. A predicate that is too loose passes
// the delete-case just as well as a correct one, and the failure it causes is a
// customer's edited redaction silently deleted on upgrade. So there is one case
// per compared column, and the case list is held to the migration's own
// predicate: every `dp.<column>` the up migration reads must have a case, or
// the test fails before any database work. A column added to the predicate
// without a case, or a case whose column the predicate stopped reading, is red.
func TestMigration179DeletesOnlyThePristineInertSensitiveDataControl_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(migrationsPath, "core", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(b)
	}
	upSQL := read("179_delete_inert_sensitive_data_control.sql")
	downSQL := read("179_delete_inert_sensitive_data_control_down.sql")

	const where = ` WHERE policy_id = 'sensitive_data_control'`
	type keepCase struct {
		// column is the dp.<column> the case varies, empty for a case about
		// something other than the row's own columns.
		column, name, edit, revert string
	}
	set := func(column, name, edited, seeded string) keepCase {
		return keepCase{
			column: column, name: name,
			edit:   `UPDATE dynamic_policies SET ` + column + ` = ` + edited + where,
			revert: `UPDATE dynamic_policies SET ` + column + ` = ` + seeded + where,
		}
	}
	const superseder = ` WHERE policy_id = 'sys_dyn_sensitive_data'`
	// sup varies one column the superseder check reads; its column is recorded as
	// "s.<column>", the alias the migration reads it through.
	sup := func(column, name, edited, seeded string) keepCase {
		return keepCase{
			column: "s." + column, name: "its superseder " + name,
			edit:   `UPDATE dynamic_policies SET ` + column + ` = ` + edited + superseder,
			revert: `UPDATE dynamic_policies SET ` + column + ` = ` + seeded + superseder,
		}
	}
	cases := []keepCase{
		set("tenant_id", "moved to a tenant", `'acme'`, `'global'`),
		set("name", "renamed", `'Control Sensitive Data Access (edited)'`, `'Control Sensitive Data Access'`),
		set("description", "re-described", `'edited'`, `'Redact sensitive data fields in responses'`),
		set("policy_type", "retyped", `'risk_based'`, `'context_aware'`),
		set("risk_threshold", "re-thresholded", `0.60`, `0.50`),
		set("conditions", "its condition corrected, so it can match",
			`'[{"field": "query", "operator": "contains_any", "value": ["salary"]}]'::jsonb`,
			`'[{"field": "query", "operator": "contains", "value": "salary|ssn|medical_record"}]'::jsonb`),
		set("actions", "its action changed",
			`'[{"type": "block"}]'::jsonb`,
			`'[{"type": "redact", "config": {"fields": ["salary", "ssn", "medical_record"]}}]'::jsonb`),
		set("priority", "re-prioritised", `901`, `900`),
		set("enabled", "disabled by somebody", `false`, `true`),
		set("category", "categorised", `'dynamic-access'`, `NULL`),
		set("version", "version bumped", `2`, `1`),
		set("created_by", "attributed to a creator", `'someone'`, `NULL`),
		set("updated_by", "attributed to an editor", `'someone'`, `NULL`),
		set("deleted_at", "soft-deleted", `NOW()`, `NULL`),
		set("metadata", "annotated", `'{"edited": true}'::jsonb`, `'{}'::jsonb`),
		set("tags", "tagged", `'["edited"]'::jsonb`, `'[]'::jsonb`),
		set("segment_id", "segment-scoped", `'segment-1'`, `NULL`),
		// 'high', not 'critical': migration 070's trigger forces
		// allow_override=false on a critical row, and the revert below would not
		// undo that.
		set("risk_level", "re-risked", `'high'`, `'medium'`),
		set("allow_override", "made non-overridable", `false`, `true`),
		{
			// The import-overwrite path (PolicyRepository.updatePolicyTx) bumps
			// version and sets updated_by, and writes NO policy_versions row -
			// so for that edit these two columns are the whole guard.
			name:   "overwritten by an import",
			edit:   `UPDATE dynamic_policies SET version = version + 1, updated_by = 'import'` + where,
			revert: `UPDATE dynamic_policies SET version = 1, updated_by = NULL` + where,
		},
		{
			name:   "carrying version history, which the cascade would destroy",
			edit:   `INSERT INTO policy_versions (policy_id, version, snapshot, change_type) VALUES ('sensitive_data_control', 2, '{}'::jsonb, 'update')`,
			revert: `DELETE FROM policy_versions WHERE policy_id = 'sensitive_data_control'`,
		},
		sup("enabled", "disabled", `false`, `true`),
		sup("deleted_at", "soft-deleted", `NOW()`, `NULL`),
		sup("tenant_id", "moved to a tenant", `'acme'`, `'global'`),
		sup("segment_id", "segment-scoped", `'segment-1'`, `NULL`),
		sup("conditions", "with its condition narrowed",
			`'[{"field": "query", "operator": "contains_any", "value": ["salary"]}]'::jsonb`,
			`'[{"field": "query", "operator": "contains_any", "value": ["salary", "ssn", "medical_record"]}]'::jsonb`),
		// The case "no decision changes" rests on: a superseder that logs instead of
		// redacting leaves the seed as its input's only redaction.
		sup("actions", "logging instead of redacting",
			`'[{"type": "log"}]'::jsonb`,
			`'[{"type": "redact", "config": {"fields": ["salary", "ssn", "medical_record"]}}]'::jsonb`),
		{
			column: "s.policy_id", name: "its superseder absent",
			edit:   `CREATE TEMP TABLE superseder_179 AS SELECT * FROM dynamic_policies` + superseder + `; DELETE FROM dynamic_policies` + superseder,
			revert: `INSERT INTO dynamic_policies SELECT * FROM superseder_179; DROP TABLE superseder_179`,
		},
	}

	// 0. The case list against the predicate, before any database work: every
	//    column the seed's conjuncts read (dp.<column>), and every column the
	//    superseder check reads (s.<column>, recorded as "s.<column>").
	predicate := map[string]bool{}
	for _, m := range regexp.MustCompile(`\bdp\.([a-z_]+)`).FindAllStringSubmatch(upSQL, -1) {
		if m[1] != "policy_id" {
			predicate[m[1]] = true
		}
	}
	for _, m := range regexp.MustCompile(`\bs\.([a-z_]+)`).FindAllStringSubmatch(upSQL, -1) {
		predicate["s."+m[1]] = true
	}

	// pristineSQL counts the rows migration 179's own DELETE selects, read from the
	// migration rather than restated. Each keep-case must start from exactly one
	// and its own edit must take that to zero, so a case cannot pass on a
	// leftover from the case before it.
	deleteStmt := regexp.MustCompile(`(?s)DELETE FROM dynamic_policies dp\s+WHERE.*?\);`).FindString(upSQL)
	if deleteStmt == "" {
		t.Fatal("cannot find migration 179's DELETE FROM dynamic_policies dp ... ; statement")
	}
	pristineSQL := "SELECT COUNT(*) FROM dynamic_policies dp" + strings.TrimSuffix(strings.TrimPrefix(deleteStmt, "DELETE FROM dynamic_policies dp"), ";")
	covered := map[string]bool{}
	for _, tc := range cases {
		if tc.column != "" {
			covered[tc.column] = true
		}
	}
	var uncovered, stale []string
	for c := range predicate {
		if !covered[c] {
			uncovered = append(uncovered, c)
		}
	}
	for c := range covered {
		if !predicate[c] {
			stale = append(stale, c)
		}
	}
	sort.Strings(uncovered)
	sort.Strings(stale)
	if len(predicate) == 0 || len(uncovered) > 0 || len(stale) > 0 {
		t.Fatalf("the keep-cases do not match migration 179's predicate: %d column(s) read, uncovered %v, cases for columns it does not read %v",
			len(predicate), uncovered, stale)
	}

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	t.Setenv("DEPLOYMENT_MODE", "community")
	db := pc.DB

	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	exec := func(q string) {
		t.Helper()
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("exec: %v\n%s", err, q)
		}
	}
	present := func() bool {
		return count(`SELECT COUNT(*) FROM dynamic_policies WHERE policy_id = 'sensitive_data_control'`) == 1
	}

	// 1. The pre-179 world, and its premise: the seed is there, untouched, and
	//    so is its working superseder. Without both the assertions below would
	//    be about a row that does not exist.
	if ran, _ := applyChainUpTo(t, db, migrationsPath, 179); ran == 0 {
		t.Fatal("applied 0 migrations before the cutoff; the premise below would be meaningless")
	}
	if !present() {
		t.Fatal("sensitive_data_control is absent before migration 179; 010 no longer seeds it or an earlier migration removed it")
	}
	if n := count(`SELECT COUNT(*) FROM dynamic_policies WHERE policy_id = 'sys_dyn_sensitive_data' AND enabled`); n != 1 {
		t.Fatalf("sys_dyn_sensitive_data enabled rows before 179 = %d, want 1", n)
	}
	var category sql.NullString
	if err := db.QueryRow(`SELECT category FROM dynamic_policies WHERE policy_id = 'sensitive_data_control'`).Scan(&category); err != nil {
		t.Fatalf("read category: %v", err)
	}
	if category.Valid {
		t.Fatalf("sensitive_data_control carries category %q before 179; the row is no longer the pristine 010 seed this migration deletes", category.String)
	}

	// 2. Every edit keeps the row. Each is applied, the up migration runs, the
	//    row must survive, and the edit is reverted so the next case starts from
	//    the pristine seed again.
	for _, tc := range cases {
		if n := count(pristineSQL); n != 1 {
			t.Fatalf("%s: migration 179's predicate selects %d row(s) before the edit, want 1: an earlier revert did not restore the seed or its superseder", tc.name, n)
		}
		exec(tc.edit)
		if n := count(pristineSQL); n != 0 {
			t.Fatalf("%s: after the edit the predicate still selects %d row(s); the case does not exercise what it names", tc.name, n)
		}
		exec(upSQL)
		if !present() {
			t.Fatalf("%s: migration 179 deleted sensitive_data_control; only the untouched 010 seed may go", tc.name)
		}
		exec(tc.revert)
	}

	// 3. The pristine seed, through the REAL runner: deleted, and nothing else.
	//    This is also the control for step 2: had a revert failed to restore the
	//    seed, the row would survive here and the test would say so.
	dynamicBefore := count(`SELECT COUNT(*) FROM dynamic_policies`)
	versionsBefore := count(`SELECT COUNT(*) FROM policy_versions`)
	applyChain(t, db, migrationsPath)
	if present() {
		t.Fatal("migration 179 left the pristine 010 seed in place")
	}
	if got := count(`SELECT COUNT(*) FROM dynamic_policies`); got != dynamicBefore-1 {
		t.Errorf("dynamic_policies holds %d rows after 179, want %d: the delete reached a row other than the seed", got, dynamicBefore-1)
	}
	if got := count(`SELECT COUNT(*) FROM policy_versions`); got != versionsBefore {
		t.Errorf("policy_versions holds %d rows after 179, want %d: the cascade removed history", got, versionsBefore)
	}
	if n := count(`SELECT COUNT(*) FROM dynamic_policies WHERE policy_id = 'sys_dyn_sensitive_data' AND enabled`); n != 1 {
		t.Errorf("sys_dyn_sensitive_data enabled rows after 179 = %d, want 1", n)
	}

	// 4. Idempotent, and the down restores the seed's content - including the
	//    client_id migration 090 backfilled - which the up then recognises as
	//    pristine again.
	exec(upSQL)
	exec(downSQL)
	if !present() {
		t.Fatal("the down migration did not restore sensitive_data_control")
	}
	if n := count(`SELECT COUNT(*) FROM dynamic_policies
		WHERE policy_id = 'sensitive_data_control' AND enabled AND category IS NULL
		  AND tenant_id = 'global' AND client_id = 'global' AND org_id = 'global'
		  AND risk_level = 'medium' AND allow_override
		  AND conditions = '[{"field": "query", "operator": "contains", "value": "salary|ssn|medical_record"}]'::jsonb`); n != 1 {
		t.Error("the down migration restored a row whose content is not the seed's: tenant, client, org, risk level, override or condition differs")
	}
	exec(downSQL)
	exec(upSQL)
	if present() {
		t.Error("the up migration did not recognise the row its own down restored")
	}
}
