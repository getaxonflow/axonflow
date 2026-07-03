// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"os"
	"testing"
)

// TestMigration139_StringTermComment_RealPostgres proves migration 139
// (#2811) against a REAL Postgres with the full core migration chain applied:
// the new sys_sqli_string_term_comment detector catches the OWASP comment-out
// authentication bypass (admin' --) that previously passed clean through every
// governed input plane, WITHOUT re-admitting the documentation-prose FP class
// migrations 135 hardened against.
//
// Layers (the migration-135 methodology):
//  1. Gap reproduction, red-on-revert — with the 139 down applied, the
//     comment-out payloads match NO enabled security-sqli/dangerous/admin
//     policy (the v9.3.1 gap); after up, every payload matches the new row.
//  2. Own-pattern TP/FP — the live seeded pattern matches the payload corpus
//     and none of the prose corpus.
//  3. FULL-CLASS FP — every prose string is run through EVERY enabled
//     security-sqli / security-dangerous / security-admin pattern (what the
//     real request-phase evaluator does), asserting no sibling matches it.
//  4. Row shape — the seeded enforcement fields mirror the post-124
//     security-sqli family posture (warn base + warn phase actions).
//  5. Idempotency + down/up round-trip.
func TestMigration139_StringTermComment_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres migration-139 test")
	}

	dsn, cleanup := startCountTestPostgres(t)
	t.Cleanup(cleanup)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	for _, kv := range []struct{ key, val string }{
		{"app.db_password", "testpass"},
		{"app.deployment_org_id", "local-dev-org"},
		{"app.deployment_kind", "dev"},
		{"app.current_org_id", "local-dev-org"},
	} {
		if _, err := db.Exec("SELECT set_config($1, $2, false)", kv.key, kv.val); err != nil {
			t.Fatalf("set_config %s: %v", kv.key, err)
		}
	}

	applyAllCoreMigrations(t, db, "../../migrations/core")

	const policyID = "sys_sqli_string_term_comment"

	// The comment-out payload corpus: a string-literal terminator directly
	// followed by a SQL line comment that ends the line.
	tps := []string{
		`admin' --`,
		`x'--`,
		`x'#`,
		`admin'-- -`, // MySQL-safe variant (space + dash after the comment)
		`admin'---`,  // multi-dash, no space
		`admin" --`,
		`admin') --`,
		"admin' -- ",
		"first line\nadmin' --\nlast line",
	}
	// The benign corpus: prose that continues after the comment (or has no
	// breakout quote), PLUS balanced-quote shell/SQL/code lines carrying a
	// trailing EMPTY comment. The latter run on EXECUTION connectors that
	// capability scoping does NOT remove, so the pattern itself — not scoping —
	// must exclude them (the first-quote breakout gate). None may match ANY
	// enabled policy.
	fps := []string{
		`she said 'stop' -- then left the room`,
		`The vulnerable clause reads WHERE account='admin'--' so always parameterize inputs.`,
		"| Step | Owner |\n|---|---|\n| Enable | Platform |",
		"Intro paragraph.\n\n---\n\nNext section.",
		`it's #1 priority for the team`,
		`the employees' #standup channel`,
		`filter rows by name = 'x' -- only the active ones`,
		`set the badge color to '#ff0000' in settings`,
		"run the migration --\nthen verify",
		// Balanced-quote token + trailing empty comment on an execution plane:
		`echo 'done'  #`,
		`git commit -m 'wip' #`,
		`SELECT count(*) FROM t WHERE region='EU' --`,
		`print('hello')  #`,
	}

	// --- Layer 1: gap reproduction (red-on-revert). ---
	downSQL, err := os.ReadFile("../../migrations/core/139_sqli_string_term_comment_down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	upSQL, err := os.ReadFile("../../migrations/core/139_sqli_string_term_comment.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}

	if _, err := db.Exec(string(downSQL)); err != nil {
		t.Fatalf("apply down migration: %v", err)
	}
	preFix := loadEnabledClassPatterns(t, db, "security-sqli", "security-dangerous", "security-admin")
	for _, s := range tps {
		if hit := firstClassMatch(preFix, s); hit != "" {
			t.Errorf("gap reproduction broken: %q already matches enabled policy %q without migration 139 — the detector is redundant or the corpus is wrong", s, hit)
		}
	}
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("re-apply up migration: %v", err)
	}

	// --- Layer 2: own-pattern TP/FP against the live seeded pattern. ---
	assertGlobalPattern(t, db, policyID, tps, fps)

	// --- Layer 3: FULL-CLASS — no enabled sibling matches the prose corpus;
	// --- every payload now matches at least one enabled policy. ---
	classPatterns := loadEnabledClassPatterns(t, db, "security-sqli", "security-dangerous", "security-admin")
	for _, s := range fps {
		if hit := firstClassMatch(classPatterns, s); hit != "" {
			t.Errorf("FULL-CLASS FP: %q is matched by enabled policy %q", s, hit)
		}
	}
	for _, s := range tps {
		if firstClassMatch(classPatterns, s) == "" {
			t.Errorf("FULL-CLASS TP: %q is matched by NO enabled policy — migration 139 did not close the gap", s)
		}
	}

	// --- Layer 4: row shape mirrors the post-124 family posture. ---
	var category, tier, severity, action, phase, actionRequest, actionResponse string
	var priority int
	var enabled bool
	if err := db.QueryRow(
		`SELECT category, tier, severity, action, phase, action_request, action_response, priority, enabled
		 FROM static_policies WHERE policy_id = $1 AND tenant_id = 'global'`,
		policyID).Scan(&category, &tier, &severity, &action, &phase, &actionRequest, &actionResponse, &priority, &enabled); err != nil {
		t.Fatalf("read %s row: %v", policyID, err)
	}
	if category != "security-sqli" || tier != "system" || severity != "high" ||
		action != "warn" || phase != "both" || actionRequest != "warn" || actionResponse != "warn" ||
		priority != 90 || !enabled {
		t.Errorf("%s row = category:%s tier:%s severity:%s action:%s phase:%s action_request:%s action_response:%s priority:%d enabled:%v; want security-sqli/system/high/warn/both/warn/warn/90/true (post-124 family posture)",
			policyID, category, tier, severity, action, phase, actionRequest, actionResponse, priority, enabled)
	}

	// --- Layer 5: idempotency (second up is a no-op) + down removes. ---
	seededPattern := readGlobalPattern(t, db, policyID)
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("re-apply up migration (idempotency): %v", err)
	}
	var rowCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM static_policies WHERE policy_id = $1`, policyID).Scan(&rowCount); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rowCount != 1 {
		t.Errorf("idempotency: %d rows for %s after double-apply, want 1", rowCount, policyID)
	}
	if got := readGlobalPattern(t, db, policyID); got != seededPattern {
		t.Errorf("idempotency: pattern changed on re-apply\n got: %s\nwant: %s", got, seededPattern)
	}
	if _, err := db.Exec(string(downSQL)); err != nil {
		t.Fatalf("apply down migration (final): %v", err)
	}
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM static_policies WHERE policy_id = $1`, policyID).Scan(&rowCount); err != nil {
		t.Fatalf("count rows after down: %v", err)
	}
	if rowCount != 0 {
		t.Errorf("down migration left %d rows for %s, want 0", rowCount, policyID)
	}
	// Restore the migrated end-state so later assertions in other tests that
	// share a fresh DB per test are unaffected (belt and suspenders — each test
	// provisions its own container, but the chain should end migrated).
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("final re-apply up migration: %v", err)
	}
}
