// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres test pinning the MIGRATED system-policy count (#2696).
//
// CORRECTED 2026-09-09 (#3884, from the #3957 audit). This header used to say
// "System-level policies live ONLY in the SQL migrations — there is no Go-side
// seed any longer". That premise is FALSE, and the sentence was load bearing:
// it is why nobody noticed that this test cannot see part of the population it
// appears to count.
//
// What is true is narrower. platform/agent/system_policies_seed.go was indeed
// deleted, and it was indeed dead. But the ORCHESTRATOR seeds five sys_media_*
// governance policies at boot, with this test's own predicate
// (tier='system', enabled=true), and no migration creates them —
// migrations/core/153's down file excludes them by name as "the Go seeder's".
// So this test applies migrations WITHOUT booting and counts 10 system-tier
// dynamic policies, while a BOOTED deployment holds 15.
//
// CORRECTED AGAIN 2026-09-10, and the correction is that the gap CLOSED.
// #3962 added migrations/core/173_seed_system_media_policies.sql, which seeds
// those five rows with this test's own predicate - so a migrated database and
// a booted one now hold the same set, and the delta this header described no
// longer exists. The test that pinned it
// (TestTheMigratedSystemDynamicCountIsNotTheBootedOne) is retired with it; what
// still matters is that the two WRITERS agree, which
// TestTheMediaSeedMigrationAndTheBootSeederWriteTheSameRows holds in
// platform/orchestrator without needing a database.
//
// THE CONSEQUENCE THIS HEADER LEFT RED-IN-WAITING HAS BEEN RESOLVED, BY THE
// LANE IT POINTED AT. While this branch was open, wantSystemDynamicEnabled
// still said 10 while migrations/core/173 seeded five more, so a fresh
// migrated database held 15 against an assertion of 10. That was deliberate:
// the number is PUBLISHED - README.md and docs/ARCHITECTURE.md both stated
// "80 built-in system policies (70 pattern-based, 10 condition-based)" and
// both cite this file by name as the pin - so moving 80 to 85 is a product
// statement about whether those five are part of the immutable corpus a
// customer cannot remove, and two PRs must not move one constant.
//
// #3970 carried it: the operator ruled 80 -> 85 correct for v11 (the five rows
// survive a delete and a restart, so they ARE the immutable corpus and the
// published figure was wrong before any of this), and #3970 moved the
// constants and swept the documentation. The constants below now read 15 and
// 85, and they are NOT this branch's to move - it asserts against them.
//
// This test stands up a fresh enterprise DB, applies every core migration in
// the production composite-key order, and asserts the seeded system-policy
// count — by policy_type, category, and enabled — equals the documented
// constants below. It is RED-ON-REVERT: any migration that adds, removes, or
// re-tiers a system policy without updating these constants fails the test, so
// the number and the migrations can never silently diverge again.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (raw postgres:15, matching the
// approletest runner so the contrib extensions the migrations need are present).
//
// AUTHORITATIVE BREAKDOWN of what a MIGRATED-BUT-NEVER-BOOTED enterprise
// database contains, as counted by this test against every applied core
// migration. It is not what a running deployment holds - see the correction
// above - and the qualifier is repeated here because this is the paragraph
// people quote:
//
//	tier='system', enabled=true (immutable, always-on):
//	  static  (static_policies) : 70
//	  dynamic (dynamic_policies): 15   (10 + the 5 sys_media_* rows, core/173)
//	  TOTAL                     : 85
//
// Static system policies by category (tier='system', enabled=true):
//
//	security-sqli       : 38   (migrations 031 + 139)
//	security-admin      :  4   (migration 031)
//	security-dangerous  :  4   (migration 116 — prompt-injection guards)
//	pii-global          :  7   (migration 031)
//	pii-us              :  2   (migration 031)
//	pii-eu              :  1   (migration 031)
//	pii-india           :  2   (migration 031)
//	pii-singapore       :  5   (migration 042)
//	pii-indonesia       :  1   (migration 116 — KTP/NIK)
//	sensitive-data      :  6   (migration 035)
//
// Beyond the 80 immutable system policies, the migrations also seed tenant-tier
// "starter" policies that ship ENABLED (editable/deletable by the customer):
// 22 static (legacy sql_injection/pii_detection/dangerous_queries +
// eu_ai_act_compliance from migrations 010/014/059) and 2 dynamic (migration
// 010). Plus 9 IDE/agent-integration static policies (migrations 060/064) that
// ship DISABLED and are activated per deployment. So a MIGRATED database
// carries ~92 enabled static + 17 dynamic policies in total (12 + the five
// sys_media_* rows core/173 now seeds); the 85 counted here is the immutable
// system subset that customers cannot remove. A BOOTED deployment holds the
// SAME set, which is the correction at the top of this file: before core/173
// it carried five dynamic rows a migrated database did not.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	sharedpolicy "axonflow/platform/shared/policy"
)

// Documented single source of truth. Keep in lock-step with the migrations:
// if you add/remove/re-tier a system policy, update the relevant constant in
// the same PR (the test fails otherwise).
// THE DYNAMIC COUNT WENT 10 -> 15 WITHOUT ANY POLICY BEING ADDED, and that is
// the finding rather than a bookkeeping detail.
//
// The five sys_media_* rows - NSFW blocking, violence warning, biometric
// logging, media PII blocking, sensitive-document warning - carry tier='system'
// and have been seeded on every deployment since long before this test read 15.
// They were created ONLY by seedSystemMediaPolicies in
// platform/orchestrator/db_dynamic_policies.go, never by a migration, and this
// test counts what the MIGRATIONS produce. So it measured 10 while every
// correctly-seeded deployment carried 15: the test's own name says migrations
// are the single source of truth, and for these five they were not.
//
// migrations/core/173 puts them in a migration, which is what moved the number
// the test can see. It did not change any deployment's contents.
//
// THE RECOVERY BEHAVIOUR RECORDED HERE NO LONGER HOLDS, AND THAT MATTERS
// OPERATIONALLY (#4026). This note used to say: measured on a live community
// stack, with core/173 already recorded as applied so it cannot re-run,
// DELETEing the five rows and restarting the orchestrator brought them straight
// back, from the Go seeder. That was true when the boot path INSERTed them. It
// no longer does - core/172 revoked the application role's INSERT, so the boot
// path VERIFIES the rows and logs at ERROR when they are absent. A restart will
// now REPORT the gap rather than repair it, and re-seeding means re-running
// core/173 against the database as its owner.
//
// WHICH MEANS THE PUBLISHED FIGURE WAS ALREADY WRONG. "80 built-in system
// policies (70 pattern-based, 10 condition-based)" is correct only for a
// deployment whose media seed FAILED - and that failure is a log line, with no
// in-memory fallback, on a deployment then missing media governance entirely
// (#3957). On a healthy deployment the figure has always been 85. README.md
// and docs/ARCHITECTURE.md are corrected in the same change, because they cite
// this test by name as the pin.
const (
	wantSystemStaticEnabled  = 70
	wantSystemDynamicEnabled = 15
	wantSystemTotalEnabled   = wantSystemStaticEnabled + wantSystemDynamicEnabled // 85
)

// wantStaticByCategory is the per-category breakdown of enabled system-tier
// static policies. The sum must equal wantSystemStaticEnabled.
var wantStaticByCategory = map[string]int{
	"security-sqli":      38,
	"security-admin":     4,
	"security-dangerous": 4,
	"pii-global":         7,
	"pii-us":             2,
	"pii-eu":             1,
	"pii-india":          2,
	"pii-singapore":      5,
	"pii-indonesia":      1,
	"sensitive-data":     6,
}

func TestSystemPolicyCount_MigrationsAreSingleSourceOfTruth(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres system-policy count test")
	}

	// Sanity: the documented per-category map must itself sum to the static total.
	sum := 0
	for _, n := range wantStaticByCategory {
		sum += n
	}
	if sum != wantSystemStaticEnabled {
		t.Fatalf("wantStaticByCategory sums to %d, but wantSystemStaticEnabled=%d — fix the constants", sum, wantSystemStaticEnabled)
	}

	dsn, cleanup := startCountTestPostgres(t)
	t.Cleanup(cleanup)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// Pin to one connection so the session GUCs set below persist across the
	// whole migration loop (some migrations read app.* via set_config(...,false)).
	db.SetMaxOpenConns(1)

	// Mirror platform/agent/run.go::setMigrationSessionVars — the production
	// runner sets these three GUCs before applying migrations.
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

	// --- TOTAL enabled system-tier counts ---------------------------------
	gotStatic := scanInt(t, db, `SELECT COUNT(*) FROM static_policies WHERE tier = 'system' AND enabled = true`)
	gotDynamic := scanInt(t, db, `SELECT COUNT(*) FROM dynamic_policies WHERE tier = 'system' AND enabled = true`)

	if gotStatic != wantSystemStaticEnabled {
		t.Errorf("enabled system-tier STATIC policy count = %d, want %d\n%s",
			gotStatic, wantSystemStaticEnabled, dumpStaticByCategory(t, db))
	}
	if gotDynamic != wantSystemDynamicEnabled {
		t.Errorf("enabled system-tier DYNAMIC policy count = %d, want %d\n%s",
			gotDynamic, wantSystemDynamicEnabled, dumpDynamicByCategory(t, db))
	}
	if total := gotStatic + gotDynamic; total != wantSystemTotalEnabled {
		t.Errorf("enabled system-tier TOTAL policy count = %d, want %d", total, wantSystemTotalEnabled)
	}

	// --- Per-category static breakdown ------------------------------------
	rows, err := db.Query(`
		SELECT category, COUNT(*)
		FROM static_policies
		WHERE tier = 'system' AND enabled = true
		GROUP BY category`)
	if err != nil {
		t.Fatalf("query static category breakdown: %v", err)
	}
	defer rows.Close()
	gotByCategory := map[string]int{}
	for rows.Next() {
		var cat string
		var n int
		if err := rows.Scan(&cat, &n); err != nil {
			t.Fatalf("scan category row: %v", err)
		}
		gotByCategory[cat] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate category rows: %v", err)
	}

	for cat, want := range wantStaticByCategory {
		if got := gotByCategory[cat]; got != want {
			t.Errorf("enabled system-tier static category %q count = %d, want %d", cat, got, want)
		}
	}
	for cat, got := range gotByCategory {
		if _, ok := wantStaticByCategory[cat]; !ok {
			t.Errorf("unexpected enabled system-tier static category %q (count %d) not in documented breakdown — a migration added a new category; update wantStaticByCategory", cat, got)
		}
	}

	// --- The same population, reconciled against the MODEL (#3884) ---------
	assertSystemTierReconcilesWithTheShippedCorpus(t, db)

	// --- The action each enforcing scope binds, against the same rows (#4046) ---
	assertEnforcingScopesBindTheActionsTheMigratedRowsStore(t, db)

	// --- Behavioral guards on the LIVE seeded regexes ---------------------
	// These re-establish (against the migration source of truth, not the old
	// Go copies) the two highest-value regressions that previously shipped:
	//   * sys_sqli_grant over-matched benign queries containing "migrant",
	//     firing block on `SELECT migrant_status FROM users`.
	//   * sys_pii_booking_ref matched every 6-char uppercase SQL keyword
	//     (SELECT/INSERT/...), inflating "PII detected" counts on benign traffic.
	// A future migration that re-introduces either over-match turns this red.
	assertSeededPattern(t, db, "sys_sqli_grant",
		[]string{"GRANT SELECT ON foo TO bar", "grant insert on baz to qux"},
		[]string{"SELECT * FROM products LIMIT 10", "SELECT migrant_status FROM users"})
	assertSeededPattern(t, db, "sys_pii_booking_ref",
		[]string{"booking ABC123", "Booking: XYZ789", "PNR ABCDEF"},
		[]string{"SELECT * FROM products LIMIT 10", "INSERT INTO orders (id) VALUES (1)", "random ABC123 word"})
}

// assertEnforcingScopesBindTheActionsTheMigratedRowsStore holds the shipped
// corpus's per-scope actions to the legacy engine's own resolution of the
// migrated rows, on every scope an enforcing seam decides (#4046).
//
// THE TWO SIDES READ DIFFERENT PATHS. The expected action is
// (*sharedpolicy.CompiledPolicy).GetActionForPhase - the legacy engine's phase
// resolution, stored column first and category fallback second - over the
// action_request, action_response, category and severity this database's
// migrations stored. The actual action is read off the policy the scope's
// restriction keeps: a split control's variant names it, and an unsplit
// control's compiled shape states it. Neither side passes through the other.
// The no-database agreement test
// (TestDecideEnforceAndOffAgreeOnEveryControlTheCorpusRedactsElsewhere) builds
// its legacy rows from the corpus, so it shows the two engines agree GIVEN the
// corpus; this is where the corpus is shown to bind what the migrations store.
func assertEnforcingScopesBindTheActionsTheMigratedRowsStore(t *testing.T, db *sql.DB) {
	t.Helper()
	type storedRow struct{ category, severity, request, response, action string }
	stored := map[string]storedRow{}
	rows, err := db.Query(`
		SELECT policy_id, category, COALESCE(severity, ''), COALESCE(action_request, ''), COALESCE(action_response, ''), COALESCE(action, '')
		FROM static_policies WHERE tier = 'system' AND enabled = true`)
	if err != nil {
		t.Fatalf("query the migrated system rows' phase actions: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var r storedRow
		if err := rows.Scan(&id, &r.category, &r.severity, &r.request, &r.response, &r.action); err != nil {
			t.Fatalf("scan a system row's phase actions: %v", err)
		}
		stored[id] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate the system rows: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("the migrated database holds no enabled system static row; the reconciliation below would judge nothing")
	}

	// The retired tier pass's arm, by id (#4253): exactly the four sys_admin_*
	// controls, and only on proxy_request. A fifth row, or the arm on any other
	// plane, is a widening this names rather than passes.
	wantRetired := map[legacycompile.Plane][]string{
		legacycompile.PlaneProxyRequest: {"sys_admin_audit_log", "sys_admin_config_table", "sys_admin_info_schema", "sys_admin_users_table"},
	}
	for _, seam := range enforcingSeams {
		spec := legacycompile.MustSpecFor(seam.scope.Plane)
		phase := sharedpolicy.PhaseRequest
		if seam.scope.ContentPhase() == legacycompile.PhaseResponse {
			phase = sharedpolicy.PhaseResponse
		}
		doc, _, err := activation.RestrictToScope(seam.scope)
		if err != nil {
			t.Fatalf("%s: %v", seam.scope, err)
		}
		split, unsplit := 0, 0
		retired := map[string]bool{}
		for _, p := range doc.Policies {
			control, variantAction, ok := legacycompile.CorpusControlOf(p.ID)
			table, encoded, ok2 := strings.Cut(strings.TrimPrefix(control, "corpus:"), ":")
			if !ok || !ok2 || table != "static_policies" {
				continue
			}
			policyID, ok := legacycompile.UnsanitizePolicyID(encoded)
			if !ok {
				t.Fatalf("%s does not key back to a legacy row", p.ID)
			}
			row, found := stored[policyID]
			if !found {
				t.Errorf("%s binds %s, and the migrated database holds no enabled system row %q", seam.scope, p.ID, policyID)
				continue
			}
			if forced, coerces := spec.Forces(row.category); coerces {
				t.Fatalf("%s coerces category %q to %q, which this reconciliation does not model; extend it before trusting it", seam.scope, row.category, forced)
			}
			want := string((&sharedpolicy.CompiledPolicy{
				Category: sharedpolicy.PolicyCategory(row.category), Severity: sharedpolicy.Severity(row.severity),
				ActionRequest: sharedpolicy.Action(row.request), ActionResponse: sharedpolicy.Action(row.response),
			}).GetActionForPhase(phase))
			// A plane that keeps the retired tier pass's read
			// (PlaneSpec.EnforcesRetiredTierPassRead, #4253) binds a system
			// row's STORED block wherever the phase resolution is less: that
			// pass read the action column, not the phase columns, and refused
			// on it. Every row here is a system row.
			if spec.EnforcesRetiredTierPassRead && row.action == "block" && want != "block" {
				want = "block"
				retired[policyID] = true
			}
			got := variantAction
			if got != "" {
				split++
				// A variant's identifier names its action and its compiled shape
				// states it; both must agree, or a variant could carry another
				// action's obligations under the right name.
				if shape, readable := compiledPolicyAction(p); !readable || shape != got {
					t.Errorf("%s keeps %s, whose identifier names %q and whose compiled shape states %q", seam.scope, p.ID, got, shape)
				}
			} else if got, ok = compiledPolicyAction(p); ok {
				unsplit++
			} else {
				t.Errorf("%s keeps %s, whose compiled shape states no legacy action this reconciliation can read", seam.scope, p.ID)
				continue
			}
			if got != want {
				t.Errorf("%s binds %s as %q; the legacy engine resolves the migrated row to %q for the %s phase (action_request=%q, action_response=%q, category %q, severity %q)",
					seam.scope, policyID, got, want, phase, row.request, row.response, row.category, row.severity)
			}
		}
		if split == 0 || unsplit == 0 {
			t.Errorf("%s judged %d split and %d unsplit controls; the reconciliation must read both kinds", seam.scope, split, unsplit)
		}
		// The population by id, which is also the anti-vacuity check: on
		// proxy_request an arm that fired for nothing reds here, and so does a
		// flag set on any other plane, whose wanted set is empty.
		gotRetired := make([]string, 0, len(retired))
		for id := range retired {
			gotRetired = append(gotRetired, id)
		}
		sort.Strings(gotRetired)
		if got, want := strings.Join(gotRetired, ","), strings.Join(wantRetired[seam.scope.Plane], ","); got != want {
			t.Errorf("%s binds the retired tier pass's stored block for [%s]; want exactly [%s] (#4253)", seam.scope, got, want)
		}
		if spec.EnforcesRetiredTierPassRead {
			t.Logf("%s: %d system rows bind their stored block over the phase resolution (the retired tier pass's read, #4253): %v", seam.scope, len(gotRetired), gotRetired)
		}
		t.Logf("%s: %d split and %d unsplit static controls bind the action the migrated rows store for the %s phase", seam.scope, split, unsplit, phase)
	}
}

// compiledPolicyAction reads the legacy action an unsplit corpus policy was
// compiled from, off its shape: a constraint blocks, a mandatory field_redact
// redacts, a notification warns, and an audit logs.
func compiledPolicyAction(p pdp.Policy) (string, bool) {
	if p.Authority == contract.AuthorityConstraint {
		return "block", true
	}
	if p.Authority != contract.AuthorityRequirement {
		return "", false
	}
	carries := map[contract.ObligationType]bool{}
	for _, o := range p.Obligations {
		if o.Type == contract.ObFieldRedact && o.Mandatory {
			return "redact", true
		}
		carries[o.Type] = true
	}
	switch {
	case carries[contract.ObNotification]:
		return "warn", true
	case carries[contract.ObImmutableAudit]:
		return "log", true
	}
	return "", false
}

// assertSystemTierReconcilesWithTheShippedCorpus holds the migrated system tier
// to the shipped system corpus this binary activates, by identity and in both
// directions (#3884).
//
// THE COUNTS ABOVE CANNOT SEE THE MIGRATION. They are pinned against the legacy
// tables, so a control removed from the typed model and left in the tables
// keeps every one of them green - an invariant that cannot fail for the class
// it appears to cover. So the same rows are read here by (table, policy_id) and
// held to the system document: every enabled system-tier row is carried by a
// system-root policy, or is declared row_not_represented with its reason, and
// every system-root policy comes from such a row.
//
// The no-database twin of this check is
// platform/decision/legacycompile/system_corpus_reconciliation_test.go, which
// replays the forward migrations instead of applying them; this one is the
// arbiter, because it reads what a migrated database actually holds.
func assertSystemTierReconcilesWithTheShippedCorpus(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query(`
		SELECT 'static_policies', policy_id FROM static_policies WHERE tier = 'system' AND enabled = true
		UNION ALL
		SELECT 'dynamic_policies', policy_id FROM dynamic_policies WHERE tier = 'system' AND enabled = true`)
	if err != nil {
		t.Fatalf("query the migrated system tier by identity: %v", err)
	}
	defer rows.Close()
	legacy := map[string]bool{}
	for rows.Next() {
		var table, policyID string
		if err := rows.Scan(&table, &policyID); err != nil {
			t.Fatalf("scan a system-tier row: %v", err)
		}
		legacy[table+"/"+policyID] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate the system-tier rows: %v", err)
	}
	if len(legacy) != wantSystemTotalEnabled {
		t.Fatalf("the identity read found %d system-tier rows where the counts above found %d; the reconciliation below would be about a different population", len(legacy), wantSystemTotalEnabled)
	}

	shipped, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatalf("the shipped system corpus does not load: %v", err)
	}
	model := map[string]int{}
	for _, p := range shipped.Policies {
		// Through the control, so a split row's per-scope variants (#4046) and a
		// multi-policy row's "#n" siblings key back to the row they came from.
		control, _, ok := legacycompile.CorpusControlOf(p.ID)
		table, encoded, ok2 := strings.Cut(strings.TrimPrefix(control, "corpus:"), ":")
		policyID, ok3 := legacycompile.UnsanitizePolicyID(encoded)
		if !ok || !ok2 || !ok3 {
			t.Fatalf("system-root policy %q does not key back to a legacy row", p.ID)
		}
		model[table+"/"+policyID]++
	}
	var artifact struct {
		Divergences []struct {
			PolicyID string `json:"policy_id"`
			Table    string `json:"table"`
			Kind     string `json:"kind"`
		} `json:"divergences"`
	}
	if err := json.Unmarshal(pdp.SystemCorpusSource, &artifact); err != nil {
		t.Fatalf("read the shipped corpus's divergences: %v", err)
	}
	notRepresented := map[string]bool{}
	for _, d := range artifact.Divergences {
		if d.Kind == string(legacycompile.DivergenceRowNotRepresented) {
			notRepresented[d.Table+"/"+d.PolicyID] = true
		}
	}

	var inTablesOnly, inModelOnly []string
	declaredAbsent := 0
	for key := range legacy {
		switch {
		case model[key] > 0:
		case notRepresented[key]:
			declaredAbsent++
		default:
			inTablesOnly = append(inTablesOnly, key)
		}
	}
	for key := range model {
		if !legacy[key] {
			inModelOnly = append(inModelOnly, key)
		}
	}
	sort.Strings(inTablesOnly)
	sort.Strings(inModelOnly)
	if len(inTablesOnly) > 0 {
		t.Errorf("%d enabled system-tier row(s) in the migrated database have no system-root policy in the shipped corpus and no declared row_not_represented divergence: %v", len(inTablesOnly), inTablesOnly)
	}
	if len(inModelOnly) > 0 {
		t.Errorf("%d system-root corpus polic(ies) come from no enabled system-tier row in the migrated database: %v", len(inModelOnly), inModelOnly)
	}
	t.Logf("migrated system tier: %d rows; shipped system document: %d policies from %d rows; declared not represented: %d",
		len(legacy), len(shipped.Policies), len(model), declaredAbsent)
}

// assertSeededPattern reads the regex for policy_id straight out of
// static_policies (the live, migration-seeded source of truth), compiles it with
// Go's RE2 engine (the same engine the policy engine uses), and asserts it
// matches every mustMatch and none of the mustNotMatch inputs.
func assertSeededPattern(t *testing.T, db *sql.DB, policyID string, mustMatch, mustNotMatch []string) {
	t.Helper()
	var pattern string
	if err := db.QueryRow(
		`SELECT pattern FROM static_policies WHERE policy_id = $1 AND tier = 'system'`, policyID,
	).Scan(&pattern); err != nil {
		t.Fatalf("read seeded pattern %q: %v", policyID, err)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("seeded pattern %q failed to compile: %v\npattern: %s", policyID, err, pattern)
	}
	for _, s := range mustMatch {
		if !re.MatchString(s) {
			t.Errorf("seeded %q should MATCH %q (pattern %q)", policyID, s, pattern)
		}
	}
	for _, s := range mustNotMatch {
		if re.MatchString(s) {
			t.Errorf("seeded %q should NOT match %q — over-matching regression (pattern %q)", policyID, s, pattern)
		}
	}
}

// scanInt runs a single-row, single-int query and returns the value.
func scanInt(t *testing.T, db *sql.DB, query string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}

// dumpStaticByCategory renders the live enabled system-tier static breakdown
// for inclusion in a failure message (so a count drift names the category).
func dumpStaticByCategory(t *testing.T, db *sql.DB) string {
	t.Helper()
	return dumpByCategory(t, db, "static_policies")
}

func dumpDynamicByCategory(t *testing.T, db *sql.DB) string {
	t.Helper()
	return dumpByCategory(t, db, "dynamic_policies")
}

func dumpByCategory(t *testing.T, db *sql.DB, table string) string {
	t.Helper()
	rows, err := db.Query(fmt.Sprintf(
		`SELECT category, COUNT(*) FROM %s WHERE tier = 'system' AND enabled = true GROUP BY category ORDER BY category`, table))
	if err != nil {
		return fmt.Sprintf("  (could not dump %s: %v)", table, err)
	}
	defer rows.Close()
	var b strings.Builder
	b.WriteString(fmt.Sprintf("  live enabled system-tier %s by category:\n", table))
	for rows.Next() {
		var cat string
		var n int
		if err := rows.Scan(&cat, &n); err != nil {
			return fmt.Sprintf("  (scan error: %v)", err)
		}
		b.WriteString(fmt.Sprintf("    %-20s %d\n", cat, n))
	}
	return b.String()
}

// applyAllCoreMigrations applies every up migration in migrationsDir, in the
// production composite (version, name) key order. Mirrors the dedup contract of
// the runner in approletest.runMigrations, but without an upper version cap so
// the full live schema (incl. the policy-seeding migrations 031/035/042/059/
// 060/064/116) is materialized.
func applyAllCoreMigrations(t *testing.T, db *sql.DB, migrationsDir string) {
	t.Helper()
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migration dir %s: %v", migrationsDir, err)
	}
	type mig struct {
		version int
		name    string
		path    string
	}
	var migs []mig
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") || strings.HasSuffix(e.Name(), "_down.sql") {
			continue
		}
		parts := strings.SplitN(e.Name(), "_", 2)
		// Accept the production naming convention: a 3-digit version prefix,
		// optionally followed by a letter suffix (e.g. "030a"). Mirrors
		// extractMigrationVersion in migration_helpers.go — using `len==3` here
		// would silently DROP a letter-suffixed policy migration (e.g. a future
		// "116a_*.sql"), letting this count test pass against an incomplete
		// schema, which would defeat its entire purpose.
		if len(parts) < 2 || !hasThreeDigitPrefix(parts[0]) {
			continue
		}
		// Sscanf("%d") reads the leading digit run and ignores any trailing
		// letter suffix ("030a" -> 30); the (version, name) composite sort then
		// keeps "030_*" before "030a_*", matching the production runner.
		var v int
		if _, err := fmt.Sscanf(parts[0], "%d", &v); err != nil {
			continue
		}
		migs = append(migs, mig{version: v, name: e.Name(), path: migrationsDir + "/" + e.Name()})
	}
	sort.Slice(migs, func(i, j int) bool {
		if migs[i].version != migs[j].version {
			return migs[i].version < migs[j].version
		}
		return migs[i].name < migs[j].name
	})
	for _, m := range migs {
		sqlBytes, err := os.ReadFile(m.path)
		if err != nil {
			t.Fatalf("read migration %s: %v", m.path, err)
		}
		if _, err := db.Exec(string(sqlBytes)); err != nil {
			t.Fatalf("apply migration %s: %v", m.name, err)
		}
	}
}

// hasThreeDigitPrefix reports whether s begins with at least three ASCII
// digits (the migration version prefix, e.g. "030" or "030a").
func hasThreeDigitPrefix(s string) bool {
	if len(s) < 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// startCountTestPostgres launches a throwaway docker postgres:15 instance and
// returns the master connection URL + a cleanup function. Same shape as
// approletest.startPostgresContainer (postgres:15 carries the contrib
// extensions the migrations create).
func startCountTestPostgres(t *testing.T) (string, func()) {
	t.Helper()
	containerName := fmt.Sprintf("axonflow-test-polcount-pg-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d",
		"--name", containerName,
		// tmpfs at the declared VOLUME path: postgres creates an ANONYMOUS
		// volume there otherwise, and `docker rm -fv` only reclaims it if the
		// cleanup actually runs - which it does not on a -timeout kill, a
		// Ctrl-C or a panic. With the mount there is nothing to leak at all.
		// Label so an orphaned container is reapable by exact match rather
		// than by a name glob, which collides on a shared daemon.
		"--label", "axonflow.test.ephemeral=1",
		"--tmpfs", "/var/lib/postgresql/data:rw,size=1g",
		"-e", "POSTGRES_PASSWORD=testpass",
		"-e", "POSTGRES_DB=axonflow_test",
		"-p", "0:5432",
		"postgres:15",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, string(out))
	}
	cleanup := func() {
		_ = exec.Command("docker", "rm", "-fv", containerName).Run()
	}

	// Poll for the published host port (the mapping can lag `docker run -d`,
	// and the race widens under parallel container starts in `go test ./...`).
	var hostPort string
	portDeadline := time.Now().Add(30 * time.Second)
	for {
		portBytes, portErr := exec.Command("docker", "port", containerName, "5432/tcp").CombinedOutput()
		if portErr == nil {
			portLine := strings.TrimSpace(strings.Split(string(portBytes), "\n")[0])
			if parts := strings.Split(portLine, ":"); len(parts) >= 2 {
				if hp := parts[len(parts)-1]; hp != "" {
					hostPort = hp
					break
				}
			}
		}
		if time.Now().After(portDeadline) {
			cleanup()
			t.Fatalf("docker port did not resolve a host port for %s within 30s (last err: %v)", containerName, portErr)
		}
		time.Sleep(250 * time.Millisecond)
	}
	url := fmt.Sprintf("postgres://postgres:testpass@localhost:%s/axonflow_test?sslmode=disable", hostPort)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := sql.Open("postgres", url)
		if err == nil {
			if pingErr := conn.Ping(); pingErr == nil {
				_ = conn.Close()
				return url, cleanup
			}
			_ = conn.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	cleanup()
	t.Fatalf("postgres container did not become ready within 30s")
	return "", nil
}
