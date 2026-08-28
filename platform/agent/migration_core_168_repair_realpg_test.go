package agent

import (
	"database/sql"
	"os"
	"testing"
)

// TestCoreMigration168_RepairsWrappedContentFilter_RealPostgres proves the
// core-set repair on the population it exists for: a COMMUNITY deployment.
//
// Enterprise deployments were repaired by enterprise/139 section 4b, and its
// test (migration_enterprise_139_us_templates_realpg_test.go) proves that
// path. But community and community-saas never run an enterprise migration
// (migration_helpers.go), core/024's seed is ON CONFLICT DO NOTHING, and the
// corrected source therefore never rewrites an already-seeded row - so an
// existing community deployment keeps an inert tpl_general_content_filter
// until core/168 repairs it. This test applies the CORE CHAIN ONLY (the
// community posture; no enterprise file is executed), asserts the fresh-apply
// state is already correct (the source half), then reproduces an existing
// deployment by re-wrapping the value and re-applying 168 alone, asserting
// the repair (the forward-fix half). Red-on-revert: break 168's jsonb path
// and the second half fails.
func TestCoreMigration168_RepairsWrappedContentFilter_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set - skipping real-Postgres migration-168 repair test")
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

	// The community posture: the core chain and NOTHING else. 168 is inside it.
	applyAllCoreMigrations(t, db, "../../migrations/core")

	const (
		id   = "tpl_general_content_filter"
		path = "{conditions,0,value}"
		want = `"{{prohibited_patterns}}"`
	)

	readValue := func() string {
		var v string
		if err := db.QueryRow(
			`SELECT (template #> $2::text[])::text FROM policy_templates WHERE id = $1`,
			id, path).Scan(&v); err != nil {
			t.Fatalf("read %s %s: %v", id, path, err)
		}
		return v
	}

	// Source half: a fresh community apply seeds the unwrapped value (024 was
	// fixed at source), and 168's guarded UPDATE matched nothing.
	if got := readValue(); got != want {
		t.Fatalf("fresh core apply: %s = %s, want %s (core/024's source fix is not what seeded)", path, got, want)
	}

	// Forward-fix half: reproduce an existing deployment that seeded the OLD
	// shape, then re-apply 168 ALONE. Assert the injection took first - a
	// repair proven against a failed injection proves nothing.
	if _, err := db.Exec(
		`UPDATE policy_templates
		    SET template = jsonb_set(template, $2::text[], '["{{prohibited_patterns}}"]'::jsonb)
		  WHERE id = $1`, id, path); err != nil {
		t.Fatalf("inject wrapped shape: %v", err)
	}
	if got := readValue(); got != `["{{prohibited_patterns}}"]` {
		t.Fatalf("injection did not take: %s = %s", path, got)
	}

	b, err := os.ReadFile("../../migrations/core/168_repair_wrapped_template_variable.sql")
	if err != nil {
		t.Fatalf("read migration 168: %v", err)
	}
	if _, err := db.Exec(string(b)); err != nil {
		t.Fatalf("re-apply migration 168: %v", err)
	}
	if got := readValue(); got != want {
		t.Errorf("%s = %s after 168 re-applied, want %s: a community deployment that seeded the old 024 keeps a Content Safety Filter that can never fire", path, got, want)
	}

	// Backfill half (#3528 item 2): a policy applied from a template BEFORE
	// ApplyTemplate stamped categories sits with an empty category and a
	// policy_template_usage record. 168's backfill must stamp it via the same
	// dynamic- prefix rule; a row with NO usage record must stay untouched
	// (the import path can still write those; routed on the epic).
	if _, err := db.Exec(`INSERT INTO dynamic_policies
			(policy_id, name, policy_type, conditions, actions, category)
		VALUES ('mig168-backfill-target', 'mig168 backfill target', 'compliance', '[]'::jsonb, '[]'::jsonb, ''),
		       ('mig168-no-usage',        'mig168 no usage',        'compliance', '[]'::jsonb, '[]'::jsonb, '')`); err != nil {
		t.Fatalf("seed backfill fixture: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO policy_template_usage (template_id, tenant_id, policy_id)
		VALUES ($1, 'mig168-tenant', 'mig168-backfill-target')`, id); err != nil {
		t.Fatalf("seed usage record: %v", err)
	}
	b2, err := os.ReadFile("../../migrations/core/168_repair_wrapped_template_variable.sql")
	if err != nil {
		t.Fatalf("re-read migration 168: %v", err)
	}
	if _, err := db.Exec(string(b2)); err != nil {
		t.Fatalf("re-apply migration 168 for the backfill: %v", err)
	}
	readCat := func(pid string) string {
		var c string
		if err := db.QueryRow(`SELECT COALESCE(category, '') FROM dynamic_policies WHERE policy_id = $1`, pid).Scan(&c); err != nil {
			t.Fatalf("read category %s: %v", pid, err)
		}
		return c
	}
	// tpl_general_content_filter's catalog category is 'general', so the rule
	// yields dynamic-general.
	if got := readCat("mig168-backfill-target"); got != "dynamic-general" {
		t.Errorf("backfilled category = %q, want dynamic-general: the usage-joined backfill did not stamp the applied row", got)
	}
	if got := readCat("mig168-no-usage"); got != "" {
		t.Errorf("no-usage row category = %q, want empty: the backfill wrote outside the population it owns", got)
	}
}
