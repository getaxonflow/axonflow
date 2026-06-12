// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
)

// #2590 real-Postgres proof of the config-governed retention executor. Drives
// the ACTUAL CleanupRetentionGovernedAudits against a live Postgres (no mocks,
// no httptest) over a minimal schema of the six governed tables + the retention
// config/defaults, asserting the three semantics the bug is about:
//
//   - a row PAST its retention window is pruned;
//   - a row INSIDE its window is kept;
//   - dry-run COUNTs exactly what enforce DELETEs (the "would delete" count
//     equals the eventual delete count);
//   - an ACTIVE per-org override is honored (its rows expire on the override
//     window) while every other org uses the default.
//
// Skips cleanly when Docker is unavailable, matching the repo's testcontainer
// integration-test convention.

// retentionTestSchema is a minimal schema carrying only the columns the executor
// references (each table's real age + org column names/types) plus a PK. RLS is
// intentionally omitted: this test proves the executor's prune/keep/override
// SQL; cross-org RLS routing is covered by the admin-pool unit test and the
// existing b2 isolation suite.
const retentionTestSchema = `
DROP TABLE IF EXISTS agent_audit_logs, orchestrator_audit_logs, llm_call_audits,
	gateway_contexts, decision_chain, hitl_approval_history,
	audit_retention_config, audit_retention_defaults CASCADE;

CREATE TABLE audit_retention_defaults (
	data_type      VARCHAR(100) PRIMARY KEY,
	retention_days INTEGER NOT NULL
);

CREATE TABLE audit_retention_config (
	id              SERIAL PRIMARY KEY,
	org_id          VARCHAR(255) NOT NULL,
	data_type       VARCHAR(100) NOT NULL,
	retention_days  INTEGER NOT NULL,
	is_active       BOOLEAN NOT NULL DEFAULT true,
	last_cleanup_at TIMESTAMPTZ,
	UNIQUE (org_id, data_type)
);

CREATE TABLE agent_audit_logs        (id SERIAL PRIMARY KEY,    org_id VARCHAR(255), timestamp  TIMESTAMP   DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE orchestrator_audit_logs (id BIGSERIAL PRIMARY KEY, org_id VARCHAR(255), timestamp  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE llm_call_audits         (id BIGSERIAL PRIMARY KEY, org_id VARCHAR(255), created_at TIMESTAMP   DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE gateway_contexts        (id BIGSERIAL PRIMARY KEY,                      created_at TIMESTAMP   DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE decision_chain          (id BIGSERIAL PRIMARY KEY, org_id VARCHAR(255) NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE hitl_approval_history   (id BIGSERIAL PRIMARY KEY, org_id VARCHAR(255) NOT NULL, created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP);
`

const retentionTestDefaultDays = 30

func mustExec(t *testing.T, db *sql.DB, q string, args ...interface{}) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func tableCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// seedGovernedTables inserts, into every governed table, one row PAST the default
// window (now - (default+10) days) and one row INSIDE it (now - 1 day), under the
// given org. gateway_contexts has no org column so its org arg is ignored.
func seedGovernedTables(t *testing.T, db *sql.DB, org string) {
	t.Helper()
	past := time.Now().UTC().AddDate(0, 0, -(retentionTestDefaultDays + 10))
	recent := time.Now().UTC().AddDate(0, 0, -1)
	for _, rt := range retentionGovernedTables {
		for _, ts := range []time.Time{past, recent} {
			if rt.orgColumn == "" {
				mustExec(t, db, "INSERT INTO "+rt.table+" ("+rt.tsColumn+") VALUES ($1)", ts)
			} else {
				mustExec(t, db, "INSERT INTO "+rt.table+" ("+rt.orgColumn+", "+rt.tsColumn+") VALUES ($1, $2)", org, ts)
			}
		}
	}
}

func newRetentionPG(t *testing.T) *sql.DB {
	t.Helper()
	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, retentionTestSchema)
	// Seed the system defaults the executor reads (small uniform window).
	for _, rt := range retentionGovernedTables {
		mustExec(t, pg.DB, "INSERT INTO audit_retention_defaults (data_type, retention_days) VALUES ($1, $2)",
			rt.dataType, retentionTestDefaultDays)
	}
	return pg.DB
}

// TestRetentionExecutorRealPG_DryRunThenEnforce proves the core bug fix end to
// end on real Postgres: dry-run mutates nothing but counts the past rows, then
// enforce deletes exactly those past rows and keeps the in-window rows.
func TestRetentionExecutorRealPG_DryRunThenEnforce(t *testing.T) {
	db := newRetentionPG(t)
	seedGovernedTables(t, db, "org-a")

	// Baseline: 2 rows per governed table.
	for _, rt := range retentionGovernedTables {
		if got := tableCount(t, db, rt.table); got != 2 {
			t.Fatalf("%s baseline = %d, want 2", rt.table, got)
		}
	}

	svc := NewAuditCleanupService(db, &mockLicenseChecker{})

	// --- Phase A: DRY-RUN — counts the 1 past row per table, deletes nothing.
	results, err := svc.CleanupRetentionGovernedAudits(context.Background())
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	dryRunByTable := map[string]int64{}
	for _, r := range results {
		if r.Enforced {
			t.Errorf("%s: expected dry-run", r.Table)
		}
		if r.Rows != 1 {
			t.Errorf("%s dry-run rows = %d, want 1 (the past row)", r.Table, r.Rows)
		}
		dryRunByTable[r.Table] = r.Rows
	}
	for _, rt := range retentionGovernedTables {
		if got := tableCount(t, db, rt.table); got != 2 {
			t.Errorf("%s after dry-run = %d, want 2 (nothing deleted)", rt.table, got)
		}
	}

	// --- Phase B: ENFORCE — deletes exactly the past rows, keeps in-window rows.
	svc.SetRetentionEnforce(true)
	results, err = svc.CleanupRetentionGovernedAudits(context.Background())
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	for _, r := range results {
		if !r.Enforced {
			t.Errorf("%s: expected enforce", r.Table)
		}
		// dry-run count must equal enforce delete count.
		if r.Rows != dryRunByTable[r.Table] {
			t.Errorf("%s enforce deleted %d but dry-run counted %d", r.Table, r.Rows, dryRunByTable[r.Table])
		}
	}
	for _, rt := range retentionGovernedTables {
		if got := tableCount(t, db, rt.table); got != 1 {
			t.Errorf("%s after enforce = %d, want 1 (in-window row kept)", rt.table, got)
		}
	}

	// --- Phase C: idempotent — a second enforce pass deletes nothing more.
	results, err = svc.CleanupRetentionGovernedAudits(context.Background())
	if err != nil {
		t.Fatalf("second enforce: %v", err)
	}
	for _, r := range results {
		if r.Rows != 0 {
			t.Errorf("%s second pass deleted %d, want 0 (idempotent)", r.Table, r.Rows)
		}
	}
}

// TestRetentionExecutorRealPG_PerOrgOverride proves an active per-org override is
// honored: the override org's rows expire on the SHORTER override window while a
// different org keeps everything inside the (longer) default window.
func TestRetentionExecutorRealPG_PerOrgOverride(t *testing.T) {
	db := newRetentionPG(t)
	// The seeded floor for every data_type is retentionTestDefaultDays (30).

	const fastOrg = "org-fast"       // sub-floor override → CLAMPED up to the floor
	const longOrg = "org-long"       // above-floor override → honored verbatim
	const defaultOrg = "org-default" // inactive override → uses the floor

	// fastOrg: aggressive 5-day override (BELOW the 30-day floor). The clamp must
	// prevent it from deleting rows still inside the mandated window.
	mustExec(t, db,
		"INSERT INTO audit_retention_config (org_id, data_type, retention_days, is_active) VALUES ($1, 'decision_chain', 5, true)",
		fastOrg)
	// longOrg: 90-day override (ABOVE the floor) → honored, extends retention.
	mustExec(t, db,
		"INSERT INTO audit_retention_config (org_id, data_type, retention_days, is_active) VALUES ($1, 'decision_chain', 90, true)",
		longOrg)
	// defaultOrg: an INACTIVE override must be ignored (org falls back to the floor).
	mustExec(t, db,
		"INSERT INTO audit_retention_config (org_id, data_type, retention_days, is_active) VALUES ($1, 'decision_chain', 1, false)",
		defaultOrg)

	now := time.Now().UTC()
	rows := []struct {
		org string
		ts  time.Time
		// keep = expected to survive an enforce pass
		keep bool
	}{
		// CLAMP proof: a naive 5d override would delete this, but it is inside the
		// 30d regulatory floor → MUST be kept.
		{fastOrg, now.AddDate(0, 0, -10), true},
		{fastOrg, now.AddDate(0, 0, -40), false}, // past the 30d floor → DELETE
		// EXTEND proof: inside the 90d override but past the 30d floor → kept
		// because the override legitimately extends retention.
		{longOrg, now.AddDate(0, 0, -60), true},
		{longOrg, now.AddDate(0, 0, -100), false},   // past the 90d override → DELETE
		{defaultOrg, now.AddDate(0, 0, -10), true},  // inside floor → KEEP
		{defaultOrg, now.AddDate(0, 0, -40), false}, // past floor → DELETE
	}
	for _, r := range rows {
		mustExec(t, db, "INSERT INTO decision_chain (org_id, created_at) VALUES ($1, $2)", r.org, r.ts)
	}
	if got := tableCount(t, db, "decision_chain"); got != 6 {
		t.Fatalf("decision_chain baseline = %d, want 6", got)
	}

	svc := NewAuditCleanupService(db, &mockLicenseChecker{})
	svc.SetRetentionEnforce(true)
	if _, err := svc.CleanupRetentionGovernedAudits(context.Background()); err != nil {
		t.Fatalf("enforce: %v", err)
	}

	// Exactly the three "keep" rows must remain.
	if got := tableCount(t, db, "decision_chain"); got != 3 {
		t.Fatalf("decision_chain after enforce = %d, want 3", got)
	}
	assertExists := func(org string, ts time.Time, want bool) {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM decision_chain WHERE org_id = $1 AND created_at = $2", org, ts).Scan(&n); err != nil {
			t.Fatalf("probe: %v", err)
		}
		if (n > 0) != want {
			t.Errorf("decision_chain row org=%s ts=%s present=%v, want present=%v", org, ts.Format(time.RFC3339), n > 0, want)
		}
	}
	for _, r := range rows {
		assertExists(r.org, r.ts, r.keep)
	}
}

// TestRetentionExecutorRealPG_AdvancesLastCleanup is the #2661 real-Postgres
// proof: after an ENFORCE pass, audit_retention_config.last_cleanup_at is
// advanced to ~now for the config rows whose data was pruned (so the SEBI export
// reads a fresh timestamp instead of the perpetually-stale 1970 sentinel), while
// a DRY-RUN pass leaves it untouched. Covers both an active per-org override row
// and an inactive row (default-bucket pruned) — both must advance, mirroring the
// dead PL/pgSQL that advanced every existing config row for the data_type.
func TestRetentionExecutorRealPG_AdvancesLastCleanup(t *testing.T) {
	db := newRetentionPG(t)

	// Two config rows for decision_chain: one ACTIVE override (org-active,
	// pruned in the scoped step) and one INACTIVE row (org-inactive, whose data
	// the default bucket prunes). Both start with a NULL last_cleanup_at.
	mustExec(t, db,
		"INSERT INTO audit_retention_config (org_id, data_type, retention_days, is_active) VALUES ('org-active', 'decision_chain', 90, true)")
	mustExec(t, db,
		"INSERT INTO audit_retention_config (org_id, data_type, retention_days, is_active) VALUES ('org-inactive', 'decision_chain', 1, false)")
	// Grain control: a config row for 'policy_violations' — intentionally NOT in
	// retentionGovernedTables (handled elsewhere) — seeded BEFORE the run. The
	// data_type-scoped advance must never touch it, proving the UPDATE is scoped
	// to the data_types the executor processes (not a blanket all-rows update).
	mustExec(t, db,
		"INSERT INTO audit_retention_config (org_id, data_type, retention_days, is_active) VALUES ('org-control', 'policy_violations', 90, true)")
	seedGovernedTables(t, db, "org-active")

	lastCleanup := func(org string) (interface{}, bool) {
		t.Helper()
		var ts sql.NullTime
		if err := db.QueryRow(
			"SELECT last_cleanup_at FROM audit_retention_config WHERE org_id = $1 AND data_type = 'decision_chain'", org,
		).Scan(&ts); err != nil {
			t.Fatalf("read last_cleanup_at(%s): %v", org, err)
		}
		if !ts.Valid {
			return nil, false
		}
		return ts.Time, true
	}

	// Baseline: both NULL.
	for _, org := range []string{"org-active", "org-inactive"} {
		if _, ok := lastCleanup(org); ok {
			t.Fatalf("%s baseline last_cleanup_at should be NULL", org)
		}
	}

	svc := NewAuditCleanupService(db, &mockLicenseChecker{})

	// --- DRY-RUN must NOT advance last_cleanup_at.
	if _, err := svc.CleanupRetentionGovernedAudits(context.Background()); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	for _, org := range []string{"org-active", "org-inactive"} {
		if _, ok := lastCleanup(org); ok {
			t.Errorf("%s last_cleanup_at advanced during DRY-RUN (must stay NULL)", org)
		}
	}

	// --- ENFORCE must advance last_cleanup_at to ~now for BOTH rows.
	before := time.Now().UTC().Add(-2 * time.Second)
	svc.SetRetentionEnforce(true)
	if _, err := svc.CleanupRetentionGovernedAudits(context.Background()); err != nil {
		t.Fatalf("enforce: %v", err)
	}
	after := time.Now().UTC().Add(2 * time.Second)
	for _, org := range []string{"org-active", "org-inactive"} {
		v, ok := lastCleanup(org)
		if !ok {
			t.Errorf("%s last_cleanup_at NULL after ENFORCE (should be advanced)", org)
			continue
		}
		ts := v.(time.Time).UTC()
		if ts.Before(before) || ts.After(after) {
			t.Errorf("%s last_cleanup_at = %s, want within [%s, %s]", org, ts, before, after)
		}
	}

	// Grain proof: the non-governed 'policy_violations' control row seeded BEFORE
	// the enforce pass must remain NULL — the executor only advances data_types
	// it actually processes, never a blanket all-rows update.
	var controlTS sql.NullTime
	if err := db.QueryRow(
		"SELECT last_cleanup_at FROM audit_retention_config WHERE org_id = 'org-control' AND data_type = 'policy_violations'",
	).Scan(&controlTS); err != nil {
		t.Fatalf("read org-control: %v", err)
	}
	if controlTS.Valid {
		t.Errorf("org-control/policy_violations last_cleanup_at advanced (=%v) — advance is not data_type-scoped", controlTS.Time)
	}
}
