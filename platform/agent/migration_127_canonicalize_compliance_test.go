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

package agent

// Regression tests for migration 127 (#2728): canonicalize the drifted
// compliance policy categories so RBI / SEBI / MAS-FEAT / EU-AI-Act seeds fire
// on /decide and the gateway.
//
// The seed migrations stored static_policies.category with a non-canonical
// spelling (eu_ai_act_compliance / rbi_compliance / sebi_compliance /
// mas_feat_compliance) that does not match the canonical constants in
// platform/shared/policy/types.go. The decide/gateway category filter is
// exact-match on the canonical PolicyCategory, so those rows never applied.
//
// Two real-Postgres tests + one always-on static guard:
//
//   - TestMigration127_ForwardFix_RealPostgres: applies every core migration
//     (014 EU AI Act seed + 127). Asserts the EU rows are canonical and zero
//     drifted remain (red-on-revert: core/014 is NOT edited, so dropping 127
//     leaves them drifted). Then injects synthetic drifted rows for all four
//     categories (simulating an existing industry deploy), re-applies 127, and
//     asserts every row canonicalised, plus a down/up round-trip.
//
//   - TestMigration127_IndustrySeedsCanonical_RealPostgres: applies core, then
//     the four canonicalised industry seeds in version order (travel/200 +
//     banking/300/302/401), reproducing the real apply ordering (core/127 runs
//     BEFORE the industry seeds). Asserts each compliance category has its
//     seeded rows live under the canonical spelling and IsComplianceCategory
//     accepts it. Red-on-revert: un-canonicalising any seed leaves drifted rows
//     that 127 cannot reach (it ran first), failing the assertions.
//
//   - TestMigration127_SeedFilesContainNoDriftedCategory: a docker-free guard
//     that greps the seed files for any quoted drifted category literal.
//
// The real-Postgres tests are gated on TEST_PG_INTEGRATION=1 + docker.

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	sharedpolicy "axonflow/platform/shared/policy"

	_ "github.com/lib/pq"
)

// driftedToCanonical maps each drifted seed category to its canonical constant.
var mig127DriftedToCanonical = map[string]sharedpolicy.PolicyCategory{
	"eu_ai_act_compliance": sharedpolicy.CategoryComplianceEUAIAct,
	"rbi_compliance":       sharedpolicy.CategoryComplianceRBI,
	"sebi_compliance":      sharedpolicy.CategoryComplianceSEBI,
	"mas_feat_compliance":  sharedpolicy.CategoryComplianceMASFEAT,
}

func TestMigration127_ForwardFix_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set: skipping real-Postgres migration 127 forward-fix test")
	}

	dsn, cleanup := startMig127Postgres(t)
	t.Cleanup(cleanup)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	setMig127Config(t, db)
	applyAllCoreMigrations127(t, db, "../../migrations/core")

	scanInt := mig127ScanInt(t, db)

	// (1) The real EU AI Act seed (core/014) is canonical after 127, with zero
	// drifted rows. core/014 is NOT edited in this PR, so this is red-on-revert
	// for 127's UPDATE: drop the migration and the EU rows stay drifted.
	if n := scanInt(`SELECT COUNT(*) FROM static_policies WHERE category = 'compliance-euaiact'`); n < 4 {
		t.Errorf("compliance-euaiact rows after 127 = %d, want >= 4 (the core/014 EU AI Act seed)", n)
	}
	for drifted := range mig127DriftedToCanonical {
		if n := scanInt(fmt.Sprintf(`SELECT COUNT(*) FROM static_policies WHERE category = '%s'`, drifted)); n != 0 {
			t.Errorf("drifted category %q still has %d rows after migration 127 (want 0)", drifted, n)
		}
	}

	// The EU AI Act reporting view exists and returns the canonical rows.
	if n := scanInt(`SELECT COUNT(*) FROM eu_ai_act_compliance_summary`); n < 4 {
		t.Errorf("eu_ai_act_compliance_summary returned %d rows, want >= 4", n)
	}

	// (2) Simulate an EXISTING industry deploy: insert one synthetic policy per
	// drifted category (tenant_id='global', matching the seeds), then re-apply
	// migration 127 (idempotent) and assert each is canonicalised.
	for drifted := range mig127DriftedToCanonical {
		pid := "mig127_synthetic_" + drifted
		if _, err := db.Exec(`
			INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, tenant_id)
			VALUES ($1, $1, $2, 'x', 'low', 'synthetic existing-deploy row', 'log', 'global')
			ON CONFLICT (policy_id) DO UPDATE SET category = EXCLUDED.category`,
			pid, drifted); err != nil {
			t.Fatalf("insert synthetic drifted row %q: %v", drifted, err)
		}
	}
	mig127ExecFile(t, db, "../../migrations/core/127_canonicalize_compliance_categories.sql")

	for drifted, canonical := range mig127DriftedToCanonical {
		pid := "mig127_synthetic_" + drifted
		var got string
		if err := db.QueryRow(`SELECT category FROM static_policies WHERE policy_id = $1`, pid).Scan(&got); err != nil {
			t.Fatalf("read synthetic row %q: %v", pid, err)
		}
		if got != string(canonical) {
			t.Errorf("synthetic row seeded as %q has category %q after 127, want %q", drifted, got, canonical)
		}
		if !sharedpolicy.IsComplianceCategory(sharedpolicy.PolicyCategory(got)) {
			t.Errorf("IsComplianceCategory(%q) = false after canonicalisation, want true", got)
		}
	}
	if n := scanInt(`SELECT COUNT(*) FROM static_policies WHERE category IN
		('eu_ai_act_compliance','rbi_compliance','sebi_compliance','mas_feat_compliance')`); n != 0 {
		t.Errorf("re-applying 127 left %d drifted rows (want 0)", n)
	}

	// (3) Down round-trip: the down migration restores the drifted spelling on
	// the global seeds; re-applying up canonicalises them again.
	mig127ExecFile(t, db, "../../migrations/core/127_canonicalize_compliance_categories_down.sql")
	if n := scanInt(`SELECT COUNT(*) FROM static_policies WHERE category = 'eu_ai_act_compliance'`); n < 4 {
		t.Errorf("after down migration: %d rows reverted to eu_ai_act_compliance, want >= 4", n)
	}
	if n := scanInt(`SELECT COUNT(*) FROM static_policies WHERE category = 'compliance-euaiact'`); n != 0 {
		t.Errorf("after down migration: %d rows still compliance-euaiact, want 0", n)
	}
	mig127ExecFile(t, db, "../../migrations/core/127_canonicalize_compliance_categories.sql")
	if n := scanInt(`SELECT COUNT(*) FROM static_policies WHERE category = 'compliance-euaiact'`); n < 4 {
		t.Errorf("after re-up: %d rows compliance-euaiact, want >= 4", n)
	}
	// Idempotent: a second up is a clean no-op.
	mig127ExecFile(t, db, "../../migrations/core/127_canonicalize_compliance_categories.sql")
}

func TestMigration127_IndustrySeedsCanonical_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set: skipping real-Postgres migration 127 industry-seed test")
	}

	dsn, cleanup := startMig127Postgres(t)
	t.Cleanup(cleanup)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	setMig127Config(t, db)
	// core (incl. 127) runs first, exactly as in production; then the four
	// canonicalised industry seeds in ascending version order. They only touch
	// static_policies + policy_violations (both created in core/010).
	applyAllCoreMigrations127(t, db, "../../migrations/core")
	for _, f := range []string{
		"../../migrations/industry/travel/200_eu_ai_act_templates.sql",
		"../../migrations/industry/banking/300_sebi_ai_ml_templates.sql",
		"../../migrations/industry/banking/302_rbi_free_ai_templates.sql",
		"../../migrations/industry/banking/401_mas_feat_templates.sql",
	} {
		mig127ExecFile(t, db, f)
	}

	scanInt := mig127ScanInt(t, db)

	// Each compliance category fires under its canonical spelling with the
	// expected seeded row count. Red-on-revert: un-canonicalising a seed leaves
	// those rows under the drifted spelling, which 127 ran too early to fix.
	wantMin := map[sharedpolicy.PolicyCategory]int{
		sharedpolicy.CategoryComplianceEUAIAct: 4, // core/014 + travel/200 (same policy_ids, deduped)
		sharedpolicy.CategoryComplianceSEBI:    6, // banking/300
		sharedpolicy.CategoryComplianceRBI:     5, // banking/302
		sharedpolicy.CategoryComplianceMASFEAT: 7, // banking/401
	}
	for cat, min := range wantMin {
		n := scanInt(fmt.Sprintf(`SELECT COUNT(*) FROM static_policies WHERE category = '%s' AND enabled = true`, cat))
		if n < min {
			t.Errorf("category %q has %d enabled policies, want >= %d", cat, n, min)
		}
		if !sharedpolicy.IsComplianceCategory(cat) {
			t.Errorf("IsComplianceCategory(%q) = false, want true", cat)
		}
	}

	// Zero drifted compliance rows anywhere after the full apply.
	if n := scanInt(`SELECT COUNT(*) FROM static_policies WHERE category IN
		('eu_ai_act_compliance','rbi_compliance','sebi_compliance','mas_feat_compliance')`); n != 0 {
		t.Errorf("after applying canonicalised seeds: %d drifted compliance rows remain (want 0)", n)
	}

	// The dependent reporting views resolve and return the canonical rows.
	for _, v := range []string{"sebi_compliance_summary", "mas_feat_compliance_summary", "eu_ai_act_compliance_summary"} {
		if n := scanInt(fmt.Sprintf(`SELECT COUNT(*) FROM %s`, v)); n < 1 {
			t.Errorf("view %s returned %d rows, want >= 1", v, n)
		}
	}
}

// TestMigration127_SeedFilesContainNoDriftedCategory is a docker-free guard: no
// edited seed migration may carry a quoted drifted compliance category literal.
func TestMigration127_SeedFilesContainNoDriftedCategory(t *testing.T) {
	seeds := []string{
		"../../migrations/core/014_eu_ai_act_templates.sql",
		"../../migrations/industry/travel/200_eu_ai_act_templates.sql",
		"../../migrations/industry/banking/300_sebi_ai_ml_templates.sql",
		"../../migrations/industry/banking/302_rbi_free_ai_templates.sql",
		"../../migrations/industry/banking/401_mas_feat_templates.sql",
	}
	// core/014 is intentionally exempt from the INSERT canonicalisation (it is
	// forward-fixed by 127, which runs after it), so it is allowed to keep the
	// drifted INSERT literal. The industry seeds run AFTER 127 and MUST be
	// canonical at source.
	industryDriftedLiterals := []string{
		"'eu_ai_act_compliance'", "'rbi_compliance'", "'sebi_compliance'", "'mas_feat_compliance'",
	}
	for _, f := range seeds {
		if strings.Contains(f, "core/014") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			if os.IsNotExist(err) {
				// The industry/ seeds are excluded from the community edition's
				// source tree (the community sync drops migrations/industry/), so
				// the file legitimately may not exist there. Skip what isn't
				// present; the canonical-at-source check still runs wherever the
				// seed ships.
				t.Logf("seed %s not present in this edition; skipping", f)
				continue
			}
			t.Fatalf("read seed %s: %v", f, err)
		}
		content := string(b)
		for _, lit := range industryDriftedLiterals {
			if strings.Contains(content, lit) {
				t.Errorf("seed %s still contains drifted category literal %s (must be canonical)", f, lit)
			}
		}
	}
}

// ----------------------------------------------------------------------------
// helpers (suffixed 127 to avoid collisions with sibling migration tests)
// ----------------------------------------------------------------------------

func setMig127Config(t *testing.T, db *sql.DB) {
	t.Helper()
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
}

func mig127ScanInt(t *testing.T, db *sql.DB) func(string) int {
	return func(query string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(query).Scan(&n); err != nil {
			t.Fatalf("query %q: %v", query, err)
		}
		return n
	}
}

func mig127ExecFile(t *testing.T, db *sql.DB, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if _, err := db.Exec(string(b)); err != nil {
		t.Fatalf("apply %s: %v", path, err)
	}
}

func applyAllCoreMigrations127(t *testing.T, db *sql.DB, migrationsDir string) {
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
		if len(parts) < 2 || !threeDigitPrefix127(parts[0]) {
			continue
		}
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

func threeDigitPrefix127(s string) bool {
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

func startMig127Postgres(t *testing.T) (string, func()) {
	t.Helper()
	containerName := fmt.Sprintf("axonflow-test-mig127-pg-%d", time.Now().UnixNano())
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
			t.Fatalf("docker port did not resolve for %s within 30s (last err: %v)", containerName, portErr)
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
