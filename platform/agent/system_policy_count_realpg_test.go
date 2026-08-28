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

// Real-Postgres test pinning the system-policy count to a single source of
// truth (#2696). System-level policies live ONLY in the SQL migrations — there
// is no Go-side seed any longer (platform/agent/system_policies_seed.go was
// deleted; it was dead, never-consumed "aspirational" code that defined a
// phantom 106-policy count and caused ~a week of operator/Greg confusion).
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
// AUTHORITATIVE BREAKDOWN (what a fresh enterprise DB actually contains, as
// counted by this test against every applied core migration):
//
//	tier='system', enabled=true (immutable, always-on):
//	  static  (static_policies) : 70
//	  dynamic (dynamic_policies): 10
//	  TOTAL                     : 80
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
// ship DISABLED and are activated per deployment. So a fresh DB carries ~92
// enabled static + 12 dynamic policies in total; the 80 counted here is the
// immutable system subset that customers cannot remove.

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Documented single source of truth. Keep in lock-step with the migrations:
// if you add/remove/re-tier a system policy, update the relevant constant in
// the same PR (the test fails otherwise).
const (
	wantSystemStaticEnabled  = 70
	wantSystemDynamicEnabled = 10
	wantSystemTotalEnabled   = wantSystemStaticEnabled + wantSystemDynamicEnabled // 80
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
