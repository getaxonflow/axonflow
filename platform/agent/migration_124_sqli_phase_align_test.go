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

// Real-Postgres test for migration 124 (#2702): align the SQLi system-policy
// phase actions (action_request/action_response) with the relaxed base action.
//
// Migrations 066/067 relaxed security-sqli's base `action` 'block' -> 'warn'
// (ADR-036 observe-first default) but left the phase columns at 'block'. Those
// columns are inert for enforcement (the AXONFLOW_PROFILE override always wins —
// see platform/shared/policy/engine.go + detection_config.go BuildActionOverrides),
// but the stored 'block' misleads readers and the metrics action label. Migration
// 124 makes the phase columns match the base action.
//
// This test stands up a fresh enterprise DB, applies EVERY core migration in
// production composite-key order, and asserts:
//   1. No security-sqli system row carries a 'block' phase action (the fix).      [red-on-revert]
//   2. security-sqli base `action` is still 'warn' for all 37 rows (no base mutation, no behavior change).
//   3. The surgical scope held: security-dangerous and pii-indonesia system rows
//      STILL have their legitimate 'block' phase action (not clobbered).
//   4. The seeded security-sqli system count is unchanged (37).
//
// Red-on-revert: delete/limit migration 124 and assertion (1) fails because the
// phase columns revert to 'block'.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (raw postgres:15, matching approletest).

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestMigration124_SQLiPhaseActionAligned_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres migration 124 test")
	}

	dsn, cleanup := startMig124Postgres(t)
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

	applyAllCoreMigrations124(t, db, "../../migrations/core")

	scanInt := func(query string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(query).Scan(&n); err != nil {
			t.Fatalf("query %q: %v", query, err)
		}
		return n
	}

	// (1) THE FIX (red-on-revert): no security-sqli system row keeps a 'block'
	// phase action after migration 124.
	staleSQLi := scanInt(`
		SELECT COUNT(*) FROM static_policies
		WHERE tier = 'system' AND category IN ('security-sqli','sqli')
		  AND (action_request = 'block' OR action_response = 'block')`)
	if staleSQLi != 0 {
		t.Errorf("migration 124 did not align SQLi phase actions: %d security-sqli system rows still have a 'block' phase action (want 0)", staleSQLi)
	}

	// (2) NO BEHAVIOR CHANGE: the base action stays 'warn' for every SQLi system
	// row (the migration must not touch `action`), and the phase columns now read
	// 'warn' too (matching base).
	sqliTotal := scanInt(`SELECT COUNT(*) FROM static_policies WHERE tier='system' AND category='security-sqli'`)
	sqliWarnBase := scanInt(`SELECT COUNT(*) FROM static_policies WHERE tier='system' AND category='security-sqli' AND action='warn'`)
	sqliWarnPhase := scanInt(`
		SELECT COUNT(*) FROM static_policies
		WHERE tier='system' AND category='security-sqli'
		  AND action_request='warn' AND action_response='warn'`)
	// 38 since migration core/139 added sys_sqli_string_term_comment (#2811),
	// which ships warn base + warn/warn phase — already aligned, so migration
	// 124 is a no-op on it, but it is still a security-sqli system row.
	if sqliTotal != 38 {
		t.Errorf("security-sqli system count = %d, want 38 (count drift — see #2696)", sqliTotal)
	}
	if sqliWarnBase != sqliTotal {
		t.Errorf("security-sqli base action: %d/%d rows are 'warn' (the migration must NOT change the base action)", sqliWarnBase, sqliTotal)
	}
	if sqliWarnPhase != sqliTotal {
		t.Errorf("security-sqli phase actions: %d/%d rows are warn/warn after migration 124 (want all)", sqliWarnPhase, sqliTotal)
	}

	// (3) SURGICAL SCOPE: the legitimately-blocking categories are NOT clobbered —
	// security-dangerous (4) and pii-indonesia (1) keep their 'block' request action.
	dangerousBlock := scanInt(`
		SELECT COUNT(*) FROM static_policies
		WHERE tier='system' AND category='security-dangerous' AND action_request='block'`)
	if dangerousBlock != 4 {
		t.Errorf("security-dangerous request action: %d/4 rows are 'block' (migration 124 must not touch this category)", dangerousBlock)
	}
	indonesiaBlock := scanInt(`
		SELECT COUNT(*) FROM static_policies
		WHERE tier='system' AND category='pii-indonesia' AND action_request='block'`)
	if indonesiaBlock != 1 {
		t.Errorf("pii-indonesia request action: %d/1 rows are 'block' (migration 124 must not touch this category)", indonesiaBlock)
	}

	// (4) PII phase columns untouched: response-phase 'redact' is preserved (the
	// detect-then-redact model). At least the US/EU/India PII should keep redact.
	piiRedactResp := scanInt(`
		SELECT COUNT(*) FROM static_policies
		WHERE tier='system' AND category LIKE 'pii-%' AND action_response='redact'`)
	if piiRedactResp == 0 {
		t.Errorf("expected PII system rows to retain a 'redact' response action; migration 124 must not touch pii-* phase columns")
	}

	// (5) DOWN round-trip: the down migration restores the pre-124 'block' phase
	// actions on the 38 SQLi rows (its scope is every warn/warn security-sqli
	// system row, so it also flips the already-aligned migration-139 row), and
	// re-applying the up migration re-aligns them — proving both directions are
	// correct and idempotent.
	downSQL, err := os.ReadFile("../../migrations/core/124_align_sqli_phase_action_with_base_down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	if _, err := db.Exec(string(downSQL)); err != nil {
		t.Fatalf("apply down migration 124: %v", err)
	}
	afterDown := scanInt(`
		SELECT COUNT(*) FROM static_policies
		WHERE tier='system' AND category='security-sqli'
		  AND action_request='block' AND action_response='block'`)
	if afterDown != 38 {
		t.Errorf("after down migration: %d/38 security-sqli rows restored to block/block phase actions", afterDown)
	}
	// Base action must STILL be warn after the down (the down is phase-only).
	if base := scanInt(`SELECT COUNT(*) FROM static_policies WHERE tier='system' AND category='security-sqli' AND action='warn'`); base != 38 {
		t.Errorf("after down migration: base action changed (%d/38 'warn') — down must be phase-only", base)
	}

	upSQL, err := os.ReadFile("../../migrations/core/124_align_sqli_phase_action_with_base.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("re-apply up migration 124: %v", err)
	}
	if reUp := scanInt(`
		SELECT COUNT(*) FROM static_policies
		WHERE tier='system' AND category IN ('security-sqli','sqli')
		  AND (action_request='block' OR action_response='block')`); reUp != 0 {
		t.Errorf("re-applying migration 124 did not re-align: %d SQLi rows still 'block' phase", reUp)
	}
	// Idempotent: a second up is a clean no-op.
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("idempotent re-apply of migration 124: %v", err)
	}
}

// applyAllCoreMigrations124 applies every up migration in migrationsDir, in the
// production composite (version, name) key order (3-digit prefix, optional letter
// suffix — mirrors migration_helpers.go extractMigrationVersion).
func applyAllCoreMigrations124(t *testing.T, db *sql.DB, migrationsDir string) {
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
		if len(parts) < 2 || !threeDigitPrefix124(parts[0]) {
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

func threeDigitPrefix124(s string) bool {
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

func startMig124Postgres(t *testing.T) (string, func()) {
	t.Helper()
	containerName := fmt.Sprintf("axonflow-test-mig124-pg-%d", time.Now().UnixNano())
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
