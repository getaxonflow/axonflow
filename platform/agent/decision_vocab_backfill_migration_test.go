// Copyright 2025 AxonFlow
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

// Real-Postgres test for migration 122 (#2643 / #2638): the one-time backfill
// that normalizes legacy audit_logs.policy_decision tokens (allow/deny/denied)
// to the canonical set, leaving already-canonical rows untouched, and is both
// idempotent and paired with a no-op down migration.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (testcontainers postgres).

import (
	"os"
	"testing"

	"axonflow/platform/testutil"
)

func TestMigration122_AuditDecisionVocabBackfill_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres migration test")
	}

	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pg.DB

	// Minimal audit_logs shape: the migration only touches policy_decision, so a
	// table carrying that NOT-NULL column is sufficient to exercise the SQL
	// faithfully (and keeps the test independent of the full migration chain).
	if _, err := db.Exec(`
		CREATE TABLE audit_logs (
			id              VARCHAR(255) PRIMARY KEY,
			policy_decision VARCHAR(50) NOT NULL
		)`); err != nil {
		t.Fatalf("create audit_logs: %v", err)
	}

	// Seed: legacy tokens that must normalize + already-canonical tokens that
	// must be LEFT UNTOUCHED (the safety property — the backfill must not rewrite
	// rows that were already canonical).
	seed := []struct{ id, decision string }{
		{"a1", "allow"}, {"a2", "allow"},
		{"d1", "deny"}, {"d2", "deny"},
		{"x1", "denied"},
		{"c1", "allowed"}, // already canonical
		{"c2", "blocked"}, // already canonical
		{"n1", "needs_approval"},
		{"r1", "redacted"},
	}
	for _, s := range seed {
		if _, err := db.Exec(`INSERT INTO audit_logs (id, policy_decision) VALUES ($1, $2)`, s.id, s.decision); err != nil {
			t.Fatalf("seed %s: %v", s.id, err)
		}
	}

	upSQL, err := os.ReadFile("../../migrations/core/122_audit_decision_vocab_backfill.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	downSQL, err := os.ReadFile("../../migrations/core/122_audit_decision_vocab_backfill_down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}

	count := func(decision string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE policy_decision = $1`, decision).Scan(&n); err != nil {
			t.Fatalf("count %q: %v", decision, err)
		}
		return n
	}

	// --- Apply the up migration (includes the fail-loud verification DO block) ---
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("apply migration 122: %v", err)
	}

	assertCounts := func(stage string) {
		t.Helper()
		// Legacy tokens gone.
		if n := count("allow"); n != 0 {
			t.Errorf("[%s] legacy 'allow' rows remain: %d", stage, n)
		}
		if n := count("deny"); n != 0 {
			t.Errorf("[%s] legacy 'deny' rows remain: %d", stage, n)
		}
		if n := count("denied"); n != 0 {
			t.Errorf("[%s] legacy 'denied' rows remain: %d", stage, n)
		}
		// allowed = 2 normalized from 'allow' + 1 already-canonical.
		if n := count("allowed"); n != 3 {
			t.Errorf("[%s] allowed: got %d want 3", stage, n)
		}
		// blocked = 2 from 'deny' + 1 from 'denied' + 1 already-canonical.
		if n := count("blocked"); n != 4 {
			t.Errorf("[%s] blocked: got %d want 4", stage, n)
		}
		// Untouched canonical tokens.
		if n := count("needs_approval"); n != 1 {
			t.Errorf("[%s] needs_approval: got %d want 1", stage, n)
		}
		if n := count("redacted"); n != 1 {
			t.Errorf("[%s] redacted: got %d want 1", stage, n)
		}
	}
	assertCounts("after-up")

	// --- Idempotent: re-running the up migration changes nothing ---
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("re-apply migration 122 (idempotency): %v", err)
	}
	assertCounts("after-up-rerun")

	// --- Down migration is a deliberate no-op: counts unchanged, no error ---
	if _, err := db.Exec(string(downSQL)); err != nil {
		t.Fatalf("apply down migration 122: %v", err)
	}
	assertCounts("after-down")
}
