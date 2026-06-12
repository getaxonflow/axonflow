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

// Real-Postgres test for migration 123 (#2638): normalize-then-CHECK for
// audit_logs.policy_decision. The migration must (1) normalize every residual
// non-canonical spelling to the canonical vocabulary (mirroring
// platform/shared/audit.Normalize, including the fail-safe of an unknown value
// to 'error', never 'allowed'); (2) preserve already-canonical rows and the
// override_lifecycle marker untouched; (3) add a CHECK that REJECTS a
// non-canonical insert and ACCEPTS the marker; and be idempotent + paired with a
// down migration that drops the CHECK.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (testcontainers postgres).

import (
	"os"
	"strings"
	"testing"

	"axonflow/platform/testutil"
)

func TestMigration123_AuditDecisionVocabCheck_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres migration test")
	}

	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pg.DB

	// Minimal audit_logs shape: the migration only touches policy_decision and
	// adds a CHECK on it, so a table carrying that NOT-NULL column is sufficient.
	if _, err := db.Exec(`
		CREATE TABLE audit_logs (
			id              VARCHAR(255) PRIMARY KEY,
			policy_decision VARCHAR(50) NOT NULL
		)`); err != nil {
		t.Fatalf("create audit_logs: %v", err)
	}

	// Seed: residual non-canonical spellings that must normalize, an unknown
	// garbage value that must fail-safe to 'error', already-canonical rows that
	// must be LEFT UNTOUCHED, and the override_lifecycle marker that must survive.
	seed := []struct{ id, decision, wantAfter string }{
		// legacy wire / divergent spellings -> canonical
		{"allow1", "allow", "allowed"},
		{"deny1", "deny", "blocked"},
		{"denied1", "denied", "blocked"},
		{"mod1", "modified", "redacted"},
		{"mask1", "masked", "redacted"},
		// THE locked fix: the off-set workflow-gate spelling -> needs_approval
		{"pend1", "pending_approval", "needs_approval"},
		{"req1", "require_approval", "needs_approval"},
		// case / whitespace insensitivity
		{"case1", "  Blocked ", "blocked"},
		// unknown garbage -> fail-safe 'error' (never 'allowed')
		{"junk1", "totally-bogus", "error"},
		// already-canonical -> untouched
		{"c-allow", "allowed", "allowed"},
		{"c-block", "blocked", "blocked"},
		{"c-redact", "redacted", "redacted"},
		{"c-need", "needs_approval", "needs_approval"},
		{"c-err", "error", "error"},
		// recognized non-verdict marker -> untouched
		{"ovr1", "override_lifecycle", "override_lifecycle"},
	}
	for _, s := range seed {
		if _, err := db.Exec(`INSERT INTO audit_logs (id, policy_decision) VALUES ($1, $2)`, s.id, s.decision); err != nil {
			t.Fatalf("seed %s: %v", s.id, err)
		}
	}

	upSQL, err := os.ReadFile("../../migrations/core/123_audit_decision_vocab_check.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	downSQL, err := os.ReadFile("../../migrations/core/123_audit_decision_vocab_check_down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}

	readDecision := func(id string) string {
		t.Helper()
		var d string
		if err := db.QueryRow(`SELECT policy_decision FROM audit_logs WHERE id = $1`, id).Scan(&d); err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		return d
	}

	// --- Apply the up migration (includes the fail-loud verification DO block) ---
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("apply migration 123: %v", err)
	}

	assertRows := func(stage string) {
		t.Helper()
		for _, s := range seed {
			if got := readDecision(s.id); got != s.wantAfter {
				t.Errorf("[%s] %s: policy_decision = %q, want %q", stage, s.id, got, s.wantAfter)
			}
		}
	}
	assertRows("after-up")

	// --- The CHECK now rejects a non-canonical insert ... ---
	if _, err := db.Exec(`INSERT INTO audit_logs (id, policy_decision) VALUES ('bad', 'deny')`); err == nil {
		t.Error("CHECK did not reject a non-canonical insert ('deny')")
	} else if !strings.Contains(strings.ToLower(err.Error()), "audit_logs_policy_decision_check") &&
		!strings.Contains(strings.ToLower(err.Error()), "check constraint") {
		t.Errorf("rejection error not from the policy_decision CHECK: %v", err)
	}

	// --- ... and accepts every canonical verdict + the override_lifecycle marker ---
	for _, ok := range []string{"allowed", "blocked", "redacted", "needs_approval", "error", "override_lifecycle"} {
		if _, err := db.Exec(`INSERT INTO audit_logs (id, policy_decision) VALUES ($1, $2)`, "ok_"+ok, ok); err != nil {
			t.Errorf("CHECK rejected canonical-or-marker value %q: %v", ok, err)
		}
	}

	// --- Idempotent: re-running the up migration changes nothing and does not error ---
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("re-apply migration 123 (idempotency): %v", err)
	}
	assertRows("after-up-rerun")

	// --- Down migration drops the CHECK: a non-canonical insert now succeeds ---
	if _, err := db.Exec(string(downSQL)); err != nil {
		t.Fatalf("apply down migration 123: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO audit_logs (id, policy_decision) VALUES ('post-down', 'deny')`); err != nil {
		t.Errorf("after down migration the CHECK should be gone, but insert was rejected: %v", err)
	}
	// Data normalization is forward-only: the rows the up migration converted stay
	// canonical after the down (the down is schema-only, like migration 122's).
	assertRows("after-down")
}
