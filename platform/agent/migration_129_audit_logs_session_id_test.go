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

// Real-Postgres test for core migration 129 (#2753/#2754): add the nullable
// session_id column + partial index to the canonical audit_logs table, with a
// tested down-migration.
//
// Mirrors migration_126_audit_logs_cross_border_test.go: seeds the canonical
// audit_logs DDL (canonicalAuditLogsDDL, defined in that file — same package)
// rather than replaying the whole core chain, then exercises up (column + index
// present, nullable, correct type/length), a round-trip row, down (removed),
// and up re-apply (idempotent).
//
// Gated on TEST_PG_INTEGRATION=1 + docker (raw postgres:15). Reuses the
// migration-124 harness helper startMig124Postgres (same package).

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

func TestMigration129_AuditLogsSessionID_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set: skipping real-Postgres migration 129 test")
	}

	dsn, cleanup := startMig124Postgres(t)
	t.Cleanup(cleanup)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(canonicalAuditLogsDDL); err != nil {
		t.Fatalf("seed canonical audit_logs DDL: %v", err)
	}

	apply := func(file string) {
		t.Helper()
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if _, err := db.Exec(string(b)); err != nil {
			t.Fatalf("apply %s: %v", file, err)
		}
	}

	assertNullableVarchar := func(col string, maxLen int) {
		t.Helper()
		var (
			gotType     string
			gotNullable string
			gotMaxLen   sql.NullInt64
		)
		err := db.QueryRow(`
			SELECT data_type, is_nullable, character_maximum_length
			FROM information_schema.columns
			WHERE table_name = 'audit_logs' AND column_name = $1`, col).
			Scan(&gotType, &gotNullable, &gotMaxLen)
		if err != nil {
			t.Fatalf("column %s not found: %v", col, err)
		}
		if gotType != "character varying" {
			t.Errorf("audit_logs.%s data_type = %q, want character varying", col, gotType)
		}
		if gotNullable != "YES" {
			t.Errorf("audit_logs.%s is_nullable = %q, want YES", col, gotNullable)
		}
		if !gotMaxLen.Valid || int(gotMaxLen.Int64) != maxLen {
			t.Errorf("audit_logs.%s max length = %v, want %d", col, gotMaxLen, maxLen)
		}
	}
	colCount := func(col string) int {
		var n int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'audit_logs' AND column_name = $1`, col,
		).Scan(&n); err != nil {
			t.Fatalf("column count query: %v", err)
		}
		return n
	}
	indexExists := func() bool {
		var n int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM pg_indexes WHERE tablename = 'audit_logs' AND indexname = 'idx_audit_logs_session_id'`,
		).Scan(&n); err != nil {
			t.Fatalf("pg_indexes query: %v", err)
		}
		return n == 1
	}

	// (1) UP.
	apply("../../migrations/core/129_audit_logs_session_id.sql")
	assertNullableVarchar("session_id", 255)
	if !indexExists() {
		t.Error("partial index idx_audit_logs_session_id missing after up migration")
	}

	// Round-trip: a row carrying session_id persists and reads back; a row
	// WITHOUT it writes NULL (proving additive/nullable — existing writers safe).
	if _, err := db.Exec(`
		INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash, policy_decision,
			session_id)
		VALUES ('m129-1','r1', NOW(), 1,'alice@example.com','unknown','c1','t1','t1','mcp_check_policy','q','h','blocked',
			'sess-abc-123')`,
	); err != nil {
		t.Fatalf("insert row with session_id: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash, policy_decision)
		VALUES ('m129-2','r2', NOW(), 1,'a@b.c','unknown','c1','t1','t1','completion','q','h','allowed')`,
	); err != nil {
		t.Fatalf("insert row without session_id: %v", err)
	}
	var sid sql.NullString
	if err := db.QueryRow(`SELECT session_id FROM audit_logs WHERE id='m129-1'`).Scan(&sid); err != nil {
		t.Fatalf("read back session_id: %v", err)
	}
	if !sid.Valid || sid.String != "sess-abc-123" {
		t.Errorf("round-trip session_id got %v, want sess-abc-123", sid)
	}
	if err := db.QueryRow(`SELECT session_id FROM audit_logs WHERE id='m129-2'`).Scan(&sid); err != nil {
		t.Fatalf("read back null session_id: %v", err)
	}
	if sid.Valid {
		t.Errorf("expected NULL session_id for the row that omitted it, got %q", sid.String)
	}

	// (2) DOWN.
	apply("../../migrations/core/129_audit_logs_session_id_down.sql")
	if colCount("session_id") != 0 {
		t.Error("session_id column still present after down migration")
	}
	if indexExists() {
		t.Error("index still present after down migration")
	}

	// (3) UP re-apply (idempotent).
	apply("../../migrations/core/129_audit_logs_session_id.sql")
	assertNullableVarchar("session_id", 255)
	if !indexExists() {
		t.Error("partial index missing after up re-apply")
	}
}
