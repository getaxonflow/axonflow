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

// Real-Postgres test for core migration 126 (#2718): add transfer_basis +
// data_residency (nullable) plus a partial index to the canonical audit_logs
// table, with a tested down-migration.
//
// It stands up a fresh DB and seeds the canonical audit_logs DDL (verbatim from
// migrations/core/059_runtime_tables_to_migrations.sql, kept in sync there)
// rather than replaying the entire core chain, because an unrelated mid-chain
// migration (028 grafana/dblink) requires the agent runner's GUC/placeholder
// injection that a bare SQL applier does not provide. The migration is exercised
// against the real audit_logs column shape: up (columns + index present, both
// nullable, correct types/lengths), down (removed), up re-apply (idempotent).
//
// Gated on TEST_PG_INTEGRATION=1 + docker (raw postgres:15). Reuses the
// migration-124 harness helper startMig124Postgres (same package).

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// canonicalAuditLogsDDL mirrors migrations/core/059_runtime_tables_to_migrations.sql
// (the authoritative audit_logs CREATE) so migration 126 is tested against the
// real column shape it ships against.
const canonicalAuditLogsDDL = `
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(255) PRIMARY KEY,
    request_id VARCHAR(255) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    user_id INTEGER NOT NULL,
    user_email VARCHAR(255) NOT NULL,
    user_role VARCHAR(50) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    org_id VARCHAR(255),
    request_type VARCHAR(50) NOT NULL,
    query TEXT NOT NULL,
    query_hash VARCHAR(255) NOT NULL,
    policy_decision VARCHAR(50) NOT NULL,
    policy_details JSONB,
    provider VARCHAR(50),
    model VARCHAR(100),
    response_time_ms BIGINT,
    tokens_used INTEGER,
    cost DECIMAL(10, 6),
    redacted_fields JSONB,
    error_message TEXT,
    response_sample TEXT,
    compliance_flags JSONB,
    security_metrics JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);`

func TestMigration126_AuditLogsCrossBorder_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set: skipping real-Postgres migration 126 test")
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

	assertCol := func(col, dataType string, maxLen int) {
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
		if gotType != dataType {
			t.Errorf("audit_logs.%s data_type = %q, want %q", col, gotType, dataType)
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
			`SELECT COUNT(*) FROM pg_indexes WHERE tablename = 'audit_logs' AND indexname = 'idx_audit_logs_transfer_basis'`,
		).Scan(&n); err != nil {
			t.Fatalf("pg_indexes query: %v", err)
		}
		return n == 1
	}

	// (1) UP.
	apply("../../migrations/core/126_audit_logs_cross_border_fields.sql")
	assertCol("transfer_basis", "character varying", 20)
	assertCol("data_residency", "character varying", 2)
	if !indexExists() {
		t.Error("partial index idx_audit_logs_transfer_basis missing after up migration")
	}

	// Sanity: a row carrying both fields persists and reads back unchanged.
	if _, err := db.Exec(`
		INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash, policy_decision,
			transfer_basis, data_residency)
		VALUES ('m126-1','r1', NOW(), 1,'a@b.c','admin','c1','t1','t1','completion','q','h','allowed','pasal_56b_dpa','US')`,
	); err != nil {
		t.Fatalf("insert row with cross-border fields: %v", err)
	}
	var rb, rr string
	if err := db.QueryRow(`SELECT transfer_basis, data_residency FROM audit_logs WHERE id='m126-1'`).Scan(&rb, &rr); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if rb != "pasal_56b_dpa" || rr != "US" {
		t.Errorf("round-trip got basis=%q residency=%q, want pasal_56b_dpa/US", rb, rr)
	}

	// (2) DOWN.
	apply("../../migrations/core/126_audit_logs_cross_border_fields_down.sql")
	if colCount("transfer_basis") != 0 || colCount("data_residency") != 0 {
		t.Error("columns still present after down migration")
	}
	if indexExists() {
		t.Error("index still present after down migration")
	}

	// (3) UP re-apply (idempotent).
	apply("../../migrations/core/126_audit_logs_cross_border_fields.sql")
	assertCol("transfer_basis", "character varying", 20)
	assertCol("data_residency", "character varying", 2)
	if !indexExists() {
		t.Error("partial index missing after up re-apply")
	}
}
