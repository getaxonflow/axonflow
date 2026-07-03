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

// Real-Postgres regression for the decision_chain INSERT (#2809). recordToDB
// binds parent_request_id via NULLIF($4,''), which yields a TEXT-typed
// expression; the column is uuid (migration 025). Postgres does NOT implicitly
// assign text→uuid for a computed expression (only for a bare placeholder), so
// without the ::uuid cast EVERY signed-chain INSERT failed with "column
// parent_request_id is of type uuid but expression is of type text" — silently
// emptying the live decision chain (recordSignedDecision is best-effort: the
// error was logged + metered, never surfaced). The regression could ONLY be
// caught against a real Postgres: sqlmock does not type-check the bound
// parameter, which is exactly why the existing db test (sqlmock) stayed green
// while production wrote zero rows.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (testcontainers postgres).

import (
	"context"
	"os"
	"testing"

	"axonflow/platform/testutil"
)

func TestDecisionChain_RecordToDB_EmptyParent_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres integration test")
	}

	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pg.DB

	// The decision_chain schema recordToDB targets: migration 025's base columns
	// (crucially parent_request_id UUID — the type under test) plus migration
	// 125's signing columns. The org FK is dropped so the table stands alone (the
	// bug is a column type mismatch, independent of the org relation).
	if _, err := db.Exec(`
		CREATE TABLE decision_chain (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			chain_id UUID NOT NULL,
			request_id UUID NOT NULL,
			parent_request_id UUID,
			step_number INTEGER NOT NULL DEFAULT 1,
			org_id VARCHAR(255) NOT NULL,
			tenant_id TEXT NOT NULL,
			client_id TEXT,
			user_id TEXT,
			decision_type TEXT NOT NULL,
			system_id TEXT NOT NULL,
			model_provider TEXT,
			model_id TEXT,
			decision_outcome TEXT NOT NULL,
			policies_evaluated TEXT[] DEFAULT '{}',
			policy_triggered TEXT,
			risk_level TEXT DEFAULT 'limited',
			requires_human_review BOOLEAN DEFAULT FALSE,
			processing_time_ms INTEGER,
			input_hash TEXT,
			output_hash TEXT,
			data_sources TEXT[] DEFAULT '{}',
			metadata JSONB DEFAULT '{}',
			audit_hash TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			prev_hash TEXT,
			record_signature TEXT,
			signing_key_id TEXT,
			chain_seq BIGINT
		)`); err != nil {
		t.Fatalf("create decision_chain: %v", err)
	}

	// Synchronous tracker (AsyncQueueSize:-1) so recordToDB runs inline and any
	// INSERT error is returned from RecordDecision — deterministic assertion.
	tracker, err := NewDecisionChainTracker(DecisionChainTrackerConfig{
		DB:             db,
		SystemID:       "test/1.0.0",
		AsyncQueueSize: -1,
		SigningKey:     testSigningKey(t),
	})
	if err != nil {
		t.Fatalf("new tracker: %v", err)
	}

	// The exact live-path shape: recordSignedDecision builds an entry with NO
	// ParentRequestID (it never sets one), so $4 is the empty string — the case
	// that tripped the uuid cast on every real decision.
	entry := sampleEntry("org-2809", "22222222-2222-2222-2222-222222222222", 1)
	if entry.ParentRequestID != "" {
		t.Fatalf("precondition: sample entry must have an empty ParentRequestID (got %q)", entry.ParentRequestID)
	}

	if err := tracker.RecordDecision(context.Background(), entry); err != nil {
		t.Fatalf("RecordDecision with empty parent_request_id failed (the #2809 uuid-cast bug): %v", err)
	}

	// The row must actually be in the table — the whole failure mode was a
	// swallowed INSERT error leaving zero rows.
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM decision_chain WHERE chain_id = $1`,
		"22222222-2222-2222-2222-222222222222").Scan(&n); err != nil {
		t.Fatalf("count decision_chain: %v", err)
	}
	if n != 1 {
		t.Fatalf("decision_chain rows for the signed decision: got %d, want 1", n)
	}

	// parent_request_id must be a genuine SQL NULL (empty string → NULL), the
	// documented genesis shape — not an empty-uuid or a text sentinel.
	var parentNull bool
	if err := db.QueryRow(`SELECT parent_request_id IS NULL FROM decision_chain WHERE chain_id = $1`,
		"22222222-2222-2222-2222-222222222222").Scan(&parentNull); err != nil {
		t.Fatalf("read parent_request_id: %v", err)
	}
	if !parentNull {
		t.Fatalf("parent_request_id should be NULL for a genesis record")
	}
}
