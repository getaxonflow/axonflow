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

// The MCP plane's override_used row must contribute NOTHING to
// audit.TopPoliciesQuery (#3426 / #3438 R3).
//
// WHY THIS TEST EXISTS AND WHY IT IS HERE. The aggregation originally excluded
// override rows with `policy_decision <> 'override_lifecycle'`. That is the
// ORCHESTRATOR writer's spelling. THIS package's writer, writeOverrideUsedEvent,
// stamps request_type = "override_used" and policy_decision = "allowed" - so it
// sailed straight through, and an override_used row names the policy the
// override BYPASSED. On a table whose columns are Policy / Triggers / Blocks, a
// bypass then renders indistinguishably from an enforcement, and the policy that
// was NOT enforced climbs the ranking of the regulator-facing artifact.
//
// The test lives in platform/agent because that is where the writer is, and it
// calls the REAL writer rather than hand-rolling its INSERT: the shape that
// broke the exclusion (which column carries what) is exactly what a hand-rolled
// row would get to choose for itself.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (testcontainers postgres).

import (
	"context"
	"os"
	"testing"

	"github.com/lib/pq"

	sharedaudit "axonflow/platform/shared/audit"
	"axonflow/platform/testutil"
)

func TestWriteOverrideUsedEvent_ContributesNothingToTopPolicies_RealPG(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set - skipping real-Postgres integration test")
	}

	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pg.DB
	ctx := context.Background()

	// The columns writeOverrideUsedEvent's INSERT names, with the production
	// NOT NULL on the two the exclusion predicates read. Both are NOT NULL in
	// migration core/059, which is what makes the bare `<>` and `<> ALL`
	// comparisons safe rather than row-dropping.
	pg.RunMigration(t, `
		CREATE TABLE audit_logs (
			id              VARCHAR(255) PRIMARY KEY,
			request_id      VARCHAR(255),
			timestamp       TIMESTAMPTZ,
			user_id         INTEGER,
			user_email      VARCHAR(255),
			user_role       VARCHAR(255),
			client_id       VARCHAR(255),
			tenant_id       VARCHAR(255),
			org_id          VARCHAR(255),
			request_type    VARCHAR(50) NOT NULL,
			query           TEXT,
			query_hash      VARCHAR(255),
			policy_decision VARCHAR(50) NOT NULL,
			policy_details  JSONB,
			decision_id     VARCHAR(255),
			plane           VARCHAR(50),
			correlation_id  VARCHAR(255),
			session_id      VARCHAR(255)
		)`)

	const (
		tenant = "acme"
		policy = "fincrime_structuring"
	)

	// One REAL enforcement of the policy: a decide-plane block, in the shape
	// stampPolicyIdentityNames produces since #3365 (ids AND names). Without it
	// the policy would be absent from the aggregate for the trivial reason that
	// nothing fired, and "excluded" could not be told from "never there".
	if _, err := db.ExecContext(ctx, `
		INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash,
			policy_decision, policy_details, plane)
		VALUES ('enf1','r1',NOW(),0,'u@acme.test','user','c1',$1,'org1','llm_chat','q','h',
			$2, $3::jsonb, 'decision')`,
		tenant, sharedaudit.DecisionBlocked,
		`{"policy_ids":["`+policy+`"],"policy_names":["FinCrime: Structuring"]}`,
	); err != nil {
		t.Fatalf("seeding the enforcement row: %v", err)
	}

	// THE REAL WRITER, twice, naming the same policy the enforcement named.
	writeOverrideUsedEvent(ctx, db, "ovr-1", "dec-1", tenant, "org1", "c1",
		"u@acme.test", policy, "FinCrime: Structuring", 3, "corr-1")
	writeOverrideUsedEvent(ctx, db, "ovr-2", "dec-2", tenant, "org1", "c1",
		"u@acme.test", policy, "FinCrime: Structuring", 3, "corr-2")

	// ANTI-VACUITY, and the guard against this DDL drifting from the writer.
	// writeOverrideUsedEvent is best-effort (`_, _ = db.ExecContext`), so a
	// column it names and this table lacks produces ZERO rows and no error -
	// under which every "is it excluded" assertion below passes for the wrong
	// reason. Assert the rows are really there, in the shape that defeated the
	// old predicate.
	var ovrRows int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM audit_logs WHERE request_type = 'override_used' AND policy_decision = $1`,
		sharedaudit.DecisionAllowed,
	).Scan(&ovrRows); err != nil {
		t.Fatalf("counting override rows: %v", err)
	}
	if ovrRows != 2 {
		t.Fatalf("the real writer persisted %d override_used rows, want 2; "+
			"the DDL above has drifted from writeOverrideUsedEvent's INSERT and every assertion below is vacuous", ovrRows)
	}

	// They also have to be RESOLVABLE by the identity chain, or the exclusion is
	// indistinguishable from an unreadable row.
	var resolvable int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM audit_logs WHERE request_type = 'override_used'
		   AND `+sharedaudit.PolicyIdentitySQLExpr("policy_details")+` = $1`, policy,
	).Scan(&resolvable); err != nil {
		t.Fatalf("checking override-row resolvability: %v", err)
	}
	if resolvable != 2 {
		t.Fatalf("the chain resolves %s out of %d of the 2 override rows; "+
			"this test cannot tell the exclusion from an unreadable row", policy, resolvable)
	}

	type hit struct {
		name     string
		isName   bool
		triggers int
		blocks   int
		total    int
	}
	run := func(t *testing.T, query string, args ...interface{}) map[string]hit {
		t.Helper()
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			t.Fatalf("top-policies query: %v", err)
		}
		defer rows.Close()
		out := map[string]hit{}
		for rows.Next() {
			var h hit
			if err := rows.Scan(&h.name, &h.isName, &h.triggers, &h.blocks, &h.total); err != nil {
				t.Fatalf("scanning: %v", err)
			}
			out[h.name] = h
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterating: %v", err)
		}
		return out
	}

	got := run(t, sharedaudit.TopPoliciesQuery("tenant_id = $1", "$2"),
		tenant, pq.Array(sharedaudit.Spellings(sharedaudit.DecisionBlocked)))

	h, ok := got[policy]
	if !ok {
		t.Fatalf("%s absent from top_policies entirely; the enforcement row should still count it (got %v)", policy, got)
	}
	if h.triggers != 1 {
		t.Errorf("%s has trigger_count %d, want 1 (the one enforcement). "+
			"The two MCP override_used rows are being counted, so the policy the override BYPASSED "+
			"is ranked as though it had been enforced three times", policy, h.triggers)
	}
	if h.blocks != 1 {
		t.Errorf("%s has block_count %d, want 1", policy, h.blocks)
	}

	// DISCRIMINATION PROOF, in the test itself rather than in a commit message.
	// The predicate this fix replaced is run against the same table: it must
	// count all three rows. If it does not, the corpus does not reproduce the
	// defect and the assertion above proves nothing.
	oldPredicateQuery := `
		SELECT fired_policy.policy, COALESCE(bool_and(` +
		sharedaudit.PolicyIdentityIsNameSQLExpr("policy_details") + `), false),
			COUNT(*), COUNT(*) FILTER (WHERE policy_decision = ANY($2)), COUNT(*) OVER ()
		FROM audit_logs
		CROSS JOIN LATERAL unnest(` + sharedaudit.PolicyIdentitySetSQLExpr("policy_details") + `) AS fired_policy(policy)
		WHERE (tenant_id = $1) AND policy_details IS NOT NULL
		  AND policy_decision <> '` + sharedaudit.DecisionOverrideLifecycle + `'
		GROUP BY fired_policy.policy`
	old := run(t, oldPredicateQuery, tenant, pq.Array(sharedaudit.Spellings(sharedaudit.DecisionBlocked)))
	if old[policy].triggers != 3 {
		t.Errorf("the REPLACED policy_decision-only predicate counts %s %d times, want 3; "+
			"this fixture does not reproduce #3438 R3 BLOCKER 2 and the assertion above is not discriminating",
			policy, old[policy].triggers)
	}
}
