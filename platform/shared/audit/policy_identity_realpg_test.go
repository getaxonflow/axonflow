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

package audit

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
)

// Real-Postgres SQL/Go parity for the policy-identity extraction chain
// (#3243 v9.16.1, second R3 round).
//
// WHY A REAL DATABASE: the Go mirror (ExtractPolicyIdentity) is what the
// cross-plane contract tests execute, but the exporters execute the SQL - and
// Postgres jsonb operators have semantics no mock reproduces (`->>0` treats a
// jsonb scalar as a one-element array; `->>` renders raw JSON text for
// object-valued keys). Both R3-confirmed divergences of this PR were exactly
// that class: the SQL resolved something the mirror did not, on a
// regulator-facing field, and every non-DB test stayed green. This test runs
// EVERY vector in policyIdentityParityVectors through the REAL expressions on
// a throwaway postgres:16 (the version the R3 confirmation used) and asserts
// the SQL agrees with the Go mirror AND with the vector's declared expectation.
//
// Hermetic, same pattern as platform/agent/approletest: spins its own
// container, no DATABASE_URL, gated on TEST_PG_INTEGRATION=1 (the
// "Unit Tests: Enterprise-Tagged + Real-PG" CI job sets it).
func TestPolicyIdentitySQL_ParityWithGoExtractor_RealPG(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set - skipping real-Postgres parity test")
	}

	db := startParityPG(t)

	// One SELECT evaluating both expressions over a bound jsonb parameter -
	// the exact strings the exporters embed, no rewriting.
	query := "SELECT " + PolicyIdentitySQLExpr("$1::jsonb") + ", " + PolicyVersionSQLExpr("$1::jsonb")

	ran := 0
	for _, tc := range policyIdentityParityVectors {
		t.Run(tc.name, func(t *testing.T) {
			// A malformed-JSON vector cannot exist in a jsonb COLUMN (Postgres
			// rejects it at write time); it exists to prove the GO side never
			// panics. The cast erroring here is the correct SQL behavior.
			var sqlID, sqlVer string
			if err := db.QueryRow(query, tc.details).Scan(&sqlID, &sqlVer); err != nil {
				if tc.name == "malformed json resolves empty, never panics" {
					return
				}
				t.Fatalf("query: %v", err)
			}
			ran++

			goID, goVer := ExtractPolicyIdentity([]byte(tc.details))
			if sqlID != goID || sqlVer != goVer {
				t.Errorf("SQL/Go DIVERGE on %s:\n  SQL (id=%q, ver=%q)\n  Go  (id=%q, ver=%q)\n  details: %s",
					tc.name, sqlID, sqlVer, goID, goVer, tc.details)
			}
			if sqlID != tc.wantIdentity || sqlVer != tc.wantVersion {
				t.Errorf("SQL resolved (id=%q, ver=%q), vector wants (id=%q, ver=%q) for %s",
					sqlID, sqlVer, tc.wantIdentity, tc.wantVersion, tc.details)
			}
		})
	}
	if ran == 0 {
		t.Fatal("no parity vectors executed against Postgres; the parity gate asserted nothing")
	}
}

// TestPolicyIdentitySetSQL_ParityWithGoExtractor_RealPG is the same gate for
// the WIDENED chain (#3426): the top-policies aggregation behind the portal
// tile and the Compliance Report export groups on
// PolicyIdentitySetSQLExpr, so a Postgres/Go divergence there under-reports
// which policies fired on a regulator artifact, exactly the class this file
// already exists for.
//
// It asserts three things per vector, on real PG16:
//
//  1. the SQL set equals the Go set, element for element and in order;
//  2. the set equals the vector's declared expectation;
//  3. set[1] equals the SCALAR expression's identity, evaluated in the SAME
//     statement. That is the invariant that keeps a chip reconcilable with
//     the Policy column beside it, and no amount of Go-side testing can
//     establish it for the SQL.
func TestPolicyIdentitySetSQL_ParityWithGoExtractor_RealPG(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set - skipping real-Postgres parity test")
	}

	db := startParityPG(t)

	// The exact strings the aggregation embeds, no rewriting. identity_is_name
	// rides along in the SAME statement: it selects out of the same arm chain,
	// so a divergence between it and the Go mirror would label a chip as a
	// stamped NAME on a row that only ever recorded an id (or hide the marker
	// on one that did), which is the #3347 / AU-9 discipline failing silently.
	query := "SELECT " + PolicyIdentitySetSQLExpr("$1::jsonb") +
		", " + PolicyIdentitySQLExpr("$1::jsonb") +
		", " + PolicyIdentityIsNameSQLExpr("$1::jsonb")

	ran := 0
	for _, tc := range policyIdentityParityVectors {
		t.Run(tc.name, func(t *testing.T) {
			var sqlSet pq.StringArray
			var sqlScalar string
			var sqlIsName sql.NullBool
			if err := db.QueryRow(query, tc.details).Scan(&sqlSet, &sqlScalar, &sqlIsName); err != nil {
				// Same rationale as the scalar test: a malformed-JSON vector
				// cannot exist in a jsonb COLUMN, so the cast erroring is
				// correct SQL behaviour.
				if tc.name == "malformed json resolves empty, never panics" {
					return
				}
				t.Fatalf("query: %v", err)
			}
			ran++

			goSet := ExtractPolicyIdentities([]byte(tc.details))
			if !sameStrings(sqlSet, goSet) {
				t.Errorf("SQL/Go DIVERGE on %s:\n  SQL %q\n  Go  %q\n  details: %s",
					tc.name, []string(sqlSet), goSet, tc.details)
			}
			if want := tc.wantSet(); !sameStrings(sqlSet, want) {
				t.Errorf("SQL resolved %q, vector wants %q for %s",
					[]string(sqlSet), want, tc.details)
			}
			// identity_is_name parity, SQL against the Go mirror. NULL and
			// not-resolved must coincide: a flag that resolves when no identity
			// does would render a marker decision for a policy that is not there.
			goIsName, goResolved := ExtractPolicyIdentityIsName([]byte(tc.details))
			if sqlIsName.Valid != goResolved {
				t.Errorf("identity_is_name RESOLUTION diverges on %s: SQL valid=%v, Go resolved=%v (details: %s)",
					tc.name, sqlIsName.Valid, goResolved, tc.details)
			} else if goResolved && sqlIsName.Bool != goIsName {
				t.Errorf("identity_is_name VALUE diverges on %s: SQL %v, Go %v (details: %s)",
					tc.name, sqlIsName.Bool, goIsName, tc.details)
			}
			// The flag must agree with the identity itself: a resolved scalar and
			// a resolved flag are the same event.
			if (sqlScalar != "") != sqlIsName.Valid {
				t.Errorf("scalar=%q but identity_is_name valid=%v on %s; the flag and the identity resolved out of different arms",
					sqlScalar, sqlIsName.Valid, tc.details)
			}

			// The reconcilability invariant.
			if len(sqlSet) == 0 {
				if sqlScalar != "" {
					t.Errorf("SQL set is empty but the scalar chain resolved %q on %s", sqlScalar, tc.details)
				}
				return
			}
			if sqlSet[0] != sqlScalar {
				t.Errorf("SQL set[1]=%q but the scalar chain resolves %q on %s; the aggregation would name a policy the Policy column never shows",
					sqlSet[0], sqlScalar, tc.details)
			}
		})
	}
	if ran == 0 {
		t.Fatal("no parity vectors executed against Postgres; the set parity gate asserted nothing")
	}
}

// TestTopPoliciesQuery_AggregatesEveryPlane_RealPG executes the SHARED
// aggregation both #3426 surfaces now build, over rows written in the shapes
// the live writers produce, and asserts the pre-fix predicate would have
// dropped most of them.
//
// This is the SQL-level twin of the runtime-e2e: the suite drives the real
// planes end to end, this pins the query against every historical shape at
// once, including the ones no live plane emits any more.
func TestTopPoliciesQuery_AggregatesEveryPlane_RealPG(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set - skipping real-Postgres aggregation test")
	}

	db := startParityPG(t)
	// request_type is NOT NULL exactly as migration core/059 has it. The column
	// was absent from this DDL until #3438 R3, which is why the aggregation's
	// override exclusion could be keyed on the wrong column with this test
	// green: a hand-built DDL only covers the query you already wrote.
	if _, err := db.Exec(`CREATE TABLE audit_logs (
		id serial PRIMARY KEY,
		tenant_id text,
		timestamp timestamptz,
		request_type varchar(50) NOT NULL,
		policy_decision text,
		policy_details jsonb)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	rows := []struct {
		requestType string
		verdict     string
		details     string
	}{
		// decide plane + FinCrime seam: three controls on ONE row, no
		// singular policy_name anywhere. Pre-fix: excluded entirely.
		{"llm_chat", "blocked", `{"policy_ids":["fincrime_structuring","fincrime_high_risk_geo","fincrime_ml_risk_score"],"policy_names":["Structuring","High-Risk Jurisdiction","ML Fraud Score"]}`},
		{"llm_chat", "blocked", `{"policy_ids":["fincrime_structuring"],"policy_names":["Structuring"]}`},
		// MCP check-input shape: policy_matches + policy_names, no ids.
		{"mcp_check_input", "blocked", `{"policy_matches":[{"policy_id":"sql-injection-block","policy_version":3}],"policy_names":["SQL Injection Block"]}`},
		// Legacy CSV names.
		{"llm_chat", "redacted", `{"policy_names":"fincrime_structuring, legacy_only"}`},
		// HITL singular scalars: the ONE shape the pre-fix query could see.
		{"llm_chat", "needs_approval", `{"workflow_id":"w1","policy_id":"hv-wire-oversight","policy_name":"High-Value Wire Transfer Oversight"}`},
		// A row with no identity at all contributes nothing.
		{"llm_chat", "allowed", `{"decision_id":"d9"}`},
		// OVERRIDE LIFECYCLE ROWS. LogOverrideEvent stamps the PLURAL
		// policy_ids and never the singular policy_name, so pre-fix these
		// failed the `policy_name IS NOT NULL` filter and were dropped by
		// accident; the widened chain resolves them, and counting them would
		// be a regression on a compliance artifact. override_used is the worst
		// case: it is written three lines after `result.Allowed = true` and
		// names the policy whose block was BYPASSED, so an actively-overridden
		// policy could top "Top Triggered Policies" while being the one policy
		// that was not enforced. Both must contribute ZERO.
		//
		// fincrime_structuring is used deliberately: it ALSO fires on real
		// rows above, so the assertion is that its count does not MOVE, which
		// is strictly stronger than a policy that only appears here.
		{"override_created", DecisionOverrideLifecycle, `{"override_id":"ov-1","policy_ids":["fincrime_structuring"],"policy_names":["Structuring"],"reason":"break glass"}`},
		{"override_used", DecisionOverrideLifecycle, `{"override_id":"ov-1","policy_ids":["fincrime_structuring"],"policy_names":["Structuring"],"decision_id":"d-42"}`},
		// A lifecycle row naming a policy NOTHING else recorded must not
		// create a policy on the report at all.
		{"override_revoked", DecisionOverrideLifecycle, `{"override_id":"ov-2","policy_ids":["override_only_never_fired"]}`},
		// THE MCP PLANE'S OVERRIDE ROW (#3438 R3 BLOCKER 2). Its writer is
		// platform/agent writeOverrideUsedEvent, which stamps
		// policy_decision = "allowed" and request_type = "override_used" - so
		// the policy_decision-keyed exclusion above never saw it, and the
		// policy whose block it records as BYPASSED was ranked as a trigger.
		// Same discipline as the lifecycle rows: on a policy that genuinely
		// fired, so the assertion is that the count does not MOVE.
		{"override_used", DecisionAllowed, `{"override_id":"ov-3","decision_id":"d-77","policy_id":"fincrime_structuring","policy_name":"Structuring","policy_versions":{"fincrime_structuring":3}}`},
		{"override_used", DecisionAllowed, `{"override_id":"ov-4","decision_id":"d-78","policy_id":"mcp_override_only","policy_name":"MCP Override Only"}`},
	}
	ts := time.Now().UTC()
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO audit_logs (tenant_id, timestamp, request_type, policy_decision, policy_details)
			VALUES ('acme', $1, $2, $3, $4::jsonb)`, ts, r.requestType, r.verdict, r.details); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	got := map[string][2]int{}
	gotIsName := map[string]bool{}
	totalPolicies := -1
	q := TopPoliciesQuery("tenant_id = $1", "$2")
	res, err := db.Query(q, "acme", pq.Array(Spellings(DecisionBlocked)))
	if err != nil {
		t.Fatalf("aggregation query: %v\n%s", err, q)
	}
	defer func() { _ = res.Close() }()
	var order []string
	for res.Next() {
		var name string
		var identityIsName bool
		var triggers, blocks, total int
		if err := res.Scan(&name, &identityIsName, &triggers, &blocks, &total); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[name] = [2]int{triggers, blocks}
		gotIsName[name] = identityIsName
		totalPolicies = total
		order = append(order, name)
	}
	if err := res.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	want := map[string][2]int{
		// two decide rows + the legacy CSV row; two of the three blocked.
		"fincrime_structuring":   {3, 2},
		"fincrime_high_risk_geo": {1, 1},
		"fincrime_ml_risk_score": {1, 1},
		"sql-injection-block":    {1, 1},
		"legacy_only":            {1, 0},
		// The HITL exception must still be counted, not swapped out.
		"hv-wire-oversight": {1, 0},
	}
	for name, w := range want {
		if g, ok := got[name]; !ok {
			t.Errorf("policy %q missing from the aggregation (got %v)", name, got)
		} else if g != w {
			t.Errorf("policy %q = (triggers %d, blocks %d), want (%d, %d)", name, g[0], g[1], w[0], w[1])
		}
	}
	if len(got) != len(want) {
		t.Errorf("aggregation returned %d policies, want %d: %v", len(got), len(want), got)
	}
	// No display names leak in beside the ids they were stamped with: one arm
	// supplies the whole set.
	if _, ok := got["Structuring"]; ok {
		t.Errorf("display name counted alongside its id; the arms are not exclusive: %v", got)
	}
	// Deterministic order: the top policy first, ties broken by identity.
	if len(order) > 0 && order[0] != "fincrime_structuring" {
		t.Errorf("ordering is not trigger_count DESC: %v", order)
	}

	// OVERRIDE LIFECYCLE ROWS CONTRIBUTE NOTHING. Three of them were seeded,
	// two on a policy that genuinely fired and one on a policy that never did.
	// Without the exclusion the first two would push fincrime_structuring from
	// 3 to 5 (already covered by the `want` comparison above, which is why the
	// counts there are the pre-lifecycle numbers) and the third would invent a
	// policy on the report.
	if _, ok := got["override_only_never_fired"]; ok {
		t.Errorf("an override LIFECYCLE row created a policy on the aggregation: %v", got)
	}
	// And the MCP plane's own override row, which the policy_decision-keyed
	// exclusion did not cover: it carries verdict "allowed", so it was counted.
	if _, ok := got["mcp_override_only"]; ok {
		t.Errorf("an MCP override_used row created a policy on the aggregation; "+
			"the exclusion is keyed on policy_decision instead of request_type: %v", got)
	}
	// The fixture must actually contain those rows, and the widened chain must
	// actually resolve them -- otherwise this assertion passes for the wrong
	// reason and would keep passing if the exclusion were deleted.
	var lifecycleRows, lifecycleResolvable int
	if err := db.QueryRow(`SELECT count(*), count(*) FILTER (WHERE cardinality(`+
		PolicyIdentitySetSQLExpr("policy_details")+`) > 0)
		FROM audit_logs WHERE policy_decision = $1`, DecisionOverrideLifecycle).
		Scan(&lifecycleRows, &lifecycleResolvable); err != nil {
		t.Fatalf("lifecycle precondition probe: %v", err)
	}
	if lifecycleRows != 3 {
		t.Fatalf("fixture holds %d override_lifecycle rows, want 3", lifecycleRows)
	}
	if lifecycleResolvable != 3 {
		t.Fatalf("only %d of 3 override_lifecycle rows resolve an identity through the widened chain; "+
			"this test cannot tell the exclusion from a chain that never saw them", lifecycleResolvable)
	}
	// The SAME preconditions for the MCP shape, and one more that is the whole
	// point: those rows must NOT be reachable by the policy_decision predicate,
	// or the fixture does not reproduce the defect at all.
	var mcpRows, mcpResolvable, mcpCaughtByDecision int
	if err := db.QueryRow(`SELECT count(*), count(*) FILTER (WHERE cardinality(`+
		PolicyIdentitySetSQLExpr("policy_details")+`) > 0),
		count(*) FILTER (WHERE policy_decision = $2)
		FROM audit_logs WHERE request_type = $1`, "override_used", DecisionOverrideLifecycle).
		Scan(&mcpRows, &mcpResolvable, &mcpCaughtByDecision); err != nil {
		t.Fatalf("MCP override precondition probe: %v", err)
	}
	// Three request_type='override_used' rows: one orchestrator lifecycle row
	// plus the two MCP rows.
	if mcpRows != 3 || mcpResolvable != 3 {
		t.Fatalf("fixture holds %d override_used rows of which %d resolve an identity, want 3 and 3", mcpRows, mcpResolvable)
	}
	if mcpCaughtByDecision != 1 {
		t.Fatalf("%d of the 3 override_used rows carry policy_decision=%q, want exactly 1; "+
			"the two MCP rows must be invisible to the policy_decision predicate or this test "+
			"cannot distinguish the request_type exclusion from the old one",
			mcpCaughtByDecision, DecisionOverrideLifecycle)
	}

	// identity_is_name reports WHICH ARM resolved, so the renderer can show the
	// #3347 marker beside a raw id instead of passing it off as a stamped name.
	wantIsName := map[string]bool{
		// Resolved from the policy_ids arm on two decide rows (an identifier)
		// AND from the legacy CSV policy_names arm on a third (a name). The
		// aggregate uses bool_and, so a group with ANY id-resolved row keeps
		// the marker: claiming "name recorded" would be false for those rows.
		"fincrime_structuring":   false,
		"fincrime_high_risk_geo": false,
		"fincrime_ml_risk_score": false,
		"sql-injection-block":    false, // policy_matches[*].policy_id: an identifier
		"legacy_only":            true,  // legacy CSV policy_names: a stamped name
		"hv-wire-oversight":      false, // singular policy_id beats policy_name
	}
	for name, wantFlag := range wantIsName {
		if gotFlag, ok := gotIsName[name]; ok && gotFlag != wantFlag {
			t.Errorf("policy %q identity_is_name = %v, want %v", name, gotFlag, wantFlag)
		}
	}

	// The pre-LIMIT distinct total, so a truncated table can disclose its scope.
	if totalPolicies != len(want) {
		t.Errorf("total_policies = %d, want %d (the distinct policy count before LIMIT)", totalPolicies, len(want))
	}

	// THE PRE-FIX PREDICATE, run side by side. It is what the two surfaces
	// used before #3426, and it must see exactly the HITL row.
	var preFix int
	if err := db.QueryRow(`SELECT count(DISTINCT policy_details->>'policy_name')
		FROM audit_logs WHERE tenant_id = 'acme' AND policy_details->>'policy_name' IS NOT NULL`).Scan(&preFix); err != nil {
		t.Fatalf("pre-fix probe: %v", err)
	}
	// 3, not 1: the HITL row plus the two MCP override_used rows, which stamp
	// the singular policy_name and which the pre-fix predicate therefore DID
	// count - one of the reasons an overridden policy topped the table.
	if preFix != 3 {
		t.Fatalf("pre-fix predicate saw %d policies; the fixture no longer reproduces #3426", preFix)
	}
	if len(got) <= preFix {
		t.Errorf("the fix reports %d policies, the pre-fix predicate saw %d; this test does not discriminate", len(got), preFix)
	}
}

// sameStrings compares two identity sets element for element, treating nil and
// empty as equal (a row with no identity resolves to no policies either way).
func sameStrings(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// startParityPG starts a throwaway postgres:16 container and returns an open,
// pinged connection. Mirrors approletest's container bring-up (including the
// docker-port polling race note there) without importing an agent package
// from a shared-package test.
func startParityPG(t *testing.T) *sql.DB {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("TEST_PG_INTEGRATION=1 is set but docker is not available; refusing to skip a requested integration test")
	}

	name := fmt.Sprintf("axonflow-test-policyid-pg-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d",
		"--name", name,
		"-e", "POSTGRES_PASSWORD=testpass",
		"-e", "POSTGRES_DB=axonflow_test",
		"-p", "0:5432",
		"postgres:16",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, string(out))
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	var hostPort string
	deadline := time.Now().Add(30 * time.Second)
	for hostPort == "" {
		if time.Now().After(deadline) {
			t.Fatal("docker port mapping did not resolve within 30s")
		}
		if portBytes, portErr := exec.Command("docker", "port", name, "5432/tcp").CombinedOutput(); portErr == nil {
			line := strings.TrimSpace(strings.Split(string(portBytes), "\n")[0])
			if parts := strings.Split(line, ":"); len(parts) >= 2 && parts[len(parts)-1] != "" {
				hostPort = parts[len(parts)-1]
			}
		}
		if hostPort == "" {
			time.Sleep(500 * time.Millisecond)
		}
	}

	dsn := fmt.Sprintf("postgres://postgres:testpass@127.0.0.1:%s/axonflow_test?sslmode=disable", hostPort)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	deadline = time.Now().Add(60 * time.Second)
	for {
		if err := db.Ping(); err == nil {
			return db
		}
		if time.Now().After(deadline) {
			t.Fatal("postgres did not become ready within 60s")
		}
		time.Sleep(500 * time.Millisecond)
	}
}
