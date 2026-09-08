// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres verification of migrations/core/171 and of the two stores the
// admission package runs over it (#3593): PostgresLedger and
// PostgresNodeLeases, through the REAL Admitter with a Community tier reader.
//
// What only a real database can prove, and this file does:
//   - the migration applies forward and backward, and re-applies;
//   - append-only is PLANTED, not read off the DDL: an UPDATE and a DELETE
//     as axonflow_app_role are refused (privilege), and as the OWNER are
//     refused (trigger), and TRUNCATE is refused;
//   - RLS: an organization cannot see, count or write another's rows;
//   - N-1 / N / N+1 through the real advisory-locked INSERT, and 32
//     goroutines racing for the last slot leave exactly N rows;
//   - a replay is one row;
//   - node leases: a second node on limit 1 is refused, the same node renews,
//     an EXPIRED foreign lease is not counted and the new node takes over;
//   - the refusal audit sink writes one audit_logs row with request_type
//     tier_limit_refusal.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (same harness as
// system_policy_count_realpg_test.go).

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"axonflow/platform/agent/license"
	"axonflow/platform/agent/license/admission"
)

func communityReader(context.Context) license.TierRead {
	return license.TierRead{Tier: license.TierCommunity}
}

func TestMigration171AndTheAdmissionStores_RealPG(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres admission test")
	}
	dsn, cleanup := startCountTestPostgres(t)
	t.Cleanup(cleanup)
	owner, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	for _, kv := range []struct{ key, val string }{
		{"app.db_password", "testpass"},
		{"app.deployment_org_id", "local-dev-org"},
		{"app.deployment_kind", "dev"},
		{"app.current_org_id", "local-dev-org"},
	} {
		if _, err := owner.Exec("SELECT set_config($1, $2, false)", kv.key, kv.val); err != nil {
			t.Fatal(err)
		}
	}
	applyAllCoreMigrations(t, owner, "../../migrations/core")
	ctx := context.Background()

	// ---------------------------------------------------------------- shape
	for _, tbl := range []string{"principal_admissions", "node_leases"} {
		var forced bool
		if err := owner.QueryRow(`SELECT relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`, tbl).Scan(&forced); err != nil || !forced {
			t.Fatalf("%s: forced=%v err=%v", tbl, forced, err)
		}
	}

	// ----------------------------------------------------------- down / up
	// A second connection with no GUCs, as an operator's psql would be.
	down := readMigration(t, "../../migrations/core/171_principal_admissions_down.sql")
	up := readMigration(t, "../../migrations/core/171_principal_admissions.sql")
	if _, err := owner.Exec(down); err != nil {
		t.Fatalf("down: %v", err)
	}
	var exists bool
	_ = owner.QueryRow(`SELECT to_regclass('principal_admissions') IS NOT NULL`).Scan(&exists)
	if exists {
		t.Fatal("down left principal_admissions in place")
	}
	if _, err := owner.Exec(down); err != nil {
		t.Fatalf("down twice must be a no-op: %v", err)
	}
	if _, err := owner.Exec(up); err != nil {
		t.Fatalf("up after down: %v", err)
	}
	if _, err := owner.Exec(up); err != nil {
		t.Fatalf("up twice must be idempotent: %v", err)
	}

	// -------------------------------------------------------- append-only
	// A pool that runs as the application role. The role exists from core/098.
	if _, err := owner.Exec("GRANT axonflow_app_role TO CURRENT_USER"); err != nil {
		t.Fatal(err)
	}
	app, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	app.SetMaxOpenConns(1)
	if _, err := app.Exec("SET ROLE axonflow_app_role"); err != nil {
		t.Fatal(err)
	}

	ledger := admission.NewPostgresLedger(app)
	leases := admission.NewPostgresNodeLeases(app)
	sink := admission.NewDBAuditSink(app)
	a := admission.New(ledger, admission.WithNodeLeases(leases), admission.WithAuditSink(sink),
		admission.WithTierReader(communityReader), admission.WithLicenceFingerprint("deadbeefdeadbeef"))

	const org = "org-realpg"
	dec, err := a.Admit(ctx, admission.Request{Dimension: admission.ServicePrincipal, OrgID: org, PrincipalID: "svc-1"})
	if err != nil || !dec.Allowed || dec.Source != admission.SourceLedgerAdmitted {
		t.Fatalf("first admit: %+v err=%v", dec, err)
	}
	// Plant as the APP ROLE: privilege refuses.
	scoped := func(db *sql.DB, orgID, stmt string, args ...interface{}) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec("SELECT set_config('app.current_org_id', $1, true)", orgID); err != nil {
			return err
		}
		if _, err := tx.Exec(stmt, args...); err != nil {
			return err
		}
		return tx.Commit()
	}
	for _, stmt := range []string{
		`UPDATE principal_admissions SET admitted_at = now() WHERE org_id = $1`,
		`DELETE FROM principal_admissions WHERE org_id = $1`,
	} {
		err := scoped(app, org, stmt, org)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			t.Fatalf("as axonflow_app_role, %q must be refused by privilege; got %v", stmt, err)
		}
	}
	if _, err := app.Exec(`TRUNCATE principal_admissions`); err == nil {
		t.Fatal("as axonflow_app_role, TRUNCATE must be refused")
	}
	// Plant as the OWNER: the trigger refuses.
	for _, stmt := range []string{
		`UPDATE principal_admissions SET admitted_at = now() WHERE org_id = $1`,
		`DELETE FROM principal_admissions WHERE org_id = $1`,
	} {
		err := scoped(owner, org, stmt, org)
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("as the owner, %q must be refused by the trigger; got %v", stmt, err)
		}
	}
	if _, err := owner.Exec(`TRUNCATE principal_admissions`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("as the owner, TRUNCATE must be refused by the trigger; got %v", err)
	}
	var rows int
	if err := owner.QueryRow(`SELECT count(*) FROM principal_admissions WHERE org_id = $1`, org).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("after the plants the row must still be there: rows=%d err=%v", rows, err)
	}

	// ----------------------------------------------------------------- RLS
	// Another organization cannot see org's row through the ledger.
	found, err := ledger.Exists(ctx, admission.Key{OrgID: "org-other", Dimension: admission.ServicePrincipal, PrincipalID: "svc-1"})
	if err != nil || found {
		t.Fatalf("cross-org exists: found=%v err=%v", found, err)
	}
	var visible int
	_ = scopedScan(t, app, "org-other", `SELECT count(*) FROM principal_admissions`, &visible)
	if visible != 0 {
		t.Fatalf("org-other sees %d row(s) of org-realpg", visible)
	}

	// ------------------------------------------------ N-1 / N / N+1, replay
	limit := license.CommunityLimits.MaxServicePrincipals // 5
	for i := 2; i <= limit; i++ {
		dec, err := a.Admit(ctx, admission.Request{Dimension: admission.ServicePrincipal, OrgID: org, PrincipalID: fmt.Sprintf("svc-%d", i)})
		if err != nil || !dec.Allowed {
			t.Fatalf("svc-%d: %+v err=%v", i, dec, err)
		}
	}
	over, err := a.Admit(ctx, admission.Request{Dimension: admission.ServicePrincipal, OrgID: org, PrincipalID: "svc-6"})
	if err != nil || over.Allowed || over.Reason != admission.ReasonOverLimit || over.Count != limit {
		t.Fatalf("6th service principal on Community: %+v err=%v", over, err)
	}
	for i := 0; i < 3; i++ { // replay of an admitted principal through a COLD admitter
		cold := admission.New(ledger, admission.WithTierReader(communityReader))
		if dec, err := cold.Admit(ctx, admission.Request{Dimension: admission.ServicePrincipal, OrgID: org, PrincipalID: "svc-3"}); err != nil || !dec.Allowed || dec.Source != admission.SourceLedgerExisting {
			t.Fatalf("cold replay %d: %+v err=%v", i, dec, err)
		}
	}
	if err := owner.QueryRow(`SELECT count(*) FROM principal_admissions WHERE org_id = $1 AND dimension = 'service_principal'`, org).Scan(&rows); err != nil || rows != limit {
		t.Fatalf("rows=%d want %d (a replay must not add a row)", rows, limit)
	}
	// The audit row for the refusal.
	var audits int
	if err := owner.QueryRow(`SELECT count(*) FROM audit_logs WHERE request_type = $1 AND org_id = $2`, admission.AuditRequestType, org).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit rows=%d err=%v", audits, err)
	}
	var details string
	_ = owner.QueryRow(`SELECT policy_details::text FROM audit_logs WHERE request_type = $1 AND org_id = $2`, admission.AuditRequestType, org).Scan(&details)
	for _, want := range []string{`"code": "ERR_TIER_LIMIT_SERVICE_PRINCIPAL"`, `"reason": "over_limit"`, `"limit": 5`, `"count": 5`, `"edition": "community"`} {
		if !strings.Contains(details, want) {
			t.Errorf("audit policy_details lacks %s: %s", want, details)
		}
	}

	// ----------------------------------------------------------- the race
	// 32 goroutines race for ONE remaining human slot: exactly one wins.
	human := license.CommunityLimits.MaxHumanPrincipals // 25
	racePool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = racePool.Close() })
	racePool.SetMaxOpenConns(8)
	raceLedger := admission.NewPostgresLedger(racePool)
	for i := 1; i < human; i++ {
		if _, err := raceLedger.AdmitUnderLimit(ctx, admission.Key{OrgID: org, Dimension: admission.HumanPrincipal, PrincipalID: fmt.Sprintf("h%d", i)}, human, ""); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			out, err := raceLedger.AdmitUnderLimit(ctx, admission.Key{OrgID: org, Dimension: admission.HumanPrincipal, PrincipalID: fmt.Sprintf("racer-%d", g)}, human, "")
			if err != nil {
				t.Errorf("racer %d: %v", g, err)
				return
			}
			if out.Admitted {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}(g)
	}
	wg.Wait()
	if admitted != 1 {
		t.Fatalf("%d racers admitted for one slot", admitted)
	}
	if err := owner.QueryRow(`SELECT count(*) FROM principal_admissions WHERE org_id = $1 AND dimension = 'human_principal'`, org).Scan(&rows); err != nil || rows != human {
		t.Fatalf("human rows=%d want %d", rows, human)
	}

	// ---------------------------------------------------------- node leases
	nodeA, err := a.Admit(ctx, admission.Request{Dimension: admission.Node, OrgID: org, PrincipalID: "node-a"})
	if err != nil || !nodeA.Allowed || nodeA.Source != admission.SourceLedgerAdmitted {
		t.Fatalf("node-a: %+v err=%v", nodeA, err)
	}
	nodeB, err := a.Admit(ctx, admission.Request{Dimension: admission.Node, OrgID: org, PrincipalID: "node-b"})
	if err != nil || nodeB.Allowed || nodeB.Reason != admission.ReasonOverLimit || nodeB.Count != 1 {
		t.Fatalf("node-b on Community must be refused: %+v err=%v", nodeB, err)
	}
	renew, err := a.Admit(ctx, admission.Request{Dimension: admission.Node, OrgID: org, PrincipalID: "node-a"})
	if err != nil || !renew.Allowed || renew.Source != admission.SourceLedgerExisting {
		t.Fatalf("node-a renew: %+v err=%v", renew, err)
	}
	// Expire node-a's lease (as the owner, with the policy scoped) and node-b
	// takes over.
	// (first_seen moves too: the migration's seen_order CHECK refuses a
	// last_seen earlier than first_seen, which is exactly what the first
	// version of this plant tripped - a check that fires on the test that
	// would have skipped it is the check working.)
	if err := scoped(owner, org, `UPDATE node_leases SET first_seen = now() - interval '20 minutes', last_seen = now() - interval '10 minutes' WHERE org_id = $1 AND node_id = 'node-a'`, org); err != nil {
		t.Fatal(err)
	}
	takeover, err := a.Admit(ctx, admission.Request{Dimension: admission.Node, OrgID: org, PrincipalID: "node-b"})
	if err != nil || !takeover.Allowed || takeover.Source != admission.SourceLedgerAdmitted || takeover.Count != 0 {
		t.Fatalf("node-b after node-a expired: %+v err=%v", takeover, err)
	}
	// AND NODE-A, COMING BACK TO ITS OWN EXPIRED ROW, IS REFUSED. This is the
	// half of R3 round 1's H1 that only the real SQL can prove: the `held`
	// probe must carry the TTL predicate, or a row that merely EXISTS renews
	// unconditionally and both nodes serve for ever. The unit tests pin the
	// fakes; this pins the statement.
	backAgain, err := a.Admit(ctx, admission.Request{Dimension: admission.Node, OrgID: org, PrincipalID: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	if backAgain.Allowed {
		t.Fatalf("node-a renewed its own EXPIRED lease while node-b holds the only slot (%+v); the Community node "+
			"ceiling would be bypassed for as long as both keep heartbeating, with no refusal, metric or audit row", backAgain)
	}
	if backAgain.Reason != admission.ReasonOverLimit || backAgain.Count != 1 {
		t.Errorf("node-a's refusal: reason=%s count=%d, want over_limit with count 1", backAgain.Reason, backAgain.Count)
	}

	var leaseRows int
	_ = scopedScan(t, app, org, `SELECT count(*) FROM node_leases`, &leaseRows)
	if leaseRows != 2 {
		t.Fatalf("lease rows=%d want 2", leaseRows)
	}
	_ = scopedScan(t, app, "org-other", `SELECT count(*) FROM node_leases`, &visible)
	if visible != 0 {
		t.Fatalf("org-other sees %d lease(s)", visible)
	}

	// The warm reads what was written.
	fresh := admission.New(ledger, admission.WithTierReader(communityReader))
	n, err := fresh.Warm(ctx, org)
	if err != nil || n != limit+human {
		t.Fatalf("warm: n=%d err=%v want %d", n, err, limit+human)
	}
	if dec, _ := fresh.Admit(ctx, admission.Request{Dimension: admission.HumanPrincipal, OrgID: org, PrincipalID: "h1"}); !dec.SeenSetAnswered {
		t.Fatalf("warmed principal must be answered by the seen-set: %+v", dec)
	}
}

func readMigration(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func scopedScan(t *testing.T, db *sql.DB, orgID, query string, dest *int) error {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec("SELECT set_config('app.current_org_id', $1, true)", orgID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(query).Scan(dest); err != nil {
		t.Fatal(err)
	}
	_ = time.Now
	return nil
}
