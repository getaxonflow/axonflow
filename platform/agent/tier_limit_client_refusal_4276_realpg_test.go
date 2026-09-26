// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #4276 on a real Postgres admission ledger: the human ceiling's boundary
// (count < limit admits) through the real advisory-locked INSERT, and the
// (N+1)th principal refused on /api/request in the one ClientResponse shape.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (the admission_realpg_test.go
// harness).

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"axonflow/platform/agent/license"
	"axonflow/platform/agent/license/admission"
)

func TestAPIRequestHumanCeilingBoundaryOnTheRealLedger_RealPG(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres admission boundary test")
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
	prev := tierAdmitter.Load()
	tierAdmitter.Store(admission.New(ledger, admission.WithTierReader(communityReader)))
	t.Cleanup(func() { tierAdmitter.Store(prev) })

	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{latencies: []int64{}, lastLatencies: []int64{}, staticPolicyLatencies: []int64{}, dynamicPolicyLatencies: []int64{}}
	}
	secret := tierRequestClient(t, "tier-4276-client")

	humanRows := func() int {
		var n int
		tx, err := owner.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec("SELECT set_config('app.current_org_id', $1, true)", tierRequestOrg); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(`SELECT count(*) FROM principal_admissions WHERE org_id = $1 AND dimension = 'human_principal'`, tierRequestOrg).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	n := license.CommunityLimits.MaxHumanPrincipals // 25
	// N-1 distinct principals: admitted, N-1 rows.
	for i := 1; i < n; i++ {
		if ref := admitPrincipal(context.Background(), admission.HumanPrincipal, tierRequestOrg, fmt.Sprintf("h-%d@example.com", i)); ref != nil {
			t.Fatalf("principal %d of %d refused: %+v", i, n, ref.Decision)
		}
	}
	if got := humanRows(); got != n-1 {
		t.Fatalf("after N-1 admissions the ledger holds %d human rows, want %d", got, n-1)
	}
	// The Nth distinct principal: admitted (count N-1 < limit N), N rows.
	if ref := admitPrincipal(context.Background(), admission.HumanPrincipal, tierRequestOrg, fmt.Sprintf("h-%d@example.com", n)); ref != nil {
		t.Fatalf("the Nth principal refused: %+v", ref.Decision)
	}
	if got := humanRows(); got != n {
		t.Fatalf("after N admissions the ledger holds %d human rows, want %d", got, n)
	}

	// The (N+1)th, on /api/request: the one shape, over_limit, no Retry-After,
	// and no row written.
	tok := generateTestJWTWithOrgEmail(1, tierRequestOrg, tierRequestOrg, "h-next@example.com", []string{"query"}, "developer")
	w := postAPIRequest(t, "tier-4276-client", secret, tok)
	assertTierClientRefusal(t, w, admission.HumanPrincipal.Code(), "")
	if want := fmt.Sprintf("%d are already admitted", n); !strings.Contains(w.Body.String(), want) {
		t.Errorf("the refusal does not state the ceiling's count %d: %s", n, w.Body.String())
	}
	if got := humanRows(); got != n {
		t.Errorf("the refused principal wrote a row: %d human rows, want %d", got, n)
	}

	// Repeating the Nth through a COLD admitter (no seen-set): admitted from
	// the ledger, still N rows.
	cold := admission.New(ledger, admission.WithTierReader(communityReader))
	dec, err := cold.Admit(context.Background(), admission.Request{Dimension: admission.HumanPrincipal, OrgID: tierRequestOrg, PrincipalID: fmt.Sprintf("h-%d@example.com", n)})
	if err != nil || !dec.Allowed || dec.Source != admission.SourceLedgerExisting {
		t.Fatalf("repeating the Nth principal: %+v err=%v, want admitted from the ledger", dec, err)
	}
	if got := humanRows(); got != n {
		t.Errorf("the repeat wrote a row: %d human rows, want %d", got, n)
	}
}
