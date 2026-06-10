// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"axonflow/platform/agent"
	"axonflow/platform/agent/approletest"

	_ "github.com/lib/pq"
)

// TestOrchestratorPerOrgDetectionOverrides_RealPostgres proves the #2612 per-org
// posture resolution on the ORCHESTRATOR plane against a REAL Postgres with the
// REAL migration 120 applied and RLS ENABLEd+FORCEd, under axonflow_app_role:
//
//   - the override table is org-isolated by RLS (a bare read under app_role with
//     no org scope sees nothing; the scoped repo read sees only its org's rows);
//   - reads work under app_role ON (RLS enforced, WithOrgScope sets the GUC) AND
//     OFF (owner/superuser bypass + the explicit WHERE org_id still scopes);
//   - the SAME orchestrator process resolves DIFFERENT gateway postures for two
//     orgs (org-redact → redact while the global config is block; org-default →
//     global block), through the orchestrator's OWN cache instance + DB handle.
//
// This is the orchestrator sibling of the agent's
// TestPerOrgDetectionOverrides_RealPostgres — same table, same RLS contract, but
// resolved through orchestrator.ResolveGatewayDetectionConfig (the response
// plane's resolver) rather than the agent's.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (approletest.Setup).
func TestOrchestratorPerOrgDetectionOverrides_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	defer func() { _ = masterDB.Close() }()

	// Apply the REAL migration 120 (Setup only runs 1..111). Exercises the
	// migration SQL — RLS ENABLE+FORCE, the isolation policy, the verifier.
	migBytes, err := os.ReadFile("../../migrations/core/120_detection_action_overrides.sql")
	if err != nil {
		t.Fatalf("read migration 120: %v", err)
	}
	if _, err := masterDB.Exec(string(migBytes)); err != nil {
		t.Fatalf("apply migration 120: %v", err)
	}

	ctx := context.Background()
	const (
		orgRedact  = "org-redact"
		orgDefault = "org-default"
	)

	// Seed via the superuser (BYPASSRLS) so we can write any org_id. org-redact
	// overrides PII→redact + SQLi→warn; org-default has NO override row.
	for _, row := range []struct{ org, cat, act string }{
		{orgRedact, "pii", "redact"},
		{orgRedact, "sqli", "warn"},
	} {
		if _, err := masterDB.Exec(
			`INSERT INTO detection_action_overrides (org_id, category, action) VALUES ($1, $2, $3)`,
			row.org, row.cat, row.act); err != nil {
			t.Fatalf("seed override (%s,%s): %v", row.org, row.cat, err)
		}
	}

	// --- app_role ON: RLS is real -------------------------------------------
	appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatalf("open app_role DSN: %v", err)
	}
	defer func() { _ = appRoleDB.Close() }()
	appRoleDB.SetMaxOpenConns(1)
	approletest.AssertCurrentUser(t, appRoleDB, "axonflow_app_role")

	// A bare read under app_role with NO org scope (app.current_org_id unset)
	// must see ZERO rows — proves RLS is enforced (FORCE) for the app role.
	var bareCount int
	if err := appRoleDB.QueryRowContext(ctx,
		`SELECT count(*) FROM detection_action_overrides WHERE org_id = $1`, orgRedact).Scan(&bareCount); err != nil {
		t.Fatalf("bare app_role count: %v", err)
	}
	if bareCount != 0 {
		t.Fatalf("RLS not enforced: bare app_role read saw %d rows (want 0 — no org scope set)", bareCount)
	}

	// The scoped repo read (WithOrgScope sets app.current_org_id) sees exactly
	// org-redact's rows — and NONE of any other org's. Reuses the agent's
	// RLS-scoped repository (the orchestrator does not reimplement the read).
	repo := agent.NewDetectionOverrideRepository(appRoleDB)
	gotRedact, err := repo.ReadOrgOverrides(ctx, orgRedact)
	if err != nil {
		t.Fatalf("ReadOrgOverrides(%s): %v", orgRedact, err)
	}
	if gotRedact["pii"] != agent.DetectionActionRedact || gotRedact["sqli"] != agent.DetectionActionWarn {
		t.Fatalf("org-redact overrides = %v, want pii=redact sqli=warn", gotRedact)
	}
	gotDefault, err := repo.ReadOrgOverrides(ctx, orgDefault)
	if err != nil {
		t.Fatalf("ReadOrgOverrides(%s): %v", orgDefault, err)
	}
	if len(gotDefault) != 0 {
		t.Fatalf("org-default must have no overrides (RLS isolation); got %v", gotDefault)
	}

	// --- app_role OFF: owner/superuser bypass + WHERE scoping ---------------
	// Mirrors AXONFLOW_DB_USE_APP_ROLE=false: the connection bypasses RLS, so
	// correctness relies on the explicit WHERE org_id in the repo query.
	repoOff := agent.NewDetectionOverrideRepository(masterDB)
	gotOff, err := repoOff.ReadOrgOverrides(ctx, orgRedact)
	if err != nil {
		t.Fatalf("ReadOrgOverrides(off-mode, %s): %v", orgRedact, err)
	}
	if gotOff["pii"] != agent.DetectionActionRedact || len(gotOff) != 2 {
		t.Fatalf("off-mode read = %v, want exactly org-redact's 2 rows (WHERE-scoped)", gotOff)
	}

	// --- SAME orchestrator process, two orgs, different gateway posture ------
	// Pin the deployment-global gateway posture to block via env, wire the
	// ORCHESTRATOR cache to the real app_role DB, and resolve both orgs through
	// the response plane's resolver.
	t.Setenv("PII_ACTION", "block")
	agent.ResetDetectionConfigCache()
	t.Cleanup(agent.ResetDetectionConfigCache)

	setDetectionOverrideCacheForTest(newDetectionOverrideCache(repo, time.Minute, defaultDetectionOverrideMaxEntries))
	t.Cleanup(ResetDetectionOverrideCacheForTest)

	if got := ResolveGatewayDetectionConfig(ctx, orgRedact).PIIAction; got != agent.DetectionActionRedact {
		t.Errorf("orchestrator org-redact gateway PIIAction = %q, want redact", got)
	}
	if got := ResolveGatewayDetectionConfig(ctx, orgDefault).PIIAction; got != agent.DetectionActionBlock {
		t.Errorf("orchestrator org-default gateway PIIAction = %q, want block (global)", got)
	}
	// The skipRedaction signal: org-redact reports an explicit PII override;
	// org-default does not (so it follows the deployment-global baseline).
	if a, ok := ResolveGatewayPIIActionOverride(ctx, orgRedact); !ok || a != agent.DetectionActionRedact {
		t.Errorf("org-redact PII override = (%q,%v), want (redact,true)", a, ok)
	}
	if _, ok := ResolveGatewayPIIActionOverride(ctx, orgDefault); ok {
		t.Errorf("org-default must report no explicit PII override")
	}
}
