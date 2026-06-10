// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"axonflow/platform/agent/approletest"

	_ "github.com/lib/pq"
)

// TestPerOrgDetectionOverrides_RealPostgres proves the #2581 per-org posture
// resolution against a REAL Postgres with the REAL migration 120 applied and
// RLS ENABLEd+FORCEd, under axonflow_app_role:
//
//   - the override table is org-isolated by RLS (a bare read under app_role with
//     no org scope sees nothing; the scoped repo read sees only its org's rows);
//   - reads work under app_role ON (RLS enforced, WithOrgScope sets the GUC) AND
//     OFF (owner/superuser bypass + the explicit WHERE org_id still scopes);
//   - the SAME process resolves DIFFERENT postures for two orgs (org-redact →
//     redact while the global config is block; org-default → global block).
//
// Gated on TEST_PG_INTEGRATION=1 + docker (approletest.Setup).
func TestPerOrgDetectionOverrides_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	defer func() { _ = masterDB.Close() }()

	// Apply the REAL migration 120 (Setup only runs 1..111). This also exercises
	// the migration SQL — RLS ENABLE+FORCE, the isolation policy, the verifier.
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
	// org-redact's rows — and NONE of any other org's.
	repo := NewDetectionOverrideRepository(appRoleDB)
	gotRedact, err := repo.ReadOrgOverrides(ctx, orgRedact)
	if err != nil {
		t.Fatalf("ReadOrgOverrides(%s): %v", orgRedact, err)
	}
	if gotRedact["pii"] != DetectionActionRedact || gotRedact["sqli"] != DetectionActionWarn {
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
	repoOff := NewDetectionOverrideRepository(masterDB)
	gotOff, err := repoOff.ReadOrgOverrides(ctx, orgRedact)
	if err != nil {
		t.Fatalf("ReadOrgOverrides(off-mode, %s): %v", orgRedact, err)
	}
	if gotOff["pii"] != DetectionActionRedact || len(gotOff) != 2 {
		t.Fatalf("off-mode read = %v, want exactly org-redact's 2 rows (WHERE-scoped)", gotOff)
	}

	// --- SAME process, two orgs, different posture --------------------------
	// Pin the deployment-global posture to block, wire the cache to the real
	// app_role DB, and resolve both orgs.
	detectionConfigMu.Lock()
	origCfg := cachedMCPConfig
	cachedMCPConfig = &ModeDetectionConfig{Enabled: true, PIIAction: DetectionActionBlock}
	detectionConfigMu.Unlock()
	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedMCPConfig = origCfg
		detectionConfigMu.Unlock()
	})

	setDetectionOverrideCacheForTest(newDetectionOverrideCache(repo, time.Minute))
	t.Cleanup(ResetDetectionOverrideCacheForTest)

	if got := ResolveMCPDetectionConfig(ctx, orgRedact).PIIAction; got != DetectionActionRedact {
		t.Errorf("same-process org-redact PIIAction = %q, want redact", got)
	}
	if got := ResolveMCPDetectionConfig(ctx, orgDefault).PIIAction; got != DetectionActionBlock {
		t.Errorf("same-process org-default PIIAction = %q, want block (global)", got)
	}
}
