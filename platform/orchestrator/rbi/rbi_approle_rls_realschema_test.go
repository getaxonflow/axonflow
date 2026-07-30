// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"axonflow/platform/agent/approletest"

	_ "github.com/lib/pq"
)

// rbiRLSTables is the exact set migration 301 switches RLS on
// (301_rbi_free_ai_compliance.sql lines 606-634, each with a
// `FOR ALL USING (org_id = get_current_org_id())` policy).
var rbiRLSTables = []string{
	"rbi_ai_system_registry",
	"rbi_model_validations",
	"rbi_ai_incidents",
	"rbi_kill_switches",
	"rbi_kill_switch_history",
	"rbi_board_reports",
	"rbi_audit_exports",
}

const (
	rlsOrgSelf  = "rbi-approle-self"
	rlsOrgOther = "rbi-approle-other"
)

// applyRBISchemaWithAppRole is applyRBISchema's two-handle sibling: it applies
// the same core+301(+303) schema, but returns BOTH the master (superuser,
// BYPASSRLS) handle used to seed fixtures and a second handle authenticated as
// the real, NOBYPASSRLS axonflow_app_role.
//
// The two-handle shape is the whole point. applyRBISchema hands back only the
// superuser DSN, and a superuser bypasses RLS unconditionally — a test on that
// handle CANNOT observe a missing WithOrgScope, because the rows come back
// either way. It reports the defect as absent. Every assertion below that is
// about scoping therefore runs on appRole, and master is used only to establish
// the fixture.
func applyRBISchemaWithAppRole(t *testing.T) (master, appRole *sql.DB) {
	t.Helper()
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../../migrations/core")

	master, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })

	for _, mig := range []string{
		"../../../migrations/industry/banking/301_rbi_free_ai_compliance.sql",
		"../../../migrations/industry/banking/303_audit_export_cloud_storage.sql",
	} {
		b, readErr := os.ReadFile(mig)
		if readErr != nil {
			t.Fatalf("read %s: %v", mig, readErr)
		}
		if _, execErr := master.Exec(string(b)); execErr != nil {
			t.Fatalf("apply %s: %v", mig, execErr)
		}
	}

	appRole, err = sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatalf("open app-role DSN: %v", err)
	}
	t.Cleanup(func() { _ = appRole.Close() })
	return master, appRole
}

// assertAppRolePostureIsReal proves the harness is capable of seeing the defect
// before any behavioural assertion is made. Three separate ways this suite could
// go green while proving nothing:
//
//   - connected as the superuser (RLS bypassed, every read succeeds regardless);
//   - connected as a role carrying BYPASSRLS (same, less obviously);
//   - the tables not actually RLS-enabled (migration 301 not applied, or applied
//     without the ALTER … ENABLE ROW LEVEL SECURITY block).
//
// Each is asserted away explicitly rather than assumed.
func assertAppRolePostureIsReal(t *testing.T, appRole *sql.DB) {
	t.Helper()

	var currentUser string
	if err := appRole.QueryRow("SELECT current_user").Scan(&currentUser); err != nil {
		t.Fatalf("SELECT current_user: %v", err)
	}
	if currentUser != "axonflow_app_role" {
		t.Fatalf("connected as %q, want axonflow_app_role — this suite cannot observe RLS from any other role", currentUser)
	}

	var bypassRLS bool
	if err := appRole.QueryRow(
		"SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&bypassRLS); err != nil {
		t.Fatalf("read rolbypassrls: %v", err)
	}
	if bypassRLS {
		t.Fatalf("axonflow_app_role has BYPASSRLS — every assertion below would be vacuous")
	}

	for _, table := range rbiRLSTables {
		var enabled, forced bool
		if err := appRole.QueryRow(
			"SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = $1",
			table).Scan(&enabled, &forced); err != nil {
			t.Fatalf("read relrowsecurity for %s: %v", table, err)
		}
		if !enabled {
			t.Fatalf("%s does not have RLS enabled — migration 301 did not apply as this suite assumes", table)
		}
		t.Logf("%s: relrowsecurity=%v relforcerowsecurity=%v", table, enabled, forced)
	}

	// The GUC the RLS policies key on must be genuinely unset outside a wrap.
	// If something in the harness had already SET it, the "silent zero rows"
	// direction would not reproduce and the suite would misreport.
	var guc sql.NullString
	if err := appRole.QueryRow(
		"SELECT current_setting('app.current_org_id', true)").Scan(&guc); err != nil {
		t.Fatalf("read app.current_org_id: %v", err)
	}
	if guc.Valid && guc.String != "" {
		t.Fatalf("app.current_org_id is pre-set to %q on a bare connection — the harness is not neutral", guc.String)
	}
}

// seedRBIFixture writes one row per RLS-gated table for BOTH orgs through the
// REAL repository writers on the master handle. Two orgs, because a suite that
// seeds only the caller's org can prove "my rows come back" but not "the other
// org's do not" — and the second half is what the RLS backstop is for.
func seedRBIFixture(t *testing.T, master *sql.DB, orgID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	sysRepo := NewPostgresAISystemRepository(master)
	sys := &AISystem{
		OrgID:        orgID,
		SystemID:     "sys-" + orgID,
		SystemName:   "Credit Scoring " + orgID,
		RiskCategory: RiskCategoryHigh,
	}
	if err := sysRepo.Create(ctx, sys); err != nil {
		t.Fatalf("seed AI system for %s: %v", orgID, err)
	}

	valRepo := NewPostgresModelValidationRepository(master)
	if err := valRepo.Create(ctx, &ModelValidation{
		OrgID:          orgID,
		SystemID:       sys.SystemID,
		ValidationType: ValidationTypeIndependent,
		ValidatorType:  ValidatorTypeExternalAuditor,
		ValidatorName:  "Auditor " + orgID,
		ValidationDate: now,
		Recommendation: ValidationRecommendationApprove,
	}); err != nil {
		t.Fatalf("seed model validation for %s: %v", orgID, err)
	}

	incRepo := NewPostgresAIIncidentRepository(master)
	if err := incRepo.Create(ctx, &AIIncident{
		OrgID:        orgID,
		IncidentID:   "INC-" + orgID,
		IncidentType: IncidentTypeModelFailure,
		Severity:     IncidentSeverityCritical,
		DetectedAt:   now.Add(-time.Hour),
		DetectedBy:   DetectionMethodAutomated,
		Title:        "Model failure " + orgID,
		Description:  "seeded incident",
		Status:       IncidentStatusOpen,
	}); err != nil {
		t.Fatalf("seed incident for %s: %v", orgID, err)
	}

	ksRepo := NewPostgresKillSwitchRepository(master)
	ks := &KillSwitch{
		OrgID:            orgID,
		Scope:            KillSwitchScopeSystem,
		SystemID:         sys.SystemID,
		IsActive:         true,
		ActivatedBy:      "admin-" + orgID,
		ActivatedAt:      &now,
		ActivationReason: "seeded kill switch",
		FallbackBehavior: FallbackBehaviorBlockAll,
	}
	if err := ksRepo.Create(ctx, ks); err != nil {
		t.Fatalf("seed kill switch for %s: %v", orgID, err)
	}
	if err := ksRepo.AddHistoryEntry(ctx, &KillSwitchHistoryEntry{
		OrgID:        orgID,
		KillSwitchID: ks.ID,
		Action:       KillSwitchActionActivated,
		ActorID:      "admin-" + orgID,
		Reason:       "seeded history",
	}); err != nil {
		t.Fatalf("seed kill-switch history for %s: %v", orgID, err)
	}
	killSwitchIDs[orgID] = ks.ID

	boardRepo := NewPostgresBoardReportRepository(master)
	if err := boardRepo.Create(ctx, &BoardReport{
		OrgID:            orgID,
		ReportType:       ReportTypeQuarterly,
		ReportQuarter:    "Q4-2026",
		GeneratedAt:      now,
		GenerationMethod: "automatic",
		ApprovalStatus:   ReportApprovalDraft,
	}); err != nil {
		t.Fatalf("seed board report for %s: %v", orgID, err)
	}

	expRepo := NewPostgresAuditExportRepository(master)
	if err := expRepo.Create(ctx, &AuditExport{
		OrgID:      orgID,
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
		Status:     AuditExportStatusPending,
		Purpose:    "seeded export " + orgID,
	}); err != nil {
		t.Fatalf("seed audit export for %s: %v", orgID, err)
	}
}

// killSwitchIDs carries the seeded kill-switch id per org so the history read
// can name its parent.
var killSwitchIDs = map[string]string{}

// TestRBI_AppRole_ReadsReturnTheCallersOwnRows is the #3103 proof, in the
// direction the issue could only INFER from reading the code: on an
// axonflow_app_role pool, every RBI repository read returned SILENT ZERO ROWS.
//
// The RBI repositories never called WithOrgScope and never SET
// app.current_org_id, so get_current_org_id() was NULL and migration 301's
// `org_id = get_current_org_id()` predicate matched nothing — for the caller's
// OWN org. Not an error, not a log line: a compliance module returning an empty
// registry, no incidents, no kill switches and no board reports, indistinguishable
// from a clean bill of health.
//
// RED ON REVERT: strip the rls.WithOrgScope wrap from any one repository read
// and its sub-test drops to 0 rows.
//
// The suite asserts BOTH directions on the same connection, because either one
// alone is satisfied by a broken implementation:
//   - own rows must be VISIBLE (a blanket-deny "fix" would pass an isolation-only
//     suite — that is exactly the #3039/#3048 failure mode);
//   - the other org's rows must NOT be (a blanket-allow would pass a
//     visibility-only suite).
func TestRBI_AppRole_ReadsReturnTheCallersOwnRows(t *testing.T) {
	master, appRole := applyRBISchemaWithAppRole(t)
	ctx := context.Background()

	assertAppRolePostureIsReal(t, appRole)

	seedRBIFixture(t, master, rlsOrgSelf)
	seedRBIFixture(t, master, rlsOrgOther)

	// Fixture control: both orgs' rows must physically coexist in every table
	// before any visibility claim is made. Counted on MASTER — the app-role
	// handle is the thing under test and cannot be its own witness.
	for _, table := range rbiRLSTables {
		var self, other int
		if err := master.QueryRow(
			"SELECT COUNT(*) FILTER (WHERE org_id = $1), COUNT(*) FILTER (WHERE org_id = $2) FROM "+table,
			rlsOrgSelf, rlsOrgOther).Scan(&self, &other); err != nil {
			t.Fatalf("fixture count on %s: %v", table, err)
		}
		if self == 0 || other == 0 {
			t.Fatalf("fixture not established in %s: self=%d other=%d — every assertion below would be vacuous",
				table, self, other)
		}
	}

	t.Run("rbi_ai_system_registry List", func(t *testing.T) {
		systems, total, err := NewPostgresAISystemRepository(appRole).List(ctx, rlsOrgSelf, nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		assertOwnedRows(t, len(systems), total)
		for _, s := range systems {
			if s.OrgID != rlsOrgSelf {
				t.Errorf("CROSS-ORG ROW: got org %q", s.OrgID)
			}
		}
	})

	t.Run("rbi_ai_system_registry GetSummary", func(t *testing.T) {
		summary, err := NewPostgresAISystemRepository(appRole).GetSummary(ctx, rlsOrgSelf)
		if err != nil {
			t.Fatalf("GetSummary: %v", err)
		}
		if summary.TotalSystems == 0 {
			t.Errorf("GetSummary returned 0 systems for an org that owns 1 — RLS-blind read (#3103)")
		}
	})

	t.Run("rbi_model_validations List", func(t *testing.T) {
		vals, total, err := NewPostgresModelValidationRepository(appRole).List(ctx, rlsOrgSelf, nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		assertOwnedRows(t, len(vals), total)
		for _, v := range vals {
			if v.OrgID != rlsOrgSelf {
				t.Errorf("CROSS-ORG ROW: got org %q", v.OrgID)
			}
		}
	})

	t.Run("rbi_ai_incidents List", func(t *testing.T) {
		incidents, total, err := NewPostgresAIIncidentRepository(appRole).List(ctx, rlsOrgSelf, nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		assertOwnedRows(t, len(incidents), total)
		for _, i := range incidents {
			if i.OrgID != rlsOrgSelf {
				t.Errorf("CROSS-ORG ROW: got org %q", i.OrgID)
			}
		}
	})

	t.Run("rbi_ai_incidents GetOpenIncidents", func(t *testing.T) {
		open, err := NewPostgresAIIncidentRepository(appRole).GetOpenIncidents(ctx, rlsOrgSelf)
		if err != nil {
			t.Fatalf("GetOpenIncidents: %v", err)
		}
		if len(open) == 0 {
			t.Errorf("GetOpenIncidents returned 0 for an org with an open critical incident — RLS-blind read (#3103)")
		}
	})

	t.Run("rbi_kill_switches List", func(t *testing.T) {
		switches, total, err := NewPostgresKillSwitchRepository(appRole).List(ctx, rlsOrgSelf, nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		assertOwnedRows(t, len(switches), total)
		for _, k := range switches {
			if k.OrgID != rlsOrgSelf {
				t.Errorf("CROSS-ORG ROW: got org %q", k.OrgID)
			}
		}
	})

	// The safety-critical one. CheckActive is the read an enforcement path
	// consults to decide whether an AI system is halted; zero rows reads as
	// "no kill switch is active" — i.e. the RLS-blind failure mode silently
	// UN-TRIPS a tripped kill switch.
	t.Run("rbi_kill_switches CheckActive", func(t *testing.T) {
		active, ks, err := NewPostgresKillSwitchRepository(appRole).CheckActive(
			ctx, rlsOrgSelf, KillSwitchScopeSystem, "sys-"+rlsOrgSelf, "")
		if err != nil {
			t.Fatalf("CheckActive: %v", err)
		}
		if !active || ks == nil {
			t.Errorf("CheckActive reported NO active kill switch for an org whose kill switch IS active — "+
				"an RLS-blind read here silently un-trips a tripped kill switch (#3103); got active=%v", active)
		}
	})

	t.Run("rbi_kill_switch_history GetHistory", func(t *testing.T) {
		history, err := NewPostgresKillSwitchRepository(appRole).GetHistory(
			ctx, rlsOrgSelf, killSwitchIDs[rlsOrgSelf], 50)
		if err != nil {
			t.Fatalf("GetHistory: %v", err)
		}
		if len(history) == 0 {
			t.Errorf("GetHistory returned 0 entries for a kill switch with a seeded entry — RLS-blind read (#3103)")
		}
		for _, h := range history {
			if h.OrgID != rlsOrgSelf {
				t.Errorf("CROSS-ORG ROW: got org %q", h.OrgID)
			}
		}
	})

	t.Run("rbi_board_reports List", func(t *testing.T) {
		reports, total, err := NewPostgresBoardReportRepository(appRole).List(ctx, rlsOrgSelf, nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		assertOwnedRows(t, len(reports), total)
		for _, b := range reports {
			if b.OrgID != rlsOrgSelf {
				t.Errorf("CROSS-ORG ROW: got org %q", b.OrgID)
			}
		}
	})

	t.Run("rbi_audit_exports List", func(t *testing.T) {
		exports, total, err := NewPostgresAuditExportRepository(appRole).List(ctx, rlsOrgSelf, nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		assertOwnedRows(t, len(exports), total)
		for _, e := range exports {
			if e.OrgID != rlsOrgSelf {
				t.Errorf("CROSS-ORG ROW: got org %q", e.OrgID)
			}
		}
	})
}

// assertOwnedRows folds the two halves every List sub-test shares: the caller's
// own row must come back (pre-fix: zero) and the COUNT(*) must agree with the
// page (pre-fix both were zero, which is why a bare "total > 0" is not enough
// on its own — the count query and the row query are separate call sites and
// each had to be wrapped).
func assertOwnedRows(t *testing.T, got, total int) {
	t.Helper()
	if got == 0 {
		t.Errorf("read returned 0 rows for an org that owns 1 — RLS-blind read, the #3103 failure mode "+
			"(app.current_org_id unset ⇒ get_current_org_id() NULL ⇒ the migration-301 policy matches nothing)")
	}
	if total == 0 {
		t.Errorf("COUNT(*) returned 0 for an org that owns 1 — the count call site is a separate unwrapped read")
	}
	if got != total {
		t.Errorf("page/count disagree: rows=%d total=%d — one of the two call sites is scoped and the other is not", got, total)
	}
}

// TestRBI_AppRole_WritesSucceedUnderRLS is the write half. Migration 301's
// policies are `FOR ALL USING (...)` with no separate WITH CHECK, so Postgres
// applies the same expression as the INSERT/UPDATE check: under app_role with
// app.current_org_id unset, an RBI write does not silently no-op, it is REFUSED
// ("new row violates row-level security policy"). That is the loud half of the
// same root cause, and it means the RBI module is not merely blind on an
// app-role pool — it cannot record an incident or trip a kill switch at all.
func TestRBI_AppRole_WritesSucceedUnderRLS(t *testing.T) {
	_, appRole := applyRBISchemaWithAppRole(t)
	ctx := context.Background()

	assertAppRolePostureIsReal(t, appRole)

	sysRepo := NewPostgresAISystemRepository(appRole)
	sys := &AISystem{
		OrgID:        rlsOrgSelf,
		SystemID:     "sys-write-path",
		SystemName:   "Write-path system",
		RiskCategory: RiskCategoryHigh,
	}
	if err := sysRepo.Create(ctx, sys); err != nil {
		t.Fatalf("AI system Create under app_role failed — the RBI write path is REFUSED by the "+
			"migration-301 policy when app.current_org_id is unset (#3103): %v", err)
	}

	incRepo := NewPostgresAIIncidentRepository(appRole)
	if err := incRepo.Create(ctx, &AIIncident{
		OrgID:        rlsOrgSelf,
		IncidentID:   "INC-write-path",
		IncidentType: IncidentTypeModelFailure,
		Severity:     IncidentSeverityCritical,
		DetectedAt:   time.Now().UTC(),
		DetectedBy:   DetectionMethodAutomated,
		Title:        "Write-path incident",
		Description:  "an incident the module must be able to record on an app-role pool",
		Status:       IncidentStatusOpen,
	}); err != nil {
		t.Fatalf("incident Create under app_role failed (#3103): %v", err)
	}

	ksRepo := NewPostgresKillSwitchRepository(appRole)
	now := time.Now().UTC()
	ks := &KillSwitch{
		OrgID:            rlsOrgSelf,
		Scope:            KillSwitchScopeSystem,
		SystemID:         sys.SystemID,
		IsActive:         true,
		ActivatedBy:      "admin",
		ActivatedAt:      &now,
		ActivationReason: "write-path proof",
		FallbackBehavior: FallbackBehaviorBlockAll,
	}
	if err := ksRepo.Create(ctx, ks); err != nil {
		t.Fatalf("kill-switch Create under app_role failed — a kill switch that cannot be WRITTEN "+
			"is a control that does not exist (#3103): %v", err)
	}
	if err := ksRepo.AddHistoryEntry(ctx, &KillSwitchHistoryEntry{
		OrgID:        rlsOrgSelf,
		KillSwitchID: ks.ID,
		Action:       KillSwitchActionActivated,
		ActorID:      "admin",
		Reason:       "write-path proof",
	}); err != nil {
		t.Fatalf("kill-switch history AddHistoryEntry under app_role failed (#3103): %v", err)
	}

	// Read it back on the same app-role handle: a write that lands but is then
	// invisible is the same outage from the operator's seat.
	active, got, err := ksRepo.CheckActive(ctx, rlsOrgSelf, KillSwitchScopeSystem, sys.SystemID, "")
	if err != nil {
		t.Fatalf("CheckActive after write: %v", err)
	}
	if !active || got == nil {
		t.Errorf("a kill switch written on this connection is not visible to it — write scoped, read not (#3103)")
	}
}
