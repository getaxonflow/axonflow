// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"database/sql"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"axonflow/platform/agent/approletest"

	_ "github.com/lib/pq"
)

// masRLSTables is the exact set migration 400 switches RLS on
// (400_mas_feat_tables.sql lines 264-268).
//
// Four of the five carry `FOR ALL USING (org_id = get_current_org_id())
// WITH CHECK (org_id = get_current_org_id())`. mas_kill_switch_history has no
// org_id column at all, so its policy resolves the owner through a subquery:
// `kill_switch_id IN (SELECT id FROM mas_kill_switches WHERE org_id =
// get_current_org_id())`. Same GUC, same failure mode — with app.current_org_id
// unset the inner SELECT is itself empty, so the IN-list is empty and the
// history table is fully opaque.
var masRLSTables = []string{
	"mas_ai_system_registry",
	"mas_feat_assessments",
	"mas_kill_switches",
	"mas_kill_switch_history",
	"mas_bias_metrics",
}

// masRepoTables is masRLSTables minus mas_bias_metrics: the four tables this
// package actually issues SQL against. mas_bias_metrics is RLS-gated by
// migration 400 but has no repository, no reader and no writer anywhere in the
// tree — TestMASFEAT_BiasMetricsHasNoGoCallSite pins that, so its absence from
// the wrap surface is a measured fact rather than an oversight.
var masRepoTables = masRLSTables[:4]

const (
	masOrgSelf  = "mas-approle-self"
	masOrgOther = "mas-approle-other"
)

// masCoreMigrations / masBankingMigration are the only two strings that differ
// between this file and its ee/ twin (along with the build tag): the ee/ copy
// sits one directory deeper.
const (
	masCoreMigrations   = "../../../migrations/core"
	masBankingMigration = "../../../migrations/industry/banking/400_mas_feat_tables.sql"
)

// applyMASSchemaWithAppRole applies core migrations 001..111 plus banking
// migration 400 and returns BOTH the master (superuser, BYPASSRLS) handle used
// to seed fixtures and a second handle authenticated as the real, NOBYPASSRLS
// axonflow_app_role.
//
// The two-handle shape is the whole point. A superuser bypasses RLS
// unconditionally, so a test on that handle CANNOT observe a missing
// WithOrgScope — the rows come back either way and the suite reports the defect
// as ABSENT. Every assertion below that is about scoping therefore runs on
// appRole, and master is used only to establish and to count the fixture. The
// connection under test is never its own witness.
func applyMASSchemaWithAppRole(t *testing.T) (master, appRole *sql.DB) {
	t.Helper()
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, masCoreMigrations)

	master, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })

	b, readErr := os.ReadFile(masBankingMigration)
	if readErr != nil {
		t.Fatalf("read %s: %v", masBankingMigration, readErr)
	}
	if _, execErr := master.Exec(string(b)); execErr != nil {
		t.Fatalf("apply %s: %v", masBankingMigration, execErr)
	}

	appRole, err = sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatalf("open app-role DSN: %v", err)
	}
	t.Cleanup(func() { _ = appRole.Close() })
	return master, appRole
}

// assertMASAppRolePostureIsReal proves the harness is capable of seeing the
// defect before any behavioural assertion is made. Four separate ways this
// suite could go green while proving nothing:
//
//   - connected as the superuser (RLS bypassed, every read succeeds regardless);
//   - connected as a role carrying BYPASSRLS (same, less obviously);
//   - the tables not actually RLS-enabled (migration 400 not applied, or applied
//     without the ALTER … ENABLE ROW LEVEL SECURITY block);
//   - app.current_org_id already set on a bare connection, so the "silent zero
//     rows" direction cannot reproduce.
//
// Each is asserted away explicitly rather than assumed.
func assertMASAppRolePostureIsReal(t *testing.T, appRole *sql.DB) {
	t.Helper()

	var currentUser string
	if err := appRole.QueryRow("SELECT current_user").Scan(&currentUser); err != nil {
		t.Fatalf("SELECT current_user: %v", err)
	}
	if currentUser != "axonflow_app_role" {
		t.Fatalf("connected as %q, want axonflow_app_role — this suite cannot observe RLS from any other role", currentUser)
	}

	// rolsuper is checked as well as rolbypassrls, and they are NOT the same
	// question: `ALTER ROLE x SUPERUSER` leaves rolbypassrls false while still
	// bypassing every RLS policy. A role that is both named axonflow_app_role and
	// SUPERUSER would otherwise satisfy the two checks above and below and still
	// report the defect as absent.
	var bypassRLS, isSuper bool
	if err := appRole.QueryRow(
		"SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&bypassRLS, &isSuper); err != nil {
		t.Fatalf("read rolbypassrls/rolsuper: %v", err)
	}
	if bypassRLS {
		t.Fatalf("axonflow_app_role has BYPASSRLS — every assertion below would be vacuous")
	}
	if isSuper {
		t.Fatalf("axonflow_app_role is SUPERUSER — RLS is bypassed regardless of rolbypassrls, " +
			"so every assertion below would be vacuous")
	}

	for _, table := range masRLSTables {
		var enabled, forced bool
		if err := appRole.QueryRow(
			"SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = $1",
			table).Scan(&enabled, &forced); err != nil {
			t.Fatalf("read relrowsecurity for %s: %v", table, err)
		}
		if !enabled {
			t.Fatalf("%s does not have RLS enabled — migration 400 did not apply as this suite assumes", table)
		}
		t.Logf("%s: relrowsecurity=%v relforcerowsecurity=%v", table, enabled, forced)
	}

	var guc sql.NullString
	if err := appRole.QueryRow(
		"SELECT current_setting('app.current_org_id', true)").Scan(&guc); err != nil {
		t.Fatalf("read app.current_org_id: %v", err)
	}
	if guc.Valid && guc.String != "" {
		t.Fatalf("app.current_org_id is pre-set to %q on a bare connection — the harness is not neutral", guc.String)
	}
}

// seedMASOrg creates the organizations row every mas_* table's org_id column
// has a FOREIGN KEY onto. Runs on master.
func seedMASOrg(t *testing.T, master *sql.DB, orgID string) {
	t.Helper()
	if _, err := master.Exec(`
		INSERT INTO organizations (org_id, name, tier, license_key, created_at, updated_at)
		VALUES ($1, $2, 'enterprise', $3, NOW(), NOW())
		ON CONFLICT (org_id) DO NOTHING`,
		orgID, "org-"+orgID, "lic-"+orgID); err != nil {
		t.Fatalf("seed organization %s: %v", orgID, err)
	}
}

// masKillSwitchIDs carries the seeded kill-switch id per org so the history
// read can name its parent system.
var masKillSwitchIDs = map[string]string{}

// seedMASFixture writes one row per repository-backed table for an org through
// the REAL repository writers on the master handle. Two orgs are seeded by the
// caller, because a suite that seeds only the caller's org can prove "my rows
// come back" but not "the other org's do not" — and the second half is what the
// RLS backstop is for.
func seedMASFixture(t *testing.T, master *sql.DB, orgID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	seedMASOrg(t, master, orgID)

	regRepo := NewPostgresRegistryRepository(master)
	sys := &AISystemRegistry{
		OrgID:                orgID,
		SystemID:             "sys-" + orgID,
		SystemName:           "Credit Scoring " + orgID,
		Description:          "seeded AI system",
		UseCase:              UseCaseCreditScoring,
		Status:               SystemStatusActive,
		RiskRatingImpact:     5,
		RiskRatingComplexity: 5,
		RiskRatingReliance:   5,
		OwnerTeam:            "ML Team",
		OwnerEmail:           "ml@" + orgID + ".example",
		CreatedBy:            "admin-" + orgID,
	}
	if err := regRepo.Create(ctx, sys); err != nil {
		t.Fatalf("seed AI system for %s: %v", orgID, err)
	}

	assessRepo := NewPostgresAssessmentRepository(master)
	if err := assessRepo.Create(ctx, &FEATAssessment{
		OrgID:          orgID,
		SystemID:       sys.SystemID,
		AssessmentType: "initial",
		Status:         FEATStatusCompleted,
		AssessmentDate: now.Add(-24 * time.Hour),
		Assessors:      []string{"assessor-" + orgID},
		CreatedBy:      "admin-" + orgID,
	}); err != nil {
		t.Fatalf("seed FEAT assessment for %s: %v", orgID, err)
	}

	ksRepo := NewPostgresKillSwitchRepository(master)
	triggeredAt := now.Add(-time.Hour)
	ks := &KillSwitch{
		OrgID:              orgID,
		SystemID:           sys.SystemID,
		Status:             KillSwitchTriggered,
		TriggerReason:      "bias threshold breached",
		AutoTriggerEnabled: true,
		TriggeredAt:        &triggeredAt,
		TriggeredBy:        "admin-" + orgID,
	}
	if err := ksRepo.Create(ctx, ks); err != nil {
		t.Fatalf("seed kill switch for %s: %v", orgID, err)
	}
	masKillSwitchIDs[orgID] = ks.ID

	if err := ksRepo.RecordHistory(ctx, orgID, &KillSwitchHistory{
		KillSwitchID:   ks.ID,
		Action:         "triggered",
		PreviousStatus: string(KillSwitchEnabled),
		NewStatus:      string(KillSwitchTriggered),
		Reason:         "seeded history",
		PerformedBy:    "admin-" + orgID,
	}); err != nil {
		t.Fatalf("seed kill-switch history for %s: %v", orgID, err)
	}
}

// assertMASFixtureCoexists counts BOTH orgs' rows on MASTER before any
// visibility claim is made. If the fixture is not physically there, every
// assertion downstream is vacuous.
func assertMASFixtureCoexists(t *testing.T, master *sql.DB) {
	t.Helper()
	for _, table := range masRepoTables {
		var self, other int
		var err error
		if table == "mas_kill_switch_history" {
			// No org_id column — resolve through the parent, exactly as the
			// migration-400 policy does.
			err = master.QueryRow(`
				SELECT COUNT(*) FILTER (WHERE ks.org_id = $1),
				       COUNT(*) FILTER (WHERE ks.org_id = $2)
				FROM mas_kill_switch_history h
				JOIN mas_kill_switches ks ON ks.id = h.kill_switch_id`,
				masOrgSelf, masOrgOther).Scan(&self, &other)
		} else {
			err = master.QueryRow(
				"SELECT COUNT(*) FILTER (WHERE org_id = $1), COUNT(*) FILTER (WHERE org_id = $2) FROM "+table,
				masOrgSelf, masOrgOther).Scan(&self, &other)
		}
		if err != nil {
			t.Fatalf("fixture count on %s: %v", table, err)
		}
		if self == 0 || other == 0 {
			t.Fatalf("fixture not established in %s: self=%d other=%d — every assertion below would be vacuous",
				table, self, other)
		}
	}
}

// TestMASFEAT_AppRole_ReadsReturnTheCallersOwnRows is the #3133 proof in the
// direction the issue could only INFER from reading the code: on an
// axonflow_app_role pool every MAS FEAT repository read returned SILENT ZERO
// ROWS.
//
// The masfeat repositories never called WithOrgScope and never SET
// app.current_org_id, so get_current_org_id() was NULL and migration 400's
// `org_id = get_current_org_id()` predicate matched nothing — for the caller's
// OWN org. Not an error, not a log line: an AI-governance module returning an
// empty registry, no assessments, no kill switches and no history.
//
// RED ON REVERT: strip the rls.WithOrgScope wrap from any one repository read
// and its sub-test drops to 0 rows.
//
// Both directions are asserted on the same connection, because either alone is
// satisfied by a broken implementation:
//   - own rows must be VISIBLE (a blanket-deny "fix" passes an isolation-only
//     suite — the #3039/#3048 failure mode);
//   - the other org's rows must NOT be (a blanket-allow passes a
//     visibility-only suite).
func TestMASFEAT_AppRole_ReadsReturnTheCallersOwnRows(t *testing.T) {
	master, appRole := applyMASSchemaWithAppRole(t)
	ctx := context.Background()

	assertMASAppRolePostureIsReal(t, appRole)

	seedMASFixture(t, master, masOrgSelf)
	seedMASFixture(t, master, masOrgOther)
	assertMASFixtureCoexists(t, master)

	t.Run("mas_ai_system_registry List", func(t *testing.T) {
		systems, err := NewPostgresRegistryRepository(appRole).List(ctx, masOrgSelf, ListParams{})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		assertMASOwnedRows(t, len(systems))
		for _, s := range systems {
			if s.OrgID != masOrgSelf {
				t.Errorf("CROSS-ORG ROW: got org %q", s.OrgID)
			}
		}
	})

	t.Run("mas_ai_system_registry GetBySystemID", func(t *testing.T) {
		sys, err := NewPostgresRegistryRepository(appRole).GetBySystemID(ctx, masOrgSelf, "sys-"+masOrgSelf)
		if err != nil {
			t.Fatalf("GetBySystemID: %v", err)
		}
		if sys == nil {
			t.Fatalf("GetBySystemID returned nil for a system this org owns — RLS-blind read (#3133)")
		}
		if sys.OrgID != masOrgSelf {
			t.Errorf("CROSS-ORG ROW: got org %q", sys.OrgID)
		}
		// GetBySystemID is a two-statement read (id lookup, then GetByID).
		// Both call sites had to be scoped; a non-nil result proves both.
	})

	t.Run("mas_ai_system_registry GetBySystemID cross-org is refused", func(t *testing.T) {
		sys, err := NewPostgresRegistryRepository(appRole).GetBySystemID(ctx, masOrgSelf, "sys-"+masOrgOther)
		if err != nil {
			t.Fatalf("GetBySystemID: %v", err)
		}
		if sys != nil {
			t.Errorf("CROSS-ORG READ: org %q resolved %q's system", masOrgSelf, masOrgOther)
		}
	})

	t.Run("mas_ai_system_registry GetSummary", func(t *testing.T) {
		summary, err := NewPostgresRegistryRepository(appRole).GetSummary(ctx, masOrgSelf)
		if err != nil {
			t.Fatalf("GetSummary: %v", err)
		}
		if summary.TotalSystems == 0 {
			t.Errorf("GetSummary returned 0 systems for an org that owns 1 — RLS-blind read (#3133)")
		}
		// The second statement in GetSummary reads mas_kill_switches, a
		// DIFFERENT RLS-gated table from the same method. It is its own call
		// site and had to be scoped separately.
		if summary.KillSwitchesTriggered == 0 {
			t.Errorf("GetSummary reported 0 triggered kill switches for an org with a TRIGGERED kill switch — " +
				"the cross-table read inside GetSummary is a separate unscoped call site (#3133)")
		}
	})

	t.Run("mas_ai_system_registry CountByStatus", func(t *testing.T) {
		counts, err := NewPostgresRegistryRepository(appRole).CountByStatus(ctx, masOrgSelf)
		if err != nil {
			t.Fatalf("CountByStatus: %v", err)
		}
		if counts[SystemStatusActive] == 0 {
			t.Errorf("CountByStatus reported 0 active systems for an org that owns 1 — RLS-blind read (#3133)")
		}
	})

	t.Run("mas_feat_assessments List", func(t *testing.T) {
		assessments, err := NewPostgresAssessmentRepository(appRole).List(ctx, masOrgSelf, ListParams{})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		assertMASOwnedRows(t, len(assessments))
		for _, a := range assessments {
			if a.OrgID != masOrgSelf {
				t.Errorf("CROSS-ORG ROW: got org %q", a.OrgID)
			}
		}
	})

	t.Run("mas_feat_assessments GetLatestForSystem", func(t *testing.T) {
		a, err := NewPostgresAssessmentRepository(appRole).GetLatestForSystem(ctx, masOrgSelf, "sys-"+masOrgSelf)
		if err != nil {
			t.Fatalf("GetLatestForSystem: %v", err)
		}
		if a == nil {
			t.Fatalf("GetLatestForSystem returned nil for a system with a seeded assessment — RLS-blind read (#3133)")
		}
		if a.OrgID != masOrgSelf {
			t.Errorf("CROSS-ORG ROW: got org %q", a.OrgID)
		}
	})

	// The safety-critical one. GetBySystemID is the read the kill-switch
	// service consults to answer "is this AI system halted?". Zero rows is
	// spelled `nil`, which KillSwitchService.GetKillSwitch turns into
	// "kill switch not found for this system" — i.e. an RLS-blind read here
	// silently UN-TRIPS a tripped kill switch: a safety control reporting
	// all-clear.
	t.Run("mas_kill_switches GetBySystemID (tripped switch must read as tripped)", func(t *testing.T) {
		ks, err := NewPostgresKillSwitchRepository(appRole).GetBySystemID(ctx, masOrgSelf, "sys-"+masOrgSelf)
		if err != nil {
			t.Fatalf("GetBySystemID: %v", err)
		}
		if ks == nil {
			t.Fatalf("GetBySystemID reported NO kill switch for an org whose kill switch IS TRIGGERED — " +
				"an RLS-blind read here silently un-trips a tripped kill switch (#3133)")
		}
		if ks.Status != KillSwitchTriggered {
			t.Errorf("kill switch read back with status %q, want %q", ks.Status, KillSwitchTriggered)
		}
		if ks.OrgID != masOrgSelf {
			t.Errorf("CROSS-ORG ROW: got org %q", ks.OrgID)
		}
	})

	t.Run("mas_kill_switches GetBySystemID cross-org is refused", func(t *testing.T) {
		ks, err := NewPostgresKillSwitchRepository(appRole).GetBySystemID(ctx, masOrgSelf, "sys-"+masOrgOther)
		if err != nil {
			t.Fatalf("GetBySystemID: %v", err)
		}
		if ks != nil {
			t.Errorf("CROSS-ORG READ: org %q resolved %q's kill switch", masOrgSelf, masOrgOther)
		}
	})

	t.Run("mas_kill_switch_history GetHistory", func(t *testing.T) {
		history, err := NewPostgresKillSwitchRepository(appRole).GetHistory(ctx, masOrgSelf, "sys-"+masOrgSelf, 50)
		if err != nil {
			t.Fatalf("GetHistory: %v", err)
		}
		if len(history) == 0 {
			t.Errorf("GetHistory returned 0 entries for a kill switch with a seeded entry — RLS-blind read (#3133)")
		}
		for _, h := range history {
			if h.KillSwitchID != masKillSwitchIDs[masOrgSelf] {
				t.Errorf("CROSS-ORG ROW: history entry for kill switch %q, want %q",
					h.KillSwitchID, masKillSwitchIDs[masOrgSelf])
			}
		}
	})
}

// assertMASOwnedRows is the positive half every List sub-test shares. Without
// it, "RLS is on" and "reads return nothing" are indistinguishable from green —
// the #3039/#3048 lesson.
func assertMASOwnedRows(t *testing.T, got int) {
	t.Helper()
	if got == 0 {
		t.Errorf("read returned 0 rows for an org that owns 1 — RLS-blind read, the #3133 failure mode " +
			"(app.current_org_id unset ⇒ get_current_org_id() NULL ⇒ the migration-400 policy matches nothing)")
	}
}

// TestMASFEAT_AppRole_WritesSucceedUnderRLS is the write half. Migration 400
// spells an explicit `WITH CHECK (org_id = get_current_org_id())` on every
// policy, so under app_role with app.current_org_id unset a MAS FEAT write does
// not silently no-op: it is REFUSED ("new row violates row-level security
// policy"). The module cannot register an AI system, record an assessment, or
// trip a kill switch at all.
//
// mas_kill_switch_history's WITH CHECK is the subquery form, so RecordHistory
// is refused for a second reason: with the GUC unset the parent lookup is
// itself empty.
func TestMASFEAT_AppRole_WritesSucceedUnderRLS(t *testing.T) {
	master, appRole := applyMASSchemaWithAppRole(t)
	ctx := context.Background()

	assertMASAppRolePostureIsReal(t, appRole)

	// The organizations row is a prerequisite of the FK, not part of what is
	// under test — seed it on master.
	seedMASOrg(t, master, masOrgSelf)

	regRepo := NewPostgresRegistryRepository(appRole)
	sys := &AISystemRegistry{
		OrgID:                masOrgSelf,
		SystemID:             "sys-write-path",
		SystemName:           "Write-path system",
		UseCase:              UseCaseCreditScoring,
		Status:               SystemStatusActive,
		RiskRatingImpact:     5,
		RiskRatingComplexity: 5,
		RiskRatingReliance:   5,
		OwnerTeam:            "ML Team",
		OwnerEmail:           "ml@example.test",
		CreatedBy:            "admin",
	}
	if err := regRepo.Create(ctx, sys); err != nil {
		t.Fatalf("registry Create under app_role failed — the MAS FEAT write path is REFUSED by the "+
			"migration-400 WITH CHECK when app.current_org_id is unset (#3133): %v", err)
	}

	assessRepo := NewPostgresAssessmentRepository(appRole)
	assessment := &FEATAssessment{
		OrgID:          masOrgSelf,
		SystemID:       sys.SystemID,
		AssessmentType: "initial",
		Status:         FEATStatusCompleted,
		AssessmentDate: time.Now().UTC(),
		Assessors:      []string{"assessor"},
		CreatedBy:      "admin",
	}
	if err := assessRepo.Create(ctx, assessment); err != nil {
		t.Fatalf("assessment Create under app_role failed (#3133): %v", err)
	}

	ksRepo := NewPostgresKillSwitchRepository(appRole)
	ks := &KillSwitch{
		OrgID:              masOrgSelf,
		SystemID:           sys.SystemID,
		Status:             KillSwitchEnabled,
		AutoTriggerEnabled: true,
	}
	if err := ksRepo.Create(ctx, ks); err != nil {
		t.Fatalf("kill-switch Create under app_role failed — a kill switch that cannot be WRITTEN "+
			"is a control that does not exist (#3133): %v", err)
	}

	// Trip it, then record the state change. Update and RecordHistory are two
	// further write call sites, and RecordHistory's policy is the subquery
	// form: it can only clear the check if the parent row is visible.
	triggeredAt := time.Now().UTC()
	ks.Status = KillSwitchTriggered
	ks.TriggerReason = "write-path proof"
	ks.TriggeredAt = &triggeredAt
	ks.TriggeredBy = "admin"
	if err := ksRepo.Update(ctx, ks); err != nil {
		t.Fatalf("kill-switch Update under app_role failed (#3133): %v", err)
	}
	if err := ksRepo.RecordHistory(ctx, masOrgSelf, &KillSwitchHistory{
		KillSwitchID:   ks.ID,
		Action:         "triggered",
		PreviousStatus: string(KillSwitchEnabled),
		NewStatus:      string(KillSwitchTriggered),
		Reason:         "write-path proof",
		PerformedBy:    "admin",
	}); err != nil {
		t.Fatalf("kill-switch RecordHistory under app_role failed — the mas_kill_switch_history policy "+
			"resolves its owner through a subquery on mas_kill_switches, which is itself empty when the "+
			"GUC is unset (#3133): %v", err)
	}

	// An UPDATE that clears WITH CHECK but matches no row under USING is a
	// silent no-op, which is indistinguishable from success at the Exec
	// boundary (ExecContext returns no error for 0 rows affected). Read it
	// back on the same app-role handle: a write that lands but is then
	// invisible is the same outage from the operator's seat.
	got, err := ksRepo.GetBySystemID(ctx, masOrgSelf, sys.SystemID)
	if err != nil {
		t.Fatalf("GetBySystemID after write: %v", err)
	}
	if got == nil {
		t.Fatalf("a kill switch written on this connection is not visible to it — write scoped, read not (#3133)")
	}
	if got.Status != KillSwitchTriggered {
		t.Errorf("kill switch reads back as %q after a TRIGGER update — the UPDATE matched no row under the "+
			"RLS USING predicate and no-opped silently (#3133)", got.Status)
	}

	history, err := ksRepo.GetHistory(ctx, masOrgSelf, sys.SystemID, 10)
	if err != nil {
		t.Fatalf("GetHistory after write: %v", err)
	}
	if len(history) == 0 {
		t.Errorf("the history entry written on this connection is not visible to it (#3133)")
	}

	// Soft-delete is an UPDATE on the registry — the last write call site.
	if err := regRepo.Delete(ctx, masOrgSelf, sys.ID); err != nil {
		t.Fatalf("registry Delete under app_role failed (#3133): %v", err)
	}
	retired, err := regRepo.GetByID(ctx, masOrgSelf, sys.ID)
	if err != nil {
		t.Fatalf("GetByID after Delete: %v", err)
	}
	if retired == nil || retired.Status != SystemStatusRetired {
		t.Errorf("soft-delete did not land: the UPDATE matched no row under the RLS USING predicate (#3133)")
	}
}

// TestMASFEAT_RecordHistoryRefusesAnotherOrgsKillSwitch pins the ONE write in
// this package whose org binding cannot be an additive backstop.
//
// Every other statement keeps a hand-written `WHERE org_id = $n`, so the RLS wrap
// is a second line of defence over an application predicate that already holds.
// mas_kill_switch_history has no org_id column: there is nothing to back up, and
// migration 400's WITH CHECK is INERT on a BYPASSRLS pool. The kill_switch_id FK
// proves only that the parent row exists, not that the caller owns it — so before
// the explicit `INSERT … SELECT … WHERE EXISTS` predicate, a history entry could be
// attached to another organization's kill switch on any deployment where RLS does
// not apply (axonflow_platform_admin, or a master pool).
//
// THIS TEST DELIBERATELY RUNS ON THE MASTER HANDLE. Running it on appRole would
// prove nothing new — RLS already refuses there, and the assertion would pass with
// the predicate removed. Master is asserted to be genuinely BYPASSRLS first, so a
// refusal observed here can only have come from the application predicate.
//
// RED ON REVERT: restore the `VALUES (...)` form of the INSERT and the cross-org
// write lands, on a connection where nothing else would have stopped it.
func TestMASFEAT_RecordHistoryRefusesAnotherOrgsKillSwitch(t *testing.T) {
	master, _ := applyMASSchemaWithAppRole(t)
	ctx := context.Background()

	// Vacuity guard: if master were NOT BYPASSRLS, a refusal below could come
	// from migration 400's policy rather than from the predicate under test, and
	// this test would certify a predicate that does not exist.
	var masterBypassRLS bool
	if err := master.QueryRow(
		"SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&masterBypassRLS); err != nil {
		t.Fatalf("read rolbypassrls on master: %v", err)
	}
	if !masterBypassRLS {
		t.Fatalf("master handle is not BYPASSRLS — this test cannot distinguish the application " +
			"predicate from the RLS policy, so it would prove nothing")
	}

	seedMASFixture(t, master, masOrgSelf)
	seedMASFixture(t, master, masOrgOther)

	victimSwitchID := masKillSwitchIDs[masOrgOther]
	if victimSwitchID == "" {
		t.Fatal("fixture did not record the other org's kill-switch id — the assertion below would be vacuous")
	}

	countFor := func(killSwitchID string) int {
		t.Helper()
		var n int
		if err := master.QueryRow(
			"SELECT COUNT(*) FROM mas_kill_switch_history WHERE kill_switch_id = $1",
			killSwitchID).Scan(&n); err != nil {
			t.Fatalf("count history rows: %v", err)
		}
		return n
	}
	before := countFor(victimSwitchID)

	repo := NewPostgresKillSwitchRepository(master)
	err := repo.RecordHistory(ctx, masOrgSelf, &KillSwitchHistory{
		KillSwitchID:   victimSwitchID,
		Action:         "restored",
		PreviousStatus: string(KillSwitchTriggered),
		NewStatus:      string(KillSwitchEnabled),
		Reason:         "cross-org write that must not land",
		PerformedBy:    "attacker@" + masOrgSelf,
	})
	if err == nil {
		t.Errorf("CROSS-ORG WRITE: org %q recorded history against org %q's kill switch on a BYPASSRLS "+
			"pool — the INSERT carries no ownership predicate (#3133)", masOrgSelf, masOrgOther)
	}

	if after := countFor(victimSwitchID); after != before {
		t.Errorf("CROSS-ORG WRITE LANDED: the victim's history went from %d to %d rows", before, after)
	}

	// Positive control. A refusal that also refuses the legitimate write is a
	// blanket deny, which would satisfy the assertions above for the wrong reason.
	ownSwitchID := masKillSwitchIDs[masOrgSelf]
	ownBefore := countFor(ownSwitchID)
	if err := repo.RecordHistory(ctx, masOrgSelf, &KillSwitchHistory{
		KillSwitchID:   ownSwitchID,
		Action:         "restored",
		PreviousStatus: string(KillSwitchTriggered),
		NewStatus:      string(KillSwitchEnabled),
		Reason:         "legitimate own-org write",
		PerformedBy:    "admin-" + masOrgSelf,
	}); err != nil {
		t.Fatalf("own-org RecordHistory was refused — the predicate is a blanket deny: %v", err)
	}
	if ownAfter := countFor(ownSwitchID); ownAfter != ownBefore+1 {
		t.Errorf("own-org history row did not land: %d → %d", ownBefore, ownAfter)
	}
}

// TestMASFEAT_BiasMetricsHasNoGoCallSite pins the one measured reason
// mas_bias_metrics is RLS-gated by migration 400 yet absent from this package's
// wrap surface: nothing in the tree issues SQL against it. If a reader or writer
// is ever added, this test fails and the author is told to wrap it — rather than
// the table quietly joining the RLS-blind class the way #3103 and #3133 did.
func TestMASFEAT_BiasMetricsHasNoGoCallSite(t *testing.T) {
	// Derived from masCoreMigrations rather than by walking up to a go.mod:
	// this tree has TWO modules (platform/go.mod and ee/go.mod), so a go.mod
	// walk stops at the module root, not the repo root, and the census would
	// silently scan half the tree. Keeping it derived also confines the whole
	// platform/-vs-ee/ divergence to the two path constants above.
	root := filepath.Dir(filepath.Dir(filepath.FromSlash(masCoreMigrations)))
	if _, err := os.Stat(filepath.Join(root, "migrations", "industry", "banking")); err != nil {
		t.Fatalf("derived repo root %q does not look like the repo root: %v", root, err)
	}
	var hits []string
	for _, dir := range []string{"platform", "ee/platform"} {
		base := filepath.Join(root, filepath.FromSlash(dir))
		if _, statErr := os.Stat(base); statErr != nil {
			continue
		}
		walkErr := filepath.Walk(base, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			// PARSED, not grepped (#3241). The previous version was a
			// strings.Contains over the whole file, so it counted a mention in
			// a DOC COMMENT as a call site. That is the worse direction for a
			// guard whose message says "wrap it": the only way to satisfy it is
			// to delete accurate documentation, which is exactly the
			// false-positive-instructs-falsification shape. A SQL statement
			// naming the table has to appear in a STRING LITERAL, so that is
			// what is scanned; comments are ignored.
			if fileHasTableLiteral(src, "mas_bias_metrics") {
				rel, _ := filepath.Rel(root, path)
				hits = append(hits, filepath.ToSlash(rel))
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk %s: %v", base, walkErr)
		}
	}
	if len(hits) > 0 {
		t.Fatalf("mas_bias_metrics now has Go call sites %v — migration 400 RLS-gates it with "+
			"`org_id = get_current_org_id()`, so every one of them must run inside rls.WithOrgScope "+
			"and be added to this package's app-role proof (#3133)", hits)
	}
}

// fileHasTableLiteral reports whether the Go source names the table inside a
// STRING LITERAL - i.e. somewhere it could actually reach the database.
//
// A file that fails to parse is treated as a HIT rather than a pass: a guard
// that goes quiet on input it cannot read has failed open, and the alternative
// (a spurious failure on a genuinely broken file) is loud and self-correcting.
func fileHasTableLiteral(src []byte, table string) bool {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", src, 0) // no ParseComments: comments are not call sites
	if err != nil {
		return true
	}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if strings.Contains(lit.Value, table) {
			found = true
			return false
		}
		return true
	})
	return found
}

// TestFileHasTableLiteralDiscriminates is the guard's own self-test.
//
// A guard rewritten to be less trigger-happy has to prove it did not simply
// stop firing. Three cases, and the decoys are the point: a mention inside a
// comment must NOT count, and a mention inside a string must.
func TestFileHasTableLiteralDiscriminates(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "a real call site in a SQL string literal",
			src:  "package p\nfunc f(db interface{ Q(string) }) { db.Q(`SELECT * FROM mas_bias_metrics`) }\n",
			want: true,
		},
		{
			name: "a concatenated SQL string still counts",
			src:  "package p\nconst q = \"SELECT * FROM \" + \"mas_bias_metrics WHERE org_id = $1\"\n",
			want: true,
		},
		{
			name: "a doc comment mentioning the table does NOT count",
			src:  "package p\n\n// mas_bias_metrics is RLS-gated but has no reader.\nfunc f() {}\n",
			want: false,
		},
		{
			name: "an inline comment does NOT count",
			src:  "package p\nfunc f() { _ = 1 /* mas_bias_metrics */ }\n",
			want: false,
		},
		{
			name: "unparseable source is treated as a hit (fails closed)",
			src:  "package p\nfunc f( {",
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fileHasTableLiteral([]byte(tc.src), "mas_bias_metrics"); got != tc.want {
				t.Errorf("fileHasTableLiteral = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMASFEAT_EveryRepositoryStatementIsWrapped is the package-local guard that
// every mas_* statement runs on a scoped transaction.
//
// It is written as a WHITELIST, and that distinction is the whole point. Two
// earlier versions were blacklists and both were defeated in review:
//
//   - v1 flagged the receiver SHAPE `r.db.XContext(...)` and claimed to fail "if
//     ANY statement survives anywhere in the package". It did not:
//     `pool := r.db; pool.QueryRowContext(...)` slipped past it, and
//     `tx := r.db; tx.QueryRowContext(...)` slipped past it AND the repo-wide
//     audit together, because that audit decides what a transaction handle is by
//     NAME.
//   - v2 required the receiver to be the enclosing rls.WithOrgScope callback's own
//     tx parameter, which fixed those two but still enumerated VERBS: it knew
//     ExecContext/QueryContext/QueryRowContext and was blind to the non-Context
//     `Exec`/`Query`/`QueryRow` the repo-wide audit does handle. It was also
//     defeated by shadowing the blessed name, by a nested closure declaring its own
//     `tx`, and by taking a method value (`exec := r.db.ExecContext`).
//
// Blacklisting a shape only ever catches the shapes you thought of, so this
// version asserts two positive invariants instead:
//
//	RULE A  every database verb — Exec, Query, QueryRow and their Context forms —
//	        must be issued on the identifier bound by the ENCLOSING
//	        rls.WithOrgScope callback's parameter list, and must be lexically
//	        inside one.
//	RULE B  the pool handle `<recv>.db` may appear ONLY as an argument to
//	        rls.WithOrgScope. Every other mention — assigned to a variable under
//	        any name, passed to a helper, or used as a method-value receiver — is
//	        a finding.
//
// Rule B is what makes Rule A un-spoofable: an unscoped statement needs the pool,
// and the pool cannot leave the WithOrgScope call site. Whatever the alias is
// called, binding it is itself the finding.
//
// The repo-wide AST audit in platform/agent is still the primary guard and DOES
// see this package: contrary to an earlier version of this comment, the
// `query := <literal>; query += fmt.Sprintf(...)` idiom in RegistryRepository.List
// and AssessmentRepository.List resolves fine, because collectStringBindings keeps
// the original literal binding and that literal already contains the FROM clause.
// This guard is not compensating for a resolver blind spot; it exists because the
// repo-wide audit identifies transaction handles by NAME, which is exactly the
// property Rule B removes here.
func TestMASFEAT_EveryRepositoryStatementIsWrapped(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var findings []string
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		f, parseErr := parser.ParseFile(fset, name, src, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		checked++

		// scopedTx is the stack of *sql.Tx parameter names belonging to the
		// rls.WithOrgScope callbacks we are currently lexically inside. A
		// statement is acceptable only if its receiver is the innermost of them.
		var scopedTx []string
		var walk func(ast.Node) bool
		walk = func(n ast.Node) bool {
			// Entering an rls.WithOrgScope(ctx, db, org, func(tx *sql.Tx) error)
			// callback pushes that callback's parameter name, walks the body under
			// it, and pops. Recursing by hand rather than via ast.Inspect is what
			// makes the scope tracking lexical.
			if call, ok := n.(*ast.CallExpr); ok && isWithOrgScopeCall(call) {
				if name, lit := withOrgScopeTxParam(call); lit != nil {
					scopedTx = append(scopedTx, name)
					ast.Inspect(lit.Body, walk)
					scopedTx = scopedTx[:len(scopedTx)-1]
					// Still walk the non-callback arguments, which may nest calls.
					for _, arg := range call.Args {
						if arg != ast.Node(lit) {
							ast.Inspect(arg, walk)
						}
					}
					return false
				}
			}

			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			// Both the Context and the non-Context forms. v2 listed only the
			// Context ones and was therefore blind to a bare r.db.Exec(...) —
			// fewer verbs than the repo-wide audit it was written to supplement.
			case "ExecContext", "QueryContext", "QueryRowContext",
				"Exec", "Query", "QueryRow":
			default:
				return true
			}

			// The non-Context verbs are not unique to database/sql: `Query` is
			// also net/url's, and this package calls r.URL.Query().Get(...) in
			// three handlers. Match only receivers that can BE a handle — the
			// pool selector `<x>.db`, or a bare identifier (a tx, or an alias of
			// one). `r.URL.Query()` is neither, because its receiver selector is
			// `.URL`, not `.db`. Anything with a DB-shaped receiver is judged
			// below; anything else was never a database statement.
			if !isDBHandleReceiver(sel.X) {
				return true
			}

			pos := fset.Position(call.Pos()).String()
			if len(scopedTx) == 0 {
				findings = append(findings, pos+": "+sel.Sel.Name+
					" is not lexically inside an rls.WithOrgScope callback")
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok || recv.Name != scopedTx[len(scopedTx)-1] {
				findings = append(findings, pos+": "+sel.Sel.Name+
					" receiver is not the enclosing rls.WithOrgScope callback's tx parameter (want "+
					scopedTx[len(scopedTx)-1]+")")
			}
			return true
		}
		ast.Inspect(f, walk)

		// RULE B. The pool handle may only ever be handed to rls.WithOrgScope.
		// Collected separately from the walk above because it is a property of
		// every mention of `<recv>.db`, not of call expressions.
		poolArgs := map[ast.Node]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && isWithOrgScopeCall(call) {
				for _, arg := range call.Args {
					poolArgs[arg] = true
				}
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "db" {
				return true
			}
			if _, ok := sel.X.(*ast.Ident); !ok {
				return true
			}
			if poolArgs[ast.Node(sel)] {
				return true
			}
			// A statement issued directly on the pool is already reported by
			// Rule A with a more specific message; do not double-report it.
			if isReceiverOfDBVerb(f, sel) {
				return true
			}
			findings = append(findings, fset.Position(sel.Pos()).String()+
				": the pool handle escapes rls.WithOrgScope — `.db` may only appear as an argument to it")
			return true
		})

		// The whole guard is keyed on the identifier `rls`, so prove it really is
		// the scoping package and not an alias or a shadowing local.
		if err := assertRLSImportIsCanonical(f); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if checked == 0 {
		t.Fatal("scanned 0 non-test .go files — this guard would pass vacuously")
	}
	if len(findings) > 0 {
		t.Fatalf("unwrapped statement(s) against RLS-gated mas_* tables (#3133):\n  %s\n"+
			"Every statement in this package must run on the *sql.Tx handed out by rls.WithOrgScope, "+
			"referenced through that callback's own parameter — not the pool, not an alias of it, "+
			"and not a handle from an outer scope.",
			strings.Join(findings, "\n  "))
	}
	t.Logf("scanned %d non-test files; every db statement runs on its enclosing WithOrgScope tx", checked)
}

// isWithOrgScopeCall reports whether call is `rls.WithOrgScope(...)`. Matched on
// the selector rather than on resolved types so the guard needs no type-checker.
func isWithOrgScopeCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "WithOrgScope" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "rls"
}

// withOrgScopeTxParam returns the name of the callback's *sql.Tx parameter and
// the callback literal itself. A WithOrgScope call whose last argument is not a
// literal function (a named function passed by reference, say) returns a nil
// literal, and the caller then treats every statement under it as unscoped —
// fail closed, since this guard cannot follow it.
func withOrgScopeTxParam(call *ast.CallExpr) (string, *ast.FuncLit) {
	if len(call.Args) == 0 {
		return "", nil
	}
	lit, ok := call.Args[len(call.Args)-1].(*ast.FuncLit)
	if !ok || lit.Type.Params == nil || len(lit.Type.Params.List) != 1 {
		return "", nil
	}
	names := lit.Type.Params.List[0].Names
	if len(names) != 1 {
		return "", nil
	}
	return names[0].Name, lit
}

// isReceiverOfDBVerb reports whether sel is the receiver of a database verb call,
// i.e. the `r.db` in `r.db.Exec(...)`. Rule A already reports those with a more
// precise message, so Rule B stays quiet to avoid two findings for one defect.
func isReceiverOfDBVerb(f *ast.File, sel *ast.SelectorExpr) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		outer, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || outer.X != ast.Expr(sel) {
			return true
		}
		switch outer.Sel.Name {
		case "ExecContext", "QueryContext", "QueryRowContext", "Exec", "Query", "QueryRow":
			found = true
		}
		return true
	})
	return found
}

// assertRLSImportIsCanonical fails if the identifier `rls` this guard keys on is
// anything other than the real scoping package. isWithOrgScopeCall matches
// `rls.WithOrgScope` syntactically, so an aliased import — or a local variable
// named rls — would otherwise satisfy the guard while doing no scoping at all.
func assertRLSImportIsCanonical(f *ast.File) error {
	const canonical = `"axonflow/platform/agent/rls"`
	usesRLS := false
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "rls" {
				usesRLS = true
			}
		}
		return true
	})
	if !usesRLS {
		return nil
	}
	for _, imp := range f.Imports {
		if imp.Path.Value != canonical {
			continue
		}
		if imp.Name == nil || imp.Name.Name == "rls" {
			return nil
		}
	}
	return fmt.Errorf("this file refers to `rls` but does not import %s under that name — "+
		"the wrap guard matches rls.WithOrgScope syntactically, so an alias or a shadowing local "+
		"would satisfy it while performing no scoping", canonical)
}

// isDBHandleReceiver reports whether expr can be a *sql.DB or *sql.Tx receiver:
// either the pool selector `<x>.db` or a bare identifier. Deliberately syntactic —
// this guard runs without a type-checker — and deliberately narrow, so that
// same-named methods on unrelated types (net/url's Query, most obviously) are not
// mistaken for database statements.
func isDBHandleReceiver(expr ast.Expr) bool {
	switch v := expr.(type) {
	case *ast.Ident:
		return true
	case *ast.SelectorExpr:
		return v.Sel.Name == "db"
	}
	return false
}
