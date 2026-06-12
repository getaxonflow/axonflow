// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"axonflow/platform/agent/approletest"

	_ "github.com/lib/pq"
)

// applyRBISchema runs the core migrations (1..111) then the RBI banking
// migration (301) against a throwaway Postgres, returning an open *sql.DB on
// the master (superuser) DSN. The superuser bypasses the RLS policies that
// migration 301 enables, so inserts/queries do not need get_current_org_id().
func applyRBISchema(t *testing.T) *sql.DB {
	t.Helper()
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../../migrations/core")

	db, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	rbiMig := "../../../migrations/industry/banking/301_rbi_free_ai_compliance.sql"
	b, err := os.ReadFile(rbiMig)
	if err != nil {
		t.Fatalf("read %s: %v", rbiMig, err)
	}
	if _, err := db.Exec(string(b)); err != nil {
		t.Fatalf("apply RBI migration 301: %v", err)
	}
	return db
}

// TestBoardReport_RealSchema_GenerationMethodAndNotifications proves #2640 end
// to end against the REAL migrated RBI schema (migration 301), with NO mocks:
//
//   - P1: an auto-generated board report INSERTs successfully — the canonical
//     generation_method value 'automatic' satisfies the CHECK constraint
//     (rbi_board_reports_generation_method_check). The pre-fix literal
//     'automated' is rejected (asserted directly as a negative control, which
//     proves the CHECK is genuinely enforced — not bypassed by a mock).
//   - AI-system Create works against the board_approval_required GENERATED
//     column (same divergence class, fixed to mirror ee/): a high-risk system
//     registers and Postgres computes board_approval_required = true.
//   - incident Create/scan works against the GENERATED *_notification_required
//     columns: inserting an incident no longer writes those columns, and
//     Postgres computes them (critical ⇒ both required).
//   - P2: GenerateReport consults GetPendingNotifications against the real
//     table; a critical incident with rbi_notified=false surfaces as a
//     'regulatory_notification' compliance issue persisted in the
//     compliance_issues JSONB column.
//
// Red-on-revert: reverting boardreport_service.go to 'automated' fails the
// GenerateReport INSERT; reverting the incident_repository.go INSERT to write
// the GENERATED columns fails incident Create; reverting the
// GetPendingNotifications consultation drops the regulatory_notification row.
//
// Gated on TEST_PG_INTEGRATION=1 + docker.
func TestBoardReport_RealSchema_GenerationMethodAndNotifications(t *testing.T) {
	db := applyRBISchema(t)
	ctx := context.Background()
	const orgID = "rbi-e2e-org"

	incidentRepo := NewPostgresAIIncidentRepository(db)
	boardRepo := NewPostgresBoardReportRepository(db)
	systemRepo := NewPostgresAISystemRepository(db)

	// --- registry Create against the board_approval_required GENERATED col ---
	// Same writer/schema-divergence class as the board-report bug: the ee/
	// tree was already fixed (CHANGELOG "registering an AI system no longer
	// 500s"), the platform/ tree was not. A high-risk system must compute
	// board_approval_required = true.
	sys := &AISystem{
		OrgID:        orgID,
		SystemID:     "credit-scoring-e2e",
		SystemName:   "Credit Scoring Model",
		RiskCategory: RiskCategoryHigh,
	}
	if err := systemRepo.Create(ctx, sys); err != nil {
		t.Fatalf("AI system Create against real schema failed (board_approval_required GENERATED-column regression?): %v", err)
	}
	gotSys, err := systemRepo.Get(ctx, orgID, sys.ID)
	if err != nil {
		t.Fatalf("AI system Get failed: %v", err)
	}
	if !gotSys.BoardApprovalRequired {
		t.Error("board_approval_required = false, want true for a high-risk system")
	}

	// --- incident Create against the GENERATED columns (the bug we fixed) ---
	now := time.Now().UTC()
	resolvedAt := now.Add(-1 * time.Hour)
	critical := &AIIncident{
		OrgID:         orgID,
		IncidentID:    "INC-RBI-E2E-1",
		IncidentType:  IncidentTypeModelFailure,
		Severity:      IncidentSeverityCritical,
		DetectedAt:    now.Add(-3 * time.Hour),
		DetectedBy:    DetectionMethodAutomated,
		Title:         "Unreported critical model failure",
		Description:   "Critical incident that was resolved but never reported to RBI/board",
		Status:        IncidentStatusResolved,
		ResolvedAt:    &resolvedAt,
		RBINotified:   false,
		BoardNotified: false,
	}
	if err := incidentRepo.Create(ctx, critical); err != nil {
		t.Fatalf("incident Create against real schema failed (GENERATED-column regression?): %v", err)
	}

	// The GENERATED columns must have been computed by Postgres (critical ⇒
	// both board and RBI notification required).
	got, err := incidentRepo.Get(ctx, orgID, critical.ID)
	if err != nil {
		t.Fatalf("incident Get failed: %v", err)
	}
	if !got.BoardNotificationRequired || !got.RBINotificationRequired {
		t.Errorf("generated columns = (board=%v, rbi=%v), want both true for a critical incident",
			got.BoardNotificationRequired, got.RBINotificationRequired)
	}

	// Sanity: the pending-notification query finds the unsent-but-required row.
	pendingRBI, err := incidentRepo.GetPendingNotifications(ctx, orgID, "rbi")
	if err != nil {
		t.Fatalf("GetPendingNotifications(rbi) failed: %v", err)
	}
	if len(pendingRBI) != 1 {
		t.Fatalf("pending RBI notifications = %d, want 1", len(pendingRBI))
	}

	// --- P1 + P2: generate a board report through the real service path -----
	service := NewBoardReportService(boardRepo, nil, nil, incidentRepo, nil)
	report, err := service.GenerateReport(ctx, orgID, &GenerateReportRequest{
		ReportType:    "quarterly",
		ReportQuarter: "Q4-2026",
		GeneratedBy:   "compliance-officer",
	})
	if err != nil {
		t.Fatalf("GenerateReport INSERT against real schema failed (generation_method regression?): %v", err)
	}

	// Read the persisted row back and assert the canonical generation_method.
	var method string
	var complianceIssuesJSON []byte
	if err := db.QueryRow(
		`SELECT generation_method, compliance_issues FROM rbi_board_reports WHERE id = $1`,
		report.ID,
	).Scan(&method, &complianceIssuesJSON); err != nil {
		t.Fatalf("read back board report row: %v", err)
	}
	if method != "automatic" {
		t.Errorf("persisted generation_method = %q, want \"automatic\"", method)
	}

	// P2: the unsent-but-required RBI notification must be persisted as a
	// regulatory_notification compliance issue.
	if report.PendingRBINotifications != 1 {
		t.Errorf("report.PendingRBINotifications = %d, want 1", report.PendingRBINotifications)
	}
	if !strings.Contains(string(complianceIssuesJSON), "regulatory_notification") {
		t.Errorf("persisted compliance_issues does not contain 'regulatory_notification': %s", complianceIssuesJSON)
	}

	// --- Negative control: the CHECK genuinely rejects 'automated' ----------
	bad := &BoardReport{
		OrgID:            orgID,
		ReportType:       ReportTypeAnnual,
		GeneratedAt:      now,
		GenerationMethod: "automated", // the pre-fix value
		ApprovalStatus:   ReportApprovalDraft,
	}
	err = boardRepo.Create(ctx, bad)
	if err == nil {
		t.Fatal("expected the CHECK constraint to REJECT generation_method='automated', but Create succeeded — the real constraint is not being exercised")
	}
	if !strings.Contains(err.Error(), "generation_method") {
		t.Errorf("expected a generation_method CHECK violation, got: %v", err)
	}
}
