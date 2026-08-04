//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// getOJKTestDB returns a database with the full core + enterprise schema.
//
// It was gated on a hand-set DATABASE_URL. R3 round 1 established that the only
// CI job running this package under -tags enterprise DELIBERATELY leaves
// DATABASE_URL unset, so this ENTIRE integration family -- breach lifecycle,
// handler full-stack, cross-border round trip -- skipped in every CI run since
// it was written. A test that never executes is a file, not a guard.
//
// It now uses the repo's standard convention (TEST_PG_INTEGRATION=1 + a
// throwaway container via approletest), which is the gate the enterprise real-PG
// job actually sets. Same schema, same assertions, now executed.
func getOJKTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return newOJKPGEnv(t).master
}

func createOJKTestOrg(t *testing.T, db *sql.DB, tenantID string) string {
	orgName := "test-org-ojk-" + tenantID
	orgIDStr := "org-ojk-" + tenantID

	var id int
	err := db.QueryRow("SELECT id FROM organizations WHERE name = $1", orgName).Scan(&id)
	if err == nil {
		return fmt.Sprintf("%d", id)
	}

	err = db.QueryRow(`
		INSERT INTO organizations (org_id, name, tier, license_key, created_at, updated_at)
		VALUES ($1, $2, 'enterprise', 'test-license-key-ojk', NOW(), NOW())
		RETURNING id
	`, orgIDStr, orgName).Scan(&id)
	if err != nil {
		t.Fatalf("Failed to create test org: %v", err)
	}

	return fmt.Sprintf("%d", id)
}

func TestOJKAuditExportService_Integration_NewService(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()

	service := NewOJKAuditExportService(db, nil)
	if service == nil {
		t.Fatal("Expected non-nil service")
	}
}

func TestOJKAuditExportService_Integration_ExportAuditData(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()

	service := NewOJKAuditExportService(db, nil)
	ctx := context.Background()

	req := &OJKAuditExportRequest{
		StartDate: "2025-01-01",
		EndDate:   "2025-12-31",
		Format:    OJKFormatJSON,
		Framework: OJKFrameworkCombined,
	}

	resp, err := service.ExportAuditData(ctx, "test-tenant-ojk", req)
	if err != nil {
		t.Fatalf("ExportAuditData failed: %v", err)
	}

	if resp.ExportID == "" {
		t.Error("Expected non-empty export_id")
	}
	if resp.Status != "completed" {
		t.Errorf("Expected status=completed, got %s", resp.Status)
	}
	if resp.Framework != OJKFrameworkCombined {
		t.Errorf("Expected framework=OJK_BI_COMBINED, got %s", resp.Framework)
	}
	if resp.Summary == nil {
		t.Error("Expected non-nil summary")
	}
	if resp.Metadata == nil {
		t.Error("Expected non-nil metadata")
	}
	if resp.Metadata != nil && resp.Metadata.Checksum == "" {
		t.Error("Expected non-empty checksum")
	}
}

func TestOJKAuditExportService_Integration_GetRetentionStatus(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()

	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")

	service := NewOJKAuditExportService(db, nil)
	ctx := context.Background()

	resp, err := service.GetRetentionStatus(ctx, "test-tenant-ojk", &OJKRetentionStatusRequest{})
	if err != nil {
		t.Fatalf("GetRetentionStatus failed: %v", err)
	}

	if resp.ComplianceStatus != "compliant" {
		t.Errorf("Expected compliant, got %s", resp.ComplianceStatus)
	}
	if resp.RetentionDays != IndonesiaRetentionDays {
		t.Errorf("Expected %d retention days, got %d", IndonesiaRetentionDays, resp.RetentionDays)
	}
}

func TestOJKAuditExportService_Integration_ValidateReadiness(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()

	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")

	service := NewOJKAuditExportService(db, nil)
	ctx := context.Background()

	resp, err := service.ValidateComplianceReadiness(ctx, "test-tenant-ojk")
	if err != nil {
		t.Fatalf("ValidateComplianceReadiness failed: %v", err)
	}

	// INVERTED (#3242). This asserted Ready=true / Score=100 for an org with no
	// traffic, no oversight records and no detection events -- true only because
	// four of the five checks were unconditional "pass" literals. Against a real
	// database the checks now MEASURE, so a silent org is "configured, never
	// exercised" (warnings), not ready.
	if resp.Ready {
		t.Error("an org with no governed traffic must not be reported OJK-ready")
	}
	if resp.Score == 100 {
		t.Error("a perfect score for an org with no evidence is the literal-pass defect")
	}
	if resp.UnknownChecks != 0 {
		t.Errorf("unknown checks = %d against a real database, want 0 (every dimension is measurable here)", resp.UnknownChecks)
	}
	if resp.MeasuredChecks != 5 {
		t.Errorf("measured checks = %d, want 5", resp.MeasuredChecks)
	}
	if len(resp.Checks) != 5 {
		t.Errorf("Expected 5 checks, got %d", len(resp.Checks))
	}
	for _, c := range resp.Checks {
		if c.Details == "" {
			t.Errorf("check %q reports no detail; a check must say what it observed", c.Name)
		}
	}
}

func TestOJKAuditExportService_Integration_SubmitBreachNotification(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()

	createOJKTestOrg(t, db, "breach-test")

	service := NewOJKAuditExportService(db, nil)
	ctx := context.Background()

	now := time.Now().UTC()
	notification := &OJKBreachNotification{
		IncidentTimestamp:    now.Add(-24 * time.Hour),
		DiscoveryTime:        now,
		DataSubjectsAffected: 500,
		DataTypesInvolved:    []string{"nik", "npwp"},
		Description:          "Integration test breach notification",
		RemediationSteps:     []string{"Revoke credentials", "Notify data subjects"},
	}

	resp, err := service.SubmitBreachNotification(ctx, "org-ojk-breach-test", notification)
	if err != nil {
		t.Fatalf("SubmitBreachNotification failed: %v", err)
	}

	if resp.ID == "" {
		t.Error("Expected non-empty notification ID")
	}
	if resp.Status != "submitted" {
		t.Errorf("Expected status=submitted, got %s", resp.Status)
	}
	if resp.NotifiedAuthority != "MOCDA" {
		t.Errorf("Expected authority=MOCDA, got %s", resp.NotifiedAuthority)
	}

	expectedDeadline := now.Add(72 * time.Hour)
	if resp.NotificationDeadline.Sub(expectedDeadline) > time.Second {
		t.Errorf("72h deadline mismatch: expected ~%v, got %v", expectedDeadline, resp.NotificationDeadline)
	}

	// Verify row was persisted
	var dbID string
	err = db.QueryRowContext(ctx,
		"SELECT id FROM ojk_breach_notifications WHERE id = $1",
		resp.ID,
	).Scan(&dbID)
	if err != nil {
		t.Logf("Note: breach notifications table may not exist in test DB (migration 130 not applied) — %v", err)
	} else if dbID != resp.ID {
		t.Errorf("Persisted ID mismatch: expected %s, got %s", resp.ID, dbID)
	}
}

func TestOJKAuditExportService_Integration_GetDashboard(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()

	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")

	service := NewOJKAuditExportService(db, nil)
	ctx := context.Background()

	resp, err := service.GetDashboard(ctx, "test-tenant-ojk")
	if err != nil {
		t.Fatalf("GetDashboard failed: %v", err)
	}

	if resp.Framework != OJKFrameworkCombined {
		t.Errorf("Expected OJK_BI_COMBINED, got %s", resp.Framework)
	}
	// INVERTED (#3242): both values were literals. active_policies is now the
	// count of ENABLED Indonesia-PII policy rows the org can see (the global
	// system tier plus its own), which on a fresh database is the single
	// sys_pii_indonesia_ktp row from core/116 -- not 8.
	if resp.ComplianceScore == 100 {
		t.Error("a perfect dashboard score for an org with no evidence is the literal-pass defect")
	}
	if resp.ActivePolicies < 0 {
		t.Errorf("active_policies = %d; the count could not be derived on a fully-migrated database", resp.ActivePolicies)
	}
	if len(resp.Unavailable) != 0 {
		t.Errorf("unavailable = %v against a real database, want none", resp.Unavailable)
	}
}

func TestOJKAuditExportService_Integration_GetExportStatus(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()

	service := NewOJKAuditExportService(db, nil)
	ctx := context.Background()

	resp, err := service.GetExportStatus(ctx, "test-tenant-ojk", "test-export-123")
	if err != nil {
		t.Fatalf("GetExportStatus failed: %v", err)
	}

	if resp.ExportID != "test-export-123" {
		t.Errorf("Expected export_id=test-export-123, got %s", resp.ExportID)
	}
}

// TestOJKAuditExportService_Integration_CrossBorderPasal56bRoundTrip seeds a
// canonical audit_logs row tagged with the explicit UU PDP Pasal 56(b) value
// (transfer_basis = "pasal_56b_dpa") and asserts it round-trips unchanged
// through the cross_border_transfers export, no auto-translation to the generic
// "safeguards" label. Requires core migration 126 (transfer_basis column on
// audit_logs) applied to the test DB. This is the direct-seed variant; the
// full stamp→write→export path is covered by the orchestrator-package end-to-end
// test (TestCrossBorderAutoStamp_EndToEnd).
func TestOJKAuditExportService_Integration_CrossBorderPasal56bRoundTrip(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()

	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")

	createOJKTestOrg(t, db, "cross-border-pasal56b")
	tenantID := "org-ojk-cross-border-pasal56b"

	ctx := context.Background()
	rowTS := time.Date(2026, 6, 1, 9, 30, 0, 0, time.UTC)
	auditID := "audit-cb-pasal56b-" + tenantID

	_, err := db.ExecContext(ctx,
		`INSERT INTO audit_logs (
			id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash,
			policy_decision, data_residency, transfer_basis
		) VALUES (
			$1, 'req-cb-1', $2, 1, 'auditor@example.com', 'admin',
			'client-1', $3, $3, 'completion', 'hello', 'h1',
			'allowed', 'US', 'pasal_56b_dpa'
		)`,
		auditID, rowTS, tenantID,
	)
	if err != nil {
		t.Skipf("Skipping: could not seed audit_logs (core migration 126 may not be applied): %v", err)
	}
	defer db.ExecContext(ctx, `DELETE FROM audit_logs WHERE id = $1`, auditID)

	service := NewOJKAuditExportService(db, nil)
	resp, err := service.ExportAuditData(ctx, tenantID, &OJKAuditExportRequest{
		StartDate: "2026-01-01",
		EndDate:   "2026-12-31",
		DataTypes: []OJKAuditDataType{OJKDataTypeCrossBorder},
		Framework: OJKFrameworkUUPDP,
	})
	if err != nil {
		t.Fatalf("ExportAuditData failed: %v", err)
	}
	if resp.Data == nil || len(resp.Data.CrossBorder) == 0 {
		t.Fatalf("expected at least one cross-border record, got %+v", resp.Data)
	}

	var found bool
	for _, rec := range resp.Data.CrossBorder {
		if rec.TransferBasis == "pasal_56b_dpa" {
			found = true
			if rec.DataResidency != "US" {
				t.Errorf("data_residency = %q, want US", rec.DataResidency)
			}
			if rec.DestinationCountry != "US" {
				t.Errorf("destination_country = %q, want US", rec.DestinationCountry)
			}
		}
	}
	if !found {
		t.Errorf("pasal_56b_dpa transfer_basis did not round-trip through export: %+v", resp.Data.CrossBorder)
	}
	if resp.Summary.RecordsByType["cross_border_transfers"] < 1 {
		t.Errorf("summary records_by_type[cross_border_transfers] = %d, want >= 1", resp.Summary.RecordsByType["cross_border_transfers"])
	}
}
