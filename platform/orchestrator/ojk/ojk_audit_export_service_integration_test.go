//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func getOJKTestDB(t *testing.T) *sql.DB {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test — DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	return db
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

	if !resp.Ready {
		t.Error("Expected ready=true when region=ID")
	}
	if resp.Score != 100 {
		t.Errorf("Expected score=100, got %d", resp.Score)
	}
	if len(resp.Checks) != 5 {
		t.Errorf("Expected 5 checks, got %d", len(resp.Checks))
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
	if resp.ComplianceScore != 100 {
		t.Errorf("Expected score=100, got %d", resp.ComplianceScore)
	}
	if resp.ActivePolicies != 8 {
		t.Errorf("Expected 8 active policies, got %d", resp.ActivePolicies)
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

// TestOJKAuditExportService_Integration_CrossBorderPasal56bRoundTrip seeds an
// orchestrator_audit_logs row tagged with the explicit UU PDP Pasal 56(b)
// value (transfer_basis = "pasal_56b_dpa") and asserts it round-trips
// unchanged through the cross_border_transfers export — no auto-translation to
// the generic "safeguards" label. Requires migration 129 (transfer_basis
// column) applied to the test DB.
func TestOJKAuditExportService_Integration_CrossBorderPasal56bRoundTrip(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()

	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")

	createOJKTestOrg(t, db, "cross-border-pasal56b")
	tenantID := "org-ojk-cross-border-pasal56b"

	ctx := context.Background()
	rowTS := time.Date(2026, 6, 1, 9, 30, 0, 0, time.UTC)

	_, err := db.ExecContext(ctx,
		`INSERT INTO orchestrator_audit_logs (org_id, service_id, action, resource, timestamp, data_residency, transfer_basis)
		 VALUES ($1, 'orchestrator', 'llm_route', 'openai/gpt-4o', $2, 'US', 'pasal_56b_dpa')`,
		tenantID, rowTS,
	)
	if err != nil {
		t.Skipf("Skipping — could not seed orchestrator_audit_logs (migration 129 may not be applied): %v", err)
	}
	defer db.ExecContext(ctx, `DELETE FROM orchestrator_audit_logs WHERE org_id = $1`, tenantID)

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
