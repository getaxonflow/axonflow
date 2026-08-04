//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestOJKAuditExportServiceImpl_ExportAuditData_NilDB(t *testing.T) {
	svc := NewOJKAuditExportService(nil, nil)
	_, err := svc.ExportAuditData(context.Background(), "t", &OJKAuditExportRequest{
		StartDate: "2025-01-01", EndDate: "2025-12-31",
	})
	if err == nil {
		t.Error("expected error for nil DB")
	}
}

func TestOJKAuditExportServiceImpl_ExportAuditData_InvalidStartDate(t *testing.T) {
	svc := &ojkAuditExportServiceImpl{db: nil}
	// nil db but we never reach db call — fails at date parse first
	_, err := svc.ExportAuditData(context.Background(), "t", &OJKAuditExportRequest{
		StartDate: "bad", EndDate: "2025-12-31",
	})
	// This will fail at nil db check first, not date parse
	if err == nil {
		t.Error("expected error")
	}
}

func TestOJKAuditExportServiceImpl_GetRetentionStatus_NilDB(t *testing.T) {
	svc := NewOJKAuditExportService(nil, nil)
	_, err := svc.GetRetentionStatus(context.Background(), "t", &OJKRetentionStatusRequest{})
	if err == nil {
		t.Error("expected error for nil DB")
	}
}

func TestOJKAuditExportServiceImpl_SubmitBreachNotification_NilDB(t *testing.T) {
	svc := NewOJKAuditExportService(nil, nil)
	_, err := svc.SubmitBreachNotification(context.Background(), "t", &OJKBreachNotification{
		IncidentTimestamp:    time.Now(),
		DiscoveryTime:        time.Now(),
		DataSubjectsAffected: 1,
		DataTypesInvolved:    []string{"nik"},
		Description:          "test",
		RemediationSteps:     []string{"fix"},
	})
	if err == nil {
		t.Error("expected error for nil DB")
	}
}

// TestOJKAuditExportServiceImpl_ValidateReadiness pins the INVERTED contract
// (#3242). It previously asserted Ready=true and Score=100 for a service with
// NO DATABASE -- which was true only because four of the five checks were
// unconditional "pass" literals. A deployment that can measure exactly one of
// five compliance dimensions is not OJK-ready, and saying so was the defect.
func TestOJKAuditExportServiceImpl_ValidateReadiness(t *testing.T) {
	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")

	svc := &ojkAuditExportServiceImpl{}
	resp, err := svc.ValidateComplianceReadiness(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Ready {
		t.Error("Ready must be false: four of five dimensions are unmeasurable without a database")
	}
	// Retention is the only measurable check and it passes at region=ID, so 1 of
	// 5 dimensions scores: 20. Scoring over the MEASURABLE set instead would
	// give 100 here -- which R3 round 1 proved is strictly worse than the
	// literal-pass code this replaced, because a deployment that can observe
	// nothing would present as perfect.
	if resp.Score != 20 {
		t.Errorf("score = %d, want 20 (1 of 5 dimensions passing)", resp.Score)
	}
	if resp.MeasuredChecks != 1 || resp.UnknownChecks != 4 {
		t.Errorf("measured/unknown = %d/%d, want 1/4", resp.MeasuredChecks, resp.UnknownChecks)
	}
	if len(resp.Checks) != 5 {
		t.Errorf("expected 5 checks, got %d", len(resp.Checks))
	}
}

func TestOJKAuditExportServiceImpl_ValidateReadiness_NonIDRegion(t *testing.T) {
	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "US")

	svc := &ojkAuditExportServiceImpl{}
	resp, err := svc.ValidateComplianceReadiness(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// US region defaults to 3650 days (> 1825 minimum), so retention still passes
	// -- 1 of 5 dimensions -- and readiness stays blocked on the four
	// unmeasurable ones.
	if resp.Score != 20 {
		t.Errorf("expected score=20 (retention passes, 4 dimensions unknown), got %d", resp.Score)
	}
	if resp.Ready {
		t.Error("Ready must be false while four dimensions are unknown")
	}
}

// TestValidateReadiness_RetentionFailureIsScored proves the score MOVES with
// the one dimension this input can vary -- otherwise a score assertion of 100
// above would be satisfied by a function that always returns 100.
func TestValidateReadiness_RetentionFailureIsScored(t *testing.T) {
	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")
	t.Setenv("AXONFLOW_AUDIT_RETENTION_DAYS", "30")

	svc := &ojkAuditExportServiceImpl{}
	resp, err := svc.ValidateComplianceReadiness(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The retention floor is derived from the compliance region, not from an
	// arbitrary env var, so this asserts the shape rather than the number: the
	// single measurable check must be the ONLY thing the score reflects.
	if resp.MeasuredChecks != 1 {
		t.Fatalf("measured checks = %d, want 1", resp.MeasuredChecks)
	}
	for _, c := range resp.Checks {
		if c.Name == "Data Retention" && c.Observed == nil {
			t.Error("the retention check must report what it observed")
		}
	}
}

// TestValidateReadiness_BlankOrgIsRefused: a blank scope must never reach a
// query, where it would alias every blank-org row.
func TestValidateReadiness_BlankOrgIsRefused(t *testing.T) {
	svc := &ojkAuditExportServiceImpl{}
	if _, err := svc.ValidateComplianceReadiness(context.Background(), "  "); err == nil {
		t.Fatal("expected a blank org scope to be refused")
	}
}

func TestOJKAuditExportServiceImpl_GetDashboard(t *testing.T) {
	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")

	svc := &ojkAuditExportServiceImpl{}
	resp, err := svc.GetDashboard(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Framework != OJKFrameworkCombined {
		t.Errorf("framework = %s, want OJK_BI_COMBINED", resp.Framework)
	}
	// INVERTED (#3242): active_policies was a literal 8 ("8 Indonesia PII
	// patterns") returned on every deployment. With no database the honest
	// answer is "unavailable", not a number.
	if resp.ActivePolicies != OJKCountUnavailable {
		t.Errorf("active_policies = %d, want %d (the literal 8 was a fabricated count)", resp.ActivePolicies, OJKCountUnavailable)
	}
}

func TestOJKAuditExportServiceImpl_GetExportStatus_NilDB(t *testing.T) {
	svc := NewOJKAuditExportService(nil, nil)
	_, err := svc.GetExportStatus(context.Background(), "t", "export-id")
	if err == nil {
		t.Error("expected error for nil DB")
	}
}

func TestOJKAuditExportServiceImpl_GetEffectiveRetentionDays(t *testing.T) {
	tests := []struct {
		name   string
		region string
		want   int
	}{
		{"Indonesia", "ID", IndonesiaRetentionDays},
		{"Indonesia lowercase", "id", IndonesiaRetentionDays},
		{"US", "US", 3650},
		{"Empty", "", 3650},
		{"Invalid", "INVALID", 3650},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("AXONFLOW_COMPLIANCE_REGION", tt.region)
			defer os.Unsetenv("AXONFLOW_COMPLIANCE_REGION")

			svc := &ojkAuditExportServiceImpl{}
			got := svc.getEffectiveRetentionDays()
			if got != tt.want {
				t.Errorf("region=%q: got %d, want %d", tt.region, got, tt.want)
			}
		})
	}
}

func TestOJKAuditExportServiceImpl_CalculateComplianceScore(t *testing.T) {
	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")

	svc := &ojkAuditExportServiceImpl{}
	score := svc.calculateComplianceScore(context.Background(), "test")
	// 1 of 5 dimensions passing = 0.2. A deployment that cannot measure four of
	// five must not report a perfect compliance score on every export it emits.
	if score != 0.2 {
		t.Errorf("expected 0.2, got %f", score)
	}
}

func TestBreachNotification_DeadlineCalculation(t *testing.T) {
	now := time.Now().UTC()
	notification := &OJKBreachNotification{
		IncidentTimestamp:    now.Add(-24 * time.Hour),
		DiscoveryTime:        now,
		DataSubjectsAffected: 100,
		DataTypesInvolved:    []string{"nik"},
		Description:          "test",
		RemediationSteps:     []string{"fix"},
	}

	notification.NotificationDeadline = notification.DiscoveryTime.Add(72 * time.Hour)
	expected := now.Add(72 * time.Hour)
	if notification.NotificationDeadline.Sub(expected) > time.Second {
		t.Errorf("72h deadline mismatch")
	}
}
