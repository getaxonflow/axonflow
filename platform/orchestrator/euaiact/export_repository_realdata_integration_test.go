// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Integration tests for the #2610 real-data export repository methods.
//
// They prove each new Get* method is ORG-SCOPED by its explicit org_id/tenant_id
// WHERE filter — a second org's rows seeded into the same table never leak into
// the first org's export. These require DATABASE_URL and run against real
// Postgres (getTestDB, defined in export_repository_integration_test.go).
//
// Source tables policy_violations / hitl_approval_history / euaiact_* are
// RLS-enabled; the integration DATABASE_URL connects as the table owner (RLS
// bypassed), so what is verified here is the explicit-filter scoping the
// processors rely on regardless of RLS posture (audit_logs is not even
// RLS-enabled).

func cleanupRealDataExportRows(t *testing.T, orgIDs ...string) {
	t.Helper()
	db := getTestDB(t)
	defer db.Close()
	for _, org := range orgIDs {
		for _, stmt := range []string{
			"DELETE FROM audit_logs WHERE org_id = $1 OR tenant_id = $1",
			"DELETE FROM policy_violations WHERE org_id = $1",
			"DELETE FROM hitl_approval_history WHERE org_id = $1 OR tenant_id = $1",
			"DELETE FROM euaiact_accuracy_metrics WHERE org_id = $1",
			"DELETE FROM euaiact_conformity_assessments WHERE org_id = $1",
		} {
			if _, err := db.Exec(stmt, org); err != nil {
				t.Logf("cleanup %q for %s: %v", stmt, org, err)
			}
		}
	}
}

func TestExportRepository_Integration_RealDataMethods_OrgScoped(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()
	ctx := context.Background()

	suffix := time.Now().Format("20060102150405")
	orgA := getOrCreateTestOrg(t, db, "rd-orgA-"+suffix)
	orgB := getOrCreateTestOrg(t, db, "rd-orgB-"+suffix)
	t.Cleanup(func() { cleanupRealDataExportRows(t, orgA, orgB) })

	now := time.Now().UTC()

	// --- seed audit_logs: 2 rows for A, 1 for B (tenant_id == org_id) ---
	insAudit := func(org string, n int, decision string) {
		id := fmt.Sprintf("rd-audit-%s-%d", org, n)
		_, err := db.Exec(`
			INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role,
				client_id, tenant_id, org_id, request_type, query, query_hash, policy_decision)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			id, "req-"+id, now, 1, "u@example.com", "user",
			"client-x", org, org, "llm_chat", "hello", "hash-"+id, decision)
		if err != nil {
			t.Fatalf("insert audit_logs: %v", err)
		}
	}
	insAudit(orgA, 1, "allowed")
	insAudit(orgA, 2, "blocked")
	insAudit(orgB, 1, "allowed")

	// --- seed policy_violations: 2 for A, 1 for B ---
	insViol := func(org, vtype string) {
		if _, err := db.Exec(`
			INSERT INTO policy_violations (org_id, violation_type, severity, client_id, user_id, description, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			org, vtype, "high", "client-x", "u1", "seeded", now); err != nil {
			t.Fatalf("insert policy_violations: %v", err)
		}
	}
	insViol(orgA, "pii_leak")
	insViol(orgA, "prompt_injection")
	insViol(orgB, "pii_leak")

	// --- seed hitl_approval_history: 2 for A, 1 for B ---
	insHITL := func(org, action string) {
		if _, err := db.Exec(`
			INSERT INTO hitl_approval_history (request_id, org_id, tenant_id, action, previous_status, new_status, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			uuid.New().String(), org, org, action, "pending", "approved", now); err != nil {
			t.Fatalf("insert hitl_approval_history: %v", err)
		}
	}
	insHITL(orgA, "approved")
	insHITL(orgA, "rejected")
	insHITL(orgB, "approved")

	// --- seed euaiact_accuracy_metrics: 2 for A, 1 for B ---
	insMetric := func(org string, n int) {
		id := fmt.Sprintf("rd-metric-%s-%d", org, n)
		if _, err := db.Exec(`
			INSERT INTO euaiact_accuracy_metrics (id, org_id, model_id, metric_type, value, sample_size, timestamp)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			id, org, "model-z", "accuracy", 0.9, 100, now); err != nil {
			t.Fatalf("insert euaiact_accuracy_metrics: %v", err)
		}
	}
	insMetric(orgA, 1)
	insMetric(orgA, 2)
	insMetric(orgB, 1)

	// --- seed euaiact_conformity_assessments: 2 for A, 1 for B ---
	insCA := func(org string, n int) {
		id := fmt.Sprintf("rd-ca-%s-%d", org, n)
		if _, err := db.Exec(`
			INSERT INTO euaiact_conformity_assessments (id, org_id, system_id, system_name, risk_category,
				status, version, assessment_date, created_by, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			id, org, "sys-"+id, "System "+id, "high-risk",
			"draft", 1, now, "tester", now, now); err != nil {
			t.Fatalf("insert euaiact_conformity_assessments: %v", err)
		}
	}
	insCA(orgA, 1)
	insCA(orgA, 2)
	insCA(orgB, 1)

	repo := NewPostgresExportRepository(db)
	var zero time.Time

	t.Run("GetFullAudit", func(t *testing.T) {
		recs, err := repo.GetFullAudit(ctx, orgA, zero, zero)
		if err != nil {
			t.Fatalf("GetFullAudit: %v", err)
		}
		if len(recs) != 2 {
			t.Fatalf("want 2 audit rows for orgA, got %d", len(recs))
		}
		for _, r := range recs {
			if r.OrgID != orgA {
				t.Errorf("cross-org leak: audit row org_id=%q (want %q)", r.OrgID, orgA)
			}
		}
	})

	t.Run("GetPolicyViolations", func(t *testing.T) {
		recs, err := repo.GetPolicyViolations(ctx, orgA, zero, zero)
		if err != nil {
			t.Fatalf("GetPolicyViolations: %v", err)
		}
		if len(recs) != 2 {
			t.Fatalf("want 2 policy_violations for orgA, got %d", len(recs))
		}
		for _, r := range recs {
			if r.OrgID != orgA {
				t.Errorf("cross-org leak: violation org_id=%q (want %q)", r.OrgID, orgA)
			}
		}
	})

	t.Run("GetHITLApprovalHistory", func(t *testing.T) {
		recs, err := repo.GetHITLApprovalHistory(ctx, orgA, zero, zero)
		if err != nil {
			t.Fatalf("GetHITLApprovalHistory: %v", err)
		}
		if len(recs) != 2 {
			t.Fatalf("want 2 hitl rows for orgA, got %d", len(recs))
		}
		for _, r := range recs {
			if r.OrgID != orgA {
				t.Errorf("cross-org leak: hitl org_id=%q (want %q)", r.OrgID, orgA)
			}
		}
	})

	t.Run("GetAccuracyMetrics", func(t *testing.T) {
		recs, err := repo.GetAccuracyMetrics(ctx, orgA, zero, zero)
		if err != nil {
			t.Fatalf("GetAccuracyMetrics: %v", err)
		}
		if len(recs) != 2 {
			t.Fatalf("want 2 accuracy metrics for orgA, got %d", len(recs))
		}
		for _, r := range recs {
			if r.OrgID != orgA {
				t.Errorf("cross-org leak: metric org_id=%q (want %q)", r.OrgID, orgA)
			}
		}
	})

	t.Run("GetConformityAssessments", func(t *testing.T) {
		recs, err := repo.GetConformityAssessments(ctx, orgA, zero, zero)
		if err != nil {
			t.Fatalf("GetConformityAssessments: %v", err)
		}
		if len(recs) != 2 {
			t.Fatalf("want 2 conformity assessments for orgA, got %d", len(recs))
		}
		for _, r := range recs {
			if r.OrgID != orgA {
				t.Errorf("cross-org leak: assessment org_id=%q (want %q)", r.OrgID, orgA)
			}
		}
	})

	// Date-range filter: a window entirely in the past returns nothing.
	t.Run("DateRangeExcludesOutOfWindow", func(t *testing.T) {
		past := now.Add(-72 * time.Hour)
		pastFrom := now.Add(-96 * time.Hour)
		recs, err := repo.GetFullAudit(ctx, orgA, pastFrom, past)
		if err != nil {
			t.Fatalf("GetFullAudit (past window): %v", err)
		}
		if len(recs) != 0 {
			t.Errorf("want 0 audit rows in a past-only window, got %d", len(recs))
		}
	})
}
