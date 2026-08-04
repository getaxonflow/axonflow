// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"errors"
	"testing"
)

// #2610: the five EU AI Act export processors that #2591 left erroring honestly
// (full_audit, conformity_evidence, hitl_summary, policy_violations,
// accuracy_metrics) are now implemented against real data sources. Each queries
// its source via the ExportRepository, records the TRUE row count, serializes a
// JSON payload, and Completes — Failing only on a genuine query/serialize error.
//
// These tests are red-on-revert: revert any processor to the old
// errExportTypeNotImplemented stub and the job goes Failed, so the
// Status==Completed + RecordCount==seeded assertions below fail.

// seedMockForType populates the mock's source for an export type with a
// type-distinct row count, so a processor wired to the WRONG source (or an empty
// one) is caught by the RecordCount assertion. Returns the expected count.
func seedMockForType(repo *MockExportRepository, et ExportType) int {
	switch et {
	case ExportTypeFullAudit:
		repo.fullAudit = []AuditLogRecord{
			{ID: "log-1", RequestID: "r1", RequestType: "llm_chat", PolicyDecision: "allow"},
			{ID: "log-2", RequestID: "r2", RequestType: "mcp-query", PolicyDecision: "deny"},
			{ID: "log-3", RequestID: "r3", RequestType: "sql", PolicyDecision: "allow"},
		}
		return 3
	case ExportTypeConformityEvidence:
		repo.conformityAssessments = []*ConformityAssessment{
			{ID: "ca-1", OrgID: "regbank-india", SystemID: "sys-a", RiskCategory: RiskCategoryHighRisk},
		}
		return 1
	case ExportTypeHITLSummary:
		repo.hitlHistory = []HITLApprovalRecord{
			{ID: 1, RequestID: "req-a", Action: "created", NewStatus: "pending"},
			{ID: 2, RequestID: "req-a", Action: "approved", PreviousStatus: "pending", NewStatus: "approved"},
		}
		return 2
	case ExportTypePolicyViolations:
		repo.policyViolations = []PolicyViolationRecord{
			{ID: 1, ViolationType: "pii_leak", Severity: "high"},
			{ID: 2, ViolationType: "prompt_injection", Severity: "critical"},
			{ID: 3, ViolationType: "rate_limit", Severity: "low"},
			{ID: 4, ViolationType: "policy_block", Severity: "medium"},
		}
		return 4
	case ExportTypeAccuracyMetrics:
		repo.accuracyMetrics = []*AccuracyMetric{
			{ID: "m-1", ModelID: "gpt-x", MetricType: MetricTypeAccuracy, Value: 0.91},
		}
		return 1
	}
	return 0
}

// TestProcessExport_RealDataTypes_CompleteWithRecords proves each of the five
// implemented export types Completes carrying the real seeded row count
// (#2610). Red-on-revert against the #2591 stubs (which Fail).
func TestProcessExport_RealDataTypes_CompleteWithRecords(t *testing.T) {
	types := []ExportType{
		ExportTypeFullAudit,
		ExportTypeConformityEvidence,
		ExportTypeHITLSummary,
		ExportTypePolicyViolations,
		ExportTypeAccuracyMetrics,
	}

	for _, et := range types {
		t.Run(string(et), func(t *testing.T) {
			repo := NewMockExportRepository()
			want := seedMockForType(repo, et)
			export := &Export{
				ID:         "export-" + string(et),
				OrgID:      "regbank-india",
				ExportType: et,
				Format:     ExportFormatJSON,
				Status:     ExportStatusPending,
			}
			repo.exports[export.ID] = export

			// Called directly, processExport runs synchronously (the goroutine is
			// only spawned by CreateExport), so the final state is deterministic.
			NewExportService(repo, nil).processExport(export.OrgID, export.ID)

			got, err := repo.GetByID(context.Background(), export.OrgID, export.ID)
			if err != nil {
				t.Fatalf("GetByID: %v", err)
			}
			if got == nil {
				t.Fatal("export missing after processExport")
			}
			if got.Status != ExportStatusCompleted {
				t.Fatalf("%s: want Status=%q (real data source → must complete, #2610), got %q err=%q",
					et, ExportStatusCompleted, got.Status, got.Error)
			}
			if got.Progress != 100 {
				t.Errorf("%s: want Progress=100 for a completed export, got %d", et, got.Progress)
			}
			if got.RecordCount != want {
				t.Errorf("%s: want RecordCount=%d (the seeded rows), got %d — wrong or empty data source",
					et, want, got.RecordCount)
			}
			if got.FileSize <= 0 {
				t.Errorf("%s: want FileSize>0 (payload serialized), got %d", et, got.FileSize)
			}
		})
	}
}

// TestProcessExport_RealDataTypes_QueryError_Fails proves a genuine repository
// read error fails the job honestly (Status=Failed with a message) rather than
// reporting a fabricated success — the #2591 contract, preserved now that the
// processors do real work. #2610.
func TestProcessExport_RealDataTypes_QueryError_Fails(t *testing.T) {
	boom := errors.New("db read failed")
	cases := []struct {
		et    ExportType
		setup func(*MockExportRepository)
	}{
		{ExportTypeFullAudit, func(m *MockExportRepository) { m.getFullAuditErr = boom }},
		{ExportTypeConformityEvidence, func(m *MockExportRepository) { m.getConformityErr = boom }},
		{ExportTypeHITLSummary, func(m *MockExportRepository) { m.getHITLErr = boom }},
		{ExportTypePolicyViolations, func(m *MockExportRepository) { m.getPolicyViolationsErr = boom }},
		{ExportTypeAccuracyMetrics, func(m *MockExportRepository) { m.getAccuracyMetricsErr = boom }},
	}

	for _, tc := range cases {
		t.Run(string(tc.et), func(t *testing.T) {
			repo := NewMockExportRepository()
			tc.setup(repo)
			export := &Export{
				ID:         "export-err-" + string(tc.et),
				OrgID:      "regbank-india",
				ExportType: tc.et,
				Format:     ExportFormatJSON,
				Status:     ExportStatusPending,
			}
			repo.exports[export.ID] = export

			NewExportService(repo, nil).processExport(export.OrgID, export.ID)

			got, err := repo.GetByID(context.Background(), export.OrgID, export.ID)
			if err != nil {
				t.Fatalf("GetByID: %v", err)
			}
			if got.Status != ExportStatusFailed {
				t.Fatalf("%s: a genuine query error must Fail the job (not fake-complete), got Status=%q", tc.et, got.Status)
			}
			if got.Error == "" {
				t.Errorf("%s: want a non-empty error on failure", tc.et)
			}
			if got.Progress == 100 {
				t.Errorf("%s: want Progress<100 for a failed export, got 100", tc.et)
			}
		})
	}
}

// TestProcessExport_DecisionChain_NotRegressed guards the #2588/#2596 wiring:
// the decision-chain processor reads real audit_logs rows and must still
// Complete with the true record count, untouched by the #2610 implementation of
// the sibling export types.
func TestProcessExport_DecisionChain_NotRegressed(t *testing.T) {
	repo := NewMockExportRepository()
	repo.decisionChain = []DecisionChainRecord{
		{ID: "decide_d1", RequestID: "req-a", DecisionType: "llm", DecisionOutcome: "approved"},
		{ID: "decide_d2", RequestID: "req-b", DecisionType: "tool", DecisionOutcome: "blocked"},
	}
	export := &Export{
		ID:         "export-dc",
		OrgID:      "regbank-india",
		ExportType: ExportTypeDecisionChain,
		Format:     ExportFormatJSON,
		Status:     ExportStatusPending,
	}
	repo.exports[export.ID] = export

	NewExportService(repo, nil).processExport(export.OrgID, export.ID)

	got, err := repo.GetByID(context.Background(), export.OrgID, export.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != ExportStatusCompleted {
		t.Fatalf("decision-chain export must still Complete (not regressed by #2610), got Status=%q err=%q",
			got.Status, got.Error)
	}
	if got.RecordCount != 2 {
		t.Errorf("decision-chain RecordCount: want 2 (the real rows), got %d", got.RecordCount)
	}
}
