// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// #2588: the EU AI Act decision-chain export previously returned an empty
// (RecordCount=0) file in every deployment because processDecisionChainExport
// was a TODO stub and the decision_chain table it was tied to has no live
// writer. These tests assert the export now returns the real per-decision audit
// rows from canonical audit_logs. Both are red-on-revert: the processor test
// fails if processDecisionChainExport ignores the repo (the old stub), and the
// repository test fails if GetDecisionChain stops querying audit_logs.

// TestProcessDecisionChainExport_PopulatesDecisionRows proves the processor sets
// RecordCount from the actual per-decision rows rather than the stub's hardcoded
// zero. The three rows carry distinct request_ids — independent governance
// decisions, not stages of one grouped chain (#2598).
func TestProcessDecisionChainExport_PopulatesDecisionRows(t *testing.T) {
	repo := NewMockExportRepository()
	ms := 12
	repo.decisionChain = []DecisionChainRecord{
		{ID: "decide_d1", RequestID: "req-a", DecisionType: "llm", DecisionOutcome: "approved", ProcessingTimeMs: &ms},
		{ID: "decide_d2", RequestID: "req-b", DecisionType: "tool", DecisionOutcome: "pending_review", RequiresReview: true},
		{ID: "decide_d3", RequestID: "req-c", DecisionType: "agent", DecisionOutcome: "blocked"},
	}
	// nil storage backend: exercises the no-upload path (RecordCount + FileSize
	// must still reflect the real decision rows).
	service := NewExportService(repo, nil)

	export := &Export{
		ID:         "export-abc123",
		OrgID:      "regbank-india",
		ExportType: ExportTypeDecisionChain,
		Format:     ExportFormatJSON,
		Status:     ExportStatusProcessing,
	}

	if err := service.processDecisionChainExport(context.Background(), export); err != nil {
		t.Fatalf("processDecisionChainExport returned error: %v", err)
	}

	if export.RecordCount != 3 {
		t.Fatalf("RecordCount: want 3 (the real decision rows), got %d — empty decision-rows regression (#2588)", export.RecordCount)
	}
	if export.FileSize <= 0 {
		t.Errorf("FileSize: want > 0 (serialized decision-rows payload), got %d", export.FileSize)
	}
	// No storage backend → no storage key, but the count is still real.
	if export.StorageKey != "" {
		t.Errorf("StorageKey: want empty with nil backend, got %q", export.StorageKey)
	}
}

// TestProcessDecisionChainExport_EmptyIsHonest verifies a genuinely empty
// window reports zero (not a fabricated count).
func TestProcessDecisionChainExport_EmptyIsHonest(t *testing.T) {
	repo := NewMockExportRepository()
	repo.decisionChain = nil
	service := NewExportService(repo, nil)

	export := &Export{ID: "export-empty", OrgID: "regbank-india", ExportType: ExportTypeDecisionChain, Format: ExportFormatJSON}
	if err := service.processDecisionChainExport(context.Background(), export); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if export.RecordCount != 0 {
		t.Errorf("RecordCount: want 0 for an empty window, got %d", export.RecordCount)
	}
}

// TestPostgresExportRepository_GetDecisionChain_FromAuditLogs proves the
// repository reads the canonical audit_logs decision rows (not decision_chain)
// and maps verdicts/columns correctly.
func TestPostgresExportRepository_GetDecisionChain_FromAuditLogs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	now := time.Now().UTC()
	from := now.Add(-24 * time.Hour)
	to := now

	// The query MUST hit audit_logs and filter on the decision_id predicate, and
	// it MUST select correlation_id (#2598) as the last column.
	mock.ExpectQuery(regexp.QuoteMeta("FROM audit_logs")).
		WithArgs("regbank-india", from, to).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "timestamp", "decision_type", "policy_decision",
			"model_id", "policies_evaluated", "policy_triggered", "response_time_ms",
			"correlation_id",
		}).
			AddRow("decide_d1", "req-a", now, "llm", "allow",
				"gpt-4o", `["sys_pii_india_pan"]`, "sys_pii_india_pan", int64(12), "trace-shared").
			AddRow("decide_d2", "req-b", now, "tool", "needs_approval",
				"gpt-4o", `["sys_high_risk_tool"]`, "sys_high_risk_tool", int64(8), "trace-shared").
			AddRow("decide_d3", "req-c", now, "agent", "deny",
				"gpt-4o", `["sebi_ai_disclosure"]`, "sebi_ai_disclosure", nil, ""))

	recs, err := repo.GetDecisionChain(context.Background(), "regbank-india", from, to)
	if err != nil {
		t.Fatalf("GetDecisionChain: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("want 3 decision rows, got %d", len(recs))
	}

	// correlation_id is scanned into the record (#2598). Red-on-revert: if the
	// scan stops reading the column these go empty.
	if recs[0].CorrelationID != "trace-shared" || recs[1].CorrelationID != "trace-shared" {
		t.Errorf("rows 0,1 want correlation_id trace-shared, got %q,%q", recs[0].CorrelationID, recs[1].CorrelationID)
	}
	if recs[2].CorrelationID != "" {
		t.Errorf("row2 correlation_id: want empty, got %q", recs[2].CorrelationID)
	}

	// Verdict → outcome mapping.
	if recs[0].DecisionOutcome != "approved" {
		t.Errorf("row0 outcome: want approved, got %q", recs[0].DecisionOutcome)
	}
	if recs[1].DecisionOutcome != "pending_review" || !recs[1].RequiresReview {
		t.Errorf("row1: want pending_review + RequiresReview, got %q review=%v", recs[1].DecisionOutcome, recs[1].RequiresReview)
	}
	if recs[2].DecisionOutcome != "blocked" {
		t.Errorf("row2 outcome: want blocked, got %q", recs[2].DecisionOutcome)
	}
	// Nullable response_time_ms → nil pointer on the last row.
	if recs[0].ProcessingTimeMs == nil || *recs[0].ProcessingTimeMs != 12 {
		t.Errorf("row0 ProcessingTimeMs: want 12, got %v", recs[0].ProcessingTimeMs)
	}
	if recs[2].ProcessingTimeMs != nil {
		t.Errorf("row2 ProcessingTimeMs: want nil, got %v", *recs[2].ProcessingTimeMs)
	}
	if recs[0].PolicyTriggered != "sys_pii_india_pan" {
		t.Errorf("row0 PolicyTriggered: want sys_pii_india_pan, got %q", recs[0].PolicyTriggered)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestPostgresExportRepository_GetDecisionChain_UnboundedDates proves a zero
// date range passes NULL bounds (the $N::timestamp IS NULL branch) rather than
// a zero-time that would exclude every row.
func TestPostgresExportRepository_GetDecisionChain_UnboundedDates(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewPostgresExportRepository(db)

	mock.ExpectQuery(regexp.QuoteMeta("FROM audit_logs")).
		WithArgs("regbank-india", nil, nil).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "timestamp", "decision_type", "policy_decision",
			"model_id", "policies_evaluated", "policy_triggered", "response_time_ms",
			"correlation_id",
		}))

	if _, err := repo.GetDecisionChain(context.Background(), "regbank-india", time.Time{}, time.Time{}); err != nil {
		t.Fatalf("GetDecisionChain: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestGroupDecisionChain_ThreeStageRequestIsOneChain is the #2598 red-on-revert
// guard: a 3-stage logical request (llm → tool → agent) whose rows share one
// correlation_id must export as exactly ONE chain with three steps in step order,
// while rows without a correlation_id remain singletons in chronological order.
// If grouping is removed (or keys off the per-row id instead of correlation_id)
// the 3-stage chain shatters into singletons and this fails.
func TestGroupDecisionChain_ThreeStageRequestIsOneChain(t *testing.T) {
	base := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	// Chronological input (as the SQL ORDER BY timestamp,id produces). The trace
	// "req-trace" has its three stages interleaved in time with an unrelated
	// single-shot decision and a second logical request.
	records := []DecisionChainRecord{
		{ID: "decide_a1", RequestID: "r1", Timestamp: base, DecisionType: "llm", CorrelationID: "req-trace"},
		{ID: "decide_z1", RequestID: "rz", Timestamp: base.Add(1 * time.Second), DecisionType: "tool"}, // legacy: no correlation
		{ID: "decide_a2", RequestID: "r2", Timestamp: base.Add(2 * time.Second), DecisionType: "tool", CorrelationID: "req-trace"},
		{ID: "decide_b1", RequestID: "rb", Timestamp: base.Add(3 * time.Second), DecisionType: "llm", CorrelationID: "other-trace"},
		{ID: "decide_a3", RequestID: "r3", Timestamp: base.Add(4 * time.Second), DecisionType: "agent", CorrelationID: "req-trace"},
	}

	groups := groupDecisionChain(records)

	// 3 chains: req-trace (3 steps), the legacy singleton, other-trace (1 step).
	if len(groups) != 3 {
		t.Fatalf("want 3 chains, got %d", len(groups))
	}
	// Group order is chronological by each chain's earliest step.
	if groups[0].CorrelationID != "req-trace" {
		t.Fatalf("chain0: want req-trace (earliest step @ base), got %q", groups[0].CorrelationID)
	}
	g := groups[0]
	if g.StepCount != 3 || len(g.Steps) != 3 {
		t.Fatalf("req-trace chain: want 3 steps, got StepCount=%d len=%d", g.StepCount, len(g.Steps))
	}
	// Steps in step (chronological) order: llm → tool → agent.
	if g.Steps[0].ID != "decide_a1" || g.Steps[1].ID != "decide_a2" || g.Steps[2].ID != "decide_a3" {
		t.Errorf("req-trace steps out of order: %s, %s, %s", g.Steps[0].ID, g.Steps[1].ID, g.Steps[2].ID)
	}
	if !g.StartedAt.Equal(base) || !g.EndedAt.Equal(base.Add(4*time.Second)) {
		t.Errorf("req-trace span: want [%v,%v], got [%v,%v]", base, base.Add(4*time.Second), g.StartedAt, g.EndedAt)
	}

	// The legacy (no-correlation) row is its OWN singleton — not merged with the
	// other empty-correlation rows (there is only one here, but the key must be
	// per-row, not the shared "").
	if groups[1].CorrelationID != "" || groups[1].StepCount != 1 || groups[1].Steps[0].ID != "decide_z1" {
		t.Errorf("chain1: want singleton legacy row decide_z1, got %+v", groups[1])
	}
	if groups[2].CorrelationID != "other-trace" || groups[2].StepCount != 1 {
		t.Errorf("chain2: want other-trace singleton, got %+v", groups[2])
	}
}

// TestGroupDecisionChain_LegacyRowsAreSeparateSingletons proves multiple
// correlation-less (legacy) rows do NOT collapse into one giant "" chain.
func TestGroupDecisionChain_LegacyRowsAreSeparateSingletons(t *testing.T) {
	base := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	records := []DecisionChainRecord{
		{ID: "d1", Timestamp: base},
		{ID: "d2", Timestamp: base.Add(time.Second)},
		{ID: "d3", Timestamp: base.Add(2 * time.Second)},
	}
	groups := groupDecisionChain(records)
	if len(groups) != 3 {
		t.Fatalf("legacy rows must each be a singleton chain: want 3, got %d", len(groups))
	}
	for i, g := range groups {
		if g.StepCount != 1 || g.CorrelationID != "" {
			t.Errorf("group %d: want singleton with empty correlation, got %+v", i, g)
		}
	}
}
