// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axonflow/platform/shared/audit"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
)

// =============================================================================
// #2636/#2653 — /decisions filter consumes the canonical vocabulary.
// =============================================================================

// TestListDecisions_AcceptsNeedsApprovalCanonical proves the canonical
// "needs_approval" verdict is now an accepted filter (the old
// allow/deny/require_approval allowlist 400'd it) and that it is expanded to
// every DB spelling it covers (audit.Spellings) for the SQL predicate.
func TestListDecisions_AcceptsNeedsApprovalCanonical(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	mock.ExpectQuery(`FROM audit_logs[\s\S]*?WHERE tenant_id = \$1`).
		WithArgs(
			"tenant-a",
			sqlmock.AnyArg(),
			pq.Array(audit.Spellings(audit.DecisionNeedsApproval)),
			"", "",
			"", // #2922 scope user_email (empty = tenant-wide)
			5,
		).
		WillReturnRows(sqlmock.NewRows(
			[]string{"decision_id", "timestamp", "decision", "policy_id", "tool_signature", "context", "transfer_basis", "data_residency"},
		))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions?decision=needs_approval", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for canonical needs_approval filter, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// TestListDecisions_RejectsPhantomRequireApproval proves the legacy phantom
// "require_approval" (no row carries it; it normalizes to needs_approval) is now
// rejected with a 400 — the filter accepts canonical values only.
func TestListDecisions_RejectsPhantomRequireApproval(t *testing.T) {
	for _, phantom := range []string{"require_approval", "allow", "deny", "logged", "modified"} {
		t.Run(phantom, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions?decision="+phantom, nil)
			req.Header.Set("X-Tenant-ID", "tenant-a")
			w := httptest.NewRecorder()
			listDecisionsHandler(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for phantom filter %q, got %d", phantom, w.Code)
			}
		})
	}
}

// TestListDecisions_NormalizesLegacyDecisionOnRead proves a legacy row value is
// surfaced as the canonical verdict in the response body.
func TestListDecisions_NormalizesLegacyDecisionOnRead(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	mock.ExpectQuery(`FROM audit_logs[\s\S]*?WHERE tenant_id = \$1`).
		WillReturnRows(sqlmock.NewRows(
			[]string{"decision_id", "timestamp", "decision", "policy_id", "tool_signature", "context", "transfer_basis", "data_residency"},
		).
			AddRow("d1", time.Now().UTC(), "deny", "p", "", nil, "", "").
			AddRow("d2", time.Now().UTC(), "require_approval", "p", "", nil, "", "").
			AddRow("d3", time.Now().UTC(), "allowed", "p", "", nil, "", ""))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body DecisionListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{audit.DecisionBlocked, audit.DecisionNeedsApproval, audit.DecisionAllowed}
	if len(body.Decisions) != len(want) {
		t.Fatalf("got %d decisions, want %d", len(body.Decisions), len(want))
	}
	for i, wantVal := range want {
		if body.Decisions[i].Decision != wantVal {
			t.Errorf("decisions[%d].decision = %q, want %q", i, body.Decisions[i].Decision, wantVal)
		}
	}
}

// TestListDecisions_DropsOverrideLifecycleRow proves the verdict-centric feed
// never surfaces a non-verdict override-lifecycle row even if a future writer
// attaches a decision_id to it (today none do, so the WHERE clause already
// excludes them — this is the defensive read-side guard for the
// "feed emits only audit.All()" contract).
func TestListDecisions_DropsOverrideLifecycleRow(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	mock.ExpectQuery(`FROM audit_logs[\s\S]*?WHERE tenant_id = \$1`).
		WillReturnRows(sqlmock.NewRows(
			[]string{"decision_id", "timestamp", "decision", "policy_id", "tool_signature", "context", "transfer_basis", "data_residency"},
		).
			AddRow("d-allow", time.Now().UTC(), "allowed", "p", "", nil, "", "").
			AddRow("d-ovr", time.Now().UTC(), "override_lifecycle", "p", "", nil, "", ""))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body DecisionListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Decisions) != 1 || body.Decisions[0].DecisionID != "d-allow" {
		t.Fatalf("expected only the verdict row to surface (override_lifecycle dropped), got %+v", body.Decisions)
	}
	for _, d := range body.Decisions {
		if d.Decision == audit.DecisionOverrideLifecycle {
			t.Errorf("non-verdict override_lifecycle leaked into the feed: %+v", d)
		}
	}
}

// =============================================================================
// #2636/#2653 — audit summary buckets every canonical value; override_lifecycle
// is routed out of the verdict triage (not bucketed as a verdict).
// =============================================================================

// TestAuditSummary_OverrideLifecycleRoutedOut proves an override grant/revoke
// lifecycle row is counted in total_events / by_action but NEVER bucketed as a
// verdict — it is excluded from total_requests and the block-rate so it cannot
// move a compliance metric.
func TestAuditSummary_OverrideLifecycleRoutedOut(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	handler := NewAuditSummaryHandler(db)

	mock.ExpectQuery("SELECT request_type, policy_decision, COUNT").
		WithArgs("org-x", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"request_type", "policy_decision", "cnt"}).
			AddRow("llm_call", "allowed", 8).
			AddRow("llm_call", "blocked", 2).
			AddRow("override_grant", "override_lifecycle", 5))
	mock.ExpectQuery("SELECT COALESCE\\(AVG\\(response_time_ms\\)").
		WithArgs("org-x", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"avg"}).AddRow(0.0))
	mock.ExpectQuery("SELECT").
		WithArgs("org-x", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"policy_name", "trigger_count", "block_count"}))

	body := `{"start_time":"2026-04-22T00:00:00Z","end_time":"2026-04-23T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "org-x")
	rr := httptest.NewRecorder()
	handler.HandleSummary(rr, req)

	var summary ComplianceSummary
	if err := json.NewDecoder(rr.Body).Decode(&summary); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// total_events counts ALL rows (verdicts + override lifecycle).
	if summary.TotalEvents != 15 {
		t.Errorf("total_events = %d, want 15 (all rows)", summary.TotalEvents)
	}
	// total_requests counts only the 10 verdict rows — the 5 override events are
	// routed out.
	if summary.TotalRequests != 10 {
		t.Errorf("total_requests = %d, want 10 (override_lifecycle excluded)", summary.TotalRequests)
	}
	if summary.AllowedRequests != 8 || summary.BlockedRequests != 2 {
		t.Errorf("allowed=%d blocked=%d, want 8/2", summary.AllowedRequests, summary.BlockedRequests)
	}
	// by_action still records the override events.
	if summary.ByAction["override_grant"] != 5 {
		t.Errorf("by_action[override_grant] = %d, want 5", summary.ByAction["override_grant"])
	}
	// block-rate is over the verdict total (10), not all events (15).
	if summary.BlockRatePercent != 20.0 {
		t.Errorf("block_rate_percent = %f, want 20.0 (2/10, override excluded)", summary.BlockRatePercent)
	}
}

// TestAuditSummary_UnknownVerdictFailsSafeToError proves an unrecognized
// policy_decision is bucketed as error (the Normalize fail-safe), NEVER swept
// into allowed by a default arm (the #2636 metric-corruption bug).
func TestAuditSummary_UnknownVerdictFailsSafeToError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	handler := NewAuditSummaryHandler(db)

	mock.ExpectQuery("SELECT request_type, policy_decision, COUNT").
		WithArgs("org-y", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"request_type", "policy_decision", "cnt"}).
			AddRow("llm_call", "allowed", 3).
			AddRow("llm_call", "some_future_verdict", 7))
	mock.ExpectQuery("SELECT COALESCE\\(AVG\\(response_time_ms\\)").
		WithArgs("org-y", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"avg"}).AddRow(0.0))
	mock.ExpectQuery("SELECT").
		WithArgs("org-y", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"policy_name", "trigger_count", "block_count"}))

	body := `{"start_time":"2026-04-22T00:00:00Z","end_time":"2026-04-23T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/summary", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "org-y")
	rr := httptest.NewRecorder()
	handler.HandleSummary(rr, req)

	var summary ComplianceSummary
	if err := json.NewDecoder(rr.Body).Decode(&summary); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if summary.AllowedRequests != 3 {
		t.Errorf("allowed_requests = %d, want 3 (unknown NOT counted as allowed)", summary.AllowedRequests)
	}
	if summary.ErrorRequests != 7 {
		t.Errorf("error_requests = %d, want 7 (unknown fails safe to error)", summary.ErrorRequests)
	}
}
