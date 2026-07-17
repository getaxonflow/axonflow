// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// #2934: org/tenant isolation of the by-id replay routes. The cross-org IDOR
// and cross-org DELETE are the cases that motivated the change; the same-org
// controls keep the assertions non-vacuous.

func seedOrgExecution(repo *MockRepository, requestID, orgID string) {
	repo.AddSummary(&ExecutionSummary{
		RequestID: requestID,
		Status:    ExecutionStatusCompleted,
		StartedAt: time.Now(),
		OrgID:     orgID,
		TenantID:  "tenant-" + orgID,
	})
	repo.AddSnapshot(&ExecutionSnapshot{
		RequestID: requestID,
		StepIndex: 0,
		StepName:  "step-1",
		Status:    StepStatusCompleted,
		StartedAt: time.Now(),
	})
}

func TestService_ScopedReads_CrossOrgIsNotFound(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()
	service := NewServiceWithLogger(repo, log.New(io.Discard, "", 0))
	seedOrgExecution(repo, "req-a", "org-a")

	other := AccessScope{OrgID: "org-b", TenantID: "tenant-org-b"}
	own := AccessScope{OrgID: "org-a", TenantID: "tenant-org-a"}

	if _, err := service.GetExecution(ctx, "req-a", other); err != ErrNotFound {
		t.Fatalf("cross-org GetExecution must be ErrNotFound, got %v", err)
	}
	if _, err := service.GetSteps(ctx, "req-a", other); err != ErrNotFound {
		t.Fatalf("cross-org GetSteps must be ErrNotFound, got %v", err)
	}
	if _, err := service.GetStep(ctx, "req-a", 0, other); err != ErrNotFound {
		t.Fatalf("cross-org GetStep must be ErrNotFound, got %v", err)
	}
	if _, err := service.GetTimeline(ctx, "req-a", other); err != ErrNotFound {
		t.Fatalf("cross-org GetTimeline must be ErrNotFound, got %v", err)
	}
	if _, err := service.ExportExecution(ctx, "req-a", ExportOptions{}, other); err != ErrNotFound {
		t.Fatalf("cross-org ExportExecution must be ErrNotFound, got %v", err)
	}
	if err := service.DeleteExecution(ctx, "req-a", other); err != ErrNotFound {
		t.Fatalf("cross-org DeleteExecution must be ErrNotFound, got %v", err)
	}
	if repo.GetSummaryCount() != 1 {
		t.Fatal("cross-org delete must not remove the execution")
	}

	// Controls (non-vacuous): the owning org reads and deletes normally.
	if _, err := service.GetExecution(ctx, "req-a", own); err != nil {
		t.Fatalf("same-org GetExecution must succeed: %v", err)
	}
	// Empty scope (single-tenant Community) is unfiltered.
	if _, err := service.GetExecution(ctx, "req-a", AccessScope{}); err != nil {
		t.Fatalf("empty-scope GetExecution must succeed: %v", err)
	}
	if err := service.DeleteExecution(ctx, "req-a", own); err != nil {
		t.Fatalf("same-org DeleteExecution must succeed: %v", err)
	}
	if repo.GetSummaryCount() != 0 {
		t.Fatal("same-org delete must remove the execution")
	}
}

func TestHandler_ByIDRoutes_CrossOrgIsNotFound(t *testing.T) {
	h, repo := newTestHandler()
	r := setupRouter(h)
	seedOrgExecution(repo, "req-a", "org-a")

	paths := []struct {
		method, path string
	}{
		{"GET", "/api/v1/executions/req-a"},
		{"GET", "/api/v1/executions/req-a/steps"},
		{"GET", "/api/v1/executions/req-a/steps/0"},
		{"GET", "/api/v1/executions/req-a/timeline"},
		{"GET", "/api/v1/executions/req-a/export"},
		{"DELETE", "/api/v1/executions/req-a"},
	}

	for _, p := range paths {
		req := httptest.NewRequest(p.method, p.path, nil)
		req.Header.Set("X-Org-ID", "org-b")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("cross-org %s %s must be 404, got %d", p.method, p.path, w.Code)
		}
	}
	if repo.GetSummaryCount() != 1 {
		t.Fatal("cross-org DELETE must not remove the execution")
	}

	// Control: the owning org reads all of them.
	for _, p := range paths[:5] {
		req := httptest.NewRequest(p.method, p.path, nil)
		req.Header.Set("X-Org-ID", "org-a")
		req.Header.Set("X-Tenant-ID", "tenant-org-a")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("same-org %s %s must be 200, got %d", p.method, p.path, w.Code)
		}
	}
}

// SQL-shape tests: the isolation is the WHERE clause, never post-fetch.

func TestPostgresRepository_GetSummaryScoped_SQL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)

	mock.ExpectQuery(`FROM execution_summaries\s+WHERE request_id = \$1\s+AND \(\$2 = '' OR org_id IS NULL OR org_id = '' OR org_id = \$2\)\s+AND \(\$3 = '' OR tenant_id IS NULL OR tenant_id = '' OR tenant_id = \$3\)`).
		WithArgs("req-a", "org-b", "tenant-b").
		WillReturnRows(sqlmock.NewRows([]string{"request_id"}))

	if _, err := repo.GetSummaryScoped(context.Background(), "req-a", AccessScope{OrgID: "org-b", TenantID: "tenant-b"}); err != ErrNotFound {
		t.Fatalf("scoped miss must be ErrNotFound, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresRepository_GetSummaryScoped_SameOrgRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)

	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"request_id", "workflow_name", "status", "total_steps", "completed_steps",
		"started_at", "completed_at", "duration_ms",
		"total_tokens", "total_cost_usd",
		"org_id", "tenant_id", "user_id", "agent_id",
		"input_summary", "output_summary", "error_message",
		"created_at", "updated_at",
	}).AddRow("req-a", "wf", "completed", 2, 2, now, now, 120, 500, 1.25,
		"org-a", "tenant-a", "42", "agent-1", []byte(`{"q":"in"}`), []byte(`{"a":"out"}`), "boom", now, now)

	mock.ExpectQuery(`FROM execution_summaries\s+WHERE request_id = \$1`).
		WithArgs("req-a", "org-a", "tenant-a").
		WillReturnRows(rows)

	summary, err := repo.GetSummaryScoped(context.Background(), "req-a", AccessScope{OrgID: "org-a", TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("GetSummaryScoped failed: %v", err)
	}
	if summary.OrgID != "org-a" || summary.UserID != "42" || summary.WorkflowName != "wf" ||
		summary.ErrorMessage != "boom" || summary.DurationMs == nil || summary.CompletedAt == nil {
		t.Fatalf("unexpected summary %+v", summary)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestNoOpRepository_ScopedMethodsFailClosed(t *testing.T) {
	repo := &NoOpRepository{}
	if _, err := repo.GetSummaryScoped(context.Background(), "req", AccessScope{}); err != ErrNotFound {
		t.Fatalf("NoOp GetSummaryScoped must be ErrNotFound, got %v", err)
	}
	if err := repo.DeleteExecutionScoped(context.Background(), "req", AccessScope{}); err != ErrNotFound {
		t.Fatalf("NoOp DeleteExecutionScoped must be ErrNotFound, got %v", err)
	}
}

func TestPostgresRepository_DeleteExecutionScoped_CrossOrgRollsBack(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)

	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM execution_summaries WHERE request_id = \$1`).
		WithArgs("req-a", "org-b", "").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	if err := repo.DeleteExecutionScoped(context.Background(), "req-a", AccessScope{OrgID: "org-b"}); err != ErrNotFound {
		t.Fatalf("cross-org scoped delete must be ErrNotFound, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (snapshots must NOT be deleted): %v", err)
	}
}

func TestPostgresRepository_DeleteExecutionScoped_SnapshotDeleteFailureRollsBack(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)

	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM execution_summaries WHERE request_id = \$1`).
		WithArgs("req-a", "org-a", "").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM execution_snapshots WHERE request_id = \$1`).
		WithArgs("req-a").
		WillReturnError(context.DeadlineExceeded)
	mock.ExpectRollback()

	if err := repo.DeleteExecutionScoped(context.Background(), "req-a", AccessScope{OrgID: "org-a"}); err == nil {
		t.Fatal("snapshot-delete failure must surface an error (and roll back the summary delete)")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresRepository_DeleteExecutionScoped_CommitFailureSurfaces(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)

	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM execution_summaries WHERE request_id = \$1`).
		WithArgs("req-a", "", "").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM execution_snapshots WHERE request_id = \$1`).
		WithArgs("req-a").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit().WillReturnError(context.DeadlineExceeded)

	if err := repo.DeleteExecutionScoped(context.Background(), "req-a", AccessScope{}); err == nil {
		t.Fatal("commit failure must surface an error")
	}
}

func TestPostgresRepository_DeleteExecutionScoped_SameOrgDeletesBoth(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)

	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM execution_summaries WHERE request_id = \$1`).
		WithArgs("req-a", "org-a", "tenant-a").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM execution_snapshots WHERE request_id = \$1`).
		WithArgs("req-a").
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectCommit()

	if err := repo.DeleteExecutionScoped(context.Background(), "req-a", AccessScope{OrgID: "org-a", TenantID: "tenant-a"}); err != nil {
		t.Fatalf("same-org scoped delete failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
