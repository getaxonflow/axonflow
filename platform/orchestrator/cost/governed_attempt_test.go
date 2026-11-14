// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPostgresGovernedModelAttemptJournal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)
	attempt := &GovernedModelAttempt{RequestID: "req-1", OrgID: "org-a", TenantID: "tenant-a",
		TraceID: "trace-a", Module: "payment_exception", CaseID: "case-a",
		EvidenceVersion: "evidence-a", InvestigationKey: "investigation-a"}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs("tenant-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id', \$1, true\)`).
		WithArgs("tenant-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO governed_model_attempts`).
		WithArgs("req-1", "org-a", "tenant-a", "trace-a", "payment_exception", "case-a",
			"evidence-a", "investigation-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := repo.BeginGovernedModelAttempt(context.Background(), attempt); err != nil {
		t.Fatalf("begin attempt: %v", err)
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs("tenant-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id', \$1, true\)`).
		WithArgs("tenant-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE governed_model_attempts`).
		WithArgs("outcome_unknown", "null", "null", "truncated", "org-a", "tenant-a", "req-1").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	attempt.Status = "outcome_unknown"
	attempt.Error = "truncated"
	if err := repo.FinishGovernedModelAttempt(context.Background(), attempt); err != nil {
		t.Fatalf("finish attempt: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresGovernedModelAttemptJournalReadinessIsScopedAndReadOnly(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs("tenant-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id', \$1, true\)`).
		WithArgs("tenant-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs("org-a", "tenant-a").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectCommit()
	if err := repo.CheckGovernedModelAttemptJournal(context.Background(), "org-a", "tenant-a"); err != nil {
		t.Fatalf("journal readiness: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresGovernedModelAttemptStatusReconcilesStaleForwarding(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)
	created := time.Date(2026, 11, 9, 18, 0, 0, 0, time.UTC)
	updated := created.Add(31 * time.Second)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs("tenant-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id', \$1, true\)`).
		WithArgs("tenant-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE governed_model_attempts`).
		WithArgs("org-a", "tenant-a", "req-1", float64(30)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT request_id,org_id,tenant_id,trace_id,module,case_id,evidence_version,investigation_key`).
		WithArgs("org-a", "tenant-a", "req-1").
		WillReturnRows(sqlmock.NewRows([]string{"request_id", "org_id", "tenant_id", "trace_id", "module",
			"case_id", "evidence_version", "investigation_key", "status", "provider_info", "usage_receipt",
			"error_text", "created_at", "updated_at"}).AddRow(
			"req-1", "org-a", "tenant-a", "trace-a", "payment_exception", "case-a", "evidence-a",
			"investigation-a", "outcome_unknown", []byte(`{}`),
			[]byte(`{"attempted":true,"recorded":false,"request_id":"req-1","status":"outcome_unknown"}`),
			"stale forwarding intent reconciled", created, updated))
	mock.ExpectCommit()

	attempt, err := repo.GetGovernedModelAttempt(context.Background(), "org-a", "tenant-a", "req-1", 30*time.Second)
	if err != nil {
		t.Fatalf("get attempt: %v", err)
	}
	if attempt.Status != "outcome_unknown" || attempt.UsageReceipt["recorded"] != false ||
		attempt.OrgID != "org-a" || attempt.TenantID != "tenant-a" {
		t.Fatalf("unexpected reconciled attempt: %#v", attempt)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresGovernedModelAttemptRejectsDuplicateIntent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)
	attempt := &GovernedModelAttempt{RequestID: "req-1", OrgID: "org-a", TenantID: "tenant-a",
		TraceID: "trace-a", Module: "payment_exception", CaseID: "case-a",
		EvidenceVersion: "evidence-a", InvestigationKey: "investigation-a"}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs("tenant-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id', \$1, true\)`).
		WithArgs("tenant-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO governed_model_attempts`).
		WithArgs("req-1", "org-a", "tenant-a", "trace-a", "payment_exception", "case-a",
			"evidence-a", "investigation-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()
	if err := repo.BeginGovernedModelAttempt(context.Background(), attempt); err == nil {
		t.Fatal("duplicate attempt intent must fail closed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
