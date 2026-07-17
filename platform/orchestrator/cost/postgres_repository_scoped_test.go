// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// #2934: the org/tenant isolation lives in the SQL WHERE clause, never as a
// post-fetch comparison — these tests pin the WHERE shape and the arg wiring.

func TestPostgresRepository_GetBudgetScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)

	rows := sqlmock.NewRows([]string{
		"id", "name", "description", "scope", "scope_id", "limit_usd", "period",
		"on_exceed", "alert_thresholds", "enabled", "org_id", "tenant_id",
		"created_by", "updated_by", "created_at", "updated_at",
	}).AddRow("b1", "Budget", "", "organization", "org-a", 100.0, "monthly",
		"warn", []byte("[50,80,100]"), true, "org-a", "tenant-a", "", "", time.Now(), time.Now())

	mock.ExpectQuery(`SELECT id, name, description, scope, scope_id, limit_usd, period,\s+on_exceed, alert_thresholds, enabled, org_id, tenant_id,\s+created_by, updated_by, created_at, updated_at\s+FROM budgets\s+WHERE id = \$1\s+AND \(\$2 = '' OR org_id IS NULL OR org_id = '' OR org_id = \$2\)\s+AND \(\$3 = '' OR tenant_id IS NULL OR tenant_id = '' OR tenant_id = \$3\)`).
		WithArgs("b1", "org-a", "tenant-a").
		WillReturnRows(rows)

	budget, err := repo.GetBudgetScoped(context.Background(), "b1", "org-a", "tenant-a")
	if err != nil {
		t.Fatalf("GetBudgetScoped failed: %v", err)
	}
	if budget.ID != "b1" || budget.OrgID != "org-a" {
		t.Fatalf("unexpected budget %+v", budget)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresRepository_GetBudgetScoped_CrossOrgNoRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)

	mock.ExpectQuery(`FROM budgets\s+WHERE id = \$1`).
		WithArgs("b1", "org-b", "").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	if _, err := repo.GetBudgetScoped(context.Background(), "b1", "org-b", ""); err != ErrBudgetNotFound {
		t.Fatalf("cross-org scoped get must be ErrBudgetNotFound, got %v", err)
	}
}

func TestPostgresRepository_DeleteBudgetScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)

	mock.ExpectExec(`DELETE FROM budgets WHERE id = \$1\s+AND \(\$2 = '' OR org_id IS NULL OR org_id = '' OR org_id = \$2\)\s+AND \(\$3 = '' OR tenant_id IS NULL OR tenant_id = '' OR tenant_id = \$3\)`).
		WithArgs("b1", "org-a", "tenant-a").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.DeleteBudgetScoped(context.Background(), "b1", "org-a", "tenant-a"); err != nil {
		t.Fatalf("DeleteBudgetScoped failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresRepository_DeleteBudgetScoped_CrossOrgZeroRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)

	mock.ExpectExec(`DELETE FROM budgets WHERE id = \$1`).
		WithArgs("b1", "org-b", "").
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := repo.DeleteBudgetScoped(context.Background(), "b1", "org-b", ""); err != ErrBudgetNotFound {
		t.Fatalf("cross-org scoped delete must be ErrBudgetNotFound, got %v", err)
	}
}
