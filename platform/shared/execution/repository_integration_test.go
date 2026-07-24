// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPostgresRepository_Create(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()
	now := time.Now()

	exec := &ExecutionStatus{
		ExecutionID:      "plan_abc123",
		ExecutionType:    ExecutionTypeMAP,
		Name:             "Test Plan",
		Source:           "",
		Status:           StatusPending,
		CurrentStepIndex: 0,
		TotalSteps:       3,
		StartedAt:        now,
		TenantID:         "tenant-1",
		OrgID:            "org-1",
		UserID:           "user-1",
		ClientID:         "client-1",
		Steps:            []StepStatus{},
		Metadata:         map[string]interface{}{"key": "value"},
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	// v9 Phase 8 #2384 PR-C1: WithOrgAndTenantScope wraps Create in
	// BEGIN/set_config×3/EXEC/COMMIT.
	expectScopedTxn := func() {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.current_tenant_id', \\$1, true\\)").WithArgs("tenant-1").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.tenant_id', \\$1, true\\)").WithArgs("tenant-1").WillReturnResult(sqlmock.NewResult(0, 0))
	}

	t.Run("successful create", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("INSERT INTO execution_history").
			WithArgs(
				exec.ExecutionID, exec.ExecutionType, exec.ExecutionID, exec.Name, exec.Source,
				sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
				exec.Status, exec.CurrentStepIndex, exec.TotalSteps,
				exec.StartedAt, exec.EstimatedCostUSD, exec.ActualCostUSD,
				sqlmock.AnyArg(), sqlmock.AnyArg(), exec.CreatedAt, exec.UpdatedAt,
			).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		err := repo.Create(ctx, exec)
		if err != nil {
			t.Errorf("Create() error = %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("INSERT INTO execution_history").
			WillReturnError(errors.New("connection refused"))
		mock.ExpectRollback()

		err := repo.Create(ctx, exec)
		if err == nil {
			t.Error("expected error")
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("nil execution", func(t *testing.T) {
		err := repo.Create(ctx, nil)
		if err != ErrInvalidExecution {
			t.Errorf("Create(nil) error = %v, want %v", err, ErrInvalidExecution)
		}
	})
}

func TestPostgresRepository_Get(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()
	now := time.Now()

	columns := []string{
		"id", "execution_type", "name", "source",
		"tenant_id", "org_id", "user_id", "client_id",
		"status", "current_step_index", "total_steps",
		"started_at", "completed_at", "estimated_cost_usd", "actual_cost_usd",
		"steps", "error_message", "metadata", "created_at", "updated_at",
	}

	stepsJSON, _ := json.Marshal([]StepStatus{})
	metadataJSON, _ := json.Marshal(map[string]interface{}{})

	t.Run("successful get", func(t *testing.T) {
		mock.ExpectQuery("SELECT .* FROM execution_history").
			WithArgs("plan_abc123").
			WillReturnRows(sqlmock.NewRows(columns).AddRow(
				"plan_abc123", "map_plan", "Test Plan", "",
				"tenant-1", "org-1", "user-1", "client-1",
				"pending", 0, 3,
				now, nil, nil, nil,
				stepsJSON, nil, metadataJSON, now, now,
			))

		exec, err := repo.Get(ctx, "plan_abc123")
		if err != nil {
			t.Errorf("Get() error = %v", err)
		}
		if exec.ExecutionID != "plan_abc123" {
			t.Errorf("ExecutionID = %v, want plan_abc123", exec.ExecutionID)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("with completed execution", func(t *testing.T) {
		completedAt := now.Add(5 * time.Minute)
		estimatedCost := 0.05
		actualCost := 0.03

		mock.ExpectQuery("SELECT .* FROM execution_history").
			WithArgs("plan_completed").
			WillReturnRows(sqlmock.NewRows(columns).AddRow(
				"plan_completed", "map_plan", "Completed Plan", "",
				"tenant-1", "org-1", "user-1", "client-1",
				"completed", 3, 3,
				now, completedAt, estimatedCost, actualCost,
				stepsJSON, nil, metadataJSON, now, now,
			))

		exec, err := repo.Get(ctx, "plan_completed")
		if err != nil {
			t.Errorf("Get() error = %v", err)
		}
		if exec.CompletedAt == nil {
			t.Error("CompletedAt should be set")
		}
		if exec.EstimatedCostUSD == nil || *exec.EstimatedCostUSD != estimatedCost {
			t.Errorf("EstimatedCostUSD = %v, want %v", exec.EstimatedCostUSD, estimatedCost)
		}
		if exec.ActualCostUSD == nil || *exec.ActualCostUSD != actualCost {
			t.Errorf("ActualCostUSD = %v, want %v", exec.ActualCostUSD, actualCost)
		}
	})

	t.Run("with error message", func(t *testing.T) {
		mock.ExpectQuery("SELECT .* FROM execution_history").
			WithArgs("plan_failed").
			WillReturnRows(sqlmock.NewRows(columns).AddRow(
				"plan_failed", "map_plan", "Failed Plan", "",
				nil, nil, nil, nil,
				"failed", 1, 3,
				now, nil, nil, nil,
				stepsJSON, "step 2 failed", metadataJSON, now, now,
			))

		exec, err := repo.Get(ctx, "plan_failed")
		if err != nil {
			t.Errorf("Get() error = %v", err)
		}
		if exec.Error != "step 2 failed" {
			t.Errorf("Error = %v, want 'step 2 failed'", exec.Error)
		}
	})

	t.Run("not found", func(t *testing.T) {
		mock.ExpectQuery("SELECT .* FROM execution_history").
			WithArgs("nonexistent").
			WillReturnError(sql.ErrNoRows)

		_, err := repo.Get(ctx, "nonexistent")
		if !errors.Is(err, ErrExecutionNotFound) {
			t.Errorf("Get() error = %v, want ErrExecutionNotFound", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery("SELECT .* FROM execution_history").
			WithArgs("plan_abc123").
			WillReturnError(errors.New("connection refused"))

		_, err := repo.Get(ctx, "plan_abc123")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestPostgresRepository_Update(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()
	now := time.Now()

	exec := &ExecutionStatus{
		ExecutionID:      "plan_abc123",
		ExecutionType:    ExecutionTypeMAP,
		Name:             "Test Plan",
		Status:           StatusRunning,
		CurrentStepIndex: 1,
		TotalSteps:       3,
		Steps:            []StepStatus{},
		Metadata:         map[string]interface{}{},
		UpdatedAt:        now,
		// v9 Phase 8 #2384 PR-C1: Update requires OrgID + TenantID populated
		// so WithOrgAndTenantScope can pin app.current_{org,tenant}_id for
		// the wrapped UPDATE.
		OrgID:    "test-org",
		TenantID: "test-tenant",
	}

	expectScopedTxn := func() {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("test-org").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.current_tenant_id', \\$1, true\\)").WithArgs("test-tenant").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.tenant_id', \\$1, true\\)").WithArgs("test-tenant").WillReturnResult(sqlmock.NewResult(0, 0))
	}

	t.Run("successful update", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WithArgs(
				exec.ExecutionID,
				exec.Status,
				exec.CurrentStepIndex,
				exec.TotalSteps,
				exec.CompletedAt,
				exec.EstimatedCostUSD,
				exec.ActualCostUSD,
				sqlmock.AnyArg(), // steps JSON
				sqlmock.AnyArg(), // error
				sqlmock.AnyArg(), // metadata JSON
				exec.UpdatedAt,
			).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		err := repo.Update(ctx, exec)
		if err != nil {
			t.Errorf("Update() error = %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectCommit()

		err := repo.Update(ctx, exec)
		if !errors.Is(err, ErrExecutionNotFound) {
			t.Errorf("Update() error = %v, want ErrExecutionNotFound", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WillReturnError(errors.New("connection refused"))
		mock.ExpectRollback()

		err := repo.Update(ctx, exec)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("nil execution", func(t *testing.T) {
		err := repo.Update(ctx, nil)
		if err != ErrInvalidExecution {
			t.Errorf("Update(nil) error = %v, want %v", err, ErrInvalidExecution)
		}
	})
}

func TestPostgresRepository_List(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()
	now := time.Now()

	columns := []string{
		"id", "execution_type", "name", "source",
		"tenant_id", "org_id", "user_id", "client_id",
		"status", "current_step_index", "total_steps",
		"started_at", "completed_at", "estimated_cost_usd", "actual_cost_usd",
		"steps", "error_message", "metadata", "created_at", "updated_at",
	}

	stepsJSON, _ := json.Marshal([]StepStatus{})
	metadataJSON, _ := json.Marshal(map[string]interface{}{})

	t.Run("list all", func(t *testing.T) {
		// Count query
		mock.ExpectQuery("SELECT COUNT\\(\\*\\)").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

		// Select query
		mock.ExpectQuery("SELECT .* FROM execution_history").
			WillReturnRows(sqlmock.NewRows(columns).
				AddRow("plan_1", "map_plan", "Plan 1", "", "tenant-1", nil, nil, nil, "pending", 0, 3, now, nil, nil, nil, stepsJSON, nil, metadataJSON, now, now).
				AddRow("plan_2", "map_plan", "Plan 2", "", "tenant-1", nil, nil, nil, "running", 1, 3, now, nil, nil, nil, stepsJSON, nil, metadataJSON, now, now))

		results, total, err := repo.List(ctx, ListExecutionsRequest{Limit: 10})
		if err != nil {
			t.Errorf("List() error = %v", err)
		}
		if len(results) != 2 {
			t.Errorf("len(results) = %v, want 2", len(results))
		}
		if total != 2 {
			t.Errorf("total = %v, want 2", total)
		}
	})

	t.Run("filter by type", func(t *testing.T) {
		mapType := ExecutionTypeMAP

		mock.ExpectQuery("SELECT COUNT\\(\\*\\)").
			WithArgs(mapType).
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

		mock.ExpectQuery("SELECT .* FROM execution_history").
			WithArgs(mapType, 10).
			WillReturnRows(sqlmock.NewRows(columns).
				AddRow("plan_1", "map_plan", "Plan 1", "", nil, nil, nil, nil, "pending", 0, 3, now, nil, nil, nil, stepsJSON, nil, metadataJSON, now, now))

		results, _, err := repo.List(ctx, ListExecutionsRequest{ExecutionType: &mapType, Limit: 10})
		if err != nil {
			t.Errorf("List() error = %v", err)
		}
		if len(results) != 1 {
			t.Errorf("len(results) = %v, want 1", len(results))
		}
	})

	t.Run("filter by status", func(t *testing.T) {
		status := StatusPending

		mock.ExpectQuery("SELECT COUNT\\(\\*\\)").
			WithArgs(status).
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

		mock.ExpectQuery("SELECT .* FROM execution_history").
			WithArgs(status, 10).
			WillReturnRows(sqlmock.NewRows(columns).
				AddRow("plan_1", "map_plan", "Plan 1", "", nil, nil, nil, nil, "pending", 0, 3, now, nil, nil, nil, stepsJSON, nil, metadataJSON, now, now))

		results, _, err := repo.List(ctx, ListExecutionsRequest{Status: &status, Limit: 10})
		if err != nil {
			t.Errorf("List() error = %v", err)
		}
		if len(results) != 1 {
			t.Errorf("len(results) = %v, want 1", len(results))
		}
	})

	t.Run("filter by tenant", func(t *testing.T) {
		// #3039: a tenant-filtered List now runs scope-wrapped
		// (WithOrgAndTenantScope: BEGIN + set_config×3 + count + select +
		// COMMIT) so mig 042's RLS admits the rows under app_role.
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("tenant-1").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.current_tenant_id', \\$1, true\\)").WithArgs("tenant-1").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.tenant_id', \\$1, true\\)").WithArgs("tenant-1").WillReturnResult(sqlmock.NewResult(0, 0))

		mock.ExpectQuery("SELECT COUNT\\(\\*\\)").
			WithArgs("tenant-1").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

		mock.ExpectQuery("SELECT .* FROM execution_history").
			WithArgs("tenant-1", 10).
			WillReturnRows(sqlmock.NewRows(columns).
				AddRow("plan_1", "map_plan", "Plan 1", "", "tenant-1", nil, nil, nil, "pending", 0, 3, now, nil, nil, nil, stepsJSON, nil, metadataJSON, now, now))
		mock.ExpectCommit()

		results, _, err := repo.List(ctx, ListExecutionsRequest{TenantID: "tenant-1", Limit: 10})
		if err != nil {
			t.Errorf("List() error = %v", err)
		}
		if len(results) != 1 {
			t.Errorf("len(results) = %v, want 1", len(results))
		}
	})

	t.Run("with pagination", func(t *testing.T) {
		mock.ExpectQuery("SELECT COUNT\\(\\*\\)").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(10))

		mock.ExpectQuery("SELECT .* FROM execution_history").
			WithArgs(5, 2).
			WillReturnRows(sqlmock.NewRows(columns).
				AddRow("plan_3", "map_plan", "Plan 3", "", nil, nil, nil, nil, "pending", 0, 3, now, nil, nil, nil, stepsJSON, nil, metadataJSON, now, now).
				AddRow("plan_4", "map_plan", "Plan 4", "", nil, nil, nil, nil, "pending", 0, 3, now, nil, nil, nil, stepsJSON, nil, metadataJSON, now, now))

		results, total, err := repo.List(ctx, ListExecutionsRequest{Limit: 5, Offset: 2})
		if err != nil {
			t.Errorf("List() error = %v", err)
		}
		if len(results) != 2 {
			t.Errorf("len(results) = %v, want 2", len(results))
		}
		if total != 10 {
			t.Errorf("total = %v, want 10", total)
		}
	})

	t.Run("count query error", func(t *testing.T) {
		mock.ExpectQuery("SELECT COUNT\\(\\*\\)").
			WillReturnError(errors.New("database error"))

		_, _, err := repo.List(ctx, ListExecutionsRequest{})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("select query error", func(t *testing.T) {
		mock.ExpectQuery("SELECT COUNT\\(\\*\\)").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

		mock.ExpectQuery("SELECT .* FROM execution_history").
			WillReturnError(errors.New("database error"))

		_, _, err := repo.List(ctx, ListExecutionsRequest{Limit: 10})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("scan error", func(t *testing.T) {
		mock.ExpectQuery("SELECT COUNT\\(\\*\\)").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

		// Return invalid column types to cause scan error
		mock.ExpectQuery("SELECT .* FROM execution_history").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("invalid"))

		_, _, err := repo.List(ctx, ListExecutionsRequest{Limit: 10})
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestPostgresRepository_Delete(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()

	// v9 Phase 8 #2384 PR-C1: WithOrgAndTenantScope wraps every Delete/Update*
	// repo call in BEGIN/SET-CONFIG×3/EXEC/COMMIT. expectScopedTxn factors
	// the BEGIN+set_config trio into one place so the per-method sub-tests
	// stay readable.
	expectScopedTxn := func() {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("test-org").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.current_tenant_id', \\$1, true\\)").
			WithArgs("test-tenant").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.tenant_id', \\$1, true\\)").
			WithArgs("test-tenant").
			WillReturnResult(sqlmock.NewResult(0, 0))
	}

	t.Run("successful delete", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("DELETE FROM execution_history").
			WithArgs("plan_abc123").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		err := repo.Delete(ctx, "test-org", "test-tenant", "plan_abc123")
		if err != nil {
			t.Errorf("Delete() error = %v", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("DELETE FROM execution_history").
			WithArgs("nonexistent").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectCommit()

		err := repo.Delete(ctx, "test-org", "test-tenant", "nonexistent")
		if !errors.Is(err, ErrExecutionNotFound) {
			t.Errorf("Delete() error = %v, want ErrExecutionNotFound", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("DELETE FROM execution_history").
			WithArgs("plan_abc123").
			WillReturnError(errors.New("connection refused"))
		mock.ExpectRollback()

		err := repo.Delete(ctx, "test-org", "test-tenant", "plan_abc123")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestPostgresRepository_UpdateStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()
	now := time.Now()

	expectScopedTxn := func() {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("test-org").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.current_tenant_id', \\$1, true\\)").WithArgs("test-tenant").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.tenant_id', \\$1, true\\)").WithArgs("test-tenant").WillReturnResult(sqlmock.NewResult(0, 0))
	}

	t.Run("successful update", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WithArgs("plan_abc123", StatusCompleted, &now, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		err := repo.UpdateStatus(ctx, "test-org", "test-tenant", "plan_abc123", StatusCompleted, &now, "")
		if err != nil {
			t.Errorf("UpdateStatus() error = %v", err)
		}
	})

	t.Run("with error message", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WithArgs("plan_abc123", StatusFailed, &now, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		err := repo.UpdateStatus(ctx, "test-org", "test-tenant", "plan_abc123", StatusFailed, &now, "step failed")
		if err != nil {
			t.Errorf("UpdateStatus() error = %v", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectCommit()

		err := repo.UpdateStatus(ctx, "test-org", "test-tenant", "nonexistent", StatusCompleted, &now, "")
		if !errors.Is(err, ErrExecutionNotFound) {
			t.Errorf("UpdateStatus() error = %v, want ErrExecutionNotFound", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WillReturnError(errors.New("connection refused"))
		mock.ExpectRollback()

		err := repo.UpdateStatus(ctx, "test-org", "test-tenant", "plan_abc123", StatusCompleted, &now, "")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestPostgresRepository_UpdateSteps(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()

	steps := []StepStatus{
		{StepID: "step-1", StepName: "Step 1", Status: StepStatusCompleted},
		{StepID: "step-2", StepName: "Step 2", Status: StepStatusRunning},
	}

	expectScopedTxn := func() {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("test-org").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.current_tenant_id', \\$1, true\\)").WithArgs("test-tenant").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.tenant_id', \\$1, true\\)").WithArgs("test-tenant").WillReturnResult(sqlmock.NewResult(0, 0))
	}

	t.Run("successful update", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WithArgs("plan_abc123", sqlmock.AnyArg(), 2, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		err := repo.UpdateSteps(ctx, "test-org", "test-tenant", "plan_abc123", steps)
		if err != nil {
			t.Errorf("UpdateSteps() error = %v", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectCommit()

		err := repo.UpdateSteps(ctx, "test-org", "test-tenant", "nonexistent", steps)
		if !errors.Is(err, ErrExecutionNotFound) {
			t.Errorf("UpdateSteps() error = %v, want ErrExecutionNotFound", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WillReturnError(errors.New("connection refused"))
		mock.ExpectRollback()

		err := repo.UpdateSteps(ctx, "test-org", "test-tenant", "plan_abc123", steps)
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestPostgresRepository_UpdateCost(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()

	estimatedCost := 0.05
	actualCost := 0.03

	expectScopedTxn := func() {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("test-org").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.current_tenant_id', \\$1, true\\)").WithArgs("test-tenant").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("SELECT set_config\\('app.tenant_id', \\$1, true\\)").WithArgs("test-tenant").WillReturnResult(sqlmock.NewResult(0, 0))
	}

	t.Run("update both costs", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WithArgs("plan_abc123", &estimatedCost, &actualCost, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		err := repo.UpdateCost(ctx, "test-org", "test-tenant", "plan_abc123", &estimatedCost, &actualCost)
		if err != nil {
			t.Errorf("UpdateCost() error = %v", err)
		}
	})

	t.Run("update estimated only", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WithArgs("plan_abc123", &estimatedCost, nil, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		err := repo.UpdateCost(ctx, "test-org", "test-tenant", "plan_abc123", &estimatedCost, nil)
		if err != nil {
			t.Errorf("UpdateCost() error = %v", err)
		}
	})

	t.Run("update actual only", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WithArgs("plan_abc123", nil, &actualCost, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		err := repo.UpdateCost(ctx, "test-org", "test-tenant", "plan_abc123", nil, &actualCost)
		if err != nil {
			t.Errorf("UpdateCost() error = %v", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectCommit()

		err := repo.UpdateCost(ctx, "test-org", "test-tenant", "nonexistent", &estimatedCost, &actualCost)
		if !errors.Is(err, ErrExecutionNotFound) {
			t.Errorf("UpdateCost() error = %v, want ErrExecutionNotFound", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		expectScopedTxn()
		mock.ExpectExec("UPDATE execution_history SET").
			WillReturnError(errors.New("connection refused"))
		mock.ExpectRollback()

		err := repo.UpdateCost(ctx, "test-org", "test-tenant", "plan_abc123", &estimatedCost, &actualCost)
		if err == nil {
			t.Error("expected error")
		}
	})
}
