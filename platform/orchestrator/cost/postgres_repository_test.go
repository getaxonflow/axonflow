// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestNewPostgresRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	if repo == nil {
		t.Fatal("Expected non-nil repository")
	}
	if repo.db != db {
		t.Error("Expected db to be set")
	}
}

func TestPostgresRepository_CreateBudget(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)

	t.Run("successful creation", func(t *testing.T) {
		budget := &Budget{
			ID:              "budget-001",
			Name:            "Test Budget",
			Description:     "Test description",
			Scope:           ScopeOrganization,
			ScopeID:         "org-123",
			LimitUSD:        1000.0,
			Period:          PeriodMonthly,
			OnExceed:        OnExceedWarn,
			AlertThresholds: []int{50, 80, 100},
			Enabled:         true,
			OrgID:           "org-123",
			TenantID:        "tenant-456",
			CreatedBy:       "user-789",
			UpdatedBy:       "user-789",
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}

		mock.ExpectExec("INSERT INTO budgets").
			WithArgs(
				budget.ID, budget.Name, budget.Description, budget.Scope, budget.ScopeID,
				budget.LimitUSD, budget.Period, budget.OnExceed, sqlmock.AnyArg(), budget.Enabled,
				sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
				sqlmock.AnyArg(), sqlmock.AnyArg(),
			).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := repo.CreateBudget(context.Background(), budget)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("Unfulfilled expectations: %v", err)
		}
	})

	t.Run("duplicate key error", func(t *testing.T) {
		budget := &Budget{
			ID:              "budget-duplicate",
			Name:            "Duplicate Budget",
			Scope:           ScopeOrganization,
			LimitUSD:        500.0,
			Period:          PeriodMonthly,
			OnExceed:        OnExceedWarn,
			AlertThresholds: []int{80},
			Enabled:         true,
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}

		mock.ExpectExec("INSERT INTO budgets").
			WillReturnError(sql.ErrConnDone) // Simulate error

		err := repo.CreateBudget(context.Background(), budget)
		if err == nil {
			t.Error("Expected error for duplicate key")
		}
	})
}

func TestPostgresRepository_GetBudget(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)

	t.Run("budget found", func(t *testing.T) {
		thresholds, _ := json.Marshal([]int{50, 80, 100})
		rows := sqlmock.NewRows([]string{
			"id", "name", "description", "scope", "scope_id", "limit_usd", "period",
			"on_exceed", "alert_thresholds", "enabled", "org_id", "tenant_id",
			"created_by", "updated_by", "created_at", "updated_at",
		}).AddRow(
			"budget-001", "Test Budget", "Description", ScopeOrganization, "org-123",
			1000.0, PeriodMonthly, OnExceedWarn, thresholds, true,
			"org-123", "tenant-456", "user-789", "user-789",
			time.Now(), time.Now(),
		)

		mock.ExpectQuery("SELECT .+ FROM budgets").
			WithArgs("budget-001").
			WillReturnRows(rows)

		budget, err := repo.GetBudget(context.Background(), "budget-001")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if budget == nil {
			t.Fatal("Expected budget to be returned")
		}
		if budget.ID != "budget-001" {
			t.Errorf("Expected ID budget-001, got %s", budget.ID)
		}
		if budget.LimitUSD != 1000.0 {
			t.Errorf("Expected LimitUSD 1000.0, got %f", budget.LimitUSD)
		}
	})

	t.Run("budget not found", func(t *testing.T) {
		mock.ExpectQuery("SELECT .+ FROM budgets").
			WithArgs("nonexistent").
			WillReturnError(sql.ErrNoRows)

		budget, err := repo.GetBudget(context.Background(), "nonexistent")
		if err != ErrBudgetNotFound {
			t.Errorf("Expected ErrBudgetNotFound, got %v", err)
		}
		if budget != nil {
			t.Error("Expected nil budget")
		}
	})
}

func TestPostgresRepository_Ping(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)

	t.Run("ping success", func(t *testing.T) {
		mock.ExpectPing()

		err := repo.Ping(context.Background())
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

func TestPostgresRepository_UpdateBudget(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)

	t.Run("successful update", func(t *testing.T) {
		budget := &Budget{
			ID:              "budget-001",
			Name:            "Updated Budget",
			Description:     "Updated description",
			Scope:           ScopeOrganization,
			ScopeID:         "org-123",
			LimitUSD:        2000.0,
			Period:          PeriodMonthly,
			OnExceed:        OnExceedBlock,
			AlertThresholds: []int{75, 90},
			Enabled:         true,
			UpdatedBy:       "user-789",
		}

		mock.ExpectExec("UPDATE budgets SET").
			WithArgs(
				budget.ID, budget.Name, budget.Description, budget.Scope, budget.ScopeID,
				budget.LimitUSD, budget.Period, budget.OnExceed, sqlmock.AnyArg(),
				budget.Enabled, sqlmock.AnyArg(), sqlmock.AnyArg(),
			).
			WillReturnResult(sqlmock.NewResult(0, 1))

		err := repo.UpdateBudget(context.Background(), budget)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("Unfulfilled expectations: %v", err)
		}
	})

	t.Run("budget not found", func(t *testing.T) {
		budget := &Budget{
			ID:              "nonexistent",
			Name:            "Not Found Budget",
			AlertThresholds: []int{80},
		}

		mock.ExpectExec("UPDATE budgets SET").
			WillReturnResult(sqlmock.NewResult(0, 0))

		err := repo.UpdateBudget(context.Background(), budget)
		if err != ErrBudgetNotFound {
			t.Errorf("Expected ErrBudgetNotFound, got %v", err)
		}
	})
}

func TestPostgresRepository_DeleteBudget(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)

	t.Run("successful delete", func(t *testing.T) {
		mock.ExpectExec("DELETE FROM budgets WHERE").
			WithArgs("budget-001").
			WillReturnResult(sqlmock.NewResult(0, 1))

		err := repo.DeleteBudget(context.Background(), "budget-001")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("Unfulfilled expectations: %v", err)
		}
	})

	t.Run("budget not found", func(t *testing.T) {
		mock.ExpectExec("DELETE FROM budgets WHERE").
			WithArgs("nonexistent").
			WillReturnResult(sqlmock.NewResult(0, 0))

		err := repo.DeleteBudget(context.Background(), "nonexistent")
		if err != ErrBudgetNotFound {
			t.Errorf("Expected ErrBudgetNotFound, got %v", err)
		}
	})
}

func TestPostgresRepository_SaveUsage(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)

	t.Run("successful save", func(t *testing.T) {
		record := &UsageRecord{
			RequestID:   "req-001",
			Timestamp:   time.Now(),
			OrgID:       "org-123",
			TenantID:    "tenant-456",
			TeamID:      "team-789",
			AgentID:     "agent-001",
			WorkflowID:  "workflow-001",
			UserID:      "user-001",
			Provider:    "openai",
			Model:       "gpt-4",
			TokensIn:    100,
			TokensOut:   50,
			CostUSD:     0.05,
			RequestType: "completion",
			Cached:      false,
		}

		rows := sqlmock.NewRows([]string{"id"}).AddRow(int64(1))
		mock.ExpectQuery("INSERT INTO usage_records").
			WithArgs(
				record.RequestID, sqlmock.AnyArg(),
				sqlmock.AnyArg(), sqlmock.AnyArg(),
				sqlmock.AnyArg(), sqlmock.AnyArg(),
				sqlmock.AnyArg(), sqlmock.AnyArg(),
				record.Provider, record.Model,
				record.TokensIn, record.TokensOut, record.CostUSD,
				sqlmock.AnyArg(), record.Cached,
			).
			WillReturnRows(rows)

		err := repo.SaveUsage(context.Background(), record)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if record.ID != 1 {
			t.Errorf("Expected ID 1, got %d", record.ID)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("Unfulfilled expectations: %v", err)
		}
	})

	t.Run("save error", func(t *testing.T) {
		record := &UsageRecord{
			RequestID: "req-fail",
			Provider:  "openai",
			Model:     "gpt-4",
		}

		mock.ExpectQuery("INSERT INTO usage_records").
			WillReturnError(sql.ErrConnDone)

		err := repo.SaveUsage(context.Background(), record)
		if err == nil {
			t.Error("Expected error, got nil")
		}
	})
}

func TestPostgresRepository_AcknowledgeAlert(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)

	t.Run("successful acknowledge", func(t *testing.T) {
		mock.ExpectExec("UPDATE budget_alerts").
			WithArgs(int64(1), "admin-user", sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))

		err := repo.AcknowledgeAlert(context.Background(), 1, "admin-user")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("Unfulfilled expectations: %v", err)
		}
	})
}

func TestPostgresRepository_GetUsageForPeriod(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)

	testCases := []struct {
		name   string
		scope  BudgetScope
		column string
	}{
		{"organization scope", ScopeOrganization, "org_id"},
		{"team scope", ScopeTeam, "team_id"},
		{"agent scope", ScopeAgent, "agent_id"},
		{"workflow scope", ScopeWorkflow, "workflow_id"},
		{"user scope", ScopeUser, "user_id"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rows := sqlmock.NewRows([]string{"total"}).AddRow(125.50)
			mock.ExpectQuery("SELECT COALESCE\\(SUM\\(cost_usd\\), 0\\)").
				WithArgs("scope-123", sqlmock.AnyArg(), "org-123", "tenant-456").
				WillReturnRows(rows)

			total, err := repo.GetUsageForPeriod(
				context.Background(),
				tc.scope,
				"scope-123",
				time.Now().AddDate(0, -1, 0),
				"org-123",
				"tenant-456",
			)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if total != 125.50 {
				t.Errorf("Expected 125.50, got %f", total)
			}
		})
	}
}

func TestNullString(t *testing.T) {
	t.Run("empty string returns null", func(t *testing.T) {
		result := nullString("")
		if result.Valid {
			t.Error("Expected invalid for empty string")
		}
	})

	t.Run("non-empty string returns valid", func(t *testing.T) {
		result := nullString("test")
		if !result.Valid {
			t.Error("Expected valid for non-empty string")
		}
		if result.String != "test" {
			t.Errorf("Expected 'test', got '%s'", result.String)
		}
	})
}
