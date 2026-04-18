// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewPostgresKillSwitchRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	require.NotNil(t, repo)
	assert.Equal(t, db, repo.db)
}

func TestNewPostgresKillSwitchRepository_NilDB(t *testing.T) {
	repo := NewPostgresKillSwitchRepository(nil)
	require.NotNil(t, repo)
	assert.Nil(t, repo.db)
}

// =============================================================================
// Create Tests
// =============================================================================

func TestKillSwitchRepository_Create_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	accuracyThreshold := 0.85
	biasThreshold := 0.10
	errorThreshold := 0.05

	ks := &KillSwitch{
		OrgID:              "org-1",
		SystemID:           "sys-credit",
		Status:             KillSwitchEnabled,
		TriggerReason:      "",
		TriggerConditions:  map[string]interface{}{"metric": "accuracy", "operator": "lt"},
		AutoTriggerEnabled: true,
		AccuracyThreshold:  &accuracyThreshold,
		BiasThreshold:      &biasThreshold,
		ErrorRateThreshold: &errorThreshold,
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO mas_kill_switches")).
		WithArgs(
			sqlmock.AnyArg(), // id
			ks.OrgID, ks.SystemID, ks.Status, ks.TriggerReason,
			sqlmock.AnyArg(), // conditions JSON
			ks.AutoTriggerEnabled, ks.AccuracyThreshold, ks.BiasThreshold,
			ks.ErrorRateThreshold,
			sqlmock.AnyArg(), // created_at
			sqlmock.AnyArg(), // updated_at
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.Create(ctx, ks)
	require.NoError(t, err)

	assert.NotEmpty(t, ks.ID)
	assert.False(t, ks.CreatedAt.IsZero())
	assert.Equal(t, ks.CreatedAt, ks.UpdatedAt)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_Create_WithExistingID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	ks := &KillSwitch{
		ID:                 "pre-set-ks-id",
		OrgID:              "org-1",
		SystemID:           "sys-1",
		Status:             KillSwitchDisabled,
		AutoTriggerEnabled: false,
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO mas_kill_switches")).
		WithArgs(
			"pre-set-ks-id",
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.Create(ctx, ks)
	require.NoError(t, err)
	assert.Equal(t, "pre-set-ks-id", ks.ID)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_Create_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	ks := &KillSwitch{
		OrgID:    "org-1",
		SystemID: "sys-1",
		Status:   KillSwitchEnabled,
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO mas_kill_switches")).
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnError(fmt.Errorf("duplicate key: system already has kill switch"))

	err = repo.Create(ctx, ks)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to insert kill switch")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_Create_NilConditions(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	ks := &KillSwitch{
		OrgID:              "org-1",
		SystemID:           "sys-1",
		Status:             KillSwitchEnabled,
		TriggerConditions:  nil,
		AutoTriggerEnabled: false,
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO mas_kill_switches")).
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.Create(ctx, ks)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// GetBySystemID Tests
// =============================================================================

func killSwitchColumns() []string {
	return []string{
		"id", "org_id", "system_id", "status", "trigger_reason", "trigger_conditions",
		"auto_trigger_enabled", "accuracy_threshold", "bias_threshold",
		"error_rate_threshold", "triggered_at", "triggered_by", "restored_at",
		"restored_by", "restore_reason", "created_at", "updated_at",
	}
}

func TestKillSwitchRepository_GetBySystemID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	triggeredAt := now.Add(-1 * time.Hour)
	conditionsJSON, _ := json.Marshal(map[string]interface{}{"metric": "accuracy"})

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id, system_id, status")).
		WithArgs("org-1", "sys-credit").
		WillReturnRows(sqlmock.NewRows(killSwitchColumns()).AddRow(
			"ks-1", "org-1", "sys-credit", KillSwitchTriggered,
			"Accuracy dropped below threshold", conditionsJSON,
			true, 0.85, 0.10, 0.05,
			triggeredAt, "system_auto", nil, nil, nil,
			now, now,
		))

	ks, err := repo.GetBySystemID(ctx, "org-1", "sys-credit")
	require.NoError(t, err)
	require.NotNil(t, ks)

	assert.Equal(t, "ks-1", ks.ID)
	assert.Equal(t, "org-1", ks.OrgID)
	assert.Equal(t, "sys-credit", ks.SystemID)
	assert.Equal(t, KillSwitchTriggered, ks.Status)
	assert.Equal(t, "Accuracy dropped below threshold", ks.TriggerReason)
	assert.True(t, ks.AutoTriggerEnabled)
	require.NotNil(t, ks.AccuracyThreshold)
	assert.Equal(t, 0.85, *ks.AccuracyThreshold)
	require.NotNil(t, ks.BiasThreshold)
	assert.Equal(t, 0.10, *ks.BiasThreshold)
	require.NotNil(t, ks.ErrorRateThreshold)
	assert.Equal(t, 0.05, *ks.ErrorRateThreshold)
	require.NotNil(t, ks.TriggeredAt)
	assert.Equal(t, "system_auto", ks.TriggeredBy)
	assert.Nil(t, ks.RestoredAt)
	assert.Empty(t, ks.RestoredBy)
	assert.Empty(t, ks.RestoreReason)
	assert.NotNil(t, ks.TriggerConditions)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetBySystemID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id, system_id")).
		WithArgs("org-1", "nonexistent").
		WillReturnError(sql.ErrNoRows)

	ks, err := repo.GetBySystemID(ctx, "org-1", "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, ks)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetBySystemID_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id")).
		WithArgs("org-1", "sys-1").
		WillReturnError(fmt.Errorf("connection timeout"))

	ks, err := repo.GetBySystemID(ctx, "org-1", "sys-1")
	assert.Error(t, err)
	assert.Nil(t, ks)
	assert.Contains(t, err.Error(), "failed to get kill switch")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetBySystemID_NullableFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id, system_id")).
		WithArgs("org-1", "sys-1").
		WillReturnRows(sqlmock.NewRows(killSwitchColumns()).AddRow(
			"ks-1", "org-1", "sys-1", KillSwitchEnabled,
			nil, nil, // trigger_reason, conditions
			false, nil, nil, nil, // thresholds
			nil, nil, nil, nil, nil, // triggered/restored fields
			now, now,
		))

	ks, err := repo.GetBySystemID(ctx, "org-1", "sys-1")
	require.NoError(t, err)
	require.NotNil(t, ks)

	assert.Equal(t, KillSwitchEnabled, ks.Status)
	assert.Empty(t, ks.TriggerReason)
	assert.Nil(t, ks.TriggerConditions)
	assert.False(t, ks.AutoTriggerEnabled)
	assert.Nil(t, ks.AccuracyThreshold)
	assert.Nil(t, ks.BiasThreshold)
	assert.Nil(t, ks.ErrorRateThreshold)
	assert.Nil(t, ks.TriggeredAt)
	assert.Empty(t, ks.TriggeredBy)
	assert.Nil(t, ks.RestoredAt)
	assert.Empty(t, ks.RestoredBy)
	assert.Empty(t, ks.RestoreReason)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetBySystemID_RestoredKillSwitch(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()
	triggeredAt := now.Add(-48 * time.Hour)
	restoredAt := now.Add(-24 * time.Hour)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id, system_id")).
		WithArgs("org-1", "sys-1").
		WillReturnRows(sqlmock.NewRows(killSwitchColumns()).AddRow(
			"ks-1", "org-1", "sys-1", KillSwitchEnabled,
			"Bias detected", nil,
			true, 0.90, 0.05, nil,
			triggeredAt, "monitor_system", restoredAt, "ops@bank.com", "Issue resolved after model retrain",
			now, now,
		))

	ks, err := repo.GetBySystemID(ctx, "org-1", "sys-1")
	require.NoError(t, err)
	require.NotNil(t, ks)

	assert.Equal(t, "Bias detected", ks.TriggerReason)
	require.NotNil(t, ks.TriggeredAt)
	assert.Equal(t, "monitor_system", ks.TriggeredBy)
	require.NotNil(t, ks.RestoredAt)
	assert.Equal(t, "ops@bank.com", ks.RestoredBy)
	assert.Equal(t, "Issue resolved after model retrain", ks.RestoreReason)

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// Update Tests
// =============================================================================

func TestKillSwitchRepository_Update_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	triggeredAt := time.Now().UTC()
	accuracyThreshold := 0.90

	ks := &KillSwitch{
		ID:                 "ks-1",
		OrgID:              "org-1",
		SystemID:           "sys-1",
		Status:             KillSwitchTriggered,
		TriggerReason:      "Accuracy below threshold",
		TriggerConditions:  map[string]interface{}{"metric": "accuracy"},
		AutoTriggerEnabled: true,
		AccuracyThreshold:  &accuracyThreshold,
		TriggeredAt:        &triggeredAt,
		TriggeredBy:        "system",
	}

	mock.ExpectExec(regexp.QuoteMeta("UPDATE mas_kill_switches SET")).
		WithArgs(
			ks.Status, ks.TriggerReason,
			sqlmock.AnyArg(), // conditions JSON
			ks.AutoTriggerEnabled,
			ks.AccuracyThreshold, ks.BiasThreshold, ks.ErrorRateThreshold,
			ks.TriggeredAt, ks.TriggeredBy,
			ks.RestoredAt, ks.RestoredBy, ks.RestoreReason,
			sqlmock.AnyArg(), // updated_at
			ks.OrgID, ks.SystemID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.Update(ctx, ks)
	require.NoError(t, err)

	assert.False(t, ks.UpdatedAt.IsZero())

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_Update_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	ks := &KillSwitch{
		ID:       "ks-1",
		OrgID:    "org-1",
		SystemID: "sys-1",
		Status:   KillSwitchTriggered,
	}

	mock.ExpectExec(regexp.QuoteMeta("UPDATE mas_kill_switches SET")).
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			"org-1", "sys-1",
		).
		WillReturnError(fmt.Errorf("row not found"))

	err = repo.Update(ctx, ks)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update kill switch")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_Update_Restore(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	restoredAt := time.Now().UTC()
	ks := &KillSwitch{
		ID:            "ks-1",
		OrgID:         "org-1",
		SystemID:      "sys-1",
		Status:        KillSwitchEnabled,
		RestoredAt:    &restoredAt,
		RestoredBy:    "ops@bank.com",
		RestoreReason: "Model retrained successfully",
	}

	mock.ExpectExec(regexp.QuoteMeta("UPDATE mas_kill_switches SET")).
		WithArgs(
			KillSwitchEnabled, sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			&restoredAt, "ops@bank.com", "Model retrained successfully",
			sqlmock.AnyArg(),
			"org-1", "sys-1",
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.Update(ctx, ks)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// RecordHistory Tests
// =============================================================================

func TestKillSwitchRepository_RecordHistory_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	history := &KillSwitchHistory{
		KillSwitchID:   "ks-1",
		Action:         "triggered",
		PreviousStatus: "enabled",
		NewStatus:      "triggered",
		Reason:         "Accuracy dropped below 85%",
		PerformedBy:    "system_monitor",
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO mas_kill_switch_history")).
		WithArgs(
			sqlmock.AnyArg(), // id (generated)
			history.KillSwitchID, history.Action, history.PreviousStatus,
			history.NewStatus, history.Reason, history.PerformedBy,
			sqlmock.AnyArg(), // performed_at (auto-set)
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.RecordHistory(ctx, history)
	require.NoError(t, err)

	assert.NotEmpty(t, history.ID)
	assert.False(t, history.PerformedAt.IsZero())

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_RecordHistory_WithExistingIDAndTimestamp(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	performedAt := time.Date(2026, 2, 15, 10, 30, 0, 0, time.UTC)
	history := &KillSwitchHistory{
		ID:             "hist-pre-set",
		KillSwitchID:   "ks-1",
		Action:         "restored",
		PreviousStatus: "triggered",
		NewStatus:      "enabled",
		Reason:         "Model retrained",
		PerformedBy:    "ops_engineer",
		PerformedAt:    performedAt,
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO mas_kill_switch_history")).
		WithArgs(
			"hist-pre-set",
			history.KillSwitchID, history.Action, history.PreviousStatus,
			history.NewStatus, history.Reason, history.PerformedBy,
			performedAt,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.RecordHistory(ctx, history)
	require.NoError(t, err)
	assert.Equal(t, "hist-pre-set", history.ID)
	assert.Equal(t, performedAt, history.PerformedAt)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_RecordHistory_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	history := &KillSwitchHistory{
		KillSwitchID:   "ks-invalid",
		Action:         "triggered",
		PreviousStatus: "enabled",
		NewStatus:      "triggered",
		Reason:         "Test",
		PerformedBy:    "system",
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO mas_kill_switch_history")).
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnError(fmt.Errorf("foreign key violation: kill_switch_id not found"))

	err = repo.RecordHistory(ctx, history)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to record kill switch history")

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// GetHistory Tests
// =============================================================================

func historyColumns() []string {
	return []string{
		"id", "kill_switch_id", "action", "previous_status",
		"new_status", "reason", "performed_by", "performed_at",
	}
}

func TestKillSwitchRepository_GetHistory_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT h.id, h.kill_switch_id, h.action, h.previous_status")).
		WithArgs("org-1", "sys-credit", 50).
		WillReturnRows(sqlmock.NewRows(historyColumns()).
			AddRow("h-1", "ks-1", "triggered", "enabled", "triggered",
				"Accuracy below threshold", "system_monitor", now.Add(-2*time.Hour)).
			AddRow("h-2", "ks-1", "restored", "triggered", "enabled",
				"Model retrained", "ops@bank.com", now.Add(-1*time.Hour)).
			AddRow("h-3", "ks-1", "triggered", "enabled", "triggered",
				nil, "system_auto", now))

	history, err := repo.GetHistory(ctx, "org-1", "sys-credit", 0)
	require.NoError(t, err)
	require.Len(t, history, 3)

	assert.Equal(t, "h-1", history[0].ID)
	assert.Equal(t, "ks-1", history[0].KillSwitchID)
	assert.Equal(t, "triggered", history[0].Action)
	assert.Equal(t, "enabled", history[0].PreviousStatus)
	assert.Equal(t, "triggered", history[0].NewStatus)
	assert.Equal(t, "Accuracy below threshold", history[0].Reason)
	assert.Equal(t, "system_monitor", history[0].PerformedBy)

	assert.Equal(t, "h-2", history[1].ID)
	assert.Equal(t, "restored", history[1].Action)
	assert.Equal(t, "Model retrained", history[1].Reason)

	assert.Equal(t, "h-3", history[2].ID)
	assert.Empty(t, history[2].Reason) // Nullable reason is nil

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetHistory_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT h.id, h.kill_switch_id")).
		WithArgs("org-1", "sys-new", 50).
		WillReturnRows(sqlmock.NewRows(historyColumns()))

	history, err := repo.GetHistory(ctx, "org-1", "sys-new", 0)
	require.NoError(t, err)
	assert.Len(t, history, 0)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetHistory_WithLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta("LIMIT $3")).
		WithArgs("org-1", "sys-1", 5).
		WillReturnRows(sqlmock.NewRows(historyColumns()).
			AddRow("h-1", "ks-1", "triggered", "enabled", "triggered",
				"Test", "system", now))

	history, err := repo.GetHistory(ctx, "org-1", "sys-1", 5)
	require.NoError(t, err)
	require.Len(t, history, 1)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetHistory_LimitClamping(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	// Limit > MaxListLimit should be clamped
	mock.ExpectQuery("SELECT").
		WithArgs("org-1", "sys-1", MaxListLimit).
		WillReturnRows(sqlmock.NewRows(historyColumns()))

	history, err := repo.GetHistory(ctx, "org-1", "sys-1", 5000)
	require.NoError(t, err)
	assert.Len(t, history, 0)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetHistory_NegativeLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	// Negative limit should default to DefaultListLimit
	mock.ExpectQuery("SELECT").
		WithArgs("org-1", "sys-1", DefaultListLimit).
		WillReturnRows(sqlmock.NewRows(historyColumns()))

	history, err := repo.GetHistory(ctx, "org-1", "sys-1", -1)
	require.NoError(t, err)
	assert.Len(t, history, 0)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetHistory_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	mock.ExpectQuery("SELECT").
		WithArgs("org-1", "sys-1", DefaultListLimit).
		WillReturnError(fmt.Errorf("join failed"))

	history, err := repo.GetHistory(ctx, "org-1", "sys-1", 0)
	assert.Error(t, err)
	assert.Nil(t, history)
	assert.Contains(t, err.Error(), "failed to get kill switch history")

	require.NoError(t, mock.ExpectationsWereMet())
}
