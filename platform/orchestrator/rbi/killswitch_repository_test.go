// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var killSwitchColumns = []string{
	"id", "org_id", "scope", "system_id", "target_identifier",
	"is_active", "activated_by", "activated_by_email", "activated_at", "activation_reason",
	"auto_triggered", "trigger_condition", "trigger_threshold",
	"fallback_behavior", "fallback_config",
	"deactivated_by", "deactivated_by_email", "deactivated_at", "deactivation_reason",
	"created_at", "updated_at",
}

var historyColumns = []string{
	"id", "org_id", "kill_switch_id", "action",
	"actor_id", "actor_email", "actor_role", "actor_ip", "reason",
	"previous_state", "new_state", "metadata",
	"created_at",
}

func sampleKillSwitchRow(id, orgID string, scope KillSwitchScope, isActive bool) []driver.Value {
	now := time.Now().UTC()
	activatedAt := now.Add(-1 * time.Hour)
	return []driver.Value{
		id, orgID, string(scope),
		sql.NullString{String: "sys-001", Valid: true},
		sql.NullString{String: "model-v2", Valid: true},
		isActive,
		sql.NullString{String: "admin-001", Valid: true},
		sql.NullString{String: "admin@example.com", Valid: true},
		sql.NullTime{Time: activatedAt, Valid: true},
		sql.NullString{String: "Safety concern", Valid: true},
		false,
		sql.NullString{String: "error_rate > 0.1", Valid: true},
		[]byte(`{"error_rate":0.1}`),
		string(FallbackBehaviorBlockAll),
		[]byte(`{"message":"Service temporarily unavailable"}`),
		sql.NullString{},
		sql.NullString{},
		sql.NullTime{},
		sql.NullString{},
		now, now,
	}
}

func TestKillSwitchRepository_Create_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	activatedAt := time.Now().UTC()
	ks := &KillSwitch{
		OrgID:            "org-001",
		Scope:            KillSwitchScopeSystem,
		SystemID:         "sys-001",
		IsActive:         true,
		ActivatedBy:      "admin-001",
		ActivatedByEmail: "admin@example.com",
		ActivatedAt:      &activatedAt,
		ActivationReason: "Safety concern",
		FallbackBehavior: FallbackBehaviorBlockAll,
		TriggerThreshold: map[string]interface{}{"error_rate": 0.1},
		FallbackConfig:   map[string]interface{}{"msg": "blocked"},
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_kill_switches`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = repo.Create(ctx, ks)
	assert.NoError(t, err)
	assert.NotEmpty(t, ks.ID)
	assert.False(t, ks.CreatedAt.IsZero())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_Create_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	ks := &KillSwitch{
		OrgID:            "org-001",
		Scope:            KillSwitchScopeGlobal,
		IsActive:         true,
		FallbackBehavior: FallbackBehaviorBlockAll,
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_kill_switches`)).
		WillReturnError(fmt.Errorf("connection refused"))
	mock.ExpectRollback()

	err = repo.Create(ctx, ks)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create kill switch")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_Create_PresetID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	ks := &KillSwitch{
		ID:               "preset-ks-id",
		OrgID:            "org-001",
		Scope:            KillSwitchScopeGlobal,
		IsActive:         false,
		FallbackBehavior: FallbackBehaviorHumanReview,
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_kill_switches`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = repo.Create(ctx, ks)
	assert.NoError(t, err)
	assert.Equal(t, "preset-ks-id", ks.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_Get_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(killSwitchColumns).
		AddRow(sampleKillSwitchRow("ks-001", "org-001", KillSwitchScopeSystem, true)...)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE id = $1 AND org_id = $2`)).
		WithArgs("ks-001", "org-001").
		WillReturnRows(rows)
	mock.ExpectCommit()

	ks, err := repo.Get(ctx, "org-001", "ks-001")
	require.NoError(t, err)
	assert.Equal(t, "ks-001", ks.ID)
	assert.Equal(t, "org-001", ks.OrgID)
	assert.Equal(t, KillSwitchScope("system"), ks.Scope)
	assert.Equal(t, "sys-001", ks.SystemID)
	assert.True(t, ks.IsActive)
	assert.Equal(t, "admin-001", ks.ActivatedBy)
	assert.NotNil(t, ks.ActivatedAt)
	assert.Equal(t, FallbackBehavior("block_all"), ks.FallbackBehavior)
	assert.NotEmpty(t, ks.TriggerThreshold)
	assert.NotEmpty(t, ks.FallbackConfig)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_Get_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE id = $1 AND org_id = $2`)).
		WithArgs("nonexistent", "org-001").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	ks, err := repo.Get(ctx, "org-001", "nonexistent")
	assert.Nil(t, ks)
	assert.ErrorIs(t, err, ErrKillSwitchNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetByScope_Global(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(killSwitchColumns).
		AddRow(sampleKillSwitchRow("ks-global", "org-001", KillSwitchScopeGlobal, true)...)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE org_id = $1 AND scope = $2`)).
		WithArgs("org-001", string(KillSwitchScopeGlobal)).
		WillReturnRows(rows)
	mock.ExpectCommit()

	ks, err := repo.GetByScope(ctx, "org-001", KillSwitchScopeGlobal, "", "")
	require.NoError(t, err)
	assert.Equal(t, "ks-global", ks.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetByScope_System(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(killSwitchColumns).
		AddRow(sampleKillSwitchRow("ks-sys", "org-001", KillSwitchScopeSystem, true)...)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE org_id = $1 AND scope = $2 AND system_id = $3`)).
		WithArgs("org-001", string(KillSwitchScopeSystem), "sys-001").
		WillReturnRows(rows)
	mock.ExpectCommit()

	ks, err := repo.GetByScope(ctx, "org-001", KillSwitchScopeSystem, "sys-001", "")
	require.NoError(t, err)
	assert.Equal(t, "ks-sys", ks.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetByScope_Model(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(killSwitchColumns).
		AddRow(sampleKillSwitchRow("ks-model", "org-001", KillSwitchScopeModel, true)...)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE org_id = $1 AND scope = $2 AND system_id = $3 AND target_identifier = $4`)).
		WithArgs("org-001", string(KillSwitchScopeModel), "sys-001", "model-v2").
		WillReturnRows(rows)
	mock.ExpectCommit()

	ks, err := repo.GetByScope(ctx, "org-001", KillSwitchScopeModel, "sys-001", "model-v2")
	require.NoError(t, err)
	assert.Equal(t, "ks-model", ks.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_List_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	params := &ListKillSwitchParams{Limit: 10, Offset: 0}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	dataRows := sqlmock.NewRows(killSwitchColumns).
		AddRow(sampleKillSwitchRow("ks-1", "org-001", KillSwitchScopeSystem, true)...).
		AddRow(sampleKillSwitchRow("ks-2", "org-001", KillSwitchScopeGlobal, false)...)

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", 10, 0).
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	switches, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, switches, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_List_WithFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	isActive := true
	params := &ListKillSwitchParams{
		SystemID: "sys-001",
		Scope:    "system",
		IsActive: &isActive,
		Limit:    20,
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001", "sys-001", "system", true).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	dataRows := sqlmock.NewRows(killSwitchColumns).
		AddRow(sampleKillSwitchRow("ks-1", "org-001", KillSwitchScopeSystem, true)...)

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", "sys-001", "system", true, 20, 0).
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	switches, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, switches, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_List_NilParams(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", 50, 0).
		WillReturnRows(sqlmock.NewRows(killSwitchColumns))
	mock.ExpectCommit()

	switches, total, err := repo.List(ctx, "org-001", nil)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, switches)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_ListActive_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	dataRows := sqlmock.NewRows(killSwitchColumns).
		AddRow(sampleKillSwitchRow("ks-1", "org-001", KillSwitchScopeGlobal, true)...).
		AddRow(sampleKillSwitchRow("ks-2", "org-001", KillSwitchScopeSystem, true)...)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE org_id = $1 AND is_active = true`)).
		WithArgs("org-001").
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	switches, err := repo.ListActive(ctx, "org-001")
	require.NoError(t, err)
	assert.Len(t, switches, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_ListBySystem_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	dataRows := sqlmock.NewRows(killSwitchColumns).
		AddRow(sampleKillSwitchRow("ks-1", "org-001", KillSwitchScopeSystem, true)...)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE org_id = $1 AND system_id = $2`)).
		WithArgs("org-001", "sys-001").
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	switches, err := repo.ListBySystem(ctx, "org-001", "sys-001")
	require.NoError(t, err)
	assert.Len(t, switches, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_Update_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	ks := &KillSwitch{
		ID:               "ks-001",
		OrgID:            "org-001",
		Scope:            KillSwitchScopeSystem,
		SystemID:         "sys-001",
		IsActive:         false,
		FallbackBehavior: FallbackBehaviorBlockAll,
		TriggerThreshold: map[string]interface{}{},
		FallbackConfig:   map[string]interface{}{},
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE rbi_kill_switches SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Update(ctx, ks)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_Update_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	ks := &KillSwitch{
		ID:               "nonexistent",
		OrgID:            "org-001",
		Scope:            KillSwitchScopeGlobal,
		IsActive:         false,
		FallbackBehavior: FallbackBehaviorBlockAll,
		TriggerThreshold: map[string]interface{}{},
		FallbackConfig:   map[string]interface{}{},
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE rbi_kill_switches SET`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	err = repo.Update(ctx, ks)
	assert.ErrorIs(t, err, ErrKillSwitchNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_Delete_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM rbi_kill_switches WHERE id = $1 AND org_id = $2`)).
		WithArgs("ks-001", "org-001").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Delete(ctx, "org-001", "ks-001")
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_Delete_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM rbi_kill_switches WHERE id = $1 AND org_id = $2`)).
		WithArgs("nonexistent", "org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	err = repo.Delete(ctx, "org-001", "nonexistent")
	assert.ErrorIs(t, err, ErrKillSwitchNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_AddHistoryEntry_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	entry := &KillSwitchHistoryEntry{
		OrgID:         "org-001",
		KillSwitchID:  "ks-001",
		Action:        KillSwitchActionActivated,
		ActorID:       "admin-001",
		ActorEmail:    "admin@example.com",
		ActorRole:     "admin",
		Reason:        "Emergency stop",
		PreviousState: map[string]interface{}{"is_active": false},
		NewState:      map[string]interface{}{"is_active": true},
		Metadata:      map[string]interface{}{"source": "manual"},
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO rbi_kill_switch_history`)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	mock.ExpectCommit()

	err = repo.AddHistoryEntry(ctx, entry)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), entry.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_AddHistoryEntry_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	entry := &KillSwitchHistoryEntry{
		OrgID:        "org-001",
		KillSwitchID: "ks-001",
		Action:       KillSwitchActionActivated,
		ActorID:      "admin-001",
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO rbi_kill_switch_history`)).
		WillReturnError(fmt.Errorf("foreign key violation"))
	mock.ExpectRollback()

	err = repo.AddHistoryEntry(ctx, entry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to add history entry")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetHistory_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	dataRows := sqlmock.NewRows(historyColumns).
		AddRow(
			int64(1), "org-001", "ks-001", string(KillSwitchActionActivated),
			"admin-001",
			sql.NullString{String: "admin@example.com", Valid: true},
			sql.NullString{String: "admin", Valid: true},
			sql.NullString{String: "192.168.1.1", Valid: true},
			sql.NullString{String: "Emergency", Valid: true},
			[]byte(`{"is_active":false}`),
			[]byte(`{"is_active":true}`),
			[]byte(`{"source":"manual"}`),
			now,
		).
		AddRow(
			int64(2), "org-001", "ks-001", string(KillSwitchActionDeactivated),
			"admin-002",
			sql.NullString{String: "admin2@example.com", Valid: true},
			sql.NullString{},
			sql.NullString{},
			sql.NullString{String: "Issue resolved", Valid: true},
			[]byte(`{"is_active":true}`),
			[]byte(`{"is_active":false}`),
			[]byte(`{}`),
			now,
		)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001", "ks-001", 50).
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	entries, err := repo.GetHistory(ctx, "org-001", "ks-001", 0)
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	assert.Equal(t, KillSwitchAction("activated"), entries[0].Action)
	assert.Equal(t, "admin-001", entries[0].ActorID)
	assert.Equal(t, "admin@example.com", entries[0].ActorEmail)
	assert.Equal(t, "admin", entries[0].ActorRole)
	assert.Equal(t, "192.168.1.1", entries[0].ActorIP)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_GetHistory_LimitCapping(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001", "ks-001", 100).
		WillReturnRows(sqlmock.NewRows(historyColumns))
	mock.ExpectCommit()

	entries, err := repo.GetHistory(ctx, "org-001", "ks-001", 999)
	require.NoError(t, err)
	assert.Empty(t, entries)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_CheckActive_GlobalFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(killSwitchColumns).
		AddRow(sampleKillSwitchRow("ks-global", "org-001", KillSwitchScopeGlobal, true)...)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`scope = 'global' AND is_active = true`)).
		WithArgs("org-001").
		WillReturnRows(rows)
	mock.ExpectCommit()

	active, ks, err := repo.CheckActive(ctx, "org-001", KillSwitchScopeModel, "sys-001", "model-v2")
	require.NoError(t, err)
	assert.True(t, active)
	assert.NotNil(t, ks)
	assert.Equal(t, "ks-global", ks.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_CheckActive_SystemFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Global not found
	mock.ExpectQuery(regexp.QuoteMeta(`scope = 'global' AND is_active = true`)).
		WithArgs("org-001").
		WillReturnError(sql.ErrNoRows)

	// System found
	rows := sqlmock.NewRows(killSwitchColumns).
		AddRow(sampleKillSwitchRow("ks-sys", "org-001", KillSwitchScopeSystem, true)...)

	mock.ExpectQuery(regexp.QuoteMeta(`scope = 'system' AND system_id = $2 AND is_active = true`)).
		WithArgs("org-001", "sys-001").
		WillReturnRows(rows)
	mock.ExpectCommit()

	active, ks, err := repo.CheckActive(ctx, "org-001", KillSwitchScopeModel, "sys-001", "model-v2")
	require.NoError(t, err)
	assert.True(t, active)
	assert.NotNil(t, ks)
	assert.Equal(t, "ks-sys", ks.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_CheckActive_NoneFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Global not found
	mock.ExpectQuery(regexp.QuoteMeta(`scope = 'global' AND is_active = true`)).
		WithArgs("org-001").
		WillReturnError(sql.ErrNoRows)

	// System not found
	mock.ExpectQuery(regexp.QuoteMeta(`scope = 'system' AND system_id = $2 AND is_active = true`)).
		WithArgs("org-001", "sys-001").
		WillReturnError(sql.ErrNoRows)

	// Specific not found
	mock.ExpectQuery(regexp.QuoteMeta(`scope = $2 AND system_id = $3 AND target_identifier = $4 AND is_active = true`)).
		WithArgs("org-001", string(KillSwitchScopeModel), "sys-001", "model-v2").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()

	active, ks, err := repo.CheckActive(ctx, "org-001", KillSwitchScopeModel, "sys-001", "model-v2")
	require.NoError(t, err)
	assert.False(t, active)
	assert.Nil(t, ks)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestKillSwitchRepository_CheckActive_NoSystemID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Global not found
	mock.ExpectQuery(regexp.QuoteMeta(`scope = 'global' AND is_active = true`)).
		WithArgs("org-001").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()

	// No system check because systemID is empty
	active, ks, err := repo.CheckActive(ctx, "org-001", KillSwitchScopeGlobal, "", "")
	require.NoError(t, err)
	assert.False(t, active)
	assert.Nil(t, ks)
	assert.NoError(t, mock.ExpectationsWereMet())
}
