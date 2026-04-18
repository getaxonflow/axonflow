// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - Circuit Breaker Repository Tests

//go:build enterprise

package circuitbreaker

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRepository_CreateCircuit_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	circuit := &Circuit{
		ID:             "circuit-1",
		OrgID:          "org-1",
		Scope:          ScopeGlobal,
		ScopeID:        "",
		State:          StateOpen,
		TripReason:     ReasonManual,
		TrippedBy:      "user-1",
		TrippedByEmail: "user@example.com",
		TripComment:    "Test trip",
		TrippedAt:      &now,
		ExpiresAt:      nil,
		ErrorCount:     0,
		ViolationCount: 0,
	}

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WithArgs(
			circuit.ID, circuit.OrgID, circuit.Scope, circuit.ScopeID, circuit.State,
			circuit.TripReason, circuit.TrippedBy,
			sqlmock.AnyArg(), sqlmock.AnyArg(), // TrippedByEmail, TripComment
			circuit.TrippedAt, circuit.ExpiresAt, circuit.ErrorCount, circuit.ViolationCount,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.CreateCircuit(ctx, circuit)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_CreateCircuit_WithExpiry(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	expiresAt := now.Add(1 * time.Hour)
	circuit := &Circuit{
		ID:          "circuit-1",
		OrgID:       "org-1",
		Scope:       ScopeGlobal,
		ScopeID:     "",
		State:       StateOpen,
		TripReason:  ReasonManual,
		TrippedBy:   "user-1",
		TrippedAt:   &now,
		ExpiresAt:   &expiresAt,
		ErrorCount:  0,
		ViolationCount: 0,
	}

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.CreateCircuit(ctx, circuit)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}
}

func TestRepository_CreateCircuit_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	circuit := &Circuit{
		ID:          "circuit-1",
		OrgID:       "org-1",
		Scope:       ScopeGlobal,
		State:       StateOpen,
		TripReason:  ReasonManual,
		TrippedBy:   "user-1",
		TrippedAt:   &now,
		ErrorCount:  0,
		ViolationCount: 0,
	}

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnError(sql.ErrConnDone)

	err = repo.CreateCircuit(ctx, circuit)
	if err == nil {
		t.Error("Expected error from CreateCircuit")
	}
}

func TestRepository_ResetCircuit_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectExec("UPDATE circuit_breaker").
		WithArgs("user-2", "org-1", ScopeGlobal, "").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.ResetCircuit(ctx, "org-1", ScopeGlobal, "", "user-2")
	if err != nil {
		t.Fatalf("ResetCircuit failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_ResetCircuit_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectExec("UPDATE circuit_breaker").
		WillReturnError(sql.ErrConnDone)

	err = repo.ResetCircuit(ctx, "org-1", ScopeGlobal, "", "user-1")
	if err == nil {
		t.Error("Expected error from ResetCircuit")
	}
}

func TestRepository_GetActiveCircuits_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"id", "org_id", "scope", "scope_id", "state",
		"trip_reason", "tripped_by", "tripped_by_email", "trip_comment",
		"tripped_at", "expires_at", "reset_by", "reset_at",
		"error_count", "violation_count", "created_at", "updated_at",
	}).
		AddRow(
			"circuit-1", "org-1", "global", "", "open",
			"manual", "user-1", "user@example.com", "Test",
			now, nil, nil, nil,
			0, 0, now, now,
		).
		AddRow(
			"circuit-2", "org-1", "tenant", "tenant-1", "open",
			"automatic", "system", nil, nil,
			now, now.Add(time.Hour), nil, nil,
			5, 0, now, now,
		)

	mock.ExpectQuery("SELECT").
		WithArgs("org-1").
		WillReturnRows(rows)

	circuits, err := repo.GetActiveCircuits(ctx, "org-1")
	if err != nil {
		t.Fatalf("GetActiveCircuits failed: %v", err)
	}

	if len(circuits) != 2 {
		t.Errorf("Expected 2 circuits, got %d", len(circuits))
	}

	if circuits[0].ID != "circuit-1" {
		t.Errorf("Expected circuit ID 'circuit-1', got %s", circuits[0].ID)
	}
	if circuits[0].State != StateOpen {
		t.Errorf("Expected state 'open', got %s", circuits[0].State)
	}
	if circuits[0].TrippedByEmail != "user@example.com" {
		t.Errorf("Expected email 'user@example.com', got %s", circuits[0].TrippedByEmail)
	}

	if circuits[1].ExpiresAt == nil {
		t.Error("Expected expires_at to be set for circuit-2")
	}
}

func TestRepository_GetActiveCircuits_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectQuery("SELECT").
		WithArgs("org-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "scope", "scope_id", "state",
			"trip_reason", "tripped_by", "tripped_by_email", "trip_comment",
			"tripped_at", "expires_at", "reset_by", "reset_at",
			"error_count", "violation_count", "created_at", "updated_at",
		}))

	circuits, err := repo.GetActiveCircuits(ctx, "org-1")
	if err != nil {
		t.Fatalf("GetActiveCircuits failed: %v", err)
	}

	if len(circuits) != 0 {
		t.Errorf("Expected 0 circuits, got %d", len(circuits))
	}
}

func TestRepository_GetActiveCircuits_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectQuery("SELECT").
		WillReturnError(sql.ErrConnDone)

	_, err = repo.GetActiveCircuits(ctx, "org-1")
	if err == nil {
		t.Error("Expected error from GetActiveCircuits")
	}
}

func TestRepository_GetCircuitHistory_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	now := time.Now()
	resetAt := now.Add(time.Hour)
	rows := sqlmock.NewRows([]string{
		"id", "org_id", "scope", "scope_id", "state",
		"trip_reason", "tripped_by", "tripped_by_email", "trip_comment",
		"tripped_at", "expires_at", "reset_by", "reset_at",
		"error_count", "violation_count", "created_at", "updated_at",
	}).
		AddRow(
			"circuit-1", "org-1", "global", "", "closed",
			"manual", "user-1", "user@example.com", "Test",
			now, nil, "user-2", resetAt,
			0, 0, now, now,
		)

	mock.ExpectQuery("SELECT").
		WithArgs("org-1", 10).
		WillReturnRows(rows)

	circuits, err := repo.GetCircuitHistory(ctx, "org-1", 10)
	if err != nil {
		t.Fatalf("GetCircuitHistory failed: %v", err)
	}

	if len(circuits) != 1 {
		t.Errorf("Expected 1 circuit, got %d", len(circuits))
	}

	if circuits[0].State != StateClosed {
		t.Errorf("Expected state 'closed', got %s", circuits[0].State)
	}
	if circuits[0].ResetBy != "user-2" {
		t.Errorf("Expected reset_by 'user-2', got %s", circuits[0].ResetBy)
	}
	if circuits[0].ResetAt == nil {
		t.Error("Expected reset_at to be set")
	}
}

func TestRepository_GetCircuitHistory_DefaultLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectQuery("SELECT").
		WithArgs("org-1", 50). // Default limit
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "scope", "scope_id", "state",
			"trip_reason", "tripped_by", "tripped_by_email", "trip_comment",
			"tripped_at", "expires_at", "reset_by", "reset_at",
			"error_count", "violation_count", "created_at", "updated_at",
		}))

	_, err = repo.GetCircuitHistory(ctx, "org-1", 0)
	if err != nil {
		t.Fatalf("GetCircuitHistory failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_GetCircuitHistory_MaxLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectQuery("SELECT").
		WithArgs("org-1", 50). // Capped to 50
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "scope", "scope_id", "state",
			"trip_reason", "tripped_by", "tripped_by_email", "trip_comment",
			"tripped_at", "expires_at", "reset_by", "reset_at",
			"error_count", "violation_count", "created_at", "updated_at",
		}))

	_, err = repo.GetCircuitHistory(ctx, "org-1", 200)
	if err != nil {
		t.Fatalf("GetCircuitHistory failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_GetCircuitHistory_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectQuery("SELECT").
		WillReturnError(sql.ErrConnDone)

	_, err = repo.GetCircuitHistory(ctx, "org-1", 10)
	if err == nil {
		t.Error("Expected error from GetCircuitHistory")
	}
}

func TestScanCircuits_ScanError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	// Return row with wrong type (string instead of int for error_count)
	rows := sqlmock.NewRows([]string{
		"id", "org_id", "scope", "scope_id", "state",
		"trip_reason", "tripped_by", "tripped_by_email", "trip_comment",
		"tripped_at", "expires_at", "reset_by", "reset_at",
		"error_count", "violation_count", "created_at", "updated_at",
	}).
		AddRow(
			"circuit-1", "org-1", "global", "", "open",
			"manual", "user-1", nil, nil,
			time.Now(), nil, nil, nil,
			"invalid", 0, time.Now(), time.Now(), // error_count should be int
		)

	mock.ExpectQuery("SELECT").
		WillReturnRows(rows)

	_, err = repo.GetActiveCircuits(ctx, "org-1")
	if err == nil {
		t.Error("Expected scan error from malformed row")
	}
}

func TestNullString_EmptyString(t *testing.T) {
	result := nullString("")
	if result.Valid {
		t.Error("Expected Valid=false for empty string")
	}
	if result.String != "" {
		t.Errorf("Expected empty String, got %s", result.String)
	}
}

func TestNullString_NonEmptyString(t *testing.T) {
	result := nullString("test")
	if !result.Valid {
		t.Error("Expected Valid=true for non-empty string")
	}
	if result.String != "test" {
		t.Errorf("Expected String='test', got %s", result.String)
	}
}

func TestRepository_CreateCircuit_OnConflictUpdate(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	circuit := &Circuit{
		ID:          "circuit-1",
		OrgID:       "org-1",
		Scope:       ScopeGlobal,
		ScopeID:     "",
		State:       StateOpen,
		TripReason:  ReasonManual,
		TrippedBy:   "user-1",
		TrippedAt:   &now,
		ErrorCount:  5,
		ViolationCount: 3,
	}

	// ON CONFLICT DO UPDATE should work
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.CreateCircuit(ctx, circuit)
	if err != nil {
		t.Fatalf("CreateCircuit failed: %v", err)
	}
}

func TestNewRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	if repo == nil {
		t.Error("Expected non-nil repository")
	}
	if repo.db != db {
		t.Error("Expected repository to reference the provided database")
	}
}
