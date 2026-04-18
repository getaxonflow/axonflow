// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - Circuit Breaker Tests

//go:build enterprise

package circuitbreaker

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestNew(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)

	// Test with default config
	cb := New(repo, Config{})
	if cb.config.DefaultTimeout != 30*time.Minute {
		t.Errorf("Expected default timeout 30m, got %v", cb.config.DefaultTimeout)
	}
	if cb.config.MaxTimeout != 24*time.Hour {
		t.Errorf("Expected max timeout 24h, got %v", cb.config.MaxTimeout)
	}
	if cb.config.ErrorThreshold != 10 {
		t.Errorf("Expected error threshold 10, got %d", cb.config.ErrorThreshold)
	}
	if cb.config.PolicyViolationThreshold != 5 {
		t.Errorf("Expected policy violation threshold 5, got %d", cb.config.PolicyViolationThreshold)
	}

	// Test with custom config
	cb = New(repo, Config{
		DefaultTimeout:           1 * time.Hour,
		MaxTimeout:               48 * time.Hour,
		ErrorThreshold:           20,
		PolicyViolationThreshold: 10,
	})
	if cb.config.DefaultTimeout != 1*time.Hour {
		t.Errorf("Expected custom default timeout 1h, got %v", cb.config.DefaultTimeout)
	}
	if cb.config.MaxTimeout != 48*time.Hour {
		t.Errorf("Expected custom max timeout 48h, got %v", cb.config.MaxTimeout)
	}
}

func TestTrip_Validation(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	tests := []struct {
		name    string
		input   TripInput
		wantErr string
	}{
		{
			name:    "missing org_id",
			input:   TripInput{},
			wantErr: "org_id is required",
		},
		{
			name: "missing tripped_by",
			input: TripInput{
				OrgID: "org-1",
			},
			wantErr: "tripped_by is required for audit trail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cb.Trip(ctx, tt.input)
			if err == nil {
				t.Errorf("Expected error containing %q, got nil", tt.wantErr)
				return
			}
			if err.Error() != tt.wantErr {
				t.Errorf("Expected error %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestTrip_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	circuit, err := cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		Scope:     ScopeGlobal,
		Reason:    ReasonManual,
		TrippedBy: "user-1",
		Comment:   "Emergency stop",
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if circuit.State != StateOpen {
		t.Errorf("Expected state 'open', got %s", circuit.State)
	}
	if circuit.OrgID != "org-1" {
		t.Errorf("Expected org_id 'org-1', got %s", circuit.OrgID)
	}
	if circuit.Scope != ScopeGlobal {
		t.Errorf("Expected scope 'global', got %s", circuit.Scope)
	}
	if circuit.TripReason != ReasonManual {
		t.Errorf("Expected reason 'manual', got %s", circuit.TripReason)
	}
	if circuit.TrippedBy != "user-1" {
		t.Errorf("Expected tripped_by 'user-1', got %s", circuit.TrippedBy)
	}
}

func TestTrip_WithDuration(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{MaxTimeout: 24 * time.Hour})
	ctx := context.Background()

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	circuit, err := cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		TrippedBy: "user-1",
		Duration:  1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if circuit.ExpiresAt == nil {
		t.Error("Expected expires_at to be set")
		return
	}

	expectedExpiry := time.Now().Add(1 * time.Hour)
	if circuit.ExpiresAt.Before(expectedExpiry.Add(-time.Minute)) || circuit.ExpiresAt.After(expectedExpiry.Add(time.Minute)) {
		t.Errorf("Expected expires_at around %v, got %v", expectedExpiry, circuit.ExpiresAt)
	}
}

func TestTrip_MaxTimeoutEnforced(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{MaxTimeout: 1 * time.Hour}) // 1 hour max
	ctx := context.Background()

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	circuit, err := cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		TrippedBy: "user-1",
		Duration:  48 * time.Hour, // Try to set 48 hours
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if circuit.ExpiresAt == nil {
		t.Error("Expected expires_at to be set")
		return
	}

	// Should be capped at 1 hour
	expectedExpiry := time.Now().Add(1 * time.Hour)
	if circuit.ExpiresAt.Before(expectedExpiry.Add(-time.Minute)) || circuit.ExpiresAt.After(expectedExpiry.Add(time.Minute)) {
		t.Errorf("Expected expires_at capped to ~1h, got %v", circuit.ExpiresAt)
	}
}

func TestReset_Validation(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	tests := []struct {
		name    string
		input   ResetInput
		wantErr string
	}{
		{
			name:    "missing org_id",
			input:   ResetInput{},
			wantErr: "org_id is required",
		},
		{
			name: "missing reset_by",
			input: ResetInput{
				OrgID: "org-1",
			},
			wantErr: "reset_by is required for audit trail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cb.Reset(ctx, tt.input)
			if err == nil {
				t.Errorf("Expected error containing %q, got nil", tt.wantErr)
				return
			}
			if err.Error() != tt.wantErr {
				t.Errorf("Expected error %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestReset_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	// First trip the circuit
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	_, err = cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		TrippedBy: "user-1",
	})
	if err != nil {
		t.Fatalf("Failed to trip: %v", err)
	}

	// Then reset it
	mock.ExpectExec("UPDATE circuit_breaker").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = cb.Reset(ctx, ResetInput{
		OrgID:   "org-1",
		ResetBy: "user-2",
	})
	if err != nil {
		t.Fatalf("Failed to reset: %v", err)
	}
}

func TestCheck_AllowedWhenClosed(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	// No circuits tripped
	result, err := cb.Check(ctx, CheckInput{
		OrgID:    "org-1",
		TenantID: "tenant-1",
		ClientID: "client-1",
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Error("Expected request to be allowed when no circuits are open")
	}
}

func TestCheck_BlockedWhenOpen(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	// Trip the circuit
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	_, err = cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		Scope:     ScopeGlobal,
		TrippedBy: "user-1",
		Comment:   "Test emergency stop",
	})
	if err != nil {
		t.Fatalf("Failed to trip: %v", err)
	}

	// Check should block
	result, err := cb.Check(ctx, CheckInput{
		OrgID:    "org-1",
		TenantID: "tenant-1",
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("Expected request to be blocked when global circuit is open")
	}
	if result.Scope != ScopeGlobal {
		t.Errorf("Expected blocking scope to be 'global', got %s", result.Scope)
	}
	if result.Comment != "Test emergency stop" {
		t.Errorf("Expected comment 'Test emergency stop', got %s", result.Comment)
	}
}

func TestCheck_ScopeHierarchy(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	// Trip at client scope
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	_, err = cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		Scope:     ScopeClient,
		ScopeID:   "client-1",
		TrippedBy: "user-1",
	})
	if err != nil {
		t.Fatalf("Failed to trip: %v", err)
	}

	// Request for client-1 should be blocked
	result, err := cb.Check(ctx, CheckInput{
		OrgID:    "org-1",
		TenantID: "tenant-1",
		ClientID: "client-1",
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("Expected client-1 request to be blocked")
	}
	if result.Scope != ScopeClient {
		t.Errorf("Expected blocking scope 'client', got %s", result.Scope)
	}

	// Request for client-2 should be allowed
	result, err = cb.Check(ctx, CheckInput{
		OrgID:    "org-1",
		TenantID: "tenant-1",
		ClientID: "client-2",
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("Expected client-2 request to be allowed")
	}
}

func TestIsAllowed(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	// Should be allowed with no circuits
	if !cb.IsAllowed(ctx, "org-1", "tenant-1", "client-1") {
		t.Error("Expected IsAllowed to return true when no circuits are open")
	}
}

func TestSetTripCallback(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	callbackCalled := make(chan bool, 1)
	var receivedEvent *TripEvent

	cb.SetTripCallback(func(event *TripEvent) {
		receivedEvent = event
		callbackCalled <- true
	})

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	_, err = cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		Scope:     ScopeGlobal,
		TrippedBy: "user-1",
		Comment:   "Test callback",
	})
	if err != nil {
		t.Fatalf("Failed to trip: %v", err)
	}

	// Wait for callback
	select {
	case <-callbackCalled:
		// OK
	case <-time.After(1 * time.Second):
		t.Fatal("Callback was not called within timeout")
	}

	if receivedEvent == nil {
		t.Fatal("Callback event is nil")
	}
	if receivedEvent.OrgID != "org-1" {
		t.Errorf("Expected org_id 'org-1', got %s", receivedEvent.OrgID)
	}
	if receivedEvent.Scope != ScopeGlobal {
		t.Errorf("Expected scope 'global', got %s", receivedEvent.Scope)
	}
}

func TestCircuitKey(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})

	tests := []struct {
		orgID    string
		scope    Scope
		scopeID  string
		expected string
	}{
		{"org-1", ScopeGlobal, "", "org-1:global:"},
		{"org-1", ScopeTenant, "tenant-1", "org-1:tenant:tenant-1"},
		{"org-1", ScopeClient, "client-1", "org-1:client:client-1"},
		{"org-1", ScopePolicy, "policy-1", "org-1:policy:policy-1"},
	}

	for _, tt := range tests {
		result := cb.circuitKey(tt.orgID, tt.scope, tt.scopeID)
		if result != tt.expected {
			t.Errorf("circuitKey(%s, %s, %s) = %s, want %s",
				tt.orgID, tt.scope, tt.scopeID, result, tt.expected)
		}
	}
}

func TestStateConstants(t *testing.T) {
	// Verify state string values
	if StateClosed != "closed" {
		t.Errorf("Expected StateClosed='closed', got %s", StateClosed)
	}
	if StateOpen != "open" {
		t.Errorf("Expected StateOpen='open', got %s", StateOpen)
	}
	if StateHalfOpen != "half_open" {
		t.Errorf("Expected StateHalfOpen='half_open', got %s", StateHalfOpen)
	}
}

func TestTripReasonConstants(t *testing.T) {
	// Verify reason string values
	if ReasonManual != "manual" {
		t.Errorf("Expected ReasonManual='manual', got %s", ReasonManual)
	}
	if ReasonAutomatic != "automatic" {
		t.Errorf("Expected ReasonAutomatic='automatic', got %s", ReasonAutomatic)
	}
	if ReasonPolicy != "policy_violation" {
		t.Errorf("Expected ReasonPolicy='policy_violation', got %s", ReasonPolicy)
	}
	if ReasonRiskLevel != "risk_level" {
		t.Errorf("Expected ReasonRiskLevel='risk_level', got %s", ReasonRiskLevel)
	}
	if ReasonError != "error_rate" {
		t.Errorf("Expected ReasonError='error_rate', got %s", ReasonError)
	}
}

func TestScopeConstants(t *testing.T) {
	// Verify scope string values
	if ScopeGlobal != "global" {
		t.Errorf("Expected ScopeGlobal='global', got %s", ScopeGlobal)
	}
	if ScopeTenant != "tenant" {
		t.Errorf("Expected ScopeTenant='tenant', got %s", ScopeTenant)
	}
	if ScopeClient != "client" {
		t.Errorf("Expected ScopeClient='client', got %s", ScopeClient)
	}
	if ScopePolicy != "policy" {
		t.Errorf("Expected ScopePolicy='policy', got %s", ScopePolicy)
	}
}
