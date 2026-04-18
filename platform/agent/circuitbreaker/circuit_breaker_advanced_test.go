// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - Circuit Breaker Advanced Tests

//go:build enterprise

package circuitbreaker

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRecordError_AutoTrip(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{
		ErrorThreshold:     3,
		EnableAutoRecovery: true,
		DefaultTimeout:     30 * time.Minute,
	})
	ctx := context.Background()

	orgID := "org-1"
	tenantID := "tenant-1"
	clientID := "client-1"

	// Record errors below threshold
	for i := 0; i < 2; i++ {
		err := cb.RecordError(ctx, orgID, tenantID, clientID)
		if err != nil {
			t.Fatalf("RecordError failed: %v", err)
		}
	}

	// Verify not tripped yet
	result, err := cb.Check(ctx, CheckInput{
		OrgID:    orgID,
		TenantID: tenantID,
		ClientID: clientID,
	})
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !result.Allowed {
		t.Error("Expected request to be allowed before threshold")
	}

	// Record error that triggers auto-trip
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = cb.RecordError(ctx, orgID, tenantID, clientID)
	if err != nil {
		t.Fatalf("RecordError failed: %v", err)
	}

	// Verify circuit is now open
	result, err = cb.Check(ctx, CheckInput{
		OrgID:    orgID,
		TenantID: tenantID,
		ClientID: clientID,
	})
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if result.Allowed {
		t.Error("Expected request to be blocked after auto-trip")
	}
	if result.Reason != ReasonError {
		t.Errorf("Expected reason 'error_rate', got %s", result.Reason)
	}
	if result.TrippedBy != "system" {
		t.Errorf("Expected tripped_by 'system', got %s", result.TrippedBy)
	}
}

func TestRecordError_NoAutoTripWhenAlreadyOpen(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{ErrorThreshold: 2})
	ctx := context.Background()

	// Manually trip the circuit first
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	_, err = cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		Scope:     ScopeClient,
		ScopeID:   "client-1",
		TrippedBy: "user-1",
	})
	if err != nil {
		t.Fatalf("Trip failed: %v", err)
	}

	// Record errors - should not trigger another DB insert
	for i := 0; i < 5; i++ {
		err = cb.RecordError(ctx, "org-1", "tenant-1", "client-1")
		if err != nil {
			t.Fatalf("RecordError failed: %v", err)
		}
	}

	// Verify expectations (no additional inserts)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRecordPolicyViolation_AutoTrip(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{
		PolicyViolationThreshold: 3,
		EnableAutoRecovery:       true,
		DefaultTimeout:           1 * time.Hour,
	})
	ctx := context.Background()

	orgID := "org-1"
	tenantID := "tenant-1"
	clientID := "client-1"
	policyID := "policy-1"

	// Record violations below threshold
	for i := 0; i < 2; i++ {
		err := cb.RecordPolicyViolation(ctx, orgID, tenantID, clientID, policyID)
		if err != nil {
			t.Fatalf("RecordPolicyViolation failed: %v", err)
		}
	}

	// Verify not tripped yet
	result, err := cb.Check(ctx, CheckInput{
		OrgID:    orgID,
		TenantID: tenantID,
		ClientID: clientID,
		PolicyID: policyID,
	})
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !result.Allowed {
		t.Error("Expected request to be allowed before threshold")
	}

	// Record violation that triggers auto-trip
	// Expect two inserts: client-scoped circuit (blocking) + policy-scoped circuit (audit)
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = cb.RecordPolicyViolation(ctx, orgID, tenantID, clientID, policyID)
	if err != nil {
		t.Fatalf("RecordPolicyViolation failed: %v", err)
	}

	// Verify circuit is now open — Check with ClientID should block (client-scoped circuit)
	result, err = cb.Check(ctx, CheckInput{
		OrgID:    orgID,
		TenantID: tenantID,
		ClientID: clientID,
	})
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if result.Allowed {
		t.Error("Expected request to be blocked after auto-trip")
	}
	if result.Reason != ReasonPolicy {
		t.Errorf("Expected reason 'policy_violation', got %s", result.Reason)
	}
	if result.Comment == "" {
		t.Error("Expected auto-trip comment to be set")
	}
}

func TestRecordPolicyViolation_NoAutoTripWhenAlreadyOpen(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{PolicyViolationThreshold: 2})
	ctx := context.Background()

	// Manually trip the client-scoped circuit first (this is what blocks in the pipeline)
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	_, err = cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		Scope:     ScopeClient,
		ScopeID:   "client-1",
		TrippedBy: "user-1",
	})
	if err != nil {
		t.Fatalf("Trip failed: %v", err)
	}

	// Record violations - client circuit is already open, so auto-trip should NOT fire
	// (the auto-trip condition checks clientCircuit.State == StateClosed)
	for i := 0; i < 5; i++ {
		err = cb.RecordPolicyViolation(ctx, "org-1", "tenant-1", "client-1", "policy-1")
		if err != nil {
			t.Fatalf("RecordPolicyViolation failed: %v", err)
		}
	}

	// Verify expectations (no additional inserts beyond the manual trip)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestExpireCircuits(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	// Create a circuit that expires in the past
	pastExpiry := time.Now().Add(-1 * time.Hour)
	circuit := &Circuit{
		ID:        "circuit-1",
		OrgID:     "org-1",
		Scope:     ScopeGlobal,
		ScopeID:   "",
		State:     StateOpen,
		ExpiresAt: &pastExpiry,
	}

	// Add to cache
	key := cb.circuitKey(circuit.OrgID, circuit.Scope, circuit.ScopeID)
	cb.mu.Lock()
	cb.circuits[key] = circuit
	cb.mu.Unlock()

	// Expect reset call
	mock.ExpectExec("UPDATE circuit_breaker").
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Run expiry
	err = cb.ExpireCircuits(ctx)
	if err != nil {
		t.Fatalf("ExpireCircuits failed: %v", err)
	}

	// Verify circuit is removed from cache
	cb.mu.RLock()
	_, exists := cb.circuits[key]
	cb.mu.RUnlock()

	if exists {
		t.Error("Expected expired circuit to be removed from cache")
	}
}

func TestExpireCircuits_NoExpirySet(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	// Create a circuit without expiry (manual reset required)
	circuit := &Circuit{
		ID:        "circuit-1",
		OrgID:     "org-1",
		Scope:     ScopeGlobal,
		ScopeID:   "",
		State:     StateOpen,
		ExpiresAt: nil, // No expiry
	}

	// Add to cache
	key := cb.circuitKey(circuit.OrgID, circuit.Scope, circuit.ScopeID)
	cb.mu.Lock()
	cb.circuits[key] = circuit
	cb.mu.Unlock()

	// Run expiry - should not remove circuit
	err = cb.ExpireCircuits(ctx)
	if err != nil {
		t.Fatalf("ExpireCircuits failed: %v", err)
	}

	// Verify circuit is still in cache
	cb.mu.RLock()
	_, exists := cb.circuits[key]
	cb.mu.RUnlock()

	if !exists {
		t.Error("Expected circuit without expiry to remain in cache")
	}
}

func TestExpireCircuits_FutureExpiry(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	// Create a circuit that expires in the future
	futureExpiry := time.Now().Add(1 * time.Hour)
	circuit := &Circuit{
		ID:        "circuit-1",
		OrgID:     "org-1",
		Scope:     ScopeGlobal,
		ScopeID:   "",
		State:     StateOpen,
		ExpiresAt: &futureExpiry,
	}

	// Add to cache
	key := cb.circuitKey(circuit.OrgID, circuit.Scope, circuit.ScopeID)
	cb.mu.Lock()
	cb.circuits[key] = circuit
	cb.mu.Unlock()

	// Run expiry - should not remove circuit
	err = cb.ExpireCircuits(ctx)
	if err != nil {
		t.Fatalf("ExpireCircuits failed: %v", err)
	}

	// Verify circuit is still in cache
	cb.mu.RLock()
	_, exists := cb.circuits[key]
	cb.mu.RUnlock()

	if !exists {
		t.Error("Expected circuit with future expiry to remain in cache")
	}
}

func TestExpireCircuits_DBErrorContinues(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	// Create an expired circuit
	pastExpiry := time.Now().Add(-1 * time.Hour)
	circuit := &Circuit{
		ID:        "circuit-1",
		OrgID:     "org-1",
		Scope:     ScopeGlobal,
		ScopeID:   "",
		State:     StateOpen,
		ExpiresAt: &pastExpiry,
	}

	// Add to cache
	key := cb.circuitKey(circuit.OrgID, circuit.Scope, circuit.ScopeID)
	cb.mu.Lock()
	cb.circuits[key] = circuit
	cb.mu.Unlock()

	// DB reset fails
	mock.ExpectExec("UPDATE circuit_breaker").
		WillReturnError(sql.ErrConnDone)

	// Run expiry - should continue despite error
	err = cb.ExpireCircuits(ctx)
	if err != nil {
		t.Fatalf("ExpireCircuits failed: %v", err)
	}

	// Circuit should remain in cache after DB error
	cb.mu.RLock()
	_, exists := cb.circuits[key]
	cb.mu.RUnlock()

	if !exists {
		t.Error("Expected circuit to remain in cache after DB error")
	}
}

func TestLoadCircuits(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	now := time.Now()
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
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
			))

	err = cb.LoadCircuits(ctx, "org-1")
	if err != nil {
		t.Fatalf("LoadCircuits failed: %v", err)
	}

	// Verify circuits are loaded
	cb.mu.RLock()
	if len(cb.circuits) != 2 {
		t.Errorf("Expected 2 circuits, got %d", len(cb.circuits))
	}

	key1 := cb.circuitKey("org-1", ScopeGlobal, "")
	circuit1, ok := cb.circuits[key1]
	if !ok {
		t.Error("Expected global circuit to be loaded")
	} else if circuit1.State != StateOpen {
		t.Errorf("Expected state 'open', got %s", circuit1.State)
	}

	key2 := cb.circuitKey("org-1", ScopeTenant, "tenant-1")
	circuit2, ok := cb.circuits[key2]
	if !ok {
		t.Error("Expected tenant circuit to be loaded")
	} else if circuit2.ExpiresAt == nil {
		t.Error("Expected expires_at to be set")
	}
	cb.mu.RUnlock()
}

func TestCheck_ExpiredCircuit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	// Trip a circuit with expiry in the past
	pastExpiry := time.Now().Add(-1 * time.Hour)
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	circuit, err := cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		Scope:     ScopeGlobal,
		TrippedBy: "user-1",
		Duration:  1 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Trip failed: %v", err)
	}

	// Manually set expiry to the past
	cb.mu.Lock()
	circuit.ExpiresAt = &pastExpiry
	key := cb.circuitKey(circuit.OrgID, circuit.Scope, circuit.ScopeID)
	cb.circuits[key] = circuit
	cb.mu.Unlock()

	// Check should allow the request (expired circuit)
	result, err := cb.Check(ctx, CheckInput{
		OrgID:    "org-1",
		TenantID: "tenant-1",
	})
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if !result.Allowed {
		t.Error("Expected request to be allowed when circuit is expired")
	}
}

func TestGetActiveCircuits_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	mock.ExpectQuery("SELECT").
		WillReturnError(sql.ErrConnDone)

	_, err = cb.GetActiveCircuits(ctx, "org-1")
	if err == nil {
		t.Error("Expected error from GetActiveCircuits")
	}
}

func TestGetCircuitHistory_InvalidLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	// Limit 0 should default to 50
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "scope", "scope_id", "state",
			"trip_reason", "tripped_by", "tripped_by_email", "trip_comment",
			"tripped_at", "expires_at", "reset_by", "reset_at",
			"error_count", "violation_count", "created_at", "updated_at",
		}))

	_, err = cb.GetCircuitHistory(ctx, "org-1", 0)
	if err != nil {
		t.Fatalf("GetCircuitHistory failed: %v", err)
	}

	// Limit > 100 should cap to 50
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "org_id", "scope", "scope_id", "state",
			"trip_reason", "tripped_by", "tripped_by_email", "trip_comment",
			"tripped_at", "expires_at", "reset_by", "reset_at",
			"error_count", "violation_count", "created_at", "updated_at",
		}))

	_, err = cb.GetCircuitHistory(ctx, "org-1", 200)
	if err != nil {
		t.Fatalf("GetCircuitHistory failed: %v", err)
	}
}

func TestTrip_DefaultScope(t *testing.T) {
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

	// Trip without specifying scope
	circuit, err := cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		TrippedBy: "user-1",
	})
	if err != nil {
		t.Fatalf("Trip failed: %v", err)
	}

	if circuit.Scope != ScopeGlobal {
		t.Errorf("Expected default scope 'global', got %s", circuit.Scope)
	}
}

func TestTrip_DefaultReason(t *testing.T) {
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

	// Trip without specifying reason
	circuit, err := cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		TrippedBy: "user-1",
	})
	if err != nil {
		t.Fatalf("Trip failed: %v", err)
	}

	if circuit.TripReason != ReasonManual {
		t.Errorf("Expected default reason 'manual', got %s", circuit.TripReason)
	}
}

func TestCheck_SkipsEmptyScopeIDs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	// Trip at tenant scope
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	_, err = cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		Scope:     ScopeTenant,
		ScopeID:   "tenant-1",
		TrippedBy: "user-1",
	})
	if err != nil {
		t.Fatalf("Trip failed: %v", err)
	}

	// Check without tenant_id should skip tenant scope check
	result, err := cb.Check(ctx, CheckInput{
		OrgID:    "org-1",
		ClientID: "client-1", // Only client ID provided
	})
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if !result.Allowed {
		t.Error("Expected request to be allowed when tenant_id is not provided")
	}
}

// --- Sliding window unit tests ---

func TestEventWindow_Record(t *testing.T) {
	w := &eventWindow{maxSize: 10}
	now := time.Now()

	w.record(now)
	w.record(now.Add(1 * time.Second))
	w.record(now.Add(2 * time.Second))

	if len(w.timestamps) != 3 {
		t.Errorf("Expected 3 timestamps, got %d", len(w.timestamps))
	}
}

func TestEventWindow_CountInWindow(t *testing.T) {
	w := &eventWindow{maxSize: 20}
	now := time.Now()

	w.record(now.Add(-10 * time.Minute)) // outside 5min window
	w.record(now.Add(-6 * time.Minute))  // outside 5min window
	w.record(now.Add(-4 * time.Minute))  // inside
	w.record(now.Add(-2 * time.Minute))  // inside
	w.record(now)                         // inside

	count := w.countInWindow(now, 5*time.Minute)
	if count != 3 {
		t.Errorf("Expected 3 events in window, got %d", count)
	}

	// Verify expired entries were compacted
	if len(w.timestamps) != 3 {
		t.Errorf("Expected 3 timestamps after compaction, got %d", len(w.timestamps))
	}
}

func TestEventWindow_MaxSizeCap(t *testing.T) {
	w := &eventWindow{maxSize: 5}
	now := time.Now()

	for i := 0; i < 10; i++ {
		w.record(now.Add(time.Duration(i) * time.Second))
	}

	if len(w.timestamps) != 5 {
		t.Errorf("Expected 5 timestamps (capped), got %d", len(w.timestamps))
	}
}

func TestEventWindow_EmptyWindow(t *testing.T) {
	w := &eventWindow{maxSize: 10}
	count := w.countInWindow(time.Now(), 5*time.Minute)
	if count != 0 {
		t.Errorf("Expected 0 for empty window, got %d", count)
	}
}

func TestEventWindow_AllExpired(t *testing.T) {
	w := &eventWindow{maxSize: 10}
	past := time.Now().Add(-1 * time.Hour)

	w.record(past)
	w.record(past.Add(1 * time.Second))

	count := w.countInWindow(time.Now(), 5*time.Minute)
	if count != 0 {
		t.Errorf("Expected 0 (all expired), got %d", count)
	}
	if len(w.timestamps) != 0 {
		t.Errorf("Expected 0 timestamps after full compaction, got %d", len(w.timestamps))
	}
}

func TestRecordError_WindowExpiry(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()
	repo := NewRepository(db)

	cb := New(repo, Config{
		ErrorThreshold:        3,
		PolicyViolationWindow: 5 * time.Minute,
		EnableAutoRecovery:    true,
	})

	// Simulate old errors by pre-populating the window
	key := cb.circuitKey("org-1", ScopeClient, "client-1")
	w := &eventWindow{maxSize: 6}
	past := time.Now().Add(-10 * time.Minute)
	w.record(past)
	w.record(past.Add(1 * time.Second))
	cb.errorWindows[key] = w

	// Add one recent error — should NOT trip (old ones outside window)
	if err := cb.RecordError(context.Background(), "org-1", "tenant-1", "client-1"); err != nil {
		t.Fatalf("RecordError failed: %v", err)
	}

	circuit := cb.circuits[key]
	if circuit.State != StateClosed {
		t.Errorf("Expected circuit to remain closed (old errors expired), got %s", circuit.State)
	}
	if circuit.ErrorCount != 1 {
		t.Errorf("Expected windowed error count 1, got %d", circuit.ErrorCount)
	}
}

func TestRecordError_FiresTripCallback(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()
	repo := NewRepository(db)
	cb := New(repo, Config{
		ErrorThreshold:        3,
		PolicyViolationWindow: 5 * time.Minute,
		EnableAutoRecovery:    true,
	})
	ctx := context.Background()

	var callbackFired bool
	var callbackEvent *TripEvent
	var mu sync.Mutex
	done := make(chan struct{})

	cb.SetTripCallback(func(event *TripEvent) {
		mu.Lock()
		callbackFired = true
		callbackEvent = event
		mu.Unlock()
		close(done)
	})

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	for i := 0; i < 3; i++ {
		if err := cb.RecordError(ctx, "org-1", "tenant-1", "client-1"); err != nil {
			t.Fatalf("RecordError %d failed: %v", i+1, err)
		}
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for trip callback")
	}

	mu.Lock()
	defer mu.Unlock()
	if !callbackFired {
		t.Error("Expected trip callback to fire on auto-trip")
	}
	if callbackEvent.Reason != ReasonError {
		t.Errorf("Expected callback reason error_rate, got %s", callbackEvent.Reason)
	}
	if callbackEvent.OrgID != "org-1" {
		t.Errorf("Expected callback orgID org-1, got %s", callbackEvent.OrgID)
	}
}

func TestRecordPolicyViolation_WindowExpiry(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()
	repo := NewRepository(db)

	cb := New(repo, Config{
		PolicyViolationThreshold: 3,
		PolicyViolationWindow:    5 * time.Minute,
		EnableAutoRecovery:       true,
	})

	// Simulate old violations
	clientKey := cb.circuitKey("org-1", ScopeClient, "client-1")
	w := &eventWindow{maxSize: 6}
	past := time.Now().Add(-10 * time.Minute)
	w.record(past)
	w.record(past.Add(1 * time.Second))
	cb.violationWindows[clientKey] = w

	policyKey := cb.circuitKey("org-1", ScopePolicy, "policy-1")
	pw := &eventWindow{maxSize: 6}
	pw.record(past)
	pw.record(past.Add(1 * time.Second))
	cb.violationWindows[policyKey] = pw

	if err := cb.RecordPolicyViolation(context.Background(), "org-1", "tenant-1", "client-1", "policy-1"); err != nil {
		t.Fatalf("RecordPolicyViolation failed: %v", err)
	}

	circuit := cb.circuits[clientKey]
	if circuit.State != StateClosed {
		t.Errorf("Expected circuit to remain closed, got %s", circuit.State)
	}
	if circuit.ViolationCount != 1 {
		t.Errorf("Expected windowed violation count 1, got %d", circuit.ViolationCount)
	}
}

func TestRecordPolicyViolation_FiresTripCallback(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()
	repo := NewRepository(db)
	cb := New(repo, Config{
		PolicyViolationThreshold: 3,
		PolicyViolationWindow:    5 * time.Minute,
		EnableAutoRecovery:       true,
	})
	ctx := context.Background()

	var callbackFired bool
	var mu sync.Mutex
	done := make(chan struct{})

	cb.SetTripCallback(func(event *TripEvent) {
		mu.Lock()
		callbackFired = true
		mu.Unlock()
		close(done)
	})

	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	for i := 0; i < 3; i++ {
		if err := cb.RecordPolicyViolation(ctx, "org-1", "tenant-1", "client-1", "policy-1"); err != nil {
			t.Fatalf("RecordPolicyViolation %d failed: %v", i+1, err)
		}
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for trip callback")
	}

	mu.Lock()
	defer mu.Unlock()
	if !callbackFired {
		t.Error("Expected trip callback to fire on policy violation auto-trip")
	}
}

func TestReset_ClearsWindows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()
	repo := NewRepository(db)
	cb := New(repo, Config{
		ErrorThreshold:        3,
		PolicyViolationWindow: 5 * time.Minute,
		EnableAutoRecovery:    true,
	})
	ctx := context.Background()

	// Record some errors to populate windows
	for i := 0; i < 2; i++ {
		_ = cb.RecordError(ctx, "org-1", "tenant-1", "client-1")
	}

	key := cb.circuitKey("org-1", ScopeClient, "client-1")
	if _, ok := cb.errorWindows[key]; !ok {
		t.Fatal("Expected error window to exist before reset")
	}

	mock.ExpectExec("UPDATE circuit_breaker").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = cb.Reset(ctx, ResetInput{
		OrgID:   "org-1",
		Scope:   ScopeClient,
		ScopeID: "client-1",
		ResetBy: "admin",
	})
	if err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	if _, ok := cb.errorWindows[key]; ok {
		t.Error("Expected error window to be cleared after reset")
	}
	if _, ok := cb.violationWindows[key]; ok {
		t.Error("Expected violation window to be cleared after reset")
	}
}

func TestReset_UpdatesCache(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{})
	ctx := context.Background()

	// First trip
	mock.ExpectExec("INSERT INTO circuit_breaker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	circuit, err := cb.Trip(ctx, TripInput{
		OrgID:     "org-1",
		Scope:     ScopeGlobal,
		TrippedBy: "user-1",
	})
	if err != nil {
		t.Fatalf("Trip failed: %v", err)
	}

	// Reset
	mock.ExpectExec("UPDATE circuit_breaker").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = cb.Reset(ctx, ResetInput{
		OrgID:   "org-1",
		Scope:   ScopeGlobal,
		ResetBy: "user-2",
	})
	if err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	// Verify cache was updated
	key := cb.circuitKey("org-1", ScopeGlobal, "")
	cb.mu.RLock()
	cachedCircuit, ok := cb.circuits[key]
	cb.mu.RUnlock()

	if !ok {
		t.Error("Expected circuit to still be in cache after reset")
	} else {
		if cachedCircuit.State != StateClosed {
			t.Errorf("Expected state 'closed', got %s", cachedCircuit.State)
		}
		if cachedCircuit.ResetBy != "user-2" {
			t.Errorf("Expected reset_by 'user-2', got %s", cachedCircuit.ResetBy)
		}
		if cachedCircuit.ResetAt == nil {
			t.Error("Expected reset_at to be set")
		}
		if cachedCircuit.ID != circuit.ID {
			t.Error("Circuit ID should not change after reset")
		}
	}
}
