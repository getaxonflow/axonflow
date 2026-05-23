// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"axonflow/platform/shared/idempotency"

	"github.com/DATA-DOG/go-sqlmock"
)

// fakeIdempotencyStore lets the test inject a hit/miss decision without
// standing up a real Postgres testcontainer. We don't use the actual
// Store because Lookup/Store touch real DB connections; for the wrap
// integration test we only care that auditToolCallHandler invokes Wrap
// against orchIdempStore at the right point in its flow.
//
// To avoid forking the idempotency package interface for tests, we install
// a real idempotency.Store backed by sqlmock with the SELECT short-circuit
// path stubbed for both miss + hit cases.

func TestAuditToolCallHandler_IdempotencyKey_HitReplaysCachedResponse(t *testing.T) {
	// Save + restore globals
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()
	origStore := orchIdempStore
	defer func() { orchIdempStore = origStore }()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	orchIdempStore = idempotency.NewStore(db, nil)

	// Cache hit: WithOrgAndTenantScope's three set_config calls + the
	// SELECT that returns the cached body.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("test-client").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs("test-client").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id'`).
		WithArgs("test-client").
		WillReturnResult(sqlmock.NewResult(0, 0))
	cachedBody := []byte(`{"audit_id":"cached_audit_id","status":"recorded","timestamp":"2026-05-23T01:00:00Z"}`)
	mock.ExpectQuery(`SELECT status_code, response_body, created_at, expires_at\s*FROM idempotency_keys`).
		WithArgs("dedup-key-1", "test-client", "audit.tool-call").
		WillReturnRows(sqlmock.NewRows([]string{"status_code", "response_body", "created_at", "expires_at"}).
			AddRow(201, cachedBody, time.Now().Add(-1*time.Hour), time.Now().Add(23*time.Hour)))
	mock.ExpectCommit()

	body, _ := json.Marshal(map[string]interface{}{"tool_name": "anyTool"})
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "dedup-key-1")
	setBasicAuth(req)

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != 201 {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("missing Idempotent-Replayed header")
	}
	var got map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("body unmarshal: %v", err)
	}
	if got["audit_id"] != "cached_audit_id" {
		t.Errorf("audit_id=%v want cached_audit_id", got["audit_id"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("mock: %v", err)
	}
}

// TestAuditToolCallHandler_IdempotencyKey_NoHeaderPassesThrough confirms
// the handler runs unmodified when no Idempotency-Key is present (the
// large existing test suite at audit_tool_call_handler_test.go already
// covers the un-keyed path, but pinning it explicitly here protects
// against regression of the gate logic.)
func TestAuditToolCallHandler_IdempotencyKey_NoHeaderPassesThrough(t *testing.T) {
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()
	origStore := orchIdempStore
	defer func() { orchIdempStore = origStore }()
	orchIdempStore = nil

	body, _ := json.Marshal(map[string]interface{}{"tool_name": "anyTool"})
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != 201 {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Idempotent-Replayed") != "" {
		t.Fatalf("Idempotent-Replayed must NOT be set on the no-header pass-through")
	}
}

// Ensure context import isn't unused if test scaffolding evolves.
var _ = context.Background
