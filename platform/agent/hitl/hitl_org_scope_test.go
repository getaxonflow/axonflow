// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package hitl

// #3048 R3 BLOCKER-2 unit tests (sqlmock cover; the real-PG suite in hitl_org_scope_realpg_test.go drives the same flows against live RLS):
// the service's caller-org check must reject cross-org by-id flows BEFORE
// any write, and the List filter must carry the org predicate.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func expectApprovalLookup(mock sqlmock.Sqlmock, requestID uuid.UUID, org string) {
	cols := []string{
		"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
		"original_query", "request_type", "request_context",
		"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
		"eu_ai_act_article", "compliance_framework", "risk_classification",
		"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
		"override_justification", "override_authorized_by", "notify_url",
		"expires_at", "created_at", "updated_at",
	}
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows(cols).AddRow(
			1, requestID, org, org, "client-1", nil,
			"wire 9000 EUR", "sql", nil,
			"pol-1", "High Value", "over threshold", "high",
			nil, nil, nil,
			"pending", nil, nil, nil, nil, nil,
			nil, nil, nil,
			time.Now().Add(time.Hour), time.Now(), time.Now(),
		))
}

func TestServiceCrossOrgRejected(t *testing.T) {
	requestID := uuid.New()
	reviewer := &Reviewer{ID: "rev-a", Email: "reviewer@a.example", Role: "admin"}

	newSvc := func(t *testing.T) (*Service, sqlmock.Sqlmock) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return NewService(NewRepository(db), ServiceConfig{}), mock
	}
	ctxA := WithCallerOrg(context.Background(), "org-a")

	t.Run("approve rejected before any write", func(t *testing.T) {
		svc, mock := newSvc(t)
		expectApprovalLookup(mock, requestID, "org-b") // fetched row belongs to org B
		err := svc.ApproveRequest(ctxA, requestID, reviewer, "gimme")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("SECURITY: cross-org approve not rejected as not-found (err=%v)", err)
		}
		// No UPDATE was registered — any write attempt fails the mock.
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("no write may have run: %v", err)
		}
	})

	t.Run("reject + override + get + history rejected", func(t *testing.T) {
		svc, mock := newSvc(t)
		expectApprovalLookup(mock, requestID, "org-b")
		if err := svc.RejectRequest(ctxA, requestID, reviewer, "no"); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("cross-org reject not rejected (err=%v)", err)
		}
		expectApprovalLookup(mock, requestID, "org-b")
		if err := svc.OverrideRequest(ctxA, requestID, "because", reviewer); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("cross-org override not rejected (err=%v)", err)
		}
		expectApprovalLookup(mock, requestID, "org-b")
		if _, err := svc.GetApprovalRequest(ctxA, requestID); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("cross-org get not rejected (err=%v)", err)
		}
		expectApprovalLookup(mock, requestID, "org-b")
		if _, err := svc.GetRequestHistory(ctxA, requestID); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("cross-org history not rejected (err=%v)", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("no write may have run: %v", err)
		}
	})

	// #3065 (F5): this sub-test used to be "empty caller org (internal
	// bridge) skips the check" and asserted that an org-less caller received
	// another org's approval request. rejectCrossOrg carried the fail-open
	// compare (`callerOrg != "" && req.OrgID != callerOrg`), so omitting
	// X-Org-ID skipped the isolation entirely — the same shape as the rest of
	// #3065. Every caller of these by-id flows arrives through the HTTP
	// handlers, which pass WithCallerOrg from the agent-authenticated
	// X-Org-ID; the MCP-tool bridge uses CreateRequest, which does not run
	// this check at all.
	t.Run("empty caller org is denied", func(t *testing.T) {
		svc, mock := newSvc(t)
		expectApprovalLookup(mock, requestID, "org-b")
		got, err := svc.GetApprovalRequest(context.Background(), requestID)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("an org-less caller must be denied, got req=%v err=%v", got, err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestListFilterCarriesOrgPredicate(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	repo := NewRepository(db)

	// The COUNT and SELECT must both carry the org predicate + arg.
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM hitl_approval_queue WHERE 1=1 AND org_id = \$1`).
		WithArgs("org-a").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`FROM hitl_approval_queue\s+WHERE 1=1 AND org_id = \$1`).
		WithArgs("org-a").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	if _, _, err := repo.List(context.Background(), ListFilter{OrgID: "org-a", Limit: 10}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("org predicate missing from List SQL: %v", err)
	}
}
