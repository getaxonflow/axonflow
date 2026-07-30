// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package hitl

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"axonflow/platform/agent/license"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// TestExpireStaleAcrossTenants_DispatchesWebhookForExpiredRow exercises the
// new admin-pool expire path end-to-end via sqlmock: a single stale pending
// row with notify_url set produces one outbound POST through the dispatcher.
func TestExpireStaleAcrossTenants_DispatchesWebhookForExpiredRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rec := &receivedPOST{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	repo := NewRepository(db)
	svc := NewService(repo, ServiceConfig{})
	d := NewWebhookDispatcher()
	d.setSigningKeyForTest([]byte(strings.Repeat("k", 32)))
	d.setHTTPClientForTest(srv.Client())
	svc.SetWebhookDispatcher(d)

	requestID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id, request_id, org_id, tenant_id, client_id, user_id,\s*original_query, request_type, severity, notify_url\s*FROM hitl_approval_queue\s*WHERE status = 'pending' AND expires_at < CURRENT_TIMESTAMP`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "severity", "notify_url",
		}).AddRow(
			1, requestID, "org-a", "tenant-a", "client-a", nil,
			"Disburse 5000", "payment", "high", srv.URL,
		))
	mock.ExpectExec(`UPDATE hitl_approval_queue\s*SET status = 'expired'`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO hitl_approval_history`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	n, err := svc.ExpireStaleAcrossTenants(context.Background(), db)
	if err != nil {
		t.Fatalf("ExpireStaleAcrossTenants err=%v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 expired, got %d", n)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rec.count.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rec.count.Load() != 1 {
		t.Fatalf("expected 1 expired webhook POST, got %d", rec.count.Load())
	}
	if rec.event != "hitl.expired" {
		t.Errorf("X-AxonFlow-Event=%q want hitl.expired", rec.event)
	}
	if rec.requestID != requestID.String() {
		t.Errorf("X-AxonFlow-Request-Id=%q want %q", rec.requestID, requestID.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("mock expectations: %v", err)
	}
}

// TestExpireStaleAcrossTenants_NoWebhookWhenNotifyURLEmpty covers the
// negative path — an expired row without notify_url must NOT produce a POST.
func TestExpireStaleAcrossTenants_NoWebhookWhenNotifyURLEmpty(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	repo := NewRepository(db)
	svc := NewService(repo, ServiceConfig{})
	d := NewWebhookDispatcher()
	d.setSigningKeyForTest([]byte(strings.Repeat("k", 32)))
	d.setHTTPClientForTest(srv.Client())
	svc.SetWebhookDispatcher(d)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id, request_id, org_id, tenant_id, client_id, user_id,\s*original_query, request_type, severity, notify_url\s*FROM hitl_approval_queue\s*WHERE status = 'pending' AND expires_at < CURRENT_TIMESTAMP`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "severity", "notify_url",
		}).AddRow(
			1, uuid.New(), "org-a", "tenant-a", "client-a", nil,
			"q", "t", "high", nil, // notify_url NULL
		))
	mock.ExpectExec(`UPDATE hitl_approval_queue`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO hitl_approval_history`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	n, err := svc.ExpireStaleAcrossTenants(context.Background(), db)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if n != 1 {
		t.Fatalf("count=%d", n)
	}
	time.Sleep(80 * time.Millisecond)
	if hits.Load() != 0 {
		t.Fatalf("unexpected webhook POST (count=%d)", hits.Load())
	}
}

// TestApproveRequest_LostRaceSkipsWebhook covers the R3 R1 HIGH #2 fix:
// when the WHERE-status='pending' guard catches a lost race (zero rows
// updated), the service returns ErrApprovalLostRace and does NOT call
// dispatchTerminal — so the receiver never sees a duplicate POST.
func TestApproveRequest_LostRaceSkipsWebhook(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	repo := NewRepository(db)
	svc := NewService(repo, ServiceConfig{})
	svc.SetTierProviderForTest(func(_ context.Context) license.Tier { return license.TierEnterprise })
	d := NewWebhookDispatcher()
	d.setSigningKeyForTest([]byte(strings.Repeat("k", 32)))
	d.setHTTPClientForTest(srv.Client())
	svc.SetWebhookDispatcher(d)

	requestID := uuid.New()
	now := time.Now()

	// GetByRequestID returns a pending row with notify_url set so
	// dispatchTerminal WOULD fire if not skipped on lost-race.
	mock.ExpectQuery("SELECT").
		WithArgs(requestID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by", "notify_url",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-a", "tenant-a", "client-a", nil,
			"q", "t", nil,
			"p-1", "Policy", "reason", "high",
			nil, nil, nil,
			"pending", nil, nil, nil, nil, nil,
			nil, nil, srv.URL,
			now.Add(1*time.Hour), now, now,
		))

	// UpdateStatus: 0 rows touched ⇒ lost race.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`UPDATE hitl_approval_queue.*WHERE request_id = \$6 AND status = 'pending'`).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	reviewer := &Reviewer{ID: "r1", Email: "r1@example.com"}
	err := svc.ApproveRequest(WithCallerOrg(context.Background(), "org-a"), requestID, reviewer, "ok")
	if err == nil {
		t.Fatal("expected lost-race error")
	}
	if !strings.Contains(err.Error(), "cannot approve request") {
		t.Fatalf("unexpected error: %v", err)
	}

	time.Sleep(80 * time.Millisecond)
	if hits.Load() != 0 {
		t.Fatalf("dispatchTerminal fired on lost-race (count=%d) — duplicate webhook would have hit receiver", hits.Load())
	}
}

// TestRejectRequest_LostRaceSkipsWebhook mirrors the Approve test for the
// reject path — separate dispatchTerminal call site, separate regression
// risk.
func TestRejectRequest_LostRaceSkipsWebhook(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	repo := NewRepository(db)
	svc := NewService(repo, ServiceConfig{})
	svc.SetTierProviderForTest(func(_ context.Context) license.Tier { return license.TierEnterprise })
	d := NewWebhookDispatcher()
	d.setSigningKeyForTest([]byte(strings.Repeat("k", 32)))
	d.setHTTPClientForTest(srv.Client())
	svc.SetWebhookDispatcher(d)

	requestID := uuid.New()
	now := time.Now()
	mock.ExpectQuery("SELECT").
		WithArgs(requestID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by", "notify_url",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-a", "tenant-a", "client-a", nil,
			"q", "t", nil, "p-1", "Policy", "reason", "high",
			nil, nil, nil,
			"pending", nil, nil, nil, nil, nil,
			nil, nil, srv.URL,
			now.Add(1*time.Hour), now, now,
		))
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`UPDATE hitl_approval_queue.*WHERE request_id = \$6 AND status = 'pending'`).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	err := svc.RejectRequest(WithCallerOrg(context.Background(), "org-a"), requestID, &Reviewer{ID: "r1", Email: "r1@example.com"}, "no")
	if err == nil || !strings.Contains(err.Error(), "cannot reject request") {
		t.Fatalf("unexpected error: %v", err)
	}
	time.Sleep(80 * time.Millisecond)
	if hits.Load() != 0 {
		t.Fatalf("dispatchTerminal fired on reject lost-race (count=%d)", hits.Load())
	}
}

// TestOverrideRequest_LostRaceSkipsWebhook mirrors the Approve test for the
// override path.
func TestOverrideRequest_LostRaceSkipsWebhook(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	repo := NewRepository(db)
	svc := NewService(repo, ServiceConfig{})
	svc.SetTierProviderForTest(func(_ context.Context) license.Tier { return license.TierEnterprise })
	d := NewWebhookDispatcher()
	d.setSigningKeyForTest([]byte(strings.Repeat("k", 32)))
	d.setHTTPClientForTest(srv.Client())
	svc.SetWebhookDispatcher(d)

	requestID := uuid.New()
	now := time.Now()
	mock.ExpectQuery("SELECT").
		WithArgs(requestID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by", "notify_url",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-a", "tenant-a", "client-a", nil,
			"q", "t", nil, "p-1", "Policy", "reason", "high",
			nil, nil, nil,
			"pending", nil, nil, nil, nil, nil,
			nil, nil, srv.URL,
			now.Add(1*time.Hour), now, now,
		))
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`UPDATE hitl_approval_queue.*WHERE request_id = \$3 AND status = 'pending'`).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	err := svc.OverrideRequest(WithCallerOrg(context.Background(), "org-a"), requestID, "policy escalation", &Reviewer{ID: "admin-1", Email: "admin@example.com"})
	if err == nil || !strings.Contains(err.Error(), "cannot override request") {
		t.Fatalf("unexpected error: %v", err)
	}
	time.Sleep(80 * time.Millisecond)
	if hits.Load() != 0 {
		t.Fatalf("dispatchTerminal fired on override lost-race (count=%d)", hits.Load())
	}
}
