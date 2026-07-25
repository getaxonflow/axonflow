// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package hitl

// #3048 R3 BLOCKER-2 real-PG regression: the HITL repository's discovery
// reads run on a BYPASSRLS lookup pool, so tenancy is owned by the SQL org
// predicate (List) and the service's caller-org check (by-id flows). These
// tests drive both against a real app-role posture DB with a REAL cross-org
// fixture: without the guards, tenant A listed tenant B's queue (including
// original_query content) and could approve/reject/override tenant B's
// pending requests.
//
// Gating: TEST_PG_INTEGRATION=1 + docker + -tags enterprise.

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/approletest"
)

func setupHITLOrgScopeFixture(t *testing.T) (*sql.DB, *sql.DB, *Repository) {
	t.Helper()
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../../migrations/core")

	open := func(dsn, label string) *sql.DB {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatalf("open %s DSN: %v", label, err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	masterDB := open(env.MasterDSN, "master")
	appRoleDB := open(env.AppRoleDSN, "app_role")
	adminDB := open(env.AdminDSN, "platform_admin")
	appRoleDB.SetMaxOpenConns(1)
	approletest.AssertCurrentUser(t, appRoleDB, "axonflow_app_role")

	// approletest's stable range stops at core/111; the repository INSERT
	// carries notify_url (mig 114) — apply it on top.
	migSQL, err := os.ReadFile("../../../migrations/core/114_hitl_notify_url.sql")
	if err != nil {
		t.Fatalf("read migration 114: %v", err)
	}
	if _, err := masterDB.Exec(string(migSQL)); err != nil {
		t.Fatalf("apply migration 114: %v", err)
	}

	repo := NewRepository(appRoleDB)
	repo.SetCrossOrgDB(adminDB)
	_ = masterDB
	return masterDB, appRoleDB, repo
}

func seedApproval(t *testing.T, repo *Repository, org string) *ApprovalRequest {
	t.Helper()
	req := &ApprovalRequest{
		RequestID:           uuid.New(),
		OrgID:               org,
		TenantID:            org,
		ClientID:            "client-" + org,
		OriginalQuery:       "wire 9000 EUR for " + org, // the content BLOCKER-2 leaked cross-org
		RequestType:         "sql",
		TriggeredPolicyID:   "pol-1",
		TriggeredPolicyName: "High Value",
		TriggerReason:       "over threshold",
		Severity:            "high",
		Status:              "pending",
		ExpiresAt:           time.Now().Add(time.Hour),
	}
	if err := repo.Create(context.Background(), req); err != nil {
		t.Fatalf("Create approval for %s: %v", org, err)
	}
	return req
}

func TestHITLOrgIsolationUnderAppRole(t *testing.T) {
	masterDB, _, repo := setupHITLOrgScopeFixture(t)
	seedOrg := func(org string) {
		if _, err := masterDB.Exec(`
			INSERT INTO organizations (org_id, name, license_key, tier)
			VALUES ($1, $2, $3, 'ENTERPRISE') ON CONFLICT (org_id) DO NOTHING
		`, org, org, "lic-"+org); err != nil {
			t.Fatalf("seed org %s: %v", org, err)
		}
	}
	const orgA = "hitl3048-org-a"
	const orgB = "hitl3048-org-b"
	seedOrg(orgA)
	seedOrg(orgB)

	svc := NewService(repo, ServiceConfig{})
	reqB := seedApproval(t, repo, orgB)
	ctx := context.Background()

	t.Run("List is org-isolated", func(t *testing.T) {
		// Caller A's filtered view (what the handler now always requests via
		// the middleware-derived X-Org-ID) must NOT contain B's request.
		rowsA, totalA, err := repo.List(ctx, ListFilter{OrgID: orgA, Limit: 50})
		if err != nil {
			t.Fatalf("List(orgA): %v", err)
		}
		if totalA != 0 || len(rowsA) != 0 {
			t.Fatalf("SECURITY: org A's queue lists %d/%d rows including org B's approvals (#3048 R3 BLOCKER-2)", len(rowsA), totalA)
		}
		rowsB, totalB, err := repo.List(ctx, ListFilter{OrgID: orgB, Limit: 50})
		if err != nil {
			t.Fatalf("List(orgB): %v", err)
		}
		if totalB != 1 || len(rowsB) != 1 || rowsB[0].RequestID != reqB.RequestID {
			t.Fatalf("org B's own queue must list its request (got %d/%d)", len(rowsB), totalB)
		}
	})

	assertStillPending := func(t *testing.T, when string) {
		t.Helper()
		var status string
		if err := masterDB.QueryRow(
			`SELECT status FROM hitl_approval_queue WHERE request_id = $1`, reqB.RequestID,
		).Scan(&status); err != nil {
			t.Fatalf("master status read (%s): %v", when, err)
		}
		if status != "pending" {
			t.Fatalf("SECURITY (%s): org B's request status = %q — mutated cross-org", when, status)
		}
	}

	reviewer := &Reviewer{ID: "rev-a", Email: "reviewer@a.example", Role: "admin"}
	ctxA := WithCallerOrg(ctx, orgA)
	ctxB := WithCallerOrg(ctx, orgB)

	t.Run("cross-org get is not-found", func(t *testing.T) {
		if _, err := svc.GetApprovalRequest(ctxA, reqB.RequestID); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("SECURITY: org A read org B's approval (err=%v)", err)
		}
	})

	t.Run("cross-org approve rejected, row unchanged", func(t *testing.T) {
		err := svc.ApproveRequest(ctxA, reqB.RequestID, reviewer, "approving your wire")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("SECURITY: org A approved org B's request (err=%v)", err)
		}
		assertStillPending(t, "after cross-org approve")
	})

	t.Run("cross-org reject rejected, row unchanged", func(t *testing.T) {
		err := svc.RejectRequest(ctxA, reqB.RequestID, reviewer, "nope")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("SECURITY: org A rejected org B's request (err=%v)", err)
		}
		assertStillPending(t, "after cross-org reject")
	})

	t.Run("cross-org override rejected, row unchanged", func(t *testing.T) {
		err := svc.OverrideRequest(ctxA, reqB.RequestID, "because I can", reviewer)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("SECURITY: org A overrode org B's request (err=%v)", err)
		}
		assertStillPending(t, "after cross-org override")
	})

	t.Run("cross-org history is not-found", func(t *testing.T) {
		if _, err := svc.GetRequestHistory(ctxA, reqB.RequestID); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("SECURITY: org A read org B's approval history (err=%v)", err)
		}
	})

	t.Run("same-org approve works", func(t *testing.T) {
		if err := svc.ApproveRequest(ctxB, reqB.RequestID, &Reviewer{ID: "rev-b", Email: "reviewer@b.example", Role: "admin"}, "ok"); err != nil {
			t.Fatalf("same-org approve must work: %v", err)
		}
		var status string
		if err := masterDB.QueryRow(
			`SELECT status FROM hitl_approval_queue WHERE request_id = $1`, reqB.RequestID,
		).Scan(&status); err != nil {
			t.Fatalf("master status read: %v", err)
		}
		if status != "approved" {
			t.Fatalf("same-org approve did not land (status=%q)", status)
		}
	})
}
