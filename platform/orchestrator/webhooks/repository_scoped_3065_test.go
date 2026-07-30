// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package webhooks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
)

// #3065 F6 — the SQL half of the webhook fix.
//
// GetSubscription's statement is the boundary: webhook_subscriptions has no
// RLS in any posture, so there is nothing underneath it. These tests pin both
// halves of what changed — the tenancy predicate, and the removal of `secret`
// from the projection.

func TestWebhookRepository_GetSubscription_IsTenancyBoundAndOmitsTheSecret(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)

	now := time.Now()
	// The projection must NOT include `secret`; a row shaped with it would
	// fail the Scan, which is the point.
	rows := sqlmock.NewRows([]string{
		"id", "url", "events", "active", "tenant_id", "org_id",
		"description", "created_at", "updated_at",
	}).AddRow("sub-1", "https://example.test/hook", pq.Array([]string{EventWorkflowCompleted}),
		true, "tenant-a", "org-a", "", now, now)

	mock.ExpectQuery(`FROM webhook_subscriptions WHERE id = \$1 AND tenant_id = \$2 AND org_id = \$3`).
		WithArgs("sub-1", "tenant-a", "org-a").
		WillReturnRows(rows)

	sub, err := repo.GetSubscription(context.Background(), "sub-1", "tenant-a", "org-a")
	if err != nil {
		t.Fatalf("GetSubscription: %v", err)
	}
	if sub.ID != "sub-1" || sub.OrgID != "org-a" || sub.TenantID != "tenant-a" {
		t.Fatalf("unexpected subscription %+v", sub)
	}
	if sub.Secret != "" {
		t.Error("the HMAC signing key must not be projected by the by-id read — only the delivery path needs it")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestWebhookRepository_UnboundCallerIssuesNoSQL(t *testing.T) {
	for _, tc := range []struct{ name, tenant, org string }{
		{"neither", "", ""},
		{"tenant missing", "", "org-a"},
		{"org missing", "tenant-a", ""},
		{"whitespace", " ", "\t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()
			repo := NewPostgresRepository(db)

			if _, err := repo.GetSubscription(context.Background(), "sub-1", tc.tenant, tc.org); err == nil {
				t.Error("an unbound caller must be refused")
			} else if !strings.Contains(err.Error(), "not found") {
				t.Errorf("the denial must read as not-found (no existence oracle), got %v", err)
			}
			if err := repo.DeleteSubscription(context.Background(), "sub-1", tc.tenant, tc.org); err == nil {
				t.Error("an unbound delete must be refused")
			}
			if _, err := repo.ListSubscriptions(context.Background(), tc.tenant, tc.org); err == nil {
				t.Error("an unbound listing must be refused")
			}
			if _, err := repo.GetActiveSubscriptionsForEvent(context.Background(), EventWorkflowCompleted, tc.tenant, tc.org); err == nil {
				t.Error("an unbound delivery fan-out must be refused — it projects the HMAC secret")
			}
			if err := repo.UpdateSubscription(context.Background(), &Subscription{ID: "sub-1"}, tc.tenant, tc.org); err == nil {
				t.Error("an unbound update must be refused")
			}
			if err := repo.CreateSubscription(context.Background(), &Subscription{ID: "sub-1", TenantID: tc.tenant, OrgID: tc.org}); err == nil {
				t.Error("persisting a subscription with no tenancy key manufactures a row every tenant can read")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("an unbound caller must issue no SQL at all: %v", err)
			}
		})
	}
}
