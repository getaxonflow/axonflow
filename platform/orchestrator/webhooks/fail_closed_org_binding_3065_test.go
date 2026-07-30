// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package webhooks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// #3065 F6 — cross-tenant read of a webhook subscription, HMAC SECRET included.
//
// GetSubscription was `WHERE id = $1`: no org predicate, no post-fetch guard,
// and a projection that included `secret` — the signing key a subscriber uses
// to authenticate our callbacks. Its own siblings UpdateSubscription and
// DeleteSubscription both carried `AND tenant_id = $n AND org_id = $n`, which
// is what makes the omission an oversight rather than a design.
//
// The service-layer compare that sat above it (`sub.TenantID != tenantID ||
// sub.OrgID != orgID`) was satisfied when BOTH sides were empty — and
// webhook_subscriptions declares tenant_id/org_id as NOT NULL with an
// empty-string DEFAULT (migrations/core/048), so unstamped rows carry exactly
// that value.

func seedSubscription(t *testing.T, repo *mockRepository, id, tenant, org string) {
	t.Helper()
	repo.subscriptions[id] = &Subscription{
		ID:       id,
		URL:      "https://example.test/hook",
		Events:   []string{EventWorkflowCompleted},
		Secret:   "victim-hmac-signing-key",
		Active:   true,
		TenantID: tenant,
		OrgID:    org,
	}
}

func TestWebhook_CallerOmitsTenancy_IsDenied(t *testing.T) {
	repo := newMockRepository()
	seedSubscription(t, repo, "sub-victim", "tenant-victim", "org-victim")
	handler := NewHandler(NewService(repo, nil))
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	routes := []struct{ name, method, path string }{
		{"getWebhook", http.MethodGet, "/api/v1/webhooks/sub-victim"},
		{"updateWebhook", http.MethodPut, "/api/v1/webhooks/sub-victim"},
		{"deleteWebhook", http.MethodDelete, "/api/v1/webhooks/sub-victim"},
		{"listWebhooks", http.MethodGet, "/api/v1/webhooks"},
		{"createWebhook", http.MethodPost, "/api/v1/webhooks"},
	}

	for _, route := range routes {
		for _, hdrs := range []struct {
			name    string
			headers map[string]string
		}{
			{"no headers", nil},
			{"tenant only", map[string]string{"X-Tenant-ID": "tenant-victim"}},
			{"org only", map[string]string{"X-Org-ID": "org-victim"}},
		} {
			t.Run(route.name+"/"+hdrs.name, func(t *testing.T) {
				req := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
				req.Header.Set("Content-Type", "application/json")
				for k, v := range hdrs.headers {
					req.Header.Set(k, v)
				}
				rr := httptest.NewRecorder()
				r.ServeHTTP(rr, req)
				if rr.Code != http.StatusUnauthorized {
					t.Fatalf("an unbound caller must be refused, got %d: %s", rr.Code, rr.Body.String())
				}
				if strings.Contains(rr.Body.String(), "victim-hmac-signing-key") {
					t.Fatal("the HMAC signing key appeared in a response to an unauthenticated caller")
				}
			})
		}
	}

	// The victim's subscription is untouched.
	if _, ok := repo.subscriptions["sub-victim"]; !ok {
		t.Fatal("an unauthenticated caller deleted the victim's subscription")
	}
}

func TestWebhook_CrossTenantByIDIsDeniedAndLeaksNoSecret(t *testing.T) {
	repo := newMockRepository()
	seedSubscription(t, repo, "sub-victim", "tenant-victim", "org-victim")
	svc := NewService(repo, nil)

	got, err := svc.Get(context.Background(), "sub-victim", "tenant-attacker", "org-attacker")
	if err == nil {
		t.Fatalf("cross-tenant Get must fail; it returned %+v", got)
	}
	if got != nil {
		t.Fatal("cross-tenant Get must return no subscription at all — the projection carries the HMAC secret")
	}

	// Positive control: the owner still reads it.
	own, err := svc.Get(context.Background(), "sub-victim", "tenant-victim", "org-victim")
	if err != nil {
		t.Fatalf("the owning tenant must still read its own subscription: %v", err)
	}
	if own.ID != "sub-victim" {
		t.Errorf("id = %q, want sub-victim", own.ID)
	}
}

// TestWebhook_UnstampedSubscriptionIsReachableByNobody covers the row side:
// the NOT NULL DEFAULT empty-string columns mean legacy rows carry that
// value,
// which used to satisfy an equally-empty caller.
func TestWebhook_UnstampedSubscriptionIsReachableByNobody(t *testing.T) {
	repo := newMockRepository()
	seedSubscription(t, repo, "sub-orphan", "", "")
	svc := NewService(repo, nil)

	for _, caller := range []struct{ tenant, org string }{
		{"", ""},
		{"tenant-a", "org-a"},
	} {
		if _, err := svc.Get(context.Background(), "sub-orphan", caller.tenant, caller.org); err == nil {
			t.Errorf("caller (%q,%q) reached an unowned subscription — and its HMAC secret", caller.tenant, caller.org)
		}
	}
}
