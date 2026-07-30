// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package webhooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func setupTestHandler() (*Handler, *mockRepository) {
	repo := newMockRepository()
	svc := NewService(repo, nil)
	handler := NewHandler(svc)
	return handler, repo
}

func TestCreateWebhookHandler(t *testing.T) {
	handler, _ := setupTestHandler()

	body, _ := json.Marshal(CreateSubscriptionRequest{
		URL:    "https://example.com/webhook",
		Events: []string{EventStepApprovalRequired},
		Active: true,
	})

	req := httptest.NewRequest("POST", "/api/v1/webhooks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.createWebhook(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var resp Subscription
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.ID == "" {
		t.Error("expected non-empty ID")
	}
	if resp.URL != "https://example.com/webhook" {
		t.Errorf("URL = %q, want %q", resp.URL, "https://example.com/webhook")
	}
}

func TestCreateWebhookHandler_InvalidBody(t *testing.T) {
	handler, _ := setupTestHandler()

	req := httptest.NewRequest("POST", "/api/v1/webhooks", bytes.NewReader([]byte("invalid")))
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.createWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestGetWebhookHandler(t *testing.T) {
	handler, repo := setupTestHandler()

	// Create subscription directly
	sub := &Subscription{
		ID:       "sub-1",
		URL:      "https://example.com/webhook",
		Events:   []string{EventStepApprovalRequired},
		Active:   true,
		TenantID: "tenant-1",
		OrgID:    "org-1",
	}
	repo.CreateSubscription(nil, sub)

	req := httptest.NewRequest("GET", "/api/v1/webhooks/sub-1", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-1")
	req = mux.SetURLVars(req, map[string]string{"id": "sub-1"})

	w := httptest.NewRecorder()
	handler.getWebhook(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestGetWebhookHandler_NotFound(t *testing.T) {
	handler, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/api/v1/webhooks/nonexistent", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-1")
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})

	w := httptest.NewRecorder()
	handler.getWebhook(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDeleteWebhookHandler(t *testing.T) {
	handler, repo := setupTestHandler()

	sub := &Subscription{
		ID:       "sub-del",
		URL:      "https://example.com/webhook",
		Events:   []string{EventStepApprovalRequired},
		Active:   true,
		TenantID: "tenant-1",
		OrgID:    "org-1",
	}
	repo.CreateSubscription(nil, sub)

	req := httptest.NewRequest("DELETE", "/api/v1/webhooks/sub-del", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-1")
	req = mux.SetURLVars(req, map[string]string{"id": "sub-del"})

	w := httptest.NewRecorder()
	handler.deleteWebhook(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusNoContent, w.Body.String())
	}
}

func TestListWebhooksHandler(t *testing.T) {
	handler, repo := setupTestHandler()

	for i := 0; i < 3; i++ {
		repo.CreateSubscription(nil, &Subscription{
			ID:       fmt.Sprintf("sub-%d", i),
			URL:      fmt.Sprintf("https://example.com/wh%d", i),
			Events:   []string{EventStepApprovalRequired},
			Active:   true,
			TenantID: "tenant-1",
			OrgID:    "org-1",
		})
	}

	req := httptest.NewRequest("GET", "/api/v1/webhooks", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-1")

	w := httptest.NewRecorder()
	handler.listWebhooks(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp ListSubscriptionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Total != 3 {
		t.Errorf("Total = %d, want 3", resp.Total)
	}
}

func TestUpdateWebhookHandler(t *testing.T) {
	handler, repo := setupTestHandler()

	sub := &Subscription{
		ID:       "sub-update",
		URL:      "https://example.com/old",
		Events:   []string{EventStepApprovalRequired},
		Active:   true,
		TenantID: "tenant-1",
		OrgID:    "org-1",
	}
	repo.CreateSubscription(nil, sub)

	newURL := "https://example.com/new"
	body, _ := json.Marshal(UpdateSubscriptionRequest{
		URL: &newURL,
	})

	req := httptest.NewRequest("PUT", "/api/v1/webhooks/sub-update", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-1")
	req = mux.SetURLVars(req, map[string]string{"id": "sub-update"})

	w := httptest.NewRecorder()
	handler.updateWebhook(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp Subscription
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.URL != newURL {
		t.Errorf("URL = %q, want %q", resp.URL, newURL)
	}
}
