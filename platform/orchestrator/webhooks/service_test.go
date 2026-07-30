// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package webhooks

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"axonflow/platform/shared/tenantscope"
)

// mockRepository is a simple in-memory mock for testing.
type mockRepository struct {
	mu            sync.RWMutex
	subscriptions map[string]*Subscription
	deliveries    []Delivery
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		subscriptions: make(map[string]*Subscription),
	}
}

func (m *mockRepository) CreateSubscription(_ context.Context, sub *Subscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscriptions[sub.ID] = sub
	return nil
}

// #3065 (F6): the mock mirrors the fixed repository contract — the by-id read
// is tenancy-bound in SQL, so the mock refuses an unbound caller and refuses a
// row whose tenancy does not match. A mock that returned the row regardless
// would let a unit test certify the very fail-open the fix removes.
func (m *mockRepository) GetSubscription(_ context.Context, id, tenantID, orgID string) (*Subscription, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := tenantscope.ValidateRowKeys(orgID, tenantID); err != nil {
		return nil, fmt.Errorf("webhook subscription not found: %s", id)
	}
	sub, ok := m.subscriptions[id]
	if !ok {
		return nil, fmt.Errorf("webhook subscription not found: %s", id)
	}
	if (tenantscope.Scope{OrgID: orgID, TenantID: tenantID}).Authorize(sub.OrgID, sub.TenantID) != nil {
		return nil, fmt.Errorf("webhook subscription not found: %s", id)
	}
	return sub, nil
}

func (m *mockRepository) UpdateSubscription(_ context.Context, sub *Subscription, tenantID, orgID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.subscriptions[sub.ID]; !ok {
		return fmt.Errorf("webhook subscription not found: %s", sub.ID)
	}
	m.subscriptions[sub.ID] = sub
	return nil
}

func (m *mockRepository) DeleteSubscription(_ context.Context, id, tenantID, orgID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.subscriptions[id]; !ok {
		return fmt.Errorf("webhook subscription not found: %s", id)
	}
	delete(m.subscriptions, id)
	return nil
}

func (m *mockRepository) ListSubscriptions(_ context.Context, tenantID, orgID string) ([]Subscription, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []Subscription
	for _, sub := range m.subscriptions {
		if sub.TenantID == tenantID && sub.OrgID == orgID {
			result = append(result, *sub)
		}
	}
	return result, nil
}

func (m *mockRepository) GetActiveSubscriptionsForEvent(_ context.Context, eventType, tenantID, orgID string) ([]Subscription, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []Subscription
	for _, sub := range m.subscriptions {
		if !sub.Active || sub.TenantID != tenantID || sub.OrgID != orgID {
			continue
		}
		for _, e := range sub.Events {
			if e == eventType {
				result = append(result, *sub)
				break
			}
		}
	}
	return result, nil
}

func (m *mockRepository) RecordDelivery(_ context.Context, delivery *Delivery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deliveries = append(m.deliveries, *delivery)
	return nil
}

func TestServiceCreate(t *testing.T) {
	repo := newMockRepository()
	svc := NewService(repo, nil)

	sub, err := svc.Create(context.Background(), &CreateSubscriptionRequest{
		URL:    "https://example.com/webhook",
		Events: []string{EventStepApprovalRequired},
		Active: true,
	}, "tenant-1", "org-1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if sub.ID == "" {
		t.Error("expected non-empty ID")
	}
	if sub.URL != "https://example.com/webhook" {
		t.Errorf("URL = %q, want %q", sub.URL, "https://example.com/webhook")
	}
	if !sub.Active {
		t.Error("expected active to be true")
	}
	if sub.TenantID != "tenant-1" {
		t.Errorf("TenantID = %q, want %q", sub.TenantID, "tenant-1")
	}
}

func TestServiceCreate_Validation(t *testing.T) {
	repo := newMockRepository()
	svc := NewService(repo, nil)

	// Missing URL
	_, err := svc.Create(context.Background(), &CreateSubscriptionRequest{
		Events: []string{EventStepApprovalRequired},
	}, "t", "o")
	if err == nil {
		t.Error("expected error for missing URL")
	}

	// Missing events
	_, err = svc.Create(context.Background(), &CreateSubscriptionRequest{
		URL: "https://example.com/webhook",
	}, "t", "o")
	if err == nil {
		t.Error("expected error for missing events")
	}

	// Invalid event
	_, err = svc.Create(context.Background(), &CreateSubscriptionRequest{
		URL:    "https://example.com/webhook",
		Events: []string{"invalid.event"},
	}, "t", "o")
	if err == nil {
		t.Error("expected error for invalid event type")
	}
}

func TestServiceGetUpdateDelete(t *testing.T) {
	repo := newMockRepository()
	svc := NewService(repo, nil)

	sub, _ := svc.Create(context.Background(), &CreateSubscriptionRequest{
		URL:    "https://example.com/webhook",
		Events: []string{EventStepApprovalRequired},
		Active: true,
	}, "tenant-1", "org-1")

	// Get
	got, err := svc.Get(context.Background(), sub.ID, "tenant-1", "org-1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.URL != sub.URL {
		t.Errorf("URL = %q, want %q", got.URL, sub.URL)
	}

	// Get with wrong tenant (should fail)
	_, err = svc.Get(context.Background(), sub.ID, "other-tenant", "org-1")
	if err == nil {
		t.Error("expected error for wrong tenant")
	}

	// Update
	newURL := "https://example.com/new-webhook"
	active := false
	updated, err := svc.Update(context.Background(), sub.ID, &UpdateSubscriptionRequest{
		URL:    &newURL,
		Active: &active,
	}, "tenant-1", "org-1")
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.URL != newURL {
		t.Errorf("URL = %q, want %q", updated.URL, newURL)
	}
	if updated.Active {
		t.Error("expected active to be false after update")
	}

	// Delete
	err = svc.Delete(context.Background(), sub.ID, "tenant-1", "org-1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify deleted
	_, err = svc.Get(context.Background(), sub.ID, "tenant-1", "org-1")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestServiceList(t *testing.T) {
	repo := newMockRepository()
	svc := NewService(repo, nil)

	// Create 2 subscriptions for tenant-1 and 1 for tenant-2
	svc.Create(context.Background(), &CreateSubscriptionRequest{
		URL:    "https://example.com/w1",
		Events: []string{EventStepApprovalRequired},
		Active: true,
	}, "tenant-1", "org-1")

	svc.Create(context.Background(), &CreateSubscriptionRequest{
		URL:    "https://example.com/w2",
		Events: []string{EventWorkflowCompleted},
		Active: true,
	}, "tenant-1", "org-1")

	svc.Create(context.Background(), &CreateSubscriptionRequest{
		URL:    "https://example.com/w3",
		Events: []string{EventStepApprovalRequired},
		Active: true,
	}, "tenant-2", "org-2")

	resp, err := svc.List(context.Background(), "tenant-1", "org-1")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d, want 2", resp.Total)
	}
}

func TestSignPayload(t *testing.T) {
	payload := []byte(`{"event":"test"}`)
	secret := "my-secret-key"

	sig1 := signPayload(payload, secret)
	sig2 := signPayload(payload, secret)

	if sig1 != sig2 {
		t.Error("expected same signature for same input")
	}

	// Different secret should produce different signature
	sig3 := signPayload(payload, "other-secret")
	if sig1 == sig3 {
		t.Error("expected different signature for different secret")
	}

	// Verify it's a valid hex string
	if len(sig1) != 64 { // SHA-256 = 32 bytes = 64 hex chars
		t.Errorf("signature length = %d, want 64", len(sig1))
	}
}

func TestIsValidEvent(t *testing.T) {
	for _, event := range AllEvents {
		if !isValidEvent(event) {
			t.Errorf("expected %q to be valid", event)
		}
	}

	if isValidEvent("invalid.event") {
		t.Error("expected invalid.event to be invalid")
	}
	if isValidEvent("") {
		t.Error("expected empty string to be invalid")
	}
}

func TestFire_NoSubscriptions(t *testing.T) {
	repo := newMockRepository()
	svc := NewService(repo, nil)

	// Should not panic even with no subscriptions
	svc.Fire(context.Background(), EventStepApprovalRequired, map[string]interface{}{
		"workflow_id": "wf-1",
	}, "tenant-1", "org-1")
}

func TestWebhookPayloadFields(t *testing.T) {
	payload := &WebhookPayload{
		Event:     EventStepApproved,
		Timestamp: "2026-02-07T12:00:00Z",
		Data: map[string]interface{}{
			"workflow_id": "wf-1",
			"step_id":     "step-1",
		},
	}

	if payload.Event != EventStepApproved {
		t.Errorf("Event = %q, want %q", payload.Event, EventStepApproved)
	}
	if payload.Data["workflow_id"] != "wf-1" {
		t.Errorf("Data[workflow_id] = %v, want wf-1", payload.Data["workflow_id"])
	}
}
