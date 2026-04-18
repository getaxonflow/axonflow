// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - Circuit Breaker Notification Tests

//go:build enterprise

package circuitbreaker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDeliverWebhook_Success(t *testing.T) {
	var received []byte
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ns := &NotificationService{
		client: server.Client(),
		sem:    make(chan struct{}, 10),
	}

	config := &NotificationConfig{
		ID:     "notif-1",
		OrgID:  "org-1",
		Type:   NotificationWebhook,
		URL:    server.URL,
		Secret: "test-secret",
		Active: true,
	}

	event := &TripEvent{
		CircuitID: "circuit-1",
		OrgID:     "org-1",
		Scope:     ScopeClient,
		ScopeID:   "client-1",
		Reason:    ReasonError,
		TrippedBy: "system",
		Comment:   "Auto-tripped",
		Timestamp: time.Now().UTC(),
	}

	err := ns.deliverWebhook(context.Background(), config, event)
	if err != nil {
		t.Fatalf("deliverWebhook failed: %v", err)
	}

	// Verify payload
	var payload map[string]interface{}
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("Failed to parse payload: %v", err)
	}
	if payload["event"] != "circuit_breaker.tripped" {
		t.Errorf("Expected event 'circuit_breaker.tripped', got %v", payload["event"])
	}
	if payload["circuit_id"] != "circuit-1" {
		t.Errorf("Expected circuit_id 'circuit-1', got %v", payload["circuit_id"])
	}

	// Verify HMAC signature
	sig := receivedHeaders.Get("X-AxonFlow-Signature-256")
	if sig == "" {
		t.Fatal("Expected X-AxonFlow-Signature-256 header")
	}

	mac := hmac.New(sha256.New, []byte("test-secret"))
	mac.Write(received)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig != expectedSig {
		t.Errorf("HMAC signature mismatch: got %s, expected %s", sig, expectedSig)
	}

	// Verify other headers
	if receivedHeaders.Get("X-AxonFlow-Event") != "circuit_breaker.tripped" {
		t.Error("Missing X-AxonFlow-Event header")
	}
	if receivedHeaders.Get("X-AxonFlow-Delivery") == "" {
		t.Error("Missing X-AxonFlow-Delivery header")
	}
}

func TestDeliverWebhook_NoSecret(t *testing.T) {
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ns := &NotificationService{
		client: server.Client(),
		sem:    make(chan struct{}, 10),
	}

	config := &NotificationConfig{
		Type: NotificationWebhook,
		URL:  server.URL,
	}

	event := &TripEvent{
		CircuitID: "circuit-1",
		OrgID:     "org-1",
		Scope:     ScopeClient,
		ScopeID:   "client-1",
		Reason:    ReasonError,
		Timestamp: time.Now().UTC(),
	}

	err := ns.deliverWebhook(context.Background(), config, event)
	if err != nil {
		t.Fatalf("deliverWebhook failed: %v", err)
	}

	// No signature header when no secret
	if receivedHeaders.Get("X-AxonFlow-Signature-256") != "" {
		t.Error("Expected no signature header when secret is empty")
	}
}

func TestDeliverSlack_Success(t *testing.T) {
	var received []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ns := &NotificationService{
		client: server.Client(),
		sem:    make(chan struct{}, 10),
	}

	config := &NotificationConfig{
		Type: NotificationSlack,
		URL:  server.URL,
	}

	event := &TripEvent{
		CircuitID: "circuit-1",
		OrgID:     "org-1",
		Scope:     ScopeClient,
		ScopeID:   "client-1",
		Reason:    ReasonError,
		Comment:   "Auto-tripped after 10 errors",
		Timestamp: time.Now().UTC(),
	}

	err := ns.deliverSlack(context.Background(), config, event)
	if err != nil {
		t.Fatalf("deliverSlack failed: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("Failed to parse Slack payload: %v", err)
	}
	blocks, ok := payload["blocks"].([]interface{})
	if !ok || len(blocks) < 2 {
		t.Fatal("Expected at least 2 blocks in Slack payload")
	}
}

func TestDeliverPagerDuty_Success(t *testing.T) {
	var received []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	ns := &NotificationService{
		client: server.Client(),
		sem:    make(chan struct{}, 10),
	}

	config := &NotificationConfig{
		Type:   NotificationPagerDuty,
		URL:    server.URL, // override for testing
		Secret: "routing-key-123",
	}

	event := &TripEvent{
		CircuitID: "circuit-1",
		OrgID:     "org-1",
		Scope:     ScopeClient,
		ScopeID:   "client-1",
		Reason:    ReasonError,
		Comment:   "Auto-tripped",
		Timestamp: time.Now().UTC(),
	}

	err := ns.deliverPagerDuty(context.Background(), config, event)
	if err != nil {
		t.Fatalf("deliverPagerDuty failed: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("Failed to parse PagerDuty payload: %v", err)
	}
	if payload["routing_key"] != "routing-key-123" {
		t.Errorf("Expected routing_key 'routing-key-123', got %v", payload["routing_key"])
	}
	if payload["event_action"] != "trigger" {
		t.Errorf("Expected event_action 'trigger', got %v", payload["event_action"])
	}
}

func TestDeliverWithRetry_RetriesOnFailure(t *testing.T) {
	var attempts int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ns := &NotificationService{
		client: server.Client(),
		sem:    make(chan struct{}, 10),
	}

	config := &NotificationConfig{
		Type: NotificationWebhook,
		URL:  server.URL,
	}

	event := &TripEvent{
		CircuitID: "circuit-1",
		OrgID:     "org-1",
		Scope:     ScopeClient,
		ScopeID:   "client-1",
		Reason:    ReasonError,
		Timestamp: time.Now().UTC(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ns.deliverWithRetry(ctx, config, event)

	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("Expected 3 attempts, got %d", atomic.LoadInt32(&attempts))
	}
}

func TestSSRF_BlocksPrivateIPs(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := isPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestSignPayload(t *testing.T) {
	payload := []byte(`{"test":"data"}`)
	secret := "my-secret"

	sig := signPayload(payload, secret)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))

	if sig != expected {
		t.Errorf("signPayload mismatch: got %s, expected %s", sig, expected)
	}
}

func TestHandleTripEvent_NilService(t *testing.T) {
	var ns *NotificationService
	// Should not panic
	ns.HandleTripEvent(&TripEvent{})
}

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com/webhook", true},
		{"http://example.com/webhook", true},
		{"ftp://example.com", false},
		{"not-a-url", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			result := isValidURL(tt.url)
			if result != tt.expected {
				t.Errorf("isValidURL(%q) = %v, want %v", tt.url, result, tt.expected)
			}
		})
	}
}

// --- Repository tests for notification CRUD ---

func TestRepository_CreateNotificationConfig(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)

	mock.ExpectExec("INSERT INTO circuit_breaker_notifications").
		WillReturnResult(sqlmock.NewResult(1, 1))

	config := &NotificationConfig{
		OrgID:  "org-1",
		Type:   NotificationWebhook,
		URL:    "https://example.com/webhook",
		Secret: "test-secret",
		Active: true,
	}

	err = repo.CreateNotificationConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("CreateNotificationConfig failed: %v", err)
	}

	if config.ID == "" {
		t.Error("Expected ID to be generated")
	}
}

func TestRepository_GetNotificationConfigs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)

	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"id", "org_id", "tenant_id", "type", "url", "secret", "active", "created_at", "updated_at",
	}).
		AddRow("notif-1", "org-1", "", "webhook", "https://example.com/webhook", "secret", true, now, now).
		AddRow("notif-2", "org-1", "tenant-1", "slack", "https://hooks.slack.com/services/xxx", nil, true, now, now)

	mock.ExpectQuery("SELECT").
		WithArgs("org-1").
		WillReturnRows(rows)

	configs, err := repo.GetNotificationConfigs(context.Background(), "org-1")
	if err != nil {
		t.Fatalf("GetNotificationConfigs failed: %v", err)
	}

	if len(configs) != 2 {
		t.Errorf("Expected 2 configs, got %d", len(configs))
	}
	if configs[0].Type != NotificationWebhook {
		t.Errorf("Expected type webhook, got %s", configs[0].Type)
	}
	if configs[0].Secret != "secret" {
		t.Errorf("Expected secret 'secret', got %s", configs[0].Secret)
	}
	if configs[1].Type != NotificationSlack {
		t.Errorf("Expected type slack, got %s", configs[1].Type)
	}
}

func TestRepository_UpdateNotificationConfig(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)

	mock.ExpectExec("UPDATE circuit_breaker_notifications").
		WillReturnResult(sqlmock.NewResult(0, 1))

	config := &NotificationConfig{
		ID:     "notif-1",
		OrgID:  "org-1",
		Type:   NotificationWebhook,
		URL:    "https://example.com/webhook-v2",
		Active: true,
	}

	err = repo.UpdateNotificationConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("UpdateNotificationConfig failed: %v", err)
	}
}

func TestRepository_UpdateNotificationConfig_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)

	mock.ExpectExec("UPDATE circuit_breaker_notifications").
		WillReturnResult(sqlmock.NewResult(0, 0))

	config := &NotificationConfig{
		ID:    "nonexistent",
		OrgID: "org-1",
		Type:  NotificationWebhook,
		URL:   "https://example.com",
	}

	err = repo.UpdateNotificationConfig(context.Background(), config)
	if err == nil {
		t.Error("Expected error for non-existent config")
	}
}

func TestRepository_DeleteNotificationConfig(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)

	mock.ExpectExec("DELETE FROM circuit_breaker_notifications").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.DeleteNotificationConfig(context.Background(), "notif-1", "org-1")
	if err != nil {
		t.Fatalf("DeleteNotificationConfig failed: %v", err)
	}
}

func TestRepository_DeleteNotificationConfig_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)

	mock.ExpectExec("DELETE FROM circuit_breaker_notifications").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = repo.DeleteNotificationConfig(context.Background(), "nonexistent", "org-1")
	if err == nil {
		t.Error("Expected error for non-existent config")
	}
}

func TestRepository_GetTenantConfig_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)

	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"id", "org_id", "tenant_id",
		"error_threshold", "violation_threshold", "window_seconds",
		"default_timeout_seconds", "max_timeout_seconds", "enable_auto_recovery",
		"created_at", "updated_at",
	}).
		AddRow("config-1", "org-1", "tenant-1",
			5, nil, 600,
			nil, nil, true,
			now, now)

	mock.ExpectQuery("SELECT").
		WithArgs("org-1", "tenant-1").
		WillReturnRows(rows)

	tc, err := repo.GetTenantConfig(context.Background(), "org-1", "tenant-1")
	if err != nil {
		t.Fatalf("GetTenantConfig failed: %v", err)
	}
	if tc == nil {
		t.Fatal("Expected non-nil tenant config")
	}
	if tc.ErrorThreshold == nil || *tc.ErrorThreshold != 5 {
		t.Error("Expected error_threshold=5")
	}
	if tc.ViolationThreshold != nil {
		t.Error("Expected violation_threshold to be nil")
	}
	if tc.WindowSeconds == nil || *tc.WindowSeconds != 600 {
		t.Error("Expected window_seconds=600")
	}
}

func TestRepository_GetTenantConfig_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)

	mock.ExpectQuery("SELECT").
		WillReturnError(sql.ErrNoRows)

	tc, err := repo.GetTenantConfig(context.Background(), "org-1", "tenant-1")
	if err != nil {
		t.Fatalf("GetTenantConfig failed: %v", err)
	}
	if tc != nil {
		t.Error("Expected nil for non-existent tenant config")
	}
}

func TestRepository_UpsertTenantConfig(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)

	mock.ExpectExec("INSERT INTO circuit_breaker_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	threshold := 5
	tc := &TenantConfig{
		OrgID:          "org-1",
		TenantID:       "tenant-1",
		ErrorThreshold: &threshold,
	}

	err = repo.UpsertTenantConfig(context.Background(), tc)
	if err != nil {
		t.Fatalf("UpsertTenantConfig failed: %v", err)
	}
}

func TestMergeConfig(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	cb := New(repo, Config{
		ErrorThreshold:           10,
		PolicyViolationThreshold: 20,
		PolicyViolationWindow:    5 * time.Minute,
		DefaultTimeout:           30 * time.Minute,
		MaxTimeout:               1 * time.Hour,
		EnableAutoRecovery:       true,
	})

	// Partial override
	threshold := 5
	windowSecs := 600
	tc := &TenantConfig{
		ErrorThreshold: &threshold,
		WindowSeconds:  &windowSecs,
	}

	merged := cb.mergeConfig(tc)

	if merged.ErrorThreshold != 5 {
		t.Errorf("Expected error threshold 5, got %d", merged.ErrorThreshold)
	}
	if merged.PolicyViolationThreshold != 20 {
		t.Errorf("Expected violation threshold 20 (global), got %d", merged.PolicyViolationThreshold)
	}
	if merged.PolicyViolationWindow != 10*time.Minute {
		t.Errorf("Expected window 10m, got %v", merged.PolicyViolationWindow)
	}
	if merged.DefaultTimeout != 30*time.Minute {
		t.Errorf("Expected timeout 30m (global), got %v", merged.DefaultTimeout)
	}
	if !merged.EnableAutoRecovery {
		t.Error("Expected auto recovery true (global)")
	}
}
