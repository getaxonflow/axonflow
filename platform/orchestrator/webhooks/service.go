// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	logutil "axonflow/platform/shared/logger"
)

const (
	maxRetries         = 3
	initialBackoff     = 1 * time.Second
	webhookTimeout     = 10 * time.Second
	signatureHeader    = "X-AxonFlow-Signature-256"
	eventHeader        = "X-AxonFlow-Event"
	deliveryIDHeader   = "X-AxonFlow-Delivery"
	timestampHeader    = "X-AxonFlow-Timestamp"
)

// Service manages webhook subscriptions and delivery.
type Service struct {
	repo      Repository
	client    *http.Client
	logger    *log.Logger
	encryptor SecretEncryptor
}

// SecretEncryptor encrypts and decrypts webhook secrets at rest.
// Implemented by config.CredentialEncryptor.
type SecretEncryptor interface {
	Encrypt(creds map[string]string) ([]byte, error)
	Decrypt(data []byte) (map[string]string, error)
	IsEnabled() bool
}

// NewService creates a new webhook service.
// The encryptor is used to encrypt/decrypt webhook secrets at rest.
// Pass nil to disable encryption (not recommended for production).
func NewService(repo Repository, encryptor SecretEncryptor) *Service {
	// Custom transport that validates resolved IPs at connection time
	// to prevent SSRF via DNS rebinding attacks.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address: %w", err)
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("DNS lookup failed: %w", err)
			}
			for _, ip := range ips {
				if isPrivateIP(ip.IP) {
					return nil, fmt.Errorf("webhook delivery blocked: resolved to private IP %s", ip.IP)
				}
			}
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &Service{
		repo:      repo,
		encryptor: encryptor,
		client: &http.Client{
			Timeout:   webhookTimeout,
			Transport: transport,
		},
		logger: log.Default(),
	}
}

// Create creates a new webhook subscription.
func (s *Service) Create(ctx context.Context, req *CreateSubscriptionRequest, tenantID, orgID string) (*Subscription, error) {
	if req.URL == "" {
		return nil, fmt.Errorf("webhook URL is required")
	}
	if len(req.Events) == 0 {
		return nil, fmt.Errorf("at least one event type is required")
	}
	for _, event := range req.Events {
		if !isValidEvent(event) {
			return nil, fmt.Errorf("invalid event type: %s", event)
		}
	}

	if err := validateWebhookURL(req.URL); err != nil {
		return nil, fmt.Errorf("invalid webhook URL: %w", err)
	}

	// Encrypt the secret before storing
	secretToStore := req.Secret
	if req.Secret != "" && s.encryptor != nil && s.encryptor.IsEnabled() {
		encrypted, err := s.encryptor.Encrypt(map[string]string{"secret": req.Secret})
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt webhook secret: %w", err)
		}
		secretToStore = string(encrypted)
	}

	sub := &Subscription{
		ID:          uuid.New().String(),
		URL:         req.URL,
		Events:      req.Events,
		Secret:      secretToStore,
		Active:      req.Active,
		TenantID:    tenantID,
		OrgID:       orgID,
		Description: req.Description,
	}

	if err := s.repo.CreateSubscription(ctx, sub); err != nil {
		return nil, fmt.Errorf("failed to create webhook subscription: %w", err)
	}

	s.logger.Printf("[Webhooks] Created subscription %s for events %v (url=%s)", sub.ID, sub.Events, logutil.Sanitize(sub.URL))
	return sub, nil
}

// Get retrieves a webhook subscription by ID.
func (s *Service) Get(ctx context.Context, id, tenantID, orgID string) (*Subscription, error) {
	sub, err := s.repo.GetSubscription(ctx, id)
	if err != nil {
		return nil, err
	}
	if sub.TenantID != tenantID || sub.OrgID != orgID {
		return nil, fmt.Errorf("webhook subscription not found: %s", id)
	}
	return sub, nil
}

// Update updates a webhook subscription.
func (s *Service) Update(ctx context.Context, id string, req *UpdateSubscriptionRequest, tenantID, orgID string) (*Subscription, error) {
	sub, err := s.Get(ctx, id, tenantID, orgID)
	if err != nil {
		return nil, err
	}

	if req.URL != nil {
		if err := validateWebhookURL(*req.URL); err != nil {
			return nil, fmt.Errorf("invalid webhook URL: %w", err)
		}
		sub.URL = *req.URL
	}
	if req.Events != nil {
		for _, event := range req.Events {
			if !isValidEvent(event) {
				return nil, fmt.Errorf("invalid event type: %s", event)
			}
		}
		sub.Events = req.Events
	}
	if req.Active != nil {
		sub.Active = *req.Active
	}
	if req.Description != nil {
		sub.Description = *req.Description
	}

	if err := s.repo.UpdateSubscription(ctx, sub, tenantID, orgID); err != nil {
		return nil, fmt.Errorf("failed to update webhook subscription: %w", err)
	}

	s.logger.Printf("[Webhooks] Updated subscription %s", logutil.Sanitize(id))
	return sub, nil
}

// Delete deletes a webhook subscription.
func (s *Service) Delete(ctx context.Context, id, tenantID, orgID string) error {
	// Verify ownership
	if _, err := s.Get(ctx, id, tenantID, orgID); err != nil {
		return err
	}
	if err := s.repo.DeleteSubscription(ctx, id, tenantID, orgID); err != nil {
		return fmt.Errorf("failed to delete webhook subscription: %w", err)
	}
	s.logger.Printf("[Webhooks] Deleted subscription %s", logutil.Sanitize(id))
	return nil
}

// List lists all webhook subscriptions for a tenant/org.
func (s *Service) List(ctx context.Context, tenantID, orgID string) (*ListSubscriptionsResponse, error) {
	subs, err := s.repo.ListSubscriptions(ctx, tenantID, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list webhook subscriptions: %w", err)
	}
	if subs == nil {
		subs = []Subscription{}
	}
	return &ListSubscriptionsResponse{
		Webhooks: subs,
		Total:    len(subs),
	}, nil
}

// Fire sends a webhook event to all matching active subscriptions.
// Delivery is async (goroutines) and best-effort.
func (s *Service) Fire(ctx context.Context, eventType string, data map[string]interface{}, tenantID, orgID string) {
	subs, err := s.repo.GetActiveSubscriptionsForEvent(ctx, eventType, tenantID, orgID)
	if err != nil {
		s.logger.Printf("[Webhooks] Failed to get subscriptions for event %s: %v", eventType, err)
		return
	}

	if len(subs) == 0 {
		return
	}

	payload := &WebhookPayload{
		Event:     eventType,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      data,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		s.logger.Printf("[Webhooks] Failed to marshal payload for event %s: %v", eventType, err)
		return
	}

	s.logger.Printf("[Webhooks] Firing event %s to %d subscriptions", eventType, len(subs))

	const maxConcurrentDeliveries = 10
	sem := make(chan struct{}, maxConcurrentDeliveries)
	for _, sub := range subs {
		sem <- struct{}{}
		go func(sub Subscription) {
			defer func() { <-sem }()
			deliverCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			s.deliverWebhook(deliverCtx, sub, eventType, payloadBytes)
		}(sub)
	}
}

// deliverWebhook sends the payload to a single subscription with retries.
func (s *Service) deliverWebhook(ctx context.Context, sub Subscription, eventType string, payloadBytes []byte) {
	deliveryID := uuid.New().String()
	var lastErr error
	var responseStatus int

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := initialBackoff * time.Duration(1<<uint(attempt-1))
			select {
			case <-ctx.Done():
				lastErr = ctx.Err()
				s.logger.Printf("[Webhooks] Delivery %s cancelled during backoff: %v", deliveryID, lastErr)
				now := time.Now()
				s.recordDelivery(sub.ID, eventType, payloadBytes, "failed", attempt, &now, &responseStatus, "", lastErr.Error())
				return
			case <-time.After(backoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, "POST", sub.URL, bytes.NewReader(payloadBytes))
		if err != nil {
			lastErr = err
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(eventHeader, eventType)
		req.Header.Set(deliveryIDHeader, deliveryID)
		req.Header.Set(timestampHeader, time.Now().UTC().Format(time.RFC3339))

		// Sign payload with HMAC-SHA256 if secret is configured
		if sub.Secret != "" {
			// Decrypt the secret if encryption is enabled
			signingSecret := sub.Secret
			if s.encryptor != nil && s.encryptor.IsEnabled() {
				decrypted, err := s.encryptor.Decrypt([]byte(sub.Secret))
				if err != nil {
					s.logger.Printf("[Webhooks] Failed to decrypt secret for subscription %s: %v", sub.ID, err)
				} else if v, ok := decrypted["secret"]; ok {
					signingSecret = v
				}
			}
			signature := signPayload(payloadBytes, signingSecret)
			req.Header.Set(signatureHeader, "sha256="+signature)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			s.logger.Printf("[Webhooks] Delivery %s attempt %d failed: %v", deliveryID, attempt+1, err)
			continue
		}

		responseStatus = resp.StatusCode
		var responseBody string
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			responseBody = string(body)
		} else {
			_, _ = io.Copy(io.Discard, resp.Body)
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Success
			now := time.Now()
			s.recordDelivery(sub.ID, eventType, payloadBytes, "delivered", attempt+1, &now, &responseStatus, "", "")
			return
		}

		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		s.logger.Printf("[Webhooks] Delivery %s attempt %d got HTTP %d: %s", deliveryID, attempt+1, resp.StatusCode, logutil.Sanitize(responseBody))
	}

	// All retries exhausted
	now := time.Now()
	errMsg := ""
	if lastErr != nil {
		errMsg = lastErr.Error()
	}
	s.recordDelivery(sub.ID, eventType, payloadBytes, "failed", maxRetries+1, &now, &responseStatus, "", errMsg)
	s.logger.Printf("[Webhooks] Delivery %s failed after %d attempts: %v", deliveryID, maxRetries+1, lastErr)
}

// recordDelivery records a delivery attempt in the database.
func (s *Service) recordDelivery(subID, eventType string, payload []byte, status string, attempts int, lastAttempt *time.Time, responseStatus *int, responseBody string, errMsg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	delivery := &Delivery{
		SubscriptionID: subID,
		EventType:      eventType,
		Payload:        payload,
		Status:         status,
		Attempts:       attempts,
		LastAttemptAt:  lastAttempt,
		ResponseStatus: responseStatus,
		ResponseBody:   responseBody,
		Error:          errMsg,
		CreatedAt:      time.Now(),
	}

	if err := s.repo.RecordDelivery(ctx, delivery); err != nil {
		s.logger.Printf("[Webhooks] Failed to record delivery for subscription %s: %v", subID, err)
	}
}

// signPayload generates an HMAC-SHA256 signature for the payload.
func signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// validateWebhookURL checks that the URL is a valid HTTP(S) URL and does not
// point to private/internal IP ranges (SSRF protection).
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("webhook URL must use http or https scheme, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("webhook URL must have a host")
	}

	// Block localhost
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "localhost." {
		return fmt.Errorf("webhook URL must not target localhost")
	}

	// Resolve and check IP ranges
	ip := net.ParseIP(host)
	if ip == nil {
		// Hostname — resolve it
		addrs, err := net.LookupHost(host)
		if err != nil {
			return fmt.Errorf("cannot resolve webhook URL host %q: %w", host, err)
		}
		for _, addr := range addrs {
			if isPrivateIP(net.ParseIP(addr)) {
				return fmt.Errorf("webhook URL must not resolve to private IP address")
			}
		}
	} else {
		if isPrivateIP(ip) {
			return fmt.Errorf("webhook URL must not target private IP address")
		}
	}

	return nil
}

// isPrivateIP returns true if the IP is in a private, loopback, or link-local range.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	privateRanges := []struct {
		network string
	}{
		{"10.0.0.0/8"},
		{"172.16.0.0/12"},
		{"192.168.0.0/16"},
		{"127.0.0.0/8"},
		{"169.254.0.0/16"},
		{"::1/128"},
		{"fc00::/7"},
		{"fe80::/10"},
	}
	for _, r := range privateRanges {
		_, cidr, _ := net.ParseCIDR(r.network)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func isValidEvent(event string) bool {
	for _, e := range AllEvents {
		if e == event {
			return true
		}
	}
	return false
}
