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

	"axonflow/platform/shared/egress"
	logutil "axonflow/platform/shared/logger"
	"axonflow/platform/shared/tenantscope"
)

const (
	maxRetries       = 3
	initialBackoff   = 1 * time.Second
	webhookTimeout   = 10 * time.Second
	signatureHeader  = "X-AxonFlow-Signature-256"
	eventHeader      = "X-AxonFlow-Event"
	deliveryIDHeader = "X-AxonFlow-Delivery"
	timestampHeader  = "X-AxonFlow-Timestamp"
)

// WebhookAllowPrivateEnv unlocks webhook subscription URLs that resolve into a
// reserved range, at BOTH the create/update validation and the delivery
// dialer. Default behavior REJECTS them.
//
// This is a migration escape hatch for #3104, which moved this surface onto
// egress.CallbackEgress. Before #3104 the local classifier covered only eight
// CIDRs, so a subscription URL on carrier-grade NAT (100.64.0.0/10 — which is
// ALSO Tailscale's address range, the most likely real-world breakage here),
// on 0.0.0.0/8, on a TEST-NET or benchmarking range, on multicast, on
// 240.0.0.0/4 or on the broadcast address was accepted. Those are now refused.
//
// It is deliberately separate from the circuit-breaker and HITL hatches: there
// is no global egress bypass, because one flag serving several surfaces makes
// re-permitting one of them re-permit all of them.
//
// Set to "true" (exactly; "1" and "yes" do not count) only while migrating
// such a receiver onto a reachable address. Engaging it WARN-logs at service
// construction and names every range it re-permits.
const WebhookAllowPrivateEnv = "AXONFLOW_ORCH_WEBHOOK_ALLOW_PRIVATE"

// allowPrivateRanges reads the escape hatch. It is a var so tests can flip the
// env between service instances.
var allowPrivateRanges = func() bool {
	return egress.AllowPrivateFromEnv(WebhookAllowPrivateEnv, "orchestrator webhook subscriptions", egress.CallbackEgress)
}

// Service manages webhook subscriptions and delivery.
type Service struct {
	repo      Repository
	client    *http.Client
	logger    *log.Logger
	encryptor SecretEncryptor
	// allowPrivate is the WebhookAllowPrivateEnv escape hatch, read once at
	// construction so the WARN fires per process rather than per request.
	allowPrivate bool
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
	// Read the escape hatch once, here, rather than per request. Engaging it
	// WARN-logs and names every range it re-permits.
	allowPrivate := allowPrivateRanges()

	// Transport that validates resolved IPs at connection time and then dials
	// the addresses it validated, by literal. Handing the hostname back to
	// net.Dialer — as this did before #3104 — makes it resolve a SECOND time,
	// which is precisely the DNS-rebinding window the check is meant to close
	// (#3104 R3 F1).
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	dialContext := dialer.DialContext
	if !allowPrivate {
		dialContext = egress.NewSafeDialContext(egress.CallbackEgress, dialer, nil, func(ip net.IP) error {
			return fmt.Errorf("webhook delivery blocked: resolved to private IP %s (%s; set %s=true to allow while migrating)",
				ip, egress.CallbackEgress.Reason(ip), WebhookAllowPrivateEnv)
		})
	}
	transport := &http.Transport{
		DialContext:         dialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &Service{
		repo:         repo,
		encryptor:    encryptor,
		allowPrivate: allowPrivate,
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

	if err := validateWebhookURL(req.URL, s.allowPrivate); err != nil {
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

// Get retrieves a webhook subscription by ID, bound to the caller's tenancy.
//
// #3065 (F6): the repository read is now predicated in SQL; the post-fetch
// compare below is kept as a second, independent statement of the same
// invariant and is fail-closed on an empty value on either side (the old
// `sub.TenantID != tenantID || sub.OrgID != orgID` was satisfied when BOTH
// the caller's and the row's keys were empty — and webhook_subscriptions
// defaults them to ”).
func (s *Service) Get(ctx context.Context, id, tenantID, orgID string) (*Subscription, error) {
	sub, err := s.repo.GetSubscription(ctx, id, tenantID, orgID)
	if err != nil {
		return nil, err
	}
	if err := (tenantscope.Scope{OrgID: orgID, TenantID: tenantID}).Authorize(sub.OrgID, sub.TenantID); err != nil {
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
		if err := validateWebhookURL(*req.URL, s.allowPrivate); err != nil {
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
func validateWebhookURL(rawURL string, allowPrivate bool) error {
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

	// Block localhost. Deliberately OUTSIDE the escape hatch: the hatch
	// re-permits reserved IP *ranges*, and an explicit `localhost` target is a
	// misconfiguration in every deployment shape, hatch or not.
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "localhost." {
		return fmt.Errorf("webhook URL must not target localhost")
	}

	// Resolve and check IP ranges
	ip := net.ParseIP(host)
	if ip == nil {
		// Hostname — resolve it. The resolvability check is also OUTSIDE the
		// hatch: a subscription whose host does not resolve can never deliver,
		// and accepting one silently is a new failure mode, not a relaxed
		// posture.
		addrs, err := net.LookupHost(host)
		if err != nil {
			return fmt.Errorf("cannot resolve webhook URL host %q: %w", host, err)
		}
		// The escape hatch covers the IP posture and ONLY the IP posture. It has
		// to cover this validation as well as the delivery dialer: refusing the
		// subscription at create time would make the hatch unusable for the
		// deployments it exists for.
		if allowPrivate {
			return nil
		}
		for _, addr := range addrs {
			resolved := net.ParseIP(addr)
			if isPrivateIP(resolved) {
				return fmt.Errorf("webhook URL must not resolve to a reserved address: %s resolves to %s (%s; set %s=true to allow while migrating)",
					host, addr, egress.CallbackEgress.Reason(resolved), WebhookAllowPrivateEnv)
			}
		}
	} else {
		if allowPrivate {
			return nil
		}
		if isPrivateIP(ip) {
			return fmt.Errorf("webhook URL must not target a reserved address: %s (set %s=true to allow while migrating)",
				egress.CallbackEgress.Reason(ip), WebhookAllowPrivateEnv)
		}
	}

	return nil
}

// isPrivateIP binds this surface to egress.CallbackEgress, the shared policy
// for operator-supplied callback URLs (#3104). The range table lives in
// platform/shared/egress.
//
// Two behaviour changes relative to the eight-CIDR list this replaces:
//
//   - It no longer returns false for a nil IP. validateWebhookURL calls this
//     on net.ParseIP of each resolved address, so an address that failed to
//     parse used to be treated as public. It is now refused.
//   - It blocks 0.0.0.0/8 (dial-routed to loopback on Linux and macOS), CGNAT,
//     the IETF protocol-assignment and TEST-NET ranges, the RFC 2544
//     benchmarking range, multicast, 240.0.0.0/4, the broadcast address, the
//     IPv6 documentation range and the wrapped-IPv4 encodings. See
//     WebhookAllowPrivateEnv for the migration hatch.
func isPrivateIP(ip net.IP) bool {
	return egress.CallbackEgress.Blocks(ip)
}

func isValidEvent(event string) bool {
	for _, e := range AllEvents {
		if e == event {
			return true
		}
	}
	return false
}
