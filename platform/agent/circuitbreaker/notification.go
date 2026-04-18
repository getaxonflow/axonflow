// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - Circuit Breaker Notification Service
// Delivers webhook, Slack, and PagerDuty notifications on auto-trip events.

//go:build enterprise

package circuitbreaker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
)

// NotificationType defines the notification channel type
type NotificationType string

const (
	NotificationWebhook  NotificationType = "webhook"
	NotificationSlack    NotificationType = "slack"
	NotificationPagerDuty NotificationType = "pagerduty"
)

// NotificationConfig holds configuration for a notification channel
type NotificationConfig struct {
	ID        string           `json:"id"`
	OrgID     string           `json:"org_id"`
	TenantID  string           `json:"tenant_id,omitempty"`
	Type      NotificationType `json:"type"`
	URL       string           `json:"url"`
	Secret    string           `json:"secret,omitempty"`
	Active    bool             `json:"active"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

// NotificationService handles notification delivery for circuit breaker events
type NotificationService struct {
	repo   *Repository
	client *http.Client
	sem    chan struct{} // bounded concurrency
}

const (
	maxConcurrentNotifications = 10
	notificationTimeout        = 10 * time.Second
	maxRetries                 = 3
	pagerDutyEventsURL         = "https://events.pagerduty.com/v2/enqueue"
)

// NewNotificationService creates a notification service with SSRF-safe transport
func NewNotificationService(repo *Repository) *NotificationService {
	transport := &http.Transport{
		DialContext: ssrfSafeDialer,
		MaxIdleConns:        20,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &NotificationService{
		repo: repo,
		client: &http.Client{
			Transport: transport,
			Timeout:   notificationTimeout,
		},
		sem: make(chan struct{}, maxConcurrentNotifications),
	}
}

// ssrfSafeDialer rejects connections to private/reserved IP ranges
func ssrfSafeDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	for _, ip := range ips {
		if isPrivateIP(ip.IP) {
			return nil, fmt.Errorf("SSRF protection: connection to private IP %s blocked", ip.IP)
		}
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, network, addr)
}

// isPrivateIP checks if an IP address is in a private/reserved range
func isPrivateIP(ip net.IP) bool {
	privateRanges := []struct {
		network *net.IPNet
	}{
		{parseCIDR("10.0.0.0/8")},
		{parseCIDR("172.16.0.0/12")},
		{parseCIDR("192.168.0.0/16")},
		{parseCIDR("127.0.0.0/8")},
		{parseCIDR("169.254.0.0/16")},
		{parseCIDR("::1/128")},
		{parseCIDR("fc00::/7")},
		{parseCIDR("fe80::/10")},
	}

	for _, r := range privateRanges {
		if r.network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDR(cidr string) *net.IPNet {
	_, network, _ := net.ParseCIDR(cidr)
	return network
}

// HandleTripEvent delivers notifications for a circuit trip event.
// Designed to be called as a trip callback (via SetTripCallback).
func (ns *NotificationService) HandleTripEvent(event *TripEvent) {
	if ns == nil || ns.repo == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	configs, err := ns.repo.GetNotificationConfigs(ctx, event.OrgID)
	if err != nil {
		log.Printf("[CircuitBreaker/Notification] Failed to fetch configs for org %s: %v", event.OrgID, err)
		return
	}

	if len(configs) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, config := range configs {
		if !config.Active {
			continue
		}
		// Filter by tenant: deliver if config has no tenant filter or matches event tenant
		if config.TenantID != "" && config.TenantID != event.TenantID {
			continue
		}

		wg.Add(1)
		go func(cfg *NotificationConfig) {
			defer wg.Done()
			// Acquire semaphore for bounded concurrency
			ns.sem <- struct{}{}
			defer func() { <-ns.sem }()

			ns.deliverWithRetry(ctx, cfg, event)
		}(config)
	}
	wg.Wait()
}

// deliverWithRetry attempts delivery up to maxRetries times with exponential backoff
func (ns *NotificationService) deliverWithRetry(ctx context.Context, config *NotificationConfig, event *TripEvent) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}

		var err error
		switch config.Type {
		case NotificationWebhook:
			err = ns.deliverWebhook(ctx, config, event)
		case NotificationSlack:
			err = ns.deliverSlack(ctx, config, event)
		case NotificationPagerDuty:
			err = ns.deliverPagerDuty(ctx, config, event)
		default:
			log.Printf("[CircuitBreaker/Notification] Unknown type %s for config %s", config.Type, config.ID)
			return
		}

		if err == nil {
			return
		}
		log.Printf("[CircuitBreaker/Notification] Attempt %d/%d failed for %s (%s): %v",
			attempt+1, maxRetries, config.Type, config.ID, err)
	}
}

// deliverWebhook sends a JSON payload with HMAC signature
func (ns *NotificationService) deliverWebhook(ctx context.Context, config *NotificationConfig, event *TripEvent) error {
	payload := map[string]interface{}{
		"event":      "circuit_breaker.tripped",
		"circuit_id": event.CircuitID,
		"org_id":     event.OrgID,
		"scope":      event.Scope,
		"scope_id":   event.ScopeID,
		"reason":     event.Reason,
		"tripped_by": event.TrippedBy,
		"comment":    event.Comment,
		"timestamp":  event.Timestamp.Format(time.RFC3339),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	deliveryID := uuid.New().String()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AxonFlow-Event", "circuit_breaker.tripped")
	req.Header.Set("X-AxonFlow-Delivery", deliveryID)
	req.Header.Set("X-AxonFlow-Timestamp", event.Timestamp.Format(time.RFC3339))

	if config.Secret != "" {
		signature := signPayload(body, config.Secret)
		req.Header.Set("X-AxonFlow-Signature-256", "sha256="+signature)
	}

	resp, err := ns.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("webhook returned status %d", resp.StatusCode)
}

// deliverSlack sends a Block Kit formatted message to a Slack incoming webhook
func (ns *NotificationService) deliverSlack(ctx context.Context, config *NotificationConfig, event *TripEvent) error {
	reasonText := string(event.Reason)
	if event.Comment != "" {
		reasonText = event.Comment
	}

	payload := map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": "Circuit Breaker Tripped",
				},
			},
			{
				"type": "section",
				"fields": []map[string]interface{}{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Scope:*\n%s: %s", event.Scope, event.ScopeID)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Reason:*\n%s", event.Reason)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Org:*\n%s", event.OrgID)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Time:*\n%s", event.Timestamp.Format(time.RFC3339))},
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Details:*\n%s", reasonText),
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ns.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("slack returned status %d", resp.StatusCode)
}

// deliverPagerDuty sends a trigger event to PagerDuty Events API v2
func (ns *NotificationService) deliverPagerDuty(ctx context.Context, config *NotificationConfig, event *TripEvent) error {
	payload := map[string]interface{}{
		"routing_key":  config.Secret, // PagerDuty routing key stored as secret
		"event_action": "trigger",
		"dedup_key":    fmt.Sprintf("axonflow-cb-%s-%s", event.OrgID, event.ScopeID),
		"payload": map[string]interface{}{
			"summary":   fmt.Sprintf("AxonFlow Circuit Breaker Tripped: %s %s (%s)", event.Scope, event.ScopeID, event.Reason),
			"severity":  "critical",
			"source":    "axonflow-agent",
			"component": "circuit-breaker",
			"group":     event.OrgID,
			"class":     string(event.Reason),
			"timestamp": event.Timestamp.Format(time.RFC3339),
			"custom_details": map[string]interface{}{
				"circuit_id": event.CircuitID,
				"scope":      event.Scope,
				"scope_id":   event.ScopeID,
				"comment":    event.Comment,
				"tripped_by": event.TrippedBy,
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	// PagerDuty uses its own events URL, not the config URL
	targetURL := pagerDutyEventsURL
	if config.URL != "" {
		targetURL = config.URL // allow override for testing
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ns.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("pagerduty returned status %d", resp.StatusCode)
}

// signPayload computes HMAC-SHA256 signature for webhook payloads
func signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// --- Repository methods for notification config ---

// CreateNotificationConfig persists a new notification config
func (r *Repository) CreateNotificationConfig(ctx context.Context, config *NotificationConfig) error {
	if config.ID == "" {
		config.ID = uuid.New().String()
	}
	query := `
		INSERT INTO circuit_breaker_notifications (
			id, org_id, tenant_id, type, url, secret, active
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.ExecContext(ctx, query,
		config.ID, config.OrgID, config.TenantID,
		config.Type, config.URL, nullString(config.Secret), config.Active,
	)
	return err
}

// GetNotificationConfigs retrieves all notification configs for an org
func (r *Repository) GetNotificationConfigs(ctx context.Context, orgID string) ([]*NotificationConfig, error) {
	query := `
		SELECT id, org_id, tenant_id, type, url, secret, active, created_at, updated_at
		FROM circuit_breaker_notifications
		WHERE org_id = $1
		ORDER BY created_at ASC`

	rows, err := r.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []*NotificationConfig
	for rows.Next() {
		c := &NotificationConfig{}
		var secret sql.NullString
		if err := rows.Scan(&c.ID, &c.OrgID, &c.TenantID, &c.Type, &c.URL, &secret, &c.Active, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.Secret = secret.String
		configs = append(configs, c)
	}
	return configs, rows.Err()
}

// UpdateNotificationConfig updates an existing notification config
func (r *Repository) UpdateNotificationConfig(ctx context.Context, config *NotificationConfig) error {
	query := `
		UPDATE circuit_breaker_notifications
		SET type = $1, url = $2, secret = $3, active = $4, tenant_id = $5
		WHERE id = $6 AND org_id = $7`

	result, err := r.db.ExecContext(ctx, query,
		config.Type, config.URL, nullString(config.Secret), config.Active, config.TenantID,
		config.ID, config.OrgID,
	)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("notification config not found")
	}
	return nil
}

// DeleteNotificationConfig deletes a notification config
func (r *Repository) DeleteNotificationConfig(ctx context.Context, id, orgID string) error {
	query := `DELETE FROM circuit_breaker_notifications WHERE id = $1 AND org_id = $2`

	result, err := r.db.ExecContext(ctx, query, id, orgID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("notification config not found")
	}
	return nil
}

// GetNotificationConfig retrieves a single notification config by ID
func (r *Repository) GetNotificationConfig(ctx context.Context, id, orgID string) (*NotificationConfig, error) {
	query := `
		SELECT id, org_id, tenant_id, type, url, secret, active, created_at, updated_at
		FROM circuit_breaker_notifications
		WHERE id = $1 AND org_id = $2`

	c := &NotificationConfig{}
	var secret sql.NullString
	err := r.db.QueryRowContext(ctx, query, id, orgID).Scan(
		&c.ID, &c.OrgID, &c.TenantID, &c.Type, &c.URL, &secret, &c.Active, &c.CreatedAt, &c.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Secret = secret.String
	return c, nil
}

// isValidURL validates a notification URL
func isValidURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http"
}
