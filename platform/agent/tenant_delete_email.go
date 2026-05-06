// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"axonflow/platform/shared/secretenv"
)

// TenantDeletionEmailSender abstracts the deletion-confirmation email transport
// so tests can substitute a no-op or capture implementation. Production uses
// ResendTenantDeletionEmailSender via Resend's API.
//
// We use a separate interface from RecoveryEmailSender because the message
// shape (subject, body, included token) is materially different from the W3
// magic-link recovery flow, even though the underlying transport is the same.
type TenantDeletionEmailSender interface {
	// SendDeletionLink sends the delete-confirmation email. The token is
	// included in the body so the user can complete the deletion via curl
	// or the dashboard. confirmURL is the POST endpoint they target.
	SendDeletionLink(ctx context.Context, toEmail, tenantID, token, confirmURL string) error
}

// NoopTenantDeletionEmailSender writes the captured deletion details to
// stdout (and optionally an env-pointed file) instead of sending email.
// Used in tests and runtime-e2e harnesses.
type NoopTenantDeletionEmailSender struct {
	mu       sync.Mutex
	captured []string
}

// SendDeletionLink prints the captured details and stores them for test inspection.
//
// If AXONFLOW_TENANT_DELETE_TEST_CAPTURE_FILE is set, also appends to that
// file (mode 0600). This lets out-of-process runtime-e2e shell tests extract
// the token to exercise the confirm endpoint. Production never sets this.
func (s *NoopTenantDeletionEmailSender) SendDeletionLink(_ context.Context, toEmail, tenantID, token, confirmURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := fmt.Sprintf("to=%s tenant=%s token=%s url=%s", toEmail, tenantID, token, confirmURL)
	s.captured = append(s.captured, line)

	if path := os.Getenv("AXONFLOW_TENANT_DELETE_TEST_CAPTURE_FILE"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			_, _ = fmt.Fprintln(f, line)
			_ = f.Close()
		}
		// Silent failures — see RecoveryEmailSender comment for rationale.
	}
	return nil
}

// CapturedLinks returns a copy of all captured deletion details so far.
func (s *NoopTenantDeletionEmailSender) CapturedLinks() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.captured))
	copy(out, s.captured)
	return out
}

// ResendTenantDeletionEmailSender sends deletion-confirmation emails via
// Resend's HTTPS API. Same shape as ResendRecoveryEmailSender but with a
// different message body and subject.
type ResendTenantDeletionEmailSender struct {
	APIKey     string
	FromEmail  string
	HTTPClient *http.Client
}

// SendDeletionLink POSTs the deletion-confirmation email body to Resend.
func (s *ResendTenantDeletionEmailSender) SendDeletionLink(ctx context.Context, toEmail, tenantID, token, confirmURL string) error {
	if s.APIKey == "" {
		return fmt.Errorf("ResendTenantDeletionEmailSender: APIKey is empty (set RESEND_API_KEY)")
	}
	if s.FromEmail == "" {
		return fmt.Errorf("ResendTenantDeletionEmailSender: FromEmail is empty")
	}

	body := map[string]interface{}{
		"from":    s.FromEmail,
		"to":      []string{toEmail},
		"subject": "Confirm AxonFlow tenant deletion",
		"text":    buildTenantDeleteEmailText(tenantID, token, confirmURL),
		"html":    buildTenantDeleteEmailHTML(tenantID, token, confirmURL),
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal deletion email body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.resend.com/emails", bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("build resend request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.APIKey)

	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("resend send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("resend returned status %d", resp.StatusCode)
	}
	return nil
}

// buildTenantDeleteEmailText is the plain-text body for the deletion email.
// Includes the curl invocation so CLI users can complete deletion without
// a dashboard. The token is shown in plain — there's no defense-in-depth
// gain from obscuring it (the confirmation flow is the gate).
func buildTenantDeleteEmailText(tenantID, token, confirmURL string) string {
	return fmt.Sprintf(`Someone requested deletion of your AxonFlow tenant.

If you initiated this, complete the deletion within 1 hour by running:

  curl -X POST '%s' \
    -H 'Content-Type: application/json' \
    -d '{"token":"%s"}'

Tenant: %s

This will permanently delete:
  - Your tenant credentials
  - Any active Pro license you hold
  - All audit history under this tenant
  - All daily-quota / usage counters

The deletion is GDPR-compliant and irreversible. If you didn't request this,
ignore this email — no changes will be made and the link will expire.

— AxonFlow
https://getaxonflow.com
`, confirmURL, token, tenantID)
}

// buildTenantDeleteEmailHTML is the HTML body for the deletion email.
// HTML-escapes interpolated values defense-in-depth (token is base64url so
// always safe; tenant_id and confirmURL are operator/system-controlled but
// could in principle contain quote characters).
func buildTenantDeleteEmailHTML(tenantID, token, confirmURL string) string {
	safeTenant := htmlAttrEscape(tenantID)
	safeToken := htmlAttrEscape(token)
	safeURL := htmlAttrEscape(confirmURL)
	return fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family: -apple-system, system-ui, sans-serif; max-width: 600px; margin: 2em auto; color: #1a1a1a;">
  <h2 style="color: #b00020;">Confirm AxonFlow tenant deletion</h2>
  <p>Someone requested deletion of your AxonFlow tenant <code>%s</code>.</p>
  <p>If you initiated this, complete the deletion within 1 hour by running:</p>
  <pre style="background: #f3f4f6; padding: 1em; border-radius: 6px; overflow-x: auto;">curl -X POST '%s' \
  -H 'Content-Type: application/json' \
  -d '{"token":"%s"}'</pre>
  <p style="color: #b00020;"><strong>This is irreversible.</strong> All credentials, audit history, and any active Pro license bound to this tenant will be permanently deleted in compliance with GDPR Article 17.</p>
  <p style="color: #666; font-size: 0.9em;">If you didn't request this, ignore this email — no changes will be made and the link will expire in 1 hour.</p>
  <hr style="border: 0; border-top: 1px solid #eee; margin: 2em 0;">
  <p style="color: #999; font-size: 0.85em;">AxonFlow · <a href="https://getaxonflow.com" style="color: #999;">getaxonflow.com</a></p>
</body></html>
`, safeTenant, safeURL, safeToken)
}

// NewTenantDeletionEmailSenderFromEnv returns a sender configured from environment.
// Selects between Resend (RESEND_API_KEY set) and Noop (otherwise).
func NewTenantDeletionEmailSenderFromEnv() TenantDeletionEmailSender {
	apiKey := secretenv.Get("RESEND_API_KEY")
	if apiKey == "" {
		return &NoopTenantDeletionEmailSender{}
	}
	from := secretenv.Get("AXONFLOW_DELETE_FROM_EMAIL")
	if from == "" {
		// Default to the recovery from-email — same domain, same Resend
		// verification, just a different subject. Operators may override
		// per env if they want a separate compliance@ alias.
		from = secretenv.Get("AXONFLOW_RECOVERY_FROM_EMAIL")
	}
	if from == "" {
		from = "AxonFlow <compliance@getaxonflow.com>"
	}
	return &ResendTenantDeletionEmailSender{
		APIKey:    apiKey,
		FromEmail: from,
	}
}
