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
	"strings"
	"sync"
	"time"
)

// RecoveryEmailSender abstracts the magic-link email transport so tests can
// substitute a no-op or capture implementation. Production uses ResendSender
// (or future SesSender if SES sandbox-exit is faster than Resend onboarding).
type RecoveryEmailSender interface {
	SendRecoveryLink(ctx context.Context, toEmail, magicLink string) error
}

// NoopRecoveryEmailSender writes the magic link to stdout instead of sending.
// Used in tests and dev environments where no email infrastructure is wired.
type NoopRecoveryEmailSender struct {
	mu       sync.Mutex
	captured []string
}

// SendRecoveryLink prints the magic link and captures it for test inspection.
//
// If AXONFLOW_RECOVERY_TEST_CAPTURE_FILE is set in the env, also appends the
// captured line to that file (mode 0600). This lets out-of-process runtime-e2e
// tests (e.g. shell scripts driving the agent via HTTP) extract the magic-link
// token to exercise the verify endpoint. Production environments never set
// this env var, so no file is created.
func (s *NoopRecoveryEmailSender) SendRecoveryLink(_ context.Context, toEmail, magicLink string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := fmt.Sprintf("to=%s link=%s", toEmail, magicLink)
	s.captured = append(s.captured, line)

	if path := os.Getenv("AXONFLOW_RECOVERY_TEST_CAPTURE_FILE"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			_, _ = fmt.Fprintln(f, line)
			_ = f.Close()
		}
		// Failures here are intentionally silent — this is a test-only signal,
		// not a production code path. If the file write fails the in-memory
		// capture still works for in-process tests.
	}
	return nil
}

// CapturedLinks returns a copy of all magic links captured so far. Tests use
// this to extract the magic-link token for the verify-endpoint step.
func (s *NoopRecoveryEmailSender) CapturedLinks() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.captured))
	copy(out, s.captured)
	return out
}

// ResendRecoveryEmailSender sends magic-link emails via Resend's HTTPS API.
// API docs: https://resend.com/docs/api-reference/emails/send-email
type ResendRecoveryEmailSender struct {
	APIKey    string        // Resend API key (from RESEND_API_KEY env var, never logged)
	FromEmail string        // verified sender address (e.g. "AxonFlow <recovery@getaxonflow.com>")
	HTTPClient *http.Client // optional override for tests; defaults to a 5-second-timeout client
}

// SendRecoveryLink POSTs the magic-link email body to Resend's send endpoint.
// Returns an error if the API call fails or returns non-2xx.
func (s *ResendRecoveryEmailSender) SendRecoveryLink(ctx context.Context, toEmail, magicLink string) error {
	if s.APIKey == "" {
		return fmt.Errorf("ResendRecoveryEmailSender: APIKey is empty (set RESEND_API_KEY)")
	}
	if s.FromEmail == "" {
		return fmt.Errorf("ResendRecoveryEmailSender: FromEmail is empty")
	}

	body := map[string]interface{}{
		"from":    s.FromEmail,
		"to":      []string{toEmail},
		"subject": "Recover your AxonFlow tenant",
		"text":    buildRecoveryEmailText(magicLink),
		"html":    buildRecoveryEmailHTML(magicLink),
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal recovery email body: %w", err)
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

// buildRecoveryEmailText is the plain-text email body sent to recovery requesters.
func buildRecoveryEmailText(magicLink string) string {
	return fmt.Sprintf(`Someone requested a tenant recovery for your email at AxonFlow.

Click this link within 15 minutes to recover your tenant identity:

  %s

If you didn't request this, you can ignore this email — no changes will be made.

— AxonFlow
https://getaxonflow.com
`, magicLink)
}

// buildRecoveryEmailHTML is the HTML email body sent to recovery requesters.
//
// HTML-escapes the magicLink before interpolation. Even though the magicLink
// is built from a controlled token (hex-only) plus AXONFLOW_RECOVERY_BASE_URL
// (operator-controlled), an operator-set base URL could in principle contain
// quote characters that break out of the href attribute. The escape is
// defense-in-depth.
func buildRecoveryEmailHTML(magicLink string) string {
	safe := htmlAttrEscape(magicLink)
	return fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family: -apple-system, system-ui, sans-serif; max-width: 540px; margin: 2em auto; color: #1a1a1a;">
  <h2 style="color: #1a1a1a;">Recover your AxonFlow tenant</h2>
  <p>Someone requested a tenant recovery for your email at AxonFlow.</p>
  <p><a href="%s" style="display: inline-block; padding: 0.75em 1.25em; background: #2563eb; color: white; text-decoration: none; border-radius: 6px;">Recover my tenant</a></p>
  <p style="color: #666; font-size: 0.9em;">This link expires in 15 minutes.</p>
  <p style="color: #666; font-size: 0.9em;">If you didn't request this, you can ignore this email — no changes will be made.</p>
  <hr style="border: 0; border-top: 1px solid #eee; margin: 2em 0;">
  <p style="color: #999; font-size: 0.85em;">AxonFlow · <a href="https://getaxonflow.com" style="color: #999;">getaxonflow.com</a></p>
</body></html>
`, safe)
}

// htmlAttrEscape escapes the five characters that have special meaning when
// interpolated inside an HTML attribute value: & < > " '. Sufficient for
// href="..." contexts where the value is wrapped in double quotes.
func htmlAttrEscape(s string) string {
	r := s
	r = strings.ReplaceAll(r, "&", "&amp;")
	r = strings.ReplaceAll(r, "<", "&lt;")
	r = strings.ReplaceAll(r, ">", "&gt;")
	r = strings.ReplaceAll(r, "\"", "&quot;")
	r = strings.ReplaceAll(r, "'", "&#39;")
	return r
}

// NewRecoveryEmailSenderFromEnv returns a sender configured from environment.
// Selects between Resend (if RESEND_API_KEY is set) and Noop (otherwise — for
// dev / tests / CI where no real email transport is wired).
//
// FromEmail defaults to "AxonFlow <recovery@getaxonflow.com>" but can be
// overridden via AXONFLOW_RECOVERY_FROM_EMAIL.
func NewRecoveryEmailSenderFromEnv() RecoveryEmailSender {
	apiKey := os.Getenv("RESEND_API_KEY")
	if apiKey == "" {
		return &NoopRecoveryEmailSender{}
	}
	from := os.Getenv("AXONFLOW_RECOVERY_FROM_EMAIL")
	if from == "" {
		from = "AxonFlow <recovery@getaxonflow.com>"
	}
	return &ResendRecoveryEmailSender{
		APIKey:    apiKey,
		FromEmail: from,
	}
}
