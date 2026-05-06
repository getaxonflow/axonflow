//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package billing

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

	"axonflow/platform/shared/secretenv"
)

// LicenseEmailSender abstracts the post-purchase email transport so tests can
// substitute a no-op or capture implementation. Production uses
// ResendLicenseEmailSender; tests / dev use NoopLicenseEmailSender.
//
// Mirrors the W3 RecoveryEmailSender pattern in
// platform/agent/community_saas_recovery_email.go so operators only have one
// email-stack mental model to maintain (Resend, sender envelope, capture
// file convention).
type LicenseEmailSender interface {
	SendLicense(ctx context.Context, toEmail, token string) error
}

// NoopLicenseEmailSender writes the license token to stdout and to an
// optional capture file instead of dispatching email. Used for tests and
// any environment where Resend isn't wired (RESEND_API_KEY unset).
//
// AXONFLOW_BILLING_TEST_CAPTURE_FILE — when set, every send appends a line
// "to=<email> token=<token>" to the file (mode 0600). This is how
// out-of-process runtime-e2e tests fish the just-issued token out of the
// agent without parsing logs.
type NoopLicenseEmailSender struct {
	mu       sync.Mutex
	captured []string
}

// SendLicense records the (email, token) pair for in-process inspection and
// optionally appends to AXONFLOW_BILLING_TEST_CAPTURE_FILE. Always returns
// nil — Noop is for environments where email failure is not meaningful.
func (s *NoopLicenseEmailSender) SendLicense(_ context.Context, toEmail, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := fmt.Sprintf("to=%s token=%s", toEmail, token)
	s.captured = append(s.captured, line)

	if path := os.Getenv("AXONFLOW_BILLING_TEST_CAPTURE_FILE"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			_, _ = fmt.Fprintln(f, line)
			_ = f.Close()
		}
		// Same intentional-silence rationale as W3: if the test capture file
		// can't be written, in-memory capture still works for in-process tests.
	}
	return nil
}

// CapturedSends returns a copy of all (email, token) lines captured so far.
func (s *NoopLicenseEmailSender) CapturedSends() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.captured))
	copy(out, s.captured)
	return out
}

// ResendLicenseEmailSender sends the post-purchase license-token email via
// Resend's HTTPS API. API docs: https://resend.com/docs/api-reference/emails/send-email
type ResendLicenseEmailSender struct {
	APIKey     string
	FromEmail  string       // verified sender (e.g. "AxonFlow <hello@getaxonflow.com>")
	HTTPClient *http.Client // optional override for tests; defaults to a 5s-timeout client
}

// SendLicense POSTs the license-delivery email body to Resend.
func (s *ResendLicenseEmailSender) SendLicense(ctx context.Context, toEmail, token string) error {
	if s.APIKey == "" {
		return fmt.Errorf("ResendLicenseEmailSender: APIKey is empty (set RESEND_API_KEY)")
	}
	if s.FromEmail == "" {
		return fmt.Errorf("ResendLicenseEmailSender: FromEmail is empty")
	}

	body := map[string]interface{}{
		"from":    s.FromEmail,
		"to":      []string{toEmail},
		"subject": "Your AxonFlow Pro license token",
		"text":    buildLicenseEmailText(token),
		"html":    buildLicenseEmailHTML(token),
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal license email body: %w", err)
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

// buildLicenseEmailText is the plain-text email body delivered after a
// successful Pro v1 checkout. The body must contain:
//  1. The full AXON- token (so the buyer can copy-paste)
//  2. Install instructions that actually work in each plugin
//
// Anyone editing this needs to keep the token on its own line so terminal
// copy-paste (triple-click) selects exactly the token without trailing
// whitespace.
//
// Recipe note (2026-05-05): the env-var install (AXONFLOW_LICENSE_TOKEN)
// is the canonical path because it works identically across all four
// plugins and is verifiable from each plugin's source. The previous body
// recommended commands that were either non-existent (`clawhub config set
// license-token`, `/axonflow login --token`) or pointed at config files
// no plugin actually reads (`~/.codex/axonflow.toml`). Per-plugin
// persistent-file alternatives + verification + the customer-facing
// docs.getaxonflow.com/pro page mirror this same canonical recipe.
func buildLicenseEmailText(token string) string {
	return fmt.Sprintf(`Thank you for upgrading to AxonFlow Pro.

Your license token (save this — you'll only see it here):

  %s

Install — works the same across OpenClaw, Cursor, Codex, and Claude Code:

  export AXONFLOW_LICENSE_TOKEN='%s'

Add the line to your shell profile (~/.zshrc, ~/.bash_profile, etc.) so
every plugin host launched from your shell inherits it. The next governed
action through any plugin picks up the token on the next invocation.

For Cursor IDE: restart Cursor after exporting so the IDE process inherits
the env var.

Per-plugin persistent-file alternatives + verification commands:
  https://docs.getaxonflow.com/pro

Lost this email or your token? Use the recovery flow (free-tier):
  https://try.getaxonflow.com/recover

Questions? Reply to this email.

— AxonFlow
https://getaxonflow.com
`, token, token)
}

// buildLicenseEmailHTML is the HTML body. Token is embedded in a <code>
// block so it renders monospaced and copy-pastable. The token is HTML-escaped
// even though it's hex-and-dot only — defense in depth, the cost is one
// function call per email.
func buildLicenseEmailHTML(token string) string {
	safe := htmlAttrEscape(token)
	return fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family: -apple-system, system-ui, sans-serif; max-width: 600px; margin: 2em auto; padding: 0 1em; color: #1a1a1a;">
  <h2 style="color: #2B9B9B;">Thank you for upgrading to AxonFlow Pro</h2>
  <p>Your license token (save this — you'll only see it here):</p>
  <pre style="background: #f3f4f6; padding: 1em; border-radius: 6px; overflow-x: auto; font-family: 'SF Mono', Menlo, monospace; font-size: 0.85em;"><code>%s</code></pre>
  <h3 style="color: #1a1a1a;">Install</h3>
  <p>Works the same across OpenClaw, Cursor, Codex, and Claude Code:</p>
  <pre style="background: #f3f4f6; padding: 1em; border-radius: 6px; overflow-x: auto; font-family: 'SF Mono', Menlo, monospace; font-size: 0.85em;"><code>export AXONFLOW_LICENSE_TOKEN='%s'</code></pre>
  <p>Add the line to your shell profile (<code>~/.zshrc</code>, <code>~/.bash_profile</code>, etc.) so every plugin host launched from your shell inherits it. The next governed action through any plugin picks up the token on the next invocation.</p>
  <p><strong>For Cursor IDE:</strong> restart Cursor after exporting so the IDE process inherits the env var.</p>
  <p>Per-plugin persistent-file alternatives + verification commands:
    <a href="https://docs.getaxonflow.com/pro" style="color: #2B9B9B;">docs.getaxonflow.com/pro</a></p>
  <p style="color: #666; font-size: 0.9em;">Lost this email or your token? Use the recovery flow (free-tier):
    <a href="https://try.getaxonflow.com/recover" style="color: #2B9B9B;">try.getaxonflow.com/recover</a></p>
  <hr style="border: 0; border-top: 1px solid #eee; margin: 2em 0;">
  <p style="color: #999; font-size: 0.85em;">AxonFlow · <a href="https://getaxonflow.com" style="color: #999;">getaxonflow.com</a></p>
</body></html>
`, safe, safe)
}

// htmlAttrEscape escapes the five HTML-attribute special characters. Local to
// this package to avoid cross-package coupling with the W3 recovery email
// helper, which has the same logic but lives in package agent.
func htmlAttrEscape(s string) string {
	r := s
	r = strings.ReplaceAll(r, "&", "&amp;")
	r = strings.ReplaceAll(r, "<", "&lt;")
	r = strings.ReplaceAll(r, ">", "&gt;")
	r = strings.ReplaceAll(r, "\"", "&quot;")
	r = strings.ReplaceAll(r, "'", "&#39;")
	return r
}

// NewLicenseEmailSenderFromEnv selects between Resend (when RESEND_API_KEY is
// set) and Noop (otherwise — for dev / tests / CI / local Docker compose).
//
// FromEmail defaults to "AxonFlow <hello@getaxonflow.com>" and can be
// overridden via AXONFLOW_BILLING_FROM_EMAIL.
//
// Reads via secretenv.Get so a trailing newline on the AWS SM secret
// value (a recurring V1-launch footgun — the Resend Authorization header
// fails closed with `net/http: invalid header field value`) is silently
// trimmed at boot rather than at the first webhook delivery.
func NewLicenseEmailSenderFromEnv() LicenseEmailSender {
	apiKey := secretenv.Get("RESEND_API_KEY")
	if apiKey == "" {
		return &NoopLicenseEmailSender{}
	}
	from := secretenv.Get("AXONFLOW_BILLING_FROM_EMAIL")
	if from == "" {
		from = "AxonFlow <hello@getaxonflow.com>"
	}
	return &ResendLicenseEmailSender{
		APIKey:    apiKey,
		FromEmail: from,
	}
}

// SenderTypeLabel returns the Prometheus label value identifying the
// concrete sender implementation. Used by webhook.go to attribute send
// success/failure counters to the right provider.
func SenderTypeLabel(s LicenseEmailSender) string {
	switch s.(type) {
	case *NoopLicenseEmailSender:
		return "noop"
	case *ResendLicenseEmailSender:
		return "resend"
	default:
		return "unknown"
	}
}
