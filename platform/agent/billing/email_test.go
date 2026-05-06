//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package billing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoopLicenseEmailSender_CapturesInMemory(t *testing.T) {
	s := &NoopLicenseEmailSender{}
	if err := s.SendLicense(context.Background(), "alice@example.com", "AXON-test-token-1"); err != nil {
		t.Fatalf("SendLicense returned error: %v", err)
	}
	if err := s.SendLicense(context.Background(), "bob@example.com", "AXON-test-token-2"); err != nil {
		t.Fatalf("second SendLicense returned error: %v", err)
	}
	got := s.CapturedSends()
	if len(got) != 2 {
		t.Fatalf("expected 2 captured sends, got %d", len(got))
	}
	if !strings.Contains(got[0], "alice@example.com") || !strings.Contains(got[0], "AXON-test-token-1") {
		t.Errorf("first capture missing expected fields: %q", got[0])
	}
}

func TestNoopLicenseEmailSender_AppendsToCaptureFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.txt")
	t.Setenv("AXONFLOW_BILLING_TEST_CAPTURE_FILE", path)

	s := &NoopLicenseEmailSender{}
	if err := s.SendLicense(context.Background(), "alice@example.com", "AXON-cap-1"); err != nil {
		t.Fatalf("SendLicense: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read capture file: %v", err)
	}
	if !strings.Contains(string(data), "AXON-cap-1") || !strings.Contains(string(data), "alice@example.com") {
		t.Errorf("capture file missing fields. got: %s", data)
	}
}

func TestResendLicenseEmailSender_PostsExpectedBody(t *testing.T) {
	var captured struct {
		Auth string
		Body map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.Auth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"resend_test"}`))
	}))
	defer srv.Close()

	s := &ResendLicenseEmailSender{
		APIKey:    "rk_test_abc",
		FromEmail: "AxonFlow <hello@getaxonflow.com>",
		HTTPClient: &http.Client{
			Transport: &rewriteTransport{target: srv.URL},
		},
	}

	err := s.SendLicense(context.Background(), "alice@example.com", "AXON-resend-test-1")
	if err != nil {
		t.Fatalf("SendLicense: %v", err)
	}
	if captured.Auth != "Bearer rk_test_abc" {
		t.Errorf("auth header: got %q", captured.Auth)
	}
	if captured.Body["from"] != "AxonFlow <hello@getaxonflow.com>" {
		t.Errorf("from: got %v", captured.Body["from"])
	}
	tos, _ := captured.Body["to"].([]any)
	if len(tos) != 1 || tos[0] != "alice@example.com" {
		t.Errorf("to: got %v", captured.Body["to"])
	}
	if !strings.Contains(captured.Body["text"].(string), "AXON-resend-test-1") {
		t.Errorf("text body must contain token, got: %s", captured.Body["text"])
	}
	if !strings.Contains(captured.Body["html"].(string), "AXON-resend-test-1") {
		t.Errorf("html body must contain token, got: %s", captured.Body["html"])
	}
}

func TestResendLicenseEmailSender_NonOKReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	s := &ResendLicenseEmailSender{
		APIKey:     "rk_test",
		FromEmail:  "AxonFlow <hello@getaxonflow.com>",
		HTTPClient: &http.Client{Transport: &rewriteTransport{target: srv.URL}},
	}
	if err := s.SendLicense(context.Background(), "x@y.com", "AXON-tok"); err == nil {
		t.Error("expected error on 503, got nil")
	}
}

func TestResendLicenseEmailSender_MissingAPIKey(t *testing.T) {
	s := &ResendLicenseEmailSender{FromEmail: "x@y.com"}
	if err := s.SendLicense(context.Background(), "a@b.com", "AXON-x"); err == nil {
		t.Error("expected error for missing APIKey")
	}
}

func TestResendLicenseEmailSender_MissingFromEmail(t *testing.T) {
	s := &ResendLicenseEmailSender{APIKey: "rk_test"}
	if err := s.SendLicense(context.Background(), "a@b.com", "AXON-x"); err == nil {
		t.Error("expected error for missing FromEmail")
	}
}

func TestNewLicenseEmailSenderFromEnv_NoAPIKeyReturnsNoop(t *testing.T) {
	t.Setenv("RESEND_API_KEY", "")
	s := NewLicenseEmailSenderFromEnv()
	if _, ok := s.(*NoopLicenseEmailSender); !ok {
		t.Errorf("expected NoopLicenseEmailSender, got %T", s)
	}
}

func TestNewLicenseEmailSenderFromEnv_WithAPIKeyReturnsResend(t *testing.T) {
	t.Setenv("RESEND_API_KEY", "rk_test_xyz")
	t.Setenv("AXONFLOW_BILLING_FROM_EMAIL", "Pro <pro@getaxonflow.com>")
	s := NewLicenseEmailSenderFromEnv()
	rs, ok := s.(*ResendLicenseEmailSender)
	if !ok {
		t.Fatalf("expected ResendLicenseEmailSender, got %T", s)
	}
	if rs.APIKey != "rk_test_xyz" {
		t.Errorf("APIKey: got %q", rs.APIKey)
	}
	if rs.FromEmail != "Pro <pro@getaxonflow.com>" {
		t.Errorf("FromEmail: got %q", rs.FromEmail)
	}
}

func TestSenderTypeLabel(t *testing.T) {
	if got := SenderTypeLabel(&NoopLicenseEmailSender{}); got != "noop" {
		t.Errorf("noop: got %q", got)
	}
	if got := SenderTypeLabel(&ResendLicenseEmailSender{}); got != "resend" {
		t.Errorf("resend: got %q", got)
	}
}

func TestBuildLicenseEmailText_ContainsTokenAndAllFourPlugins(t *testing.T) {
	body := buildLicenseEmailText("AXON-x-y-z")
	if !strings.Contains(body, "AXON-x-y-z") {
		t.Error("text body should contain token")
	}
	for _, plugin := range []string{"OpenClaw", "Cursor", "Codex", "Claude Code"} {
		if !strings.Contains(body, plugin) {
			t.Errorf("text body should mention %q plugin", plugin)
		}
	}
}

// TestBuildLicenseEmailText_NoStaleInstallCommands is the regression test for
// the 2026-05-05 fix that replaced four wrong per-plugin install commands
// (clawhub config set / Cursor settings UI / ~/.codex/axonflow.toml /
// /axonflow login --token) with the canonical AXONFLOW_LICENSE_TOKEN env
// var. None of the stale strings should ever reappear in the email body —
// each was either a non-existent command (clawhub had no `config`
// subcommand; `/axonflow login --token` was the wrong slash-command
// invocation; Cursor IDE has no env-var settings UI) or a non-existent
// config path (~/.codex/axonflow.toml was never read by the codex plugin).
func TestBuildLicenseEmailText_NoStaleInstallCommands(t *testing.T) {
	body := buildLicenseEmailText("AXON-x-y-z")
	staleStrings := []string{
		"clawhub config set",
		"Cursor settings",
		"axonflow.toml",
		"axonflow login",
	}
	for _, stale := range staleStrings {
		if strings.Contains(body, stale) {
			t.Errorf("text body should NOT contain stale install string %q (regression of pre-fix wording — see PR #1938)", stale)
		}
	}
	if !strings.Contains(body, "export AXONFLOW_LICENSE_TOKEN=") {
		t.Error("text body must contain the canonical `export AXONFLOW_LICENSE_TOKEN=` install line that works for all 4 plugins")
	}
	if !strings.Contains(body, "https://docs.getaxonflow.com/pro") {
		t.Error("text body must link to docs.getaxonflow.com/pro for per-plugin persistent-file alternatives")
	}
}

func TestBuildLicenseEmailHTML_NoStaleInstallCommands(t *testing.T) {
	body := buildLicenseEmailHTML("AXON-x-y-z")
	// HTML body uses different escaping but the same install recipe.
	staleStrings := []string{
		"clawhub config set",
		"Cursor settings",
		"axonflow.toml",
		"axonflow login",
	}
	for _, stale := range staleStrings {
		if strings.Contains(body, stale) {
			t.Errorf("HTML body should NOT contain stale install string %q (regression of pre-fix wording — see PR #1938)", stale)
		}
	}
	if !strings.Contains(body, "export AXONFLOW_LICENSE_TOKEN=") {
		t.Error("HTML body must contain the canonical `export AXONFLOW_LICENSE_TOKEN=` install line")
	}
	if !strings.Contains(body, "docs.getaxonflow.com/pro") {
		t.Error("HTML body must link to docs.getaxonflow.com/pro for per-plugin persistent-file alternatives")
	}
}

func TestBuildLicenseEmailHTML_EscapesToken(t *testing.T) {
	body := buildLicenseEmailHTML(`AXON-"><script>x`)
	if strings.Contains(body, `<script>`) {
		t.Errorf("HTML body must escape <script>: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("HTML body should contain escaped script tag: %s", body)
	}
}

// =============================================================================
// rewriteTransport — test helper that rewrites all outbound URLs to a target
// =============================================================================

type rewriteTransport struct {
	target string
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	target, err := url.Parse(rt.target)
	if err != nil {
		return nil, err
	}
	req2.URL.Scheme = target.Scheme
	req2.URL.Host = target.Host
	req2.Host = target.Host
	return http.DefaultTransport.RoundTrip(req2)
}
