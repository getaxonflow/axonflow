// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRenderConfirmPageEscapesXSS proves the html/template conversion neutralizes
// a reflected-XSS payload in both the element-text (email) and attribute-value
// (token) contexts. Closes go/reflected-xss on community_saas_recovery.go.
func TestRenderConfirmPageEscapesXSS(t *testing.T) {
	rec := httptest.NewRecorder()
	const xssEmail = `"><script>alert(1)</script>`
	const xssToken = `"><img src=x onerror=alert(2)>`
	renderConfirmPage(rec, xssToken, xssEmail)

	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("email payload was not escaped: body contains raw <script>")
	}
	// html/template escapes the breakout chars (" < >) in the attribute-value
	// context, so a raw <img tag must never appear; the inert literal text
	// "onerror" inside a properly-escaped value is harmless.
	if strings.Contains(body, "<img src=x") {
		t.Fatalf("token payload broke out of the attribute: body contains raw <img tag")
	}
	// The escaped form must still be present so the page renders the values.
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("expected HTML-escaped script tag in body, got: %s", body)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected X-Content-Type-Options=nosniff, got %q", got)
	}
}

// TestRenderConfirmErrorPageEscapes verifies the error page (also converted to
// html/template) escapes its message and sets nosniff.
func TestRenderConfirmErrorPageEscapes(t *testing.T) {
	rec := httptest.NewRecorder()
	renderConfirmErrorPage(rec, 400, `<script>alert(3)</script>`)
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(3)</script>") {
		t.Fatalf("error-page message was not escaped: %s", body)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected nosniff on error page, got %q", got)
	}
}

// TestTransparencyResponseWriterSetsNoSniff verifies the passthrough wrapper sets
// the anti-MIME-sniffing header on both the WriteHeader and Write paths.
func TestTransparencyResponseWriterSetsNoSniff(t *testing.T) {
	t.Run("WriteHeader path", func(t *testing.T) {
		rec := httptest.NewRecorder()
		tw := NewTransparencyResponseWriter(rec, NewTransparencyContext())
		tw.WriteHeader(200)
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Fatalf("expected nosniff after WriteHeader, got %q", got)
		}
	})
	t.Run("Write path", func(t *testing.T) {
		rec := httptest.NewRecorder()
		tw := NewTransparencyResponseWriter(rec, NewTransparencyContext())
		if _, err := tw.Write([]byte(`{"ok":true}`)); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Fatalf("expected nosniff after Write, got %q", got)
		}
	})
}

// TestStatusWriterSetsNoSniff verifies the telemetry status-capture wrapper sets
// the anti-MIME-sniffing header.
func TestStatusWriterSetsNoSniff(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, statusCode: 200}
	if _, err := sw.Write([]byte(`{"ok":true}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected nosniff, got %q", got)
	}
}
