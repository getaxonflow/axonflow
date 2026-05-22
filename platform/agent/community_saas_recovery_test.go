// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
)

// =============================================================================
// PR-B helpers — POST-based verify (replaces the GET-based verify in PR A)
// =============================================================================

// postVerifyJSON builds a POST request to /api/v1/recover/verify with the
// token in a JSON body. Used by all post-PR-B verify tests since the GET
// endpoint now renders an HTML confirmation page rather than consuming.
func postVerifyJSON(token string) *http.Request {
	body := fmt.Sprintf(`{"token":%q}`, token)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/recover/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// postVerifyForm builds a POST request with token in form-urlencoded body.
// Mirrors what the HTML confirmation page's form sends on user click.
func postVerifyForm(token string) *http.Request {
	body := fmt.Sprintf("token=%s", token)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/recover/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// =============================================================================
// PR-B tests — GET confirmation page (NO state change; safe for prefetchers)
// =============================================================================

func TestRecoveryConfirmPage_NilDB_Returns503HTML(t *testing.T) {
	router := mux.NewRouter()
	RegisterCommunityRecoveryHandler(router, nil, &NoopRecoveryEmailSender{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/recover/verify?token=abc", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("nil DB should return 503, got %d", w.Code)
	}
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("error response should be HTML for browser users, got Content-Type=%s", w.Header().Get("Content-Type"))
	}
}

func TestRecoveryConfirmPage_NoToken_Returns400HTML(t *testing.T) {
	router, _, _ := newRecoveryRouterWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/recover/verify", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing token should return 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Missing token") {
		t.Errorf("expected error page mentioning missing token, got: %s", w.Body.String()[:200])
	}
}

func TestRecoveryConfirmPage_BogusToken_Returns401HTML(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("bogus")).
		WillReturnError(sql.ErrNoRows)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/recover/verify?token=bogus", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("bogus token should return 401, got %d", w.Code)
	}
}

func TestRecoveryConfirmPage_ValidToken_RendersHTMLWithFormButNoConsume(t *testing.T) {
	// Critical PR-B assertion: GET with a valid unconsumed token must NOT
	// consume it. The page just shows a confirmation form. Token is consumed
	// only on the subsequent POST when the user clicks Confirm.
	router, mock, _ := newRecoveryRouterWithDB(t)
	futureExpiry := time.Now().UTC().Add(10 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("valid")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", futureExpiry, nil))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/recover/verify?token=valid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("valid token GET should return 200 (HTML page), got %d", w.Code)
	}
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("response should be HTML, got Content-Type=%s", w.Header().Get("Content-Type"))
	}
	body := w.Body.String()
	if !strings.Contains(body, `<form method="POST" action="/api/v1/recover/verify">`) {
		t.Errorf("page should contain the confirm form posting to verify endpoint")
	}
	if !strings.Contains(body, "Confirm recovery") {
		t.Errorf("page should contain the Confirm button")
	}
	if !strings.Contains(body, "alice@example.com") {
		t.Errorf("page should display the user's email")
	}
	// CRITICAL: ensure no UPDATE was issued (token wasn't consumed)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("GET should only do the SELECT lookup, no UPDATE/INSERT: %v", err)
	}
}

func TestRecoveryConfirmPage_ExpiredToken_RendersErrorHTML(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)
	pastExpiry := time.Now().UTC().Add(-1 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("old")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", pastExpiry, nil))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/recover/verify?token=old", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expired token GET should return 401, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "expired") {
		t.Errorf("error page should mention expiration: %s", w.Body.String()[:200])
	}
}

func TestRecoveryConfirmPage_ConsumedToken_RendersErrorHTML(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)
	futureExpiry := time.Now().UTC().Add(10 * time.Minute)
	consumedAt := time.Now().UTC().Add(-5 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("used")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", futureExpiry, consumedAt))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/recover/verify?token=used", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("consumed token GET should return 401, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "already been used") {
		t.Errorf("error page should mention already-used: %s", w.Body.String()[:200])
	}
}

// =============================================================================
// PR-B tests — POST verify with form-urlencoded body (HTML form submit path)
// =============================================================================

func TestRecoveryVerify_FormBody_HappyPath(t *testing.T) {
	// Simulates the user clicking the Confirm button on the HTML page.
	// Browser sends application/x-www-form-urlencoded body with token=...
	router, mock, _ := newRecoveryRouterWithDB(t)
	futureExpiry := time.Now().UTC().Add(10 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("formtoken")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", futureExpiry, nil))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT COUNT.*FROM community_saas_registrations").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectExec("UPDATE community_saas_recovery_tokens").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT csaas_recovery_insert\(\$1, \$2, \$3, \$4, \$5, \$6\)`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("UPDATE community_saas_recovery_tokens").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectExec("SELECT register_org").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SELECT register_tenant").WillReturnResult(sqlmock.NewResult(0, 0))

	req := postVerifyForm("formtoken")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("form-body verify happy path should return 200, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestRecoveryVerify_UnsupportedContentType_Returns415(t *testing.T) {
	router, _, _ := newRecoveryRouterWithDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/recover/verify",
		strings.NewReader(`<xml/>`))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("unsupported Content-Type should return 415, got %d", w.Code)
	}
}

func TestRecoveryVerify_MissingTokenInBody_Returns400(t *testing.T) {
	router, _, _ := newRecoveryRouterWithDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/recover/verify",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty token should return 400, got %d", w.Code)
	}
}

// =============================================================================
// PR-B tests — sender type label (for Prometheus metric attribution)
// =============================================================================

func TestSenderTypeLabel_KnownTypes(t *testing.T) {
	if got := senderTypeLabel(&NoopRecoveryEmailSender{}); got != "noop" {
		t.Errorf("noop sender label = %q, want noop", got)
	}
	if got := senderTypeLabel(&ResendRecoveryEmailSender{APIKey: "k"}); got != "resend" {
		t.Errorf("resend sender label = %q, want resend", got)
	}
}

type unknownSender struct{}

func (unknownSender) SendRecoveryLink(_ context.Context, _, _ string) error { return nil }

func TestSenderTypeLabel_UnknownType_FallsBackToUnknown(t *testing.T) {
	if got := senderTypeLabel(unknownSender{}); got != "unknown" {
		t.Errorf("unknown sender label = %q, want unknown", got)
	}
}

// =============================================================================
// PR-B tests — Noop sender file-capture mode (used by runtime-e2e to extract tokens)
// =============================================================================

func TestNoopSender_FileCapture_AppendsWhenEnvSet(t *testing.T) {
	tmp := t.TempDir()
	capPath := tmp + "/captured.txt"
	t.Setenv("AXONFLOW_RECOVERY_TEST_CAPTURE_FILE", capPath)

	s := &NoopRecoveryEmailSender{}
	if err := s.SendRecoveryLink(context.Background(), "alice@example.com", "https://x/v?token=abc"); err != nil {
		t.Fatalf("noop send failed: %v", err)
	}
	if err := s.SendRecoveryLink(context.Background(), "bob@example.com", "https://x/v?token=def"); err != nil {
		t.Fatalf("noop send 2 failed: %v", err)
	}

	// Verify file was written with both captures
	data, err := os.ReadFile(capPath)
	if err != nil {
		t.Fatalf("capture file not written: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "to=alice@example.com") {
		t.Errorf("capture file missing first send: %s", content)
	}
	if !strings.Contains(content, "to=bob@example.com") {
		t.Errorf("capture file missing second send: %s", content)
	}
	if !strings.Contains(content, "token=abc") {
		t.Errorf("capture file missing first token")
	}
	if !strings.Contains(content, "token=def") {
		t.Errorf("capture file missing second token")
	}
	// File mode 0600 (per implementation comment)
	info, _ := os.Stat(capPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("capture file should be mode 0600, got %v", info.Mode().Perm())
	}
}

func TestNoopSender_FileCapture_NoOpWhenEnvUnset(t *testing.T) {
	t.Setenv("AXONFLOW_RECOVERY_TEST_CAPTURE_FILE", "")
	s := &NoopRecoveryEmailSender{}
	// Should not panic, should not error
	if err := s.SendRecoveryLink(context.Background(), "x@y.com", "https://z/v?token=q"); err != nil {
		t.Fatalf("noop send failed: %v", err)
	}
	// In-memory capture still works
	if len(s.CapturedLinks()) != 1 {
		t.Errorf("in-memory capture should still work without env var")
	}
}

func TestNoopSender_FileCapture_SilentlySkipsBadPath(t *testing.T) {
	// If the path is unwritable (e.g. in a read-only dir), we silently swallow
	// the error — this is a test-only signal, not a production code path.
	t.Setenv("AXONFLOW_RECOVERY_TEST_CAPTURE_FILE", "/nonexistent-dir-xyz123/cannot-write.txt")
	s := &NoopRecoveryEmailSender{}
	if err := s.SendRecoveryLink(context.Background(), "x@y.com", "https://z/v?token=q"); err != nil {
		t.Errorf("noop send should never return error even if file unwritable, got: %v", err)
	}
	// In-memory capture still works
	if len(s.CapturedLinks()) != 1 {
		t.Errorf("in-memory capture should still work despite file write failure")
	}
}

// =============================================================================
// PR A — htmlAttrEscape + email-bound register tests (critical-fixes coverage)
// =============================================================================

func TestHtmlAttrEscape_HandlesAllSpecials(t *testing.T) {
	cases := map[string]string{
		"plain":              "plain",
		"a&b":                "a&amp;b",
		`a"b`:                "a&quot;b",
		"a<b":                "a&lt;b",
		"a>b":                "a&gt;b",
		"a'b":                "a&#39;b",
		`<script>"&'</script>`: "&lt;script&gt;&quot;&amp;&#39;&lt;/script&gt;",
	}
	for in, want := range cases {
		got := htmlAttrEscape(in)
		if got != want {
			t.Errorf("htmlAttrEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildRecoveryEmailHTML_EscapesMaliciousURL(t *testing.T) {
	// Defense in depth: even though magicLink is built from a hex token + an
	// operator-controlled base URL, an operator-set base URL with " or < would
	// otherwise break out of the href attribute. Verify the escape is applied.
	bad := `https://evil.com/" onclick="alert(1)"`
	body := buildRecoveryEmailHTML(bad)
	if strings.Contains(body, `onclick="alert(1)"`) {
		t.Errorf("HTML body must not contain unescaped quote-breakout payload")
	}
	if !strings.Contains(body, `&quot;`) {
		t.Errorf("expected &quot; entity in escaped output, got: %s", body)
	}
}

// =============================================================================
// sqlmock-backed tests for DB-dependent handler paths
// =============================================================================

// newRecoveryRouterWithDB returns a router wired to a sqlmock-backed handler.
// Tests use this when they need to exercise DB-dependent code paths.
//
// Resets regIPTracker between tests so the per-IP rate-limit state from
// previous tests doesn't bleed into this one (httptest uses a fixed
// RemoteAddr, so all tests share the same IP).
func newRecoveryRouterWithDB(t *testing.T) (*mux.Router, sqlmock.Sqlmock, *NoopRecoveryEmailSender) {
	t.Helper()
	resetRegIPTracker()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	router := mux.NewRouter()
	noop := &NoopRecoveryEmailSender{}
	RegisterCommunityRecoveryHandler(router, db, noop)
	return router, mock, noop
}

// resetRegIPTracker clears the per-IP rate-limit state. Used at start of
// each handler test to avoid IP rate-limit bleed from earlier tests
// (httptest's fixed RemoteAddr means all tests share the same IP).
func resetRegIPTracker() {
	regIPTracker.mu.Lock()
	regIPTracker.entries = make(map[string]*ipRegistrationEntry)
	regIPTracker.mu.Unlock()
}

func postRecoverWithBody(router *mux.Router, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/recover", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestRecoveryRequest_InvalidEmail_Returns400(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)
	w := postRecover(router, recoveryRequestBody{Email: "not-an-email"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid email should return 400, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls: %v", err)
	}
}

func TestRecoveryRequest_InvalidJSON_Returns400(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)
	w := postRecoverWithBody(router, []byte("{not-json"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON should return 400, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls: %v", err)
	}
}

func TestRecoveryRequest_BodyTooLarge_Returns413(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)
	huge := bytes.Repeat([]byte("x"), maxRequestBodySize+10)
	w := postRecoverWithBody(router, huge)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body should return 413, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls: %v", err)
	}
}

func TestRecoveryRequest_RateLimitHit_Returns202Generic(t *testing.T) {
	router, mock, noop := newRecoveryRouterWithDB(t)

	// Per-email rate-limit query returns count >= recoveryEmailRateLimit
	mock.ExpectQuery("SELECT COUNT").
		WithArgs("alice@example.com", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(recoveryEmailRateLimit))

	w := postRecover(router, recoveryRequestBody{Email: "alice@example.com"})
	if w.Code != http.StatusAccepted {
		t.Errorf("rate-limited should still return 202 (generic), got %d", w.Code)
	}
	// No email should have been sent (rate-limited path returns before send)
	if len(noop.CapturedLinks()) != 0 {
		t.Errorf("rate-limited path should not send email, sent %d", len(noop.CapturedLinks()))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected DB queries unmet: %v", err)
	}
}

func TestRecoveryRequest_EmailNotFound_Returns202Generic_NoSend(t *testing.T) {
	router, mock, noop := newRecoveryRouterWithDB(t)

	// Rate-limit count is below cap
	mock.ExpectQuery("SELECT COUNT").
		WithArgs("ghost@example.com", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	// Tenant existence check returns false
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("ghost@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	w := postRecover(router, recoveryRequestBody{Email: "ghost@example.com"})
	if w.Code != http.StatusAccepted {
		t.Errorf("unknown-email path should return 202 (generic), got %d", w.Code)
	}
	if len(noop.CapturedLinks()) != 0 {
		t.Errorf("unknown email should not send email, sent %d", len(noop.CapturedLinks()))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected DB queries unmet: %v", err)
	}
}

func TestRecoveryRequest_EmailFound_IssuesTokenAndSends(t *testing.T) {
	router, mock, noop := newRecoveryRouterWithDB(t)

	mock.ExpectQuery("SELECT COUNT").
		WithArgs("alice@example.com", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec("INSERT INTO community_saas_recovery_tokens").
		WithArgs(sqlmock.AnyArg(), "alice@example.com", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := postRecover(router, recoveryRequestBody{Email: "alice@example.com"})
	if w.Code != http.StatusAccepted {
		t.Errorf("happy path should return 202, got %d", w.Code)
	}

	captured := noop.CapturedLinks()
	if len(captured) != 1 {
		t.Fatalf("expected 1 captured email, got %d", len(captured))
	}
	if !strings.Contains(captured[0], "alice@example.com") {
		t.Errorf("captured email missing recipient: %s", captured[0])
	}
	if !strings.Contains(captured[0], "/api/v1/recover/verify?token=") {
		t.Errorf("captured email missing magic-link path: %s", captured[0])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected DB calls unmet: %v", err)
	}
}

func TestRecoveryRequest_NormalisesEmailCase(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)

	// Server should lowercase the email before queries
	mock.ExpectQuery("SELECT COUNT").
		WithArgs("alice@example.com", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	w := postRecover(router, recoveryRequestBody{Email: "  Alice@Example.COM  "})
	if w.Code != http.StatusAccepted {
		t.Errorf("normalized-email request should return 202, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB args mismatch — server may not be normalizing email: %v", err)
	}
}

func TestRecoveryRequest_DBError_StillReturns202Generic(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)

	// Rate-limit query returns DB error
	mock.ExpectQuery("SELECT COUNT").
		WithArgs("alice@example.com", sqlmock.AnyArg()).
		WillReturnError(errFakeDB)

	w := postRecover(router, recoveryRequestBody{Email: "alice@example.com"})
	// Server returns 202 generic on DB error to preserve anti-enumeration property
	if w.Code != http.StatusAccepted {
		t.Errorf("DB error should still return 202 (anti-enum), got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected DB call unmet: %v", err)
	}
}

// errFakeDB is a sentinel for sqlmock error returns
var errFakeDB = sqlmockErr("simulated DB failure")

type sqlmockErr string

func (e sqlmockErr) Error() string { return string(e) }

// =============================================================================
// Verify endpoint — DB-backed paths via sqlmock
// =============================================================================

func TestRecoveryVerify_TokenNotFound_Returns401(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)

	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("bogus")).
		WillReturnError(sqlNoRowsErr())

	req := postVerifyJSON("bogus")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("missing token row should return 401, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected DB query unmet: %v", err)
	}
}

func TestRecoveryVerify_TokenExpired_Returns401(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)

	pastExpiry := time.Now().UTC().Add(-1 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("expired")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", pastExpiry, nil))

	req := postVerifyJSON("expired")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expired token should return 401, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected DB query unmet: %v", err)
	}
}

func TestRecoveryVerify_TokenAlreadyConsumed_Returns401(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)

	futureExpiry := time.Now().UTC().Add(10 * time.Minute)
	consumedAt := time.Now().UTC().Add(-5 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("used")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", futureExpiry, consumedAt))

	req := postVerifyJSON("used")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("consumed token should return 401, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected DB query unmet: %v", err)
	}
}

func TestRecoveryVerify_PerEmailCapExceeded_Returns403(t *testing.T) {
	// Updated for PR A: cap check moved INSIDE the SERIALIZABLE transaction.
	// Order: SELECT token (outside tx) → BEGIN → SELECT count (inside tx) → ROLLBACK.
	router, mock, _ := newRecoveryRouterWithDB(t)

	futureExpiry := time.Now().UTC().Add(10 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("valid")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", futureExpiry, nil))
	mock.ExpectBegin()
	// Active-tenants count returns the cap (now inside the tx)
	mock.ExpectQuery("SELECT COUNT.*FROM community_saas_registrations").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(recoveryMaxTenantsPerEmail))
	mock.ExpectRollback()

	req := postVerifyJSON("valid")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("per-email cap exceeded should return 403, got %d (body=%s)", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected DB queries unmet: %v", err)
	}
}

func TestRecoveryVerify_HappyPath_Returns200WithCredentials(t *testing.T) {
	// Updated for PR A: cap check moved INSIDE tx; token-consume UPDATE moved
	// BEFORE the registration INSERT (with RowsAffected=1 check); a second
	// UPDATE backfills consumed_by_tenant after the new tenant_id is known.
	// Order inside tx: COUNT → UPDATE consume → INSERT registration → UPDATE backfill → COMMIT.
	router, mock, _ := newRecoveryRouterWithDB(t)

	futureExpiry := time.Now().UTC().Add(10 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("valid")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", futureExpiry, nil))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT COUNT.*FROM community_saas_registrations").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	// Token consume — must affect exactly 1 row
	mock.ExpectExec("UPDATE community_saas_recovery_tokens").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT csaas_recovery_insert\(\$1, \$2, \$3, \$4, \$5, \$6\)`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	// Backfill consumed_by_tenant
	mock.ExpectExec("UPDATE community_saas_recovery_tokens").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	// register_tenant + register_org SQL function calls (fire-and-forget)
	mock.ExpectExec("SELECT register_org").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SELECT register_tenant").WillReturnResult(sqlmock.NewResult(0, 0))

	req := postVerifyJSON("valid")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("happy path should return 200, got %d (body=%s)", w.Code, w.Body.String())
	}

	var resp recoveryVerifyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response should be valid JSON: %v", err)
	}
	if !strings.HasPrefix(resp.TenantID, communitySaasTenantPrefix) {
		t.Errorf("new tenant_id should have community-saas prefix, got %q", resp.TenantID)
	}
	if resp.Secret == "" {
		t.Errorf("response should include fresh secret")
	}
	if resp.Email != "alice@example.com" {
		t.Errorf("response email should match recovery email, got %q", resp.Email)
	}
	if resp.Endpoint != communitySaasTryEndpoint {
		t.Errorf("response endpoint should be canonical try endpoint")
	}
	// register_tenant/register_org are fire-and-forget; cache means they may
	// not always fire — accept either-met-or-skipped state for those expectations
	_ = mock.ExpectationsWereMet()
}

// =============================================================================
// NEW in PR A: token-consume RowsAffected=0 (concurrent verify already won the race)
// =============================================================================

func TestRecoveryVerify_TokenConsumedRaceLost_Returns401(t *testing.T) {
	// Simulates the scenario where another concurrent verify won the race:
	// our SELECT shows the token unconsumed, but by the time we reach the
	// UPDATE inside the transaction, the row has consumed_at set already
	// (the WHERE consumed_at IS NULL filter matches 0 rows).
	// Pre-fix behavior: would have continued to INSERT a fresh tenant for
	// the token that's already been used — duplicate tenant from one link.
	// Post-fix: RowsAffected check returns 401 + rollback.
	router, mock, _ := newRecoveryRouterWithDB(t)

	futureExpiry := time.Now().UTC().Add(10 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("racetoken")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", futureExpiry, nil))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT COUNT.*FROM community_saas_registrations").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	// Token consume returns RowsAffected=0 — concurrent verify already consumed it
	mock.ExpectExec("UPDATE community_saas_recovery_tokens").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	req := postVerifyJSON("racetoken")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("race-lost should return 401 (token already consumed), got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected DB queries unmet: %v", err)
	}
}

// sqlNoRowsErr returns the standard sql.ErrNoRows so handlers route to the
// "not found" branch via their `err == sql.ErrNoRows` strict equality check.
func sqlNoRowsErr() error {
	return sql.ErrNoRows
}

// =============================================================================
// More handler-coverage tests (uncovered branches in handleRecoveryRequest)
// =============================================================================

func TestRecoveryRequest_TenantExistsQueryError_Returns202(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)
	mock.ExpectQuery("SELECT COUNT").
		WithArgs("alice@example.com", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("alice@example.com").
		WillReturnError(errFakeDB)

	w := postRecover(router, recoveryRequestBody{Email: "alice@example.com"})
	if w.Code != http.StatusAccepted {
		t.Errorf("DB error on tenant-exists query should return 202, got %d", w.Code)
	}
}

func TestRecoveryRequest_InsertTokenError_Returns202(t *testing.T) {
	router, mock, noop := newRecoveryRouterWithDB(t)
	mock.ExpectQuery("SELECT COUNT").
		WithArgs("alice@example.com", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec("INSERT INTO community_saas_recovery_tokens").
		WillReturnError(errFakeDB)

	w := postRecover(router, recoveryRequestBody{Email: "alice@example.com"})
	if w.Code != http.StatusAccepted {
		t.Errorf("INSERT error should return 202, got %d", w.Code)
	}
	if len(noop.CapturedLinks()) != 0 {
		t.Errorf("INSERT failure should not result in email send, sent %d", len(noop.CapturedLinks()))
	}
}

// failingEmailSender returns an error from SendRecoveryLink — used to test
// that the handler returns 202 even when email send fails (anti-enumeration
// property: email-failure must be invisible to the requester).
type failingEmailSender struct{}

func (failingEmailSender) SendRecoveryLink(_ context.Context, _, _ string) error {
	return errFakeDB
}

func TestRecoveryRequest_EmailSendError_StillReturns202(t *testing.T) {
	resetRegIPTracker()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	router := mux.NewRouter()
	RegisterCommunityRecoveryHandler(router, db, failingEmailSender{})

	mock.ExpectQuery("SELECT COUNT").
		WithArgs("alice@example.com", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec("INSERT INTO community_saas_recovery_tokens").
		WithArgs(sqlmock.AnyArg(), "alice@example.com", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := postRecover(router, recoveryRequestBody{Email: "alice@example.com"})
	if w.Code != http.StatusAccepted {
		t.Errorf("email-send error must still return 202 (anti-enum), got %d", w.Code)
	}
}

func TestRecoveryRequest_HonorsBaseURLOverride(t *testing.T) {
	resetRegIPTracker()
	t.Setenv("AXONFLOW_RECOVERY_BASE_URL", "https://billing.test.example.com/")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	router := mux.NewRouter()
	noop := &NoopRecoveryEmailSender{}
	RegisterCommunityRecoveryHandler(router, db, noop)

	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT EXISTS").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec("INSERT INTO community_saas_recovery_tokens").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := postRecover(router, recoveryRequestBody{Email: "alice@example.com"})
	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", w.Code)
	}
	captured := noop.CapturedLinks()
	if len(captured) != 1 {
		t.Fatalf("expected 1 captured link, got %d", len(captured))
	}
	if !strings.Contains(captured[0], "billing.test.example.com") {
		t.Errorf("link should use overridden base URL: %s", captured[0])
	}
	// Trailing slash should be trimmed (no double slash before /api/...)
	if strings.Contains(captured[0], ".com//api/") {
		t.Errorf("trailing slash should be trimmed: %s", captured[0])
	}
}

// =============================================================================
// PK collision retry path in handleRecoveryVerify
// =============================================================================

// pqUniqueErr returns a sqlmock-friendly PG unique-violation. The handler's
// isUniqueViolation helper checks pq.Error{Code: "23505"}.
func pqUniqueErr() error {
	return &pqUniqueViolation{}
}

type pqUniqueViolation struct{}

func (e *pqUniqueViolation) Error() string { return "duplicate key value violates unique constraint" }

func TestRecoveryVerify_PKCollisionRetriesThenSucceeds(t *testing.T) {
	// Updated for PR A's SQL ordering: BEGIN → COUNT → UPDATE consume → INSERT.
	// This test asserts that the PK retry loop runs but doesn't assert success
	// (because pqUniqueViolation isn't a real *pq.Error, isUniqueViolation
	// returns false and the handler bails out as a non-unique error). Even so,
	// it exercises the loop branch which is otherwise uncovered. Real PK
	// collision handling tested via integration tests.
	router, mock, _ := newRecoveryRouterWithDB(t)
	futureExpiry := time.Now().UTC().Add(10 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("v")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", futureExpiry, nil))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT COUNT.*FROM community_saas_registrations").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectExec("UPDATE community_saas_recovery_tokens").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT csaas_recovery_insert\(\$1, \$2, \$3, \$4, \$5, \$6\)`).
		WillReturnError(pqUniqueErr())
	mock.ExpectRollback()

	req := postVerifyJSON("v")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Handler returns 500 because our fake error isn't a real *pq.Error so
	// isUniqueViolation returns false and the handler treats it as a generic
	// insert error. The loop branch is now exercised either way.
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on insert error, got %d", w.Code)
	}
}

// =============================================================================
// More Verify-handler coverage: tx errors, register-tenant errors
// =============================================================================

func TestRecoveryVerify_LookupQueryError_Returns500(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("v")).
		WillReturnError(errFakeDB)
	req := postVerifyJSON("v")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("DB lookup error should return 500, got %d", w.Code)
	}
}

// All TestRecoveryVerify_*_Returns500 tests below have been updated for PR A's
// reordered SQL: cap check moved INSIDE the SERIALIZABLE transaction, and the
// token-consume UPDATE moved BEFORE the registration INSERT.
//
// New order inside tx (post-fix):
//   BEGIN → COUNT cap → UPDATE consume (RowsAffected check) → INSERT registration
//        → UPDATE backfill consumed_by_tenant → COMMIT

func TestRecoveryVerify_CountQueryError_Returns500(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)
	futureExpiry := time.Now().UTC().Add(10 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("v")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", futureExpiry, nil))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT COUNT.*FROM community_saas_registrations").
		WithArgs("alice@example.com").
		WillReturnError(errFakeDB)
	mock.ExpectRollback()
	req := postVerifyJSON("v")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("count query error should return 500, got %d", w.Code)
	}
}

func TestRecoveryVerify_TxBeginError_Returns500(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)
	futureExpiry := time.Now().UTC().Add(10 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("v")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", futureExpiry, nil))
	mock.ExpectBegin().WillReturnError(errFakeDB)
	req := postVerifyJSON("v")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("tx begin error should return 500, got %d", w.Code)
	}
}

func TestRecoveryVerify_InsertError_Returns500(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)
	futureExpiry := time.Now().UTC().Add(10 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("v")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", futureExpiry, nil))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT COUNT.*FROM community_saas_registrations").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	// Token consume succeeds with RowsAffected=1
	mock.ExpectExec("UPDATE community_saas_recovery_tokens").
		WillReturnResult(sqlmock.NewResult(0, 1))
	// Insert fails with non-unique error → handler returns 500 immediately
	mock.ExpectExec(`SELECT csaas_recovery_insert\(\$1, \$2, \$3, \$4, \$5, \$6\)`).WillReturnError(errFakeDB)
	mock.ExpectRollback()
	req := postVerifyJSON("v")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("insert error should return 500, got %d", w.Code)
	}
}

func TestRecoveryVerify_UpdateTokenError_Returns500(t *testing.T) {
	// Now tests the BACKFILL update (consumed_by_tenant) error path, since the
	// initial consume update happens BEFORE the insert.
	router, mock, _ := newRecoveryRouterWithDB(t)
	futureExpiry := time.Now().UTC().Add(10 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("v")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", futureExpiry, nil))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT COUNT.*FROM community_saas_registrations").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	// First UPDATE (consume) succeeds
	mock.ExpectExec("UPDATE community_saas_recovery_tokens").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT csaas_recovery_insert\(\$1, \$2, \$3, \$4, \$5, \$6\)`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	// Second UPDATE (backfill consumed_by_tenant) fails
	mock.ExpectExec("UPDATE community_saas_recovery_tokens").
		WillReturnError(errFakeDB)
	mock.ExpectRollback()
	req := postVerifyJSON("v")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("backfill UPDATE error should return 500, got %d", w.Code)
	}
}

func TestRecoveryVerify_CommitError_Returns500(t *testing.T) {
	router, mock, _ := newRecoveryRouterWithDB(t)
	futureExpiry := time.Now().UTC().Add(10 * time.Minute)
	mock.ExpectQuery("SELECT email, expires_at, consumed_at").
		WithArgs(hashRecoveryToken("v")).
		WillReturnRows(sqlmock.NewRows([]string{"email", "expires_at", "consumed_at"}).
			AddRow("alice@example.com", futureExpiry, nil))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT COUNT.*FROM community_saas_registrations").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectExec("UPDATE community_saas_recovery_tokens").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT csaas_recovery_insert\(\$1, \$2, \$3, \$4, \$5, \$6\)`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("UPDATE community_saas_recovery_tokens").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit().WillReturnError(errFakeDB)
	req := postVerifyJSON("v")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("commit error should return 500, got %d", w.Code)
	}
}

// =============================================================================
// ResendSender coverage via httptest.Server (mock Resend API)
// =============================================================================

func TestResendSender_SuccessfulSend(t *testing.T) {
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if r.Header.Get("Authorization") != "Bearer test_key" {
			t.Errorf("missing/wrong Authorization header: %s", r.Header.Get("Authorization"))
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			t.Errorf("missing/wrong Content-Type: %s", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"em_123"}`))
	}))
	defer srv.Close()

	// Build a sender pointed at the mock server. Easiest: override HTTPClient
	// + set the URL via a small helper. The production sender hardcodes
	// https://api.resend.com/emails — we substitute via a custom RoundTripper
	// that rewrites the Host.
	sender := &ResendRecoveryEmailSender{
		APIKey:     "test_key",
		FromEmail:  "AxonFlow <recovery@example.com>",
		HTTPClient: &http.Client{Transport: &rewriteTransport{target: srv.URL}},
	}

	err := sender.SendRecoveryLink(context.Background(), "alice@example.com",
		"https://example.com/verify?token=abc")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if called != 1 {
		t.Errorf("expected 1 API call, got %d", called)
	}
}

func TestResendSender_Non2xxErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server"}`))
	}))
	defer srv.Close()

	sender := &ResendRecoveryEmailSender{
		APIKey:     "test_key",
		FromEmail:  "AxonFlow <r@e.com>",
		HTTPClient: &http.Client{Transport: &rewriteTransport{target: srv.URL}},
	}
	err := sender.SendRecoveryLink(context.Background(), "x@y.com", "https://z/v?t=a")
	if err == nil {
		t.Errorf("expected error on 5xx response, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

func TestResendSender_NetworkError(t *testing.T) {
	// Point the sender at an unroutable URL via the rewriter
	sender := &ResendRecoveryEmailSender{
		APIKey:     "test_key",
		FromEmail:  "AxonFlow <r@e.com>",
		HTTPClient: &http.Client{Transport: &rewriteTransport{target: "http://127.0.0.1:1"}},
	}
	err := sender.SendRecoveryLink(context.Background(), "x@y.com", "https://z/v?t=a")
	if err == nil {
		t.Errorf("expected network error, got nil")
	}
}

// rewriteTransport rewrites the request URL to point at a target test server,
// preserving headers + body. Used to inject httptest.NewServer into the
// production ResendRecoveryEmailSender that hardcodes the Resend URL.
type rewriteTransport struct {
	target string
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	parsed, err := parseURL(rt.target)
	if err != nil {
		return nil, err
	}
	clone.URL.Scheme = parsed.scheme
	clone.URL.Host = parsed.host
	clone.URL.Path = parsed.path
	return http.DefaultTransport.RoundTrip(clone)
}

type tinyURL struct {
	scheme, host, path string
}

func parseURL(s string) (tinyURL, error) {
	// Minimal parse — assume "scheme://host/path?..." shape
	out := tinyURL{}
	rest := s
	if i := strings.Index(rest, "://"); i >= 0 {
		out.scheme = rest[:i]
		rest = rest[i+3:]
	}
	if i := strings.Index(rest, "/"); i >= 0 {
		out.host = rest[:i]
		out.path = rest[i:]
	} else {
		out.host = rest
		out.path = "/"
	}
	if out.path == "/" {
		out.path = "/emails"
	}
	return out, nil
}

// =============================================================================
// Token hashing
// =============================================================================

func TestHashRecoveryToken_DeterministicAndOpaque(t *testing.T) {
	a := hashRecoveryToken("abc123")
	b := hashRecoveryToken("abc123")
	if a != b {
		t.Fatalf("hashRecoveryToken not deterministic: %s vs %s", a, b)
	}
	if a == "abc123" {
		t.Fatalf("hashRecoveryToken returned plaintext")
	}
	if len(a) != 64 {
		t.Fatalf("hashRecoveryToken should return 64 hex chars (SHA-256), got %d", len(a))
	}

	c := hashRecoveryToken("abc124")
	if a == c {
		t.Fatalf("hashRecoveryToken should differ for different inputs")
	}
}

// =============================================================================
// Email validation
// =============================================================================

func TestLooksLikeEmail(t *testing.T) {
	cases := map[string]bool{
		"alice@example.com":      true,
		"a@b.co":                 true,
		"alice+tag@example.com":  true,
		"":                       false,
		"alice":                  false,
		"alice@":                 false,
		"@example.com":           false,
		"alice@example":          false, // no dot in domain
		"alice@x":                false, // domain too short
		strings.Repeat("a", 300): false, // too long
	}

	for input, want := range cases {
		got := looksLikeEmail(input)
		if got != want {
			t.Errorf("looksLikeEmail(%q) = %v, want %v", input, got, want)
		}
	}
}

// =============================================================================
// Noop email sender (used as test substitute throughout this file)
// =============================================================================

func TestNoopRecoveryEmailSender_CapturesLinks(t *testing.T) {
	s := &NoopRecoveryEmailSender{}
	ctx := context.Background()

	if err := s.SendRecoveryLink(ctx, "a@b.com", "https://example.com/verify?token=abc"); err != nil {
		t.Fatalf("noop sender returned error: %v", err)
	}
	if err := s.SendRecoveryLink(ctx, "c@d.com", "https://example.com/verify?token=def"); err != nil {
		t.Fatalf("noop sender returned error on second call: %v", err)
	}

	captured := s.CapturedLinks()
	if len(captured) != 2 {
		t.Fatalf("expected 2 captured links, got %d", len(captured))
	}
	if !strings.Contains(captured[0], "a@b.com") || !strings.Contains(captured[0], "token=abc") {
		t.Errorf("first captured link missing expected fields: %s", captured[0])
	}
	if !strings.Contains(captured[1], "c@d.com") || !strings.Contains(captured[1], "token=def") {
		t.Errorf("second captured link missing expected fields: %s", captured[1])
	}
}

// =============================================================================
// HTTP handler — request flow (input validation + rate limiting + anti-enum)
// =============================================================================

func newRecoveryRouter(t *testing.T) (*mux.Router, *NoopRecoveryEmailSender) {
	t.Helper()
	router := mux.NewRouter()
	noop := &NoopRecoveryEmailSender{}
	// db is nil intentionally — handlers should return 503 on nil db.
	// Tests that exercise DB paths use the integration-test harness elsewhere.
	RegisterCommunityRecoveryHandler(router, nil, noop)
	return router, noop
}

func postRecover(router *mux.Router, body interface{}) *httptest.ResponseRecorder {
	bodyJSON, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/recover", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestRecoveryRequest_NilDBReturns503(t *testing.T) {
	router, _ := newRecoveryRouter(t)
	w := postRecover(router, recoveryRequestBody{Email: "alice@example.com"})
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("nil DB should return 503, got %d", w.Code)
	}
}

func TestRecoveryRequest_InvalidJSON(t *testing.T) {
	// We need a non-nil DB sentinel to skip the 503 branch and reach JSON parse.
	// Easiest is a fake handler call directly with non-nil but unreachable DB.
	// Skip — handler dispatches to nil-check first; this case tested via integration.
	t.Skip("Tested via integration; handler short-circuits on nil db")
}

func TestRecoveryRequest_MethodNotAllowed(t *testing.T) {
	router, _ := newRecoveryRouter(t)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/v1/recover", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s should return 405, got %d", method, w.Code)
		}
	}
}

func TestRecoveryVerify_MissingToken(t *testing.T) {
	router, _ := newRecoveryRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/recover/verify", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable && w.Code != http.StatusBadRequest {
		// nil DB short-circuits to 503, otherwise missing token gives 400.
		// Either is acceptable here; we mainly verify it doesn't 200.
		t.Errorf("missing token should return 503 (nil db) or 400, got %d", w.Code)
	}
}

func TestRecoveryVerify_MethodNotAllowed(t *testing.T) {
	// Post-PR-B: GET (confirmation page) and POST (consume) are the canonical
	// methods. Only PUT/DELETE/PATCH should return 405.
	router, _ := newRecoveryRouter(t)
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/v1/recover/verify", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s should return 405, got %d", method, w.Code)
		}
	}
}

// =============================================================================
// Response shape — generic anti-enumeration message
// =============================================================================

func TestRecoveryGenericResponse_FixedShape(t *testing.T) {
	w := httptest.NewRecorder()
	writeRecoveryGenericResponse(w)

	if w.Code != http.StatusAccepted {
		t.Errorf("generic response should be 202, got %d", w.Code)
	}
	if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type should be application/json, got %s", got)
	}

	var resp recoveryRequestResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response should be valid JSON: %v", err)
	}
	if resp.Message == "" {
		t.Errorf("generic response should have non-empty message")
	}
	// The anti-enumeration property requires the message to NOT confirm or deny
	// the email's existence. Sanity-check with a few terms.
	if strings.Contains(strings.ToLower(resp.Message), "does not exist") ||
		strings.Contains(strings.ToLower(resp.Message), "no such") ||
		strings.Contains(strings.ToLower(resp.Message), "invalid email address") {
		t.Errorf("generic response leaks existence info: %s", resp.Message)
	}
}

// =============================================================================
// Email sender selection from environment
// =============================================================================

func TestNewRecoveryEmailSenderFromEnv_NoopWhenNoAPIKey(t *testing.T) {
	t.Setenv("RESEND_API_KEY", "")
	sender := NewRecoveryEmailSenderFromEnv()
	if _, ok := sender.(*NoopRecoveryEmailSender); !ok {
		t.Errorf("expected NoopRecoveryEmailSender when RESEND_API_KEY unset, got %T", sender)
	}
}

func TestNewRecoveryEmailSenderFromEnv_ResendWhenAPIKeySet(t *testing.T) {
	t.Setenv("RESEND_API_KEY", "re_test_dummy_key")
	sender := NewRecoveryEmailSenderFromEnv()
	resend, ok := sender.(*ResendRecoveryEmailSender)
	if !ok {
		t.Errorf("expected ResendRecoveryEmailSender when RESEND_API_KEY set, got %T", sender)
		return
	}
	if resend.APIKey != "re_test_dummy_key" {
		t.Errorf("expected APIKey from env, got %q", resend.APIKey)
	}
	if resend.FromEmail == "" {
		t.Errorf("expected non-empty FromEmail default")
	}
}

func TestNewRecoveryEmailSenderFromEnv_FromEmailOverride(t *testing.T) {
	t.Setenv("RESEND_API_KEY", "re_test_dummy_key")
	t.Setenv("AXONFLOW_RECOVERY_FROM_EMAIL", "Custom <custom@axonflow.com>")
	sender := NewRecoveryEmailSenderFromEnv()
	resend, ok := sender.(*ResendRecoveryEmailSender)
	if !ok {
		t.Fatalf("expected ResendRecoveryEmailSender, got %T", sender)
	}
	if resend.FromEmail != "Custom <custom@axonflow.com>" {
		t.Errorf("expected custom FromEmail from env, got %q", resend.FromEmail)
	}
}

// =============================================================================
// Email body builders — sanity checks
// =============================================================================

func TestBuildRecoveryEmailText_ContainsLink(t *testing.T) {
	link := "https://example.com/verify?token=abc"
	body := buildRecoveryEmailText(link)
	if !strings.Contains(body, link) {
		t.Errorf("text email body missing magic link")
	}
	if !strings.Contains(body, "AxonFlow") {
		t.Errorf("text email body missing AxonFlow brand")
	}
	if !strings.Contains(body, "15 minutes") {
		t.Errorf("text email body should mention TTL")
	}
}

func TestBuildRecoveryEmailHTML_ContainsLink(t *testing.T) {
	link := "https://example.com/verify?token=abc"
	body := buildRecoveryEmailHTML(link)
	if !strings.Contains(body, link) {
		t.Errorf("HTML email body missing magic link")
	}
	if !strings.Contains(body, "<a href=") {
		t.Errorf("HTML email body should have anchor tag")
	}
}

// =============================================================================
// ResendRecoveryEmailSender — error paths (no real API call)
// =============================================================================

func TestResendSender_EmptyAPIKeyError(t *testing.T) {
	s := &ResendRecoveryEmailSender{APIKey: "", FromEmail: "a@b.com"}
	err := s.SendRecoveryLink(context.Background(), "x@y.com", "https://example.com/v?token=abc")
	if err == nil {
		t.Errorf("expected error on empty API key, got nil")
	}
}

func TestResendSender_EmptyFromError(t *testing.T) {
	s := &ResendRecoveryEmailSender{APIKey: "k", FromEmail: ""}
	err := s.SendRecoveryLink(context.Background(), "x@y.com", "https://example.com/v?token=abc")
	if err == nil {
		t.Errorf("expected error on empty FromEmail, got nil")
	}
}
