//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package billing

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

const testSigningSecret = "whsec_test_skeletontest1234567890abcdef"

// fixedClock returns a closure suitable for h.now so signature checks
// happen against a known timestamp.
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// signRequest produces a Stripe-Signature header for body that the
// real verifier will accept (assuming clock alignment).
func signRequest(t *testing.T, body []byte, ts time.Time, secret string) string {
	t.Helper()
	signed := fmt.Sprintf("%d.%s", ts.Unix(), body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	return fmt.Sprintf("t=%d,v1=%s", ts.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

// stripeCheckoutEvent builds a minimal Stripe Event JSON matching the
// stripeEvent shape the handler unmarshals. Mirrors the REAL Stripe
// Payment-Link payload shape (verified against a live Test session
// 2026-05-06): customer_email and customer top-level are NULL because
// our Payment Link's customer_creation is "if_required" and Stripe
// doesn't create a Customer for one-time payments. The buyer's email
// arrives in customer_details.email instead. Synthetic fixtures that
// hardcoded customer_email caused the V1 launch showstopper because
// they self-confirmed a code path that doesn't fire on real buyers.
//
// tenant_id is wired through custom_fields[].key="tenantid" — that's
// what real Stripe Live and Test webhook deliveries carry (label
// "tenant_id" sluggifies to "tenantid"). amount_total = 999 cents =
// $9.99, the V1 Pro price; the alarm-stable `event=first_paid_license_issued`
// log line (#1894) carries it.
func stripeCheckoutEvent(tenantID, email string) []byte {
	ev := map[string]any{
		"id":   "evt_test_1",
		"type": "checkout.session.completed",
		"data": map[string]any{
			"object": map[string]any{
				"id":             "cs_test_session_1",
				"customer":       nil,
				"customer_email": nil,
				"customer_details": map[string]any{
					"email": email,
					"name":  "Test Buyer",
				},
				"mode":           "payment",
				"payment_status": "paid",
				"amount_total":   999,
				"currency":       "usd",
				"custom_fields": []map[string]any{
					{"key": "tenantid", "type": "text", "text": map[string]any{"value": tenantID}},
				},
			},
		},
	}
	b, _ := json.Marshal(ev)
	return b
}

// captureLog redirects the standard `log` package output for the duration
// of the test and returns a func that yields the captured bytes. Used by
// the alarm-line tests below to assert the EXACT log line shape — the CW
// alarm metric filter pattern is matched against these strings, so any
// drift breaks the alarm contract.
func captureLog(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	// Strip date/time prefix so the captured output is exactly the
	// fmt-printed line, easier to assert against.
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prev)
		log.SetFlags(prevFlags)
	})
	return buf.String
}

// =============================================================================
// Stripe-Signature verification
// =============================================================================

func TestVerifyStripeSignature_ValidSignature_OK(t *testing.T) {
	body := []byte(`{"id":"evt_x"}`)
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	header := signRequest(t, body, now, testSigningSecret)

	if err := verifyStripeSignature(header, body, testSigningSecret, now); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestVerifyStripeSignature_BadSignature_Rejects(t *testing.T) {
	body := []byte(`{"id":"evt_x"}`)
	now := time.Now()
	header := fmt.Sprintf("t=%d,v1=deadbeef", now.Unix())

	if err := verifyStripeSignature(header, body, testSigningSecret, now); err == nil {
		t.Error("expected signature mismatch error")
	}
}

func TestVerifyStripeSignature_StaleTimestamp_Rejects(t *testing.T) {
	body := []byte(`{"id":"evt_x"}`)
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-stripeSignatureMaxAge - time.Second)
	header := signRequest(t, body, stale, testSigningSecret)

	err := verifyStripeSignature(header, body, testSigningSecret, now)
	if err == nil || !strings.Contains(err.Error(), "out of tolerance") {
		t.Errorf("expected timestamp rejection, got %v", err)
	}
}

func TestVerifyStripeSignature_MissingHeader_Rejects(t *testing.T) {
	if err := verifyStripeSignature("", []byte("{}"), testSigningSecret, time.Now()); err == nil {
		t.Error("expected error for missing header")
	}
}

func TestVerifyStripeSignature_NoSecret_Rejects(t *testing.T) {
	if err := verifyStripeSignature("t=1,v1=abc", []byte("{}"), "", time.Now()); err == nil {
		t.Error("expected error for missing secret")
	}
}

func TestVerifyStripeSignature_TolerantOfMultipleV1Sigs(t *testing.T) {
	body := []byte(`{"id":"evt_x"}`)
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	good := signRequest(t, body, now, testSigningSecret)
	// Stripe rotates signing secrets by sending TWO v1 entries during the
	// rotation window. Verify any single match accepts the request.
	mixed := good + ",v1=fakefakefakefakefakefakefakefakefakefakefakefakefakefakefakefake"

	if err := verifyStripeSignature(mixed, body, testSigningSecret, now); err != nil {
		t.Errorf("expected accept on dual-sig rotation header, got %v", err)
	}
}

// =============================================================================
// HTTP handler — wrong method, no signature, bad body
// =============================================================================

func TestWebhookHandler_WrongMethod_405(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})

	req := httptest.NewRequest(http.MethodGet, "/webhook", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestWebhookHandler_NoSignatureHeader_401(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(`{"id":"evt"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestWebhookHandler_OversizedBody_413(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})

	big := make([]byte, maxRequestBodyBytes+10)
	for i := range big {
		big[i] = 'x'
	}
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(big)))
	req.Header.Set(stripeSignatureHeader, "t=1,v1=abc")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", rec.Code)
	}
}

// =============================================================================
// HTTP handler — checkout.session.completed happy path
// =============================================================================

func TestWebhookHandler_CheckoutCompleted_HappyPath_IssuesAndReturns200(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	body := stripeCheckoutEvent("cs_abc", "alice@example.com")
	header := signRequest(t, body, now, testSigningSecret)

	mock.ExpectBegin()
	// Per-tenant lock (GAP-2 race fix).
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Idempotency lookup (GAP-2) — no existing row for this session, fall through to issue path.
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_test_session_1").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE plugin_user_licenses`).
		WithArgs("cs_abc", "cs_test_session_1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO plugin_user_licenses`).
		WillReturnRows(sqlmock.NewRows([]string{"license_id", "issued_at"}).
			AddRow("11111111-2222-3333-4444-555555555555", now))
	mock.ExpectCommit()

	emailSender := &NoopLicenseEmailSender{}
	h := NewWebhookHandler(db, WebhookHandlerConfig{
		SigningSecret: testSigningSecret,
		ValidityDays:  90, // Pro V1 lock per PRD_TENANT_DURABILITY_AND_CLAIM
		EmailSender:   emailSender,
	})
	h.now = fixedClock(now)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if resp["status"] != "issued" {
		t.Errorf("status: got %v", resp["status"])
	}
	if tok, _ := resp["token"].(string); !strings.HasPrefix(tok, "AXON-") {
		t.Errorf("token in response should be AXON-prefixed, got: %v", resp["token"])
	}
	if id, _ := resp["license_id"].(string); id == "" {
		t.Error("license_id should be present in response")
	}

	// Email integration: the issued token must be handed off to the
	// configured EmailSender with the buyer's address. This is the
	// mechanism by which V1 paid-tier buyers actually receive the token —
	// without this assertion the previous "happy path" is the same
	// skeleton failure that motivated this PR.
	captured := emailSender.CapturedSends()
	if len(captured) != 1 {
		t.Fatalf("expected exactly 1 captured email send, got %d: %v", len(captured), captured)
	}
	if !strings.Contains(captured[0], "alice@example.com") {
		t.Errorf("captured send must include buyer email, got: %q", captured[0])
	}
	if !strings.Contains(captured[0], "AXON-") {
		t.Errorf("captured send must include AXON- token, got: %q", captured[0])
	}
	// The X-Sensitive-Body response header signals to log scrubbers that
	// the response body should not be persisted in raw form (token leak).
	if rec.Header().Get("X-Sensitive-Body") != "token" {
		t.Errorf("expected X-Sensitive-Body=token, got %q", rec.Header().Get("X-Sensitive-Body"))
	}
}

// TestWebhookHandler_NilEmailSender_DoesNotPanic verifies the documented
// fallback to NoopLicenseEmailSender when cfg.EmailSender is nil. Important
// because operators wiring run.go may set up the webhook before configuring
// Resend; we want issuance to keep working with a noop send rather than
// panicking on every checkout.
func TestWebhookHandler_NilEmailSender_DoesNotPanic(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	body := stripeCheckoutEvent("cs_nilsender", "carol@example.com")
	header := signRequest(t, body, now, testSigningSecret)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_test_session_1").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE plugin_user_licenses`).WithArgs("cs_nilsender", "cs_test_session_1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO plugin_user_licenses`).
		WillReturnRows(sqlmock.NewRows([]string{"license_id", "issued_at"}).
			AddRow("aaaa-bbbb", now))
	mock.ExpectCommit()

	h := NewWebhookHandler(db, WebhookHandlerConfig{
		SigningSecret: testSigningSecret,
		EmailSender:   nil, // explicitly nil — should fall back to noop
	})
	h.now = fixedClock(now)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()

	// If NewWebhookHandler did not install a noop fallback, this would
	// panic with nil pointer dereference at SendLicense().
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 even with nil sender (noop fallback), got %d", rec.Code)
	}
}

// =============================================================================
// HTTP handler — non-handled events return 200 (so Stripe doesn't retry)
// =============================================================================

func TestWebhookHandler_UnhandledEventType_Returns200Ignored(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	body, _ := json.Marshal(map[string]any{
		"id":   "evt_other",
		"type": "invoice.paid",
		"data": map[string]any{"object": map[string]any{}},
	})
	header := signRequest(t, body, now, testSigningSecret)

	h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})
	h.now = fixedClock(now)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 ignored, got %d", rec.Code)
	}
	bodyStr, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(bodyStr), `"ignored"`) {
		t.Errorf("response should mention ignored, got: %s", bodyStr)
	}
}

// =============================================================================
// HTTP handler — checkout missing tenant_id custom field returns 400
// =============================================================================

func TestWebhookHandler_CheckoutMissingTenantID_Returns400(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	body, _ := json.Marshal(map[string]any{
		"id":   "evt_x",
		"type": "checkout.session.completed",
		"data": map[string]any{
			"object": map[string]any{
				"id":             "cs_x",
				"customer":       "cus_x",
				"customer_email": "x@y.com",
				"payment_status": "paid",
				// No custom_fields[].key="tenantid" — should reject 400.
				"custom_fields": []map[string]any{},
			},
		},
	})
	header := signRequest(t, body, now, testSigningSecret)

	h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})
	h.now = fixedClock(now)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// =============================================================================
// HTTP handler — checkout payment_status != paid returns 200 skipped
// (so Stripe doesn't retry, but we don't issue)
// =============================================================================

func TestWebhookHandler_CheckoutNotPaid_Returns200Skipped(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	body, _ := json.Marshal(map[string]any{
		"id":   "evt_x",
		"type": "checkout.session.completed",
		"data": map[string]any{
			"object": map[string]any{
				"id":             "cs_x",
				"customer":       "cus_x",
				"customer_email": "x@y.com",
				"payment_status": "unpaid",
				"custom_fields": []map[string]any{
					{"key": "tenantid", "type": "text", "text": map[string]any{"value": "cs_abc"}},
				},
			},
		},
	})
	header := signRequest(t, body, now, testSigningSecret)

	h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})
	h.now = fixedClock(now)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 skipped, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"skipped"`) {
		t.Errorf("response should mention skipped: %s", rec.Body.String())
	}
}

// =============================================================================
// resolveTenantID — Stripe Payment Link path (custom_fields[].key="tenantid")
// =============================================================================

// V1 ships Stripe Payment Links only. Stripe constrains custom_fields[].key
// to alphanumeric, so a Dashboard label "tenant_id" sluggifies to "tenantid"
// — that's the only key shape we ever receive on a real webhook delivery.
// Backend-driven Checkout Sessions (which would let us choose the key
// explicitly) are not part of V1.

// =============================================================================
// resolveBuyerEmail — customer_details.email vs top-level customer_email
// =============================================================================
//
// Real Stripe hosted Checkout (Payment Links + Sessions API) populates the
// buyer's email at customer_details.email. The top-level customer_email is
// only set when the API caller passes it explicitly at Session create time
// — V1 doesn't (the buyer types it on the Stripe-hosted form). The
// resolver prefers customer_details.email and falls back to top-level for
// any future caller that does set it explicitly.

func TestResolveBuyerEmail_FromCustomerDetails(t *testing.T) {
	cs := stripeCheckoutSession{
		CustomerDetails: &stripeCheckoutCustomerDetails{Email: "buyer@example.com"},
	}
	if got := resolveBuyerEmail(cs); got != "buyer@example.com" {
		t.Errorf("got %q, want buyer@example.com", got)
	}
}

func TestResolveBuyerEmail_FromTopLevelCustomerEmail(t *testing.T) {
	cs := stripeCheckoutSession{
		CustomerEmail: "legacy@example.com",
	}
	if got := resolveBuyerEmail(cs); got != "legacy@example.com" {
		t.Errorf("got %q, want legacy@example.com", got)
	}
}

func TestResolveBuyerEmail_PrefersCustomerDetails(t *testing.T) {
	// If both populated, prefer customer_details.email (the real-Stripe
	// path). The legacy customer_email would only appear in synthetic
	// fixtures or a future explicit-caller scenario; customer_details
	// is the source of truth.
	cs := stripeCheckoutSession{
		CustomerEmail:   "legacy@example.com",
		CustomerDetails: &stripeCheckoutCustomerDetails{Email: "real@example.com"},
	}
	if got := resolveBuyerEmail(cs); got != "real@example.com" {
		t.Errorf("got %q, want real@example.com", got)
	}
}

func TestResolveBuyerEmail_TrimsWhitespace(t *testing.T) {
	cs := stripeCheckoutSession{
		CustomerDetails: &stripeCheckoutCustomerDetails{Email: "  padded@example.com  "},
	}
	if got := resolveBuyerEmail(cs); got != "padded@example.com" {
		t.Errorf("got %q, want padded@example.com", got)
	}
}

func TestResolveBuyerEmail_NeitherSet_Empty(t *testing.T) {
	if got := resolveBuyerEmail(stripeCheckoutSession{}); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestResolveBuyerEmail_EmptyCustomerDetailsEmail_FallsBack(t *testing.T) {
	// customer_details present but email is empty — should fall through
	// to top-level customer_email.
	cs := stripeCheckoutSession{
		CustomerEmail:   "fallback@example.com",
		CustomerDetails: &stripeCheckoutCustomerDetails{Email: ""},
	}
	if got := resolveBuyerEmail(cs); got != "fallback@example.com" {
		t.Errorf("got %q, want fallback@example.com", got)
	}
}

func TestResolveTenantID_FromCustomField(t *testing.T) {
	cs := stripeCheckoutSession{
		CustomFields: []stripeCustomField{
			{Key: "tenantid", Type: "text", Text: &stripeCustomFieldVal{Value: "cs_buyer_xyz"}},
		},
	}
	got, err := resolveTenantID(cs)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "cs_buyer_xyz" {
		t.Errorf("got %q, want cs_buyer_xyz", got)
	}
}

func TestResolveTenantID_Empty_ReturnsEmpty(t *testing.T) {
	cs := stripeCheckoutSession{}
	got, err := resolveTenantID(cs)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestResolveTenantID_TrimsWhitespace(t *testing.T) {
	// Stripe-hosted custom-field input is user-typed and frequently has
	// trailing whitespace from copy-paste. The webhook handler must trim
	// before binding the license to the tenant_id; otherwise the
	// plugin_user_licenses row's tenant_id won't match the FK target.
	cs := stripeCheckoutSession{
		CustomFields: []stripeCustomField{
			{Key: "tenantid", Type: "text", Text: &stripeCustomFieldVal{Value: "  cs_padded  "}},
		},
	}
	got, _ := resolveTenantID(cs)
	if got != "cs_padded" {
		t.Errorf("got %q, want cs_padded (trimmed)", got)
	}
}

func TestResolveTenantID_IgnoresOtherCustomFields(t *testing.T) {
	// Buyer might add other custom fields in the future (company name,
	// referral source, etc.). Only key="tenantid" with type="text" matters.
	cs := stripeCheckoutSession{
		CustomFields: []stripeCustomField{
			{Key: "company_name", Type: "text", Text: &stripeCustomFieldVal{Value: "Acme Corp"}},
			{Key: "tenantid", Type: "text", Text: &stripeCustomFieldVal{Value: "cs_real"}},
			{Key: "referral", Type: "dropdown"}, // dropdown — no text field
		},
	}
	got, _ := resolveTenantID(cs)
	if got != "cs_real" {
		t.Errorf("got %q, want cs_real", got)
	}
}

func TestResolveTenantID_IgnoresNonTextTenantIDField(t *testing.T) {
	// Defense in depth: if someone configures the Payment Link with a
	// numeric or dropdown custom field named "tenantid" (wrong shape but
	// same key), don't pull whatever stub is there. Tenant IDs are text.
	cs := stripeCheckoutSession{
		CustomFields: []stripeCustomField{
			{Key: "tenantid", Type: "numeric"}, // wrong type — ignored
		},
	}
	got, err := resolveTenantID(cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty (numeric type should be ignored)", got)
	}
}

// TestResolveTenantID_RejectsUnknownKey ensures an unrelated custom field
// doesn't accidentally match. Variants of the key (tenant_id with
// underscore, tenantId camelCase, anything else) are explicitly rejected
// — only the literal sluggified "tenantid" matches.
func TestResolveTenantID_RejectsUnknownKey(t *testing.T) {
	cases := []string{
		"tenant_id",            // pre-#1937 synthetic-tool legacy
		"tenantId",             // camelCase (an API-driven Payment Link could set this, but V1 doesn't)
		"youraxonflowtenantid", // unrelated label whose sluggification happens to share a substring
		"company_id",           // wholly unrelated
	}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			cs := stripeCheckoutSession{
				CustomFields: []stripeCustomField{
					{Key: key, Type: "text", Text: &stripeCustomFieldVal{Value: "cs_xxx"}},
				},
			}
			got, _ := resolveTenantID(cs)
			if got != "" {
				t.Errorf("key=%q: got %q, want empty (only 'tenantid' should match)", key, got)
			}
		})
	}
}

// =============================================================================
// Webhook handler — Payment Link path (custom_fields, no metadata)
// =============================================================================

func TestWebhookHandler_PaymentLinkPath_IssuesOnCustomFieldTenantID(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	body, _ := json.Marshal(map[string]any{
		"id":   "evt_payment_link_1",
		"type": "checkout.session.completed",
		"data": map[string]any{
			"object": map[string]any{
				"id":             "cs_payment_link_1",
				"customer":       "cus_pl_1",
				"customer_email": "buyer@example.com",
				"mode":           "payment",
				"payment_status": "paid",
				"custom_fields": []map[string]any{
					{
						// Stripe sluggifies a Dashboard label "tenant_id" to
						// the alphanumeric "tenantid" — that's the canonical
						// key on every real Live and Test webhook delivery.
						"key":  "tenantid",
						"type": "text",
						"text": map[string]any{"value": "cs_payment_link_buyer"},
					},
				},
			},
		},
	})
	header := signRequest(t, body, now, testSigningSecret)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_payment_link_1").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE plugin_user_licenses`).
		WithArgs("cs_payment_link_buyer", "cs_payment_link_1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO plugin_user_licenses`).
		WillReturnRows(sqlmock.NewRows([]string{"license_id", "issued_at"}).
			AddRow("99999999-aaaa-bbbb-cccc-dddddddddddd", now))
	mock.ExpectCommit()

	h := NewWebhookHandler(db, WebhookHandlerConfig{
		SigningSecret: testSigningSecret,
		EmailSender:   &NoopLicenseEmailSender{},
	})
	h.now = fixedClock(now)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if resp["tenant_id"] != "cs_payment_link_buyer" {
		t.Errorf("response tenant_id: got %v, want cs_payment_link_buyer", resp["tenant_id"])
	}
}

// TestWebhookHandler_AmbiguousTenantID_Rejects400 was removed when the
// resolveTenantID resolution was simplified to a single path
// (custom_fields[].key="tenantid"). With only one source there's no
// possibility of ambiguity. Removed in the same PR that simplified
// resolveTenantID; see the resolveTenantID tests above for the current
// contract.

// =============================================================================
// #1894 — explicit alarm-stable log tokens
//
// CW alarms (community-saas-alarms.yaml) match metric filters against the
// EXACT log strings emitted below. Any drift in spelling / spacing / token
// order breaks the alarm contract. These tests lock the contract.
// =============================================================================

// TestWebhookHandler_FirstPaidLicenseLogLine_OnSuccess asserts that the
// success path emits BOTH:
//
//   - The legacy `[billing.webhook] issued license=...` line — kept for
//     backward compat with the previous CW filter pattern; CW filter
//     `?"event=first_paid_license_issued" ?"issued license="` ORs them so
//     the alarm fires during a rolling deploy where some agent tasks are
//     still on the pre-#1894 image.
//   - The NEW `[billing.webhook] event=first_paid_license_issued
//     license=... tenant=... amount_cents=...` line — single-purpose token
//     the upgraded alarm filter keys off.
//
// amount_cents is asserted explicitly (=999 = $9.99 V1 Pro price) so we
// catch any silent breakage of the AmountTotal JSON unmarshal path.
func TestWebhookHandler_FirstPaidLicenseLogLine_OnSuccess(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	body := stripeCheckoutEvent("cs_buyer_1894_a", "buyer1894a@example.com")
	header := signRequest(t, body, now, testSigningSecret)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_test_session_1").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE plugin_user_licenses`).
		WithArgs("cs_buyer_1894_a", "cs_test_session_1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO plugin_user_licenses`).
		WillReturnRows(sqlmock.NewRows([]string{"license_id", "issued_at"}).
			AddRow("dddddddd-eeee-ffff-1111-222222222222", now))
	mock.ExpectCommit()

	getLog := captureLog(t)

	h := NewWebhookHandler(db, WebhookHandlerConfig{
		SigningSecret: testSigningSecret,
		ValidityDays:  90,
		EmailSender:   &NoopLicenseEmailSender{},
	})
	h.now = fixedClock(now)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	logged := getLog()

	// Legacy line — must still fire (backward compat with existing alarm
	// metric filter on stacks that haven't seen a CFN update yet).
	wantLegacy := "[billing.webhook] issued license=dddddddd-eeee-ffff-1111-222222222222"
	if !strings.Contains(logged, wantLegacy) {
		t.Errorf("legacy log line missing: want substring %q in:\n%s", wantLegacy, logged)
	}

	// New alarm-stable token. Match the EXACT shape, including amount_cents.
	wantNew := "[billing.webhook] event=first_paid_license_issued license=dddddddd-eeee-ffff-1111-222222222222 tenant=cs_buyer_1894_a amount_cents=999"
	if !strings.Contains(logged, wantNew) {
		t.Errorf("new alarm token line missing: want substring %q in:\n%s", wantNew, logged)
	}
}

// TestWebhookHandler_PaidButNoTokenIssued_OnIssueFailure asserts that when
// IssueLicense returns an error the handler emits BOTH the legacy
// `IssueLicense failed` line AND the new explicit
// `event=paid_but_no_token_issued reason=<canonical>` line. The reason
// value comes from classifyIssueLicenseErr, which buckets every wrapped
// error path into a small fixed set (see issueReason* consts).
func TestWebhookHandler_PaidButNoTokenIssued_OnIssueFailure(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	body := stripeCheckoutEvent("cs_buyer_1894_b", "buyer1894b@example.com")
	header := signRequest(t, body, now, testSigningSecret)

	// Force IssueLicense to fail on the BeginTx step → maps to reason=tx_begin.
	mock.ExpectBegin().WillReturnError(errors.New("connection refused"))

	getLog := captureLog(t)

	h := NewWebhookHandler(db, WebhookHandlerConfig{
		SigningSecret: testSigningSecret,
		ValidityDays:  90,
		EmailSender:   &NoopLicenseEmailSender{},
	})
	h.now = fixedClock(now)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 (Stripe should retry), got %d: %s", rec.Code, rec.Body.String())
	}

	logged := getLog()

	// Legacy line — must still fire.
	wantLegacy := "[billing.webhook] IssueLicense failed for session=cs_test_session_1 tenant=cs_buyer_1894_b"
	if !strings.Contains(logged, wantLegacy) {
		t.Errorf("legacy IssueLicense-failed line missing: want substring %q in:\n%s", wantLegacy, logged)
	}

	// New explicit alarm token. reason MUST be a canonical value, not the
	// raw err string — that's the whole point.
	wantNew := "[billing.webhook] event=paid_but_no_token_issued reason=tx_begin session=cs_test_session_1 tenant=cs_buyer_1894_b err="
	if !strings.Contains(logged, wantNew) {
		t.Errorf("new paid-but-no-token line missing: want substring %q in:\n%s", wantNew, logged)
	}
}

// TestClassifyIssueLicenseErr_AllReasons covers the full canonical set so
// the alarm-pattern stability contract is locked. Adding a new reason value
// requires a corresponding case here.
func TestClassifyIssueLicenseErr_AllReasons(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		// Boundary
		{name: "nil-returns-empty", err: nil, want: ""},

		// Validation
		{name: "validation",
			err:  errors.New("invalid IssueRequest: TenantID is required"),
			want: issueReasonValidation},

		// Tx + lock
		{name: "tx-begin",
			err:  errors.New("begin tx: connection refused"),
			want: issueReasonTxBegin},
		{name: "advisory-lock",
			err:  errors.New("acquire per-tenant lock: lock not granted"),
			want: issueReasonAdvisoryLock},

		// Idempotency lookup
		{name: "idempotency-lookup",
			err:  errors.New("idempotency lookup: pq: connection broken"),
			want: issueReasonIdempotencyLookup},
		{name: "post-conflict-lookup",
			err:  errors.New("post-conflict lookup: row not found"),
			want: issueReasonIdempotencyLookup},

		// Signing
		{name: "generate",
			err:  errors.New("GeneratePluginClaimLicense: signing key not loaded"),
			want: issueReasonSigningFailed},
		{name: "self-verify",
			err:  errors.New("self-verify newly-issued token: bad signature"),
			want: issueReasonSigningFailed},
		{name: "remint-existing",
			err:  errors.New("re-mint existing token: payload mismatch"),
			want: issueReasonSigningFailed},
		{name: "remint-conflict",
			err:  errors.New("re-mint after conflict: payload mismatch"),
			want: issueReasonSigningFailed},

		// DB write
		{name: "revoke-prior",
			err:  errors.New("revoke prior active row: pq: deadlock detected"),
			want: issueReasonDBInsert},
		{name: "insert",
			err:  errors.New("insert plugin_user_licenses: pq: foreign key violation"),
			want: issueReasonDBInsert},
		{name: "insert-conflict-impossible",
			err:  errors.New("INSERT conflict but no existing row found (serializable race)"),
			want: issueReasonDBInsert},

		// Commit
		{name: "commit",
			err:  errors.New("commit: connection lost"),
			want: issueReasonCommit},
		{name: "commit-idempotent",
			err:  errors.New("commit (idempotent path): connection lost"),
			want: issueReasonCommit},
		{name: "commit-conflict",
			err:  errors.New("commit (conflict path): connection lost"),
			want: issueReasonCommit},

		// Fallback
		{name: "unmapped-falls-back-to-unknown",
			err:  errors.New("totally unrelated wrapper: foo"),
			want: issueReasonUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyIssueLicenseErr(tc.err)
			if got != tc.want {
				t.Errorf("classifyIssueLicenseErr(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestClassifyIssueLicenseErr_ReasonsAreShellSafe ensures every canonical
// reason value is a single token with no whitespace / shell metacharacters.
// The CW metric-filter pattern is space-separated; a reason containing a
// space would silently get split into "reason=db" + "insert", breaking
// any per-reason dashboard that splits on the space.
func TestClassifyIssueLicenseErr_ReasonsAreShellSafe(t *testing.T) {
	all := []string{
		issueReasonTxBegin,
		issueReasonAdvisoryLock,
		issueReasonIdempotencyLookup,
		issueReasonValidation,
		issueReasonSigningFailed,
		issueReasonDBInsert,
		issueReasonCommit,
		issueReasonUnknown,
	}
	for _, r := range all {
		if r == "" {
			t.Errorf("reason value is empty — must be a non-empty token")
		}
		if strings.ContainsAny(r, " \t\n\"'$`") {
			t.Errorf("reason %q contains whitespace or shell metacharacter — must be a bare alphanumeric_underscore token", r)
		}
	}
}

// =============================================================================
// #1895 — charge.refunded auto-revoke on full refund
//
// Stripe fires charge.refunded whenever a Refund is created/updated for a
// Charge. Full refund → revoke license. Partial refund → no-op. Replays of
// already-revoked rows → idempotent no-op. See handleChargeRefunded for the
// canonical decision rule.
// =============================================================================

// chargeRefundedEvent builds a minimal charge.refunded event JSON. amount is
// the original charge in cents; refundAmount is the cumulative amount_refunded
// on the Charge after this Refund. status is the latest refund's Stripe
// status. Setting refundAmount==amount AND status=="succeeded" produces a
// full-refund payload; refundAmount<amount produces a partial-refund payload.
//
// `paymentIntentID` is the lookup key into plugin_user_licenses
// (stripe_payment_intent_id column) — Charge.metadata is empty on real
// Stripe Payment Link refunds (verified live), so we no longer go via
// metadata.checkout_session_id. Test helpers carry the same shape so the
// SQL mocks line up with the production query.
func chargeRefundedEvent(paymentIntentID, chargeID string, amount, refundAmount int64, status string) []byte {
	ev := map[string]any{
		"id":   "evt_test_refund_" + chargeID,
		"type": "charge.refunded",
		"data": map[string]any{
			"object": map[string]any{
				"id":              chargeID,
				"amount":          amount,
				"amount_refunded": refundAmount,
				"currency":        "usd",
				"refunded":        refundAmount >= amount,
				"payment_intent":  paymentIntentID,
				// Metadata kept on the synthetic payload to exercise the
				// "field unmarshals but is ignored" path. Real Live Payment
				// Link refunds carry an empty / absent metadata map; our
				// production code reads `payment_intent` regardless.
				"metadata": map[string]any{},
				"refunds": map[string]any{
					"data": []map[string]any{
						{
							"id":     "re_test_" + chargeID,
							"amount": refundAmount,
							"status": status,
						},
					},
				},
			},
		},
	}
	b, _ := json.Marshal(ev)
	return b
}

// TestResolvePaymentIntentFromCharge covers the payment_intent extraction —
// reverse-lookup key into plugin_user_licenses.stripe_payment_intent_id.
func TestResolvePaymentIntentFromCharge(t *testing.T) {
	cases := []struct {
		name string
		pi   string
		want string
	}{
		{name: "happy_path", pi: "pi_test_123", want: "pi_test_123"},
		{name: "trims_whitespace", pi: "  pi_padded_456  ", want: "pi_padded_456"},
		{name: "empty_returns_empty", pi: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolvePaymentIntentFromCharge(stripeChargeRefundedObject{PaymentIntent: tc.pi})
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIsFullRefund locks the full-vs-partial decision rule.
func TestIsFullRefund(t *testing.T) {
	cases := []struct {
		name string
		ch   stripeChargeRefundedObject
		want bool
	}{
		{name: "full_refund_succeeded",
			ch: stripeChargeRefundedObject{
				Amount:         999,
				AmountRefunded: 999,
				Refunds:        stripeChargeRefundsList{Data: []stripeRefund{{Status: "succeeded", Amount: 999}}},
			},
			want: true},
		{name: "partial_refund_lower_amount",
			ch: stripeChargeRefundedObject{
				Amount:         999,
				AmountRefunded: 500,
				Refunds:        stripeChargeRefundsList{Data: []stripeRefund{{Status: "succeeded", Amount: 500}}},
			},
			want: false},
		{name: "full_amount_but_pending_refund_NOT_full",
			ch: stripeChargeRefundedObject{
				Amount:         999,
				AmountRefunded: 999,
				Refunds:        stripeChargeRefundsList{Data: []stripeRefund{{Status: "pending", Amount: 999}}},
			},
			want: false},
		{name: "boolean_refunded_fallback_when_refunds_list_empty",
			ch: stripeChargeRefundedObject{
				Amount:         999,
				AmountRefunded: 999,
				Refunded:       true,
				Refunds:        stripeChargeRefundsList{Data: nil},
			},
			want: true},
		{name: "zero_amount_charge_not_full",
			// Defensive — Stripe shouldn't ever fire charge.refunded on a
			// zero-amount charge, but if it does we treat it as not-full
			// rather than panic on division-by-zero or an absurd revoke.
			ch: stripeChargeRefundedObject{
				Amount:         0,
				AmountRefunded: 0,
			},
			want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isFullRefund(tc.ch)
			if got != tc.want {
				t.Errorf("isFullRefund(%+v) = %v, want %v", tc.ch, got, tc.want)
			}
		})
	}
}

// TestWebhookHandler_ChargeRefunded_FullRefund_Revokes is scenario 1 from
// #1895: a full refund (amount_refunded == amount, status==succeeded) drives
// an UPDATE keyed on stripe_payment_intent_id that sets revoked_at +
// revocation_reason='full_refund', RETURNING stripe_session_id; an audit row
// is written under the returned session_id; returns 200. The alarm-stable
// log line `event=license_revoked_on_refund` must fire with session=<cs_id>
// (NOT the payment_intent — operators key dashboards off session_id).
func TestWebhookHandler_ChargeRefunded_FullRefund_Revokes(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	// Lookup by payment_intent; the test fixture's session_id is recovered
	// via UPDATE ... RETURNING.
	body := chargeRefundedEvent("pi_test_full_1", "ch_test_full_1", 999, 999, "succeeded")
	header := signRequest(t, body, now, testSigningSecret)

	// v9 Phase 8 #2384 PR-C1: UPDATE now RETURNs stripe_session_id AND
	// tenant_id so the downstream agent_audit_logs INSERT can pin
	// app.current_org_id via WithOrgScope.
	mock.ExpectQuery(`UPDATE plugin_user_licenses[\s\S]*RETURNING stripe_session_id, tenant_id`).
		WithArgs("pi_test_full_1", "full_refund").
		WillReturnRows(sqlmock.NewRows([]string{"stripe_session_id", "tenant_id"}).
			AddRow("cs_test_session_1", "tenant-1"))

	// Audit row INSERT — wrapped in WithOrgScope using the returned
	// tenant_id (== org_id post mig 100 csaas remap). agent_audit_logs is
	// ENABLE-RLS (mig 018) and the INSERT now includes org_id as $4.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("tenant-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO agent_audit_logs`).
		WithArgs("cs_test_session_1", "license_revoked_full_refund", "charge=ch_test_full_1 amount_refunded=999", "tenant-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	getLog := captureLog(t)

	h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})
	h.now = fixedClock(now)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if resp["status"] != "revoked" {
		t.Errorf("status: got %v, want revoked", resp["status"])
	}
	if resp["reason"] != "full_refund" {
		t.Errorf("reason: got %v, want full_refund", resp["reason"])
	}
	if resp["session"] != "cs_test_session_1" {
		t.Errorf("session: got %v, want cs_test_session_1 (recovered via RETURNING)", resp["session"])
	}

	// Alarm-stable log line: lock the EXACT shape (token order + spacing).
	logged := getLog()
	want := "[billing.webhook] event=license_revoked_on_refund session=cs_test_session_1 charge=ch_test_full_1 amount_refunded=999 reason=full_refund"
	if !strings.Contains(logged, want) {
		t.Errorf("alarm-stable log line missing: want substring %q in:\n%s", want, logged)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations not met: %v", err)
	}
}

// TestWebhookHandler_ChargeRefunded_PartialRefund_NoOp is scenario 2 from
// #1895: a partial refund (amount_refunded < amount) leaves the license
// untouched. NO UPDATE, NO audit row. Returns 200 with status=skipped.
// The `event=partial_refund_no_op` log token fires with session=<cs_id>
// recovered via the best-effort lookup helper (so dashboards keyed off
// session= keep working on partial-refund volume).
func TestWebhookHandler_ChargeRefunded_PartialRefund_NoOp(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	// Partial refund: charged 999, only 500 refunded; lookup by payment_intent.
	body := chargeRefundedEvent("pi_test_partial_1", "ch_test_partial_1", 999, 500, "succeeded")
	header := signRequest(t, body, now, testSigningSecret)

	// Best-effort SELECT to recover session_id for the log/response context;
	// no UPDATE, no audit on the partial path.
	mock.ExpectQuery(`SELECT stripe_session_id\s+FROM plugin_user_licenses\s+WHERE stripe_payment_intent_id`).
		WithArgs("pi_test_partial_1").
		WillReturnRows(sqlmock.NewRows([]string{"stripe_session_id"}).
			AddRow("cs_test_session_partial"))

	getLog := captureLog(t)

	h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})
	h.now = fixedClock(now)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if resp["status"] != "skipped" {
		t.Errorf("status: got %v, want skipped", resp["status"])
	}

	// Alarm-stable log line for partial refunds.
	logged := getLog()
	want := "[billing.webhook] event=partial_refund_no_op session=cs_test_session_partial charge=ch_test_partial_1 refund_amount=500 charge_amount=999"
	if !strings.Contains(logged, want) {
		t.Errorf("partial-refund log line missing: want substring %q in:\n%s", want, logged)
	}

	// Belt-and-braces: lookup-only, no UPDATE / audit.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations not met (partial refund must only do lookup-SELECT): %v", err)
	}
}

// TestWebhookHandler_ChargeRefunded_Replay_Idempotent is scenario 3 from
// #1895: the same charge.refunded event arriving twice (Stripe retries on
// 5xx; the same event ID can land 2-3x). The first call revokes (UPDATE
// RETURNING returns the session_id); the second finds the row already-
// revoked (UPDATE returns sql.ErrNoRows because the `revoked_at IS NULL`
// filter excludes it) and emits the no-op log line — session_id recovered
// via the lookup-helper SELECT so dashboards keep working.
func TestWebhookHandler_ChargeRefunded_Replay_Idempotent(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	body := chargeRefundedEvent("pi_test_replay_1", "ch_test_replay_1", 999, 999, "succeeded")
	header := signRequest(t, body, now, testSigningSecret)

	// First delivery: full refund path → UPDATE RETURNING session_id +
	// tenant_id + audit (wrapped). v9 Phase 8 #2384 PR-C1.
	mock.ExpectQuery(`UPDATE plugin_user_licenses[\s\S]*RETURNING stripe_session_id, tenant_id`).
		WithArgs("pi_test_replay_1", "full_refund").
		WillReturnRows(sqlmock.NewRows([]string{"stripe_session_id", "tenant_id"}).
			AddRow("cs_test_session_replay", "tenant-1"))
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("tenant-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO agent_audit_logs`).
		WithArgs("cs_test_session_replay", "license_revoked_full_refund", "charge=ch_test_replay_1 amount_refunded=999", "tenant-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Second delivery (replay): same UPDATE returns no rows because revoked_at
	// is now non-null. Lookup-helper SELECT recovers session_id for log/response.
	// NO audit on this path.
	mock.ExpectQuery(`UPDATE plugin_user_licenses[\s\S]*RETURNING stripe_session_id, tenant_id`).
		WithArgs("pi_test_replay_1", "full_refund").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT stripe_session_id\s+FROM plugin_user_licenses\s+WHERE stripe_payment_intent_id`).
		WithArgs("pi_test_replay_1").
		WillReturnRows(sqlmock.NewRows([]string{"stripe_session_id"}).
			AddRow("cs_test_session_replay"))

	h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})
	h.now = fixedClock(now)

	// First delivery
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first delivery: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Second delivery — fresh log capture so we can assert the no-op token
	// fires this time (not the revoke token).
	getLog := captureLog(t)
	req2 := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req2.Header.Set(stripeSignatureHeader, header)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("replay: expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp)
	if resp["status"] != "no_op" {
		t.Errorf("replay status: got %v, want no_op", resp["status"])
	}

	logged := getLog()
	want := "[billing.webhook] event=refund_already_revoked session=cs_test_session_replay charge=ch_test_replay_1"
	if !strings.Contains(logged, want) {
		t.Errorf("idempotent log line missing on replay: want substring %q in:\n%s", want, logged)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations not met: %v", err)
	}
}

// TestWebhookHandler_ChargeRefunded_AlreadyRevoked_NoOp is scenario 4 from
// #1895: the license was already revoked by a different path (e.g. token
// expiry / replaced-by-new-purchase) before this refund event arrived. From
// the handler's perspective this is identical to the replay case — UPDATE
// returns ErrNoRows. Same `event=refund_already_revoked` log line; session_id
// recovered via the lookup-helper SELECT.
func TestWebhookHandler_ChargeRefunded_AlreadyRevoked_NoOp(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	body := chargeRefundedEvent("pi_already_revoked", "ch_test_already_1", 999, 999, "succeeded")
	header := signRequest(t, body, now, testSigningSecret)

	// UPDATE returns ErrNoRows — pre-existing revoked_at means the WHERE
	// `revoked_at IS NULL` filter excludes the row.
	mock.ExpectQuery(`UPDATE plugin_user_licenses[\s\S]*RETURNING stripe_session_id`).
		WithArgs("pi_already_revoked", "full_refund").
		WillReturnError(sql.ErrNoRows)
	// Lookup-helper SELECT finds the (revoked) row to surface session_id.
	mock.ExpectQuery(`SELECT stripe_session_id\s+FROM plugin_user_licenses\s+WHERE stripe_payment_intent_id`).
		WithArgs("pi_already_revoked").
		WillReturnRows(sqlmock.NewRows([]string{"stripe_session_id"}).
			AddRow("cs_already_revoked"))
	// NO audit row insert (handler skips audit on the no-op path).

	getLog := captureLog(t)

	h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})
	h.now = fixedClock(now)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	logged := getLog()
	want := "[billing.webhook] event=refund_already_revoked session=cs_already_revoked"
	if !strings.Contains(logged, want) {
		t.Errorf("already-revoked log line missing: want substring %q in:\n%s", want, logged)
	}
	// Crucially: the revoke-success token MUST NOT fire on this path (would
	// double-count in any operator dashboard).
	dontWant := "event=license_revoked_on_refund"
	if strings.Contains(logged, dontWant) {
		t.Errorf("revoke-success token fired on already-revoked path; got:\n%s", logged)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations not met: %v", err)
	}
}

// TestWebhookHandler_ChargeRefunded_NoPaymentIntent_Skips covers the
// defensive path where charge.payment_intent is missing — would be a
// Stripe-side payload-shape change for a Charge that originated from a
// Checkout Session / Payment Link, but a hand-created Charge (or a future
// Stripe Connect destination-charge variant) might omit it. Handler must
// 200 (so Stripe doesn't retry forever) and emit a canonical log token an
// operator can trace. NO DB calls on this path — no UPDATE, no SELECT.
func TestWebhookHandler_ChargeRefunded_NoPaymentIntent_Skips(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	// Build a charge.refunded event whose Charge has no payment_intent at all.
	body, _ := json.Marshal(map[string]any{
		"id":   "evt_test_no_pi",
		"type": "charge.refunded",
		"data": map[string]any{
			"object": map[string]any{
				"id":              "ch_test_no_pi",
				"amount":          999,
				"amount_refunded": 999,
				"currency":        "usd",
				"refunded":        true,
				// payment_intent intentionally omitted.
				"metadata": map[string]any{},
				"refunds": map[string]any{
					"data": []map[string]any{
						{"id": "re_x", "amount": 999, "status": "succeeded"},
					},
				},
			},
		},
	})
	header := signRequest(t, body, now, testSigningSecret)

	getLog := captureLog(t)

	h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})
	h.now = fixedClock(now)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	logged := getLog()
	want := "[billing.webhook] event=refund_no_payment_intent charge=ch_test_no_pi"
	if !strings.Contains(logged, want) {
		t.Errorf("no-payment-intent log line missing: want substring %q in:\n%s", want, logged)
	}
}

// TestWebhookHandler_ChargeRefunded_Replay5xIdempotent is the explicit
// many-replays test asked for in #1895: hammering the SAME event-id 5 times
// must produce exactly one row-revoke and four no-op log lines. Stripe's
// at-least-once delivery guarantees can fire 2–3x in practice; we bound at 5
// for safety margin.
func TestWebhookHandler_ChargeRefunded_Replay5xIdempotent(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	body := chargeRefundedEvent("pi_5x", "ch_5x", 999, 999, "succeeded")
	header := signRequest(t, body, now, testSigningSecret)

	// First delivery: revoke (RETURNING session_id + tenant_id) +
	// audit (wrapped). v9 Phase 8 #2384 PR-C1.
	mock.ExpectQuery(`UPDATE plugin_user_licenses[\s\S]*RETURNING stripe_session_id, tenant_id`).
		WithArgs("pi_5x", "full_refund").
		WillReturnRows(sqlmock.NewRows([]string{"stripe_session_id", "tenant_id"}).AddRow("cs_5x", "tenant-1"))
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("tenant-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO agent_audit_logs`).
		WithArgs("cs_5x", "license_revoked_full_refund", "charge=ch_5x amount_refunded=999", "tenant-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	// Subsequent 4 deliveries: UPDATE returns ErrNoRows; lookup-helper
	// SELECT recovers the session_id; no audit.
	for i := 0; i < 4; i++ {
		mock.ExpectQuery(`UPDATE plugin_user_licenses[\s\S]*RETURNING stripe_session_id, tenant_id`).
			WithArgs("pi_5x", "full_refund").
			WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery(`SELECT stripe_session_id\s+FROM plugin_user_licenses\s+WHERE stripe_payment_intent_id`).
			WithArgs("pi_5x").
			WillReturnRows(sqlmock.NewRows([]string{"stripe_session_id"}).AddRow("cs_5x"))
	}

	h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})
	h.now = fixedClock(now)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
		req.Header.Set(stripeSignatureHeader, header)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("delivery %d: expected 200, got %d: %s", i+1, rec.Code, rec.Body.String())
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations not met (idempotency under 5x replay): %v", err)
	}
}

// TestWebhookHandler_ChargeRefunded_DBError_Returns500 covers the retry path:
// when the UPDATE itself errors with a non-ErrNoRows failure (DB unreachable
// / connection-broken), the handler must return 500 so Stripe retries the
// delivery. The log line carries payment_intent= (not session=) because the
// UPDATE never returned the RETURNING column.
func TestWebhookHandler_ChargeRefunded_DBError_Returns500(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	body := chargeRefundedEvent("pi_db_fail", "ch_db_fail", 999, 999, "succeeded")
	header := signRequest(t, body, now, testSigningSecret)

	mock.ExpectQuery(`UPDATE plugin_user_licenses[\s\S]*RETURNING stripe_session_id`).
		WithArgs("pi_db_fail", "full_refund").
		WillReturnError(errors.New("connection refused"))

	getLog := captureLog(t)

	h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})
	h.now = fixedClock(now)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(stripeSignatureHeader, header)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 (Stripe should retry), got %d: %s", rec.Code, rec.Body.String())
	}

	logged := getLog()
	want := "[billing.webhook] event=refund_revoke_db_error payment_intent=pi_db_fail charge=ch_db_fail err="
	if !strings.Contains(logged, want) {
		t.Errorf("DB-error log line missing: want substring %q in:\n%s", want, logged)
	}
}

// TestWebhookHandler_DisputeEvents_Returns200Ignored covers the explicit
// out-of-scope case from #1895: dispute / chargeback events are NOT handled
// in V1. The default-case ignore path must fire.
func TestWebhookHandler_DisputeEvents_Returns200Ignored(t *testing.T) {
	cases := []string{"charge.dispute.created", "charge.dispute.funds_withdrawn"}
	for _, evType := range cases {
		t.Run(evType, func(t *testing.T) {
			db, _, _ := sqlmock.New()
			defer db.Close()

			now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
			body, _ := json.Marshal(map[string]any{
				"id":   "evt_dispute",
				"type": evType,
				"data": map[string]any{"object": map[string]any{}},
			})
			header := signRequest(t, body, now, testSigningSecret)

			getLog := captureLog(t)

			h := NewWebhookHandler(db, WebhookHandlerConfig{SigningSecret: testSigningSecret})
			h.now = fixedClock(now)

			req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
			req.Header.Set(stripeSignatureHeader, header)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected 200 ignored, got %d", rec.Code)
			}
			logged := getLog()
			wantLog := fmt.Sprintf(`event type %q ignored`, evType)
			if !strings.Contains(logged, wantLog) {
				t.Errorf("ignored-event log missing: want %q in:\n%s", wantLog, logged)
			}
		})
	}
}
