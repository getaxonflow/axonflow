//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"axonflow/platform/agent/license"

	"github.com/DATA-DOG/go-sqlmock"
)

// =============================================================================
// Test fixtures
// =============================================================================

// setupPluginClaimSigningKey sets a fresh Ed25519 signing key in the env so
// license.Generate / Validate can round-trip in tests. Returns a teardown.
func setupPluginClaimSigningKey(t *testing.T) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", base64.StdEncoding.EncodeToString(priv.Seed()))
}

// issueTestPluginClaimToken returns a signed plugin-claim token for the given
// tenant + jti so tests can exercise the middleware's verify path against a
// real signature. Caller must call setupPluginClaimSigningKey first.
func issueTestPluginClaimToken(t *testing.T, tenantID, jti, email string) string {
	t.Helper()
	tok, err := license.GeneratePluginClaimLicense(license.PluginClaimLicenseInput{
		TenantID:       tenantID,
		ClaimedByEmail: email,
		Tier:           license.TierPluginClaimed,
		ValidityDays:   365,
		JTI:            jti,
	})
	if err != nil {
		t.Fatalf("GeneratePluginClaimLicense: %v", err)
	}
	return tok
}

// passThroughHandler is the inner handler the middleware wraps; tests assert
// on whether it ran (200) or got short-circuited by the middleware.
func passThroughHandler(t *testing.T, expectContext bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pcc := PluginClaimFromContext(r.Context())
		if expectContext && pcc == nil {
			t.Errorf("expected PluginClaimContext in request context, got nil")
		}
		if !expectContext && pcc != nil {
			t.Errorf("did NOT expect PluginClaimContext, got %+v", pcc)
		}
		w.WriteHeader(http.StatusOK)
	})
}

// pluginRowSelectRegex matches the SELECT query the middleware issues.
// Trimmed to the columns + table so sqlmock matches across whitespace.
var pluginRowSelectRegex = regexp.MustCompile(
	`SELECT license_id::text, tier, tenant_id, entitlements::text,\s+COALESCE\(stripe_customer_id, ''\), revoked_at\s+FROM plugin_user_licenses\s+WHERE license_token_jti = \$1`,
)

// =============================================================================
// No token → pass-through (free tier)
// =============================================================================

func TestPluginClaimMiddleware_NoToken_PassesThrough(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	mw := PluginClaimMiddleware(db)
	h := mw(passThroughHandler(t, false))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/decide", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (pass-through), got %d: %s", rec.Code, rec.Body.String())
	}
}

// =============================================================================
// Invalid token → 401
// =============================================================================

func TestPluginClaimMiddleware_InvalidToken_Returns401(t *testing.T) {
	setupPluginClaimSigningKey(t)
	db, _, _ := sqlmock.New()
	defer db.Close()

	mw := PluginClaimMiddleware(db)
	h := mw(passThroughHandler(t, false))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/decide", nil)
	req.Header.Set("X-License-Token", "AXON-bogus.bogus")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (invalid token), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPluginClaimMiddleware_NoPrefix_Returns401(t *testing.T) {
	setupPluginClaimSigningKey(t)
	db, _, _ := sqlmock.New()
	defer db.Close()

	mw := PluginClaimMiddleware(db)
	h := mw(passThroughHandler(t, false))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/decide", nil)
	req.Header.Set("X-License-Token", "not-axon-prefixed")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// =============================================================================
// Valid token + no DB row → 401 (not_found)
// =============================================================================

func TestPluginClaimMiddleware_ValidToken_NoRow_Returns401(t *testing.T) {
	setupPluginClaimSigningKey(t)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tok := issueTestPluginClaimToken(t, "cs_abc", "jti-no-row", "alice@example.com")

	mock.ExpectQuery(pluginRowSelectRegex.String()).
		WithArgs("jti-no-row").
		WillReturnError(sql.ErrNoRows)

	mw := PluginClaimMiddleware(db)
	h := mw(passThroughHandler(t, false))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/decide", nil)
	req.Header.Set("X-License-Token", tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (not_found), got %d: %s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// =============================================================================
// Valid token + revoked row → 401 (revoked)
// =============================================================================

func TestPluginClaimMiddleware_ValidToken_RevokedRow_Returns401(t *testing.T) {
	setupPluginClaimSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	tok := issueTestPluginClaimToken(t, "cs_abc", "jti-revoked", "alice@example.com")

	revokedTime := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{
		"license_id", "tier", "tenant_id", "entitlements", "stripe_customer_id", "revoked_at",
	}).AddRow("lid-1", "plugin-claimed", "cs_abc", `{"retention_days":365}`, "cus_test", revokedTime)

	mock.ExpectQuery(pluginRowSelectRegex.String()).
		WithArgs("jti-revoked").
		WillReturnRows(rows)

	mw := PluginClaimMiddleware(db)
	h := mw(passThroughHandler(t, false))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/decide", nil)
	req.Header.Set("X-License-Token", tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (revoked), got %d: %s", rec.Code, rec.Body.String())
	}
	if !regexp.MustCompile(`(?i)revoked`).MatchString(rec.Body.String()) {
		t.Errorf("response body should mention revocation, got: %s", rec.Body.String())
	}
}

// =============================================================================
// Valid token + tenant mismatch → 403
// =============================================================================

func TestPluginClaimMiddleware_ValidToken_TenantMismatch_Returns403(t *testing.T) {
	setupPluginClaimSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	tok := issueTestPluginClaimToken(t, "cs_abc", "jti-mismatch", "alice@example.com")

	// Token says tenant cs_abc, DB row says cs_xyz — forgery / re-use attempt
	rows := sqlmock.NewRows([]string{
		"license_id", "tier", "tenant_id", "entitlements", "stripe_customer_id", "revoked_at",
	}).AddRow("lid-1", "plugin-claimed", "cs_xyz", `{}`, "", nil)

	mock.ExpectQuery(pluginRowSelectRegex.String()).
		WithArgs("jti-mismatch").
		WillReturnRows(rows)

	mw := PluginClaimMiddleware(db)
	h := mw(passThroughHandler(t, false))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/decide", nil)
	req.Header.Set("X-License-Token", tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 (tenant_mismatch), got %d: %s", rec.Code, rec.Body.String())
	}
}

// =============================================================================
// Valid token + active row → 200 with PluginClaimContext set
// =============================================================================

func TestPluginClaimMiddleware_ValidToken_ActiveRow_PassesThroughWithContext(t *testing.T) {
	setupPluginClaimSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	tok := issueTestPluginClaimToken(t, "cs_abc", "jti-active", "alice@example.com")

	rows := sqlmock.NewRows([]string{
		"license_id", "tier", "tenant_id", "entitlements", "stripe_customer_id", "revoked_at",
	}).AddRow("lid-active", "plugin-claimed", "cs_abc",
		`{"retention_days":365,"daily_event_quota":10000,"support_level":"best_effort_email"}`,
		"cus_test", nil)

	mock.ExpectQuery(pluginRowSelectRegex.String()).
		WithArgs("jti-active").
		WillReturnRows(rows)

	// Inner handler asserts PluginClaimContext is populated AND that the
	// JSONB entitlements decoded into the right keys.
	innerRan := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerRan = true
		pcc := PluginClaimFromContext(r.Context())
		if pcc == nil {
			t.Fatalf("expected PluginClaimContext, got nil")
		}
		if pcc.LicenseID != "lid-active" {
			t.Errorf("LicenseID mismatch: got %q", pcc.LicenseID)
		}
		if pcc.Tier != "plugin-claimed" {
			t.Errorf("Tier mismatch: got %q", pcc.Tier)
		}
		if pcc.JTI != "jti-active" {
			t.Errorf("JTI mismatch: got %q", pcc.JTI)
		}
		if v, ok := pcc.Entitlements["retention_days"].(float64); !ok || v != 365 {
			t.Errorf("retention_days entitlement: got %v (type %T)", pcc.Entitlements["retention_days"], pcc.Entitlements["retention_days"])
		}
		if v, ok := pcc.Entitlements["support_level"].(string); !ok || v != "best_effort_email" {
			t.Errorf("support_level entitlement: got %v", pcc.Entitlements["support_level"])
		}
		if pcc.StripeCustomerID != "cus_test" {
			t.Errorf("StripeCustomerID mismatch: got %q", pcc.StripeCustomerID)
		}
		w.WriteHeader(http.StatusOK)
	})

	mw := PluginClaimMiddleware(db)
	h := mw(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/decide", nil)
	req.Header.Set("X-License-Token", tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !innerRan {
		t.Fatalf("inner handler never ran (middleware short-circuited)")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// =============================================================================
// DB nil → 503
// =============================================================================

func TestPluginClaimMiddleware_DBNil_Returns503(t *testing.T) {
	setupPluginClaimSigningKey(t)
	tok := issueTestPluginClaimToken(t, "cs_abc", "jti-nodb", "alice@example.com")

	mw := PluginClaimMiddleware(nil)
	h := mw(passThroughHandler(t, false))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/decide", nil)
	req.Header.Set("X-License-Token", tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

// =============================================================================
// DB query error → 503
// =============================================================================

func TestPluginClaimMiddleware_DBError_Returns503(t *testing.T) {
	setupPluginClaimSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	tok := issueTestPluginClaimToken(t, "cs_abc", "jti-dberr", "alice@example.com")

	// Simulate connection refused / query timeout
	mock.ExpectQuery(pluginRowSelectRegex.String()).
		WithArgs("jti-dberr").
		WillReturnError(sql.ErrConnDone)

	mw := PluginClaimMiddleware(db)
	h := mw(passThroughHandler(t, false))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/decide", nil)
	req.Header.Set("X-License-Token", tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (db error), got %d", rec.Code)
	}
}

// =============================================================================
// Bad entitlements JSON → still succeeds with empty entitlements
// =============================================================================

func TestPluginClaimMiddleware_BadEntitlementsJSON_StillSucceeds(t *testing.T) {
	setupPluginClaimSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	tok := issueTestPluginClaimToken(t, "cs_abc", "jti-badjson", "alice@example.com")

	// Malformed JSON in entitlements column — middleware should tolerate it
	// (log + empty map) so a single bad row doesn't take down the tier.
	rows := sqlmock.NewRows([]string{
		"license_id", "tier", "tenant_id", "entitlements", "stripe_customer_id", "revoked_at",
	}).AddRow("lid-bad", "plugin-claimed", "cs_abc", `{not valid json`, "", nil)

	mock.ExpectQuery(pluginRowSelectRegex.String()).
		WithArgs("jti-badjson").
		WillReturnRows(rows)

	innerRan := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerRan = true
		pcc := PluginClaimFromContext(r.Context())
		if pcc == nil {
			t.Fatal("expected PluginClaimContext")
		}
		if len(pcc.Entitlements) != 0 {
			t.Errorf("expected empty entitlements (bad JSON), got: %+v", pcc.Entitlements)
		}
		w.WriteHeader(http.StatusOK)
	})

	mw := PluginClaimMiddleware(db)
	mw(inner).ServeHTTP(httptest.NewRecorder(), withTokenHeader(httptest.NewRequest(http.MethodGet, "/", nil), tok))

	if !innerRan {
		t.Errorf("inner handler should have run despite bad entitlements JSON")
	}
}

// withTokenHeader is a tiny helper to set the X-License-Token header on a
// request. Saves a few lines of boilerplate in inline test calls.
func withTokenHeader(r *http.Request, tok string) *http.Request {
	r.Header.Set("X-License-Token", tok)
	return r
}

// =============================================================================
// PluginClaimFromContext on a context with no middleware → nil
// =============================================================================

func TestPluginClaimFromContext_NoMiddleware_ReturnsNil(t *testing.T) {
	if got := PluginClaimFromContext(context.Background()); got != nil {
		t.Errorf("expected nil from background context, got %+v", got)
	}
}
