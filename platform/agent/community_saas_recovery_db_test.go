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

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// DB-backed integration tests for the W3 free email-recovery flow. These run
// against a real PostgreSQL in CI (DATABASE_URL set) and skip locally when
// no DB is available — same pattern as community_saas_db_test.go and
// auth_middleware_db_test.go.
//
// What these test that sqlmock-only tests don't:
//   - Migration 076 schema is correct (table + indexes actually created)
//   - Real SQL parses + executes against Postgres (catches PG-specific syntax)
//   - bcrypt + rand.Read happy paths actually execute (instead of being skipped)
//   - register_tenant + register_org SQL functions actually fire
//   - Per-email cap counted from real registrations, not mocks
//   - Token consumed-then-replayed scenario verifies real UPDATE semantics

func getTestDBForRecovery(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping DB integration test: DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping: %v", err)
	}

	// Migration 075 (claimed_by_email) + 076 (recovery_tokens) must be applied.
	for _, table := range []string{"community_saas_registrations", "community_saas_recovery_tokens"} {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (
			SELECT FROM information_schema.tables WHERE table_name = $1
		)`, table).Scan(&exists); err != nil || !exists {
			t.Skipf("Skipping: %s table not present (migration 076 not applied?)", table)
		}
	}

	// Confirm claimed_by_email column exists (migration 075)
	var hasCol bool
	if err := db.QueryRow(`SELECT EXISTS (
		SELECT FROM information_schema.columns
		WHERE table_name = 'community_saas_registrations' AND column_name = 'claimed_by_email'
	)`).Scan(&hasCol); err != nil || !hasCol {
		t.Skip("Skipping: claimed_by_email column not present (migration 075 not applied?)")
	}

	return db
}

// seedRegistrationWithEmail inserts a registration row pre-claimed to the
// given email. Returns the tenant_id. Used by tests that need an existing
// email-bound tenant before exercising recovery.
func seedRegistrationWithEmail(t *testing.T, db *sql.DB, email string) string {
	t.Helper()
	tenantID := communitySaasTenantPrefix + uuidNewString()
	expiresAt := time.Now().UTC().Add(communitySaasRegistrationTTL)
	_, err := db.Exec(`
		INSERT INTO community_saas_registrations
		(tenant_id, secret_hash, secret_prefix, org_id, label, expires_at, claimed_by_email, claimed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
		tenantID, "$2a$12$dummyhashdummyhashdummyhashdummyhashdummyhashdumm", "12345678",
		communitySaasOrgID, "test-recovery", expiresAt, email)
	if err != nil {
		t.Fatalf("seedRegistrationWithEmail failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM community_saas_registrations WHERE tenant_id = $1`, tenantID)
	})
	return tenantID
}

// cleanupRecoveryTokensForEmail removes all recovery_tokens rows for an email.
// Used in test setup/teardown to keep tests independent.
func cleanupRecoveryTokensForEmail(t *testing.T, db *sql.DB, email string) {
	t.Helper()
	_, _ = db.Exec(`DELETE FROM community_saas_recovery_tokens WHERE email = $1`, email)
}

// uniqueEmail returns a per-test email so concurrent CI runs don't collide.
func uniqueEmail(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("w3-test-%d-%s@axonflow-test.invalid", time.Now().UnixNano(), strings.ToLower(t.Name()))
}

// =============================================================================
// Recovery request — DB-backed
// =============================================================================

func TestRecoveryRequest_DB_AntiEnumeration_UnknownEmail(t *testing.T) {
	db := getTestDBForRecovery(t)
	defer db.Close()

	resetRegIPTracker()
	router := mux.NewRouter()
	noop := &NoopRecoveryEmailSender{}
	RegisterCommunityRecoveryHandler(router, db, noop)

	email := uniqueEmail(t)
	cleanupRecoveryTokensForEmail(t, db, email)

	w := postRecover(router, recoveryRequestBody{Email: email})
	if w.Code != http.StatusAccepted {
		t.Errorf("unknown email should return 202 (anti-enum), got %d", w.Code)
	}

	// No token should have been inserted
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM community_saas_recovery_tokens WHERE email = $1`, email).Scan(&count); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != 0 {
		t.Errorf("anti-enum: expected 0 tokens for unknown email, got %d", count)
	}
	if len(noop.CapturedLinks()) != 0 {
		t.Errorf("anti-enum: expected 0 emails sent for unknown email, got %d", len(noop.CapturedLinks()))
	}
}

func TestRecoveryRequest_DB_KnownEmail_IssuesToken(t *testing.T) {
	db := getTestDBForRecovery(t)
	defer db.Close()

	resetRegIPTracker()
	router := mux.NewRouter()
	noop := &NoopRecoveryEmailSender{}
	RegisterCommunityRecoveryHandler(router, db, noop)

	email := uniqueEmail(t)
	cleanupRecoveryTokensForEmail(t, db, email)
	_ = seedRegistrationWithEmail(t, db, email)

	w := postRecover(router, recoveryRequestBody{Email: email})
	if w.Code != http.StatusAccepted {
		t.Errorf("known email should return 202, got %d", w.Code)
	}

	// Exactly one token should have been inserted
	var count int
	var hashedTokenLength int
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(MAX(LENGTH(token_hash)), 0)
		FROM community_saas_recovery_tokens WHERE email = $1`, email).Scan(&count, &hashedTokenLength); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 token, got %d", count)
	}
	if hashedTokenLength != 64 {
		t.Errorf("token_hash should be 64 hex chars (SHA-256), got %d", hashedTokenLength)
	}
	if len(noop.CapturedLinks()) != 1 {
		t.Errorf("expected 1 email sent, got %d", len(noop.CapturedLinks()))
	}

	// Token expires_at should be ~15 minutes in the future
	var expiresAt time.Time
	if err := db.QueryRow(`SELECT expires_at FROM community_saas_recovery_tokens WHERE email = $1`, email).Scan(&expiresAt); err != nil {
		t.Fatalf("expires_at query failed: %v", err)
	}
	delta := time.Until(expiresAt)
	if delta < 14*time.Minute || delta > 16*time.Minute {
		t.Errorf("token TTL should be ~15min, got %v", delta)
	}

	cleanupRecoveryTokensForEmail(t, db, email)
}

func TestRecoveryRequest_DB_PerEmailRateLimit(t *testing.T) {
	db := getTestDBForRecovery(t)
	defer db.Close()

	resetRegIPTracker()
	router := mux.NewRouter()
	noop := &NoopRecoveryEmailSender{}
	RegisterCommunityRecoveryHandler(router, db, noop)

	email := uniqueEmail(t)
	cleanupRecoveryTokensForEmail(t, db, email)
	_ = seedRegistrationWithEmail(t, db, email)

	// First recoveryEmailRateLimit requests should succeed and issue tokens
	for i := 0; i < recoveryEmailRateLimit; i++ {
		w := postRecover(router, recoveryRequestBody{Email: email})
		if w.Code != http.StatusAccepted {
			t.Fatalf("request %d/%d should return 202, got %d", i+1, recoveryEmailRateLimit, w.Code)
		}
	}

	var countBeforeLimit int
	if err := db.QueryRow(`SELECT COUNT(*) FROM community_saas_recovery_tokens WHERE email = $1`, email).Scan(&countBeforeLimit); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if countBeforeLimit != recoveryEmailRateLimit {
		t.Errorf("expected %d tokens after limit-1 requests, got %d", recoveryEmailRateLimit, countBeforeLimit)
	}

	// Next request should be rate-limited (still 202 generic, but no new token + no email)
	priorEmails := len(noop.CapturedLinks())
	w := postRecover(router, recoveryRequestBody{Email: email})
	if w.Code != http.StatusAccepted {
		t.Errorf("rate-limited request should still return 202 (anti-enum), got %d", w.Code)
	}

	var countAfterLimit int
	if err := db.QueryRow(`SELECT COUNT(*) FROM community_saas_recovery_tokens WHERE email = $1`, email).Scan(&countAfterLimit); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if countAfterLimit != recoveryEmailRateLimit {
		t.Errorf("rate-limit hit: token count should not have increased; got %d", countAfterLimit)
	}
	if len(noop.CapturedLinks()) != priorEmails {
		t.Errorf("rate-limit hit: should not have sent additional email")
	}

	cleanupRecoveryTokensForEmail(t, db, email)
}

// =============================================================================
// Recovery verify — DB-backed (full happy path + edge cases)
// =============================================================================

// issueTestRecoveryToken inserts a recovery token directly with the given
// email + expiry. Returns the plain token (not hashed) to use in verify.
// Caller is responsible for cleanup.
func issueTestRecoveryToken(t *testing.T, db *sql.DB, email string, ttl time.Duration) string {
	t.Helper()
	plainToken := fmt.Sprintf("test-token-%d", time.Now().UnixNano())
	tokenHash := hashRecoveryToken(plainToken)
	_, err := db.Exec(`
		INSERT INTO community_saas_recovery_tokens (token_hash, email, expires_at)
		VALUES ($1, $2, $3)`,
		tokenHash, email, time.Now().UTC().Add(ttl))
	if err != nil {
		t.Fatalf("issueTestRecoveryToken failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM community_saas_recovery_tokens WHERE token_hash = $1`, tokenHash)
	})
	return plainToken
}

func TestRecoveryVerify_DB_HappyPath_NewTenantBoundToEmail(t *testing.T) {
	db := getTestDBForRecovery(t)
	defer db.Close()

	resetRegIPTracker()
	router := mux.NewRouter()
	RegisterCommunityRecoveryHandler(router, db, &NoopRecoveryEmailSender{})

	email := uniqueEmail(t)
	cleanupRecoveryTokensForEmail(t, db, email)
	_ = seedRegistrationWithEmail(t, db, email)
	plainToken := issueTestRecoveryToken(t, db, email, 15*time.Minute)

	req := postVerifyJSON(plainToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("happy path should return 200, got %d (body=%s)", w.Code, w.Body.String())
	}

	var resp recoveryVerifyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response should be JSON: %v", err)
	}
	if !strings.HasPrefix(resp.TenantID, communitySaasTenantPrefix) {
		t.Errorf("new tenant_id should have cs_ prefix, got %q", resp.TenantID)
	}
	if resp.Secret == "" || len(resp.Secret) != 32 {
		t.Errorf("response secret should be 32 hex chars, got %d", len(resp.Secret))
	}
	if resp.Email != email {
		t.Errorf("response email should match recovery email, got %q want %q", resp.Email, email)
	}

	// New tenant should be in the DB, bound to the same email
	var dbEmail string
	var claimedAt sql.NullTime
	err := db.QueryRow(`
		SELECT claimed_by_email, claimed_at FROM community_saas_registrations
		WHERE tenant_id = $1`, resp.TenantID).Scan(&dbEmail, &claimedAt)
	if err != nil {
		t.Fatalf("new tenant not found in DB: %v", err)
	}
	if dbEmail != email {
		t.Errorf("new tenant email mismatch: got %q want %q", dbEmail, email)
	}
	if !claimedAt.Valid {
		t.Errorf("claimed_at should be set after recovery")
	}

	// Token should be marked consumed
	var consumedAt sql.NullTime
	var consumedByTenant sql.NullString
	err = db.QueryRow(`
		SELECT consumed_at, consumed_by_tenant FROM community_saas_recovery_tokens
		WHERE token_hash = $1`, hashRecoveryToken(plainToken)).Scan(&consumedAt, &consumedByTenant)
	if err != nil {
		t.Fatalf("token row not found: %v", err)
	}
	if !consumedAt.Valid {
		t.Errorf("consumed_at should be set after successful verify")
	}
	if !consumedByTenant.Valid || consumedByTenant.String != resp.TenantID {
		t.Errorf("consumed_by_tenant should match new tenant_id, got %v want %s", consumedByTenant, resp.TenantID)
	}

	// Cleanup new tenant we just created
	_, _ = db.Exec(`DELETE FROM community_saas_registrations WHERE tenant_id = $1`, resp.TenantID)
	cleanupRecoveryTokensForEmail(t, db, email)
}

func TestRecoveryVerify_DB_ConsumedTokenRejected(t *testing.T) {
	db := getTestDBForRecovery(t)
	defer db.Close()

	resetRegIPTracker()
	router := mux.NewRouter()
	RegisterCommunityRecoveryHandler(router, db, &NoopRecoveryEmailSender{})

	email := uniqueEmail(t)
	cleanupRecoveryTokensForEmail(t, db, email)
	_ = seedRegistrationWithEmail(t, db, email)
	plainToken := issueTestRecoveryToken(t, db, email, 15*time.Minute)

	// First use — should succeed
	req1 := postVerifyJSON(plainToken)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first use should succeed, got %d (body=%s)", w1.Code, w1.Body.String())
	}
	var resp1 recoveryVerifyResponse
	_ = json.Unmarshal(w1.Body.Bytes(), &resp1)

	// Second use of same token — should be rejected with 401
	req2 := postVerifyJSON(plainToken)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("replayed token should return 401, got %d (body=%s)", w2.Code, w2.Body.String())
	}

	// Cleanup
	if resp1.TenantID != "" {
		_, _ = db.Exec(`DELETE FROM community_saas_registrations WHERE tenant_id = $1`, resp1.TenantID)
	}
	cleanupRecoveryTokensForEmail(t, db, email)
}

func TestRecoveryVerify_DB_ExpiredTokenRejected(t *testing.T) {
	db := getTestDBForRecovery(t)
	defer db.Close()

	resetRegIPTracker()
	router := mux.NewRouter()
	RegisterCommunityRecoveryHandler(router, db, &NoopRecoveryEmailSender{})

	email := uniqueEmail(t)
	cleanupRecoveryTokensForEmail(t, db, email)
	_ = seedRegistrationWithEmail(t, db, email)
	// Issue a token that's already expired
	plainToken := issueTestRecoveryToken(t, db, email, -1*time.Minute)

	req := postVerifyJSON(plainToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expired token should return 401, got %d", w.Code)
	}

	cleanupRecoveryTokensForEmail(t, db, email)
}

func TestRecoveryVerify_DB_PerEmailCapEnforcedFromRealRows(t *testing.T) {
	db := getTestDBForRecovery(t)
	defer db.Close()

	resetRegIPTracker()
	router := mux.NewRouter()
	RegisterCommunityRecoveryHandler(router, db, &NoopRecoveryEmailSender{})

	email := uniqueEmail(t)
	cleanupRecoveryTokensForEmail(t, db, email)
	// Seed exactly recoveryMaxTenantsPerEmail tenants for this email
	tenantIDs := make([]string, 0, recoveryMaxTenantsPerEmail)
	for i := 0; i < recoveryMaxTenantsPerEmail; i++ {
		tenantIDs = append(tenantIDs, seedRegistrationWithEmail(t, db, email))
	}
	plainToken := issueTestRecoveryToken(t, db, email, 15*time.Minute)

	req := postVerifyJSON(plainToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("at-cap should return 403, got %d (body=%s)", w.Code, w.Body.String())
	}

	cleanupRecoveryTokensForEmail(t, db, email)
}

func TestRecoveryRequest_DB_FullEndToEnd_RecoveryProducesUsableTenant(t *testing.T) {
	db := getTestDBForRecovery(t)
	defer db.Close()

	resetRegIPTracker()
	router := mux.NewRouter()
	noop := &NoopRecoveryEmailSender{}
	RegisterCommunityRecoveryHandler(router, db, noop)

	email := uniqueEmail(t)
	cleanupRecoveryTokensForEmail(t, db, email)
	originalTenantID := seedRegistrationWithEmail(t, db, email)

	// Step 1: request recovery
	w1 := postRecover(router, recoveryRequestBody{Email: email})
	if w1.Code != http.StatusAccepted {
		t.Fatalf("recovery request failed: %d", w1.Code)
	}
	captured := noop.CapturedLinks()
	if len(captured) != 1 {
		t.Fatalf("expected 1 captured email, got %d", len(captured))
	}

	// Step 2: extract the token from the magic link
	idx := strings.Index(captured[0], "token=")
	if idx < 0 {
		t.Fatalf("captured email does not contain token=...: %s", captured[0])
	}
	token := captured[0][idx+len("token="):]

	// Step 3: verify the token
	req2 := postVerifyJSON(token)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("verify failed: %d (body=%s)", w2.Code, w2.Body.String())
	}

	var resp recoveryVerifyResponse
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}

	// Assert: new tenant_id is different from original
	if resp.TenantID == originalTenantID {
		t.Errorf("recovery should produce NEW tenant_id, got same as original: %s", resp.TenantID)
	}
	// Assert: same email binding
	if resp.Email != email {
		t.Errorf("recovered tenant email mismatch: got %q want %q", resp.Email, email)
	}
	// Assert: original tenant still exists (recovery doesn't disable it)
	var origExists bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM community_saas_registrations WHERE tenant_id = $1)`, originalTenantID).Scan(&origExists); err != nil {
		t.Fatalf("original tenant lookup failed: %v", err)
	}
	if !origExists {
		t.Errorf("original tenant should still exist after recovery (audit history under it stays accessible)")
	}

	// Cleanup
	_, _ = db.Exec(`DELETE FROM community_saas_registrations WHERE tenant_id = $1`, resp.TenantID)
	cleanupRecoveryTokensForEmail(t, db, email)
}

// =============================================================================
// Schema sanity checks
// =============================================================================

func TestMigration076_TableExistsWithExpectedColumns(t *testing.T) {
	db := getTestDBForRecovery(t)
	defer db.Close()

	expectedCols := map[string]string{
		"token_hash":         "character varying",
		"email":              "character varying",
		"requesting_ip_hash": "character varying",
		"created_at":         "timestamp with time zone",
		"expires_at":         "timestamp with time zone",
		"consumed_at":        "timestamp with time zone",
		"consumed_by_tenant": "character varying",
	}

	rows, err := db.Query(`
		SELECT column_name, data_type FROM information_schema.columns
		WHERE table_name = 'community_saas_recovery_tokens'`)
	if err != nil {
		t.Fatalf("columns query failed: %v", err)
	}
	defer rows.Close()

	got := make(map[string]string)
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		got[name] = typ
	}

	for col, expectedType := range expectedCols {
		gotType, ok := got[col]
		if !ok {
			t.Errorf("migration 076: column %s missing", col)
			continue
		}
		if gotType != expectedType {
			t.Errorf("migration 076: column %s type=%s, want %s", col, gotType, expectedType)
		}
	}
}

func TestMigration076_IndexesExist(t *testing.T) {
	db := getTestDBForRecovery(t)
	defer db.Close()

	expectedIndexes := []string{
		"idx_csaas_recovery_expires",
		"idx_csaas_recovery_email_recent",
	}

	for _, idx := range expectedIndexes {
		var exists bool
		err := db.QueryRow(`SELECT EXISTS (
			SELECT 1 FROM pg_indexes WHERE indexname = $1
		)`, idx).Scan(&exists)
		if err != nil {
			t.Fatalf("index lookup failed for %s: %v", idx, err)
		}
		if !exists {
			t.Errorf("migration 076: index %s missing", idx)
		}
	}
}

// silenceContext is a tiny ctx.Done() guard used in integration setup to
// avoid linter complaints about unused context vars.
var _ = context.Background
var _ = bytes.Buffer{}
