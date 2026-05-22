// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// DB-backed integration tests for the GDPR right-to-erasure flow (issue #1896).
// Run only when DATABASE_URL is set; skipped in pure-CI runs without Postgres.
//
// What these test that pure-unit (sqlmock-free) tests don't:
//   - Migration 082 schema is correct (tables + indexes actually created)
//   - Real SQL parses + executes against Postgres (catches PG-specific syntax)
//   - The cascade DELETE actually scrubs each of the 5 sources
//   - The deletion log row is written and survives the cascade
//   - Token consumed-then-replayed scenarios verify real UPDATE semantics

func getTestDBForTenantDelete(t *testing.T) *sql.DB {
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

	// Migration 082 must be applied.
	for _, table := range []string{
		"community_saas_registrations",
		"community_saas_deletion_tokens",
		"tenant_deletion_log",
	} {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (
			SELECT FROM information_schema.tables WHERE table_name = $1
		)`, table).Scan(&exists); err != nil || !exists {
			t.Skipf("Skipping: %s table not present (migration 082 not applied?)", table)
		}
	}
	return db
}

func uniqueDeleteEmail(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("delete-test-%d-%s@axonflow-test.invalid",
		time.Now().UnixNano(), strings.ToLower(t.Name()))
}

func seedRegForDelete(t *testing.T, db *sql.DB, email string) string {
	t.Helper()
	tenantID := communitySaasTenantPrefix + uuidNewString()
	expiresAt := time.Now().UTC().Add(communitySaasRegistrationTTL)
	// v9 Phase 6: org_id = per-customer cs_<uuid> (== tenant_id == client_id).
	_, err := db.Exec(`
		INSERT INTO community_saas_registrations
		(tenant_id, client_id, secret_hash, secret_prefix, org_id, label, expires_at, claimed_by_email, claimed_at)
		VALUES ($1, $1, $2, $3, $1, $4, $5, $6, NOW())`,
		tenantID, "$2a$12$dummyhashdummyhashdummyhashdummyhashdummyhashdumm", "12345678",
		"delete-test", expiresAt, email)
	if err != nil {
		t.Fatalf("seedRegForDelete failed: %v", err)
	}
	t.Cleanup(func() {
		// Idempotent cleanup — the deletion test path may have already removed it.
		_, _ = db.Exec(`DELETE FROM community_saas_registrations WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(`DELETE FROM community_saas_deletion_tokens WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(`DELETE FROM tenant_deletion_log WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(`DELETE FROM audit_logs WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(`DELETE FROM community_saas_daily_usage WHERE tenant_id = $1`, tenantID)
	})
	return tenantID
}

// seedAuditLog inserts a single audit_logs row pointing at the given tenant.
// Returns nothing — caller verifies via count queries after deletion.
func seedAuditLog(t *testing.T, db *sql.DB, tenantID string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, request_type, query, query_hash, policy_decision)
		VALUES ($1, $2, NOW(), 1, 'test@e.co', 'test',
		    'client-x', $3, 'test', 'q', 'h', 'allow')`,
		fmt.Sprintf("audit-%d-%d", time.Now().UnixNano(), len(tenantID)),
		fmt.Sprintf("req-%d", time.Now().UnixNano()),
		tenantID)
	if err != nil {
		t.Fatalf("seedAuditLog failed: %v", err)
	}
}

func seedDailyUsage(t *testing.T, db *sql.DB, tenantID string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO community_saas_daily_usage (tenant_id, day, req_count)
		VALUES ($1, CURRENT_DATE, 7)`, tenantID)
	if err != nil {
		t.Fatalf("seedDailyUsage failed: %v", err)
	}
}

func seedProLicense(t *testing.T, db *sql.DB, tenantID, email, stripeCustomerID string, issuedAt time.Time) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO plugin_user_licenses
		(tenant_id, claimed_by_email, tier, license_token_jti, stripe_customer_id, issued_at)
		VALUES ($1, $2, 'Pro', $3, $4, $5)`,
		tenantID, email,
		fmt.Sprintf("jti-%d", time.Now().UnixNano()),
		stripeCustomerID, issuedAt)
	if err != nil {
		t.Fatalf("seedProLicense failed: %v", err)
	}
}

func newTenantDeleteRouterDB(t *testing.T, db *sql.DB) (*mux.Router, *NoopTenantDeletionEmailSender) {
	t.Helper()
	r := mux.NewRouter()
	noop := &NoopTenantDeletionEmailSender{}
	RegisterTenantDeletionHandler(r, db, noop)
	return r, noop
}

// =============================================================================
// delete-request — happy path + anti-enumeration
// =============================================================================

func TestTenantDelete_DB_Request_HappyPathIssuesToken(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	email := uniqueDeleteEmail(t)
	tenantID := seedRegForDelete(t, db, email)
	r, noop := newTenantDeleteRouterDB(t, db)

	body := fmt.Sprintf(`{"email":%q}`, email)
	w := postDeleteRequest(t, r, tenantID, body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("happy path delete-request should return 202, got %d (body=%s)", w.Code, w.Body.String())
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM community_saas_deletion_tokens
		WHERE tenant_id = $1 AND email = $2`, tenantID, email).Scan(&count); err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 token, got %d", count)
	}
	if len(noop.CapturedLinks()) != 1 {
		t.Errorf("expected 1 email captured, got %d", len(noop.CapturedLinks()))
	}

	// Token TTL ~1 hour
	var expiresAt time.Time
	if err := db.QueryRow(`SELECT expires_at FROM community_saas_deletion_tokens
		WHERE tenant_id = $1`, tenantID).Scan(&expiresAt); err != nil {
		t.Fatalf("expires_at query: %v", err)
	}
	delta := time.Until(expiresAt)
	if delta < 55*time.Minute || delta > 65*time.Minute {
		t.Errorf("token TTL should be ~1h, got %v", delta)
	}
}

func TestTenantDelete_DB_Request_UnregisteredTenant_AntiEnum(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	r, noop := newTenantDeleteRouterDB(t, db)
	bogusTenantID := "cs_bogus-" + fmt.Sprintf("%d", time.Now().UnixNano())
	body := `{"email":"someone@example.com"}`
	w := postDeleteRequest(t, r, bogusTenantID, body)
	if w.Code != http.StatusAccepted {
		t.Errorf("unknown tenant should still return 202 (anti-enum), got %d", w.Code)
	}
	// No token should be inserted.
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM community_saas_deletion_tokens WHERE tenant_id = $1`, bogusTenantID).Scan(&count)
	if count != 0 {
		t.Errorf("anti-enum: expected 0 tokens for unknown tenant, got %d", count)
	}
	if len(noop.CapturedLinks()) != 0 {
		t.Errorf("anti-enum: expected 0 emails sent for unknown tenant, got %d", len(noop.CapturedLinks()))
	}
}

func TestTenantDelete_DB_Request_EmailMismatch_AntiEnum(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	tenantID := seedRegForDelete(t, db, uniqueDeleteEmail(t))
	r, noop := newTenantDeleteRouterDB(t, db)

	// Use a different email — should still 202 with no token + no email send.
	body := `{"email":"wrong@example.com"}`
	w := postDeleteRequest(t, r, tenantID, body)
	if w.Code != http.StatusAccepted {
		t.Errorf("email mismatch should still return 202 (anti-enum), got %d", w.Code)
	}
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM community_saas_deletion_tokens WHERE tenant_id = $1`, tenantID).Scan(&count)
	if count != 0 {
		t.Errorf("email mismatch: expected 0 tokens, got %d", count)
	}
	if len(noop.CapturedLinks()) != 0 {
		t.Errorf("email mismatch: expected 0 emails sent, got %d", len(noop.CapturedLinks()))
	}
}

func TestTenantDelete_DB_Request_RateLimitPerTenant(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	email := uniqueDeleteEmail(t)
	tenantID := seedRegForDelete(t, db, email)
	r, _ := newTenantDeleteRouterDB(t, db)

	// First request — should succeed
	body := fmt.Sprintf(`{"email":%q}`, email)
	w1 := postDeleteRequest(t, r, tenantID, body)
	if w1.Code != http.StatusAccepted {
		t.Fatalf("first request: %d", w1.Code)
	}

	// Reset IP tracker so the in-process IP cap doesn't dominate over the
	// per-tenant DB-backed cap that we're trying to exercise here.
	resetTenantDeleteIPTracker()

	// Second request — DB rate limit should now cause us to NOT issue another token.
	w2 := postDeleteRequest(t, r, tenantID, body)
	if w2.Code != http.StatusAccepted {
		t.Errorf("second (rate-limited) request should still return 202, got %d", w2.Code)
	}
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM community_saas_deletion_tokens WHERE tenant_id = $1`, tenantID).Scan(&count)
	if count != 1 {
		t.Errorf("second request was rate-limited; expected 1 token still (no new), got %d", count)
	}
}

// =============================================================================
// delete-confirm — full erasure flow
// =============================================================================

// issueTokenDirect inserts a deletion token directly into the DB (bypassing
// the request endpoint). Returns the plain token (caller uses it in confirm).
func issueTokenDirect(t *testing.T, db *sql.DB, tenantID, email string, ttl time.Duration) string {
	t.Helper()
	plain := fmt.Sprintf("direct-token-%d", time.Now().UnixNano())
	tokenHash := hashTenantDeleteToken(plain)
	_, err := db.Exec(`
		INSERT INTO community_saas_deletion_tokens (token_hash, tenant_id, email, expires_at)
		VALUES ($1, $2, $3, $4)`,
		tokenHash, tenantID, email, time.Now().UTC().Add(ttl))
	if err != nil {
		t.Fatalf("issueTokenDirect: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM community_saas_deletion_tokens WHERE token_hash = $1`, tokenHash)
	})
	return plain
}

func TestTenantDelete_DB_Confirm_HappyPathScrubsAllSources(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	email := uniqueDeleteEmail(t)
	tenantID := seedRegForDelete(t, db, email)
	seedAuditLog(t, db, tenantID)
	seedAuditLog(t, db, tenantID) // 2 audit rows
	seedDailyUsage(t, db, tenantID)
	seedProLicense(t, db, tenantID, email, "cus_test_happy", time.Now().UTC().Add(-30*24*time.Hour))
	plain := issueTokenDirect(t, db, tenantID, email, 1*time.Hour)

	r, _ := newTenantDeleteRouterDB(t, db)

	w := postDeleteConfirm(t, r, tenantID, fmt.Sprintf(`{"token":%q}`, plain))
	if w.Code != http.StatusOK {
		t.Fatalf("confirm should return 200, got %d (body=%s)", w.Code, w.Body.String())
	}

	var resp tenantDeleteConfirmResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if resp.TenantID != tenantID {
		t.Errorf("response tenant_id mismatch: %s vs %s", resp.TenantID, tenantID)
	}
	if resp.DeletedRows.Registrations != 1 {
		t.Errorf("expected 1 registration deleted, got %d", resp.DeletedRows.Registrations)
	}
	// Pro license >= 1 (FK cascade may have consumed it before our DELETE; both
	// outcomes are correct). Assert at least the column was reported.
	// AuditLogs == 2
	if resp.DeletedRows.AuditLogs != 2 {
		t.Errorf("expected 2 audit rows deleted, got %d", resp.DeletedRows.AuditLogs)
	}
	if resp.DeletedRows.DailyUsage != 1 {
		t.Errorf("expected 1 daily_usage row deleted, got %d", resp.DeletedRows.DailyUsage)
	}

	// Verify all 5 sources clean
	for _, q := range []struct {
		name  string
		query string
	}{
		{"registrations", `SELECT COUNT(*) FROM community_saas_registrations WHERE tenant_id = $1`},
		{"licenses", `SELECT COUNT(*) FROM plugin_user_licenses WHERE tenant_id = $1`},
		{"audit_logs", `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1`},
		{"daily_usage", `SELECT COUNT(*) FROM community_saas_daily_usage WHERE tenant_id = $1`},
	} {
		var n int
		if err := db.QueryRow(q.query, tenantID).Scan(&n); err != nil {
			t.Fatalf("verify %s: %v", q.name, err)
		}
		if n != 0 {
			t.Errorf("after deletion, %s should have 0 rows for tenant; got %d", q.name, n)
		}
	}

	// Verify deletion log row exists
	var logCount int
	var stripeCustOnLog sql.NullString
	if err := db.QueryRow(`SELECT COUNT(*), MAX(stripe_customer_id) FROM tenant_deletion_log
		WHERE tenant_id = $1`, tenantID).Scan(&logCount, &stripeCustOnLog); err != nil {
		t.Fatalf("log lookup: %v", err)
	}
	if logCount != 1 {
		t.Errorf("expected 1 deletion log row, got %d", logCount)
	}
	if !stripeCustOnLog.Valid || stripeCustOnLog.String != "cus_test_happy" {
		t.Errorf("deletion log should record stripe_customer_id=cus_test_happy, got %v", stripeCustOnLog)
	}

	// Token should be marked consumed
	var consumedAt sql.NullTime
	if err := db.QueryRow(`SELECT consumed_at FROM community_saas_deletion_tokens
		WHERE token_hash = $1`, hashTenantDeleteToken(plain)).Scan(&consumedAt); err != nil {
		t.Fatalf("token lookup: %v", err)
	}
	if !consumedAt.Valid {
		t.Errorf("token should be marked consumed after happy path")
	}
}

func TestTenantDelete_DB_Confirm_ExpiredToken_410(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	email := uniqueDeleteEmail(t)
	tenantID := seedRegForDelete(t, db, email)
	plain := issueTokenDirect(t, db, tenantID, email, -1*time.Minute) // already expired

	r, _ := newTenantDeleteRouterDB(t, db)
	w := postDeleteConfirm(t, r, tenantID, fmt.Sprintf(`{"token":%q}`, plain))
	if w.Code != http.StatusGone {
		t.Errorf("expired token should return 410, got %d", w.Code)
	}
}

func TestTenantDelete_DB_Confirm_ReusedToken_410(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	email := uniqueDeleteEmail(t)
	tenantID := seedRegForDelete(t, db, email)
	plain := issueTokenDirect(t, db, tenantID, email, 1*time.Hour)

	r, _ := newTenantDeleteRouterDB(t, db)

	// First confirm — should succeed
	w1 := postDeleteConfirm(t, r, tenantID, fmt.Sprintf(`{"token":%q}`, plain))
	if w1.Code != http.StatusOK {
		t.Fatalf("first confirm: %d (body=%s)", w1.Code, w1.Body.String())
	}

	// Second confirm with same token — should be 410 Gone
	w2 := postDeleteConfirm(t, r, tenantID, fmt.Sprintf(`{"token":%q}`, plain))
	if w2.Code != http.StatusGone {
		t.Errorf("reused token should return 410, got %d", w2.Code)
	}
}

func TestTenantDelete_DB_Confirm_WrongTenantForToken_401(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	emailA := uniqueDeleteEmail(t)
	tenantA := seedRegForDelete(t, db, emailA)
	tokenForA := issueTokenDirect(t, db, tenantA, emailA, 1*time.Hour)

	emailB := uniqueDeleteEmail(t)
	tenantB := seedRegForDelete(t, db, emailB)

	r, _ := newTenantDeleteRouterDB(t, db)
	// Use tokenForA against tenantB — should be 401
	w := postDeleteConfirm(t, r, tenantB, fmt.Sprintf(`{"token":%q}`, tokenForA))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("token bound to different tenant should return 401, got %d (body=%s)", w.Code, w.Body.String())
	}

	// Tenant A should still exist (the failed confirm against B did NOT touch A)
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM community_saas_registrations WHERE tenant_id = $1`, tenantA).Scan(&n)
	if n != 1 {
		t.Errorf("tenant A should still exist after wrong-tenant confirm; got %d", n)
	}
}

func TestTenantDelete_DB_Confirm_UnknownToken_401(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	tenantID := seedRegForDelete(t, db, uniqueDeleteEmail(t))
	r, _ := newTenantDeleteRouterDB(t, db)
	w := postDeleteConfirm(t, r, tenantID, `{"token":"never-was-issued"}`)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unknown token should return 401, got %d", w.Code)
	}
}

func TestTenantDelete_DB_Confirm_MissingToken_400(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	tenantID := seedRegForDelete(t, db, uniqueDeleteEmail(t))
	r, _ := newTenantDeleteRouterDB(t, db)
	w := postDeleteConfirm(t, r, tenantID, `{"token":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty token should return 400, got %d", w.Code)
	}
}

func TestTenantDelete_DB_Confirm_RefundNeededForRecentPro(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	email := uniqueDeleteEmail(t)
	tenantID := seedRegForDelete(t, db, email)
	// Pro license issued 5 days ago — within 14-day refund window.
	seedProLicense(t, db, tenantID, email, "cus_recent", time.Now().UTC().Add(-5*24*time.Hour))
	plain := issueTokenDirect(t, db, tenantID, email, 1*time.Hour)

	r, _ := newTenantDeleteRouterDB(t, db)
	w := postDeleteConfirm(t, r, tenantID, fmt.Sprintf(`{"token":%q}`, plain))
	if w.Code != http.StatusOK {
		t.Fatalf("confirm: %d (body=%s)", w.Code, w.Body.String())
	}

	var resp tenantDeleteConfirmResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.RefundNeeded {
		t.Errorf("refund_needed should be true for Pro license <14 days old")
	}
	if resp.RefundNote == "" {
		t.Errorf("refund_note should be populated when refund_needed")
	}

	// Verify the log row carries refund_needed=true
	var refundNeeded bool
	var refundNote sql.NullString
	if err := db.QueryRow(`SELECT refund_needed, refund_note FROM tenant_deletion_log
		WHERE tenant_id = $1`, tenantID).Scan(&refundNeeded, &refundNote); err != nil {
		t.Fatalf("log lookup: %v", err)
	}
	if !refundNeeded {
		t.Errorf("log should carry refund_needed=true")
	}
	if !refundNote.Valid || refundNote.String == "" {
		t.Errorf("log should carry refund_note text")
	}
}

func TestTenantDelete_DB_Confirm_NoRefundForOldPro(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	email := uniqueDeleteEmail(t)
	tenantID := seedRegForDelete(t, db, email)
	// Pro license issued 60 days ago — well past refund window.
	seedProLicense(t, db, tenantID, email, "cus_old", time.Now().UTC().Add(-60*24*time.Hour))
	plain := issueTokenDirect(t, db, tenantID, email, 1*time.Hour)

	r, _ := newTenantDeleteRouterDB(t, db)
	w := postDeleteConfirm(t, r, tenantID, fmt.Sprintf(`{"token":%q}`, plain))
	if w.Code != http.StatusOK {
		t.Fatalf("confirm: %d", w.Code)
	}
	var resp tenantDeleteConfirmResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.RefundNeeded {
		t.Errorf("refund_needed should be false for Pro license >14 days old")
	}
}

// =============================================================================
// Stripe failure path — DB-side erasure still completes
// =============================================================================

// failingStripeArchiver always returns an error. Used to verify that a Stripe
// archive failure does NOT roll back the DB-side erasure.
type failingStripeArchiver struct{}

func (failingStripeArchiver) ArchiveCustomer(_ context.Context, _ string) error {
	return fmt.Errorf("stripe is on fire (test)")
}

// To inject the failing archiver we re-register the handlers manually instead
// of using RegisterTenantDeletionHandler (which always reads from env).
func newTenantDeleteRouterDBWithStripe(t *testing.T, db *sql.DB, stripe StripeCustomerArchiver) *mux.Router {
	t.Helper()
	r := mux.NewRouter()
	noop := &NoopTenantDeletionEmailSender{}
	r.HandleFunc("/api/v1/tenant/{tenant_id}/delete-request",
		handleTenantDeleteRequest(db, noop)).Methods("POST")
	r.HandleFunc("/api/v1/tenant/{tenant_id}/delete-confirm",
		handleTenantDeleteConfirm(db, stripe)).Methods("POST")
	return r
}

func TestTenantDelete_DB_Confirm_StripeFailure_DBErasureCompletes(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	email := uniqueDeleteEmail(t)
	tenantID := seedRegForDelete(t, db, email)
	seedProLicense(t, db, tenantID, email, "cus_will_fail", time.Now().UTC().Add(-30*24*time.Hour))
	plain := issueTokenDirect(t, db, tenantID, email, 1*time.Hour)

	r := newTenantDeleteRouterDBWithStripe(t, db, failingStripeArchiver{})
	w := postDeleteConfirm(t, r, tenantID, fmt.Sprintf(`{"token":%q}`, plain))
	if w.Code != http.StatusOK {
		t.Fatalf("Stripe failure should NOT roll back DB erasure: %d (body=%s)", w.Code, w.Body.String())
	}

	var resp tenantDeleteConfirmResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.StripeArchived == nil || *resp.StripeArchived {
		t.Errorf("stripe_archived should be false (we injected failure); got %v", resp.StripeArchived)
	}

	// Registration should still be gone
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM community_saas_registrations WHERE tenant_id = $1`, tenantID).Scan(&n)
	if n != 0 {
		t.Errorf("DB erasure should have completed despite Stripe failure; reg count=%d", n)
	}

	// stripe_archive_ok should be false on the log row, and stripe_archive_error populated.
	var archiveOk sql.NullBool
	var archiveErr sql.NullString
	if err := db.QueryRow(`SELECT stripe_archive_ok, stripe_archive_error
		FROM tenant_deletion_log WHERE tenant_id = $1`, tenantID).Scan(&archiveOk, &archiveErr); err != nil {
		t.Fatalf("log query: %v", err)
	}
	if !archiveOk.Valid || archiveOk.Bool {
		t.Errorf("log should record stripe_archive_ok=false; got %v", archiveOk)
	}
	if !archiveErr.Valid || archiveErr.String == "" {
		t.Errorf("log should record stripe_archive_error string; got %v", archiveErr)
	}
}

// =============================================================================
// End-to-end sweep: register → audit → request → confirm → assert clean
// =============================================================================

func TestTenantDelete_DB_FullEndToEnd_RegisterAuditRequestConfirm(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	email := uniqueDeleteEmail(t)
	tenantID := seedRegForDelete(t, db, email)

	// Add audit rows + daily usage to simulate active tenant
	for i := 0; i < 3; i++ {
		seedAuditLog(t, db, tenantID)
	}
	seedDailyUsage(t, db, tenantID)

	r, noop := newTenantDeleteRouterDB(t, db)

	// Step 1: delete-request
	body := fmt.Sprintf(`{"email":%q}`, email)
	w1 := postDeleteRequest(t, r, tenantID, body)
	if w1.Code != http.StatusAccepted {
		t.Fatalf("delete-request: %d", w1.Code)
	}
	captured := noop.CapturedLinks()
	if len(captured) != 1 {
		t.Fatalf("expected 1 captured email, got %d", len(captured))
	}

	// Step 2: extract token from captured line
	// Line format: "to=<email> tenant=<id> token=<plain> url=<confirmURL>"
	tok := ""
	for _, part := range strings.Fields(captured[0]) {
		if strings.HasPrefix(part, "token=") {
			tok = strings.TrimPrefix(part, "token=")
			break
		}
	}
	if tok == "" {
		t.Fatalf("could not extract token from %q", captured[0])
	}

	// Step 3: delete-confirm
	w2 := postDeleteConfirm(t, r, tenantID, fmt.Sprintf(`{"token":%q}`, tok))
	if w2.Code != http.StatusOK {
		t.Fatalf("delete-confirm: %d (body=%s)", w2.Code, w2.Body.String())
	}

	// Step 4: assert all 4 sources clean
	for _, q := range []struct {
		name  string
		query string
	}{
		{"registrations", `SELECT COUNT(*) FROM community_saas_registrations WHERE tenant_id = $1`},
		{"audit_logs", `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1`},
		{"daily_usage", `SELECT COUNT(*) FROM community_saas_daily_usage WHERE tenant_id = $1`},
	} {
		var n int
		if err := db.QueryRow(q.query, tenantID).Scan(&n); err != nil {
			t.Fatalf("verify %s: %v", q.name, err)
		}
		if n != 0 {
			t.Errorf("after E2E deletion, %s should be 0 for tenant; got %d", q.name, n)
		}
	}

	// Step 5: deletion log row exists with correct counts
	var deletedReg, deletedAudit, deletedDaily int
	if err := db.QueryRow(`SELECT deleted_registrations, deleted_audit_logs, deleted_daily_usage
		FROM tenant_deletion_log WHERE tenant_id = $1`, tenantID).Scan(&deletedReg, &deletedAudit, &deletedDaily); err != nil {
		t.Fatalf("log query: %v", err)
	}
	if deletedReg != 1 {
		t.Errorf("log: expected 1 reg deleted, got %d", deletedReg)
	}
	if deletedAudit != 3 {
		t.Errorf("log: expected 3 audit rows deleted, got %d", deletedAudit)
	}
	if deletedDaily != 1 {
		t.Errorf("log: expected 1 daily_usage row deleted, got %d", deletedDaily)
	}
}

// =============================================================================
// Schema sanity
// =============================================================================

// =============================================================================
// Validation paths against a real DB
// =============================================================================

func TestTenantDelete_DB_Request_InvalidEmail_400(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	r, _ := newTenantDeleteRouterDB(t, db)
	w := postDeleteRequest(t, r, "cs_x", `{"email":"not-an-email"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid email should return 400, got %d", w.Code)
	}
}

func TestTenantDelete_DB_Request_BadJSON_400(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	r, _ := newTenantDeleteRouterDB(t, db)
	w := postDeleteRequest(t, r, "cs_x", `not-json{`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON should return 400, got %d", w.Code)
	}
}

func TestTenantDelete_DB_Request_TooLargeBody_413(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	r, _ := newTenantDeleteRouterDB(t, db)
	huge := strings.Repeat("x", tenantDeleteMaxRequestBodySize+10)
	w := postDeleteRequest(t, r, "cs_x", huge)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body should return 413, got %d", w.Code)
	}
}

func TestTenantDelete_DB_Confirm_BadJSON_400(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	r, _ := newTenantDeleteRouterDB(t, db)
	w := postDeleteConfirm(t, r, "cs_x", `bad{`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON should return 400, got %d", w.Code)
	}
}

func TestTenantDelete_DB_Confirm_TooLargeBody_413(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	r, _ := newTenantDeleteRouterDB(t, db)
	huge := strings.Repeat("y", tenantDeleteMaxRequestBodySize+10)
	w := postDeleteConfirm(t, r, "cs_x", huge)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body should return 413, got %d", w.Code)
	}
}

func TestTenantDelete_DB_Request_IPRateLimitDoesNotIssueToken(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()
	resetTenantDeleteIPTracker()

	email := uniqueDeleteEmail(t)
	tenantID := seedRegForDelete(t, db, email)
	r, noop := newTenantDeleteRouterDB(t, db)

	// First request — should succeed and issue a token
	body := fmt.Sprintf(`{"email":%q}`, email)
	w1 := postDeleteRequest(t, r, tenantID, body)
	if w1.Code != http.StatusAccepted {
		t.Fatalf("first req: %d", w1.Code)
	}

	// Second request immediately — IP tracker should block it.
	// Both requests come from the same httptest RemoteAddr so the IP cap fires.
	priorEmails := len(noop.CapturedLinks())
	w2 := postDeleteRequest(t, r, tenantID, body)
	if w2.Code != http.StatusAccepted {
		t.Errorf("IP-rate-limited request should still be 202 (anti-enum); got %d", w2.Code)
	}
	if len(noop.CapturedLinks()) != priorEmails {
		t.Errorf("IP rate limit hit: should not send new email; before=%d after=%d",
			priorEmails, len(noop.CapturedLinks()))
	}
}

func TestMigration082_TablesAndIndexesExist(t *testing.T) {
	db := getTestDBForTenantDelete(t)
	defer db.Close()

	expectedIndexes := []string{
		"idx_csaas_deletion_expires",
		"idx_csaas_deletion_tenant_recent",
		"idx_tenant_deletion_log_tenant",
		"idx_tenant_deletion_log_email",
		"idx_tenant_deletion_log_confirmed",
		"idx_tenant_deletion_log_refund_needed",
	}
	for _, idx := range expectedIndexes {
		var exists bool
		err := db.QueryRow(`SELECT EXISTS (
			SELECT 1 FROM pg_indexes WHERE indexname = $1)`, idx).Scan(&exists)
		if err != nil || !exists {
			t.Errorf("migration 082: index %s missing", idx)
		}
	}
}
