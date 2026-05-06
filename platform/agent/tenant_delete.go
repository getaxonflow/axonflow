// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	logutil "axonflow/platform/shared/logger"
	"axonflow/platform/shared/secretenv"
)

// =============================================================================
// GDPR right-to-erasure: DELETE /api/v1/tenant/<id> (issue #1896)
// =============================================================================
//
// Two-step email-verified deletion flow that mirrors the W3 recovery design:
//
//   POST /api/v1/tenant/<id>/delete-request   { "email": "..." }   →  202 generic
//     - Always returns 202 with the same generic message (anti-enumeration:
//       caller cannot distinguish "tenant exists with that email" from
//       "tenant doesn't exist" or "email mismatch").
//     - On the happy path: writes a token row + sends a confirmation email
//       containing the plain token. Token is 32 random bytes URL-safe-base64-
//       encoded. Stored as HMAC-SHA256(token, server-pepper) hex.
//
//   POST /api/v1/tenant/<id>/delete-confirm   { "token": "..." }    →  200 / 401 / 403 / 410
//     - Atomic transaction: writes audit row to tenant_deletion_log, then
//       cascades DELETE across community_saas_registrations,
//       plugin_user_licenses, audit_logs, community_saas_daily_usage,
//       usage_events. Token consumed in same transaction (single-use).
//     - Best-effort Stripe customer archive AFTER commit. Failure here
//       does NOT roll back the DB deletion (per design — we must complete
//       the erasure on our side; Stripe followup is operator-driven).
//
// NEVER allow tenant_id-only deletion without email verification — defense
// against tenant enumeration + accidental wipes.

// Tenant-deletion flow constants.
const (
	// tenantDeleteTokenBytes is the number of random bytes for the confirm token.
	// 32 bytes = 256 bits of entropy. URL-safe-base64 encoded → 43 chars.
	tenantDeleteTokenBytes = 32

	// tenantDeleteTokenTTL is the lifetime of a delete-confirmation token.
	// 1 hour per the issue spec — long enough for the user to read the email
	// and click; short enough to limit exposure if the token leaks via inbox
	// compromise / referer.
	tenantDeleteTokenTTL = 1 * time.Hour

	// tenantDeleteIPLimit is the max delete-request POSTs per IP per minute.
	// Prevents spray attacks against many tenant_ids from one source.
	tenantDeleteIPLimit       = 1
	tenantDeleteIPLimitWindow = 1 * time.Minute

	// tenantDeleteTenantLimit caps delete-requests per tenant_id per hour
	// independent of IP. Even if an attacker has access to many IPs, they
	// can't keep spamming a specific tenant's email inbox.
	tenantDeleteTenantLimit       = 1
	tenantDeleteTenantLimitWindow = 1 * time.Hour

	// tenantDeleteDefaultBaseURL is used when AXONFLOW_DELETE_BASE_URL is unset.
	// Mirrors the W3 recovery default — same SaaS endpoint surface.
	tenantDeleteDefaultBaseURL = "https://try.getaxonflow.com"

	// tenantDeleteMaxRequestBodySize caps the inbound body size for both
	// delete-request and delete-confirm. Both bodies are tiny JSON.
	tenantDeleteMaxRequestBodySize = 4 * 1024 // 4KB

	// tenantDeleteRefundEligibilityDays — Stripe payment is refundable
	// within this many days. Pro v1 charges $9.99/90d; if the license was
	// issued <14 days ago, the refund window is still open and we mark
	// refund_needed=TRUE in the deletion log so ops can follow up.
	tenantDeleteRefundEligibilityDays = 14
)

// Tenant-deletion errors (typed for structured logging).
var (
	ErrTenantDeleteTokenNotFound    = fmt.Errorf("delete token not found")
	ErrTenantDeleteTokenExpired     = fmt.Errorf("delete token expired")
	ErrTenantDeleteTokenAlreadyUsed = fmt.Errorf("delete token already used")
	ErrTenantDeleteTenantMismatch   = fmt.Errorf("delete token does not match tenant")
)

// =============================================================================
// Per-IP / per-tenant rate-limit trackers (in-process, identical pattern to
// the registration IP tracker — same caveats apply: single-instance only,
// resets on restart, sufficient for the V1 SaaS plugin tier where the
// canonical rate-limit story is "abuse is rare; defense-in-depth here").
// =============================================================================

type tenantDeleteIPEntry struct {
	count     int
	resetTime time.Time
}

type tenantDeleteIPTracker struct {
	mu      sync.Mutex
	entries map[string]*tenantDeleteIPEntry
}

func (t *tenantDeleteIPTracker) check(ip string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()

	if len(t.entries) > ipTrackerMaxEntries {
		for k, v := range t.entries {
			if now.After(v.resetTime) {
				delete(t.entries, k)
			}
		}
	}

	entry, exists := t.entries[ip]
	if !exists || now.After(entry.resetTime) {
		t.entries[ip] = &tenantDeleteIPEntry{
			count:     1,
			resetTime: now.Add(tenantDeleteIPLimitWindow),
		}
		return nil
	}

	entry.count++
	if entry.count > tenantDeleteIPLimit {
		return fmt.Errorf("delete-request IP rate limit exceeded")
	}
	return nil
}

var tenantDeleteIPTrack = &tenantDeleteIPTracker{
	entries: make(map[string]*tenantDeleteIPEntry),
}

// resetTenantDeleteIPTracker clears in-process IP state. Test-only.
func resetTenantDeleteIPTracker() {
	tenantDeleteIPTrack.mu.Lock()
	tenantDeleteIPTrack.entries = make(map[string]*tenantDeleteIPEntry)
	tenantDeleteIPTrack.mu.Unlock()
}

// =============================================================================
// Request / response shapes
// =============================================================================

type tenantDeleteRequestBody struct {
	Email string `json:"email"`
}

type tenantDeleteRequestResponse struct {
	Message string `json:"message"`
}

type tenantDeleteConfirmBody struct {
	Token string `json:"token"`
}

type tenantDeleteConfirmResponse struct {
	Message    string `json:"message"`
	TenantID   string `json:"tenant_id"`
	DeletedAt  string `json:"deleted_at"`
	DeletedRows struct {
		Registrations int `json:"registrations"`
		Licenses      int `json:"licenses"`
		AuditLogs     int `json:"audit_logs"`
		DailyUsage    int `json:"daily_usage"`
		UsageEvents   int `json:"usage_events"`
	} `json:"deleted_rows"`
	StripeArchived *bool  `json:"stripe_archived,omitempty"` // nil = no Stripe customer
	RefundNeeded   bool   `json:"refund_needed"`
	RefundNote     string `json:"refund_note,omitempty"`
}

// =============================================================================
// Wire-up
// =============================================================================

// RegisterTenantDeletionHandler registers the GDPR right-to-erasure endpoints.
//
// Endpoints:
//
//	POST /api/v1/tenant/{tenant_id}/delete-request — issue confirmation token via email
//	POST /api/v1/tenant/{tenant_id}/delete-confirm — consume token + execute erasure
//
// All endpoints are intentionally NOT protected by apiAuthMiddleware — the
// caller may have already lost their auth credentials (which is exactly when
// they would need to invoke right-to-erasure). The auth proof is the
// single-use, short-lived token delivered to the email-on-file.
//
// The sender argument is the email transport — RecoveryEmailSender's interface
// is reused (we just send a different subject + body via the SendDeletionLink
// adapter on top of the same transport); if nil, reads from environment.
func RegisterTenantDeletionHandler(router *mux.Router, db *sql.DB, sender TenantDeletionEmailSender) {
	if sender == nil {
		sender = NewTenantDeletionEmailSenderFromEnv()
	}
	stripe := NewStripeCustomerArchiverFromEnv()

	router.HandleFunc("/api/v1/tenant/{tenant_id}/delete-request",
		handleTenantDeleteRequest(db, sender)).Methods("POST")
	router.HandleFunc("/api/v1/tenant/{tenant_id}/delete-confirm",
		handleTenantDeleteConfirm(db, stripe)).Methods("POST")

	// Reject other methods on the same paths so callers get a clear 405
	// instead of a 404 that suggests "this endpoint doesn't exist".
	router.HandleFunc("/api/v1/tenant/{tenant_id}/delete-request",
		methodNotAllowedJSON("Use POST to request a deletion confirmation email.")).
		Methods("GET", "PUT", "DELETE", "PATCH")
	router.HandleFunc("/api/v1/tenant/{tenant_id}/delete-confirm",
		methodNotAllowedJSON("Use POST to confirm deletion with the token from your email.")).
		Methods("GET", "PUT", "DELETE", "PATCH")
}

func methodNotAllowedJSON(msg string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, msg, http.StatusMethodNotAllowed)
	}
}

// =============================================================================
// POST /api/v1/tenant/{tenant_id}/delete-request
// =============================================================================
//
// Always returns 202 with the same generic message regardless of:
//   - tenant_id existence
//   - email match / mismatch
//   - rate-limit hit
//   - email send success / failure
//
// This is the anti-enumeration property: an attacker probing tenant_ids
// learns nothing from the response. Real conditions are logged server-side.
func handleTenantDeleteRequest(db *sql.DB, sender TenantDeletionEmailSender) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			writeJSONError(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}

		tenantID := strings.TrimSpace(mux.Vars(r)["tenant_id"])
		if tenantID == "" {
			writeJSONError(w, "Missing tenant_id in path", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, tenantDeleteMaxRequestBodySize+1))
		if err != nil {
			writeJSONError(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		if len(body) > tenantDeleteMaxRequestBodySize {
			writeJSONError(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		var req tenantDeleteRequestBody
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSONError(w, "Invalid JSON in request body", http.StatusBadRequest)
			return
		}
		email := strings.TrimSpace(strings.ToLower(req.Email))
		if !looksLikeEmail(email) {
			writeJSONError(w, "Invalid email", http.StatusBadRequest)
			return
		}

		// Per-IP rate limit. Failure still returns 202 (anti-enum).
		clientIP := extractClientIP(r)
		if err := tenantDeleteIPTrack.check(clientIP); err != nil {
			log.Printf("[TENANT-DELETE] IP rate limit exceeded for %s",
				logutil.Sanitize(clientIP))
			writeTenantDeleteGenericResponse(w)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Per-tenant rate limit (DB-backed): block if a recent token already exists.
		var recentCount int
		err = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM community_saas_deletion_tokens
			 WHERE tenant_id = $1 AND created_at > $2`,
			tenantID, time.Now().UTC().Add(-tenantDeleteTenantLimitWindow)).Scan(&recentCount)
		if err != nil {
			log.Printf("[TENANT-DELETE] DB rate-limit check failed for tenant %s: %v",
				logutil.Sanitize(tenantID), err)
			writeTenantDeleteGenericResponse(w)
			return
		}
		if recentCount >= tenantDeleteTenantLimit {
			log.Printf("[TENANT-DELETE] Per-tenant rate limit hit for %s (count=%d)",
				logutil.Sanitize(tenantID), recentCount)
			writeTenantDeleteGenericResponse(w)
			return
		}

		// Check whether the (tenant_id, email) pair exists. We don't reveal
		// the answer; only generate a token + email if it's a real match.
		var matched bool
		err = db.QueryRowContext(ctx,
			`SELECT EXISTS (
				SELECT 1 FROM community_saas_registrations
				WHERE tenant_id = $1
				  AND claimed_by_email = $2
				  AND terminated_at IS NULL
			 )`, tenantID, email).Scan(&matched)
		if err != nil {
			log.Printf("[TENANT-DELETE] DB lookup failed: %v", err)
			writeTenantDeleteGenericResponse(w)
			return
		}
		if !matched {
			log.Printf("[TENANT-DELETE] No matching tenant for %s + email — returning generic 202",
				logutil.Sanitize(tenantID))
			tenantDeleteRequestUnmatchedTotal.Inc()
			writeTenantDeleteGenericResponse(w)
			return
		}

		// Generate token + store HASH (HMAC-SHA256 with optional server pepper).
		tokenRaw := make([]byte, tenantDeleteTokenBytes)
		if _, err := rand.Read(tokenRaw); err != nil {
			log.Printf("[TENANT-DELETE] Failed to generate token: %v", err)
			writeTenantDeleteGenericResponse(w)
			return
		}
		token := base64.RawURLEncoding.EncodeToString(tokenRaw)
		tokenHash := hashTenantDeleteToken(token)

		ipHashBytes := sha256.Sum256([]byte(clientIP))
		ipHash := hex.EncodeToString(ipHashBytes[:])

		expiresAt := time.Now().UTC().Add(tenantDeleteTokenTTL)
		_, err = db.ExecContext(ctx,
			`INSERT INTO community_saas_deletion_tokens
			 (token_hash, tenant_id, email, requesting_ip_hash, expires_at)
			 VALUES ($1, $2, $3, $4, $5)`,
			tokenHash, tenantID, email, ipHash, expiresAt)
		if err != nil {
			log.Printf("[TENANT-DELETE] Failed to insert token for tenant %s: %v",
				logutil.Sanitize(tenantID), err)
			writeTenantDeleteGenericResponse(w)
			return
		}

		// Build confirmation URL the user pastes into a curl OR a confirm-page.
		// Unlike W3 recovery (where the URL clicks directly to a confirm page),
		// the deletion confirm path is intentionally programmatic:
		//   POST /api/v1/tenant/<id>/delete-confirm
		//   body: {"token": "..."}
		// Email contains both the curl command and the raw token so both
		// CLI users (most plugin users) and dashboard users can complete it.
		baseURL := os.Getenv("AXONFLOW_DELETE_BASE_URL")
		if baseURL == "" {
			baseURL = tenantDeleteDefaultBaseURL
		}
		confirmURL := fmt.Sprintf("%s/api/v1/tenant/%s/delete-confirm",
			strings.TrimRight(baseURL, "/"), url.PathEscape(tenantID))

		if sender != nil {
			if err := sender.SendDeletionLink(ctx, email, tenantID, token, confirmURL); err != nil {
				log.Printf("[TENANT-DELETE] Email send failed for %s: %v",
					logutil.Sanitize(email), err)
				tenantDeleteEmailFailuresTotal.WithLabelValues(senderTypeLabelTD(sender)).Inc()
			} else {
				tenantDeleteEmailSuccessTotal.WithLabelValues(senderTypeLabelTD(sender)).Inc()
			}
		}

		log.Printf("[TENANT-DELETE] Issued deletion token for tenant %s (email=%s, expires=%s)",
			logutil.Sanitize(tenantID), logutil.Sanitize(email), expiresAt.Format(time.RFC3339))
		writeTenantDeleteGenericResponse(w)
	}
}

// =============================================================================
// POST /api/v1/tenant/{tenant_id}/delete-confirm
// =============================================================================
//
// Status codes (PRECISE — these are tested explicitly):
//   - 200 OK            — deletion completed; body has counts + Stripe state
//   - 400 Bad Request   — malformed body / missing token
//   - 401 Unauthorized  — token doesn't exist OR doesn't match this tenant
//   - 410 Gone          — token expired OR already consumed (idempotency)
//   - 500               — DB / transaction failure
//
// The token row is consumed in the SAME transaction as the cascade DELETE.
// If anything in the cascade fails, the token UPDATE rolls back — so a
// failed confirm leaves the token still consumable for retry. Successful
// confirm is fully atomic: log row written, all 5 sources cleaned, token
// marked consumed, all in one commit.
func handleTenantDeleteConfirm(db *sql.DB, stripe StripeCustomerArchiver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			writeJSONError(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}

		tenantID := strings.TrimSpace(mux.Vars(r)["tenant_id"])
		if tenantID == "" {
			writeJSONError(w, "Missing tenant_id in path", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, tenantDeleteMaxRequestBodySize+1))
		if err != nil {
			writeJSONError(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		if len(body) > tenantDeleteMaxRequestBodySize {
			writeJSONError(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		var req tenantDeleteConfirmBody
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSONError(w, "Invalid JSON in request body", http.StatusBadRequest)
			return
		}
		token := strings.TrimSpace(req.Token)
		if token == "" {
			writeJSONError(w, "Missing token", http.StatusBadRequest)
			return
		}
		tokenHash := hashTenantDeleteToken(token)

		// 30-second timeout for the whole transaction. Cascade DELETEs across
		// audit_logs (potentially thousands of rows for an active tenant) +
		// indexed lookups across plugin_user_licenses + community_saas_daily_usage.
		// 30s is generous; the actual happy-path cost is sub-second.
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		// Pre-tx lookup of token row — gives us the bound tenant_id + email so
		// we can validate them against the path tenant_id BEFORE we open the tx.
		// Also lets us return 410 (Gone) for already-consumed without holding a tx.
		var bondTenantID, bondEmail string
		var requestedAt time.Time
		var expiresAt time.Time
		var consumedAt sql.NullTime
		err = db.QueryRowContext(ctx,
			`SELECT tenant_id, email, created_at, expires_at, consumed_at
			 FROM community_saas_deletion_tokens
			 WHERE token_hash = $1`, tokenHash).Scan(&bondTenantID, &bondEmail, &requestedAt, &expiresAt, &consumedAt)
		if err == sql.ErrNoRows {
			// 401: don't differentiate "wrong token" from "wrong tenant" — both
			// look the same to the caller. Anti-token-fishing.
			writeJSONError(w, "Invalid deletion token", http.StatusUnauthorized)
			return
		}
		if err != nil {
			log.Printf("[TENANT-DELETE-CONFIRM] DB lookup failed: %v", err)
			writeJSONError(w, "Failed to verify deletion token", http.StatusInternalServerError)
			return
		}

		if consumedAt.Valid {
			// 410 Gone: idempotent semantic. Same response for "already consumed"
			// AND "tenant already deleted on prior call".
			writeJSONError(w, "Deletion token has already been used", http.StatusGone)
			return
		}
		if time.Now().UTC().After(expiresAt) {
			writeJSONError(w, "Deletion token has expired", http.StatusGone)
			return
		}
		if bondTenantID != tenantID {
			// 401 (not 403) — same as "token not found" so an attacker can't
			// distinguish "tenant exists but wrong token" from "wrong tenant".
			log.Printf("[TENANT-DELETE-CONFIRM] Token-tenant mismatch (token bound to %s, request for %s)",
				logutil.Sanitize(bondTenantID), logutil.Sanitize(tenantID))
			writeJSONError(w, "Invalid deletion token", http.StatusUnauthorized)
			return
		}

		// Look up Stripe customer + active Pro license info for refund-needed flag.
		// Done outside the tx to keep tx short. (Worst case we read stale data
		// here — fine: the only consequence is the deletion log's refund_needed
		// flag is wrong, which is a logged operator review item not a data bug.)
		var stripeCustID sql.NullString
		var issuedAt sql.NullTime
		var refundNeeded bool
		var refundNote string
		err = db.QueryRowContext(ctx,
			`SELECT stripe_customer_id, issued_at
			 FROM plugin_user_licenses
			 WHERE tenant_id = $1
			   AND tier = 'Pro'
			   AND revoked_at IS NULL
			 ORDER BY issued_at DESC
			 LIMIT 1`, tenantID).Scan(&stripeCustID, &issuedAt)
		if err != nil && err != sql.ErrNoRows {
			// Non-fatal: log + proceed with no Stripe linkage.
			log.Printf("[TENANT-DELETE-CONFIRM] License lookup failed (non-fatal): %v", err)
		}
		if issuedAt.Valid {
			if time.Since(issuedAt.Time) <= time.Duration(tenantDeleteRefundEligibilityDays)*24*time.Hour {
				refundNeeded = true
				refundNote = fmt.Sprintf("Active Pro license issued at %s (within %d-day refund window). Manual Stripe refund required.",
					issuedAt.Time.UTC().Format(time.RFC3339), tenantDeleteRefundEligibilityDays)
				log.Printf("[TENANT-DELETE-CONFIRM] Refund-needed for tenant %s: %s",
					logutil.Sanitize(tenantID), refundNote)
			}
		}

		// =====================================================================
		// Atomic transaction: cascade DELETE + audit log + token consume.
		// =====================================================================
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			log.Printf("[TENANT-DELETE-CONFIRM] Failed to begin tx: %v", err)
			writeJSONError(w, "Failed to begin deletion", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback() }() // no-op after commit

		// Mark token consumed FIRST. RowsAffected MUST be 1 — if 0, another
		// confirm raced us between our SELECT and now.
		updateRes, err := tx.ExecContext(ctx,
			`UPDATE community_saas_deletion_tokens
			 SET consumed_at = NOW()
			 WHERE token_hash = $1 AND consumed_at IS NULL`, tokenHash)
		if err != nil {
			log.Printf("[TENANT-DELETE-CONFIRM] Failed to mark token consumed: %v", err)
			writeJSONError(w, "Failed to complete deletion", http.StatusInternalServerError)
			return
		}
		rowsAffected, err := updateRes.RowsAffected()
		if err != nil {
			log.Printf("[TENANT-DELETE-CONFIRM] RowsAffected failed: %v", err)
			writeJSONError(w, "Failed to complete deletion", http.StatusInternalServerError)
			return
		}
		if rowsAffected == 0 {
			log.Printf("[TENANT-DELETE-CONFIRM] Concurrent consume — token already used")
			writeJSONError(w, "Deletion token has already been used", http.StatusGone)
			return
		}

		// Cascade DELETEs. Order matters because plugin_user_licenses has a
		// foreign-key reference to community_saas_registrations.tenant_id —
		// children must be deleted before the parent or Postgres rejects the
		// parent DELETE with a constraint-violation error.
		// Order: licenses → audit_logs → daily_usage → usage_events → registration.
		// We use a per-table RowsAffected count for the audit log entry. Any
		// single DELETE failure rolls the entire transaction back.
		deletedLicenses, err := execDeleteCount(ctx, tx,
			`DELETE FROM plugin_user_licenses WHERE tenant_id = $1`, tenantID)
		if err != nil {
			log.Printf("[TENANT-DELETE-CONFIRM] Failed to delete licenses: %v", err)
			writeJSONError(w, "Failed to complete deletion", http.StatusInternalServerError)
			return
		}

		deletedAuditLogs, err := execDeleteCount(ctx, tx,
			`DELETE FROM audit_logs WHERE tenant_id = $1`, tenantID)
		if err != nil {
			log.Printf("[TENANT-DELETE-CONFIRM] Failed to delete audit_logs: %v", err)
			writeJSONError(w, "Failed to complete deletion", http.StatusInternalServerError)
			return
		}

		deletedDailyUsage, err := execDeleteCount(ctx, tx,
			`DELETE FROM community_saas_daily_usage WHERE tenant_id = $1`, tenantID)
		if err != nil {
			log.Printf("[TENANT-DELETE-CONFIRM] Failed to delete daily_usage: %v", err)
			writeJSONError(w, "Failed to complete deletion", http.StatusInternalServerError)
			return
		}

		// usage_events is keyed on org_id + client_id (per migration 081). For
		// community-saas the client_id IS the tenant_id, so target by client_id.
		// If the table was promoted but not yet populated (fresh stack), this
		// is a no-op — fine.
		deletedUsageEvents, err := execDeleteCount(ctx, tx,
			`DELETE FROM usage_events WHERE client_id = $1`, tenantID)
		if err != nil {
			log.Printf("[TENANT-DELETE-CONFIRM] Failed to delete usage_events: %v", err)
			writeJSONError(w, "Failed to complete deletion", http.StatusInternalServerError)
			return
		}

		// LAST: delete the registration row itself. Now safe — all FK children
		// above have been removed.
		deletedRegistrations, err := execDeleteCount(ctx, tx,
			`DELETE FROM community_saas_registrations WHERE tenant_id = $1`, tenantID)
		if err != nil {
			log.Printf("[TENANT-DELETE-CONFIRM] Failed to delete registrations: %v", err)
			writeJSONError(w, "Failed to complete deletion", http.StatusInternalServerError)
			return
		}

		// Pre-write the audit row (Stripe-archive-state filled in post-commit).
		_, err = tx.ExecContext(ctx,
			`INSERT INTO tenant_deletion_log
			 (tenant_id, email, deletion_token_jti, requested_at, confirmed_at,
			  deleted_registrations, deleted_licenses, deleted_audit_logs,
			  deleted_daily_usage, deleted_usage_events,
			  stripe_customer_id, refund_needed, refund_note)
			 VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7, $8, $9, $10, $11, $12)`,
			tenantID, bondEmail, tokenHash, requestedAt,
			deletedRegistrations, deletedLicenses, deletedAuditLogs,
			deletedDailyUsage, deletedUsageEvents,
			nullableString(stripeCustID), refundNeeded, refundNote)
		if err != nil {
			log.Printf("[TENANT-DELETE-CONFIRM] Failed to write deletion log: %v", err)
			writeJSONError(w, "Failed to complete deletion", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(); err != nil {
			log.Printf("[TENANT-DELETE-CONFIRM] Commit failed: %v", err)
			writeJSONError(w, "Failed to complete deletion", http.StatusInternalServerError)
			return
		}

		// Post-commit: best-effort Stripe customer archive. Failure here is
		// LOGGED but does NOT roll back our DB-side erasure — the user's data
		// is gone from our systems regardless. Operator follow-up (manual
		// archive in Stripe Dashboard) is captured by the deletion log.
		var stripeArchivedPtr *bool
		if stripeCustID.Valid && stripe != nil {
			archiveCtx, archiveCancel := context.WithTimeout(context.Background(), 10*time.Second)
			archiveErr := stripe.ArchiveCustomer(archiveCtx, stripeCustID.String)
			archiveCancel()

			ok := archiveErr == nil
			stripeArchivedPtr = &ok

			// Update the log row with the actual outcome. If this fails we
			// just log — the deletion itself succeeded.
			updateCtx, updateCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, upErr := db.ExecContext(updateCtx,
				`UPDATE tenant_deletion_log
				 SET stripe_archive_ok = $1, stripe_archive_error = $2
				 WHERE tenant_id = $3 AND deletion_token_jti = $4`,
				ok, nullableErrorString(archiveErr), tenantID, tokenHash)
			updateCancel()
			if upErr != nil {
				log.Printf("[TENANT-DELETE-CONFIRM] Failed to backfill stripe state on log: %v", upErr)
			}

			if archiveErr != nil {
				log.Printf("[TENANT-DELETE-CONFIRM] Stripe archive failed for cust=%s tenant=%s: %v (DB deletion still succeeded)",
					logutil.Sanitize(stripeCustID.String), logutil.Sanitize(tenantID), archiveErr)
				tenantDeleteStripeArchiveFailuresTotal.Inc()
			} else {
				tenantDeleteStripeArchiveSuccessTotal.Inc()
			}
		}

		log.Printf("[TENANT-DELETE-CONFIRM] Tenant %s erased: reg=%d lic=%d audit=%d daily=%d usage=%d refund_needed=%v",
			logutil.Sanitize(tenantID),
			deletedRegistrations, deletedLicenses, deletedAuditLogs,
			deletedDailyUsage, deletedUsageEvents, refundNeeded)
		tenantDeleteCompletedTotal.Inc()

		resp := tenantDeleteConfirmResponse{
			Message:   "Tenant deleted. All associated data has been removed from our systems per GDPR Article 17.",
			TenantID:  tenantID,
			DeletedAt: time.Now().UTC().Format(time.RFC3339),
			StripeArchived: stripeArchivedPtr,
			RefundNeeded:   refundNeeded,
			RefundNote:     refundNote,
		}
		resp.DeletedRows.Registrations = deletedRegistrations
		resp.DeletedRows.Licenses = deletedLicenses
		resp.DeletedRows.AuditLogs = deletedAuditLogs
		resp.DeletedRows.DailyUsage = deletedDailyUsage
		resp.DeletedRows.UsageEvents = deletedUsageEvents

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("[TENANT-DELETE-CONFIRM] Failed to encode response: %v", err)
		}
	}
}

// execDeleteCount runs a parameterized DELETE inside the transaction and
// returns the RowsAffected count. Used so we can populate the per-table
// counts on the deletion log without copy-pasting err-handling 5 times.
func execDeleteCount(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) (int, error) {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// =============================================================================
// Helpers
// =============================================================================

// hashTenantDeleteToken returns a HMAC-SHA256 hex digest of the token using
// the server-side pepper from AXONFLOW_TENANT_DELETE_TOKEN_PEPPER (or a
// build-time fallback constant if unset — the fallback is intentionally
// non-empty so the hash is deterministic in dev/test, and DIFFERENT from the
// prod pepper so a leaked test DB can't be replayed against prod).
func hashTenantDeleteToken(token string) string {
	pepper := secretenv.Get("AXONFLOW_TENANT_DELETE_TOKEN_PEPPER")
	if pepper == "" {
		// Test/dev fallback. Production stacks set this via SM.
		pepper = "axonflow-tenant-delete-default-pepper-v1"
	}
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

// writeTenantDeleteGenericResponse writes the same 202 response regardless
// of branch — anti-enumeration property.
func writeTenantDeleteGenericResponse(w http.ResponseWriter) {
	resp := tenantDeleteRequestResponse{
		Message: "If a tenant matching this id and email exists, a deletion-confirmation email will be sent to the registered address within a few minutes. The link expires in 1 hour.",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(resp)
}

func nullableString(v sql.NullString) interface{} {
	if v.Valid {
		return v.String
	}
	return nil
}

func nullableErrorString(err error) interface{} {
	if err == nil {
		return nil
	}
	return err.Error()
}

// =============================================================================
// Prometheus metrics
// =============================================================================

var (
	tenantDeleteRequestUnmatchedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "axonflow_tenant_delete_request_unmatched_total",
		Help: "Number of delete-request POSTs where (tenant_id, email) did not match an active registration. Driven by anti-enum 202 responses; high values signal a probing campaign.",
	})

	tenantDeleteCompletedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "axonflow_tenant_delete_completed_total",
		Help: "Number of successful tenant erasures (POST delete-confirm 200).",
	})

	tenantDeleteEmailFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "axonflow_tenant_delete_email_failures_total",
		Help: "Tenant-deletion confirmation email send failures, labeled by sender type.",
	}, []string{"sender"})

	tenantDeleteEmailSuccessTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "axonflow_tenant_delete_email_success_total",
		Help: "Tenant-deletion confirmation email sends that succeeded, labeled by sender type.",
	}, []string{"sender"})

	tenantDeleteStripeArchiveSuccessTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "axonflow_tenant_delete_stripe_archive_success_total",
		Help: "Stripe customer archive API calls that succeeded after a successful tenant deletion.",
	})

	tenantDeleteStripeArchiveFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "axonflow_tenant_delete_stripe_archive_failures_total",
		Help: "Stripe customer archive API calls that failed (DB-side deletion still succeeded; operator follow-up needed).",
	})
)

// senderTypeLabelTD is the tenant-deletion sender-type labelizer. Mirrors
// senderTypeLabel for recovery.
func senderTypeLabelTD(s TenantDeletionEmailSender) string {
	switch s.(type) {
	case *NoopTenantDeletionEmailSender:
		return "noop"
	case *ResendTenantDeletionEmailSender:
		return "resend"
	default:
		return "unknown"
	}
}
