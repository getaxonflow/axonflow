// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/crypto/bcrypt"

	logutil "axonflow/platform/shared/logger"
)

// Recovery flow constants.
const (
	// recoveryTokenBytes is the number of random bytes for the magic-link token.
	// 32 bytes = 256 bits of entropy, hex-encoded to 64 chars in the URL.
	recoveryTokenBytes = 32

	// recoveryTokenTTL is how long a magic link is valid before expiry.
	// 15 minutes balances "user has time to check email" against
	// "shorter exposure if token leaks via referer/proxy/inbox compromise".
	recoveryTokenTTL = 15 * time.Minute

	// recoveryEmailRateLimit is the max recovery requests per email per hour.
	// Prevents magic-link spam attacks where an attacker repeatedly requests
	// recovery for someone else's email.
	recoveryEmailRateLimit = 5

	// recoveryEmailRateLimitWindow is the time window for the per-email rate limit.
	recoveryEmailRateLimitWindow = 1 * time.Hour

	// recoveryMaxTenantsPerEmail enforces the app-level cap on email-bound tenants
	// per ADR-049 section 4. Cap is intentionally low for v1; easy to raise.
	recoveryMaxTenantsPerEmail = 3

	// recoveryDefaultRecoverEndpoint is the path used when AXONFLOW_RECOVERY_BASE_URL
	// is not set. The full URL is BASE_URL + "/api/v1/recover/verify?token=..."
	recoveryDefaultBaseURL = "https://try.getaxonflow.com"
)

// Recovery flow errors (typed for structured logging).
var (
	ErrRecoveryEmailNotFound     = errors.New("no tenant bound to this email")
	ErrRecoveryRateLimit         = errors.New("recovery request rate limit exceeded")
	ErrRecoveryTokenNotFound     = errors.New("recovery token not found")
	ErrRecoveryTokenExpired      = errors.New("recovery token expired")
	ErrRecoveryTokenAlreadyUsed  = errors.New("recovery token already used")
	ErrRecoveryEmailMismatch     = errors.New("recovery email does not match token")
	ErrRecoveryTenantCapExceeded = errors.New("max active tenants per email reached")
)

// recoveryRequestBody is the JSON request body for POST /api/v1/recover.
type recoveryRequestBody struct {
	Email string `json:"email"`
}

// recoveryRequestResponse is the JSON response returned by POST /api/v1/recover.
// Intentionally always returns 202 with the same generic message regardless of
// whether the email matched a tenant — this prevents email enumeration attacks.
type recoveryRequestResponse struct {
	Message string `json:"message"`
}

// recoveryVerifyResponse is the JSON response returned by GET /api/v1/recover/verify.
// Returns NEW credentials bound to the same email; the previous tenant_id
// remains in the DB but is now orphaned (audit history under the old tenant_id
// stays accessible via the read tools as long as it falls within retention).
type recoveryVerifyResponse struct {
	TenantID     string `json:"tenant_id"`
	Secret       string `json:"secret"`
	SecretPrefix string `json:"secret_prefix"`
	ExpiresAt    string `json:"expires_at"`
	Endpoint     string `json:"endpoint"`
	Email        string `json:"email"`
	Note         string `json:"note"`
}

// RegisterCommunityRecoveryHandler wires the W3 recovery endpoints onto the router.
// Endpoints:
//
//	POST /api/v1/recover         — request a magic link for a given email
//	GET  /api/v1/recover/verify  — show HTML confirmation page (NO state change;
//	                                safe for email-link prefetchers like Outlook
//	                                SafeLinks, Slack unfurlers, Gmail previewers
//	                                that fetch links automatically)
//	POST /api/v1/recover/verify  — actually consume the token (state-changing)
//
// All three endpoints are intentionally NOT protected by apiAuthMiddleware —
// they are the recovery path for users who have lost their auth credentials.
//
// The sender argument is the email transport (Resend in production, Noop in tests).
// If nil, the function reads from environment via NewRecoveryEmailSenderFromEnv.
//
// PR-B race fix: sender is captured into each handler closure rather than stored
// in a package-level var, so concurrent registration calls (e.g. tests + production
// wiring) cannot race on the sender pointer.
func RegisterCommunityRecoveryHandler(router *mux.Router, db *sql.DB, sender RecoveryEmailSender) {
	if sender == nil {
		sender = NewRecoveryEmailSenderFromEnv()
	}

	router.HandleFunc("/api/v1/recover", handleRecoveryRequest(db, sender)).Methods("POST")
	router.HandleFunc("/api/v1/recover/verify", handleRecoveryConfirmPage(db)).Methods("GET")
	router.HandleFunc("/api/v1/recover/verify", handleRecoveryVerify(db)).Methods("POST")

	// Reject other methods on these paths with a clear 405
	router.HandleFunc("/api/v1/recover", func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, "Method not allowed. Use POST to request a recovery link.", http.StatusMethodNotAllowed)
	}).Methods("GET", "PUT", "DELETE", "PATCH")
	router.HandleFunc("/api/v1/recover/verify", func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, "Method not allowed. Use GET to confirm or POST to consume.", http.StatusMethodNotAllowed)
	}).Methods("PUT", "DELETE", "PATCH")
}

// handleRecoveryRequest handles POST /api/v1/recover.
// Always returns 202 with a generic message regardless of whether the email
// matched a tenant — prevents email enumeration. Real failures are only logged
// server-side, never returned to the client.
//
// PR-B race fix: sender is captured by closure rather than read from a package
// var, so concurrent registrations are race-free.
func handleRecoveryRequest(db *sql.DB, sender RecoveryEmailSender) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			writeJSONError(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize+1))
		if err != nil {
			writeJSONError(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		if len(body) > maxRequestBodySize {
			writeJSONError(w, fmt.Sprintf("Request body too large (max %d bytes)", maxRequestBodySize), http.StatusRequestEntityTooLarge)
			return
		}

		var req recoveryRequestBody
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSONError(w, "Invalid JSON in request body", http.StatusBadRequest)
			return
		}

		email := strings.TrimSpace(strings.ToLower(req.Email))
		if !looksLikeEmail(email) {
			writeJSONError(w, "Invalid email", http.StatusBadRequest)
			return
		}

		// IP-based rate limit on the recovery endpoint itself (anti-spam,
		// independent from per-email rate limit which is checked next)
		clientIP := extractClientIP(r)
		if err := regIPTracker.check(clientIP); err != nil {
			log.Printf("[CSAAS-RECOVERY] IP rate limit exceeded for %s", logutil.Sanitize(clientIP))
			// Still return 202 to avoid exposing the per-IP cap to enumeration probes
			writeRecoveryGenericResponse(w)
			return
		}

		// Per-email rate limit: count recovery tokens issued for this email in the
		// last hour. If above the cap, log and return generic 202.
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		var recentCount int
		err = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM community_saas_recovery_tokens
			 WHERE email = $1 AND created_at > $2`,
			email, time.Now().UTC().Add(-recoveryEmailRateLimitWindow)).Scan(&recentCount)
		if err != nil {
			log.Printf("[CSAAS-RECOVERY] DB query failed for rate-limit check: %v", err)
			writeRecoveryGenericResponse(w)
			return
		}
		if recentCount >= recoveryEmailRateLimit {
			log.Printf("[CSAAS-RECOVERY] Per-email rate limit hit for %s (count=%d)",
				logutil.Sanitize(email), recentCount)
			writeRecoveryGenericResponse(w)
			return
		}

		// Look up whether ANY tenant exists for this email. We don't reveal the
		// answer in the response — but we only generate a token + send email if
		// the email actually corresponds to a real tenant.
		var tenantExists bool
		err = db.QueryRowContext(ctx,
			`SELECT EXISTS (
				SELECT 1 FROM community_saas_registrations
				WHERE claimed_by_email = $1
				  AND terminated_at IS NULL
				  AND disabled_at IS NULL
			 )`, email).Scan(&tenantExists)
		if err != nil {
			log.Printf("[CSAAS-RECOVERY] DB query failed for email lookup: %v", err)
			writeRecoveryGenericResponse(w)
			return
		}

		if !tenantExists {
			log.Printf("[CSAAS-RECOVERY] Recovery requested for unknown email %s (returning generic 202)",
				logutil.Sanitize(email))
			writeRecoveryGenericResponse(w)
			return
		}

		// Generate magic-link token and store HASH (not plain) in DB
		tokenRaw := make([]byte, recoveryTokenBytes)
		if _, err := rand.Read(tokenRaw); err != nil {
			log.Printf("[CSAAS-RECOVERY] Failed to generate token: %v", err)
			writeRecoveryGenericResponse(w)
			return
		}
		token := hex.EncodeToString(tokenRaw)
		tokenHash := hashRecoveryToken(token)

		// Hash the requesting IP for audit (privacy-preserving)
		ipHashBytes := sha256.Sum256([]byte(clientIP))
		ipHash := hex.EncodeToString(ipHashBytes[:])

		expiresAt := time.Now().UTC().Add(recoveryTokenTTL)
		_, err = db.ExecContext(ctx,
			`INSERT INTO community_saas_recovery_tokens
			 (token_hash, email, requesting_ip_hash, expires_at)
			 VALUES ($1, $2, $3, $4)`,
			tokenHash, email, ipHash, expiresAt)
		if err != nil {
			log.Printf("[CSAAS-RECOVERY] Failed to insert recovery token: %v", err)
			writeRecoveryGenericResponse(w)
			return
		}

		// Build the magic link and send email
		baseURL := os.Getenv("AXONFLOW_RECOVERY_BASE_URL")
		if baseURL == "" {
			baseURL = recoveryDefaultBaseURL
		}
		magicLink := fmt.Sprintf("%s/api/v1/recover/verify?token=%s", strings.TrimRight(baseURL, "/"), url.QueryEscape(token))

		if sender != nil {
			if err := sender.SendRecoveryLink(ctx, email, magicLink); err != nil {
				log.Printf("[CSAAS-RECOVERY] Failed to send recovery email to %s: %v",
					logutil.Sanitize(email), err)
				// Increment metric so ops can alert on the silent-failure mode.
				// Anti-enumeration property still holds (response is the same
				// generic 202 regardless), but operators can see the failure rate
				// in Prometheus / Grafana and alert when it crosses a threshold.
				recoveryEmailFailuresTotal.WithLabelValues(senderTypeLabel(sender)).Inc()
			} else {
				recoveryEmailSuccessTotal.WithLabelValues(senderTypeLabel(sender)).Inc()
			}
		}

		log.Printf("[CSAAS-RECOVERY] Issued recovery token for %s (expires %s)",
			logutil.Sanitize(email), expiresAt.Format(time.RFC3339))
		writeRecoveryGenericResponse(w)
	}
}

// handleRecoveryVerify handles POST /api/v1/recover/verify.
// Exchanges a valid (unexpired, unconsumed) magic-link token for a fresh
// tenant_id + secret bound to the same email. Marks the token as consumed
// atomically so it cannot be replayed.
//
// PR-B: GET → POST split. POST is the only state-changing path for the
// token. The GET handler at the same URL renders an HTML confirmation page
// without consuming the token — safe for email-link prefetchers.
//
// Token can be sent as either:
//   - form-urlencoded body: `token=...` (when the user clicks Confirm on the
//     HTML page rendered by the GET handler)
//   - JSON body: `{"token": "..."}` (when called programmatically by a
//     plugin's --recover CLI flow or an SDK)
//
// Response is JSON (recoveryVerifyResponse) on success, JSON error on failure.
// HTML rendering of the JSON response on the post-confirm page is the browser's
// job (the form's POST receives JSON; in v1 we render it minimally; future
// polish in axonflow-billing).
func handleRecoveryVerify(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			writeJSONError(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}

		// Accept token from either form body (HTML form submit from the
		// confirmation page) or JSON body (programmatic plugin call).
		token := ""
		ct := r.Header.Get("Content-Type")
		if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			if err := r.ParseForm(); err != nil {
				writeJSONError(w, "Failed to parse form body", http.StatusBadRequest)
				return
			}
			token = r.FormValue("token")
		} else if strings.HasPrefix(ct, "application/json") || ct == "" {
			body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize+1))
			if err != nil {
				writeJSONError(w, "Failed to read request body", http.StatusBadRequest)
				return
			}
			if len(body) > maxRequestBodySize {
				writeJSONError(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			if len(body) > 0 {
				var jb struct {
					Token string `json:"token"`
				}
				if err := json.Unmarshal(body, &jb); err != nil {
					writeJSONError(w, "Invalid JSON in request body", http.StatusBadRequest)
					return
				}
				token = jb.Token
			}
		} else {
			writeJSONError(w, "Content-Type must be application/json or application/x-www-form-urlencoded", http.StatusUnsupportedMediaType)
			return
		}
		if token == "" {
			writeJSONError(w, "Missing token", http.StatusBadRequest)
			return
		}
		tokenHash := hashRecoveryToken(token)

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Look up the token row
		var email string
		var expiresAt time.Time
		var consumedAt sql.NullTime
		err := db.QueryRowContext(ctx,
			`SELECT email, expires_at, consumed_at
			 FROM community_saas_recovery_tokens
			 WHERE token_hash = $1`, tokenHash).Scan(&email, &expiresAt, &consumedAt)
		if err == sql.ErrNoRows {
			writeJSONError(w, "Invalid or expired recovery token", http.StatusUnauthorized)
			return
		}
		if err != nil {
			log.Printf("[CSAAS-RECOVERY-VERIFY] DB lookup failed: %v", err)
			writeJSONError(w, "Failed to verify recovery token", http.StatusInternalServerError)
			return
		}

		if consumedAt.Valid {
			writeJSONError(w, "Recovery token has already been used", http.StatusUnauthorized)
			return
		}
		if time.Now().UTC().After(expiresAt) {
			writeJSONError(w, "Invalid or expired recovery token", http.StatusUnauthorized)
			return
		}

		// Generate fresh credentials for the new tenant (outside the tx since
		// rand + bcrypt are expensive and don't need transactional scope)
		secretRaw := make([]byte, secretBytes)
		if _, err := rand.Read(secretRaw); err != nil {
			log.Printf("[CSAAS-RECOVERY-VERIFY] Failed to generate secret: %v", err)
			writeJSONError(w, "Internal error during recovery", http.StatusInternalServerError)
			return
		}
		secret := hex.EncodeToString(secretRaw)
		secretPrefix := secret[:8]

		hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcryptCost)
		if err != nil {
			log.Printf("[CSAAS-RECOVERY-VERIFY] Failed to hash secret: %v", err)
			writeJSONError(w, "Internal error during recovery", http.StatusInternalServerError)
			return
		}

		// Atomic SERIALIZABLE transaction containing:
		//   1. Per-email cap check (was outside-tx in pre-fix → TOCTOU race)
		//   2. Token consume UPDATE (with RowsAffected check to detect concurrent verify)
		//   3. New registration INSERT
		// All three roll back together on any failure; SERIALIZABLE isolation makes
		// Postgres detect concurrent races on the same email and abort one transaction.
		tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			log.Printf("[CSAAS-RECOVERY-VERIFY] Failed to start transaction: %v", err)
			writeJSONError(w, "Internal error during recovery", http.StatusInternalServerError)
			return
		}
		defer func() {
			_ = tx.Rollback() // no-op if already committed
		}()

		// Per-email tenant cap check INSIDE the transaction.
		// SERIALIZABLE isolation prevents two concurrent verifies for the same email
		// from both seeing count<cap and both inserting → cap exceeded.
		var activeTenants int
		err = tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM community_saas_registrations
			 WHERE claimed_by_email = $1
			   AND terminated_at IS NULL
			   AND disabled_at IS NULL
			   AND expires_at > NOW()`, email).Scan(&activeTenants)
		if err != nil {
			log.Printf("[CSAAS-RECOVERY-VERIFY] DB count failed: %v", err)
			writeJSONError(w, "Failed to verify recovery token", http.StatusInternalServerError)
			return
		}
		if activeTenants >= recoveryMaxTenantsPerEmail {
			log.Printf("[CSAAS-RECOVERY-VERIFY] Email %s already has %d active tenants — cap reached",
				logutil.Sanitize(email), activeTenants)
			writeJSONError(w,
				fmt.Sprintf("Max %d active tenants per email reached. Use one of your existing tenants or contact support.", recoveryMaxTenantsPerEmail),
				http.StatusForbidden)
			return
		}

		// Mark token consumed FIRST (before INSERT so we lock out concurrent verifies).
		// RowsAffected MUST equal 1 — if 0, another concurrent verify already
		// consumed this token between our SELECT and now. Roll back our work so
		// only one verify wins and only one new tenant is created.
		updateRes, err := tx.ExecContext(ctx,
			`UPDATE community_saas_recovery_tokens
			 SET consumed_at = NOW()
			 WHERE token_hash = $1 AND consumed_at IS NULL`,
			tokenHash)
		if err != nil {
			log.Printf("[CSAAS-RECOVERY-VERIFY] Failed to mark token consumed: %v", err)
			writeJSONError(w, "Failed to complete recovery", http.StatusInternalServerError)
			return
		}
		rowsAffected, err := updateRes.RowsAffected()
		if err != nil {
			log.Printf("[CSAAS-RECOVERY-VERIFY] Failed to read rows affected: %v", err)
			writeJSONError(w, "Failed to complete recovery", http.StatusInternalServerError)
			return
		}
		if rowsAffected == 0 {
			log.Printf("[CSAAS-RECOVERY-VERIFY] Token already consumed by concurrent request (race avoided)")
			writeJSONError(w, "Recovery token has already been used", http.StatusUnauthorized)
			return
		}

		// Generate new tenant_id with PK retry (same pattern as registration)
		var newTenantID string
		expiresAtNew := time.Now().UTC().Add(communitySaasRegistrationTTL)
		var insertErr error
		for attempt := 0; attempt < communitySaasMaxRegistrationRetries; attempt++ {
			newTenantID = communitySaasTenantPrefix + uuidNewString()
			// v9 Phase 6: org_id = per-customer cs_<uuid>; see auth.go and
			// community_saas_register.go for rationale (ADR-052 §"Community-SaaS").
			// Also write client_id to match the fresh-registration INSERT shape
			// (community_saas_register.go writes both); pre-Phase-6 this path
			// silently skipped client_id, leaving the column NULL on recovered
			// rows — same partial-unique-index defeat that PR #2246 closed for
			// the fresh-registration path. Phase 6 closes the recovery-side gap.
			// v9 Phase 8 PR-A (mig 109): route through csaas_recovery_insert
			// SECURITY DEFINER helper so the INSERT bypasses FORCE RLS (mig
			// 105) — recovery-verify mints the tenant_id in this very tx, so
			// there's no pre-existing GUC to set. PK-collision retry still
			// works: the helper re-RAISEs SQLSTATE 23505 unchanged.
			_, insertErr = tx.ExecContext(ctx,
				`SELECT csaas_recovery_insert($1, $2, $3, $4, $5, $6)`,
				newTenantID, string(hash), secretPrefix,
				"recovery for "+email, expiresAtNew, email)
			if insertErr == nil {
				break
			}
			if !isUniqueViolation(insertErr) {
				log.Printf("[CSAAS-RECOVERY-VERIFY] Failed to insert recovered tenant %s: %v",
					logutil.Sanitize(newTenantID), insertErr)
				writeJSONError(w, "Failed to create recovered tenant", http.StatusInternalServerError)
				return
			}
			log.Printf("[CSAAS-RECOVERY-VERIFY] PK collision on tenant_id %s (attempt %d/%d)",
				logutil.Sanitize(newTenantID), attempt+1, communitySaasMaxRegistrationRetries)
		}
		if insertErr != nil {
			log.Printf("[CSAAS-RECOVERY-VERIFY] Exhausted UUID retries — surfacing 500")
			writeJSONError(w, "Failed to create recovered tenant", http.StatusInternalServerError)
			return
		}

		// Backfill consumed_by_tenant now that we have the new tenant_id.
		_, err = tx.ExecContext(ctx,
			`UPDATE community_saas_recovery_tokens
			 SET consumed_by_tenant = $1
			 WHERE token_hash = $2`,
			newTenantID, tokenHash)
		if err != nil {
			log.Printf("[CSAAS-RECOVERY-VERIFY] Failed to set consumed_by_tenant: %v", err)
			writeJSONError(w, "Failed to complete recovery", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(); err != nil {
			log.Printf("[CSAAS-RECOVERY-VERIFY] Failed to commit recovery transaction: %v", err)
			writeJSONError(w, "Failed to complete recovery", http.StatusInternalServerError)
			return
		}

		// Register in tenants table synchronously (same pattern as fresh registration).
		// v9 Phase 6: org_id = per-customer cs_<uuid>; tier+max_nodes match the
		// 094 backfill seed so register_org's ON CONFLICT UPDATE never fires a
		// silent downgrade. See community_saas_register.go for rationale.
		registerTenantAndOrg(db, newTenantID, newTenantID, csaasOrgTier, csaasOrgMaxNodes)

		log.Printf("[CSAAS-RECOVERY-VERIFY] Recovered tenant %s for email %s (expires %s)",
			logutil.Sanitize(newTenantID), logutil.Sanitize(email), expiresAtNew.Format(time.RFC3339))

		resp := recoveryVerifyResponse{
			TenantID:     newTenantID,
			Secret:       secret,
			SecretPrefix: secretPrefix,
			ExpiresAt:    expiresAtNew.Format(time.RFC3339),
			Endpoint:     communitySaasTryEndpoint,
			Email:        email,
			Note:         "Recovery successful. Save these credentials — the secret is shown only once.",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("[CSAAS-RECOVERY-VERIFY] Failed to encode response: %v", err)
		}
	}
}

// =============================================================================
// PR-B: Prometheus metrics for recovery email send observability
// =============================================================================

// recoveryEmailFailuresTotal counts magic-link email send failures.
// Labeled by sender type (resend / noop / future ses) so ops can correlate
// failures with provider issues. Anti-enumeration design returns 202 generic
// to the requester regardless of send outcome — this metric is the ONLY
// signal ops has that recovery emails are failing.
//
// Suggested alert (Grafana / Prometheus): rate(recoveryEmailFailuresTotal[5m])
// > 0.1 for 10m → page on-call. Email is the only recovery path users have;
// silent failure means users can't recover.
var recoveryEmailFailuresTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_recovery_email_send_failures_total",
		Help: "Total magic-link recovery email send failures, labeled by sender type.",
	},
	[]string{"sender"},
)

// recoveryEmailSuccessTotal is the success counterpart. Together with
// recoveryEmailFailuresTotal they enable the failure-rate alert
// (failures / (failures + success)). Without the success counter, a 100%
// failure rate during low-traffic periods looks identical to no traffic.
var recoveryEmailSuccessTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_recovery_email_send_success_total",
		Help: "Total magic-link recovery email sends that succeeded, labeled by sender type.",
	},
	[]string{"sender"},
)

// senderTypeLabel returns the Prometheus label value for the email sender's
// concrete type. Used to attribute failures to the right provider.
func senderTypeLabel(s RecoveryEmailSender) string {
	switch s.(type) {
	case *NoopRecoveryEmailSender:
		return "noop"
	case *ResendRecoveryEmailSender:
		return "resend"
	default:
		return "unknown"
	}
}

// =============================================================================
// PR-B: GET handler for confirmation page (NO state change)
// =============================================================================

// handleRecoveryConfirmPage handles GET /api/v1/recover/verify?token=...
// Returns an HTML confirmation page with a "Confirm Recovery" button that
// POSTs the token. NO state change — safe to be fetched by email-link
// prefetchers (Outlook SafeLinks, Slack unfurlers, Gmail link previewers).
//
// The actual token consumption happens in the POST handler triggered by the
// user clicking the form submit button — that requires explicit user intent
// and cannot be triggered by passive prefetch.
//
// On token-invalid (not found, expired, already consumed): renders an error
// page rather than the confirmation page. We don't want to confuse users by
// showing them a "Confirm Recovery" button for a token that's no good.
func handleRecoveryConfirmPage(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			renderConfirmErrorPage(w, http.StatusServiceUnavailable, "Service temporarily unavailable")
			return
		}

		token := r.URL.Query().Get("token")
		if token == "" {
			renderConfirmErrorPage(w, http.StatusBadRequest, "Missing token in URL")
			return
		}
		tokenHash := hashRecoveryToken(token)

		// Validate the token exists, hasn't expired, hasn't been consumed.
		// All of this is read-only — no state change.
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		var email string
		var expiresAt time.Time
		var consumedAt sql.NullTime
		err := db.QueryRowContext(ctx,
			`SELECT email, expires_at, consumed_at
			 FROM community_saas_recovery_tokens
			 WHERE token_hash = $1`, tokenHash).Scan(&email, &expiresAt, &consumedAt)
		if err == sql.ErrNoRows {
			renderConfirmErrorPage(w, http.StatusUnauthorized,
				"Invalid recovery link. Request a new one at the AxonFlow recovery page.")
			return
		}
		if err != nil {
			log.Printf("[CSAAS-RECOVERY-CONFIRM] DB lookup failed: %v", err)
			renderConfirmErrorPage(w, http.StatusInternalServerError, "Failed to verify recovery link")
			return
		}
		if consumedAt.Valid {
			renderConfirmErrorPage(w, http.StatusUnauthorized,
				"This recovery link has already been used. Request a new one if you still need to recover.")
			return
		}
		if time.Now().UTC().After(expiresAt) {
			renderConfirmErrorPage(w, http.StatusUnauthorized,
				"This recovery link has expired. Request a new one to recover your tenant.")
			return
		}

		renderConfirmPage(w, token, email)
	}
}

// renderConfirmPage writes the HTML confirmation page. The form POSTs the
// token to /api/v1/recover/verify on user click — that POST is what actually
// consumes the token + creates the new tenant.
//
// HTML-escapes the email and embeds the token in a hidden form input.
// (The token was already validated by the caller; including it in the form
// is safe because POST will re-validate before consume.)
// confirmPageTmpl renders the recovery confirmation page. Using html/template
// (not fmt.Sprintf) gives contextual auto-escaping for {{.Email}} (element text)
// and {{.Token}} (attribute value), closing go/reflected-xss with a sanitizer
// the analyzer recognizes rather than the custom htmlAttrEscape helper.
var confirmPageTmpl = template.Must(template.New("confirm").Parse(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Confirm AxonFlow Recovery</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 540px; margin: 4em auto; padding: 0 1em; color: #1a1a1a; }
  h1 { color: #2B9B9B; }
  .email { background: #f3f4f6; padding: 0.4em 0.6em; border-radius: 4px; font-family: monospace; }
  button { display: inline-block; padding: 0.85em 1.5em; background: #2B9B9B; color: white; border: 0; border-radius: 6px; font-size: 1em; cursor: pointer; }
  button:hover { background: #1E5F5F; }
  .warning { color: #999; font-size: 0.9em; margin-top: 2em; }
</style>
</head><body>
<h1>Confirm AxonFlow recovery</h1>
<p>Recover the AxonFlow tenant associated with <span class="email">{{.Email}}</span>?</p>
<p>Clicking <strong>Confirm</strong> will issue fresh credentials. You'll be shown the new credentials once. Save them in your plugin config.</p>
<form method="POST" action="/api/v1/recover/verify">
  <input type="hidden" name="token" value="{{.Token}}">
  <button type="submit">Confirm recovery</button>
</form>
<p class="warning">If you didn't request this, just close this page. No changes will be made.</p>
</body></html>`))

func renderConfirmPage(w http.ResponseWriter, token, email string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_ = confirmPageTmpl.Execute(w, struct{ Email, Token string }{Email: email, Token: token})
}

// confirmErrorPageTmpl renders the recovery error page. All current callers
// pass a static string literal as the message (no tainted source), but it is
// rendered through html/template + nosniff for consistency with renderConfirmPage
// so any future caller that passes a dynamic value stays safe by construction.
var confirmErrorPageTmpl = template.Must(template.New("confirmError").Parse(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>AxonFlow Recovery Error</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 540px; margin: 4em auto; padding: 0 1em; color: #1a1a1a; }
  h1 { color: #b00020; }
</style>
</head><body>
<h1>Recovery error</h1>
<p>{{.Message}}</p>
</body></html>`))

// renderConfirmErrorPage writes a minimal HTML error page for the GET endpoint.
func renderConfirmErrorPage(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = confirmErrorPageTmpl.Execute(w, struct{ Message string }{Message: message})
}

// hashRecoveryToken returns the SHA-256 hex digest of the token. Tokens are
// stored hashed so a DB compromise doesn't reveal usable magic links.
func hashRecoveryToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// looksLikeEmail does a minimal "has @ and a dot in the domain part" check.
// Not full RFC validation — server-side bouncing handled by the email provider.
func looksLikeEmail(email string) bool {
	if len(email) < 5 || len(email) > 255 {
		return false
	}
	at := strings.Index(email, "@")
	if at < 1 || at >= len(email)-3 {
		return false
	}
	if !strings.Contains(email[at+1:], ".") {
		return false
	}
	return true
}

// writeRecoveryGenericResponse writes the same 202 response regardless of
// whether the email was found, the rate limit was hit, or the email send failed.
// This is the anti-enumeration property — an attacker cannot distinguish
// "valid email" from "invalid email" by reading the response.
func writeRecoveryGenericResponse(w http.ResponseWriter) {
	resp := recoveryRequestResponse{
		Message: "If an AxonFlow tenant is associated with this email, you'll receive a recovery link within a few minutes. Check your inbox (and spam folder).",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(resp)
}
