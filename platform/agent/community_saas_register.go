// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	logutil "axonflow/platform/shared/logger"
)

// Community-SaaS registration errors (typed for structured logging)
var (
	ErrRegistrationNotFound   = errors.New("registration not found")
	ErrRegistrationExpired    = errors.New("registration expired")
	ErrRegistrationDisabled   = errors.New("registration disabled")
	ErrRegistrationTerminated = errors.New("registration terminated")
	ErrInvalidSecret          = errors.New("invalid secret")
	ErrDatabaseUnavailable    = errors.New("database unavailable")
	ErrRegistrationRateLimit  = errors.New("registration rate limit exceeded")
)

const (
	// communitySaasOrgID is the org_id for all community-saas tenants.
	communitySaasOrgID = "community-saas"

	// communitySaasTenantPrefix distinguishes community-saas tenants in logs and DB.
	communitySaasTenantPrefix = "cs_"

	// bcryptCost for hashing registration secrets. Cost 12 gives ~400ms on modern hardware.
	bcryptCost = 12

	// secretBytes is the number of random bytes for the secret (hex encoded = 32 chars).
	secretBytes = 16

	// maxLabelLength is the maximum length of the optional label field.
	maxLabelLength = 255

	// maxRequestBodySize is the maximum size of the registration request body.
	maxRequestBodySize = 1024 // 1KB

	// registrationIPLimit is the max registrations per IP per hour.
	registrationIPLimit = 5

	// ipTrackerMaxEntries is the max number of entries in the IP tracker before cleanup.
	ipTrackerMaxEntries = 10000

	// communitySaasTryEndpoint is the canonical endpoint URL returned to registrants.
	communitySaasTryEndpoint = "https://try.getaxonflow.com"

	// communitySaasRegistrationTTL is the lifetime of a fresh registration. After
	// this period (regardless of activity) the registration becomes inactive and
	// the daily inactivity sweep terminates it. Active registrations whose
	// last_seen_at goes 3 months without traffic are terminated earlier; see
	// community_saas_sweep.go.
	communitySaasRegistrationTTL = 365 * 24 * time.Hour

	// communitySaasMaxRegistrationRetries is the upper bound on retries when a
	// freshly-generated UUID v4 collides with an existing tombstone in the
	// community_saas_registrations PK. Collision probability per call is ~2^-122,
	// so this should never fire in practice — present strictly as defense-in-depth
	// against the impossible-but-not-zero case. After this many retries the
	// registration handler returns 500 to surface the impossible event to the
	// operator instead of silently looping.
	communitySaasMaxRegistrationRetries = 3

	// communitySaasDisclaimerNote is the disclaimer returned with every registration.
	// This text is the canonical source for what the plugin's first-run setup message
	// and the public privacy policy say about Community-SaaS. Keep all three surfaces
	// in sync — drift across surfaces is the failure mode.
	communitySaasDisclaimerNote = "AxonFlow Community SaaS is intended for basic testing and evaluation. " +
		"For real workflows, real systems, or sensitive data, we recommend self-hosting AxonFlow from day one " +
		"(https://docs.getaxonflow.com/quickstart). Best-effort retention up to 1 year. After 3 months of " +
		"inactivity, your tenant data is disassociated and the tenant terminated. Due to the limits of " +
		"identifying users on Community SaaS, we cannot offer reliability or security guarantees — by " +
		"using it you accept these constraints."

	// activityUpdateBufferSize is the capacity of the activity update channel.
	// When full, updates are dropped (non-critical — activity tracking is best-effort).
	activityUpdateBufferSize = 256
)

// registrationIPTracker tracks registration attempts per IP for rate limiting.
// Entries are cleaned up when the map exceeds ipTrackerMaxEntries.
type registrationIPTracker struct {
	mu      sync.Mutex
	entries map[string]*ipRegistrationEntry
}

type ipRegistrationEntry struct {
	count     int
	resetTime time.Time
}

var regIPTracker = &registrationIPTracker{
	entries: make(map[string]*ipRegistrationEntry),
}

// uuidNewString is a package-level indirection over uuid.NewString to allow
// deterministic UUIDs in tests covering the PK-collision retry path. Production
// code never reassigns this; only test files do, in setup/teardown.
var uuidNewString = uuid.NewString

// check verifies the given IP has not exceeded the registration rate limit.
// Returns nil if under limit, ErrRegistrationRateLimit if exceeded.
// Periodically sweeps expired entries to prevent unbounded memory growth.
func (t *registrationIPTracker) check(ip string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()

	// Sweep expired entries if map is getting large
	if len(t.entries) > ipTrackerMaxEntries {
		for k, v := range t.entries {
			if now.After(v.resetTime) {
				delete(t.entries, k)
			}
		}
	}

	entry, exists := t.entries[ip]

	if !exists || now.After(entry.resetTime) {
		t.entries[ip] = &ipRegistrationEntry{
			count:     1,
			resetTime: now.Add(1 * time.Hour),
		}
		return nil
	}

	entry.count++
	if entry.count > registrationIPLimit {
		return ErrRegistrationRateLimit
	}
	return nil
}

// registrationResponse is the JSON response returned by POST /api/v1/register.
type registrationResponse struct {
	TenantID     string `json:"tenant_id"`
	Secret       string `json:"secret"`
	SecretPrefix string `json:"secret_prefix"`
	ExpiresAt    string `json:"expires_at"`
	Endpoint     string `json:"endpoint"`
	Note         string `json:"note"`
}

// registrationRequest is the JSON request body for POST /api/v1/register.
//
// Email is OPTIONAL but required for the W3 free email-recovery flow to be
// reachable. Plugins that send `email` at registration bind it to the new
// tenant_id, enabling users to recover the same identity via /api/v1/recover
// after a lost local cache. Plugins that omit `email` get the existing pre-W3
// behavior: tenant_id stored locally only, no recovery path.
//
// App-level cap of 3 active tenants per email enforced at registration time
// per ADR-049 section 4. Registration with an over-cap email returns 409 with
// a clear error message; the user can either use one of their existing tenants
// or contact support.
type registrationRequest struct {
	Label string `json:"label"`
	Email string `json:"email,omitempty"`
}

// activityUpdateChan is a bounded channel for fire-and-forget activity updates.
// A single worker drains it. If the channel is full, updates are dropped.
var activityUpdateChan chan activityUpdate

type activityUpdate struct {
	db       *sql.DB
	tenantID string
}

// startActivityUpdateWorker starts a single background worker that processes
// tenant activity updates from the channel. Call once at startup.
func startActivityUpdateWorker() {
	activityUpdateChan = make(chan activityUpdate, activityUpdateBufferSize)
	go func() {
		for update := range activityUpdateChan {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, err := update.db.ExecContext(ctx,
				`UPDATE community_saas_registrations
				 SET last_seen_at = NOW(), request_count = request_count + 1
				 WHERE tenant_id = $1`, update.tenantID)
			if err != nil {
				log.Printf("[CSAAS-AUTH] Failed to update activity for tenant %s: %v",
					logutil.Sanitize(update.tenantID), err)
			}
			cancel()
		}
	}()
}

// enqueueActivityUpdate sends an activity update to the bounded channel.
// If the channel is full, the update is silently dropped (best-effort tracking).
func enqueueActivityUpdate(db *sql.DB, tenantID string) {
	if activityUpdateChan == nil {
		return
	}
	select {
	case activityUpdateChan <- activityUpdate{db: db, tenantID: tenantID}:
	default:
		// Channel full — drop update (non-critical)
	}
}

// RegisterCommunityRegistrationHandler wires POST /api/v1/register onto the router.
// This endpoint is only active when DEPLOYMENT_MODE=community-saas.
// It is intentionally NOT protected by apiAuthMiddleware — it is the bootstrap
// endpoint that creates the credentials needed for all other endpoints.
func RegisterCommunityRegistrationHandler(router *mux.Router, db *sql.DB) {
	// Start the bounded activity update worker
	startActivityUpdateWorker()

	router.HandleFunc("/api/v1/register", handleCommunityRegister(db)).Methods("POST")
	// Reject non-POST with 405
	router.HandleFunc("/api/v1/register", func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, "Method not allowed. Use POST to register.", http.StatusMethodNotAllowed)
	}).Methods("GET", "PUT", "DELETE", "PATCH")
}

// handleCommunityRegister creates a new community-saas tenant registration.
// Generates a UUID tenant_id (prefixed cs_), a cryptographic random secret,
// bcrypt-hashes the secret, and stores the registration in the database.
// Also calls register_tenant() and register_org() synchronously to ensure the
// tenant is visible in the tenants table for data partitioning before responding.
func handleCommunityRegister(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Validate database availability
		if db == nil {
			writeJSONError(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}

		// Content-Type validation — accept "application/json" with optional params (charset, etc.)
		contentType := r.Header.Get("Content-Type")
		if contentType != "" && !strings.HasPrefix(contentType, "application/json") {
			writeJSONError(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}

		// IP-based registration rate limit
		clientIP := extractClientIP(r)
		if err := regIPTracker.check(clientIP); err != nil {
			log.Printf("[CSAAS-REGISTER] Rate limit exceeded for IP %s", logutil.Sanitize(clientIP))
			writeJSONError(w, fmt.Sprintf("Registration rate limit exceeded (%d per hour). Try again later.", registrationIPLimit), http.StatusTooManyRequests)
			return
		}

		// Read and validate request body
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize+1))
		if err != nil {
			writeJSONError(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		if len(body) > maxRequestBodySize {
			writeJSONError(w, fmt.Sprintf("Request body too large (max %d bytes)", maxRequestBodySize), http.StatusRequestEntityTooLarge)
			return
		}

		// Parse request (empty body is OK — label is optional)
		var req registrationRequest
		if len(body) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				writeJSONError(w, "Invalid JSON in request body", http.StatusBadRequest)
				return
			}
		}

		// Validate label length
		if len(req.Label) > maxLabelLength {
			writeJSONError(w, fmt.Sprintf("Label too long (max %d characters)", maxLabelLength), http.StatusBadRequest)
			return
		}

		// Optional email — normalize + validate. If present, will bind the new
		// tenant_id to this email for W3 recovery. App-level cap of 3 active
		// tenants per email is enforced inside the registration transaction
		// below (per ADR-049 section 4 — TOCTOU-safe via SERIALIZABLE isolation).
		email := strings.TrimSpace(strings.ToLower(req.Email))
		if email != "" && !looksLikeEmail(email) {
			writeJSONError(w, "Invalid email format", http.StatusBadRequest)
			return
		}

		// Generate cryptographic random secret (shared across PK retries)
		secretRaw := make([]byte, secretBytes)
		if _, err := rand.Read(secretRaw); err != nil {
			log.Printf("[CSAAS-REGISTER] Failed to generate secret: %v", err)
			writeJSONError(w, "Internal error during registration", http.StatusInternalServerError)
			return
		}
		secret := hex.EncodeToString(secretRaw)
		secretPrefix := secret[:8]

		// Bcrypt hash the secret for storage
		hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcryptCost)
		if err != nil {
			log.Printf("[CSAAS-REGISTER] Failed to hash secret: %v", err)
			writeJSONError(w, "Internal error during registration", http.StatusInternalServerError)
			return
		}

		// Store registration in database with PK retry on UUID collision.
		// Tombstone rows (terminated_at non-NULL) hold the PK slot indefinitely so a
		// freshly-generated UUID could in principle collide. The probability is
		// astronomical (~2^-122 per generation) but the retry preserves "never reuse
		// tenant_id" as a hard guarantee rather than a probabilistic one.
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		expiresAt := time.Now().UTC().Add(communitySaasRegistrationTTL)
		var labelParam interface{}
		if req.Label != "" {
			labelParam = req.Label
		}
		// Email param: NULL when not provided (so claimed_by_email column stays NULL)
		var emailParam interface{}
		if email != "" {
			emailParam = email

			// Per-email cap check inside SERIALIZABLE transaction to prevent
			// TOCTOU races (two concurrent registrations with same email both
			// passing the cap check, both inserting → cap exceeded).
			//
			// We use a separate transaction for the cap check to keep the existing
			// PK-retry loop simple. SERIALIZABLE makes Postgres detect the race
			// and abort one of the transactions if they would conflict.
			capTx, capErr := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
			if capErr != nil {
				log.Printf("[CSAAS-REGISTER] Failed to start cap-check tx for %s: %v",
					logutil.Sanitize(email), capErr)
				writeJSONError(w, "Internal error during registration", http.StatusInternalServerError)
				return
			}
			var activeTenants int
			capErr = capTx.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM community_saas_registrations
				 WHERE claimed_by_email = $1
				   AND terminated_at IS NULL
				   AND disabled_at IS NULL
				   AND expires_at > NOW()`, email).Scan(&activeTenants)
			if capErr != nil {
				_ = capTx.Rollback()
				log.Printf("[CSAAS-REGISTER] Cap-check query failed for %s: %v",
					logutil.Sanitize(email), capErr)
				writeJSONError(w, "Internal error during registration", http.StatusInternalServerError)
				return
			}
			if activeTenants >= recoveryMaxTenantsPerEmail {
				_ = capTx.Rollback()
				log.Printf("[CSAAS-REGISTER] Per-email cap reached for %s (active=%d, cap=%d)",
					logutil.Sanitize(email), activeTenants, recoveryMaxTenantsPerEmail)
				writeJSONError(w,
					fmt.Sprintf("Max %d active tenants per email reached. Use one of your existing tenants or contact support.", recoveryMaxTenantsPerEmail),
					http.StatusConflict)
				return
			}
			if commitErr := capTx.Commit(); commitErr != nil {
				log.Printf("[CSAAS-REGISTER] Cap-check commit failed for %s: %v",
					logutil.Sanitize(email), commitErr)
				writeJSONError(w, "Internal error during registration", http.StatusInternalServerError)
				return
			}
		}

		var tenantID string
		var insertErr error
		for attempt := 0; attempt < communitySaasMaxRegistrationRetries; attempt++ {
			tenantID = communitySaasTenantPrefix + uuidNewString()
			if emailParam != nil {
				_, insertErr = db.ExecContext(ctx,
					`INSERT INTO community_saas_registrations
					 (tenant_id, secret_hash, secret_prefix, org_id, label, expires_at, claimed_by_email, claimed_at)
					 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
					tenantID, string(hash), secretPrefix, communitySaasOrgID, labelParam, expiresAt, emailParam)
			} else {
				_, insertErr = db.ExecContext(ctx,
					`INSERT INTO community_saas_registrations (tenant_id, secret_hash, secret_prefix, org_id, label, expires_at)
					 VALUES ($1, $2, $3, $4, $5, $6)`,
					tenantID, string(hash), secretPrefix, communitySaasOrgID, labelParam, expiresAt)
			}
			if insertErr == nil {
				break
			}
			if !isUniqueViolation(insertErr) {
				log.Printf("[CSAAS-REGISTER] Failed to insert registration for tenant %s: %v",
					logutil.Sanitize(tenantID), insertErr)
				writeJSONError(w, "Failed to create registration", http.StatusInternalServerError)
				return
			}
			// Unique violation — log it (operationally interesting) and retry with a fresh UUID
			log.Printf("[CSAAS-REGISTER] PK collision on tenant_id %s (attempt %d/%d), retrying",
				logutil.Sanitize(tenantID), attempt+1, communitySaasMaxRegistrationRetries)
		}
		if insertErr != nil {
			log.Printf("[CSAAS-REGISTER] Exhausted %d UUID retries — impossible state, surfacing 500",
				communitySaasMaxRegistrationRetries)
			writeJSONError(w, "Failed to create registration", http.StatusInternalServerError)
			return
		}

		// Register in the tenants table synchronously (not hot path — registration is infrequent).
		// This ensures the tenant is visible for data partitioning before the response is sent.
		registerTenantAndOrg(db, tenantID, communitySaasOrgID, "community", 1)

		log.Printf("[CSAAS-REGISTER] New tenant registered: %s (label: %s, expires: %s)",
			logutil.Sanitize(tenantID), logutil.Sanitize(req.Label), expiresAt.Format(time.RFC3339))

		// Return credentials (secret shown only once)
		resp := registrationResponse{
			TenantID:     tenantID,
			Secret:       secret,
			SecretPrefix: secretPrefix,
			ExpiresAt:    expiresAt.Format(time.RFC3339),
			Endpoint:     communitySaasTryEndpoint,
			Note:         communitySaasDisclaimerNote,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("[CSAAS-REGISTER] Failed to encode response: %v", err)
		}
	}
}

// validateCommunityRegistration validates Basic auth credentials against the
// community_saas_registrations table. Called by apiAuthMiddleware for every
// authenticated request in community-saas mode.
//
// Returns nil on success, or a typed error:
//   - ErrRegistrationNotFound: tenant_id not in table
//   - ErrRegistrationTerminated: terminated_at is set (3-month inactivity sweep
//     or 1-year hard-cap sweep — the row is a tombstone, secret has been cleared,
//     tenant-scoped data has been cascade-deleted; client must re-register)
//   - ErrRegistrationExpired: expires_at in the past (registration TTL exceeded
//     before the inactivity sweep ran — operationally close to ErrRegistrationTerminated
//     but the underlying state differs and the typed errors give different log signal)
//   - ErrRegistrationDisabled: disabled_at is set (operator kill-switch)
//   - ErrInvalidSecret: bcrypt mismatch
//   - ErrDatabaseUnavailable: db is nil
func validateCommunityRegistration(ctx context.Context, db *sql.DB, tenantID, secret string) error {
	if db == nil {
		return ErrDatabaseUnavailable
	}

	var secretHash string
	var expiresAt time.Time
	var disabledAt sql.NullTime
	var terminatedAt sql.NullTime

	err := db.QueryRowContext(ctx,
		`SELECT secret_hash, expires_at, disabled_at, terminated_at
		 FROM community_saas_registrations
		 WHERE tenant_id = $1`, tenantID).Scan(&secretHash, &expiresAt, &disabledAt, &terminatedAt)
	if err == sql.ErrNoRows {
		return ErrRegistrationNotFound
	}
	if err != nil {
		return fmt.Errorf("database query failed: %w", err)
	}

	// Check tombstone (sweep-terminated tenant). Distinct from disabled (operator
	// action) and expired (TTL): tombstone means the row exists only to hold the
	// PK slot and prevent UUID reuse — the tenant's data is gone.
	if terminatedAt.Valid {
		return ErrRegistrationTerminated
	}

	// Check operator kill-switch
	if disabledAt.Valid {
		return ErrRegistrationDisabled
	}

	// Check expiry
	if time.Now().After(expiresAt) {
		return ErrRegistrationExpired
	}

	// Verify secret
	if err := bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(secret)); err != nil {
		return ErrInvalidSecret
	}

	return nil
}

// extractClientIP extracts the client IP from the request.
// Checks X-Forwarded-For first (for ALB/proxy), then falls back to RemoteAddr.
// Trims whitespace and returns a non-empty result or "unknown".
func extractClientIP(r *http.Request) string {
	// X-Forwarded-For: client, proxy1, proxy2
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First entry is the original client
		firstComma := strings.IndexByte(xff, ',')
		var ip string
		if firstComma >= 0 {
			ip = strings.TrimSpace(xff[:firstComma])
		} else {
			ip = strings.TrimSpace(xff)
		}
		if ip != "" {
			return ip
		}
		// Malformed XFF (empty first entry) — fall through to RemoteAddr
	}

	// Strip port from RemoteAddr (e.g., "192.168.1.1:12345" → "192.168.1.1")
	addr := r.RemoteAddr
	lastColon := strings.LastIndexByte(addr, ':')
	if lastColon >= 0 {
		return addr[:lastColon]
	}
	if addr == "" {
		return "unknown"
	}
	return addr
}

// isUniqueViolation reports whether err is a Postgres unique-constraint violation
// (SQLSTATE 23505). Used by the registration handler to distinguish a UUID v4 PK
// collision (retryable) from any other insert failure (operational error). Driver:
// github.com/lib/pq.
func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}
