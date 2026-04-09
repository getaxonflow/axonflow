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
	"golang.org/x/crypto/bcrypt"

	logutil "axonflow/platform/shared/logger"
)

// Community-SaaS registration errors (typed for structured logging)
var (
	ErrRegistrationNotFound  = errors.New("registration not found")
	ErrRegistrationExpired   = errors.New("registration expired")
	ErrRegistrationDisabled  = errors.New("registration disabled")
	ErrInvalidSecret         = errors.New("invalid secret")
	ErrDatabaseUnavailable   = errors.New("database unavailable")
	ErrRegistrationRateLimit = errors.New("registration rate limit exceeded")
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

	// communitySaasDisclaimerNote is the mandatory disclaimer returned with every registration.
	communitySaasDisclaimerNote = "This is a shared evaluation server. No SLA, no security guarantee. " +
		"Do not send real PII or production data. Data retained 30 days max. " +
		"For production use, deploy self-hosted or contact hello@getaxonflow.com for enterprise licensing."

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
type registrationRequest struct {
	Label string `json:"label"`
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

		// Generate tenant_id (cs_ prefix + UUID)
		tenantID := communitySaasTenantPrefix + uuid.NewString()

		// Generate cryptographic random secret
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

		// Store registration in database
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)
		var labelParam interface{}
		if req.Label != "" {
			labelParam = req.Label
		}

		_, err = db.ExecContext(ctx,
			`INSERT INTO community_saas_registrations (tenant_id, secret_hash, secret_prefix, org_id, label, expires_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			tenantID, string(hash), secretPrefix, communitySaasOrgID, labelParam, expiresAt)
		if err != nil {
			log.Printf("[CSAAS-REGISTER] Failed to insert registration for tenant %s: %v",
				logutil.Sanitize(tenantID), err)
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
//   - ErrRegistrationExpired: expires_at in the past
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

	err := db.QueryRowContext(ctx,
		`SELECT secret_hash, expires_at, disabled_at
		 FROM community_saas_registrations
		 WHERE tenant_id = $1`, tenantID).Scan(&secretHash, &expiresAt, &disabledAt)
	if err == sql.ErrNoRows {
		return ErrRegistrationNotFound
	}
	if err != nil {
		return fmt.Errorf("database query failed: %w", err)
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
