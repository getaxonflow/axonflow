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
	// communitySaasTenantPrefix distinguishes community-saas tenants in logs and DB.
	communitySaasTenantPrefix = "cs_"

	// csaasOrgTier + csaasOrgMaxNodes are the values stamped into the
	// organizations row created for each Community-SaaS customer via
	// register_org() (migration 062). Matching migration 094 Pass-1A-seed
	// + migration 100's organizations seed prevents register_org's
	// ON CONFLICT UPDATE WHERE clause from firing a silent
	// (tier,max_nodes) downgrade on every fresh registration when the
	// row already exists from the backfill.
	csaasOrgTier     = "Community"
	csaasOrgMaxNodes = 999999

	// internalTenantIDPrefix marks tenant_ids minted for AxonFlow's own
	// internal write-paths (synthetic-monitoring canary, future internal
	// probes). VALUE is intentionally the narrow `axonflow-internal-`
	// sub-namespace per ADR-054 — broader rotations land via the
	// telemetryfilter.InternalOrgIDPrefix constant ("axonflow-" post-#2261)
	// and customer-facing demos don't use this minting path. Classification
	// at write time is ee/platform/telemetry-filter/classify.go IsInternal
	// rule 4 (HasPrefix(TenantID, InternalOrgIDPrefix)) — the broader rule
	// catches any axonflow-* tenant_id, of which axonflow-internal-* is a
	// subset, so rows minted with this prefix correctly classify as
	// source=internal at write time. See epic #2047 / PR-2.
	internalTenantIDPrefix = "axonflow-internal-"

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

	// communitySaasDisclaimerNote is returned with every registration response.
	// Operational facts only — what the tenant gets on the Free tier, the
	// inactivity sweep that customers should be aware of, and the upgrade path
	// to Plugin Pro. Quality-of-service framing belongs in the Terms of Service
	// and Privacy Policy, not in the API surface.
	communitySaasDisclaimerNote = "Free tier: 3-day audit retention, 200 events/day. Tenants are deprovisioned " +
		"after 3 months of inactivity, or 1 year from creation regardless of activity (data disassociated, " +
		"tenant terminated). Plugin Pro upgrades to 30-day retention and 1,000 events/day for 90 days ($9.99) " +
		"— see https://www.getaxonflow.com/pricing/."

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

	// InternalTenantIDPrefix overrides the default `cs_` tenant_id prefix
	// with one of a small allowlist of internal-known prefixes (see
	// internalTenantIDPrefixAllowlist). Used by AxonFlow's own internal
	// callers (synthetic-monitoring canary, future internal probes) so
	// the resulting tenant_id classifies as source=internal at write time
	// via classify.go IsInternal rule 4 (HasPrefix(TenantID,
	// InternalOrgIDPrefix="axonflow-") — the broadened prefix family per
	// ADR-054 / #2261, of which axonflow-internal-* is a sub-namespace).
	// Real customers should not set this field; if they do, only
	// allowlisted values are accepted, otherwise 400. Allowlist abuse
	// risk is low — the only "harm" is the abuser opts themselves out of
	// our analytics, which they could already do via
	// AXONFLOW_TELEMETRY=off. Epic #2047 / PR-3.
	InternalTenantIDPrefix string `json:"internal_tenant_id_prefix,omitempty"`
}

// internalTenantIDPrefixAllowlist is the set of acceptable values for
// registrationRequest.InternalTenantIDPrefix. Each entry MUST start with
// internalTenantIDPrefix so the resulting tenant_id starts with
// `axonflow-` (the broader ADR-054 / #2261 family) and classifies as
// source=internal via classify.go IsInternal rule 4. A value not in this
// set is rejected with 400 — we don't silently fall back to `cs_`
// because that would hide an attempted prefix-injection from operators.
//
// Each value is constructed by appending a suffix to internalTenantIDPrefix
// rather than embedding the literal — that way a future rename of the
// constant ripples through the allowlist automatically (the test
// TestInternalTenantIDPrefixAllowlist_Shape asserts the every-entry-
// starts-with-internalTenantIDPrefix invariant; this construction makes
// drift impossible by construction).
//
// Adding a new entry here is safe AS LONG AS the prefix is reserved
// for AxonFlow's own internal callers (no real-customer surface should
// ever send these values).
var internalTenantIDPrefixAllowlist = map[string]bool{
	internalTenantIDPrefix + "canary-":     true, // synthetic-monitoring canary (PR-3)
	internalTenantIDPrefix + "perf-bench-": true, // perf-benchmark internal license (future PR-5)
	internalTenantIDPrefix + "e2e-":        true, // runtime-e2e telemetry-path tests (future PR-5)
	internalTenantIDPrefix + "smoke-":      true, // ad-hoc smoke probes
}

// resolveTenantPrefix returns the tenant_id prefix to mint for this
// registration request, plus an error if the request opts into a
// non-allowlisted internal prefix. Pure function — no side effects —
// so the validation logic is unit-testable independent of the HTTP
// handler's nil-DB / rate-limit / content-type guards.
//
// Contract:
//
//   - empty InternalTenantIDPrefix → returns communitySaasTenantPrefix, nil
//     (default behavior, preserves backwards-compat for real-customer
//     plugins that don't set the field)
//   - InternalTenantIDPrefix in internalTenantIDPrefixAllowlist → returns
//     the supplied prefix, nil
//   - InternalTenantIDPrefix not in allowlist → returns "",
//     ErrInvalidInternalPrefix (caller should log + 400)
//
// The errReason is the operator-facing string for the log line, distinct
// from the customer-facing 400 message.
func resolveTenantPrefix(req registrationRequest) (prefix string, err error) {
	if req.InternalTenantIDPrefix == "" {
		return communitySaasTenantPrefix, nil
	}
	if !internalTenantIDPrefixAllowlist[req.InternalTenantIDPrefix] {
		return "", ErrInvalidInternalPrefix
	}
	return req.InternalTenantIDPrefix, nil
}

// ErrInvalidInternalPrefix is returned by resolveTenantPrefix when the
// request's InternalTenantIDPrefix value is non-empty but not in the
// allowlist. The handler converts this to HTTP 400 with a generic
// "Unsupported internal_tenant_id_prefix value" message.
var ErrInvalidInternalPrefix = errors.New("internal_tenant_id_prefix not in allowlist")

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
			// v9 Phase 8 PR-A (mig 109): activity worker runs on a separate
			// pool/conn — no GUC propagates from the auth handler. Route the
			// UPDATE through the csaas_register_touch SECURITY DEFINER helper
			// so it bypasses FORCE RLS (mig 105) under axonflow_app_role.
			_, err := update.db.ExecContext(ctx,
				`SELECT csaas_register_touch($1)`, update.tenantID)
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

		// Resolve the tenant_id prefix via the pure resolveTenantPrefix
		// function so the validation is unit-testable independent of this
		// handler's nil-DB / rate-limit / content-type guards. Out-of-
		// allowlist values are rejected with 400; operator log line names
		// the offending value + IP so abuse attempts are visible in logs.
		tenantPrefix, prefixErr := resolveTenantPrefix(req)
		if prefixErr != nil {
			log.Printf("[CSAAS-REGISTER] Rejected non-allowlisted internal_tenant_id_prefix=%q from IP %s: %v",
				logutil.Sanitize(req.InternalTenantIDPrefix), logutil.Sanitize(clientIP), prefixErr)
			writeJSONError(w, "Unsupported internal_tenant_id_prefix value", http.StatusBadRequest)
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
			tenantID = tenantPrefix + uuidNewString()
			// v9 Phase 6 (Epic #2230): org_id MUST be the per-customer cs_<uuid>
			// (== tenant_id == client_id) — NOT the legacy shared constant
			// "community-saas". Pre-Phase-6 every SaaS row collapsed into a
			// single RLS class; Phase 8 B8/B9 FORCE RLS would have leaked
			// customer A's rows to customer B under the same app.current_org_id.
			// See ADR-052 §"Community-SaaS" and technical-docs/
			// v9_phase8_rls_rollout.md §"Phase 6 gating note".
			//
			// v9 Phase 2/4 invariant retained: tenant_id AND client_id receive
			// the same cs_* value (migration 088 added client_id; this INSERT
			// keeps both columns populated explicitly because no trigger /
			// generated column is in place).
			// v9 Phase 8 PR-A (mig 109): route the per-tenant register INSERT
			// through the csaas_register_tenant SECURITY DEFINER helper so it
			// bypasses FORCE RLS (mig 105). Both with-email and without-email
			// shapes collapse onto the single helper via emailParam's nil
			// passthrough to the function's DEFAULT NULL branch. The
			// PK-collision retry loop still works because the helper
			// re-RAISEs the unique violation with SQLSTATE 23505 unchanged —
			// isUniqueViolation() at line 522 below catches it.
			_, insertErr = db.ExecContext(ctx,
				`SELECT csaas_register_tenant($1, $2, $3, $4, $5, $6)`,
				tenantID, string(hash), secretPrefix, labelParam, expiresAt, emailParam)
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
		//
		// v9 Phase 6: pass the per-customer cs_<uuid> as org_id so the tenants row +
		// the org row land with the per-customer identity. register_tenant() (migration
		// 097) writes client_id = tenant_id; register_org() upserts an organizations row
		// keyed by this org_id. Pre-Phase-6 every SaaS tenants row pointed at the single
		// "community-saas" org, defeating per-customer RLS.
		//
		// tier="Community"/max_nodes=999999 mirror migration 094 Pass-1A-seed +
		// migration 100 seed values, so register_org's ON CONFLICT UPDATE WHERE clause
		// (`tier != EXCLUDED.tier OR max_nodes != EXCLUDED.max_nodes`) NEVER fires on
		// already-seeded cs_* rows. Without this alignment, every fresh-registration's
		// register_org call would silently rewrite the row's (tier,max_nodes) to
		// (community, 1) — operationally meaningless for SaaS customers, but visible
		// drift between the cohort backfilled by 094 and the cohort minted post-Phase-6.
		registerTenantAndOrg(db, tenantID, tenantID, csaasOrgTier, csaasOrgMaxNodes)

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

	// v9 Phase 8 B9 (issue #2337): SECURITY DEFINER helper csaas_auth_lookup
	// (migration 105) bypasses FORCE RLS on community_saas_registrations
	// for this PRE-auth credential resolution. The whole point of the
	// SELECT is to figure out which tenant/org the caller claims to be —
	// there is no app.current_org_id to SET LOCAL.
	//
	// Falls back to a direct SELECT on the table if the helper isn't
	// installed (legacy DB pre-mig-105, or community-only build that
	// skipped the migration). Under non-FORCE state both code paths
	// behave identically.
	var secretHash string
	var expiresAt time.Time
	var disabledAt sql.NullTime
	var terminatedAt sql.NullTime
	var orgID sql.NullString // ignored at this layer; passed back to caller via context if needed

	err := db.QueryRowContext(ctx,
		`SELECT secret_hash, expires_at, disabled_at, terminated_at, org_id
		 FROM csaas_auth_lookup($1)`, tenantID).Scan(&secretHash, &expiresAt, &disabledAt, &terminatedAt, &orgID)
	// R3-H1 fix: only fall back when the function genuinely doesn't exist
	// (Postgres SQLSTATE 42883 = undefined_function). All other errors —
	// ErrNoRows (genuine not-found), permission_denied, FORCE RLS rejection,
	// connection errors, timeouts — propagate without masking. Falling back
	// on every error class was a security latent: it would silently bypass
	// the helper and route through the direct FORCE-blocked SELECT, which
	// under app_role flips to 0 rows → blanket ErrRegistrationNotFound → 401
	// for valid credentials.
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "42883" {
			// Helper not installed (legacy DB pre-mig-105) — fall back to
			// the direct SELECT. Same query shape as the pre-105 code.
			err = db.QueryRowContext(ctx,
				`SELECT secret_hash, expires_at, disabled_at, terminated_at
				 FROM community_saas_registrations
				 WHERE tenant_id = $1`, tenantID).Scan(&secretHash, &expiresAt, &disabledAt, &terminatedAt)
		}
		// Any other error — including sql.ErrNoRows — propagates below.
	}
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
//
// AWS ALB always appends the connecting peer's IP to the X-Forwarded-For
// header chain, so the LAST entry is the real client IP — regardless of
// whatever the client sent. Reading the FIRST entry would be unsafe
// because any client can spoof it (e.g. sending `X-Forwarded-For:
// 10.1.2.3` would let the caller bypass per-IP rate limits, since each
// forged value looks like a fresh client). The single-hop ALB assumption
// matches the production stack topology; if a CDN (CloudFront) is added
// later, this needs a configurable trusted-proxy count.
//
// Falls back to RemoteAddr if XFF is absent or malformed. Returns
// "unknown" only when both are empty.
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Walk from the right: the LAST non-empty trimmed entry is the
		// IP the trusted proxy (ALB) observed at its peer socket.
		lastComma := strings.LastIndexByte(xff, ',')
		var ip string
		if lastComma >= 0 {
			ip = strings.TrimSpace(xff[lastComma+1:])
		} else {
			ip = strings.TrimSpace(xff)
		}
		if ip != "" {
			return ip
		}
		// Malformed XFF (empty last entry) — fall through to RemoteAddr
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
