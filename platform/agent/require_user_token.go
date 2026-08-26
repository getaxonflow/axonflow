// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Per-org require_user_token posture (#3476, ADR-060 follow-up, mig 163).
//
// PROBLEM: ADR-060 (#2989) segment-scoped policies are only meaningful if a
// caller cannot CHOOSE to arrive without an identity. Today a token-less
// enterprise caller gets a synthetic service identity on /decide, the
// MCP-server plane, and the four MCP REST routes — so dropping a header
// silently switches a control off. The fix belongs at authentication, not the
// policy evaluator.
//
// THIS FILE carries the storage + resolution half, and the gate points
// consume it: ResolveRequireUserToken is read at authentication time on
// /decide, the MCP-server session-auth plane, and the four MCP REST routes
// (six call sites, wired in the same PR that landed the identity stack). A
// true resolution refuses a token-less enterprise caller with
// user_token_required.
//
// RESOLUTION ORDER: the org's `organizations.require_user_token` column value
// if the row is readable, ELSE the deployment-wide env default
// (AXONFLOW_REQUIRE_USER_TOKEN, default false — so an unconfigured deployment
// keeps today's behaviour).
//
// HOT-PATH SAFETY: resolution NEVER does a per-request DB query — a short-TTL
// per-org cache (same shape as detection_override.go's) serves the org's
// posture for the TTL window and refreshes lazily on miss.
//
// ⚠ FAIL-CLOSED, NOT FAIL-SAFE — the one place this file must NOT mirror
// detection_override.go. detection_override.go is a detection POSTURE lever:
// a lookup error there falls back to the deployment-global config, because
// "governance keeps running under yesterday's settings" is the safe failure.
// require_user_token is an AUTHENTICATION gate: its entire job is to make an
// org's "callers must present an identity" promise NOT optional, so a lookup
// failure must never silently resolve to "false" (not required) — that would
// let a DB hiccup quietly turn the control off for every request in the
// window. On DB down / table absent / column absent / schema drift / scan
// error, resolution returns TRUE (required) and caches that outcome for a
// short bounded window (mirrors maxDetectionOverrideErrTTL, 15s) so a failing
// DB is not hammered on the hot path — but the cached value during that
// window is the fail-closed true, never false.
//
// THREE DISTINCT CASES on the read path — conflating any two of them is the
// whole risk of this file:
//
//  1. Org row genuinely absent (query succeeded, zero rows / sql.ErrNoRows).
//     NOT an error. It means "no per-org posture set" → fall through to the
//     env default. Treating this as an error would fail every org WITHOUT a
//     row closed, breaking the compatibility claim that an unconfigured
//     deployment behaves exactly as before.
//  2. Query/scan genuinely failed (DB down, table/column absent, driver
//     error). Fail closed to true. Treating this as "no row" would silently
//     resolve false on a DB outage — the opposite of this feature's purpose.
//  3. No DB wired at all (db == nil — the community / no-DB topology). This
//     is NOT a failure to read a posture; there IS no posture store. Falls
//     through to the env default, same as case 1 — NOT fail-closed. A
//     self-hosted single-org deployment with no database must be able to run
//     with the env default undisturbed.

// EnvRequireUserToken is the deployment-wide default used where no org row
// says otherwise. Covers self-hosted single-org deployments without anyone
// touching the DB. Parsed permissively via the existing parseBoolEnv idiom
// (detection_config.go): "true"/"1"/"yes" / "false"/"0"/"no", case-insensitive,
// unset or unrecognized → the supplied default (false).
const EnvRequireUserToken = "AXONFLOW_REQUIRE_USER_TOKEN"

// EnvRequireUserTokenTTLSeconds tunes how long a per-org resolution is cached
// before a refresh. Default 60s; clamped to [5s, 600s] — same shape as
// EnvDetectionOverrideTTLSeconds.
const EnvRequireUserTokenTTLSeconds = "AXONFLOW_REQUIRE_USER_TOKEN_TTL_SECONDS"

const (
	defaultRequireUserTokenTTL = 60 * time.Second
	minRequireUserTokenTTL     = 5 * time.Second
	maxRequireUserTokenTTL     = 600 * time.Second
	// maxRequireUserTokenErrTTL bounds how long a fail-closed (lookup-error)
	// outcome is cached. Short so the cache recovers quickly once the DB
	// heals, but long enough to protect the hot path from hammering a
	// failing DB. Mirrors maxDetectionOverrideErrTTL.
	maxRequireUserTokenErrTTL = 15 * time.Second
)

// requireUserTokenReader reads one org's require_user_token posture. An
// interface so the cache can be unit-tested without a real DB.
type requireUserTokenReader interface {
	// ReadOrgRequireUserToken reads orgID's require_user_token column.
	//
	//   - (value, true, nil)   — row present; value is the stored posture.
	//   - (false, false, nil)  — row genuinely absent (sql.ErrNoRows). NOT an
	//     error: caller must fall through to the env default.
	//   - (false, false, err)  — read/scan failed. Caller must fail closed.
	ReadOrgRequireUserToken(ctx context.Context, orgID string) (value bool, ok bool, err error)
}

// RequireUserTokenRepository reads organizations.require_user_token (mig 163)
// under org scope.
type RequireUserTokenRepository struct {
	db *sql.DB
}

// NewRequireUserTokenRepository constructs a repository over db.
func NewRequireUserTokenRepository(db *sql.DB) *RequireUserTokenRepository {
	return &RequireUserTokenRepository{db: db}
}

// ReadOrgRequireUserToken reads orgID's require_user_token column under RLS
// org scope. See requireUserTokenReader for the three-way return contract.
//
// WithOrgScope sets app.current_org_id on a transaction, so this works
// identically under AXONFLOW_DB_USE_APP_ROLE on (RLS enforced) and off (RLS
// bypassed by the owner role, explicit WHERE org_id still scopes).
func (r *RequireUserTokenRepository) ReadOrgRequireUserToken(ctx context.Context, orgID string) (bool, bool, error) {
	var value bool
	err := WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT require_user_token FROM organizations WHERE org_id = $1`, orgID,
		).Scan(&value)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Case 1: row genuinely absent — not an error.
			return false, false, nil
		}
		// Case 2: query/scan failed — propagate so the cache fails closed.
		return false, false, err
	}
	return value, true, nil
}

// requireUserTokenCacheEntry is one org's cached RESOLVED posture (the org
// row value if present, else the env default, else fail-closed true on a
// read error) plus its expiry.
type requireUserTokenCacheEntry struct {
	value     bool
	expiresAt time.Time
}

// requireUserTokenCache caches per-org resolved postures with a short TTL.
type requireUserTokenCache struct {
	mu         sync.RWMutex
	entries    map[string]requireUserTokenCacheEntry
	reader     requireUserTokenReader
	ttl        time.Duration
	errTTL     time.Duration
	envDefault bool
}

func newRequireUserTokenCache(reader requireUserTokenReader, ttl time.Duration, envDefault bool) *requireUserTokenCache {
	if ttl < minRequireUserTokenTTL {
		ttl = minRequireUserTokenTTL
	}
	if ttl > maxRequireUserTokenTTL {
		ttl = maxRequireUserTokenTTL
	}
	errTTL := ttl
	if errTTL > maxRequireUserTokenErrTTL {
		errTTL = maxRequireUserTokenErrTTL
	}
	return &requireUserTokenCache{
		entries:    make(map[string]requireUserTokenCacheEntry),
		reader:     reader,
		ttl:        ttl,
		errTTL:     errTTL,
		envDefault: envDefault,
	}
}

// get returns the cached (or freshly-resolved) require_user_token posture for
// orgID. Never returns an error: a lookup failure resolves + caches true
// (fail CLOSED) — the opposite fallback direction from
// detectionOverrideCache.get, which fails safe to the deployment-global
// config. See the file-level doc comment for why.
func (c *requireUserTokenCache) get(ctx context.Context, orgID string) bool {
	now := time.Now()

	c.mu.RLock()
	entry, ok := c.entries[orgID]
	c.mu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.value
	}

	value, rowOK, err := c.reader.ReadOrgRequireUserToken(ctx, orgID)
	if err != nil {
		// Case 2: read/scan failed — fail CLOSED (required=true), cached only
		// for the short error window so a failing DB is not hammered.
		log.Printf("[RequireUserToken] WARNING: org %q posture lookup failed — failing CLOSED (required=true): %v", orgID, err)
		c.mu.Lock()
		c.entries[orgID] = requireUserTokenCacheEntry{value: true, expiresAt: now.Add(c.errTTL)}
		c.mu.Unlock()
		return true
	}

	resolved := c.envDefault
	if rowOK {
		// Case: explicit per-org row — it wins over the env default in
		// EITHER direction (an org can opt OUT of a true env default just as
		// it can opt IN over a false one).
		resolved = value
	}
	// Case 1 (rowOK == false, err == nil): no per-org posture set — resolved
	// stays the env default.

	c.mu.Lock()
	c.entries[orgID] = requireUserTokenCacheEntry{value: resolved, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()
	return resolved
}

// Package-global cache, wired once at agent startup (DB mode only). nil when
// the agent runs without a DB (community / no-DB / most unit tests) →
// ResolveRequireUserToken returns the env default unchanged (Case 3 — NOT
// fail-closed; see the file-level doc comment).
var (
	globalRequireUserTokenCache   *requireUserTokenCache
	globalRequireUserTokenCacheMu sync.RWMutex
)

// InitRequireUserToken wires the per-org require_user_token cache to db. Call
// once at agent startup AFTER the DB connection is open. Safe to skip in
// no-DB mode (ResolveRequireUserToken then returns the env default).
func InitRequireUserToken(db *sql.DB) {
	if db == nil {
		return
	}
	ttl := resolveRequireUserTokenTTL()
	requireUserTokenEnvOrFatal()
	envDefault := parseBoolEnv(EnvRequireUserToken, false)
	cache := newRequireUserTokenCache(NewRequireUserTokenRepository(db), ttl, envDefault)
	globalRequireUserTokenCacheMu.Lock()
	globalRequireUserTokenCache = cache
	globalRequireUserTokenCacheMu.Unlock()
	log.Printf("✅ Per-org require_user_token posture enabled (#3476; cache TTL %s, env default=%v, fail-closed on read error)", ttl, envDefault)
}

// ResetRequireUserTokenCacheForTest clears the wired cache. Test-only.
func ResetRequireUserTokenCacheForTest() {
	globalRequireUserTokenCacheMu.Lock()
	globalRequireUserTokenCache = nil
	globalRequireUserTokenCacheMu.Unlock()
}

// setRequireUserTokenCacheForTest installs a cache backed by an arbitrary
// reader. Test-only.
func setRequireUserTokenCacheForTest(c *requireUserTokenCache) {
	globalRequireUserTokenCacheMu.Lock()
	globalRequireUserTokenCache = c
	globalRequireUserTokenCacheMu.Unlock()
}

func getRequireUserTokenCache() *requireUserTokenCache {
	globalRequireUserTokenCacheMu.RLock()
	defer globalRequireUserTokenCacheMu.RUnlock()
	return globalRequireUserTokenCache
}

func resolveRequireUserTokenTTL() time.Duration {
	raw := os.Getenv(EnvRequireUserTokenTTLSeconds)
	if raw == "" {
		return defaultRequireUserTokenTTL
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		log.Printf("[RequireUserToken] WARNING: invalid %s=%q — using default %s", EnvRequireUserTokenTTLSeconds, raw, defaultRequireUserTokenTTL)
		return defaultRequireUserTokenTTL
	}
	ttl := time.Duration(secs) * time.Second
	if ttl < minRequireUserTokenTTL {
		ttl = minRequireUserTokenTTL
	}
	if ttl > maxRequireUserTokenTTL {
		ttl = maxRequireUserTokenTTL
	}
	return ttl
}

// ResolveRequireUserToken returns whether orgID's caller must present a user
// token (as opposed to being allowed through as a synthetic service
// identity). Cached and fail-closed, and consumed on every gate path the
// flag governs: /decide, the MCP-server session-auth plane, and the four MCP
// REST routes all read it at authentication time.
//
// Resolution order: the org's organizations.require_user_token column value
// if the row is readable, ELSE the deployment-wide env default
// (AXONFLOW_REQUIRE_USER_TOKEN). A lookup error resolves to true (fail
// closed) — never false. See the file-level doc comment for the full
// decision table.
func ResolveRequireUserToken(ctx context.Context, orgID string) bool {
	if orgID == "" {
		// An enterprise caller CAN reach here with no org binding: the
		// boot-time licence check (run.go, "License org_id mismatch") is
		// `result.OrgID != "" && result.OrgID != deploymentOrgID`, so it
		// fatals only on a MISMATCH and deliberately tolerates a licence
		// carrying NO org_id at all. Such a licence boots, and every request
		// authenticated with it arrives with Client.OrgID == "".
		//
		// Falling back to the env default here would be a hole rather than a
		// neutral default: an operator who set require_user_token = true on
		// their org would find the control silently not applying to exactly
		// that credential. So resolve against the DEPLOYMENT's canonical org
		// identity instead — the same substitution the rest of the codebase
		// already makes for an empty org_id (migration 094 Pass-2 backfills
		// empty-org_id audit rows from ORG_ID, and the boot check itself logs
		// getDeploymentOrgID() as the deployment's "Org"). getDeploymentOrgID()
		// is never empty; it falls back to "local-dev-org".
		//
		// This is a posture READ keyed on the deployment's own identity, never
		// a privilege decision, and orgID is derived from the validated
		// credential rather than from caller-supplied input — so this cannot
		// be steered by a request.
		deploymentOrg := getDeploymentOrgID()
		log.Printf("[RequireUserToken] NOTICE: resolution requested with an EMPTY org id "+
			"(credential authenticated by a licence carrying no org_id claim); "+
			"resolving against the deployment org %q instead so per-org posture still applies.",
			deploymentOrg)
		orgID = deploymentOrg
	}
	cache := getRequireUserTokenCache()
	if cache == nil {
		// Case 3: no DB / cache not wired — env default, NOT fail-closed.
		return parseBoolEnv(EnvRequireUserToken, false)
	}
	return cache.get(ctx, orgID)
}

// requireUserTokenEnvOrFatal refuses to boot on an AXONFLOW_REQUIRE_USER_TOKEN
// value this deployment cannot interpret.
//
// This is the one direction in this file where an unresolvable input would
// otherwise fail OPEN. Everything else here is emphatic that an unreadable
// posture must never quietly resolve false — a DB error resolves true and is
// cached for at most the error TTL. But parseBoolEnv's default arm returns the
// DEFAULT on an unrecognised value, so "True " with a stray character,
// "enabled", or "yes please" turns the control off across every gate point,
// permanently, for a deployment whose operator explicitly set the flag
// intending the opposite. That is the more likely of the two operator errors,
// and its only signal was one boot line prefixed "[Detection]", pointing at an
// unrelated subsystem.
//
// Refusing to boot rather than guessing: an unparseable value means the
// operator's intent is unknown, and BOTH guesses are wrong in a way that is
// invisible afterwards — resolving false silently disables a security control,
// resolving true silently denies every token-less caller. A deployment that
// never sets the variable is unaffected; only a set-but-unintelligible value
// reaches this. Mirrors the license org_id and admin-pool fatals already in
// this codebase.
func requireUserTokenEnvOrFatal() {
	raw := os.Getenv(EnvRequireUserToken)
	if strings.TrimSpace(raw) == "" {
		return
	}
	if requireUserTokenEnvIsRecognised(raw) {
		return
	}
	log.Fatalf("❌ [RequireUserToken] %s=%q is not a recognised boolean (accepted: true/1/yes, false/0/no). "+
		"Refusing to boot rather than guess: this flag decides whether a token-less enterprise caller is "+
		"rejected at authentication, and silently defaulting it either way is invisible afterwards.",
		EnvRequireUserToken, raw)
}

// requireUserTokenEnvIsRecognised reports whether parseBoolEnv will actually
// interpret raw, rather than silently returning its default. Kept separate
// from the fatal so the classification is testable in-process.
func requireUserTokenEnvIsRecognised(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "true", "1", "yes", "false", "0", "no":
		return true
	default:
		return false
	}
}
