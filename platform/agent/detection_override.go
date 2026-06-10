// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

// Per-(org, category) detection-action overrides (#2581).
//
// PROBLEM: InitDetectionConfigs resolves PII_ACTION (and the SQLI / dangerous-*
// levers) ONCE at boot and caches it process-wide, so one agent = one detection
// posture for the whole deployment. Teams that need redact-for-chat and
// block-for-batch cannot coexist.
//
// SOLUTION: an org may override the deployment-global action per detection
// category in the detection_action_overrides table (mig 120). The MCP + gateway
// check paths consult a SHORT-TTL per-org cache layered on top of the cached
// global ModeDetectionConfig:
//
//	effective action = per-org override (if any) ELSE deployment-global env config
//
// HOT-PATH SAFETY: resolution NEVER does a per-request DB query — the cache
// serves the org's overrides for the TTL window and is refreshed lazily on miss.
//
// FAIL-SAFE: a lookup error (DB down, table absent, schema drift) falls back to
// the deployment-global config — NEVER to "no governance". The error is cached
// for a short window so a failing DB cannot be hammered on the hot path.
//
// GLOBAL-ONLY DEPLOYMENTS: with no override rows (or no DB / cache not wired),
// resolution returns the exact cached global config — byte-identical to the
// pre-#2581 behavior.

// Detection categories addressable by a per-org override. These map onto the
// four ModeDetectionConfig action fields. The string values are the table's
// `category` column (see the CHECK constraint in mig 120).
const (
	DetectionCategoryPII              = "pii"
	DetectionCategorySQLI             = "sqli"
	DetectionCategoryDangerousQuery   = "dangerous_query"
	DetectionCategoryDangerousCommand = "dangerous_command"
)

// EnvDetectionOverrideTTLSeconds tunes how long a per-org override set is cached
// before a refresh. A posture change set via the portal (follow-up) becomes
// effective within this window. Default 60s; clamped to [5s, 600s].
const EnvDetectionOverrideTTLSeconds = "AXONFLOW_DETECTION_OVERRIDE_TTL_SECONDS"

const (
	defaultDetectionOverrideTTL = 60 * time.Second
	minDetectionOverrideTTL     = 5 * time.Second
	maxDetectionOverrideTTL     = 600 * time.Second
	// maxDetectionOverrideErrTTL bounds how long a fail-safe (lookup-error)
	// fallback is cached. Short so the cache recovers quickly once the DB heals,
	// but long enough to protect the hot path from hammering a failing DB.
	maxDetectionOverrideErrTTL = 15 * time.Second
)

// detectionOverrideReader reads the per-org category→action overrides. An
// interface so the cache can be unit-tested without a real DB.
type detectionOverrideReader interface {
	// ReadOrgOverrides returns the category→action map for orgID. An org with
	// no overrides returns an empty (non-nil) map and a nil error.
	ReadOrgOverrides(ctx context.Context, orgID string) (map[string]DetectionAction, error)
}

// DetectionOverrideRepository reads detection_action_overrides under org scope.
type DetectionOverrideRepository struct {
	db *sql.DB
}

// NewDetectionOverrideRepository constructs a repository over db.
func NewDetectionOverrideRepository(db *sql.DB) *DetectionOverrideRepository {
	return &DetectionOverrideRepository{db: db}
}

// ReadOrgOverrides reads every override row for orgID under RLS org scope.
//
// WithOrgScope sets app.current_org_id on a transaction, so this works
// identically under AXONFLOW_DB_USE_APP_ROLE on (RLS enforced — the GUC matches
// the row's org_id) and off (RLS bypassed by the owner role — the explicit
// WHERE org_id still scopes). The result is small and cached, so the txn cost
// is paid at most once per org per TTL window.
func (r *DetectionOverrideRepository) ReadOrgOverrides(ctx context.Context, orgID string) (map[string]DetectionAction, error) {
	out := make(map[string]DetectionAction)
	err := WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx,
			`SELECT category, action FROM detection_action_overrides WHERE org_id = $1`, orgID)
		if qErr != nil {
			return qErr
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var category, action string
			if sErr := rows.Scan(&category, &action); sErr != nil {
				return sErr
			}
			if parsed, ok := parseOverrideAction(action); ok {
				out[category] = parsed
			} else {
				// Should be unreachable (mig 120 CHECK constraint), but never
				// trust DB content blindly: skip the unknown action so this
				// category falls back to the global config rather than coercing
				// to a wrong (possibly weaker) posture.
				log.Printf("[Detection] WARNING: org %q category %q has unrecognized override action %q — ignoring", orgID, category, action)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// parseOverrideAction validates a stored action string against the four legal
// detection actions. Returns ok=false for anything else.
func parseOverrideAction(action string) (DetectionAction, bool) {
	switch DetectionAction(action) {
	case DetectionActionBlock, DetectionActionRedact, DetectionActionWarn, DetectionActionLog:
		return DetectionAction(action), true
	default:
		return "", false
	}
}

// detectionOverrideCacheEntry is one org's cached override set + its expiry.
type detectionOverrideCacheEntry struct {
	overrides map[string]DetectionAction
	expiresAt time.Time
}

// detectionOverrideCache caches per-org override sets with a short TTL.
type detectionOverrideCache struct {
	mu      sync.RWMutex
	entries map[string]detectionOverrideCacheEntry
	reader  detectionOverrideReader
	ttl     time.Duration
	errTTL  time.Duration
}

func newDetectionOverrideCache(reader detectionOverrideReader, ttl time.Duration) *detectionOverrideCache {
	if ttl < minDetectionOverrideTTL {
		ttl = minDetectionOverrideTTL
	}
	if ttl > maxDetectionOverrideTTL {
		ttl = maxDetectionOverrideTTL
	}
	errTTL := ttl
	if errTTL > maxDetectionOverrideErrTTL {
		errTTL = maxDetectionOverrideErrTTL
	}
	return &detectionOverrideCache{
		entries: make(map[string]detectionOverrideCacheEntry),
		reader:  reader,
		ttl:     ttl,
		errTTL:  errTTL,
	}
}

// get returns the cached (or freshly-read) override set for orgID. It never
// returns an error: on a lookup failure it caches + returns an empty set so the
// caller fails SAFE to the deployment-global config.
func (c *detectionOverrideCache) get(ctx context.Context, orgID string) map[string]DetectionAction {
	now := time.Now()

	c.mu.RLock()
	entry, ok := c.entries[orgID]
	c.mu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.overrides
	}

	overrides, err := c.reader.ReadOrgOverrides(ctx, orgID)
	if err != nil {
		// Fail-safe: cache an empty set briefly so the global config is used and
		// a failing DB is not re-hit on every request inside the error window.
		log.Printf("[Detection] WARNING: per-org override lookup failed for org %q — falling back to global config: %v", orgID, err)
		empty := map[string]DetectionAction{}
		c.mu.Lock()
		c.entries[orgID] = detectionOverrideCacheEntry{overrides: empty, expiresAt: now.Add(c.errTTL)}
		c.mu.Unlock()
		return empty
	}

	c.mu.Lock()
	c.entries[orgID] = detectionOverrideCacheEntry{overrides: overrides, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()
	return overrides
}

// invalidate drops orgID's cached entry so the next resolution re-reads. Called
// by the (follow-up) portal write path after an operator changes a posture.
func (c *detectionOverrideCache) invalidate(orgID string) {
	c.mu.Lock()
	delete(c.entries, orgID)
	c.mu.Unlock()
}

// Package-global cache, wired once at agent startup (DB mode only). nil when the
// agent runs without a DB (community / no-DB / most unit tests) → resolution
// returns the global config unchanged, identical to pre-#2581 behavior.
var (
	globalDetectionOverrideCache   *detectionOverrideCache
	globalDetectionOverrideCacheMu sync.RWMutex
)

// InitDetectionOverrides wires the per-org override cache to db. Call once at
// agent startup AFTER the DB connection is open and AFTER InitDetectionConfigs.
// Safe to skip in no-DB mode (the resolvers then return the global config).
func InitDetectionOverrides(db *sql.DB) {
	if db == nil {
		return
	}
	ttl := resolveDetectionOverrideTTL()
	cache := newDetectionOverrideCache(NewDetectionOverrideRepository(db), ttl)
	globalDetectionOverrideCacheMu.Lock()
	globalDetectionOverrideCache = cache
	globalDetectionOverrideCacheMu.Unlock()
	log.Printf("✅ Per-org detection-action overrides enabled (#2581; cache TTL %s, fallback=global config)", ttl)
}

// ResetDetectionOverrideCacheForTest clears the wired cache. Test-only.
func ResetDetectionOverrideCacheForTest() {
	globalDetectionOverrideCacheMu.Lock()
	globalDetectionOverrideCache = nil
	globalDetectionOverrideCacheMu.Unlock()
}

// setDetectionOverrideCacheForTest installs a cache backed by an arbitrary
// reader. Test-only.
func setDetectionOverrideCacheForTest(c *detectionOverrideCache) {
	globalDetectionOverrideCacheMu.Lock()
	globalDetectionOverrideCache = c
	globalDetectionOverrideCacheMu.Unlock()
}

func getDetectionOverrideCache() *detectionOverrideCache {
	globalDetectionOverrideCacheMu.RLock()
	defer globalDetectionOverrideCacheMu.RUnlock()
	return globalDetectionOverrideCache
}

// InvalidateOrgDetectionOverrides drops orgID's cached overrides. No-op when the
// cache isn't wired. Exposed for the follow-up portal posture-set path.
func InvalidateOrgDetectionOverrides(orgID string) {
	if c := getDetectionOverrideCache(); c != nil {
		c.invalidate(orgID)
	}
}

func resolveDetectionOverrideTTL() time.Duration {
	raw := os.Getenv(EnvDetectionOverrideTTLSeconds)
	if raw == "" {
		return defaultDetectionOverrideTTL
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		log.Printf("[Detection] WARNING: invalid %s=%q — using default %s", EnvDetectionOverrideTTLSeconds, raw, defaultDetectionOverrideTTL)
		return defaultDetectionOverrideTTL
	}
	ttl := time.Duration(secs) * time.Second
	if ttl < minDetectionOverrideTTL {
		ttl = minDetectionOverrideTTL
	}
	if ttl > maxDetectionOverrideTTL {
		ttl = maxDetectionOverrideTTL
	}
	return ttl
}

// ResolveMCPDetectionConfig returns the MCP detection config for orgID: the
// cached deployment-global config (GetMCPDetectionConfig) with any per-org
// category overrides applied on top. Falls back to the global config when orgID
// is empty, the override cache isn't wired, the org has no overrides, or the
// lookup fails (fail-safe).
func ResolveMCPDetectionConfig(ctx context.Context, orgID string) ModeDetectionConfig {
	return applyOrgDetectionOverrides(ctx, orgID, GetMCPDetectionConfig())
}

// ResolveGatewayDetectionConfig is the gateway-surface sibling of
// ResolveMCPDetectionConfig.
func ResolveGatewayDetectionConfig(ctx context.Context, orgID string) ModeDetectionConfig {
	return applyOrgDetectionOverrides(ctx, orgID, GetGatewayDetectionConfig())
}

// applyOrgDetectionOverrides layers orgID's per-category overrides onto base.
// base is returned UNCHANGED (same value) whenever no override applies, so a
// global-only deployment is byte-identical to today.
func applyOrgDetectionOverrides(ctx context.Context, orgID string, base ModeDetectionConfig) ModeDetectionConfig {
	if orgID == "" {
		return base // unauthenticated / community / internal-service with no org → global
	}
	cache := getDetectionOverrideCache()
	if cache == nil {
		return base // no DB / cache not wired → global
	}
	overrides := cache.get(ctx, orgID)
	if len(overrides) == 0 {
		return base // org has no overrides (or fail-safe empty) → global
	}

	out := base
	if a, ok := overrides[DetectionCategoryPII]; ok {
		out.PIIAction = a
	}
	if a, ok := overrides[DetectionCategorySQLI]; ok {
		out.SQLIAction = a
	}
	if a, ok := overrides[DetectionCategoryDangerousQuery]; ok {
		out.DangerousQueryAction = a
	}
	if a, ok := overrides[DetectionCategoryDangerousCommand]; ok {
		out.DangerousCommandAction = a
	}
	return out
}
