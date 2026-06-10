// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"axonflow/platform/agent"
)

// Per-(org, category) detection-action overrides on the ORCHESTRATOR response
// plane (#2612, follow-up to #2581/#2609).
//
// PROBLEM: #2609 wired per-org posture into the AGENT process. The orchestrator
// is a SEPARATE binary (platform/cmd/orchestrator) and its LLM-response
// redaction path still resolved the deployment-global gateway config
// (agent.GetGatewayDetectionConfig), so an org configured to redact/block was
// honored on the agent's check planes but NOT on the orchestrator's
// proxy/gateway/MAP response plane. That left a plane where per-org posture
// silently degraded to the deployment-global — the #2566/#2563 multi-plane PII
// lesson.
//
// SOLUTION: the orchestrator gets its OWN per-org override cache instance, wired
// with its OWN *sql.DB handle (the orchestrator's usageDB) in
// orchestrator.Run(). It REUSES the agent's RLS-scoped reader
// (agent.DetectionOverrideRepository.ReadOrgOverrides — the security-critical
// WithOrgScope read of mig 120's detection_action_overrides) and the agent's
// config types, so the DB/RLS logic is shared (not a divergent copy that could
// drift). The orchestrator only owns the cache + apply glue:
//
//	effective gateway action = per-org override (if any) ELSE deployment-global config
//
// HOT-PATH SAFETY: resolution NEVER does a per-request DB query — the cache
// serves an org's overrides for the TTL window, refreshed lazily on miss, and is
// size-bounded so a flood of distinct orgs cannot grow it without limit.
//
// FAIL-SAFE: a lookup error (DB down, table absent, schema drift) falls back to
// the deployment-global config — NEVER to "no governance". This is the response
// plane, where a fail-open leaks PII. The error is cached for a short window so a
// failing DB is not hammered on the hot path.
//
// GLOBAL-ONLY DEPLOYMENTS: with no override rows (or no DB / cache not wired /
// empty org), resolution returns the cached deployment-global config unchanged —
// byte-identical to the pre-#2612 behavior.
//
// CACHE-INVALIDATION CONTRACT: InvalidateOrgDetectionOverrides mirrors the
// agent's identically-named hook (agent.InvalidateOrgDetectionOverrides). The
// two processes hold independent in-memory caches, so a future portal
// posture-set path must call the local hook in EACH process (or rely on the
// short TTL) — there is no shared memory to invalidate across a process boundary.
// Keeping the contract (name + semantics) identical lets that follow-up wire both
// the same way.

// EnvDetectionOverrideMaxEntries bounds the per-org override cache size so a
// flood of distinct org IDs cannot grow it without limit. Default 10000;
// clamped to [128, 1_000_000].
const EnvDetectionOverrideMaxEntries = "AXONFLOW_DETECTION_OVERRIDE_MAX_ENTRIES"

const (
	defaultDetectionOverrideTTL = 60 * time.Second
	minDetectionOverrideTTL     = 5 * time.Second
	maxDetectionOverrideTTL     = 600 * time.Second
	// maxDetectionOverrideErrTTL bounds how long a fail-safe (lookup-error)
	// fallback is cached. Short so the cache recovers quickly once the DB heals,
	// but long enough to protect the hot path from hammering a failing DB.
	maxDetectionOverrideErrTTL = 15 * time.Second

	defaultDetectionOverrideMaxEntries = 10000
	minDetectionOverrideMaxEntries     = 128
	maxDetectionOverrideMaxEntries     = 1_000_000
)

// detectionOverrideReader reads the per-org category→action overrides. An
// interface so the cache can be unit-tested without a real DB.
// *agent.DetectionOverrideRepository satisfies it (it is the RLS-scoped read of
// mig 120, reused verbatim — see agent/detection_override.go).
type detectionOverrideReader interface {
	ReadOrgOverrides(ctx context.Context, orgID string) (map[string]agent.DetectionAction, error)
}

// detectionOverrideCacheEntry is one org's cached override set + its expiry.
type detectionOverrideCacheEntry struct {
	overrides map[string]agent.DetectionAction
	expiresAt time.Time
}

// detectionOverrideCache caches per-org override sets with a short TTL and a
// hard size bound.
type detectionOverrideCache struct {
	mu         sync.RWMutex
	entries    map[string]detectionOverrideCacheEntry
	reader     detectionOverrideReader
	ttl        time.Duration
	errTTL     time.Duration
	maxEntries int
}

func newDetectionOverrideCache(reader detectionOverrideReader, ttl time.Duration, maxEntries int) *detectionOverrideCache {
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
	if maxEntries < minDetectionOverrideMaxEntries {
		maxEntries = minDetectionOverrideMaxEntries
	}
	if maxEntries > maxDetectionOverrideMaxEntries {
		maxEntries = maxDetectionOverrideMaxEntries
	}
	return &detectionOverrideCache{
		entries:    make(map[string]detectionOverrideCacheEntry),
		reader:     reader,
		ttl:        ttl,
		errTTL:     errTTL,
		maxEntries: maxEntries,
	}
}

// get returns the cached (or freshly-read) override set for orgID. It never
// returns an error: on a lookup failure it caches + returns an empty set so the
// caller fails SAFE to the deployment-global config.
func (c *detectionOverrideCache) get(ctx context.Context, orgID string) map[string]agent.DetectionAction {
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
		log.Printf("[Detection] WARNING: orchestrator per-org override lookup failed for org %q — falling back to global config: %v", orgID, err)
		empty := map[string]agent.DetectionAction{}
		c.store(orgID, empty, now.Add(c.errTTL))
		return empty
	}

	c.store(orgID, overrides, now.Add(c.ttl))
	return overrides
}

// store inserts an entry, enforcing the size bound. When at capacity it first
// sweeps expired entries; if still full it evicts one arbitrary entry (Go map
// iteration order is unspecified, which is an acceptable victim policy for a
// short-TTL cache). The newly-resolved entry is always inserted so the current
// request is served from the cache.
func (c *detectionOverrideCache) store(orgID string, overrides map[string]agent.DetectionAction, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[orgID]; !exists && len(c.entries) >= c.maxEntries {
		c.evictLocked()
	}
	c.entries[orgID] = detectionOverrideCacheEntry{overrides: overrides, expiresAt: expiresAt}
}

// evictLocked frees room for at least one insert. Caller holds c.mu. It drops
// every expired entry first (cheap, and the common case under churn); if none
// were expired it drops a single arbitrary entry.
func (c *detectionOverrideCache) evictLocked() {
	now := time.Now()
	evicted := false
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
			evicted = true
		}
	}
	if evicted {
		return
	}
	for k := range c.entries {
		delete(c.entries, k)
		return
	}
}

// invalidate drops orgID's cached entry so the next resolution re-reads. Called
// by the (follow-up) portal write path after an operator changes a posture.
func (c *detectionOverrideCache) invalidate(orgID string) {
	c.mu.Lock()
	delete(c.entries, orgID)
	c.mu.Unlock()
}

// Package-global cache, wired once at orchestrator startup (DB mode only). nil
// when the orchestrator runs without a DB → resolution returns the global config
// unchanged, identical to pre-#2612 behavior.
var (
	globalDetectionOverrideCache   *detectionOverrideCache
	globalDetectionOverrideCacheMu sync.RWMutex
)

// InitDetectionOverrides wires the orchestrator's per-org override cache to db.
// Call once at orchestrator startup AFTER the DB connection is open. Safe to
// skip in no-DB mode (the resolvers then return the global config). db is the
// orchestrator's OWN handle (usageDB) — distinct from the agent process's.
func InitDetectionOverrides(db *sql.DB) {
	if db == nil {
		return
	}
	ttl := resolveDetectionOverrideTTL()
	maxEntries := resolveDetectionOverrideMaxEntries()
	cache := newDetectionOverrideCache(agent.NewDetectionOverrideRepository(db), ttl, maxEntries)
	globalDetectionOverrideCacheMu.Lock()
	globalDetectionOverrideCache = cache
	globalDetectionOverrideCacheMu.Unlock()
	log.Printf("✅ Orchestrator per-org detection-action overrides enabled (#2612; cache TTL %s, max %d orgs, fallback=global config)", ttl, maxEntries)
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
// cache isn't wired. Mirrors agent.InvalidateOrgDetectionOverrides (same name +
// semantics) so the follow-up portal posture-set path invalidates both processes
// the same way.
func InvalidateOrgDetectionOverrides(orgID string) {
	if c := getDetectionOverrideCache(); c != nil {
		c.invalidate(orgID)
	}
}

func resolveDetectionOverrideTTL() time.Duration {
	raw := os.Getenv(agent.EnvDetectionOverrideTTLSeconds)
	if raw == "" {
		return defaultDetectionOverrideTTL
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		log.Printf("[Detection] WARNING: invalid %s=%q — using default %s", agent.EnvDetectionOverrideTTLSeconds, raw, defaultDetectionOverrideTTL)
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

func resolveDetectionOverrideMaxEntries() int {
	raw := os.Getenv(EnvDetectionOverrideMaxEntries)
	if raw == "" {
		return defaultDetectionOverrideMaxEntries
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		log.Printf("[Detection] WARNING: invalid %s=%q — using default %d", EnvDetectionOverrideMaxEntries, raw, defaultDetectionOverrideMaxEntries)
		return defaultDetectionOverrideMaxEntries
	}
	if n < minDetectionOverrideMaxEntries {
		n = minDetectionOverrideMaxEntries
	}
	if n > maxDetectionOverrideMaxEntries {
		n = maxDetectionOverrideMaxEntries
	}
	return n
}

// orgDetectionOverrides returns orgID's cached override map, or nil when the org
// is empty, the cache isn't wired, the org has no overrides, or the lookup
// failed (fail-safe). Never hits the DB on the hot path beyond the cache.
func orgDetectionOverrides(ctx context.Context, orgID string) map[string]agent.DetectionAction {
	if orgID == "" {
		return nil // unauthenticated / community / internal-service with no org → global
	}
	cache := getDetectionOverrideCache()
	if cache == nil {
		return nil // no DB / cache not wired → global
	}
	return cache.get(ctx, orgID)
}

// ResolveGatewayDetectionConfig returns the gateway detection config for orgID:
// the cached deployment-global config (agent.GetGatewayDetectionConfig) with any
// per-org category overrides applied on top. Falls back to the global config
// when orgID is empty, the override cache isn't wired, the org has no overrides,
// or the lookup fails (fail-safe). This is the orchestrator response plane's
// sibling of agent.ResolveGatewayDetectionConfig.
func ResolveGatewayDetectionConfig(ctx context.Context, orgID string) agent.ModeDetectionConfig {
	return applyOrgDetectionOverrides(orgDetectionOverrides(ctx, orgID), agent.GetGatewayDetectionConfig())
}

// applyOrgDetectionOverrides layers a per-category override map onto base. base
// is returned UNCHANGED (same value) whenever no override applies, so a
// global-only deployment is byte-identical to today.
func applyOrgDetectionOverrides(overrides map[string]agent.DetectionAction, base agent.ModeDetectionConfig) agent.ModeDetectionConfig {
	if len(overrides) == 0 {
		return base
	}
	out := base
	if a, ok := overrides[agent.DetectionCategoryPII]; ok {
		out.PIIAction = a
	}
	if a, ok := overrides[agent.DetectionCategorySQLI]; ok {
		out.SQLIAction = a
	}
	if a, ok := overrides[agent.DetectionCategoryDangerousQuery]; ok {
		out.DangerousQueryAction = a
	}
	if a, ok := overrides[agent.DetectionCategoryDangerousCommand]; ok {
		out.DangerousCommandAction = a
	}
	return out
}

// ResolveGatewayPIIActionOverride returns orgID's EXPLICIT per-org PII action and
// true when one is set, or ("", false) otherwise. It is distinct from
// ResolveGatewayDetectionConfig: callers that must distinguish "this org has no
// override, use the deployment-global behavior unchanged" from "this org
// explicitly set warn/log/redact/block" need the boolean — notably the
// ProcessResponse skipRedaction (detect-don't-modify vs redact) decision, which
// must stay byte-identical to the deployment-global PII_ACTION baseline when an
// org has no explicit override.
func ResolveGatewayPIIActionOverride(ctx context.Context, orgID string) (agent.DetectionAction, bool) {
	a, ok := orgDetectionOverrides(ctx, orgID)[agent.DetectionCategoryPII]
	return a, ok
}
