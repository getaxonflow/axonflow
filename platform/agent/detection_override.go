// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"log"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/detectionposture"
)

// Per-(org, category) detection-action overrides (#2581) - the ONLY thing that
// may replace a policy's stored action (#3961).
//
// An organization may choose a different action per detection category in the
// detection_action_overrides table (mig 120). The table is written through
// platform/shared/detectionposture - by the customer portal's detection-posture
// API, and by the Community SaaS registration for the sqli=block every new
// organization starts with (#4017) - which records the actor in updated_by and
// writes an admin_audit_log row for every set and delete in the same
// transaction, so an override is an authored, attributable change - the property the environment
// variables it once sat on top of never had, and the reason those are gone
// (RemovedPostureEnvVars). The MCP + gateway check paths consult a SHORT-TTL
// per-org cache:
//
//	effective action = per-org override (if any) ELSE the stored policy action
//
// HOT-PATH SAFETY: resolution NEVER does a per-request DB query — the cache
// serves the org's overrides for the TTL window and is refreshed lazily on miss.
//
// FAIL-SAFE: a lookup error (DB down, table absent, schema drift) resolves no
// override, so the stored policy actions decide — NEVER "no governance". The
// error is cached for a short window so a failing DB cannot be hammered on the
// hot path.
//
// NO OVERRIDE: with no override rows (or no DB / cache not wired), resolution
// returns the process's mode config unchanged, whose action fields are empty,
// so every category keeps its stored action.

// Detection categories addressable by a per-org override. These map onto the
// four ModeDetectionConfig action fields. The string values are the table's
// `category` column (see the CHECK constraint in mig 120).
const (
	DetectionCategoryPII              = "pii"
	DetectionCategorySQLI             = "sqli"
	DetectionCategoryDangerousQuery   = "dangerous_query"
	DetectionCategoryDangerousCommand = "dangerous_command"

	// DetectionCategoryObligationFallback (#2958, mig 144) is NOT a detector —
	// it is the org's answer to "what should happen when a policy decided to
	// redact, but the PEP's seam cannot carry that out?" (e.g. an Envoy
	// ext_authz leg, which is headers-only and cannot rewrite a body).
	//
	// It lives in this table because it is the same shape — a per-org posture
	// lever consulted on the hot path through the same short-TTL cache — and it
	// could NOT ride the existing `pii` category: `pii=block` makes every PII
	// match block outright (BuildActionOverrides fans it onto every PII
	// category, and convertSharedResultToStatic only sets RequiresRedaction when
	// the result is NOT blocked), so no redact obligation can ever coexist with
	// it. Reusing `pii` would have produced a lever whose block branch is
	// unreachable by construction.
	//
	// Only `block` and `log` are meaningful (see ResolveObligationFallbackAction);
	// the portal write path rejects the other two for this category.
	DetectionCategoryObligationFallback = "obligation_fallback"
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
				// category keeps its stored policy action rather than coercing
				// to a wrong (possibly weaker) one.
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
	// err is a failed read, cached for the error window beside the empty set
	// get serves in its place; read serves the error.
	err error
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
// returns an error: on a lookup failure it caches + returns an empty set, so no
// override applies and the stored policy actions decide.
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
		// Fail-safe: cache an empty set briefly so the stored actions decide and
		// a failing DB is not re-hit on every request inside the error window.
		log.Printf("[Detection] WARNING: per-org override lookup failed for org %q — applying no override, the stored policy actions decide: %v", orgID, err)
		empty := map[string]DetectionAction{}
		c.mu.Lock()
		c.entries[orgID] = detectionOverrideCacheEntry{overrides: empty, expiresAt: now.Add(c.errTTL), err: err}
		c.mu.Unlock()
		return empty
	}

	c.mu.Lock()
	c.entries[orgID] = detectionOverrideCacheEntry{overrides: overrides, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()
	return overrides
}

// read returns orgID's recorded overrides, or the error that kept them from
// being read. It is the anchored engine's read (#4045): it never substitutes an
// empty set for a failed read, because an enforcing seam that cannot read an
// override fails closed rather than enforcing the shipped action the
// organization recorded a change to. A failure is cached for the error window,
// as get caches one, so a failing store is not re-read on every request.
func (c *detectionOverrideCache) read(ctx context.Context, orgID string) (map[string]DetectionAction, error) {
	now := time.Now()

	c.mu.RLock()
	entry, ok := c.entries[orgID]
	c.mu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		if entry.err != nil {
			return nil, entry.err
		}
		return entry.overrides, nil
	}

	overrides, err := c.reader.ReadOrgOverrides(ctx, orgID)
	if err != nil {
		c.mu.Lock()
		c.entries[orgID] = detectionOverrideCacheEntry{overrides: map[string]DetectionAction{}, expiresAt: now.Add(c.errTTL), err: err}
		c.mu.Unlock()
		return nil, err
	}
	c.mu.Lock()
	c.entries[orgID] = detectionOverrideCacheEntry{overrides: overrides, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()
	return overrides, nil
}

// invalidate drops orgID's cached entry so the next resolution re-reads. Called
// by the (follow-up) portal write path after an operator changes a posture.
func (c *detectionOverrideCache) invalidate(orgID string) {
	c.mu.Lock()
	delete(c.entries, orgID)
	c.mu.Unlock()
}

// Package-global cache, wired once at agent startup (DB mode only). nil when the
// agent runs without a DB (community / no-DB / most unit tests) → no override
// resolves and the stored policy actions decide.
var (
	globalDetectionOverrideCache   *detectionOverrideCache
	globalDetectionOverrideCacheMu sync.RWMutex
)

// InitDetectionOverrides wires the per-org override cache to db. Call once at
// agent startup AFTER the DB connection is open and AFTER InitDetectionConfigs.
// Safe to skip in no-DB mode (no override then resolves; stored actions decide).
func InitDetectionOverrides(db *sql.DB) {
	if db == nil {
		return
	}
	ttl := resolveDetectionOverrideTTL()
	cache := newDetectionOverrideCache(NewDetectionOverrideRepository(db), ttl)
	globalDetectionOverrideCacheMu.Lock()
	globalDetectionOverrideCache = cache
	globalDetectionOverrideCacheMu.Unlock()
	log.Printf("✅ Per-org detection-action overrides enabled (#2581; cache TTL %s, no override = stored policy action)", ttl)
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
// process's MCP mode config (GetMCPDetectionConfig) with the org's recorded
// overrides in its action fields. When orgID is empty, the override cache isn't
// wired, the org has no overrides, or the lookup fails, the action fields stay
// empty and every category keeps its stored policy action.
func ResolveMCPDetectionConfig(ctx context.Context, orgID string) ModeDetectionConfig {
	return applyOrgDetectionOverrides(ctx, orgID, GetMCPDetectionConfig())
}

// ResolveGatewayDetectionConfig is the gateway-surface sibling of
// ResolveMCPDetectionConfig.
func ResolveGatewayDetectionConfig(ctx context.Context, orgID string) ModeDetectionConfig {
	return applyOrgDetectionOverrides(ctx, orgID, GetGatewayDetectionConfig())
}

// applyOrgDetectionOverrides layers orgID's per-category overrides onto base.
// base is returned UNCHANGED (same value) whenever no override applies.
func applyOrgDetectionOverrides(ctx context.Context, orgID string, base ModeDetectionConfig) ModeDetectionConfig {
	if orgID == "" {
		return base // unauthenticated / community / internal-service with no org → stored actions
	}
	cache := getDetectionOverrideCache()
	if cache == nil {
		return base // no DB / cache not wired → stored actions
	}
	overrides := cache.get(ctx, orgID)
	if len(overrides) == 0 {
		return base // org has no overrides (or fail-safe empty) → stored actions
	}
	out, _ := layerRecordedOverrides(base, overrides)
	return out
}

// layerRecordedOverrides writes each recorded category's action into the config
// field that category sets, and returns the recorded categories no field
// carries, sorted: obligation_fallback, and any category the table's CHECK
// constraint does not admit. It is the legacy engine's reading of a recorded
// category; the anchored engine folds through detectionposture.
// AnchoredCategoryActions, and both reach the policy categories
// sharedpolicy.OrgOverrideReach names.
func layerRecordedOverrides(base ModeDetectionConfig, overrides map[string]DetectionAction) (ModeDetectionConfig, []string) {
	out := base
	var unlayered []string
	for category, a := range overrides {
		switch category {
		case DetectionCategoryPII:
			out.PIIAction = a
		case DetectionCategorySQLI:
			out.SQLIAction = a
		case DetectionCategoryDangerousQuery:
			out.DangerousQueryAction = a
		case DetectionCategoryDangerousCommand:
			out.DangerousCommandAction = a
		default:
			unlayered = append(unlayered, category)
		}
	}
	sort.Strings(unlayered)
	return out, unlayered
}

// anchoredCategoryActions is an organization's recorded overrides in the
// anchored compiler's key: detectionposture.AnchoredCategoryActions, the one
// fold the enforcing seam and both publication dry runs share (#4045).
func anchoredCategoryActions(recorded map[string]DetectionAction) (legacycompile.CategoryActions, error) {
	plain := make(map[string]string, len(recorded))
	for category, action := range recorded {
		plain[category] = string(action)
	}
	return detectionposture.AnchoredCategoryActions(plain)
}

// recordedAnchoredOverrides is the anchored enforcer's read of an organization's
// recorded overrides. A process with no override cache wired has no database, so
// no override is recorded anywhere and the legacy engine applies none either.
func recordedAnchoredOverrides(ctx context.Context, orgID string) (legacycompile.CategoryActions, error) {
	cache := getDetectionOverrideCache()
	if cache == nil || orgID == "" {
		return nil, nil
	}
	recorded, err := cache.read(ctx, orgID)
	if err != nil {
		return nil, err
	}
	return anchoredCategoryActions(recorded)
}

// ResolveObligationFallbackAction returns what to do when a policy decided a
// request body must be redacted but the calling PEP's seam cannot carry that
// out (#2958) — the org's obligation-fallback posture.
//
// DEFAULT is LOG: allow the request, emit NO obligation, and record the
// suppressed redaction + detected categories on the canonical audit row. That
// is the faithful degradation of what the org already asked for: an org whose
// policy redacts has said "mask it, don't block it" — i.e. it values
// continuity — so a seam that cannot mask degrades to detect-and-audit rather
// than to an outage. It is also what the alternative was: before this posture
// existed the adapter turned the PDP's allow into a local 403 and the org got
// neither the content nor an audit record.
//
// CONFIGURABLE to BLOCK for an org that refuses detect-and-log on content it
// wanted masked ("redact where you can, block where you can't" — a real
// preference that no existing lever could express). Set via the per-(org,
// category) override on the `obligation_fallback` category (mig 144), the same
// table + short-TTL cache as every other detection override.
//
// Anything OTHER than block/log stored for this category (only reachable by
// hand-editing the DB — the portal write path rejects them) falls back to the
// documented default with a rate-limited WARN. Failing toward `log` on a config
// typo is deliberate: the alternative is denying live traffic because someone
// typo'd a posture, and this lever's job is to make a non-capable seam
// governable, not to become a new outage source.
//
// Never returns an error: resolution is on the decide hot path, and the cache
// already fails SAFE to "no overrides" on a DB problem.
func ResolveObligationFallbackAction(ctx context.Context, orgID string) DetectionAction {
	if orgID == "" {
		return DetectionActionLog
	}
	cache := getDetectionOverrideCache()
	if cache == nil {
		return DetectionActionLog // no DB / cache not wired → documented default
	}
	action, ok := cache.get(ctx, orgID)[DetectionCategoryObligationFallback]
	if !ok {
		return DetectionActionLog // org set no posture → documented default
	}
	switch action {
	case DetectionActionBlock, DetectionActionLog:
		return action
	default:
		// redact / warn are meaningless here: "redact" is precisely what the
		// seam cannot do (it is why we are in this function at all), and "warn"
		// has no distinct enforcement from "log" on this axis.
		warnUnusableObligationFallback(orgID, action)
		return DetectionActionLog
	}
}

// obligationFallbackWarn rate-limits the unusable-posture WARN to at most one
// line per org per window, so a misconfigured org cannot flood the log from the
// decide hot path.
var obligationFallbackWarn = struct {
	mu   sync.Mutex
	last map[string]time.Time
}{last: map[string]time.Time{}}

// obligationFallbackWarnInterval is the per-org quiet period between WARNs.
const obligationFallbackWarnInterval = time.Minute

// warnUnusableObligationFallback logs (at most once per org per interval) that
// an org has a nonsense obligation_fallback action stored, naming the value and
// the default being applied instead.
//
// The map is keyed by org and bounded in practice by the org count of one
// deployment; entries are only created for orgs that actually hold an invalid
// posture, which the portal write path prevents — so this is a hand-edited-DB
// diagnostic, not a per-request allocation.
func warnUnusableObligationFallback(orgID string, action DetectionAction) {
	now := time.Now()
	obligationFallbackWarn.mu.Lock()
	last, seen := obligationFallbackWarn.last[orgID]
	quiet := seen && now.Sub(last) < obligationFallbackWarnInterval
	if !quiet {
		obligationFallbackWarn.last[orgID] = now
	}
	obligationFallbackWarn.mu.Unlock()
	if quiet {
		return
	}
	log.Printf("[Detection] WARNING: org %q has obligation_fallback=%q, which is not enforceable (only block|log are) — applying the default %q. Fix it via the detection-posture API.",
		orgID, action, DetectionActionLog)
}

// ResetObligationFallbackWarnForTest clears the WARN rate-limiter. Test-only.
func ResetObligationFallbackWarnForTest() {
	obligationFallbackWarn.mu.Lock()
	obligationFallbackWarn.last = map[string]time.Time{}
	obligationFallbackWarn.mu.Unlock()
}
