// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package agent provides the AxonFlow Agent service.
//
// This file implements the tier-aware policy evaluation engine for ADR-018/ADR-020.
// It provides:
//   - Tier hierarchy enforcement: System → Organization → Tenant
//   - Override application: Enterprise customers can downgrade system policy actions
//   - Caching with configurable TTL: Default 5-minute cache for effective policies
//   - Integration with StaticPolicyRepository for database-backed policies
package agent

import (
	"context"
	"database/sql"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
)

// Default cache settings
const (
	// DefaultEffectivePolicyCacheTTL is the default time-to-live for effective policy cache.
	DefaultEffectivePolicyCacheTTL = 5 * time.Minute

	// MinEffectivePolicyCacheTTL is the minimum TTL allowed.
	MinEffectivePolicyCacheTTL = 30 * time.Second

	// MaxEffectivePolicyCacheTTL is the maximum TTL allowed.
	MaxEffectivePolicyCacheTTL = 30 * time.Minute

	// MaxPatternCacheSize prevents unbounded memory growth from unique patterns.
	MaxPatternCacheSize = 1000
)

// TierAwarePolicyEngine provides tier-aware policy evaluation with caching.
// It respects the policy tier hierarchy (System > Organization > Tenant)
// and applies Enterprise overrides when present.
//
// Note: Overrides are applied via StaticPolicyRepository.GetEffective() which
// uses a LEFT JOIN to include override data. This engine does not need a
// separate PolicyOverrideRepository.
type TierAwarePolicyEngine struct {
	db         *sql.DB
	policyRepo *StaticPolicyRepository

	// Cache for compiled effective policies
	cacheMutex    sync.RWMutex
	policyCache   map[string]*tenantPolicyCache
	cacheTTL      time.Duration
	defaultTenant string // Used when no tenant specified

	// Compiled pattern cache (bounded by MaxPatternCacheSize)
	patternMutex   sync.RWMutex
	compiledRegexp map[string]*regexp.Regexp
}

// tenantPolicyCache holds cached policies for a specific tenant.
type tenantPolicyCache struct {
	policies      []EffectiveStaticPolicy
	byCategory    map[PolicyCategory][]EffectiveStaticPolicy
	byTier        map[PolicyTier][]EffectiveStaticPolicy
	compiledAt    time.Time
	expiresAt     time.Time
	policyCount   int
	overrideCount int
}

// TierAwarePolicyEngineConfig configures the tier-aware policy engine.
type TierAwarePolicyEngineConfig struct {
	CacheTTL      time.Duration
	DefaultTenant string
}

// NewTierAwarePolicyEngine creates a new tier-aware policy engine.
func NewTierAwarePolicyEngine(db *sql.DB, config *TierAwarePolicyEngineConfig) *TierAwarePolicyEngine {
	if config == nil {
		config = &TierAwarePolicyEngineConfig{}
	}

	cacheTTL := config.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = DefaultEffectivePolicyCacheTTL
	} else if cacheTTL < MinEffectivePolicyCacheTTL {
		cacheTTL = MinEffectivePolicyCacheTTL
	} else if cacheTTL > MaxEffectivePolicyCacheTTL {
		cacheTTL = MaxEffectivePolicyCacheTTL
	}

	return &TierAwarePolicyEngine{
		db:             db,
		policyRepo:     NewStaticPolicyRepository(db),
		policyCache:    make(map[string]*tenantPolicyCache),
		cacheTTL:       cacheTTL,
		defaultTenant:  config.DefaultTenant,
		compiledRegexp: make(map[string]*regexp.Regexp),
	}
}

// GetEffectivePolicies returns effective policies for a tenant with caching.
// It respects tier priority and applies any active overrides.
//
// segmentIDs (ADR-060 #2989 P3) is the caller's resolved governance-segment
// set — see StaticPolicyRepository.GetEffective's doc for the selection
// contract (additive, orthogonal to tier; nil/empty is exactly pre-P3
// behavior). It is normalized (deduped + sorted) once here so the cache key
// (buildCacheKey) and the repository query both see a canonical form —
// callers passing the same logical set in a different order or with
// duplicates must hit the same cache entry, never a distinct one (a
// cache-key miss here would mean two requests for the identical resolved
// segment set redundantly hit the database, not a correctness bug, but
// still worth normalizing once at the entry point).
func (e *TierAwarePolicyEngine) GetEffectivePolicies(ctx context.Context, tenantID string, orgID *string, segmentIDs []string) ([]EffectiveStaticPolicy, error) {
	if tenantID == "" {
		tenantID = e.defaultTenant
	}
	normSegments := normalizeSegmentIDs(segmentIDs)

	cacheKey := e.buildCacheKey(tenantID, orgID, normSegments)

	// Try to get from cache first
	e.cacheMutex.RLock()
	cache, exists := e.policyCache[cacheKey]
	if exists && time.Now().Before(cache.expiresAt) {
		policies := cache.policies
		e.cacheMutex.RUnlock()
		return policies, nil
	}
	e.cacheMutex.RUnlock()

	// Cache miss or expired - fetch from database
	return e.refreshCache(ctx, tenantID, orgID, normSegments, cacheKey)
}

// GetEffectivePoliciesByCategory returns effective policies for a specific category.
func (e *TierAwarePolicyEngine) GetEffectivePoliciesByCategory(ctx context.Context, tenantID string, orgID *string, segmentIDs []string, category PolicyCategory) ([]EffectiveStaticPolicy, error) {
	policies, err := e.GetEffectivePolicies(ctx, tenantID, orgID, segmentIDs)
	if err != nil {
		return nil, err
	}

	cacheKey := e.buildCacheKey(tenantID, orgID, normalizeSegmentIDs(segmentIDs))
	e.cacheMutex.RLock()
	cache, exists := e.policyCache[cacheKey]
	e.cacheMutex.RUnlock()

	if exists && cache.byCategory != nil {
		if categoryPolicies, ok := cache.byCategory[category]; ok {
			return categoryPolicies, nil
		}
	}

	// Filter by category
	var result []EffectiveStaticPolicy
	for _, p := range policies {
		if PolicyCategory(p.Category) == category {
			result = append(result, p)
		}
	}
	return result, nil
}

// GetEffectivePoliciesByTier returns effective policies for a specific tier.
func (e *TierAwarePolicyEngine) GetEffectivePoliciesByTier(ctx context.Context, tenantID string, orgID *string, segmentIDs []string, tier PolicyTier) ([]EffectiveStaticPolicy, error) {
	policies, err := e.GetEffectivePolicies(ctx, tenantID, orgID, segmentIDs)
	if err != nil {
		return nil, err
	}

	cacheKey := e.buildCacheKey(tenantID, orgID, normalizeSegmentIDs(segmentIDs))
	e.cacheMutex.RLock()
	cache, exists := e.policyCache[cacheKey]
	e.cacheMutex.RUnlock()

	if exists && cache.byTier != nil {
		if tierPolicies, ok := cache.byTier[tier]; ok {
			return tierPolicies, nil
		}
	}

	// Filter by tier
	var result []EffectiveStaticPolicy
	for _, p := range policies {
		if p.Tier == tier {
			result = append(result, p)
		}
	}
	return result, nil
}

// EvaluatePolicy evaluates input against all effective policies for a tenant,
// combining the tier-effective result with any applicable segment policies
// per ADR-060 Decision 1 (additive, restriction-only — LOCKED): a segment can
// only TIGHTEN the outcome, never loosen it, and never participates in the
// Enterprise override-downgrade path. See combineTierAndSegmentResults for
// the combiner itself.
//
// When segmentIDs is empty (including every org with zero segment-scoped
// policies, regardless of what segmentIDs the caller passes), this is
// byte-identical to the pre-P3 single-pass "first tier/priority match wins"
// behavior: GetEffectivePolicies returns only segment_id IS NULL rows, the
// segment pass finds nothing to evaluate, and the combiner returns the tier
// result unchanged.
func (e *TierAwarePolicyEngine) EvaluatePolicy(ctx context.Context, tenantID string, orgID *string, segmentIDs []string, input string, sc TierShadowContext) (*PolicyEvaluationResult, error) {
	policies, err := e.GetEffectivePolicies(ctx, tenantID, orgID, segmentIDs)
	if err != nil {
		return nil, err
	}

	startTime := time.Now()
	// ADR-065 decision shadow (#3564). Nil when the shadow could not observe;
	// every method on a nil trace is a no-op.
	trace := newTierShadowTrace(policies)
	tierPolicies, segmentPolicies := splitBySegment(policies)

	tierResult := e.evaluateFirstMatch(tierPolicies, input, trace)
	segmentResult := e.evaluateStrictestMatch(segmentPolicies, input, trace)
	result := combineTierAndSegmentResults(tierResult, segmentResult)
	result.EvaluationTimeMs = time.Since(startTime).Milliseconds()

	// The at-most-two rows the combined verdict rests on. Built from the two
	// walks' own results rather than from the combined one, because the
	// combiner returns ONE result and the determining set is the union of what
	// each walk contributed before it chose.
	determining := map[string]bool{}
	if tierResult != nil && tierResult.Matched {
		determining[tierResult.PolicyID] = true
	}
	if segmentResult != nil && segmentResult.Matched {
		determining[segmentResult.PolicyID] = true
	}
	loadScope := tenantID
	if orgID != nil && *orgID != "" {
		loadScope = *orgID
	}
	// LAST, after the verdict is final. It returns nothing.
	//
	// NO `result == nil` GUARD HERE, and its absence is deliberate.
	// combineTierAndSegmentResults returns one of its two arguments, and
	// neither evaluateFirstMatch nor evaluateStrictestMatch can return nil -
	// every return in both is a non-nil pointer. `result` is already
	// dereferenced unconditionally two statements above, so a guard here would
	// assert a possibility that statement has already ruled out. staticcheck
	// says so (SA5011), and it is right: the guard did not add safety, it
	// added a contradiction. isBlockingTierAction is nil-safe on its own
	// account, which is the level a nil belongs at if one ever arrives.
	trace.emit(ctx, sc, loadScope, segmentIDs, determining, !isBlockingTierAction(result))

	return result, nil
}

// isBlockingTierAction reports whether a tier verdict stops the request.
//
// It is the executability question the shadow compares on, and it is answered
// from the ACTION rather than from a boolean, because PolicyEvaluationResult
// on this plane carries no Allowed field - the caller decides what to do with
// the action. block and require_approval both stop the request in the running
// system (require_approval sets no CHALLENGE state anywhere in the legacy
// engines; it refuses and appends a marker), and everything else lets it
// through.
func isBlockingTierAction(r *PolicyEvaluationResult) bool {
	if r == nil || !r.Matched {
		return false
	}
	switch OverrideAction(r.Action) {
	case ActionBlock, ActionRequireApproval:
		return true
	default:
		return false
	}
}

// evaluateFirstMatch is the EXACT pre-P3 EvaluatePolicy algorithm (unchanged
// byte-for-byte): walk policies in their existing tier/priority sort order
// and return the first pattern match. This is deliberately NOT
// "most-restrictive wins" — that is the existing, preserved tier-effective
// semantics (system→org→tenant + override-downgrade), which ADR-060 Decision
// 1 requires this combiner leave untouched. Never called with segment-scoped
// policies mixed in (see splitBySegment) — interleaving a segment row into
// this order-dependent walk could let a WEAKER segment match pre-empt a
// stronger tier match purely by sort position, which would be a loosening
// bug (the exact R3 risk this split exists to rule out).
func (e *TierAwarePolicyEngine) evaluateFirstMatch(policies []EffectiveStaticPolicy, input string, trace *tierShadowTrace) *PolicyEvaluationResult {
	for _, policy := range policies {
		if !policy.EffectiveEnabled() {
			continue
		}
		re, err := e.getCompiledPattern(policy.Pattern)
		if err != nil {
			log.Printf("[TierAwarePolicyEngine] Error compiling pattern for policy %s: %v", policy.PolicyID, err)
			continue
		}
		// The pattern is about to be RUN. Marked here rather than at the top
		// of the loop, because a disabled row and a row whose pattern will not
		// compile were both never looked at - and this walk RETURNS on the
		// first match, so every row after the winner was never looked at
		// either. That is the tri-state distinction ADR-065 turns into an
		// unknown attribute.
		trace.markRan(policy.PolicyID)
		if re.MatchString(input) {
			trace.markMatched(policy.PolicyID, policy.EffectiveAction())
			return &PolicyEvaluationResult{
				Matched:        true,
				PolicyID:       policy.PolicyID,
				PolicyName:     policy.Name,
				Category:       policy.Category,
				Tier:           policy.Tier,
				Action:         policy.EffectiveAction(),
				Severity:       policy.Severity,
				Description:    policy.Description,
				HasOverride:    policy.HasOverride,
				OverrideReason: policy.OverrideReason,
			}
		}
	}
	return &PolicyEvaluationResult{Matched: false}
}

// evaluateStrictestMatch scans ALL matching segment-scoped policies (already
// filtered to the caller's resolved segment set by GetEffectivePolicies) and
// returns the single MOST RESTRICTIVE match by OverrideAction ordering
// (block > require_approval > redact > warn > log), never merely the first
// in sort order — "strictest applicable segment policy" (ADR-060 §"Combining
// multiple segments") is a restrictiveness ranking, not a priority ranking.
//
// Deliberately reads policy.Action / policy.Enabled (the RAW columns), never
// EffectiveAction() / EffectiveEnabled() (which fold in override fields) —
// this is belt-and-suspenders on top of GetEffective's own override-JOIN
// exclusion + field-stripping for segment rows (ADR-060 Decision 1: a
// segment policy must never enter the override-downgrade path). Reading the
// Effective* accessors here would trust HasOverride/OverrideAction/
// OverrideEnabled on a segment row if they were EVER non-zero — whether from
// a defect in GetEffective, a future refactor, or a caller constructing an
// EffectiveStaticPolicy directly (as tests do) — and an OverrideEnabled=
// false would even let an override silently DISABLE a segment block policy
// outright, a loosening path strictly worse than a downgraded action. Using
// the raw fields makes that whole class of bug structurally unreachable from
// this function, independent of what the repository layer does.
func (e *TierAwarePolicyEngine) evaluateStrictestMatch(policies []EffectiveStaticPolicy, input string, trace *tierShadowTrace) *PolicyEvaluationResult {
	var best *PolicyEvaluationResult
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		re, err := e.getCompiledPattern(policy.Pattern)
		if err != nil {
			log.Printf("[TierAwarePolicyEngine] Error compiling segment pattern for policy %s: %v", policy.PolicyID, err)
			continue
		}
		trace.markRan(policy.PolicyID)
		if !re.MatchString(input) {
			continue
		}
		// Deliberately policy.Action, the RAW column, matching this walk's own
		// rule two lines below: reading EffectiveAction() here would report an
		// override-folded action for a segment row that never enters the
		// override path, which is the loosening this function is written to
		// make structurally unreachable.
		trace.markMatched(policy.PolicyID, policy.Action)
		candidate := &PolicyEvaluationResult{
			Matched:        true,
			PolicyID:       policy.PolicyID,
			PolicyName:     policy.Name,
			Category:       policy.Category,
			Tier:           policy.Tier,
			Action:         policy.Action,
			Severity:       policy.Severity,
			Description:    policy.Description,
			HasOverride:    false,
			OverrideReason: "",
		}
		if best == nil || ActionRestrictiveness(OverrideAction(candidate.Action)) > ActionRestrictiveness(OverrideAction(best.Action)) {
			best = candidate
		}
	}
	if best == nil {
		return &PolicyEvaluationResult{Matched: false}
	}
	return best
}

// combineTierAndSegmentResults is the ADR-060 Decision 1 combiner (LOCKED,
// additive restriction-only): effective = strictest(tier_effective,
// strictest applicable segment policy). Segments only ADD restriction:
//   - No segment match -> tier result verbatim (byte-identical to pre-P3;
//     also covers "no segment-scoped policies for this org at all").
//   - No tier match, but a segment matches -> the segment result alone: a
//     segment-only block policy (no corresponding org/tenant/system policy)
//     must still fire — required by the runtime-e2e "member of segment X
//     with a segment-X block policy is blocked" gate.
//   - Both match -> whichever action is MORE restrictive wins; a tie prefers
//     the tier result (deterministic, and keeps existing PolicyID/Tier
//     attribution stable for callers used to today's single-result shape).
//     A tie can never mean the segment loosened anything, by construction —
//     ActionRestrictiveness is compared, never overwritten downward.
func combineTierAndSegmentResults(tier, segment *PolicyEvaluationResult) *PolicyEvaluationResult {
	if segment == nil || !segment.Matched {
		return tier
	}
	if tier == nil || !tier.Matched {
		return segment
	}
	if ActionRestrictiveness(OverrideAction(segment.Action)) > ActionRestrictiveness(OverrideAction(tier.Action)) {
		return segment
	}
	return tier
}

// splitBySegment partitions an already tier/priority-sorted effective-policy
// list into (tier-scoped, segment-scoped) sublists, preserving each side's
// relative order. tierPolicies (segment_id == nil) is therefore, for an org
// with zero segment-scoped policies, IDENTICAL to the full input slice —
// which is exactly what makes evaluateFirstMatch(tierPolicies, ...)
// byte-identical to the pre-P3 single-list walk in that case.
func splitBySegment(policies []EffectiveStaticPolicy) (tierPolicies, segmentPolicies []EffectiveStaticPolicy) {
	for _, p := range policies {
		if p.SegmentID != nil && *p.SegmentID != "" {
			segmentPolicies = append(segmentPolicies, p)
		} else {
			tierPolicies = append(tierPolicies, p)
		}
	}
	return tierPolicies, segmentPolicies
}

// normalizeSegmentIDs dedupes, drops empty entries, and sorts a caller-
// supplied segment-ID set so the cache key (buildCacheKey) and the
// repository selection query both see one canonical form regardless of the
// order or duplication the caller happened to pass — required so two
// requests resolving to the SAME logical segment set (e.g. ["b","a"] and
// ["a","b","a"]) hit the SAME cache entry rather than needlessly bypassing
// the cache, and so a cache key can never accidentally differ (or collide)
// based on incidental ordering. Returns nil (never a non-nil empty slice)
// for an empty/all-empty input, matching the "no segments" contract used
// throughout (GetEffective/buildCacheKey treat nil and [] identically).
// Thin wrapper over platform/shared/identity.NormalizeSegmentIDs, the single
// implementation shared with platform/orchestrator's function of the same
// name (#3239 round 2 extraction).
func normalizeSegmentIDs(segmentIDs []string) []string {
	return sharedidentity.NormalizeSegmentIDs(segmentIDs)
}

// EvaluateAllPolicies evaluates input against all effective policies and returns all matches.
// This is useful for comprehensive policy reporting.
//
// segmentIDs threads through to GetEffectivePolicies exactly like
// EvaluatePolicy. Unlike EvaluatePolicy's order-dependent first-match walk,
// this method's aggregate outputs (ShouldBlock = OR across every match,
// HighestSeverity = MAX across every match) are already monotonic in the
// number of matched policies — adding segment-scoped rows to the same
// evaluated set can only ever add matches, which can only turn ShouldBlock
// true or raise HighestSeverity, never the reverse — so no separate
// tier/segment combiner is needed here for ADR-060 Decision 1 to hold: it
// falls out of the existing OR/MAX aggregation once segment rows carry no
// override (already enforced by GetEffective, see its doc).
func (e *TierAwarePolicyEngine) EvaluateAllPolicies(ctx context.Context, tenantID string, orgID *string, segmentIDs []string, input string) (*PolicyEvaluationResults, error) {
	policies, err := e.GetEffectivePolicies(ctx, tenantID, orgID, segmentIDs)
	if err != nil {
		return nil, err
	}

	startTime := time.Now()
	results := &PolicyEvaluationResults{
		Input:    input,
		Matches:  make([]PolicyEvaluationResult, 0),
		Checked:  0,
		TenantID: tenantID,
	}
	if orgID != nil {
		results.OrgID = *orgID
	}

	var highestSeverity string
	var shouldBlock bool

	for _, policy := range policies {
		results.Checked++

		// Skip disabled policies
		if !policy.EffectiveEnabled() {
			continue
		}

		re, err := e.getCompiledPattern(policy.Pattern)
		if err != nil {
			continue
		}

		if re.MatchString(input) {
			result := PolicyEvaluationResult{
				Matched:        true,
				PolicyID:       policy.PolicyID,
				PolicyName:     policy.Name,
				Category:       policy.Category,
				Tier:           policy.Tier,
				Action:         policy.EffectiveAction(),
				Severity:       policy.Severity,
				Description:    policy.Description,
				HasOverride:    policy.HasOverride,
				OverrideReason: policy.OverrideReason,
			}
			results.Matches = append(results.Matches, result)

			// Track highest severity and block status
			if compareSeverity(policy.Severity, highestSeverity) > 0 {
				highestSeverity = policy.Severity
			}
			if result.Action == "block" {
				shouldBlock = true
			}
		}
	}

	results.HighestSeverity = highestSeverity
	results.ShouldBlock = shouldBlock
	results.EvaluationTimeMs = time.Since(startTime).Milliseconds()

	return results, nil
}

// InvalidateCache invalidates the cache for a specific tenant/org, including
// every segment-scoped cache entry for that same (tenantID, orgID) pair
// (ADR-060 #2989 P3): buildCacheKey now appends a sorted segment suffix, so
// a plain exact-key delete keyed on (tenantID, orgID) alone would leave every
// segment-keyed variant stale after a policy edit — an admin editing (or
// adding) a segment-scoped policy would not see it take effect until the
// unrelated cache TTL expired. This deletes the base (no-segment) key plus
// every "base:seg=..." key, and nothing belonging to a DIFFERENT
// (tenantID, orgID) pair (the base+":seg=" prefix match is anchored to the
// exact base string, not a loose substring match).
func (e *TierAwarePolicyEngine) InvalidateCache(tenantID string, orgID *string) {
	base := e.buildCacheKey(tenantID, orgID, nil)
	segPrefix := base + ":seg="
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()
	for k := range e.policyCache {
		if k == base || strings.HasPrefix(k, segPrefix) {
			delete(e.policyCache, k)
		}
	}
}

// InvalidateAllCaches invalidates all tenant caches.
func (e *TierAwarePolicyEngine) InvalidateAllCaches() {
	e.cacheMutex.Lock()
	e.policyCache = make(map[string]*tenantPolicyCache)
	e.cacheMutex.Unlock()
}

// GetCacheStats returns statistics about the policy cache.
func (e *TierAwarePolicyEngine) GetCacheStats() map[string]interface{} {
	e.cacheMutex.RLock()
	defer e.cacheMutex.RUnlock()

	stats := map[string]interface{}{
		"total_tenants_cached": len(e.policyCache),
		"cache_ttl_seconds":    e.cacheTTL.Seconds(),
	}

	var totalPolicies, totalOverrides int
	for _, cache := range e.policyCache {
		totalPolicies += cache.policyCount
		totalOverrides += cache.overrideCount
	}

	stats["total_policies_cached"] = totalPolicies
	stats["total_overrides_cached"] = totalOverrides

	return stats
}

// refreshCache fetches policies from database and updates the cache.
func (e *TierAwarePolicyEngine) refreshCache(ctx context.Context, tenantID string, orgID *string, segmentIDs []string, cacheKey string) ([]EffectiveStaticPolicy, error) {
	// Fetch effective policies from repository
	policies, err := e.policyRepo.GetEffective(ctx, tenantID, orgID, segmentIDs)
	if err != nil {
		log.Printf("[TierAwarePolicyEngine] Error fetching effective policies: %v", err)
		return nil, err
	}

	// Sort by tier priority (System > Organization > Tenant) and then by priority
	sortPoliciesByTierAndPriority(policies)

	// Build category and tier indices
	byCategory := make(map[PolicyCategory][]EffectiveStaticPolicy)
	byTier := make(map[PolicyTier][]EffectiveStaticPolicy)
	var overrideCount int

	for _, p := range policies {
		category := PolicyCategory(p.Category)
		byCategory[category] = append(byCategory[category], p)
		byTier[p.Tier] = append(byTier[p.Tier], p)
		if p.HasOverride {
			overrideCount++
		}
	}

	// Create cache entry
	now := time.Now()
	cache := &tenantPolicyCache{
		policies:      policies,
		byCategory:    byCategory,
		byTier:        byTier,
		compiledAt:    now,
		expiresAt:     now.Add(e.cacheTTL),
		policyCount:   len(policies),
		overrideCount: overrideCount,
	}

	// Update cache
	e.cacheMutex.Lock()
	e.policyCache[cacheKey] = cache
	e.cacheMutex.Unlock()

	log.Printf("[TierAwarePolicyEngine] Cached %d policies (%d overrides) for tenant %s (TTL: %v)",
		len(policies), overrideCount, tenantID, e.cacheTTL)

	return policies, nil
}

// buildCacheKey creates a cache key from tenant ID, org ID, and the resolved
// segment set (ADR-060 #2989 P3). segmentIDs MUST already be normalized
// (normalizeSegmentIDs — deduped + sorted) by the caller: GetEffectivePolicies
// does this once at the entry point so every reader of the cache (including
// InvalidateCache) agrees on one canonical key shape. A caller passing an
// un-normalized set here directly (bypassing GetEffectivePolicies) would
// fragment the cache across order/duplicate variants of the SAME logical
// segment set — not a correctness bug (each variant still selects the right
// policies), but a cache-efficiency footgun and a way to defeat the
// same-request-same-key invariant InvalidateCache relies on. Segments are
// appended as a THIRD, clearly delimited component precisely so a
// segment-scoped entry never collides with — or gets read back as — the
// base (no-segment) entry for the same tenant/org (would otherwise be
// cross-segment/cross-org policy bleed: R3 focus item).
func (e *TierAwarePolicyEngine) buildCacheKey(tenantID string, orgID *string, segmentIDs []string) string {
	key := tenantID
	if orgID != nil && *orgID != "" {
		key += ":" + *orgID
	}
	if len(segmentIDs) > 0 {
		key += ":seg=" + strings.Join(segmentIDs, ",")
	}
	return key
}

// getCompiledPattern returns a compiled regex pattern, using cache when possible.
func (e *TierAwarePolicyEngine) getCompiledPattern(pattern string) (*regexp.Regexp, error) {
	e.patternMutex.RLock()
	re, exists := e.compiledRegexp[pattern]
	e.patternMutex.RUnlock()

	if exists {
		return re, nil
	}

	// Compile pattern
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	// Cache if under size limit (prevents unbounded memory growth)
	e.patternMutex.Lock()
	if len(e.compiledRegexp) < MaxPatternCacheSize {
		e.compiledRegexp[pattern] = re
	}
	e.patternMutex.Unlock()

	return re, nil
}

// sortPoliciesByTierAndPriority sorts policies by tier (System first) then by priority (descending).
func sortPoliciesByTierAndPriority(policies []EffectiveStaticPolicy) {
	// Simple bubble sort since we typically have <100 policies
	for i := 0; i < len(policies)-1; i++ {
		for j := 0; j < len(policies)-i-1; j++ {
			if shouldSwap(policies[j], policies[j+1]) {
				policies[j], policies[j+1] = policies[j+1], policies[j]
			}
		}
	}
}

// shouldSwap returns true if a should come after b in the sorted order.
func shouldSwap(a, b EffectiveStaticPolicy) bool {
	// Tier priority: System (0) > Organization (1) > Tenant (2)
	tierOrder := map[PolicyTier]int{
		TierSystem:       0,
		TierOrganization: 1,
		TierTenant:       2,
	}

	aTier := tierOrder[a.Tier]
	bTier := tierOrder[b.Tier]

	if aTier != bTier {
		return aTier > bTier // Higher tier value comes later
	}

	// Same tier: sort by priority descending (higher priority first)
	return a.Priority < b.Priority
}

// compareSeverity returns positive if a is more severe than b.
func compareSeverity(a, b string) int {
	order := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}
	return order[a] - order[b]
}

// PolicyEvaluationResult contains the result of evaluating a single policy.
type PolicyEvaluationResult struct {
	Matched          bool       `json:"matched"`
	PolicyID         string     `json:"policy_id,omitempty"`
	PolicyName       string     `json:"policy_name,omitempty"`
	Category         string     `json:"category,omitempty"`
	Tier             PolicyTier `json:"tier,omitempty"`
	Action           string     `json:"action,omitempty"`
	Severity         string     `json:"severity,omitempty"`
	Description      string     `json:"description,omitempty"`
	HasOverride      bool       `json:"has_override,omitempty"`
	OverrideReason   string     `json:"override_reason,omitempty"`
	EvaluationTimeMs int64      `json:"evaluation_time_ms"`
}

// PolicyEvaluationResults contains results from evaluating all policies.
type PolicyEvaluationResults struct {
	Input            string                   `json:"input"`
	Matches          []PolicyEvaluationResult `json:"matches"`
	Checked          int                      `json:"checked"`
	HighestSeverity  string                   `json:"highest_severity,omitempty"`
	ShouldBlock      bool                     `json:"should_block"`
	TenantID         string                   `json:"tenant_id"`
	OrgID            string                   `json:"org_id,omitempty"`
	EvaluationTimeMs int64                    `json:"evaluation_time_ms"`
}
