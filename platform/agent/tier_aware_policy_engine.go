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
	"sync"
	"time"
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
func (e *TierAwarePolicyEngine) GetEffectivePolicies(ctx context.Context, tenantID string, orgID *string) ([]EffectiveStaticPolicy, error) {
	if tenantID == "" {
		tenantID = e.defaultTenant
	}

	cacheKey := e.buildCacheKey(tenantID, orgID)

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
	return e.refreshCache(ctx, tenantID, orgID, cacheKey)
}

// GetEffectivePoliciesByCategory returns effective policies for a specific category.
func (e *TierAwarePolicyEngine) GetEffectivePoliciesByCategory(ctx context.Context, tenantID string, orgID *string, category PolicyCategory) ([]EffectiveStaticPolicy, error) {
	policies, err := e.GetEffectivePolicies(ctx, tenantID, orgID)
	if err != nil {
		return nil, err
	}

	cacheKey := e.buildCacheKey(tenantID, orgID)
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
func (e *TierAwarePolicyEngine) GetEffectivePoliciesByTier(ctx context.Context, tenantID string, orgID *string, tier PolicyTier) ([]EffectiveStaticPolicy, error) {
	policies, err := e.GetEffectivePolicies(ctx, tenantID, orgID)
	if err != nil {
		return nil, err
	}

	cacheKey := e.buildCacheKey(tenantID, orgID)
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

// EvaluatePolicy evaluates input against all effective policies for a tenant.
// Returns the first matching policy result or nil if no match.
func (e *TierAwarePolicyEngine) EvaluatePolicy(ctx context.Context, tenantID string, orgID *string, input string) (*PolicyEvaluationResult, error) {
	policies, err := e.GetEffectivePolicies(ctx, tenantID, orgID)
	if err != nil {
		return nil, err
	}

	startTime := time.Now()

	for _, policy := range policies {
		// Skip disabled policies (including those disabled via override)
		if !policy.EffectiveEnabled() {
			continue
		}

		// Get or compile pattern
		re, err := e.getCompiledPattern(policy.Pattern)
		if err != nil {
			log.Printf("[TierAwarePolicyEngine] Error compiling pattern for policy %s: %v", policy.PolicyID, err)
			continue
		}

		if re.MatchString(input) {
			return &PolicyEvaluationResult{
				Matched:          true,
				PolicyID:         policy.PolicyID,
				PolicyName:       policy.Name,
				Category:         policy.Category,
				Tier:             policy.Tier,
				Action:           policy.EffectiveAction(),
				Severity:         policy.Severity,
				Description:      policy.Description,
				HasOverride:      policy.HasOverride,
				OverrideReason:   policy.OverrideReason,
				EvaluationTimeMs: time.Since(startTime).Milliseconds(),
			}, nil
		}
	}

	return &PolicyEvaluationResult{
		Matched:          false,
		EvaluationTimeMs: time.Since(startTime).Milliseconds(),
	}, nil
}

// EvaluateAllPolicies evaluates input against all effective policies and returns all matches.
// This is useful for comprehensive policy reporting.
func (e *TierAwarePolicyEngine) EvaluateAllPolicies(ctx context.Context, tenantID string, orgID *string, input string) (*PolicyEvaluationResults, error) {
	policies, err := e.GetEffectivePolicies(ctx, tenantID, orgID)
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

// InvalidateCache invalidates the cache for a specific tenant.
func (e *TierAwarePolicyEngine) InvalidateCache(tenantID string, orgID *string) {
	cacheKey := e.buildCacheKey(tenantID, orgID)
	e.cacheMutex.Lock()
	delete(e.policyCache, cacheKey)
	e.cacheMutex.Unlock()
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
func (e *TierAwarePolicyEngine) refreshCache(ctx context.Context, tenantID string, orgID *string, cacheKey string) ([]EffectiveStaticPolicy, error) {
	// Fetch effective policies from repository
	policies, err := e.policyRepo.GetEffective(ctx, tenantID, orgID)
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

// buildCacheKey creates a cache key from tenant and org IDs.
func (e *TierAwarePolicyEngine) buildCacheKey(tenantID string, orgID *string) string {
	if orgID == nil || *orgID == "" {
		return tenantID
	}
	return tenantID + ":" + *orgID
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
