package policy

import (
	"sync"
	"sync/atomic"
	"time"
)

// PolicyCache provides thread-safe caching of compiled policies.
// It uses a TTL-based expiration strategy with per-tenant isolation.
type PolicyCache struct {
	mu sync.RWMutex

	// Per-tenant policy cache
	// Key: tenantID (or "global" for system policies)
	// Value: cachedPolicies
	tenantCache map[string]*cachedPolicies

	// Configuration
	ttl time.Duration

	// Statistics (atomic for lock-free reads)
	hits   int64
	misses int64

	// Last refresh tracking
	lastRefresh     time.Time
	refreshDuration time.Duration
}

// cachedPolicies holds policies for a single tenant with expiration.
type cachedPolicies struct {
	// Request-phase policies (sorted by priority)
	requestPolicies []CompiledPolicy

	// Response-phase policies (sorted by priority)
	responsePolicies []CompiledPolicy

	// Expiration time
	expiresAt time.Time

	// Organization ID (nil for tenant-level)
	orgID *string
}

// NewPolicyCache creates a new policy cache with the specified TTL.
func NewPolicyCache(ttl time.Duration, maxPatterns int) *PolicyCache {
	return &PolicyCache{
		tenantCache: make(map[string]*cachedPolicies),
		ttl:         ttl,
	}
}

// Get retrieves policies for a tenant and phase from the cache.
// Returns (policies, found) where found is true if cache hit.
func (c *PolicyCache) Get(tenantID string, orgID *string, phase Phase) ([]CompiledPolicy, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.cacheKey(tenantID, orgID)
	cached, exists := c.tenantCache[key]
	if !exists {
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	// Check expiration
	if time.Now().After(cached.expiresAt) {
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	atomic.AddInt64(&c.hits, 1)

	// Return appropriate policies for phase
	switch phase {
	case PhaseRequest:
		return cached.requestPolicies, true
	case PhaseResponse:
		return cached.responsePolicies, true
	case PhaseBoth:
		// Return all policies (deduplicated)
		return c.mergePolicies(cached.requestPolicies, cached.responsePolicies), true
	default:
		return nil, false
	}
}

// Set stores policies for a tenant in the cache.
// Policies are automatically separated by phase.
func (c *PolicyCache) Set(tenantID string, orgID *string, policies []CompiledPolicy) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.cacheKey(tenantID, orgID)

	// Separate policies by phase
	var requestPolicies, responsePolicies []CompiledPolicy

	for _, p := range policies {
		switch p.Phase {
		case PhaseRequest:
			requestPolicies = append(requestPolicies, p)
		case PhaseResponse:
			responsePolicies = append(responsePolicies, p)
		case PhaseBoth:
			requestPolicies = append(requestPolicies, p)
			responsePolicies = append(responsePolicies, p)
		}
	}

	// Sort by priority (higher first)
	sortByPriority(requestPolicies)
	sortByPriority(responsePolicies)

	c.tenantCache[key] = &cachedPolicies{
		requestPolicies:  requestPolicies,
		responsePolicies: responsePolicies,
		expiresAt:        time.Now().Add(c.ttl),
		orgID:            orgID,
	}
}

// Invalidate removes cached policies for a tenant.
func (c *PolicyCache) Invalidate(tenantID string, orgID *string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.cacheKey(tenantID, orgID)
	delete(c.tenantCache, key)
}

// InvalidateAll clears the entire cache.
func (c *PolicyCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.tenantCache = make(map[string]*cachedPolicies)
}

// GetStats returns cache statistics.
func (c *PolicyCache) GetStats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalPolicies := 0
	for _, cached := range c.tenantCache {
		totalPolicies += len(cached.requestPolicies) + len(cached.responsePolicies)
	}

	return CacheStats{
		TotalPolicies:   totalPolicies,
		CachedTenants:   len(c.tenantCache),
		CacheHits:       atomic.LoadInt64(&c.hits),
		CacheMisses:     atomic.LoadInt64(&c.misses),
		LastRefresh:     c.lastRefresh,
		RefreshDuration: c.refreshDuration,
	}
}

// SetLastRefresh records when the cache was last refreshed.
func (c *PolicyCache) SetLastRefresh(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastRefresh = time.Now()
	c.refreshDuration = duration
}

// cacheKey generates a unique cache key for tenant/org combination.
func (c *PolicyCache) cacheKey(tenantID string, orgID *string) string {
	if orgID != nil {
		return tenantID + ":" + *orgID
	}
	return tenantID
}

// mergePolicies combines two policy slices, removing duplicates by PolicyID.
func (c *PolicyCache) mergePolicies(a, b []CompiledPolicy) []CompiledPolicy {
	seen := make(map[string]bool)
	var result []CompiledPolicy

	for _, p := range a {
		if !seen[p.PolicyID] {
			seen[p.PolicyID] = true
			result = append(result, p)
		}
	}

	for _, p := range b {
		if !seen[p.PolicyID] {
			seen[p.PolicyID] = true
			result = append(result, p)
		}
	}

	return result
}

// sortByPriority sorts policies by priority (descending) in place.
func sortByPriority(policies []CompiledPolicy) {
	// Simple insertion sort (policies are usually small lists)
	for i := 1; i < len(policies); i++ {
		j := i
		for j > 0 && policies[j].Priority > policies[j-1].Priority {
			policies[j], policies[j-1] = policies[j-1], policies[j]
			j--
		}
	}
}

// PatternCache provides thread-safe caching of compiled regex patterns.
type PatternCache struct {
	mu    sync.RWMutex
	cache map[string]*cachedPattern
	max   int
	count int
}

// cachedPattern holds a compiled pattern with usage tracking.
type cachedPattern struct {
	pattern  *CompiledPolicy
	lastUsed time.Time
}

// NewPatternCache creates a new pattern cache with maximum size.
func NewPatternCache(maxSize int) *PatternCache {
	return &PatternCache{
		cache: make(map[string]*cachedPattern),
		max:   maxSize,
	}
}

// Get retrieves a compiled pattern from the cache.
func (c *PatternCache) Get(patternStr string) (*CompiledPolicy, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if cached, exists := c.cache[patternStr]; exists {
		cached.lastUsed = time.Now()
		return cached.pattern, true
	}
	return nil, false
}

// Set stores a compiled pattern in the cache.
// If the cache is full, the least recently used pattern is evicted.
func (c *PatternCache) Set(patternStr string, pattern *CompiledPolicy) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if already cached
	if _, exists := c.cache[patternStr]; exists {
		c.cache[patternStr].pattern = pattern
		c.cache[patternStr].lastUsed = time.Now()
		return
	}

	// Evict if full
	if c.count >= c.max {
		c.evictLRU()
	}

	c.cache[patternStr] = &cachedPattern{
		pattern:  pattern,
		lastUsed: time.Now(),
	}
	c.count++
}

// evictLRU removes the least recently used pattern.
func (c *PatternCache) evictLRU() {
	var oldestKey string
	var oldestTime time.Time

	for key, cached := range c.cache {
		if oldestKey == "" || cached.lastUsed.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.lastUsed
		}
	}

	if oldestKey != "" {
		delete(c.cache, oldestKey)
		c.count--
	}
}

// Size returns the current number of cached patterns.
func (c *PatternCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.count
}
