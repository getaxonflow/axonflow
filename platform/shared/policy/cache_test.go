package policy

import (
	"testing"
	"time"
)

func TestPolicyCache_SetAndGet(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)

	policies := []CompiledPolicy{
		{
			PolicyID: "test1",
			Phase:    PhaseRequest,
			Enabled:  true,
		},
		{
			PolicyID: "test2",
			Phase:    PhaseResponse,
			Enabled:  true,
		},
		{
			PolicyID: "test3",
			Phase:    PhaseBoth,
			Enabled:  true,
		},
	}

	// Set policies
	cache.Set("tenant1", nil, policies)

	// Get request phase policies
	requestPolicies, found := cache.Get("tenant1", nil, PhaseRequest)
	if !found {
		t.Error("Expected cache hit for request phase")
	}
	// Should have test1 and test3 (both phases)
	if len(requestPolicies) != 2 {
		t.Errorf("Expected 2 request policies, got %d", len(requestPolicies))
	}

	// Get response phase policies
	responsePolicies, found := cache.Get("tenant1", nil, PhaseResponse)
	if !found {
		t.Error("Expected cache hit for response phase")
	}
	// Should have test2 and test3 (both phases)
	if len(responsePolicies) != 2 {
		t.Errorf("Expected 2 response policies, got %d", len(responsePolicies))
	}

	// Get both phases
	allPolicies, found := cache.Get("tenant1", nil, PhaseBoth)
	if !found {
		t.Error("Expected cache hit for both phases")
	}
	// Should have all 3 unique policies
	if len(allPolicies) != 3 {
		t.Errorf("Expected 3 policies for both phases, got %d", len(allPolicies))
	}
}

func TestPolicyCache_Miss(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)

	// Miss on non-existent tenant
	_, found := cache.Get("nonexistent", nil, PhaseRequest)
	if found {
		t.Error("Expected cache miss for nonexistent tenant")
	}
}

func TestPolicyCache_Expiration(t *testing.T) {
	// Very short TTL for testing
	cache := NewPolicyCache(10*time.Millisecond, 100)

	policies := []CompiledPolicy{
		{
			PolicyID: "test1",
			Phase:    PhaseRequest,
		},
	}

	cache.Set("tenant1", nil, policies)

	// Should be found immediately
	_, found := cache.Get("tenant1", nil, PhaseRequest)
	if !found {
		t.Error("Expected cache hit before expiration")
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Should be expired now
	_, found = cache.Get("tenant1", nil, PhaseRequest)
	if found {
		t.Error("Expected cache miss after expiration")
	}
}

func TestPolicyCache_Invalidate(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)

	policies := []CompiledPolicy{
		{
			PolicyID: "test1",
			Phase:    PhaseRequest,
		},
	}

	cache.Set("tenant1", nil, policies)
	cache.Set("tenant2", nil, policies)

	// Both should exist
	_, found := cache.Get("tenant1", nil, PhaseRequest)
	if !found {
		t.Error("Expected cache hit for tenant1")
	}

	// Invalidate tenant1
	cache.Invalidate("tenant1", nil)

	// tenant1 should be gone
	_, found = cache.Get("tenant1", nil, PhaseRequest)
	if found {
		t.Error("Expected cache miss after invalidation")
	}

	// tenant2 should still exist
	_, found = cache.Get("tenant2", nil, PhaseRequest)
	if !found {
		t.Error("Expected cache hit for tenant2")
	}
}

func TestPolicyCache_InvalidateAll(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)

	policies := []CompiledPolicy{
		{
			PolicyID: "test1",
			Phase:    PhaseRequest,
		},
	}

	cache.Set("tenant1", nil, policies)
	cache.Set("tenant2", nil, policies)

	// Invalidate all
	cache.InvalidateAll()

	// Both should be gone
	_, found := cache.Get("tenant1", nil, PhaseRequest)
	if found {
		t.Error("Expected cache miss after InvalidateAll")
	}
	_, found = cache.Get("tenant2", nil, PhaseRequest)
	if found {
		t.Error("Expected cache miss after InvalidateAll")
	}
}

func TestPolicyCache_GetStats(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)

	policies := []CompiledPolicy{
		{
			PolicyID: "test1",
			Phase:    PhaseRequest,
		},
	}

	cache.Set("tenant1", nil, policies)

	// Generate hits and misses
	cache.Get("tenant1", nil, PhaseRequest) // hit
	cache.Get("tenant1", nil, PhaseRequest) // hit
	cache.Get("nonexistent", nil, PhaseRequest) // miss

	stats := cache.GetStats()

	if stats.CacheHits != 2 {
		t.Errorf("Expected 2 hits, got %d", stats.CacheHits)
	}
	if stats.CacheMisses != 1 {
		t.Errorf("Expected 1 miss, got %d", stats.CacheMisses)
	}
	if stats.CachedTenants != 1 {
		t.Errorf("Expected 1 cached tenant, got %d", stats.CachedTenants)
	}
}

func TestPolicyCache_WithOrgID(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)

	policies := []CompiledPolicy{
		{
			PolicyID: "test1",
			Phase:    PhaseRequest,
		},
	}

	orgID := "org123"

	// Set with org ID
	cache.Set("tenant1", &orgID, policies)

	// Should not find without org ID
	_, found := cache.Get("tenant1", nil, PhaseRequest)
	if found {
		t.Error("Expected cache miss without org ID")
	}

	// Should find with correct org ID
	_, found = cache.Get("tenant1", &orgID, PhaseRequest)
	if !found {
		t.Error("Expected cache hit with org ID")
	}
}

func TestPolicyCache_SortByPriority(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)

	policies := []CompiledPolicy{
		{PolicyID: "low", Phase: PhaseRequest, Priority: 10},
		{PolicyID: "high", Phase: PhaseRequest, Priority: 100},
		{PolicyID: "medium", Phase: PhaseRequest, Priority: 50},
	}

	cache.Set("tenant1", nil, policies)

	result, _ := cache.Get("tenant1", nil, PhaseRequest)

	// Should be sorted by priority (high to low)
	if result[0].PolicyID != "high" {
		t.Errorf("Expected high priority first, got %s", result[0].PolicyID)
	}
	if result[1].PolicyID != "medium" {
		t.Errorf("Expected medium priority second, got %s", result[1].PolicyID)
	}
	if result[2].PolicyID != "low" {
		t.Errorf("Expected low priority last, got %s", result[2].PolicyID)
	}
}

func TestPolicyCache_MergePolicies(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)

	policies := []CompiledPolicy{
		{PolicyID: "request_only", Phase: PhaseRequest, Priority: 100},
		{PolicyID: "response_only", Phase: PhaseResponse, Priority: 90},
		{PolicyID: "both_phases", Phase: PhaseBoth, Priority: 80},
	}

	cache.Set("tenant1", nil, policies)

	// Get both phases - should merge without duplicates
	result, found := cache.Get("tenant1", nil, PhaseBoth)
	if !found {
		t.Error("Expected cache hit")
	}

	// Should have all unique policies
	policyIDs := make(map[string]bool)
	for _, p := range result {
		policyIDs[p.PolicyID] = true
	}

	if len(policyIDs) != 3 {
		t.Errorf("Expected 3 unique policies, got %d", len(policyIDs))
	}
}

func TestPolicyCache_SetLastRefresh(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)

	duration := 50 * time.Millisecond
	cache.SetLastRefresh(duration)

	stats := cache.GetStats()
	if stats.RefreshDuration != duration {
		t.Errorf("Expected refresh duration %v, got %v", duration, stats.RefreshDuration)
	}
}

func TestPolicyCache_InvalidPhase(t *testing.T) {
	cache := NewPolicyCache(5*time.Minute, 100)

	policies := []CompiledPolicy{
		{PolicyID: "test", Phase: PhaseRequest},
	}

	cache.Set("tenant1", nil, policies)

	// Get with invalid phase
	_, found := cache.Get("tenant1", nil, "invalid_phase")
	if found {
		t.Error("Expected cache miss for invalid phase")
	}
}

func TestPatternCache_GetAndSet(t *testing.T) {
	cache := NewPatternCache(10)

	// Set a pattern
	cache.Set("pattern1", nil)

	// Get the pattern
	_, found := cache.Get("pattern1")
	if !found {
		t.Error("Expected pattern cache hit")
	}

	// Miss on non-existent
	_, found = cache.Get("nonexistent")
	if found {
		t.Error("Expected pattern cache miss")
	}
}

func TestPatternCache_Eviction(t *testing.T) {
	// Small cache for testing eviction
	cache := NewPatternCache(3)

	// Fill cache
	cache.Set("pattern1", nil)
	cache.Set("pattern2", nil)
	cache.Set("pattern3", nil)

	// Should evict oldest when adding new
	cache.Set("pattern4", nil)

	// Size should be limited
	if cache.Size() > 3 {
		t.Errorf("Expected cache size <= 3, got %d", cache.Size())
	}
}
