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

package config

import (
	"sync"
	"time"

	"axonflow/platform/connectors/base"
)

// CacheEntry represents a cached configuration entry with expiration
type CacheEntry[T any] struct {
	Value      T
	ExpiresAt  time.Time
	LastUpdate time.Time
}

// IsExpired checks if the cache entry has expired
func (e *CacheEntry[T]) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// ConfigCache provides thread-safe caching for connector and LLM configurations
// with configurable TTL and per-tenant isolation
type ConfigCache struct {
	connectorConfigs map[string]*CacheEntry[[]*base.ConnectorConfig] // key: tenantID
	llmConfigs       map[string]*CacheEntry[[]*LLMProviderConfig]    // key: tenantID
	ttl              time.Duration
	mu               sync.RWMutex
	stats            CacheStats
}

// CacheStats tracks cache performance metrics
type CacheStats struct {
	Hits          int64
	Misses        int64
	Evictions     int64
	LastEviction  time.Time
	mu            sync.Mutex
}

// NewConfigCache creates a new configuration cache with the specified TTL
func NewConfigCache(ttl time.Duration) *ConfigCache {
	if ttl <= 0 {
		ttl = 30 * time.Second // Default 30s TTL as per ADR-007
	}
	return &ConfigCache{
		connectorConfigs: make(map[string]*CacheEntry[[]*base.ConnectorConfig]),
		llmConfigs:       make(map[string]*CacheEntry[[]*LLMProviderConfig]),
		ttl:              ttl,
	}
}

// GetConnectors retrieves cached connector configs for a tenant
// Returns the configs and a boolean indicating if the cache hit was successful
func (c *ConfigCache) GetConnectors(tenantID string) ([]*base.ConnectorConfig, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.connectorConfigs[tenantID]
	if !exists || entry.IsExpired() {
		c.recordMiss()
		return nil, false
	}

	c.recordHit()
	return entry.Value, true
}

// SetConnectors caches connector configs for a tenant
func (c *ConfigCache) SetConnectors(tenantID string, configs []*base.ConnectorConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	c.connectorConfigs[tenantID] = &CacheEntry[[]*base.ConnectorConfig]{
		Value:      configs,
		ExpiresAt:  now.Add(c.ttl),
		LastUpdate: now,
	}
}

// InvalidateConnector invalidates all cached configs for a tenant or a specific connector
func (c *ConfigCache) InvalidateConnector(tenantID string, connectorName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if connectorName == "" {
		// Invalidate all connectors for tenant
		delete(c.connectorConfigs, tenantID)
	} else {
		// Remove specific connector from cached list
		if entry, exists := c.connectorConfigs[tenantID]; exists && !entry.IsExpired() {
			filtered := make([]*base.ConnectorConfig, 0, len(entry.Value))
			for _, cfg := range entry.Value {
				if cfg.Name != connectorName {
					filtered = append(filtered, cfg)
				}
			}
			entry.Value = filtered
		}
	}

	c.stats.mu.Lock()
	c.stats.Evictions++
	c.stats.LastEviction = time.Now()
	c.stats.mu.Unlock()
}

// GetLLMProviders retrieves cached LLM provider configs for a tenant
func (c *ConfigCache) GetLLMProviders(tenantID string) ([]*LLMProviderConfig, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.llmConfigs[tenantID]
	if !exists || entry.IsExpired() {
		c.recordMiss()
		return nil, false
	}

	c.recordHit()
	return entry.Value, true
}

// SetLLMProviders caches LLM provider configs for a tenant
func (c *ConfigCache) SetLLMProviders(tenantID string, configs []*LLMProviderConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	c.llmConfigs[tenantID] = &CacheEntry[[]*LLMProviderConfig]{
		Value:      configs,
		ExpiresAt:  now.Add(c.ttl),
		LastUpdate: now,
	}
}

// InvalidateLLMProvider invalidates cached LLM configs for a tenant
func (c *ConfigCache) InvalidateLLMProvider(tenantID string, providerName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if providerName == "" {
		delete(c.llmConfigs, tenantID)
	} else {
		if entry, exists := c.llmConfigs[tenantID]; exists && !entry.IsExpired() {
			filtered := make([]*LLMProviderConfig, 0, len(entry.Value))
			for _, cfg := range entry.Value {
				if cfg.ProviderName != providerName {
					filtered = append(filtered, cfg)
				}
			}
			entry.Value = filtered
		}
	}

	c.stats.mu.Lock()
	c.stats.Evictions++
	c.stats.LastEviction = time.Now()
	c.stats.mu.Unlock()
}

// InvalidateAll clears all cached configurations
func (c *ConfigCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connectorConfigs = make(map[string]*CacheEntry[[]*base.ConnectorConfig])
	c.llmConfigs = make(map[string]*CacheEntry[[]*LLMProviderConfig])

	c.stats.mu.Lock()
	c.stats.Evictions++
	c.stats.LastEviction = time.Now()
	c.stats.mu.Unlock()
}

// Cleanup removes expired entries from the cache
// Should be called periodically (e.g., every minute)
func (c *ConfigCache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	evicted := 0

	for key, entry := range c.connectorConfigs {
		if entry.IsExpired() {
			delete(c.connectorConfigs, key)
			evicted++
		}
	}

	for key, entry := range c.llmConfigs {
		if entry.IsExpired() {
			delete(c.llmConfigs, key)
			evicted++
		}
	}

	if evicted > 0 {
		c.stats.mu.Lock()
		c.stats.Evictions += int64(evicted)
		c.stats.LastEviction = time.Now()
		c.stats.mu.Unlock()
	}

	return evicted
}

// GetStats returns cache performance statistics
func (c *ConfigCache) GetStats() CacheStats {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()
	// Return a copy of stats values to avoid copying the mutex
	return CacheStats{
		Hits:         c.stats.Hits,
		Misses:       c.stats.Misses,
		Evictions:    c.stats.Evictions,
		LastEviction: c.stats.LastEviction,
	}
}

// HitRate returns the cache hit rate as a percentage (0-100)
func (c *ConfigCache) HitRate() float64 {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()

	total := c.stats.Hits + c.stats.Misses
	if total == 0 {
		return 0
	}
	return float64(c.stats.Hits) / float64(total) * 100
}

func (c *ConfigCache) recordHit() {
	c.stats.mu.Lock()
	c.stats.Hits++
	c.stats.mu.Unlock()
}

func (c *ConfigCache) recordMiss() {
	c.stats.mu.Lock()
	c.stats.Misses++
	c.stats.mu.Unlock()
}
