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
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

func TestCacheEntry_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired - future time",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "expired - past time",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "expired - exactly now (race condition edge case)",
			expiresAt: time.Now().Add(-1 * time.Millisecond),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &CacheEntry[string]{
				Value:     "test",
				ExpiresAt: tt.expiresAt,
			}
			if got := entry.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewConfigCache(t *testing.T) {
	tests := []struct {
		name    string
		ttl     time.Duration
		wantTTL time.Duration
	}{
		{
			name:    "custom TTL",
			ttl:     1 * time.Minute,
			wantTTL: 1 * time.Minute,
		},
		{
			name:    "zero TTL uses default",
			ttl:     0,
			wantTTL: 30 * time.Second,
		},
		{
			name:    "negative TTL uses default",
			ttl:     -1 * time.Second,
			wantTTL: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewConfigCache(tt.ttl)
			if cache.ttl != tt.wantTTL {
				t.Errorf("NewConfigCache().ttl = %v, want %v", cache.ttl, tt.wantTTL)
			}
		})
	}
}

func TestConfigCache_Connectors(t *testing.T) {
	cache := NewConfigCache(1 * time.Second)

	// Test cache miss
	configs, ok := cache.GetConnectors("tenant1")
	if ok {
		t.Error("expected cache miss for empty cache")
	}
	if configs != nil {
		t.Error("expected nil configs for cache miss")
	}

	// Test cache set and get
	testConfigs := []*base.ConnectorConfig{
		{Name: "postgres1", Type: "postgres"},
		{Name: "cassandra1", Type: "cassandra"},
	}
	cache.SetConnectors("tenant1", testConfigs)

	configs, ok = cache.GetConnectors("tenant1")
	if !ok {
		t.Error("expected cache hit after set")
	}
	if len(configs) != 2 {
		t.Errorf("expected 2 configs, got %d", len(configs))
	}

	// Test different tenant
	configs, ok = cache.GetConnectors("tenant2")
	if ok {
		t.Error("expected cache miss for different tenant")
	}
}

func TestConfigCache_ConnectorsExpiry(t *testing.T) {
	cache := NewConfigCache(10 * time.Millisecond)

	testConfigs := []*base.ConnectorConfig{
		{Name: "postgres1", Type: "postgres"},
	}
	cache.SetConnectors("tenant1", testConfigs)

	// Should be cached
	_, ok := cache.GetConnectors("tenant1")
	if !ok {
		t.Error("expected cache hit immediately after set")
	}

	// Wait for expiry
	time.Sleep(20 * time.Millisecond)

	// Should be expired
	_, ok = cache.GetConnectors("tenant1")
	if ok {
		t.Error("expected cache miss after expiry")
	}
}

func TestConfigCache_LLMProviders(t *testing.T) {
	cache := NewConfigCache(1 * time.Second)

	// Test cache miss
	providers, ok := cache.GetLLMProviders("tenant1")
	if ok {
		t.Error("expected cache miss for empty cache")
	}
	if providers != nil {
		t.Error("expected nil providers for cache miss")
	}

	// Test cache set and get
	testProviders := []*LLMProviderConfig{
		{ProviderName: "openai", DisplayName: "OpenAI"},
		{ProviderName: "anthropic", DisplayName: "Anthropic"},
	}
	cache.SetLLMProviders("tenant1", testProviders)

	providers, ok = cache.GetLLMProviders("tenant1")
	if !ok {
		t.Error("expected cache hit after set")
	}
	if len(providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(providers))
	}
}

func TestConfigCache_LLMProvidersExpiry(t *testing.T) {
	cache := NewConfigCache(10 * time.Millisecond)

	testProviders := []*LLMProviderConfig{
		{ProviderName: "openai"},
	}
	cache.SetLLMProviders("tenant1", testProviders)

	// Should be cached
	_, ok := cache.GetLLMProviders("tenant1")
	if !ok {
		t.Error("expected cache hit immediately after set")
	}

	// Wait for expiry
	time.Sleep(20 * time.Millisecond)

	// Should be expired
	_, ok = cache.GetLLMProviders("tenant1")
	if ok {
		t.Error("expected cache miss after expiry")
	}
}

func TestConfigCache_InvalidateConnector(t *testing.T) {
	cache := NewConfigCache(1 * time.Minute)

	testConfigs := []*base.ConnectorConfig{
		{Name: "postgres1", Type: "postgres"},
		{Name: "cassandra1", Type: "cassandra"},
	}
	cache.SetConnectors("tenant1", testConfigs)

	// Verify initial state
	configs, ok := cache.GetConnectors("tenant1")
	if !ok || len(configs) != 2 {
		t.Fatal("setup failed: expected 2 configs")
	}

	// Invalidate specific connector
	cache.InvalidateConnector("tenant1", "postgres1")

	configs, ok = cache.GetConnectors("tenant1")
	if !ok {
		t.Error("expected cache hit after partial invalidation")
	}
	if len(configs) != 1 {
		t.Errorf("expected 1 config after invalidation, got %d", len(configs))
	}
	if configs[0].Name != "cassandra1" {
		t.Errorf("expected cassandra1 to remain, got %s", configs[0].Name)
	}

	// Invalidate entire tenant
	cache.InvalidateConnector("tenant1", "")

	_, ok = cache.GetConnectors("tenant1")
	if ok {
		t.Error("expected cache miss after full invalidation")
	}

	// Check stats
	stats := cache.GetStats()
	if stats.Evictions < 2 {
		t.Errorf("expected at least 2 evictions, got %d", stats.Evictions)
	}
}

func TestConfigCache_InvalidateLLMProvider(t *testing.T) {
	cache := NewConfigCache(1 * time.Minute)

	testProviders := []*LLMProviderConfig{
		{ProviderName: "openai"},
		{ProviderName: "anthropic"},
	}
	cache.SetLLMProviders("tenant1", testProviders)

	// Invalidate specific provider
	cache.InvalidateLLMProvider("tenant1", "openai")

	providers, ok := cache.GetLLMProviders("tenant1")
	if !ok {
		t.Error("expected cache hit after partial invalidation")
	}
	if len(providers) != 1 {
		t.Errorf("expected 1 provider after invalidation, got %d", len(providers))
	}

	// Invalidate entire tenant
	cache.InvalidateLLMProvider("tenant1", "")

	_, ok = cache.GetLLMProviders("tenant1")
	if ok {
		t.Error("expected cache miss after full invalidation")
	}
}

func TestConfigCache_InvalidateAll(t *testing.T) {
	cache := NewConfigCache(1 * time.Minute)

	// Set up data for multiple tenants
	cache.SetConnectors("tenant1", []*base.ConnectorConfig{{Name: "pg1"}})
	cache.SetConnectors("tenant2", []*base.ConnectorConfig{{Name: "pg2"}})
	cache.SetLLMProviders("tenant1", []*LLMProviderConfig{{ProviderName: "openai"}})

	// Invalidate all
	cache.InvalidateAll()

	// Verify all caches are empty
	if _, ok := cache.GetConnectors("tenant1"); ok {
		t.Error("expected cache miss for tenant1 connectors")
	}
	if _, ok := cache.GetConnectors("tenant2"); ok {
		t.Error("expected cache miss for tenant2 connectors")
	}
	if _, ok := cache.GetLLMProviders("tenant1"); ok {
		t.Error("expected cache miss for tenant1 LLM providers")
	}
}

func TestConfigCache_Cleanup(t *testing.T) {
	cache := NewConfigCache(10 * time.Millisecond)

	// Add entries
	cache.SetConnectors("tenant1", []*base.ConnectorConfig{{Name: "pg1"}})
	cache.SetLLMProviders("tenant1", []*LLMProviderConfig{{ProviderName: "openai"}})

	// Cleanup before expiry should evict nothing
	evicted := cache.Cleanup()
	if evicted != 0 {
		t.Errorf("expected 0 evictions before expiry, got %d", evicted)
	}

	// Wait for expiry
	time.Sleep(20 * time.Millisecond)

	// Cleanup after expiry should evict entries
	evicted = cache.Cleanup()
	if evicted != 2 {
		t.Errorf("expected 2 evictions after expiry, got %d", evicted)
	}

	// Second cleanup should evict nothing
	evicted = cache.Cleanup()
	if evicted != 0 {
		t.Errorf("expected 0 evictions on second cleanup, got %d", evicted)
	}
}

func TestConfigCache_Stats(t *testing.T) {
	cache := NewConfigCache(1 * time.Second)

	// Initial stats
	stats := cache.GetStats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Error("expected zero hits and misses initially")
	}

	// Generate some cache misses
	cache.GetConnectors("tenant1")
	cache.GetLLMProviders("tenant1")

	stats = cache.GetStats()
	if stats.Misses != 2 {
		t.Errorf("expected 2 misses, got %d", stats.Misses)
	}

	// Add data and generate hits
	cache.SetConnectors("tenant1", []*base.ConnectorConfig{{Name: "pg1"}})
	cache.GetConnectors("tenant1")
	cache.GetConnectors("tenant1")

	stats = cache.GetStats()
	if stats.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", stats.Hits)
	}
}

func TestConfigCache_HitRate(t *testing.T) {
	cache := NewConfigCache(1 * time.Second)

	// Zero requests should return 0%
	if rate := cache.HitRate(); rate != 0 {
		t.Errorf("expected 0%% hit rate with no requests, got %.2f%%", rate)
	}

	// All misses
	cache.GetConnectors("tenant1")
	cache.GetConnectors("tenant2")
	if rate := cache.HitRate(); rate != 0 {
		t.Errorf("expected 0%% hit rate with all misses, got %.2f%%", rate)
	}

	// Add some hits
	cache.SetConnectors("tenant1", []*base.ConnectorConfig{{Name: "pg1"}})
	cache.GetConnectors("tenant1") // hit
	cache.GetConnectors("tenant1") // hit

	// 2 hits, 2 misses = 50%
	rate := cache.HitRate()
	if rate != 50 {
		t.Errorf("expected 50%% hit rate, got %.2f%%", rate)
	}
}

func TestConfigCache_ConcurrentAccess(t *testing.T) {
	cache := NewConfigCache(1 * time.Second)
	done := make(chan bool)

	// Concurrent writers
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				cache.SetConnectors("tenant1", []*base.ConnectorConfig{{Name: "pg1"}})
				cache.SetLLMProviders("tenant1", []*LLMProviderConfig{{ProviderName: "openai"}})
			}
			done <- true
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				cache.GetConnectors("tenant1")
				cache.GetLLMProviders("tenant1")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}

	// If we get here without race detector complaints, test passes
}

func TestConfigCache_InvalidateExpiredEntry(t *testing.T) {
	cache := NewConfigCache(10 * time.Millisecond)

	// Set connector
	cache.SetConnectors("tenant1", []*base.ConnectorConfig{
		{Name: "pg1"},
		{Name: "pg2"},
	})

	// Wait for expiry
	time.Sleep(20 * time.Millisecond)

	// Invalidate specific connector on expired entry should not panic
	cache.InvalidateConnector("tenant1", "pg1")

	// Invalidate LLM provider on non-existent entry
	cache.InvalidateLLMProvider("tenant1", "openai")
}
