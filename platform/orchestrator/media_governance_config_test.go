// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// ---------- MediaGovernanceConfig struct tests ----------

func TestMediaGovernanceConfig_Defaults(t *testing.T) {
	cfg := MediaGovernanceConfig{}

	if cfg.TenantID != "" {
		t.Errorf("expected empty TenantID, got %q", cfg.TenantID)
	}
	if cfg.Enabled {
		t.Error("expected Enabled to be false by default")
	}
	if cfg.AllowedAnalyzers != nil {
		t.Errorf("expected nil AllowedAnalyzers, got %v", cfg.AllowedAnalyzers)
	}
	if cfg.UpdatedBy != "" {
		t.Errorf("expected empty UpdatedBy, got %q", cfg.UpdatedBy)
	}
	if !cfg.UpdatedAt.IsZero() {
		t.Errorf("expected zero UpdatedAt, got %v", cfg.UpdatedAt)
	}
}

func TestMediaGovernanceConfig_WithValues(t *testing.T) {
	now := time.Now()
	cfg := MediaGovernanceConfig{
		TenantID:         "tenant-abc-123",
		Enabled:          true,
		AllowedAnalyzers: []string{"nsfw", "text-in-image", "facial-recognition"},
		UpdatedAt:        now,
		UpdatedBy:        "admin@example.com",
	}

	if cfg.TenantID != "tenant-abc-123" {
		t.Errorf("expected TenantID 'tenant-abc-123', got %q", cfg.TenantID)
	}
	if !cfg.Enabled {
		t.Error("expected Enabled to be true")
	}
	if len(cfg.AllowedAnalyzers) != 3 {
		t.Errorf("expected 3 allowed analyzers, got %d", len(cfg.AllowedAnalyzers))
	}
	if cfg.AllowedAnalyzers[0] != "nsfw" {
		t.Errorf("expected first analyzer 'nsfw', got %q", cfg.AllowedAnalyzers[0])
	}
	if cfg.UpdatedBy != "admin@example.com" {
		t.Errorf("expected UpdatedBy 'admin@example.com', got %q", cfg.UpdatedBy)
	}
	if !cfg.UpdatedAt.Equal(now) {
		t.Errorf("expected UpdatedAt %v, got %v", now, cfg.UpdatedAt)
	}
}

func TestMediaGovernanceConfig_JSONSerialization(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	cfg := MediaGovernanceConfig{
		TenantID:         "tenant-json-test",
		Enabled:          true,
		AllowedAnalyzers: []string{"nsfw", "text-in-image"},
		UpdatedAt:        now,
		UpdatedBy:        "user@example.com",
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	var decoded MediaGovernanceConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	if decoded.TenantID != cfg.TenantID {
		t.Errorf("TenantID mismatch: got %q, want %q", decoded.TenantID, cfg.TenantID)
	}
	if decoded.Enabled != cfg.Enabled {
		t.Errorf("Enabled mismatch: got %v, want %v", decoded.Enabled, cfg.Enabled)
	}
	if len(decoded.AllowedAnalyzers) != len(cfg.AllowedAnalyzers) {
		t.Errorf("AllowedAnalyzers length mismatch: got %d, want %d", len(decoded.AllowedAnalyzers), len(cfg.AllowedAnalyzers))
	}
	if decoded.UpdatedBy != cfg.UpdatedBy {
		t.Errorf("UpdatedBy mismatch: got %q, want %q", decoded.UpdatedBy, cfg.UpdatedBy)
	}
}

func TestMediaGovernanceConfig_JSONOmitsEmptyAnalyzers(t *testing.T) {
	cfg := MediaGovernanceConfig{
		TenantID: "tenant-omit",
		Enabled:  false,
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if _, exists := raw["allowed_analyzers"]; exists {
		t.Error("expected allowed_analyzers to be omitted when nil")
	}
}

func TestMediaGovernanceConfig_JSONOmitsEmptyUpdatedBy(t *testing.T) {
	cfg := MediaGovernanceConfig{
		TenantID: "tenant-omit-by",
		Enabled:  true,
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if _, exists := raw["updated_by"]; exists {
		t.Error("expected updated_by to be omitted when empty")
	}
}

// ---------- MediaGovernanceStatus struct tests ----------

func TestMediaGovernanceStatus_Defaults(t *testing.T) {
	status := MediaGovernanceStatus{}

	if status.Available {
		t.Error("expected Available to be false by default")
	}
	if status.EnabledByDefault {
		t.Error("expected EnabledByDefault to be false by default")
	}
	if status.PerTenantControl {
		t.Error("expected PerTenantControl to be false by default")
	}
	if status.Tier != "" {
		t.Errorf("expected empty Tier, got %q", status.Tier)
	}
}

func TestMediaGovernanceStatus_Enterprise(t *testing.T) {
	status := MediaGovernanceStatus{
		Available:        true,
		EnabledByDefault: true,
		PerTenantControl: true,
		Tier:             "enterprise",
	}

	if !status.Available {
		t.Error("expected Available to be true for enterprise")
	}
	if !status.EnabledByDefault {
		t.Error("expected EnabledByDefault to be true for enterprise")
	}
	if !status.PerTenantControl {
		t.Error("expected PerTenantControl to be true for enterprise")
	}
	if status.Tier != "enterprise" {
		t.Errorf("expected Tier 'enterprise', got %q", status.Tier)
	}
}

func TestMediaGovernanceStatus_Community(t *testing.T) {
	status := MediaGovernanceStatus{
		Available:        false,
		EnabledByDefault: false,
		PerTenantControl: false,
		Tier:             "community",
	}

	if status.Available {
		t.Error("expected Available to be false for community")
	}
	if status.PerTenantControl {
		t.Error("expected PerTenantControl to be false for community")
	}
}

func TestMediaGovernanceStatus_JSONSerialization(t *testing.T) {
	status := MediaGovernanceStatus{
		Available:        true,
		EnabledByDefault: true,
		PerTenantControl: false,
		Tier:             "evaluation",
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("failed to marshal status: %v", err)
	}

	var decoded MediaGovernanceStatus
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal status: %v", err)
	}

	if decoded.Available != status.Available {
		t.Errorf("Available mismatch: got %v, want %v", decoded.Available, status.Available)
	}
	if decoded.EnabledByDefault != status.EnabledByDefault {
		t.Errorf("EnabledByDefault mismatch: got %v, want %v", decoded.EnabledByDefault, status.EnabledByDefault)
	}
	if decoded.PerTenantControl != status.PerTenantControl {
		t.Errorf("PerTenantControl mismatch: got %v, want %v", decoded.PerTenantControl, status.PerTenantControl)
	}
	if decoded.Tier != status.Tier {
		t.Errorf("Tier mismatch: got %q, want %q", decoded.Tier, status.Tier)
	}
}

// ---------- MediaGovernanceConfigStore cache tests ----------

// newTestConfigStore creates a config store with a pre-populated cache and no DB.
// This bypasses NewMediaGovernanceConfigStore which requires a real postgres connection.
func newTestConfigStore() *MediaGovernanceConfigStore {
	return &MediaGovernanceConfigStore{
		db:    nil,
		cache: make(map[string]*MediaGovernanceConfig),
	}
}

func TestConfigStore_Get_EmptyCache(t *testing.T) {
	store := newTestConfigStore()

	result := store.Get("nonexistent-tenant")
	if result != nil {
		t.Errorf("expected nil for nonexistent tenant, got %+v", result)
	}
}

func TestConfigStore_Get_CacheHit(t *testing.T) {
	store := newTestConfigStore()

	now := time.Now()
	store.cache["tenant-1"] = &MediaGovernanceConfig{
		TenantID:         "tenant-1",
		Enabled:          true,
		AllowedAnalyzers: []string{"nsfw", "text-in-image"},
		UpdatedAt:        now,
		UpdatedBy:        "admin@example.com",
	}

	result := store.Get("tenant-1")
	if result == nil {
		t.Fatal("expected non-nil result for cached tenant")
	}
	if result.TenantID != "tenant-1" {
		t.Errorf("expected TenantID 'tenant-1', got %q", result.TenantID)
	}
	if !result.Enabled {
		t.Error("expected Enabled to be true")
	}
	if len(result.AllowedAnalyzers) != 2 {
		t.Errorf("expected 2 allowed analyzers, got %d", len(result.AllowedAnalyzers))
	}
	if result.UpdatedBy != "admin@example.com" {
		t.Errorf("expected UpdatedBy 'admin@example.com', got %q", result.UpdatedBy)
	}
}

func TestConfigStore_Get_CacheMiss(t *testing.T) {
	store := newTestConfigStore()

	store.cache["tenant-1"] = &MediaGovernanceConfig{
		TenantID: "tenant-1",
		Enabled:  true,
	}

	result := store.Get("tenant-2")
	if result != nil {
		t.Errorf("expected nil for tenant not in cache, got %+v", result)
	}
}

func TestConfigStore_Get_ReturnsCopy(t *testing.T) {
	store := newTestConfigStore()

	store.cache["tenant-copy"] = &MediaGovernanceConfig{
		TenantID:         "tenant-copy",
		Enabled:          true,
		AllowedAnalyzers: []string{"nsfw"},
		UpdatedBy:        "original@example.com",
	}

	// Get a copy
	result := store.Get("tenant-copy")
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Mutate the returned copy
	result.Enabled = false
	result.UpdatedBy = "mutated@example.com"

	// Verify the cache entry was not affected
	cached := store.cache["tenant-copy"]
	if !cached.Enabled {
		t.Error("cache entry should not have been mutated: Enabled changed")
	}
	if cached.UpdatedBy != "original@example.com" {
		t.Errorf("cache entry should not have been mutated: UpdatedBy changed to %q", cached.UpdatedBy)
	}
}

func TestConfigStore_Get_MultipleTenants(t *testing.T) {
	store := newTestConfigStore()

	store.cache["tenant-a"] = &MediaGovernanceConfig{
		TenantID: "tenant-a",
		Enabled:  true,
	}
	store.cache["tenant-b"] = &MediaGovernanceConfig{
		TenantID: "tenant-b",
		Enabled:  false,
	}
	store.cache["tenant-c"] = &MediaGovernanceConfig{
		TenantID:         "tenant-c",
		Enabled:          true,
		AllowedAnalyzers: []string{"facial-recognition"},
	}

	// Verify each tenant returns correct config
	resultA := store.Get("tenant-a")
	if resultA == nil || !resultA.Enabled {
		t.Error("tenant-a should exist and be enabled")
	}

	resultB := store.Get("tenant-b")
	if resultB == nil || resultB.Enabled {
		t.Error("tenant-b should exist and be disabled")
	}

	resultC := store.Get("tenant-c")
	if resultC == nil || len(resultC.AllowedAnalyzers) != 1 {
		t.Error("tenant-c should exist with 1 analyzer")
	}
	if resultC.AllowedAnalyzers[0] != "facial-recognition" {
		t.Errorf("expected analyzer 'facial-recognition', got %q", resultC.AllowedAnalyzers[0])
	}

	// Nonexistent tenant should still return nil
	resultD := store.Get("tenant-d")
	if resultD != nil {
		t.Error("tenant-d should not exist")
	}
}

func TestConfigStore_Get_DisabledConfig(t *testing.T) {
	store := newTestConfigStore()

	store.cache["disabled-tenant"] = &MediaGovernanceConfig{
		TenantID: "disabled-tenant",
		Enabled:  false,
	}

	result := store.Get("disabled-tenant")
	if result == nil {
		t.Fatal("expected non-nil result for disabled tenant")
	}
	if result.Enabled {
		t.Error("expected Enabled to be false")
	}
}

func TestConfigStore_Get_EmptyTenantID(t *testing.T) {
	store := newTestConfigStore()

	result := store.Get("")
	if result != nil {
		t.Error("expected nil for empty tenant ID")
	}
}

func TestConfigStore_Get_CacheWithEmptyKeyEntry(t *testing.T) {
	store := newTestConfigStore()

	// It's technically possible to have an empty key in the map
	store.cache[""] = &MediaGovernanceConfig{
		TenantID: "",
		Enabled:  true,
	}

	result := store.Get("")
	if result == nil {
		t.Fatal("expected non-nil result for empty key entry")
	}
	if !result.Enabled {
		t.Error("expected Enabled to be true for empty key entry")
	}
}

func TestConfigStore_CacheDirectManipulation_Set(t *testing.T) {
	store := newTestConfigStore()

	now := time.Now()
	cfg := &MediaGovernanceConfig{
		TenantID:         "direct-set",
		Enabled:          true,
		AllowedAnalyzers: []string{"nsfw", "violence-detection"},
		UpdatedAt:        now,
		UpdatedBy:        "test-user",
	}

	// Directly set in cache (simulating what loadAll or Upsert does)
	store.mu.Lock()
	store.cache[cfg.TenantID] = cfg
	store.mu.Unlock()

	// Verify via Get
	result := store.Get("direct-set")
	if result == nil {
		t.Fatal("expected non-nil result after direct cache set")
	}
	if result.TenantID != "direct-set" {
		t.Errorf("expected TenantID 'direct-set', got %q", result.TenantID)
	}
	if len(result.AllowedAnalyzers) != 2 {
		t.Errorf("expected 2 analyzers, got %d", len(result.AllowedAnalyzers))
	}
}

func TestConfigStore_CacheDirectManipulation_Delete(t *testing.T) {
	store := newTestConfigStore()

	store.cache["to-delete"] = &MediaGovernanceConfig{
		TenantID: "to-delete",
		Enabled:  true,
	}

	// Verify it exists first
	if store.Get("to-delete") == nil {
		t.Fatal("expected entry to exist before delete")
	}

	// Directly delete from cache (simulating what Delete does)
	store.mu.Lock()
	delete(store.cache, "to-delete")
	store.mu.Unlock()

	// Verify it's gone
	result := store.Get("to-delete")
	if result != nil {
		t.Error("expected nil after cache delete")
	}
}

func TestConfigStore_CacheDirectManipulation_Update(t *testing.T) {
	store := newTestConfigStore()

	store.cache["to-update"] = &MediaGovernanceConfig{
		TenantID: "to-update",
		Enabled:  true,
		UpdatedBy: "original-user",
	}

	// Verify original
	result := store.Get("to-update")
	if result == nil || !result.Enabled {
		t.Fatal("expected entry to exist and be enabled")
	}

	// Update cache entry (simulating what Upsert does)
	store.mu.Lock()
	updated := &MediaGovernanceConfig{
		TenantID:         "to-update",
		Enabled:          false,
		AllowedAnalyzers: []string{"nsfw"},
		UpdatedAt:        time.Now(),
		UpdatedBy:        "updated-user",
	}
	store.cache["to-update"] = updated
	store.mu.Unlock()

	// Verify update
	result = store.Get("to-update")
	if result == nil {
		t.Fatal("expected entry to exist after update")
	}
	if result.Enabled {
		t.Error("expected Enabled to be false after update")
	}
	if result.UpdatedBy != "updated-user" {
		t.Errorf("expected UpdatedBy 'updated-user', got %q", result.UpdatedBy)
	}
	if len(result.AllowedAnalyzers) != 1 {
		t.Errorf("expected 1 analyzer after update, got %d", len(result.AllowedAnalyzers))
	}
}

func TestConfigStore_ConcurrentReads(t *testing.T) {
	store := newTestConfigStore()

	// Pre-populate cache
	for i := 0; i < 10; i++ {
		tenantID := "concurrent-tenant-" + string(rune('0'+i))
		store.cache[tenantID] = &MediaGovernanceConfig{
			TenantID: tenantID,
			Enabled:  i%2 == 0,
		}
	}

	// Concurrent reads should not panic or race
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tenantID := "concurrent-tenant-" + string(rune('0'+idx%10))
			result := store.Get(tenantID)
			if result == nil {
				t.Errorf("expected non-nil result for %s", tenantID)
			}
		}(i)
	}
	wg.Wait()
}

func TestConfigStore_ConcurrentReadWrite(t *testing.T) {
	store := newTestConfigStore()

	store.cache["rw-tenant"] = &MediaGovernanceConfig{
		TenantID: "rw-tenant",
		Enabled:  true,
	}

	var wg sync.WaitGroup

	// Concurrent readers
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				result := store.Get("rw-tenant")
				if result == nil {
					// During writes the entry might be briefly removed,
					// but our store never removes on update, so this should not happen
					t.Error("unexpected nil during concurrent read")
				}
			}
		}()
	}

	// Concurrent writers (updating the cache directly)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				store.mu.Lock()
				store.cache["rw-tenant"] = &MediaGovernanceConfig{
					TenantID: "rw-tenant",
					Enabled:  j%2 == 0,
					UpdatedBy: "writer-" + string(rune('0'+idx)),
				}
				store.mu.Unlock()
			}
		}(i)
	}

	wg.Wait()
}

// ---------- UpdateMediaGovernanceConfigRequest tests ----------

func TestUpdateMediaGovernanceConfigRequest_Defaults(t *testing.T) {
	req := UpdateMediaGovernanceConfigRequest{}

	if req.Enabled != nil {
		t.Errorf("expected nil Enabled, got %v", *req.Enabled)
	}
	if req.AllowedAnalyzers != nil {
		t.Errorf("expected nil AllowedAnalyzers, got %v", req.AllowedAnalyzers)
	}
}

func TestUpdateMediaGovernanceConfigRequest_EnabledOnly(t *testing.T) {
	enabled := true
	req := UpdateMediaGovernanceConfigRequest{
		Enabled: &enabled,
	}

	if req.Enabled == nil {
		t.Fatal("expected non-nil Enabled")
	}
	if !*req.Enabled {
		t.Error("expected Enabled to be true")
	}
	if req.AllowedAnalyzers != nil {
		t.Error("expected nil AllowedAnalyzers")
	}
}

func TestUpdateMediaGovernanceConfigRequest_DisableOnly(t *testing.T) {
	disabled := false
	req := UpdateMediaGovernanceConfigRequest{
		Enabled: &disabled,
	}

	if req.Enabled == nil {
		t.Fatal("expected non-nil Enabled")
	}
	if *req.Enabled {
		t.Error("expected Enabled to be false")
	}
}

func TestUpdateMediaGovernanceConfigRequest_AnalyzersOnly(t *testing.T) {
	req := UpdateMediaGovernanceConfigRequest{
		AllowedAnalyzers: []string{"nsfw", "violence-detection"},
	}

	if req.Enabled != nil {
		t.Error("expected nil Enabled when only analyzers are set")
	}
	if len(req.AllowedAnalyzers) != 2 {
		t.Errorf("expected 2 analyzers, got %d", len(req.AllowedAnalyzers))
	}
}

func TestUpdateMediaGovernanceConfigRequest_BothFields(t *testing.T) {
	enabled := true
	req := UpdateMediaGovernanceConfigRequest{
		Enabled:          &enabled,
		AllowedAnalyzers: []string{"nsfw"},
	}

	if req.Enabled == nil || !*req.Enabled {
		t.Error("expected Enabled to be true")
	}
	if len(req.AllowedAnalyzers) != 1 || req.AllowedAnalyzers[0] != "nsfw" {
		t.Errorf("expected AllowedAnalyzers [nsfw], got %v", req.AllowedAnalyzers)
	}
}

func TestUpdateMediaGovernanceConfigRequest_EmptyAnalyzersList(t *testing.T) {
	req := UpdateMediaGovernanceConfigRequest{
		AllowedAnalyzers: []string{},
	}

	// Empty slice is non-nil but empty - this represents "clear all analyzers"
	if req.AllowedAnalyzers == nil {
		t.Error("expected non-nil AllowedAnalyzers (empty slice)")
	}
	if len(req.AllowedAnalyzers) != 0 {
		t.Errorf("expected 0 analyzers, got %d", len(req.AllowedAnalyzers))
	}
}

func TestUpdateMediaGovernanceConfigRequest_JSONDeserialization(t *testing.T) {
	tests := []struct {
		name             string
		jsonInput        string
		expectEnabled    *bool
		expectAnalyzers  []string
	}{
		{
			name:      "empty object",
			jsonInput: `{}`,
		},
		{
			name:          "enabled only",
			jsonInput:     `{"enabled": true}`,
			expectEnabled: mediaGovBoolPtr(true),
		},
		{
			name:          "disabled only",
			jsonInput:     `{"enabled": false}`,
			expectEnabled: mediaGovBoolPtr(false),
		},
		{
			name:            "analyzers only",
			jsonInput:       `{"allowed_analyzers": ["nsfw", "text-in-image"]}`,
			expectAnalyzers: []string{"nsfw", "text-in-image"},
		},
		{
			name:            "both fields",
			jsonInput:       `{"enabled": true, "allowed_analyzers": ["nsfw"]}`,
			expectEnabled:   mediaGovBoolPtr(true),
			expectAnalyzers: []string{"nsfw"},
		},
		{
			name:            "empty analyzers list",
			jsonInput:       `{"allowed_analyzers": []}`,
			expectAnalyzers: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req UpdateMediaGovernanceConfigRequest
			if err := json.Unmarshal([]byte(tt.jsonInput), &req); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if tt.expectEnabled == nil {
				if req.Enabled != nil {
					t.Errorf("expected nil Enabled, got %v", *req.Enabled)
				}
			} else {
				if req.Enabled == nil {
					t.Fatal("expected non-nil Enabled")
				}
				if *req.Enabled != *tt.expectEnabled {
					t.Errorf("expected Enabled=%v, got %v", *tt.expectEnabled, *req.Enabled)
				}
			}

			if tt.expectAnalyzers == nil {
				if req.AllowedAnalyzers != nil {
					t.Errorf("expected nil AllowedAnalyzers, got %v", req.AllowedAnalyzers)
				}
			} else {
				if len(req.AllowedAnalyzers) != len(tt.expectAnalyzers) {
					t.Errorf("expected %d analyzers, got %d", len(tt.expectAnalyzers), len(req.AllowedAnalyzers))
				}
				for i, expected := range tt.expectAnalyzers {
					if i < len(req.AllowedAnalyzers) && req.AllowedAnalyzers[i] != expected {
						t.Errorf("analyzer[%d]: expected %q, got %q", i, expected, req.AllowedAnalyzers[i])
					}
				}
			}
		})
	}
}

func TestUpdateMediaGovernanceConfigRequest_JSONSerialization(t *testing.T) {
	enabled := true
	req := UpdateMediaGovernanceConfigRequest{
		Enabled:          &enabled,
		AllowedAnalyzers: []string{"nsfw"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded UpdateMediaGovernanceConfigRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Enabled == nil || !*decoded.Enabled {
		t.Error("expected Enabled to be true after round-trip")
	}
	if len(decoded.AllowedAnalyzers) != 1 || decoded.AllowedAnalyzers[0] != "nsfw" {
		t.Errorf("expected AllowedAnalyzers [nsfw] after round-trip, got %v", decoded.AllowedAnalyzers)
	}
}

func TestUpdateMediaGovernanceConfigRequest_OmitsEmptyFields(t *testing.T) {
	req := UpdateMediaGovernanceConfigRequest{}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if _, exists := raw["enabled"]; exists {
		t.Error("expected 'enabled' to be omitted when nil")
	}
	if _, exists := raw["allowed_analyzers"]; exists {
		t.Error("expected 'allowed_analyzers' to be omitted when nil")
	}
}

// ---------- ConfigStore cache population (simulating loadAll) ----------

func TestConfigStore_CachePopulation_MultipleEntries(t *testing.T) {
	store := newTestConfigStore()

	entries := []MediaGovernanceConfig{
		{TenantID: "t1", Enabled: true, AllowedAnalyzers: []string{"nsfw"}},
		{TenantID: "t2", Enabled: false},
		{TenantID: "t3", Enabled: true, AllowedAnalyzers: []string{"nsfw", "text-in-image", "violence-detection"}},
	}

	// Simulate loadAll populating the cache
	store.mu.Lock()
	for i := range entries {
		store.cache[entries[i].TenantID] = &entries[i]
	}
	store.mu.Unlock()

	// Verify all entries
	for _, entry := range entries {
		result := store.Get(entry.TenantID)
		if result == nil {
			t.Errorf("expected non-nil result for %s", entry.TenantID)
			continue
		}
		if result.Enabled != entry.Enabled {
			t.Errorf("tenant %s: expected Enabled=%v, got %v", entry.TenantID, entry.Enabled, result.Enabled)
		}
		if len(result.AllowedAnalyzers) != len(entry.AllowedAnalyzers) {
			t.Errorf("tenant %s: expected %d analyzers, got %d", entry.TenantID, len(entry.AllowedAnalyzers), len(result.AllowedAnalyzers))
		}
	}
}

func TestConfigStore_CacheOverwrite(t *testing.T) {
	store := newTestConfigStore()

	// Initial entry
	store.mu.Lock()
	store.cache["overwrite-tenant"] = &MediaGovernanceConfig{
		TenantID: "overwrite-tenant",
		Enabled:  true,
		UpdatedBy: "first-user",
	}
	store.mu.Unlock()

	result := store.Get("overwrite-tenant")
	if result == nil || result.UpdatedBy != "first-user" {
		t.Fatal("initial cache entry not set correctly")
	}

	// Overwrite
	store.mu.Lock()
	store.cache["overwrite-tenant"] = &MediaGovernanceConfig{
		TenantID:         "overwrite-tenant",
		Enabled:          false,
		AllowedAnalyzers: []string{"text-in-image"},
		UpdatedBy:        "second-user",
	}
	store.mu.Unlock()

	result = store.Get("overwrite-tenant")
	if result == nil {
		t.Fatal("expected non-nil result after overwrite")
	}
	if result.Enabled {
		t.Error("expected Enabled to be false after overwrite")
	}
	if result.UpdatedBy != "second-user" {
		t.Errorf("expected UpdatedBy 'second-user', got %q", result.UpdatedBy)
	}
	if len(result.AllowedAnalyzers) != 1 {
		t.Errorf("expected 1 analyzer after overwrite, got %d", len(result.AllowedAnalyzers))
	}
}

// ---------- NewMediaGovernanceConfigStore (DB-backed) ----------

func TestNewMediaGovernanceConfigStore_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	// initializeSchema
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS media_governance_config").
		WillReturnResult(sqlmock.NewResult(0, 0))

	// loadAll returns empty result
	mock.ExpectQuery("SELECT tenant_id, enabled, allowed_analyzers, updated_at").
		WillReturnRows(sqlmock.NewRows([]string{
			"tenant_id", "enabled", "allowed_analyzers", "updated_at", "updated_by",
		}))

	store, err := NewMediaGovernanceConfigStore(db)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if store.db != db {
		t.Error("expected store.db to match provided db")
	}
	if store.cache == nil {
		t.Error("expected non-nil cache map")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestNewMediaGovernanceConfigStore_SchemaError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS media_governance_config").
		WillReturnError(fmt.Errorf("permission denied"))

	store, err := NewMediaGovernanceConfigStore(db)
	if err == nil {
		t.Fatal("expected error when schema initialization fails")
	}
	if store != nil {
		t.Error("expected nil store when schema initialization fails")
	}
	if !containsSubstring(err.Error(), "failed to initialize media governance config schema") {
		t.Errorf("expected error message to mention schema initialization, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestNewMediaGovernanceConfigStore_LoadAllError_StillReturnsStore(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	// initializeSchema succeeds
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS media_governance_config").
		WillReturnResult(sqlmock.NewResult(0, 0))

	// loadAll fails (logged as warning, does not return error)
	mock.ExpectQuery("SELECT tenant_id, enabled, allowed_analyzers, updated_at").
		WillReturnError(fmt.Errorf("connection reset"))

	store, err := NewMediaGovernanceConfigStore(db)
	if err != nil {
		t.Fatalf("expected no error (loadAll failure is non-fatal), got %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store even when loadAll fails")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestNewMediaGovernanceConfigStore_LoadAllPopulatesCache(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	ts := time.Date(2026, 2, 18, 10, 0, 0, 0, time.UTC)

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS media_governance_config").
		WillReturnResult(sqlmock.NewResult(0, 0))

	mock.ExpectQuery("SELECT tenant_id, enabled, allowed_analyzers, updated_at").
		WillReturnRows(sqlmock.NewRows([]string{
			"tenant_id", "enabled", "allowed_analyzers", "updated_at", "updated_by",
		}).AddRow("tenant-1", true, []byte(`["nsfw","text-in-image"]`), ts, "admin@example.com").
			AddRow("tenant-2", false, []byte(`[]`), ts, ""))

	store, err := NewMediaGovernanceConfigStore(db)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Check cache populated correctly
	cfg1 := store.Get("tenant-1")
	if cfg1 == nil {
		t.Fatal("expected tenant-1 in cache")
	}
	if !cfg1.Enabled {
		t.Error("expected tenant-1 Enabled=true")
	}
	if len(cfg1.AllowedAnalyzers) != 2 {
		t.Errorf("expected 2 analyzers for tenant-1, got %d", len(cfg1.AllowedAnalyzers))
	}
	if cfg1.UpdatedBy != "admin@example.com" {
		t.Errorf("expected UpdatedBy=admin@example.com, got %q", cfg1.UpdatedBy)
	}

	cfg2 := store.Get("tenant-2")
	if cfg2 == nil {
		t.Fatal("expected tenant-2 in cache")
	}
	if cfg2.Enabled {
		t.Error("expected tenant-2 Enabled=false")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ---------- initializeSchema ----------

func TestInitializeSchema_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := &MediaGovernanceConfigStore{
		db:    db,
		cache: make(map[string]*MediaGovernanceConfig),
	}

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS media_governance_config").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = store.initializeSchema()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestInitializeSchema_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := &MediaGovernanceConfigStore{
		db:    db,
		cache: make(map[string]*MediaGovernanceConfig),
	}

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS media_governance_config").
		WillReturnError(fmt.Errorf("disk full"))

	err = store.initializeSchema()
	if err == nil {
		t.Fatal("expected error when CREATE TABLE fails")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ---------- loadAll ----------

func TestLoadAll_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := &MediaGovernanceConfigStore{
		db:    db,
		cache: make(map[string]*MediaGovernanceConfig),
	}

	ts := time.Date(2026, 2, 18, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery("SELECT tenant_id, enabled, allowed_analyzers, updated_at").
		WillReturnRows(sqlmock.NewRows([]string{
			"tenant_id", "enabled", "allowed_analyzers", "updated_at", "updated_by",
		}).AddRow("t-load-1", true, []byte(`["nsfw"]`), ts, "user1@test.com").
			AddRow("t-load-2", false, []byte(`["violence-detection","facial-recognition"]`), ts, "user2@test.com"))

	err = store.loadAll()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(store.cache) != 2 {
		t.Errorf("expected 2 entries in cache, got %d", len(store.cache))
	}

	cfg1 := store.cache["t-load-1"]
	if cfg1 == nil || !cfg1.Enabled || len(cfg1.AllowedAnalyzers) != 1 {
		t.Error("t-load-1 not loaded correctly")
	}

	cfg2 := store.cache["t-load-2"]
	if cfg2 == nil || cfg2.Enabled || len(cfg2.AllowedAnalyzers) != 2 {
		t.Error("t-load-2 not loaded correctly")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestLoadAll_EmptyResult(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := &MediaGovernanceConfigStore{
		db:    db,
		cache: make(map[string]*MediaGovernanceConfig),
	}

	mock.ExpectQuery("SELECT tenant_id, enabled, allowed_analyzers, updated_at").
		WillReturnRows(sqlmock.NewRows([]string{
			"tenant_id", "enabled", "allowed_analyzers", "updated_at", "updated_by",
		}))

	err = store.loadAll()
	if err != nil {
		t.Fatalf("expected no error for empty result, got %v", err)
	}

	if len(store.cache) != 0 {
		t.Errorf("expected empty cache, got %d entries", len(store.cache))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestLoadAll_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := &MediaGovernanceConfigStore{
		db:    db,
		cache: make(map[string]*MediaGovernanceConfig),
	}

	mock.ExpectQuery("SELECT tenant_id, enabled, allowed_analyzers, updated_at").
		WillReturnError(fmt.Errorf("connection refused"))

	err = store.loadAll()
	if err == nil {
		t.Fatal("expected error when query fails")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestLoadAll_ScanError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := &MediaGovernanceConfigStore{
		db:    db,
		cache: make(map[string]*MediaGovernanceConfig),
	}

	// Return a row with wrong types to trigger scan error
	mock.ExpectQuery("SELECT tenant_id, enabled, allowed_analyzers, updated_at").
		WillReturnRows(sqlmock.NewRows([]string{
			"tenant_id", "enabled", "allowed_analyzers", "updated_at", "updated_by",
		}).AddRow("tenant-ok", true, []byte(`["nsfw"]`), time.Now(), "user@test.com").
			AddRow(nil, "not-a-bool", nil, nil, nil))

	err = store.loadAll()
	if err == nil {
		t.Fatal("expected error when scan fails")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestLoadAll_InvalidAnalyzersJSON_StillLoads(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := &MediaGovernanceConfigStore{
		db:    db,
		cache: make(map[string]*MediaGovernanceConfig),
	}

	ts := time.Date(2026, 2, 18, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery("SELECT tenant_id, enabled, allowed_analyzers, updated_at").
		WillReturnRows(sqlmock.NewRows([]string{
			"tenant_id", "enabled", "allowed_analyzers", "updated_at", "updated_by",
		}).AddRow("tenant-bad-json", true, []byte(`not-valid-json`), ts, "admin"))

	err = store.loadAll()
	if err != nil {
		t.Fatalf("expected no error (invalid JSON logged as warning), got %v", err)
	}

	// Entry should still be cached, just with nil analyzers
	cfg := store.cache["tenant-bad-json"]
	if cfg == nil {
		t.Fatal("expected tenant-bad-json in cache despite invalid analyzer JSON")
	}
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ---------- Delete ----------

func TestConfigStore_Delete_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := &MediaGovernanceConfigStore{
		db:    db,
		cache: make(map[string]*MediaGovernanceConfig),
	}

	// Pre-populate cache
	store.cache["tenant-del"] = &MediaGovernanceConfig{
		TenantID: "tenant-del",
		Enabled:  true,
	}

	mock.ExpectExec("DELETE FROM media_governance_config WHERE tenant_id").
		WithArgs("tenant-del").
		WillReturnResult(sqlmock.NewResult(0, 1))

	ctx := context.Background()
	err = store.Delete(ctx, "tenant-del")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify cache entry was removed
	if store.Get("tenant-del") != nil {
		t.Error("expected tenant-del to be removed from cache after Delete")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestConfigStore_Delete_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := &MediaGovernanceConfigStore{
		db:    db,
		cache: make(map[string]*MediaGovernanceConfig),
	}

	// Pre-populate cache
	store.cache["tenant-del-err"] = &MediaGovernanceConfig{
		TenantID: "tenant-del-err",
		Enabled:  true,
	}

	mock.ExpectExec("DELETE FROM media_governance_config WHERE tenant_id").
		WithArgs("tenant-del-err").
		WillReturnError(fmt.Errorf("foreign key constraint"))

	ctx := context.Background()
	err = store.Delete(ctx, "tenant-del-err")
	if err == nil {
		t.Fatal("expected error when DB delete fails")
	}
	if !containsSubstring(err.Error(), "failed to delete media governance config") {
		t.Errorf("expected error message to mention delete failure, got: %v", err)
	}

	// Cache should NOT be modified on error
	if store.Get("tenant-del-err") == nil {
		t.Error("expected tenant-del-err to remain in cache when Delete fails")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestConfigStore_Delete_NonexistentTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := &MediaGovernanceConfigStore{
		db:    db,
		cache: make(map[string]*MediaGovernanceConfig),
	}

	// Delete a tenant that doesn't exist - should succeed (0 rows affected)
	mock.ExpectExec("DELETE FROM media_governance_config WHERE tenant_id").
		WithArgs("nonexistent").
		WillReturnResult(sqlmock.NewResult(0, 0))

	ctx := context.Background()
	err = store.Delete(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("expected no error for deleting nonexistent tenant, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ---------- Helpers ----------

func mediaGovBoolPtr(b bool) *bool {
	return &b
}
