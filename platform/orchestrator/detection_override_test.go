// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"axonflow/platform/agent"
)

// fakeOverrideReader is an in-memory detectionOverrideReader for unit tests — no
// DB. It counts calls so cache hit/miss behavior can be asserted, and can be made
// to fail to exercise the fail-safe path. Mirrors the agent's test double.
type fakeOverrideReader struct {
	mu    sync.Mutex
	data  map[string]map[string]agent.DetectionAction
	calls int
	err   error
}

func (f *fakeOverrideReader) ReadOrgOverrides(_ context.Context, orgID string) (map[string]agent.DetectionAction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]agent.DetectionAction{}
	for k, v := range f.data[orgID] {
		out[k] = v
	}
	return out, nil
}

func (f *fakeOverrideReader) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// installTestOverrideCache wires a cache over reader for the test's lifetime.
func installTestOverrideCache(t *testing.T, reader detectionOverrideReader, ttl time.Duration) *detectionOverrideCache {
	t.Helper()
	c := newDetectionOverrideCache(reader, ttl, defaultDetectionOverrideMaxEntries)
	setDetectionOverrideCacheForTest(c)
	t.Cleanup(ResetDetectionOverrideCacheForTest)
	return c
}

// sameActions reports whether two configs carry identical detection actions
// (ModeDetectionConfig has slice fields, so it isn't directly comparable).
func sameActions(a, b agent.ModeDetectionConfig) bool {
	return a.Enabled == b.Enabled &&
		a.PIIAction == b.PIIAction &&
		a.SQLIAction == b.SQLIAction &&
		a.DangerousQueryAction == b.DangerousQueryAction &&
		a.DangerousCommandAction == b.DangerousCommandAction
}

func blockBase() agent.ModeDetectionConfig {
	return agent.ModeDetectionConfig{
		Enabled:                true,
		PIIAction:              agent.DetectionActionBlock,
		SQLIAction:             agent.DetectionActionBlock,
		DangerousQueryAction:   agent.DetectionActionBlock,
		DangerousCommandAction: agent.DetectionActionBlock,
	}
}

// resolveViaCache mirrors the agent's combined resolver for test convenience:
// the cache lookup followed by the per-category apply onto base.
func resolveViaCache(ctx context.Context, orgID string, base agent.ModeDetectionConfig) agent.ModeDetectionConfig {
	return applyOrgDetectionOverrides(orgDetectionOverrides(ctx, orgID), base)
}

// An org with a per-category override gets that action; categories without an
// override keep the deployment-global value. This is the core #2581/#2612 contract.
func TestApplyOrgDetectionOverrides_OverrideWinsPerCategory(t *testing.T) {
	installTestOverrideCache(t, &fakeOverrideReader{
		data: map[string]map[string]agent.DetectionAction{
			"org-a": {agent.DetectionCategoryPII: agent.DetectionActionRedact, agent.DetectionCategorySQLI: agent.DetectionActionWarn},
		},
	}, time.Minute)

	got := resolveViaCache(context.Background(), "org-a", blockBase())
	if got.PIIAction != agent.DetectionActionRedact {
		t.Errorf("PIIAction = %q, want redact (per-org override)", got.PIIAction)
	}
	if got.SQLIAction != agent.DetectionActionWarn {
		t.Errorf("SQLIAction = %q, want warn (per-org override)", got.SQLIAction)
	}
	if got.DangerousQueryAction != agent.DetectionActionBlock || got.DangerousCommandAction != agent.DetectionActionBlock {
		t.Errorf("un-overridden categories must keep global block; got dq=%q dc=%q", got.DangerousQueryAction, got.DangerousCommandAction)
	}
}

// An org with NO override row resolves to the deployment-global config unchanged.
func TestApplyOrgDetectionOverrides_NoOverrideUsesGlobal(t *testing.T) {
	installTestOverrideCache(t, &fakeOverrideReader{
		data: map[string]map[string]agent.DetectionAction{"org-a": {agent.DetectionCategoryPII: agent.DetectionActionRedact}},
	}, time.Minute)

	got := resolveViaCache(context.Background(), "org-other", blockBase())
	if !sameActions(got, blockBase()) {
		t.Errorf("org with no override must equal global config; got %+v", got)
	}
}

// Empty orgID (unauthenticated / community / internal-service-with-no-org) must
// NOT touch the cache and must return the global config — fail-safe + cheap.
func TestApplyOrgDetectionOverrides_EmptyOrgUsesGlobalNoLookup(t *testing.T) {
	r := &fakeOverrideReader{data: map[string]map[string]agent.DetectionAction{"org-a": {agent.DetectionCategoryPII: agent.DetectionActionRedact}}}
	installTestOverrideCache(t, r, time.Minute)

	got := resolveViaCache(context.Background(), "", blockBase())
	if !sameActions(got, blockBase()) {
		t.Errorf("empty orgID must return global config; got %+v", got)
	}
	if r.callCount() != 0 {
		t.Errorf("empty orgID must not hit the reader; calls=%d", r.callCount())
	}
}

// With no cache wired (no-DB mode / community), resolution returns the global
// config — byte-identical to the pre-#2612 behavior.
func TestApplyOrgDetectionOverrides_NilCacheUsesGlobal(t *testing.T) {
	ResetDetectionOverrideCacheForTest()
	got := resolveViaCache(context.Background(), "org-a", blockBase())
	if !sameActions(got, blockBase()) {
		t.Errorf("nil cache must return global config; got %+v", got)
	}
}

// applyOrgDetectionOverrides is pure: an empty/nil override map returns base
// unchanged (same value), and an invalid category key is ignored.
func TestApplyOrgDetectionOverrides_Pure(t *testing.T) {
	if got := applyOrgDetectionOverrides(nil, blockBase()); !sameActions(got, blockBase()) {
		t.Errorf("nil overrides must return base unchanged; got %+v", got)
	}
	if got := applyOrgDetectionOverrides(map[string]agent.DetectionAction{}, blockBase()); !sameActions(got, blockBase()) {
		t.Errorf("empty overrides must return base unchanged; got %+v", got)
	}
	got := applyOrgDetectionOverrides(map[string]agent.DetectionAction{"not_a_category": agent.DetectionActionWarn}, blockBase())
	if !sameActions(got, blockBase()) {
		t.Errorf("unknown category must be ignored; got %+v", got)
	}
}

// A lookup error falls back to the global config (NEVER fail-open to "no
// governance") and is cached briefly so a failing DB is not re-hit per request.
func TestDetectionOverrideCache_LookupErrorFailsSafeToGlobal(t *testing.T) {
	r := &fakeOverrideReader{err: errors.New("db down")}
	installTestOverrideCache(t, r, time.Minute)

	got := resolveViaCache(context.Background(), "org-a", blockBase())
	if !sameActions(got, blockBase()) {
		t.Errorf("lookup error must fall back to global config; got %+v", got)
	}
	_ = resolveViaCache(context.Background(), "org-a", blockBase())
	if r.callCount() != 1 {
		t.Errorf("error result must be cached (no hot-path hammering); calls=%d, want 1", r.callCount())
	}
}

// A fresh result is served from cache within the TTL window (no per-request DB).
func TestDetectionOverrideCache_CachesWithinTTL(t *testing.T) {
	r := &fakeOverrideReader{data: map[string]map[string]agent.DetectionAction{"org-a": {agent.DetectionCategoryPII: agent.DetectionActionRedact}}}
	c := installTestOverrideCache(t, r, time.Minute)

	_ = c.get(context.Background(), "org-a")
	_ = c.get(context.Background(), "org-a")
	if r.callCount() != 1 {
		t.Errorf("two gets within TTL must read the DB once; calls=%d", r.callCount())
	}
}

// An expired entry triggers a refresh on the next get.
func TestDetectionOverrideCache_ExpiryRefreshes(t *testing.T) {
	r := &fakeOverrideReader{data: map[string]map[string]agent.DetectionAction{"org-a": {agent.DetectionCategoryPII: agent.DetectionActionRedact}}}
	c := installTestOverrideCache(t, r, time.Minute)

	_ = c.get(context.Background(), "org-a")
	c.mu.Lock()
	entry := c.entries["org-a"]
	entry.expiresAt = time.Now().Add(-time.Second)
	c.entries["org-a"] = entry
	c.mu.Unlock()

	_ = c.get(context.Background(), "org-a")
	if r.callCount() != 2 {
		t.Errorf("an expired entry must refresh; calls=%d, want 2", r.callCount())
	}
}

// Invalidation drops the cached entry so the next get re-reads (the hook the
// follow-up portal posture-set path calls after a write).
func TestDetectionOverrideCache_InvalidateForcesReread(t *testing.T) {
	r := &fakeOverrideReader{data: map[string]map[string]agent.DetectionAction{"org-a": {agent.DetectionCategoryPII: agent.DetectionActionRedact}}}
	c := installTestOverrideCache(t, r, time.Minute)

	_ = c.get(context.Background(), "org-a")
	InvalidateOrgDetectionOverrides("org-a")
	_ = c.get(context.Background(), "org-a")
	if r.callCount() != 2 {
		t.Errorf("invalidate must force a re-read; calls=%d, want 2", r.callCount())
	}
}

// The cache is size-bounded: inserting more distinct orgs than maxEntries must
// not grow the map without limit (protects against a flood of distinct org IDs).
func TestDetectionOverrideCache_SizeBounded(t *testing.T) {
	r := &fakeOverrideReader{data: map[string]map[string]agent.DetectionAction{}}
	// Construct directly to use a tiny cap (the constructor clamps to >=128).
	c := &detectionOverrideCache{
		entries:    make(map[string]detectionOverrideCacheEntry),
		reader:     r,
		ttl:        time.Minute,
		errTTL:     time.Minute,
		maxEntries: 2,
	}
	for _, org := range []string{"o1", "o2", "o3", "o4", "o5"} {
		_ = c.get(context.Background(), org)
	}
	c.mu.RLock()
	n := len(c.entries)
	c.mu.RUnlock()
	if n > 2 {
		t.Errorf("cache exceeded size bound: %d entries, want <= 2", n)
	}
}

// ResolveGatewayDetectionConfig layers the override on top of the cached
// deployment-global gateway config (driven by env) end to end.
func TestResolveGatewayDetectionConfig_LayersOnGlobalEnv(t *testing.T) {
	t.Setenv("PII_ACTION", "block")
	t.Setenv("SQLI_ACTION", "block")
	agent.ResetDetectionConfigCache()
	t.Cleanup(agent.ResetDetectionConfigCache)

	installTestOverrideCache(t, &fakeOverrideReader{
		data: map[string]map[string]agent.DetectionAction{"org-redact": {agent.DetectionCategoryPII: agent.DetectionActionRedact}},
	}, time.Minute)

	ctx := context.Background()
	if got := ResolveGatewayDetectionConfig(ctx, "org-redact").PIIAction; got != agent.DetectionActionRedact {
		t.Errorf("org-redact gateway PIIAction = %q, want redact", got)
	}
	if got := ResolveGatewayDetectionConfig(ctx, "org-default").PIIAction; got != agent.DetectionActionBlock {
		t.Errorf("org-default gateway PIIAction = %q, want block (global)", got)
	}
}

// ResolveGatewayPIIActionOverride reports the EXPLICIT per-org PII action and
// whether one is set (the signal the skipRedaction revert decision needs).
func TestResolveGatewayPIIActionOverride(t *testing.T) {
	installTestOverrideCache(t, &fakeOverrideReader{
		data: map[string]map[string]agent.DetectionAction{
			"org-redact": {agent.DetectionCategoryPII: agent.DetectionActionRedact},
			"org-sqli":   {agent.DetectionCategorySQLI: agent.DetectionActionWarn}, // no pii override
		},
	}, time.Minute)
	ctx := context.Background()

	if a, ok := ResolveGatewayPIIActionOverride(ctx, "org-redact"); !ok || a != agent.DetectionActionRedact {
		t.Errorf("org-redact = (%q,%v), want (redact,true)", a, ok)
	}
	if _, ok := ResolveGatewayPIIActionOverride(ctx, "org-sqli"); ok {
		t.Errorf("org-sqli has no PII override; want ok=false")
	}
	if _, ok := ResolveGatewayPIIActionOverride(ctx, "org-none"); ok {
		t.Errorf("org-none has no overrides; want ok=false")
	}
	if _, ok := ResolveGatewayPIIActionOverride(ctx, ""); ok {
		t.Errorf("empty org must report no override; want ok=false")
	}
}

func TestResolveDetectionOverrideTTL(t *testing.T) {
	t.Run("unset uses default", func(t *testing.T) {
		t.Setenv(agent.EnvDetectionOverrideTTLSeconds, "")
		if got := resolveDetectionOverrideTTL(); got != defaultDetectionOverrideTTL {
			t.Errorf("got %s, want default %s", got, defaultDetectionOverrideTTL)
		}
	})
	t.Run("valid", func(t *testing.T) {
		t.Setenv(agent.EnvDetectionOverrideTTLSeconds, "120")
		if got := resolveDetectionOverrideTTL(); got != 120*time.Second {
			t.Errorf("got %s, want 120s", got)
		}
	})
	t.Run("invalid uses default", func(t *testing.T) {
		t.Setenv(agent.EnvDetectionOverrideTTLSeconds, "abc")
		if got := resolveDetectionOverrideTTL(); got != defaultDetectionOverrideTTL {
			t.Errorf("got %s, want default", got)
		}
	})
	t.Run("clamped to min", func(t *testing.T) {
		t.Setenv(agent.EnvDetectionOverrideTTLSeconds, "1")
		if got := resolveDetectionOverrideTTL(); got != minDetectionOverrideTTL {
			t.Errorf("got %s, want min %s", got, minDetectionOverrideTTL)
		}
	})
	t.Run("clamped to max", func(t *testing.T) {
		t.Setenv(agent.EnvDetectionOverrideTTLSeconds, "99999")
		if got := resolveDetectionOverrideTTL(); got != maxDetectionOverrideTTL {
			t.Errorf("got %s, want max %s", got, maxDetectionOverrideTTL)
		}
	})
}

func TestResolveDetectionOverrideMaxEntries(t *testing.T) {
	t.Run("unset uses default", func(t *testing.T) {
		t.Setenv(EnvDetectionOverrideMaxEntries, "")
		if got := resolveDetectionOverrideMaxEntries(); got != defaultDetectionOverrideMaxEntries {
			t.Errorf("got %d, want default %d", got, defaultDetectionOverrideMaxEntries)
		}
	})
	t.Run("valid", func(t *testing.T) {
		t.Setenv(EnvDetectionOverrideMaxEntries, "500")
		if got := resolveDetectionOverrideMaxEntries(); got != 500 {
			t.Errorf("got %d, want 500", got)
		}
	})
	t.Run("invalid uses default", func(t *testing.T) {
		t.Setenv(EnvDetectionOverrideMaxEntries, "nope")
		if got := resolveDetectionOverrideMaxEntries(); got != defaultDetectionOverrideMaxEntries {
			t.Errorf("got %d, want default", got)
		}
	})
	t.Run("clamped to min", func(t *testing.T) {
		t.Setenv(EnvDetectionOverrideMaxEntries, "1")
		if got := resolveDetectionOverrideMaxEntries(); got != minDetectionOverrideMaxEntries {
			t.Errorf("got %d, want min %d", got, minDetectionOverrideMaxEntries)
		}
	})
}
