// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	sharedpolicy "axonflow/platform/shared/policy"
)

// fakeOverrideReader is an in-memory detectionOverrideReader for unit tests —
// no DB. It counts calls so cache hit/miss behavior can be asserted, and can be
// made to fail to exercise the fail-safe path.
type fakeOverrideReader struct {
	mu    sync.Mutex
	data  map[string]map[string]DetectionAction
	calls int
	err   error
}

func (f *fakeOverrideReader) ReadOrgOverrides(_ context.Context, orgID string) (map[string]DetectionAction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]DetectionAction{}
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
	c := newDetectionOverrideCache(reader, ttl)
	setDetectionOverrideCacheForTest(c)
	t.Cleanup(ResetDetectionOverrideCacheForTest)
	return c
}

// sameActions reports whether two configs carry identical detection actions
// (ModeDetectionConfig has slice fields, so it isn't directly comparable).
func sameActions(a, b ModeDetectionConfig) bool {
	return a.Enabled == b.Enabled &&
		a.PIIAction == b.PIIAction &&
		a.SQLIAction == b.SQLIAction &&
		a.DangerousQueryAction == b.DangerousQueryAction &&
		a.DangerousCommandAction == b.DangerousCommandAction
}

func blockBase() ModeDetectionConfig {
	return ModeDetectionConfig{
		Enabled:                true,
		PIIAction:              DetectionActionBlock,
		SQLIAction:             DetectionActionBlock,
		DangerousQueryAction:   DetectionActionBlock,
		DangerousCommandAction: DetectionActionBlock,
	}
}

// An org with a per-category override gets that action; categories without an
// override keep the deployment-global value. This is the core #2581 contract.
func TestApplyOrgDetectionOverrides_OverrideWinsPerCategory(t *testing.T) {
	installTestOverrideCache(t, &fakeOverrideReader{
		data: map[string]map[string]DetectionAction{
			"org-a": {DetectionCategoryPII: DetectionActionRedact, DetectionCategorySQLI: DetectionActionWarn},
		},
	}, time.Minute)

	got := applyOrgDetectionOverrides(context.Background(), "org-a", blockBase())
	if got.PIIAction != DetectionActionRedact {
		t.Errorf("PIIAction = %q, want redact (per-org override)", got.PIIAction)
	}
	if got.SQLIAction != DetectionActionWarn {
		t.Errorf("SQLIAction = %q, want warn (per-org override)", got.SQLIAction)
	}
	// No override for these → keep the global (block).
	if got.DangerousQueryAction != DetectionActionBlock || got.DangerousCommandAction != DetectionActionBlock {
		t.Errorf("un-overridden categories must keep global block; got dq=%q dc=%q", got.DangerousQueryAction, got.DangerousCommandAction)
	}
}

// An org with NO override row resolves to the deployment-global config unchanged.
func TestApplyOrgDetectionOverrides_NoOverrideUsesGlobal(t *testing.T) {
	installTestOverrideCache(t, &fakeOverrideReader{
		data: map[string]map[string]DetectionAction{"org-a": {DetectionCategoryPII: DetectionActionRedact}},
	}, time.Minute)

	got := applyOrgDetectionOverrides(context.Background(), "org-other", blockBase())
	if !sameActions(got, blockBase()) {
		t.Errorf("org with no override must equal global config; got %+v", got)
	}
}

// Empty orgID (unauthenticated / community / internal-service-with-no-org) must
// NOT touch the cache and must return the global config — fail-safe + cheap.
func TestApplyOrgDetectionOverrides_EmptyOrgUsesGlobalNoLookup(t *testing.T) {
	r := &fakeOverrideReader{data: map[string]map[string]DetectionAction{"org-a": {DetectionCategoryPII: DetectionActionRedact}}}
	installTestOverrideCache(t, r, time.Minute)

	got := applyOrgDetectionOverrides(context.Background(), "", blockBase())
	if !sameActions(got, blockBase()) {
		t.Errorf("empty orgID must return global config; got %+v", got)
	}
	if r.callCount() != 0 {
		t.Errorf("empty orgID must not hit the reader; calls=%d", r.callCount())
	}
}

// With no cache wired (no-DB mode / community), resolution returns the global
// config — byte-identical to the pre-#2581 behavior.
func TestApplyOrgDetectionOverrides_NilCacheUsesGlobal(t *testing.T) {
	ResetDetectionOverrideCacheForTest()
	got := applyOrgDetectionOverrides(context.Background(), "org-a", blockBase())
	if !sameActions(got, blockBase()) {
		t.Errorf("nil cache must return global config; got %+v", got)
	}
}

// A lookup error falls back to the global config (NEVER fail-open to "no
// governance") and is cached briefly so a failing DB is not re-hit per request.
func TestDetectionOverrideCache_LookupErrorFailsSafeToGlobal(t *testing.T) {
	r := &fakeOverrideReader{err: errors.New("db down")}
	installTestOverrideCache(t, r, time.Minute)

	got := applyOrgDetectionOverrides(context.Background(), "org-a", blockBase())
	if !sameActions(got, blockBase()) {
		t.Errorf("lookup error must fall back to global config; got %+v", got)
	}
	// Second resolution within the error window must not re-hit the failing DB.
	_ = applyOrgDetectionOverrides(context.Background(), "org-a", blockBase())
	if r.callCount() != 1 {
		t.Errorf("error result must be cached (no hot-path hammering); calls=%d, want 1", r.callCount())
	}
}

// A fresh result is served from cache within the TTL window (no per-request DB).
func TestDetectionOverrideCache_CachesWithinTTL(t *testing.T) {
	r := &fakeOverrideReader{data: map[string]map[string]DetectionAction{"org-a": {DetectionCategoryPII: DetectionActionRedact}}}
	c := installTestOverrideCache(t, r, time.Minute)

	_ = c.get(context.Background(), "org-a")
	_ = c.get(context.Background(), "org-a")
	if r.callCount() != 1 {
		t.Errorf("two gets within TTL must read the DB once; calls=%d", r.callCount())
	}
}

// An expired entry triggers a refresh on the next get.
func TestDetectionOverrideCache_ExpiryRefreshes(t *testing.T) {
	r := &fakeOverrideReader{data: map[string]map[string]DetectionAction{"org-a": {DetectionCategoryPII: DetectionActionRedact}}}
	c := installTestOverrideCache(t, r, time.Minute)

	_ = c.get(context.Background(), "org-a")
	// Force expiry deterministically (no sleep).
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
	r := &fakeOverrideReader{data: map[string]map[string]DetectionAction{"org-a": {DetectionCategoryPII: DetectionActionRedact}}}
	c := installTestOverrideCache(t, r, time.Minute)

	_ = c.get(context.Background(), "org-a")
	InvalidateOrgDetectionOverrides("org-a")
	_ = c.get(context.Background(), "org-a")
	if r.callCount() != 2 {
		t.Errorf("invalidate must force a re-read; calls=%d, want 2", r.callCount())
	}
}

// ResolveMCPDetectionConfig / ResolveGatewayDetectionConfig layer the override on
// top of the cached deployment-global config end to end.
func TestResolveDetectionConfig_LayersOnGlobalEnv(t *testing.T) {
	t.Setenv("PII_ACTION", "block")
	ResetDetectionConfigCache()
	InitDetectionConfigs()
	t.Cleanup(ResetDetectionConfigCache)

	installTestOverrideCache(t, &fakeOverrideReader{
		data: map[string]map[string]DetectionAction{"org-redact": {DetectionCategoryPII: DetectionActionRedact}},
	}, time.Minute)

	ctx := context.Background()
	if got := ResolveMCPDetectionConfig(ctx, "org-redact").PIIAction; got != DetectionActionRedact {
		t.Errorf("MCP org-redact PIIAction = %q, want redact", got)
	}
	if got := ResolveMCPDetectionConfig(ctx, "org-default").PIIAction; got != DetectionActionBlock {
		t.Errorf("MCP org-default PIIAction = %q, want block (global)", got)
	}
	if got := ResolveGatewayDetectionConfig(ctx, "org-redact").PIIAction; got != DetectionActionRedact {
		t.Errorf("Gateway org-redact PIIAction = %q, want redact", got)
	}
	if got := ResolveGatewayDetectionConfig(ctx, "org-default").PIIAction; got != DetectionActionBlock {
		t.Errorf("Gateway org-default PIIAction = %q, want block (global)", got)
	}
}

// WIRING + red-on-revert: the same agent process, with one global posture
// (PII_ACTION=block), must produce DIFFERENT outcomes for two orgs based on the
// org carried in the request context. This drives the real evaluateOutputPolicies
// check path (which resolves the org from ctx), so reverting the call-site change
// from ResolveMCPDetectionConfig(ctx, …) back to GetMCPDetectionConfig() turns it
// red. Uses the built-in Indonesia NIK detector (no DB / no engine needed).
func TestEvaluateOutputPolicies_PerOrgPosture_SameProcess(t *testing.T) {
	// Pin the deployment-global posture to block and nil the static engine so
	// only the (DB-free) Indonesia response step runs — deterministic.
	detectionConfigMu.Lock()
	origCfg := cachedMCPConfig
	cachedMCPConfig = &ModeDetectionConfig{Enabled: true, PIIAction: DetectionActionBlock}
	detectionConfigMu.Unlock()
	origEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedMCPConfig = origCfg
		detectionConfigMu.Unlock()
		sharedpolicy.SetGlobalEngine(origEngine)
	})

	// org-redact overrides PII to redact; org-default has no override.
	installTestOverrideCache(t, &fakeOverrideReader{
		data: map[string]map[string]DetectionAction{"org-redact": {DetectionCategoryPII: DetectionActionRedact}},
	}, time.Minute)

	const nikMsg = "Pelanggan NIK 3174042506780001 terdaftar" // checksum-valid NIK

	// org-default → deployment-global block → the NIK is BLOCKED on output.
	ctxDefault := context.WithValue(context.Background(), ContextKeyOrgID, "org-default")
	outDefault := evaluateOutputPolicies(ctxDefault, "t1", "u1", "gw.test", "gw.test", nil, nikMsg, nil, 0, false, true /* isGateway */)
	if outDefault.StaticResult == nil || !outDefault.StaticResult.Blocked {
		t.Fatalf("org-default must BLOCK the NIK under global block; got %+v", outDefault.StaticResult)
	}

	// org-redact → per-org redact → the NIK is MASKED, not blocked.
	ctxRedact := context.WithValue(context.Background(), ContextKeyOrgID, "org-redact")
	outRedact := evaluateOutputPolicies(ctxRedact, "t1", "u1", "gw.test", "gw.test", nil, nikMsg, nil, 0, false, true /* isGateway */)
	if outRedact.StaticResult != nil && outRedact.StaticResult.Blocked {
		t.Fatalf("org-redact must NOT block (override=redact); got blocked")
	}
	if outRedact.RedactedMessage == "" || strings.Contains(outRedact.RedactedMessage, "3174042506780001") {
		t.Fatalf("org-redact must MASK the NIK; got RedactedMessage=%q", outRedact.RedactedMessage)
	}

	// Empty org (no stamp) → deployment-global block (fail-safe).
	outNoOrg := evaluateOutputPolicies(context.Background(), "t1", "u1", "gw.test", "gw.test", nil, nikMsg, nil, 0, false, true)
	if outNoOrg.StaticResult == nil || !outNoOrg.StaticResult.Blocked {
		t.Fatalf("no-org request must fall back to global block; got %+v", outNoOrg.StaticResult)
	}
}

func TestParseOverrideAction(t *testing.T) {
	for _, a := range []string{"block", "redact", "warn", "log"} {
		if got, ok := parseOverrideAction(a); !ok || string(got) != a {
			t.Errorf("parseOverrideAction(%q) = (%q,%v), want (%q,true)", a, got, ok, a)
		}
	}
	for _, bad := range []string{"", "deny", "allow", "BLOCK", "redactt"} {
		if _, ok := parseOverrideAction(bad); ok {
			t.Errorf("parseOverrideAction(%q) must be rejected", bad)
		}
	}
}

func TestResolveDetectionOverrideTTL(t *testing.T) {
	t.Run("unset uses default", func(t *testing.T) {
		t.Setenv(EnvDetectionOverrideTTLSeconds, "")
		if got := resolveDetectionOverrideTTL(); got != defaultDetectionOverrideTTL {
			t.Errorf("got %s, want default %s", got, defaultDetectionOverrideTTL)
		}
	})
	t.Run("valid", func(t *testing.T) {
		t.Setenv(EnvDetectionOverrideTTLSeconds, "120")
		if got := resolveDetectionOverrideTTL(); got != 120*time.Second {
			t.Errorf("got %s, want 120s", got)
		}
	})
	t.Run("invalid uses default", func(t *testing.T) {
		t.Setenv(EnvDetectionOverrideTTLSeconds, "abc")
		if got := resolveDetectionOverrideTTL(); got != defaultDetectionOverrideTTL {
			t.Errorf("got %s, want default", got)
		}
	})
	t.Run("clamped to min", func(t *testing.T) {
		t.Setenv(EnvDetectionOverrideTTLSeconds, "1")
		if got := resolveDetectionOverrideTTL(); got != minDetectionOverrideTTL {
			t.Errorf("got %s, want min %s", got, minDetectionOverrideTTL)
		}
	})
	t.Run("clamped to max", func(t *testing.T) {
		t.Setenv(EnvDetectionOverrideTTLSeconds, "99999")
		if got := resolveDetectionOverrideTTL(); got != maxDetectionOverrideTTL {
			t.Errorf("got %s, want max %s", got, maxDetectionOverrideTTL)
		}
	})
}
