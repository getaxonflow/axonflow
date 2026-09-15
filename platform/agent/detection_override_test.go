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

// pinGatewayOverride writes set's changes into the cached GATEWAY mode config
// for the test's lifetime. The action fields of that config are exactly the slot
// applyOrgDetectionOverrides fills from an organization's recorded override, so
// this is how a test whose request resolves NO organization (a community-mode
// pre-check, an AuthZEN envelope) puts the handler under an override. A test
// whose request carries an org should install an override cache for that org
// instead (installTestOverrideCache), which exercises the resolution itself.
func pinGatewayOverride(t *testing.T, set func(*ModeDetectionConfig)) {
	t.Helper()
	cfg := GatewayDetectionConfigFromEnv()
	set(&cfg)
	detectionConfigMu.Lock()
	orig := cachedGatewayConfig
	cachedGatewayConfig = &cfg
	detectionConfigMu.Unlock()
	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedGatewayConfig = orig
		detectionConfigMu.Unlock()
	})
}

// pinMCPOverride is pinGatewayOverride for the cached MCP mode config.
func pinMCPOverride(t *testing.T, set func(*ModeDetectionConfig)) {
	t.Helper()
	cfg := MCPDetectionConfigFromEnv()
	set(&cfg)
	detectionConfigMu.Lock()
	orig := cachedMCPConfig
	cachedMCPConfig = &cfg
	detectionConfigMu.Unlock()
	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedMCPConfig = orig
		detectionConfigMu.Unlock()
	})
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

// noOverrideBase is the process mode config as v11 builds it: enabled, and with
// no action in any field, because only an organization's recorded override
// writes one (#3961).
func noOverrideBase() ModeDetectionConfig {
	return ModeDetectionConfig{Enabled: true}
}

// An org with a per-category override gets that action; categories without an
// override stay empty, so their stored policy action decides. This is the core
// #2581 contract.
func TestApplyOrgDetectionOverrides_OverrideWinsPerCategory(t *testing.T) {
	installTestOverrideCache(t, &fakeOverrideReader{
		data: map[string]map[string]DetectionAction{
			"org-a": {DetectionCategoryPII: DetectionActionRedact, DetectionCategorySQLI: DetectionActionWarn},
		},
	}, time.Minute)

	got := applyOrgDetectionOverrides(context.Background(), "org-a", noOverrideBase())
	if got.PIIAction != DetectionActionRedact {
		t.Errorf("PIIAction = %q, want redact (per-org override)", got.PIIAction)
	}
	if got.SQLIAction != DetectionActionWarn {
		t.Errorf("SQLIAction = %q, want warn (per-org override)", got.SQLIAction)
	}
	// No override for these → no action, the stored policy action decides.
	if got.DangerousQueryAction != "" || got.DangerousCommandAction != "" {
		t.Errorf("un-overridden categories must carry no action; got dq=%q dc=%q", got.DangerousQueryAction, got.DangerousCommandAction)
	}
	if overrides := got.BuildActionOverrides(); overrides[sharedpolicy.CategorySecurityDangerous] != "" {
		t.Errorf("an un-overridden category reached ActionOverrides: %v", overrides)
	}
}

// An org with NO override row resolves to the mode config unchanged.
func TestApplyOrgDetectionOverrides_NoOverrideLeavesConfigUnchanged(t *testing.T) {
	installTestOverrideCache(t, &fakeOverrideReader{
		data: map[string]map[string]DetectionAction{"org-a": {DetectionCategoryPII: DetectionActionRedact}},
	}, time.Minute)

	got := applyOrgDetectionOverrides(context.Background(), "org-other", noOverrideBase())
	if !sameActions(got, noOverrideBase()) {
		t.Errorf("org with no override must equal the mode config; got %+v", got)
	}
	// Control: the org that HAS an override resolves one through the same cache,
	// so the equality above is not the cache being unreachable.
	if a := applyOrgDetectionOverrides(context.Background(), "org-a", noOverrideBase()).PIIAction; a != DetectionActionRedact {
		t.Fatalf("control: org-a PIIAction = %q, want redact", a)
	}
}

// Empty orgID (unauthenticated / community / internal-service-with-no-org) must
// NOT touch the cache and must return the mode config — fail-safe + cheap.
func TestApplyOrgDetectionOverrides_EmptyOrgNoLookup(t *testing.T) {
	r := &fakeOverrideReader{data: map[string]map[string]DetectionAction{"org-a": {DetectionCategoryPII: DetectionActionRedact}}}
	installTestOverrideCache(t, r, time.Minute)

	got := applyOrgDetectionOverrides(context.Background(), "", noOverrideBase())
	if !sameActions(got, noOverrideBase()) {
		t.Errorf("empty orgID must return the mode config; got %+v", got)
	}
	if r.callCount() != 0 {
		t.Errorf("empty orgID must not hit the reader; calls=%d", r.callCount())
	}
}

// With no cache wired (no-DB mode / community), resolution returns the mode
// config: no override, stored actions decide.
func TestApplyOrgDetectionOverrides_NilCacheNoOverride(t *testing.T) {
	ResetDetectionOverrideCacheForTest()
	got := applyOrgDetectionOverrides(context.Background(), "org-a", noOverrideBase())
	if !sameActions(got, noOverrideBase()) {
		t.Errorf("nil cache must return the mode config; got %+v", got)
	}
}

// A lookup error resolves no override (the stored actions decide - NEVER "no
// governance") and is cached briefly so a failing DB is not re-hit per request.
func TestDetectionOverrideCache_LookupErrorFailsSafeToStoredActions(t *testing.T) {
	r := &fakeOverrideReader{err: errors.New("db down")}
	installTestOverrideCache(t, r, time.Minute)

	got := applyOrgDetectionOverrides(context.Background(), "org-a", noOverrideBase())
	if !sameActions(got, noOverrideBase()) {
		t.Errorf("lookup error must resolve no override; got %+v", got)
	}
	// Second resolution within the error window must not re-hit the failing DB.
	_ = applyOrgDetectionOverrides(context.Background(), "org-a", noOverrideBase())
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

// ResolveMCPDetectionConfig / ResolveGatewayDetectionConfig carry the org's
// recorded override end to end, and NOTHING else sets an action: PII_ACTION is
// set here and an org with no override still resolves no action (#3961).
func TestResolveDetectionConfig_OnlyTheRecordedOverrideSetsAnAction(t *testing.T) {
	t.Setenv("PII_ACTION", "block") // removed variable: must set nothing
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
	if got := ResolveMCPDetectionConfig(ctx, "org-default").PIIAction; got != "" {
		t.Errorf("MCP org-default PIIAction = %q, want none: PII_ACTION=block must not set an action", got)
	}
	if got := ResolveGatewayDetectionConfig(ctx, "org-redact").PIIAction; got != DetectionActionRedact {
		t.Errorf("Gateway org-redact PIIAction = %q, want redact", got)
	}
	if got := ResolveGatewayDetectionConfig(ctx, "org-default").PIIAction; got != "" {
		t.Errorf("Gateway org-default PIIAction = %q, want none: PII_ACTION=block must not set an action", got)
	}
}

// WIRING + red-on-revert: the same agent process must produce DIFFERENT
// outcomes for orgs based on their recorded override. This drives the real
// evaluateOutputPolicies check path, so reverting the call-site change from
// ResolveMCPDetectionConfig(ctx, orgID) back to GetMCPDetectionConfig() turns it
// red. Uses the built-in Indonesia NIK detector (no DB / no engine needed),
// which blocks only under a pii=block override and masks only under redact.
// (Test name predates v11, when the "posture" was a deployment-wide variable.)
func TestEvaluateOutputPolicies_PerOrgPosture_SameProcess(t *testing.T) {
	// The mode config carries no action (v11), so each organization's recorded
	// override is the only action the Indonesia response step can take; the
	// migrated database's shipped rows match nothing this message carries.
	detectionConfigMu.Lock()
	origCfg := cachedMCPConfig
	cachedMCPConfig = &ModeDetectionConfig{Enabled: true}
	detectionConfigMu.Unlock()
	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedMCPConfig = origCfg
		detectionConfigMu.Unlock()
	})

	// org-block and org-redact carry pii overrides; org-default has none.
	installTestOverrideCache(t, &fakeOverrideReader{
		data: map[string]map[string]DetectionAction{
			"org-block":  {DetectionCategoryPII: DetectionActionBlock},
			"org-redact": {DetectionCategoryPII: DetectionActionRedact},
		},
	}, time.Minute)

	const nikMsg = "Pelanggan NIK 3174042506780001 terdaftar" // checksum-valid NIK
	eval := func(orgID string) OutputPolicyOutcome {
		return evaluateOutputPolicies(responseRouteContext(orgID), "t1", orgID, "u1", "gw.test", "gw.test", nil, nikMsg, nil, 0, false, true /* isGateway */)
	}

	// org-block → pii=block override → the NIK is BLOCKED on output.
	if out := eval("org-block"); out.StaticResult == nil || !out.StaticResult.Blocked {
		t.Fatalf("org-block must BLOCK the NIK under its pii=block override; got %+v", out.StaticResult)
	}

	// org-redact → pii=redact override → the NIK is MASKED, not blocked.
	outRedact := eval("org-redact")
	if outRedact.StaticResult != nil && outRedact.StaticResult.Blocked {
		t.Fatalf("org-redact must NOT block (override=redact); got blocked")
	}
	if outRedact.RedactedMessage == "" || strings.Contains(outRedact.RedactedMessage, "3174042506780001") {
		t.Fatalf("org-redact must MASK the NIK; got RedactedMessage=%q", outRedact.RedactedMessage)
	}

	// org-default records no override, so it resolves no action: the code-backed
	// detector detects and neither blocks nor masks.
	out := eval("org-default")
	if out.StaticResult != nil && out.StaticResult.Blocked {
		t.Errorf("org-default: no override must not block; got %+v", out.StaticResult)
	}
	if out.RedactedMessage != "" || out.WasRedacted() {
		t.Errorf("org-default: no override must not mask; got RedactedMessage=%q", out.RedactedMessage)
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
