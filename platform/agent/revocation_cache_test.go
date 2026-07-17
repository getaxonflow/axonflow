// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	identity "axonflow/platform/shared/identity"
)

// fakeWatermarkChecker is a programmable WatermarkedRevocationChecker that
// counts how many times each method touched the "DB".
type fakeWatermarkChecker struct {
	mu            sync.Mutex
	checkCalls    int
	isRevokedCall int
	fn            func(orgID, jti, email string, issuedAt time.Time) (identity.RevocationCheck, error)
}

func (f *fakeWatermarkChecker) CheckRevocation(_ context.Context, orgID, jti, email string, issuedAt time.Time) (identity.RevocationCheck, error) {
	f.mu.Lock()
	f.checkCalls++
	f.mu.Unlock()
	if f.fn != nil {
		return f.fn(orgID, jti, email, issuedAt)
	}
	return identity.RevocationCheck{}, nil
}

func (f *fakeWatermarkChecker) IsRevoked(ctx context.Context, orgID, jti, email string, issuedAt time.Time) (bool, error) {
	f.mu.Lock()
	f.isRevokedCall++
	f.mu.Unlock()
	res, err := f.CheckRevocation(ctx, orgID, jti, email, issuedAt)
	// undo the double count from the delegated CheckRevocation
	f.mu.Lock()
	f.checkCalls--
	f.mu.Unlock()
	return res.Revoked, err
}

func (f *fakeWatermarkChecker) calls() (check, isRevoked int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checkCalls, f.isRevokedCall
}

// plainChecker implements ONLY RevocationChecker (no watermark support), to
// exercise the TTL-only fallback path.
type plainChecker struct {
	mu      sync.Mutex
	calls   int
	revoked bool
	err     error
}

func (p *plainChecker) IsRevoked(_ context.Context, _, _, _ string, _ time.Time) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.revoked, p.err
}

// newTestCache builds a cache with an injectable clock over the given inner.
func newTestCache(inner identity.RevocationChecker, clock *int64) *cachedRevocationChecker {
	c := newCachedRevocationChecker(inner).(*cachedRevocationChecker)
	c.ttl = 5 * time.Second
	base := time.Unix(1_700_000_000, 0).UTC()
	c.now = func() time.Time { return base.Add(time.Duration(*clock) * time.Second) }
	return c
}

func TestRevocationCache_HitSkipsDB(t *testing.T) {
	ctx := context.Background()
	var clk int64
	inner := &fakeWatermarkChecker{} // always not-revoked, zero watermark
	c := newTestCache(inner, &clk)

	// First call: miss → one DB query.
	revoked, err := c.IsRevoked(ctx, "org-a", "jti-1", "u@x.com", time.Unix(1_700_000_000, 0))
	if err != nil || revoked {
		t.Fatalf("call 1: revoked=%v err=%v, want false/nil", revoked, err)
	}
	// Second call within TTL: hit → no new DB query.
	revoked, err = c.IsRevoked(ctx, "org-a", "jti-1", "u@x.com", time.Unix(1_700_000_000, 0))
	if err != nil || revoked {
		t.Fatalf("call 2: revoked=%v err=%v, want false/nil", revoked, err)
	}
	if check, _ := inner.calls(); check != 1 {
		t.Fatalf("expected exactly 1 DB CheckRevocation (second served from cache), got %d", check)
	}
}

func TestRevocationCache_TTLExpiryRequeries(t *testing.T) {
	ctx := context.Background()
	var clk int64
	inner := &fakeWatermarkChecker{}
	c := newTestCache(inner, &clk)

	iat := time.Unix(1_700_000_000, 0)
	if _, err := c.IsRevoked(ctx, "org-a", "jti-1", "u@x.com", iat); err != nil {
		t.Fatal(err)
	}
	// Advance past TTL (5s).
	clk = 6
	if _, err := c.IsRevoked(ctx, "org-a", "jti-1", "u@x.com", iat); err != nil {
		t.Fatal(err)
	}
	if check, _ := inner.calls(); check != 2 {
		t.Fatalf("expected 2 DB queries (TTL expired between them), got %d", check)
	}
}

// The heart of the security contract: a checker ERROR must DENY (propagate the
// error), and it must NOT be cached as an allow.
func TestRevocationCache_CheckerErrorDenies(t *testing.T) {
	ctx := context.Background()
	var clk int64
	boom := errors.New("db unreachable")
	inner := &fakeWatermarkChecker{
		fn: func(_, _, _ string, _ time.Time) (identity.RevocationCheck, error) {
			return identity.RevocationCheck{}, boom
		},
	}
	c := newTestCache(inner, &clk)

	iat := time.Unix(1_700_000_000, 0)
	revoked, err := c.IsRevoked(ctx, "org-a", "jti-1", "u@x.com", iat)
	if err == nil {
		t.Fatal("checker error must propagate (fail-closed), got nil err")
	}
	if revoked {
		// IsRevoked returns (false, err); the CALLER treats a non-nil err as a
		// deny (checkUserTokenRevoked wraps it into an invalid-token rejection).
		t.Fatal("must not report revoked=true; the non-nil error is the deny signal")
	}
	// A subsequent successful check must hit the DB again — the error was NOT
	// cached as an allow.
	inner.fn = nil // now succeeds, not revoked
	revoked, err = c.IsRevoked(ctx, "org-a", "jti-1", "u@x.com", iat)
	if err != nil || revoked {
		t.Fatalf("after recovery: revoked=%v err=%v, want false/nil", revoked, err)
	}
	if check, _ := inner.calls(); check != 2 {
		t.Fatalf("error path must not cache: expected 2 DB queries, got %d", check)
	}
}

// A mass revoke must NOT be masked by the TTL. Once the process observes a
// user's mass-revoke watermark (via ANY query for that user), every cached
// not-revoked token of that user predating the watermark is denied on its next
// check — without a DB round trip and without waiting for TTL expiry.
func TestRevocationCache_MassRevokeCaughtViaWatermark(t *testing.T) {
	ctx := context.Background()
	var clk int64
	base := time.Unix(1_700_000_000, 0)
	tokenIAT := base                        // both tokens minted at base
	massRevokeBefore := base.Add(time.Hour) // revoke everything minted before base+1h

	var massRevokeActive bool
	inner := &fakeWatermarkChecker{
		fn: func(_, jti, _ string, issuedAt time.Time) (identity.RevocationCheck, error) {
			if !massRevokeActive {
				return identity.RevocationCheck{Revoked: false}, nil
			}
			// mass revoke live: token is revoked iff minted before the watermark,
			// and the watermark is reported to the caller.
			return identity.RevocationCheck{
				Revoked:             issuedAt.Before(massRevokeBefore),
				MassRevokeWatermark: massRevokeBefore,
			}, nil
		},
	}
	c := newTestCache(inner, &clk)

	// jti-1 cached as not-revoked (before the mass revoke).
	if revoked, err := c.IsRevoked(ctx, "org-a", "jti-1", "u@x.com", tokenIAT); err != nil || revoked {
		t.Fatalf("jti-1 pre-revoke: revoked=%v err=%v, want false/nil", revoked, err)
	}

	// Admin mass-revokes the user. The process learns the watermark the next
	// time it queries ANY token for that user — here jti-2 (a fresh jti, cache
	// miss → live query).
	massRevokeActive = true
	if revoked, err := c.IsRevoked(ctx, "org-a", "jti-2", "u@x.com", tokenIAT); err != nil || !revoked {
		t.Fatalf("jti-2 post-revoke: revoked=%v err=%v, want true/nil", revoked, err)
	}

	// Now jti-1 is STILL within its 5s TTL (clock has not advanced), but it must
	// be denied via the learned watermark — NOT served stale from cache — and
	// WITHOUT another DB round trip.
	checkBefore, _ := inner.calls()
	if revoked, err := c.IsRevoked(ctx, "org-a", "jti-1", "u@x.com", tokenIAT); err != nil || !revoked {
		t.Fatalf("jti-1 after mass-revoke observed: revoked=%v err=%v, want true/nil (watermark)", revoked, err)
	}
	checkAfter, _ := inner.calls()
	if checkAfter != checkBefore {
		t.Fatalf("watermark deny must not hit the DB: DB calls went %d→%d", checkBefore, checkAfter)
	}
}

// A token minted AT OR AFTER the mass-revoke watermark survives (rotation).
func TestRevocationCache_TokenAfterWatermarkSurvives(t *testing.T) {
	ctx := context.Background()
	var clk int64
	base := time.Unix(1_700_000_000, 0)
	watermark := base.Add(time.Hour)
	inner := &fakeWatermarkChecker{
		fn: func(_, _, _ string, issuedAt time.Time) (identity.RevocationCheck, error) {
			return identity.RevocationCheck{
				Revoked:             issuedAt.Before(watermark),
				MassRevokeWatermark: watermark,
			}, nil
		},
	}
	c := newTestCache(inner, &clk)

	// Fresh token minted after the watermark (rotation replacement).
	fresh := watermark.Add(time.Minute)
	if revoked, err := c.IsRevoked(ctx, "org-a", "jti-new", "u@x.com", fresh); err != nil || revoked {
		t.Fatalf("post-watermark token: revoked=%v err=%v, want false/nil", revoked, err)
	}
	// And it is cached (second call, no DB).
	if revoked, err := c.IsRevoked(ctx, "org-a", "jti-new", "u@x.com", fresh); err != nil || revoked {
		t.Fatalf("post-watermark token cached: revoked=%v err=%v, want false/nil", revoked, err)
	}
	if check, _ := inner.calls(); check != 1 {
		t.Fatalf("expected 1 DB call (second cached), got %d", check)
	}
}

// A revoked verdict must never be written as a not-revoked cache entry.
func TestRevocationCache_RevokedNotCachedAsAllow(t *testing.T) {
	ctx := context.Background()
	var clk int64
	inner := &fakeWatermarkChecker{
		fn: func(_, _, _ string, _ time.Time) (identity.RevocationCheck, error) {
			return identity.RevocationCheck{Revoked: true}, nil // jti individually revoked
		},
	}
	c := newTestCache(inner, &clk)

	iat := time.Unix(1_700_000_000, 0)
	for i := 0; i < 3; i++ {
		revoked, err := c.IsRevoked(ctx, "org-a", "jti-dead", "u@x.com", iat)
		if err != nil || !revoked {
			t.Fatalf("call %d: revoked=%v err=%v, want true/nil", i, revoked, err)
		}
	}
	// Every call must have hit the DB — a revoked verdict is never cached.
	if check, _ := inner.calls(); check != 3 {
		t.Fatalf("revoked verdict must not be cached: expected 3 DB calls, got %d", check)
	}
}

// A jti-less token is delegated uncached (the cache keys on jti).
func TestRevocationCache_NoJTIDelegatesUncached(t *testing.T) {
	ctx := context.Background()
	var clk int64
	inner := &fakeWatermarkChecker{}
	c := newTestCache(inner, &clk)

	for i := 0; i < 2; i++ {
		if _, err := c.IsRevoked(ctx, "org-a", "", "u@x.com", time.Unix(1_700_000_000, 0)); err != nil {
			t.Fatal(err)
		}
	}
	_, isRevoked := inner.calls()
	if isRevoked != 2 {
		t.Fatalf("jti-less must delegate uncached via IsRevoked each time, got %d", isRevoked)
	}
}

// The TTL-only fallback path (inner without watermark support) still caches a
// not-revoked result and fails closed on error.
func TestRevocationCache_PlainCheckerFallback(t *testing.T) {
	ctx := context.Background()
	var clk int64
	inner := &plainChecker{revoked: false}
	c := newTestCache(inner, &clk)
	if c.wm != nil {
		t.Fatal("plainChecker must NOT be detected as a watermarker")
	}

	iat := time.Unix(1_700_000_000, 0)
	// First miss caches; second within TTL is a hit.
	for i := 0; i < 2; i++ {
		if revoked, err := c.IsRevoked(ctx, "org-a", "jti-1", "u@x.com", iat); err != nil || revoked {
			t.Fatalf("call %d: revoked=%v err=%v", i, revoked, err)
		}
	}
	inner.mu.Lock()
	got := inner.calls
	inner.mu.Unlock()
	if got != 1 {
		t.Fatalf("plain fallback should cache: expected 1 DB call, got %d", got)
	}

	// Error path denies and is not cached.
	inner.mu.Lock()
	inner.err = errors.New("boom")
	inner.mu.Unlock()
	clk = 10 // expire the cached entry
	if _, err := c.IsRevoked(ctx, "org-a", "jti-1", "u@x.com", iat); err == nil {
		t.Fatal("plain fallback must fail closed on error")
	}
}

func TestNewCachedRevocationChecker_NilInner(t *testing.T) {
	if got := newCachedRevocationChecker(nil); got != nil {
		t.Fatalf("nil inner must yield nil checker (preserve skip semantics), got %v", got)
	}
}

// The not-revoked and watermark maps are bounded: on overflow the cache evicts
// expired entries and, if still full, clears — never growing without bound and
// always failing closed (a dropped entry just re-queries).
func TestRevocationCache_BoundedEviction(t *testing.T) {
	ctx := context.Background()
	var clk int64
	inner := &fakeWatermarkChecker{} // always not-revoked, zero watermark
	c := newTestCache(inner, &clk)
	c.maxEntries = 2 // tiny cap to force eviction paths

	iat := time.Unix(1_700_000_000, 0)

	// Phase 1 — overflow while every entry is still FRESH exercises the
	// clear-fallback: eviction frees nothing, so the map is cleared. Fill past
	// the cap all at clk=0.
	for i, jti := range []string{"j1", "j2", "j3", "j4", "j5"} {
		email := string(rune('a'+i)) + "@x.com"
		if _, err := c.IsRevoked(ctx, "org-a", jti, email, iat); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		n := len(c.notRevoked)
		c.mu.Unlock()
		if n > c.maxEntries {
			t.Fatalf("after %s: notRevoked unbounded (%d > cap %d)", jti, n, c.maxEntries)
		}
	}

	// Phase 2 — refill to exactly the cap with FRESH entries, then advance past
	// the TTL and insert once more so the overflow SWEEPS the now-expired
	// entries (the delete branch), not the clear fallback.
	c.mu.Lock()
	c.notRevoked = map[string]notRevokedEntry{
		"e1": {expiresAt: c.now().Add(c.ttl)},
		"e2": {expiresAt: c.now().Add(c.ttl)},
	}
	c.mu.Unlock()
	clk = 10 // past the 5s TTL → e1/e2 are expired
	if _, err := c.IsRevoked(ctx, "org-a", "e3", "z@x.com", iat); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	_, hasE1 := c.notRevoked["e1"]
	_, hasE3 := c.notRevoked[revocationCacheKey("org-a", "e3")]
	after := len(c.notRevoked)
	c.mu.Unlock()
	if hasE1 {
		t.Fatal("expired entry e1 should have been swept on overflow")
	}
	if !hasE3 || after > c.maxEntries {
		t.Fatalf("post-sweep state wrong: hasE3=%v size=%d cap=%d", hasE3, after, c.maxEntries)
	}
}

// storeNotRevokedLocked falls back to clearing the map when the full map has no
// expired entries to evict — the defensive branch that keeps the map bounded
// even if every entry is still fresh. White-box: exercised directly because a
// forward-only clock makes older entries always evictable via the public path.
func TestRevocationCache_StoreClearsWhenNothingExpired(t *testing.T) {
	inner := &fakeWatermarkChecker{}
	var clk int64
	c := newTestCache(inner, &clk)
	c.maxEntries = 2

	future := time.Unix(1_700_100_000, 0)
	c.mu.Lock()
	// Two entries whose expiry is AFTER "now" → eviction frees nothing, so the
	// clear fallback must fire.
	c.notRevoked["k1"] = notRevokedEntry{expiresAt: future}
	c.notRevoked["k2"] = notRevokedEntry{expiresAt: future}
	c.storeNotRevokedLocked("k3", future.Add(-time.Hour)) // now is before the entries' expiry
	n := len(c.notRevoked)
	_, hasK3 := c.notRevoked["k3"]
	c.mu.Unlock()

	if n != 1 || !hasK3 {
		t.Fatalf("clear fallback: expected map reset to just the new entry, got %d entries (hasK3=%v)", n, hasK3)
	}
}

// Watermark-map overflow clears BOTH maps (a dropped watermark must not leave a
// stale not-revoked entry behind).
func TestRevocationCache_WatermarkMapBounded(t *testing.T) {
	ctx := context.Background()
	var clk int64
	base := time.Unix(1_700_000_000, 0)
	// Every user has a mass-revoke watermark, but tokens are minted AFTER it so
	// they survive (not revoked) and get cached — exercising both maps growing.
	wm := base.Add(-time.Hour)
	inner := &fakeWatermarkChecker{
		fn: func(_, _, _ string, _ time.Time) (identity.RevocationCheck, error) {
			return identity.RevocationCheck{Revoked: false, MassRevokeWatermark: wm}, nil
		},
	}
	c := newTestCache(inner, &clk)
	c.maxEntries = 2

	for i, jti := range []string{"j1", "j2", "j3", "j4"} {
		email := string(rune('a'+i)) + "@x.com"
		if _, err := c.IsRevoked(ctx, "org-a", jti, email, base); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	nW := len(c.watermark)
	c.mu.Unlock()
	if nW > c.maxEntries {
		t.Fatalf("watermark map unbounded: %d > cap %d", nW, c.maxEntries)
	}
}

// The watermark map is monotonic: an older (smaller) watermark reported later
// never lowers a higher one already observed.
func TestRevocationCache_WatermarkMonotonic(t *testing.T) {
	ctx := context.Background()
	var clk int64
	base := time.Unix(1_700_000_000, 0)
	high := base.Add(2 * time.Hour)
	low := base.Add(1 * time.Hour)

	reported := high
	inner := &fakeWatermarkChecker{
		fn: func(_, _, _ string, issuedAt time.Time) (identity.RevocationCheck, error) {
			return identity.RevocationCheck{
				Revoked:             issuedAt.Before(reported),
				MassRevokeWatermark: reported,
			}, nil
		},
	}
	c := newTestCache(inner, &clk)

	// Observe the HIGH watermark first (token minted after it → survives).
	survivor := high.Add(time.Minute)
	if revoked, err := c.IsRevoked(ctx, "org-a", "jti-s", "u@x.com", survivor); err != nil || revoked {
		t.Fatalf("survivor: revoked=%v err=%v, want false/nil", revoked, err)
	}
	// Now a query reports a LOWER watermark. It must not lower the stored high.
	reported = low
	if _, err := c.IsRevoked(ctx, "org-a", "jti-x", "u@x.com", base); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	stored := c.watermark[revocationUserKey("org-a", "u@x.com")]
	c.mu.Unlock()
	if !stored.Equal(high) {
		t.Fatalf("watermark must stay monotonic at %v, got %v", high, stored)
	}
}
