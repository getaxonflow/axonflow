// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"sync"
	"time"

	identity "axonflow/platform/shared/identity"
)

// revocationCacheTTL bounds how long a confirmed not-revoked result is served
// from memory before it is re-queried. 5s keeps the residual staleness of a
// SINGLE-token revoke small while still absorbing a high-QPS fleet's repeated
// decides for the same live token (#2931). A MASS revoke is NOT bound by this
// TTL — it is caught early via the per-user watermark (see below).
const revocationCacheTTL = 5 * time.Second

// revocationCacheMaxEntries caps the not-revoked map so a churn of distinct
// jtis cannot grow it without bound. On overflow the cache sweeps expired
// entries and, if still full, clears — always the fail-closed direction (a
// dropped entry just forces a fresh DB query, never a spurious allow).
const revocationCacheMaxEntries = 16384

// cachedRevocationChecker fronts a RevocationChecker with a short-TTL,
// jti-keyed cache of CONFIRMED NOT-REVOKED results, for the /decide hot path
// (#2931). Design invariants (each load-bearing for security):
//
//   - Only a confirmed not-revoked result is ever cached. A revoked verdict is
//     never written as a not-revoked entry, and a checker ERROR is never
//     cached at all — it propagates so the caller fails closed (denies). There
//     is no cached-DENY→ALLOW path.
//   - A mass revocation is not masked by the TTL. Every live query also learns
//     the user's mass-revoke watermark (MAX(issued_before)); the moment the
//     process observes a newer watermark for a user, EVERY cached not-revoked
//     entry for that user whose token predates the watermark is treated as
//     revoked on its next check — without waiting out its TTL. The TTL remains
//     the hard upper bound for the residual case where a user's only active
//     token is the one being mass-revoked (no other query refreshes the
//     watermark); that residual is ≤ revocationCacheTTL.
//   - A single-token (jti) revoke of an already-cached token is served stale
//     for at most revocationCacheTTL — the documented, bounded cost of any
//     TTL cache; the short TTL keeps it small.
//   - It only ever sees minted-token traffic: checkUserTokenRevoked returns
//     before calling into the cache for jti-less legacy tokens and when no
//     checker is wired (community / non-Enterprise), so legacy/license-only
//     traffic pays nothing.
//
// It implements identity.RevocationChecker so it drops in transparently where
// the raw store did.
type cachedRevocationChecker struct {
	inner identity.RevocationChecker
	// wm is inner when inner also reports the mass-revoke watermark; nil
	// otherwise (the cache then degrades to TTL-only, no early cross-token
	// invalidation — still correct, just less timely on a mass revoke).
	wm         identity.WatermarkedRevocationChecker
	ttl        time.Duration
	now        func() time.Time
	maxEntries int

	mu sync.Mutex
	// notRevoked maps orgID\x00jti → a confirmed-not-revoked entry. Keyed on
	// jti alone (not email/iat): a jti uniquely identifies a validated token —
	// the signature is checked upstream before revocation — so (orgID, jti)
	// determines the token, and the live email/iat carry all the state the
	// watermark short-circuit needs.
	notRevoked map[string]notRevokedEntry
	// watermark maps orgID\x00canonicalEmail → the greatest mass-revoke
	// issued_before observed for that user. Monotonic (only ever advances).
	watermark map[string]time.Time
}

// notRevokedEntry is a named type (rather than a bare time.Time) so it is never
// confused with the watermark map at a call site; expiresAt is the only state a
// not-revoked entry needs.
type notRevokedEntry struct {
	expiresAt time.Time
}

// newCachedRevocationChecker wraps inner. Returns nil when inner is nil so the
// caller's nil-checker semantics (revocation lookup skipped) are preserved.
func newCachedRevocationChecker(inner identity.RevocationChecker) identity.RevocationChecker {
	if inner == nil {
		return nil
	}
	c := &cachedRevocationChecker{
		inner:      inner,
		ttl:        revocationCacheTTL,
		now:        time.Now,
		maxEntries: revocationCacheMaxEntries,
		notRevoked: make(map[string]notRevokedEntry),
		watermark:  make(map[string]time.Time),
	}
	if w, ok := inner.(identity.WatermarkedRevocationChecker); ok {
		c.wm = w
	}
	return c
}

func revocationCacheKey(orgID, jti string) string  { return orgID + "\x00" + jti }
func revocationUserKey(orgID, email string) string { return orgID + "\x00" + email }

// IsRevoked answers from cache when a fresh confirmed not-revoked entry exists
// (skipping the DB), catches a mass revocation via the watermark without a DB
// round trip, and otherwise queries the underlying checker — caching only a
// confirmed not-revoked result and failing closed on any error.
func (c *cachedRevocationChecker) IsRevoked(ctx context.Context, orgID, jti, email string, issuedAt time.Time) (bool, error) {
	// No jti → not an individually-revocable minted token; the cache keys on
	// jti, so there is nothing to cache. Delegate uncached to preserve exact
	// semantics (checkUserTokenRevoked already skips jti-less tokens, so this is
	// defense in depth for any other caller).
	if jti == "" {
		return c.inner.IsRevoked(ctx, orgID, jti, email, issuedAt)
	}

	canonEmail := identity.CanonicalEmail(email)
	key := revocationCacheKey(orgID, jti)
	userKey := revocationUserKey(orgID, canonEmail)
	now := c.now()

	c.mu.Lock()
	// 1) Watermark short-circuit: a mass revocation this process has already
	//    observed for the user definitively kills every token minted before it.
	//    This is a provably-correct DENY served without a DB round trip — NOT a
	//    cached allow — and it is not bound by the entry TTL.
	if canonEmail != "" {
		if wm, ok := c.watermark[userKey]; ok && issuedAt.Before(wm) {
			c.mu.Unlock()
			return true, nil
		}
	}
	// 2) Fresh confirmed not-revoked entry → cache hit, skip the DB.
	if e, ok := c.notRevoked[key]; ok && now.Before(e.expiresAt) {
		c.mu.Unlock()
		return false, nil
	}
	c.mu.Unlock()

	// 3) Miss (or expired) → live query, fail-closed on error.
	if c.wm != nil {
		res, err := c.wm.CheckRevocation(ctx, orgID, jti, canonEmail, issuedAt)
		if err != nil {
			return false, err // propagate → caller denies; nothing cached
		}
		c.mu.Lock()
		c.recordWatermarkLocked(userKey, res.MassRevokeWatermark)
		if !res.Revoked {
			c.storeNotRevokedLocked(key, now)
		}
		c.mu.Unlock()
		return res.Revoked, nil
	}

	// Underlying checker has no watermark support: TTL-only cache.
	revoked, err := c.inner.IsRevoked(ctx, orgID, jti, canonEmail, issuedAt)
	if err != nil {
		return false, err
	}
	if !revoked {
		c.mu.Lock()
		c.storeNotRevokedLocked(key, now)
		c.mu.Unlock()
	}
	return revoked, nil
}

// recordWatermarkLocked advances the user's observed mass-revoke watermark
// (never lowers it). Caller holds c.mu.
func (c *cachedRevocationChecker) recordWatermarkLocked(userKey string, wm time.Time) {
	if wm.IsZero() {
		return
	}
	if cur, ok := c.watermark[userKey]; !ok || wm.After(cur) {
		if len(c.watermark) >= c.maxEntries {
			// Bound the user map. Clearing both maps is safe: a dropped
			// watermark can only force a fresh DB query (fail-closed direction),
			// and dropping the not-revoked entries alongside it prevents any
			// entry from outliving its watermark.
			c.watermark = make(map[string]time.Time)
			c.notRevoked = make(map[string]notRevokedEntry)
		}
		c.watermark[userKey] = wm
	}
}

// storeNotRevokedLocked records a confirmed not-revoked entry expiring at
// now+ttl. When the map is at capacity it first sweeps genuinely-expired
// entries and, if that frees nothing, clears the map — always bounded, always
// fail-closed (a dropped entry just re-queries). Caller holds c.mu.
func (c *cachedRevocationChecker) storeNotRevokedLocked(key string, now time.Time) {
	if len(c.notRevoked) >= c.maxEntries {
		c.evictExpiredLocked(now)
		if len(c.notRevoked) >= c.maxEntries {
			c.notRevoked = make(map[string]notRevokedEntry)
		}
	}
	c.notRevoked[key] = notRevokedEntry{expiresAt: now.Add(c.ttl)}
}

// evictExpiredLocked drops entries whose TTL has genuinely elapsed as of now
// (now >= expiresAt). Caller holds c.mu.
func (c *cachedRevocationChecker) evictExpiredLocked(now time.Time) {
	for k, e := range c.notRevoked {
		if !now.Before(e.expiresAt) {
			delete(c.notRevoked, k)
		}
	}
}
