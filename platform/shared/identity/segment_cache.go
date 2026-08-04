//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

// Per-(org, email) governance-segment cache (ADR-060 #2989 P2), modeled on
// the shape of platform/agent/detection_override.go's per-org override
// cache: in-process, short clamped TTL, a local invalidation hook. It is
// deliberately NOT a literal copy — the key adds email (segments are a
// per-USER fact, not a per-org one) and, more importantly, the FAILURE
// semantics differ:
//
//   - detection_override.go fails OPEN on a lookup error (falls back to the
//     deployment-global posture, which is always a safe default).
//   - This cache fails CLOSED: ADR-060 requires a genuine segment-query
//     error to surface as an error from Resolve, never be silently
//     swallowed into an empty-but-successful segment set (that would be
//     indistinguishable from the legitimate "zero group memberships"
//     outcome and could under-govern a user whose segment lookup is merely
//     broken). Consequently an ERROR result is NEVER cached here — only a
//     successful (possibly empty) segment set is. A transient failure is
//     therefore retried on the very next call rather than being masked
//     behind a cached "resolved to empty" entry for the TTL window.
//
// Cross-process propagation (a portal write on one replica, an agent read
// on another) is bounded by the TTL, exactly like detection_override.go —
// there is no cross-service invalidation, only the local
// InvalidateUserSegments hook a same-process writer can call.

// EnvSegmentCacheTTLSeconds tunes how long a resolved (org, email) segment
// set is cached before a refresh. Default 60s; clamped to [5s, 600s] —
// identical bounds to detection_override.go's TTL, for the same reasoning
// (fast enough to reflect an admin's group-membership change promptly,
// slow enough to keep the SCIM lookup off the hot path of every request).
const EnvSegmentCacheTTLSeconds = "AXONFLOW_SEGMENT_CACHE_TTL_SECONDS"

const (
	defaultSegmentCacheTTL = 60 * time.Second
	minSegmentCacheTTL     = 5 * time.Second
	maxSegmentCacheTTL     = 600 * time.Second
)

// segmentReader reads the applicable SCIM-group segment set for one
// (orgID, email). An interface so the cache can be unit-tested against a
// fake, mirroring detectionOverrideReader.
type segmentReader interface {
	// ReadUserSegments returns the applicable segment set for (orgID,
	// email). Zero group memberships (or no scim_users row at all) is
	// success: a non-nil, empty slice and a nil error. Any storage/query
	// failure is a non-nil error.
	ReadUserSegments(ctx context.Context, orgID, email string) ([]Segment, error)
}

// dbSegmentReader reads scim_users -> scim_group_members -> scim_groups
// under org scope.
type dbSegmentReader struct {
	db *sql.DB
}

// ReadUserSegments resolves the applicable segment set for (orgID, email):
// every SCIM group email is a member of, in the org addressed by orgID.
//
// Runs inside the same withOrgScope pattern scim_role_resolver.go uses for
// role_assignments: an explicit WHERE, scoping BOTH u.tenant_id AND
// g.tenant_id to orgID (self-hosted single-tenant posture: tenant == org,
// matching scimDirectoryDeactivatedTx's existing assumption), is the
// PRIMARY isolation guarantee here — mig 117 enables RLS on scim_users /
// scim_groups / scim_group_members but does not FORCE it (unlike
// role_assignments, hardened by mig 147), so on the common table-owner
// connection RLS is not a reliably-live second layer; do not remove either
// WHERE condition on the assumption RLS alone would still catch a leak.
// g.tenant_id is scoped independently of u.tenant_id (not inferred via the
// join) as defense-in-depth against a corrupt/cross-tenant
// scim_group_members row — scim_group_members has no CHECK or trigger
// tying a membership's group and user to the same tenant, only FKs on
// group_id/user_id individually — so a membership row that (through a
// provisioning bug, not reachable via this codebase's own write paths)
// links a user in one org to a group in another must not leak that group
// id/display_name into this org's resolution.
//
// A user with no matching scim_users row at all (never SCIM-provisioned, or
// provisioned in a different org) naturally joins to zero rows — the SAME
// "zero groups -> empty success" outcome as a provisioned user with no group
// memberships. No special-casing is needed: the query's own join semantics
// give the correct answer.
func (r *dbSegmentReader) ReadUserSegments(ctx context.Context, orgID, email string) ([]Segment, error) {
	segments := []Segment{}
	err := withOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, `
			SELECT DISTINCT g.id, g.display_name
			FROM scim_users u
			INNER JOIN scim_group_members m ON m.user_id = u.id
			INNER JOIN scim_groups g ON g.id = m.group_id
			WHERE u.tenant_id = $1
			  AND g.tenant_id = $1
			  AND lower(btrim(u.email)) = $2
			ORDER BY g.display_name
		`, orgID, email)
		if qErr != nil {
			return qErr
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var s Segment
			if scanErr := rows.Scan(&s.ID, &s.DisplayName); scanErr != nil {
				return scanErr
			}
			segments = append(segments, s)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("identity: segment membership lookup failed: %w", err)
	}
	return segments, nil
}

// segmentCacheEntry is one (org, email)'s cached segment set + its expiry.
type segmentCacheEntry struct {
	segments  []Segment
	expiresAt time.Time
}

// segmentCache caches per-(org, email) segment sets with a short TTL. See
// the file doc for why lookup ERRORS are never cached (fail closed, not
// fail open).
type segmentCache struct {
	mu      sync.RWMutex
	entries map[string]segmentCacheEntry
	reader  segmentReader
	ttl     time.Duration
}

func newSegmentCache(reader segmentReader, ttl time.Duration) *segmentCache {
	if ttl < minSegmentCacheTTL {
		ttl = minSegmentCacheTTL
	}
	if ttl > maxSegmentCacheTTL {
		ttl = maxSegmentCacheTTL
	}
	return &segmentCache{
		entries: make(map[string]segmentCacheEntry),
		reader:  reader,
		ttl:     ttl,
	}
}

// segmentCacheKey builds the (org, email) cache key. email is expected
// already-canonicalized by the caller (Resolve canonicalizes before calling
// get), so this is a plain join, not a second normalization pass.
func segmentCacheKey(orgID, email string) string {
	return orgID + "\x00" + email
}

// get returns the cached (or freshly-read) segment set for (orgID, email).
// On a read error it returns the error UNCACHED (see file doc: fail closed,
// never fail open) so the very next call retries against storage rather than
// serving a masked empty result for the TTL window.
func (c *segmentCache) get(ctx context.Context, orgID, email string) ([]Segment, error) {
	key := segmentCacheKey(orgID, email)
	now := time.Now()

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.segments, nil
	}

	segments, err := c.reader.ReadUserSegments(ctx, orgID, email)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.entries[key] = segmentCacheEntry{segments: segments, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()
	return segments, nil
}

// invalidate drops (orgID, email)'s cached entry so the next get re-reads.
// Local-process-only (see the InvalidateUserSegments interface doc).
func (c *segmentCache) invalidate(orgID, email string) {
	c.mu.Lock()
	delete(c.entries, segmentCacheKey(orgID, email))
	c.mu.Unlock()
}

// resolveSegmentCacheTTL reads + clamps EnvSegmentCacheTTLSeconds, mirroring
// detection_override.go's resolveDetectionOverrideTTL.
func resolveSegmentCacheTTL() time.Duration {
	raw := os.Getenv(EnvSegmentCacheTTLSeconds)
	if raw == "" {
		return defaultSegmentCacheTTL
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		log.Printf("[Identity] WARNING: invalid %s=%q — using default %s", EnvSegmentCacheTTLSeconds, raw, defaultSegmentCacheTTL)
		return defaultSegmentCacheTTL
	}
	ttl := time.Duration(secs) * time.Second
	if ttl < minSegmentCacheTTL {
		ttl = minSegmentCacheTTL
	}
	if ttl > maxSegmentCacheTTL {
		ttl = maxSegmentCacheTTL
	}
	return ttl
}
