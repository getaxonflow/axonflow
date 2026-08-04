//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Real-Postgres suite for the #2989 (ADR-060 Phase 2) segment resolution:
// Resolve's Segments field, sourced from scim_users -> scim_group_members ->
// scim_groups (mig 117), org-scoped, cached per (org, email). Covers the
// DoD's required cases: a multi-segment applicable set, zero-group
// empty-success, a forced query error failing Resolve closed (never masked
// into a role-only success), cache hit/miss + local invalidation, and
// cross-org isolation.
package identity

import (
	"context"
	"database/sql"
	"testing"

	"axonflow/platform/testutil"
)

// seedSegmentSchema creates the minimal role_assignments/custom_roles mirror
// (so Resolve's role leg has something — possibly empty — to query) plus a
// mirror of the SCIM group tables (mig 117: VARCHAR(255) text-uuid PKs,
// tenant_id-keyed) the segment query joins.
func seedSegmentSchema(t *testing.T, pc *testutil.PostgresContainer) {
	t.Helper()
	pc.RunMigration(t, `
		CREATE TABLE custom_roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id VARCHAR(255) NOT NULL,
			name VARCHAR(100) NOT NULL,
			permissions JSONB NOT NULL DEFAULT '[]'::jsonb
		);
		CREATE TABLE role_assignments (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id VARCHAR(255) NOT NULL,
			user_email VARCHAR(255) NOT NULL,
			role_id UUID NOT NULL REFERENCES custom_roles(id),
			source VARCHAR(20) DEFAULT 'scim',
			expires_at TIMESTAMPTZ,
			assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE scim_users (
			id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
			tenant_id VARCHAR(255) NOT NULL,
			email VARCHAR(255) NOT NULL,
			active BOOLEAN DEFAULT true
		);
		CREATE TABLE scim_groups (
			id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
			tenant_id VARCHAR(255) NOT NULL,
			display_name VARCHAR(255) NOT NULL
		);
		CREATE TABLE scim_group_members (
			id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
			group_id VARCHAR(255) NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
			user_id VARCHAR(255) NOT NULL REFERENCES scim_users(id) ON DELETE CASCADE
		);
	`)
}

// segmentTestFixture bundles the seeded ids a test needs to insert/remove
// group memberships directly.
type segmentTestFixture struct {
	db *testutil.PostgresContainer
}

func setupSegmentFixture(t *testing.T) *segmentTestFixture {
	t.Helper()
	testutil.SkipIfNoDocker(t)
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	seedSegmentSchema(t, pc)
	return &segmentTestFixture{db: pc}
}

func (f *segmentTestFixture) mustExec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.db.DB.Exec(q, args...); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// seedUser inserts a scim_users row and returns its id.
func (f *segmentTestFixture) seedUser(t *testing.T, orgID, email string) string {
	t.Helper()
	var id string
	if err := f.db.DB.QueryRow(
		`INSERT INTO scim_users (tenant_id, email) VALUES ($1, $2) RETURNING id`, orgID, email,
	).Scan(&id); err != nil {
		t.Fatalf("seed scim_users: %v", err)
	}
	return id
}

// seedGroup inserts a scim_groups row and returns its id.
func (f *segmentTestFixture) seedGroup(t *testing.T, orgID, displayName string) string {
	t.Helper()
	var id string
	if err := f.db.DB.QueryRow(
		`INSERT INTO scim_groups (tenant_id, display_name) VALUES ($1, $2) RETURNING id`, orgID, displayName,
	).Scan(&id); err != nil {
		t.Fatalf("seed scim_groups: %v", err)
	}
	return id
}

func (f *segmentTestFixture) addMember(t *testing.T, groupID, userID string) {
	t.Helper()
	f.mustExec(t, `INSERT INTO scim_group_members (group_id, user_id) VALUES ($1, $2)`, groupID, userID)
}

// segmentIDs extracts the sorted-by-display-name IDs for assertion (Resolve
// already ORDER BYs display_name, so this just projects).
func segmentIDs(segs []Segment) []SegmentID {
	out := make([]SegmentID, len(segs))
	for i, s := range segs {
		out[i] = s.ID
	}
	return out
}

// --- multi-segment applicable set ---

func TestIdentityAttributeResolver_Resolve_MultiSegmentSet(t *testing.T) {
	f := setupSegmentFixture(t)
	ctx := context.Background()

	userID := f.seedUser(t, "org-a", "alice@example.com")
	financeID := f.seedGroup(t, "org-a", "finance")
	mlPlatformID := f.seedGroup(t, "org-a", "ml-platform")
	f.addMember(t, financeID, userID)
	f.addMember(t, mlPlatformID, userID)
	// A group alice is NOT a member of must not appear.
	f.seedGroup(t, "org-a", "support")

	resolver, err := NewIdentityAttributeResolver(f.db.DB)
	if err != nil {
		t.Fatalf("NewIdentityAttributeResolver: %v", err)
	}
	resolved, err := resolver.Resolve(ctx, "org-a", "alice@example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resolved.Segments) != 2 {
		t.Fatalf("want 2 segments (applicable SET, never collapsed), got %d: %+v", len(resolved.Segments), resolved.Segments)
	}
	ids := segmentIDs(resolved.Segments)
	if !(ids[0] == SegmentID(financeID) && ids[1] == SegmentID(mlPlatformID)) &&
		!(ids[0] == SegmentID(mlPlatformID) && ids[1] == SegmentID(financeID)) {
		t.Fatalf("segment IDs = %v, want {%s, %s}", ids, financeID, mlPlatformID)
	}
	// DisplayName carried alongside the stable ID, per the master decision.
	names := map[SegmentID]string{}
	for _, s := range resolved.Segments {
		names[s.ID] = s.DisplayName
	}
	if names[SegmentID(financeID)] != "finance" || names[SegmentID(mlPlatformID)] != "ml-platform" {
		t.Fatalf("display names not carried through: %+v", names)
	}

	// Case-insensitive email lookup, matching CanonicalEmail elsewhere.
	resolved2, err := resolver.Resolve(ctx, "org-a", "  Alice@EXAMPLE.com ")
	if err != nil {
		t.Fatalf("Resolve (mixed case): %v", err)
	}
	if len(resolved2.Segments) != 2 {
		t.Fatalf("canonical-email lookup must find the same 2 segments, got %d", len(resolved2.Segments))
	}
}

// --- zero-group empty-success ---

func TestIdentityAttributeResolver_Resolve_ZeroGroupsIsEmptySuccess(t *testing.T) {
	f := setupSegmentFixture(t)
	ctx := context.Background()

	resolver, err := NewIdentityAttributeResolver(f.db.DB)
	if err != nil {
		t.Fatalf("NewIdentityAttributeResolver: %v", err)
	}

	t.Run("user provisioned but in no groups", func(t *testing.T) {
		f.seedUser(t, "org-a", "loner@example.com")
		resolved, err := resolver.Resolve(ctx, "org-a", "loner@example.com")
		if err != nil {
			t.Fatalf("Resolve must succeed with zero groups, got error: %v", err)
		}
		if resolved.Segments == nil {
			t.Fatal("Segments must be a non-nil empty slice, not nil, on success")
		}
		if len(resolved.Segments) != 0 {
			t.Fatalf("want 0 segments, got %d", len(resolved.Segments))
		}
	})

	t.Run("no scim_users row at all", func(t *testing.T) {
		resolved, err := resolver.Resolve(ctx, "org-a", "never-provisioned@example.com")
		if err != nil {
			t.Fatalf("Resolve must succeed for an unprovisioned identity, got error: %v", err)
		}
		if resolved.Segments == nil || len(resolved.Segments) != 0 {
			t.Fatalf("want non-nil empty Segments, got %v", resolved.Segments)
		}
	})
}

// --- forced query error fails closed, never masked into role-only success ---

func TestIdentityAttributeResolver_Resolve_SegmentQueryErrorFailsClosed(t *testing.T) {
	f := setupSegmentFixture(t)
	ctx := context.Background()

	// A role assignment exists for this user, so if the segment error were
	// (incorrectly) masked, Resolve could still return a "successful"
	// role-only ResolvedIdentity. It must not.
	var roleID string
	if err := f.db.DB.QueryRow(
		`INSERT INTO custom_roles (org_id, name, permissions) VALUES ('org-a', 'developer', '["query"]'::jsonb) RETURNING id`,
	).Scan(&roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	f.mustExec(t, `INSERT INTO role_assignments (org_id, user_email, role_id) VALUES ('org-a', 'bob@example.com', $1)`, roleID)

	resolver, err := NewIdentityAttributeResolver(f.db.DB)
	if err != nil {
		t.Fatalf("NewIdentityAttributeResolver: %v", err)
	}

	// Prove role resolution alone works first (connection is live). Uses
	// ResolveRole directly (NOT Resolve) so it does not populate the segment
	// cache for bob — the segment query below must be a genuine cache MISS
	// hitting the (about to be) broken table, not a cache hit masking it.
	if role, err := resolver.ResolveRole(ctx, "org-a", "bob@example.com"); err != nil || role != "developer" {
		t.Fatalf("precondition: ResolveRole(bob) = %q, err=%v; want role=developer, no error", role, err)
	}

	// Corrupt the segment query's dependency: drop the joined table out from
	// under a LIVE connection (connection stays up; the query itself now
	// fails — precisely the "connection is up and the query fails" shape the
	// brief calls out as a bug/corruption that MUST surface).
	f.mustExec(t, `DROP TABLE scim_group_members`)

	resolved, err := resolver.Resolve(ctx, "org-a", "bob@example.com")
	if err == nil {
		t.Fatalf("Resolve must fail closed when the segment query errors, got success: %+v", resolved)
	}
	if resolved.Role != "" || resolved.Segments != nil {
		t.Fatalf("a failed Resolve must return the ZERO ResolvedIdentity, not a partially-populated one (role-only masking an error): %+v", resolved)
	}
}

// --- cache hit/miss + local invalidation ---

func TestIdentityAttributeResolver_SegmentCache_HitMissInvalidate(t *testing.T) {
	f := setupSegmentFixture(t)
	ctx := context.Background()

	userID := f.seedUser(t, "org-a", "carol@example.com")
	groupID := f.seedGroup(t, "org-a", "finance")
	f.addMember(t, groupID, userID)

	resolver, err := NewIdentityAttributeResolver(f.db.DB)
	if err != nil {
		t.Fatalf("NewIdentityAttributeResolver: %v", err)
	}

	resolved, err := resolver.Resolve(ctx, "org-a", "carol@example.com")
	if err != nil || len(resolved.Segments) != 1 {
		t.Fatalf("precondition: Resolve(carol) = %+v, err=%v; want 1 segment", resolved, err)
	}

	// Mutate storage directly (bypassing the cache) — a cache HIT must still
	// serve the stale (pre-mutation) result within the TTL window.
	f.mustExec(t, `DELETE FROM scim_group_members WHERE user_id = $1`, userID)
	resolvedAgain, err := resolver.Resolve(ctx, "org-a", "carol@example.com")
	if err != nil {
		t.Fatalf("Resolve (cache hit): %v", err)
	}
	if len(resolvedAgain.Segments) != 1 {
		t.Fatalf("expected a CACHE HIT still serving the pre-deletion segment set, got %d segments", len(resolvedAgain.Segments))
	}

	// Local invalidation forces a re-read, which now observes the deletion.
	resolver.InvalidateUserSegments("org-a", "carol@example.com")
	resolvedAfterInvalidate, err := resolver.Resolve(ctx, "org-a", "carol@example.com")
	if err != nil {
		t.Fatalf("Resolve (post-invalidate): %v", err)
	}
	if len(resolvedAfterInvalidate.Segments) != 0 {
		t.Fatalf("InvalidateUserSegments must force a re-read reflecting the deletion, got %d segments", len(resolvedAfterInvalidate.Segments))
	}

	// Invalidation is case/whitespace-insensitive, matching CanonicalEmail —
	// re-seed a membership and invalidate via a differently-cased email.
	f.addMember(t, groupID, userID)
	resolver.InvalidateUserSegments("org-a", "  CAROL@Example.com ")
	resolvedAfterReseed, err := resolver.Resolve(ctx, "org-a", "carol@example.com")
	if err != nil {
		t.Fatalf("Resolve (post-reseed): %v", err)
	}
	if len(resolvedAfterReseed.Segments) != 1 {
		t.Fatalf("canonical-email invalidation must have forced a re-read observing the re-seeded membership, got %d segments", len(resolvedAfterReseed.Segments))
	}
}

// TestSegmentCache_ErrorIsNeverCached proves the divergence from
// detection_override.go's fail-open cache documented in segment_cache.go: an
// error result must not be cached, so the immediately-following call retries
// storage rather than replaying a masked failure.
func TestSegmentCache_ErrorIsNeverCached(t *testing.T) {
	reader := &countingFailingSegmentReader{failUntilCall: 2}
	cache := newSegmentCache(reader, defaultSegmentCacheTTL)
	ctx := context.Background()

	if _, err := cache.get(ctx, "org-a", "x@example.com"); err == nil {
		t.Fatal("first call must fail (reader configured to fail)")
	}
	if reader.calls != 1 {
		t.Fatalf("calls = %d, want 1", reader.calls)
	}
	// Second call must hit the reader AGAIN (the error was not cached) and
	// this time succeed (failUntilCall=2 means call 2 succeeds).
	segs, err := cache.get(ctx, "org-a", "x@example.com")
	if err != nil {
		t.Fatalf("second call must succeed (not still serving a cached error): %v", err)
	}
	if reader.calls != 2 {
		t.Fatalf("calls = %d, want 2 (error must not have been cached)", reader.calls)
	}
	if len(segs) != 1 {
		t.Fatalf("got %d segments, want 1", len(segs))
	}
	// Third call within TTL must now be a genuine cache HIT (no third reader call).
	if _, err := cache.get(ctx, "org-a", "x@example.com"); err != nil {
		t.Fatalf("third call: %v", err)
	}
	if reader.calls != 2 {
		t.Fatalf("calls = %d, want still 2 (successful result must be cached)", reader.calls)
	}
}

type countingFailingSegmentReader struct {
	calls         int
	failUntilCall int // calls strictly before this number fail
}

func (r *countingFailingSegmentReader) ReadUserSegments(_ context.Context, _, _ string) ([]Segment, error) {
	r.calls++
	if r.calls < r.failUntilCall {
		return nil, sql.ErrConnDone
	}
	return []Segment{{ID: "seg-1", DisplayName: "seg-one"}}, nil
}

// --- cross-org isolation ---

func TestIdentityAttributeResolver_Resolve_CrossOrgIsolation(t *testing.T) {
	f := setupSegmentFixture(t)
	ctx := context.Background()

	// Same email, provisioned identically in TWO different orgs, each with
	// its own group of the same display name — the ids are necessarily
	// different rows, so a leak is detectable even though the names match.
	userA := f.seedUser(t, "org-a", "shared@example.com")
	userB := f.seedUser(t, "org-b", "shared@example.com")
	groupA := f.seedGroup(t, "org-a", "finance")
	groupB := f.seedGroup(t, "org-b", "finance")
	f.addMember(t, groupA, userA)
	f.addMember(t, groupB, userB)

	resolver, err := NewIdentityAttributeResolver(f.db.DB)
	if err != nil {
		t.Fatalf("NewIdentityAttributeResolver: %v", err)
	}

	resolvedA, err := resolver.Resolve(ctx, "org-a", "shared@example.com")
	if err != nil {
		t.Fatalf("Resolve org-a: %v", err)
	}
	if len(resolvedA.Segments) != 1 || resolvedA.Segments[0].ID != SegmentID(groupA) {
		t.Fatalf("org-a resolved %+v, want exactly org-a's group %s", resolvedA.Segments, groupA)
	}

	resolvedB, err := resolver.Resolve(ctx, "org-b", "shared@example.com")
	if err != nil {
		t.Fatalf("Resolve org-b: %v", err)
	}
	if len(resolvedB.Segments) != 1 || resolvedB.Segments[0].ID != SegmentID(groupB) {
		t.Fatalf("org-b resolved %+v, want exactly org-b's group %s", resolvedB.Segments, groupB)
	}

	// An org with NO scim_users row for this email sees nothing.
	resolvedC, err := resolver.Resolve(ctx, "org-c", "shared@example.com")
	if err != nil {
		t.Fatalf("Resolve org-c: %v", err)
	}
	if len(resolvedC.Segments) != 0 {
		t.Fatalf("org-c (no directory row) must see zero segments, got %+v", resolvedC.Segments)
	}

	t.Run("RLS isolates orgs for a plain (non-superuser) role", func(t *testing.T) {
		if _, err := f.db.DB.Exec(`CREATE ROLE seg_rls_probe LOGIN PASSWORD 'probe'`); err != nil {
			t.Fatalf("create probe role: %v", err)
		}
		if _, err := f.db.DB.Exec(`
			ALTER TABLE scim_users ENABLE ROW LEVEL SECURITY;
			ALTER TABLE scim_users FORCE ROW LEVEL SECURITY;
			CREATE POLICY seg_probe_users_isolation ON scim_users
				USING (tenant_id = current_setting('app.current_org_id', true))
				WITH CHECK (tenant_id = current_setting('app.current_org_id', true));
			ALTER TABLE scim_groups ENABLE ROW LEVEL SECURITY;
			ALTER TABLE scim_groups FORCE ROW LEVEL SECURITY;
			CREATE POLICY seg_probe_groups_isolation ON scim_groups
				USING (tenant_id = current_setting('app.current_org_id', true))
				WITH CHECK (tenant_id = current_setting('app.current_org_id', true));
			GRANT SELECT ON scim_users, scim_groups, scim_group_members, role_assignments, custom_roles TO seg_rls_probe;
		`); err != nil {
			t.Fatalf("enable RLS + grant: %v", err)
		}
		probeDB, err := sql.Open("postgres", replaceCreds(t, f.db.URL, "seg_rls_probe", "probe"))
		if err != nil {
			t.Fatalf("open probe conn: %v", err)
		}
		defer func() { _ = probeDB.Close() }()

		probeResolver, err := NewIdentityAttributeResolver(probeDB)
		if err != nil {
			t.Fatalf("probe resolver: %v", err)
		}
		probeResolvedA, err := probeResolver.Resolve(ctx, "org-a", "shared@example.com")
		if err != nil {
			t.Fatalf("probe Resolve org-a: %v", err)
		}
		if len(probeResolvedA.Segments) != 1 || probeResolvedA.Segments[0].ID != SegmentID(groupA) {
			t.Fatalf("RLS-scoped probe org-a resolved %+v, want exactly org-a's group", probeResolvedA.Segments)
		}
		// A bare connection (no org GUC set) must see nothing via RLS — this
		// exercises withOrgScope's set_config, not the WHERE clause.
		var bare int
		if err := probeDB.QueryRow(`SELECT COUNT(*) FROM scim_groups`).Scan(&bare); err != nil {
			t.Fatalf("bare probe count: %v", err)
		}
		if bare != 0 {
			t.Fatalf("RLS breach: unscoped connection sees %d scim_groups rows", bare)
		}
	})
}

// TestIdentityAttributeResolver_Resolve_CorruptCrossTenantMembershipRow is
// the defense-in-depth case for a scim_group_members row that (through a
// provisioning bug, never through this codebase's own write paths — there
// are none in this repo) links a user in one org to a GROUP belonging to a
// DIFFERENT org. scim_group_members has FKs on group_id/user_id
// individually but no constraint tying them to the same tenant, so this
// shape is representable in storage even though nothing here writes it.
// The query must scope g.tenant_id independently of u.tenant_id (not rely
// on inferring it through the join) so a corrupt row like this cannot leak
// another org's group id/display_name.
func TestIdentityAttributeResolver_Resolve_CorruptCrossTenantMembershipRow(t *testing.T) {
	f := setupSegmentFixture(t)
	ctx := context.Background()

	userA := f.seedUser(t, "org-a", "victim@example.com")
	groupB := f.seedGroup(t, "org-b", "org-b-only-group")
	// Directly wire org-a's user to org-b's group — a corrupt row no
	// production write path in this repo produces, but one the schema does
	// not forbid.
	f.addMember(t, groupB, userA)

	resolver, err := NewIdentityAttributeResolver(f.db.DB)
	if err != nil {
		t.Fatalf("NewIdentityAttributeResolver: %v", err)
	}
	resolved, err := resolver.Resolve(ctx, "org-a", "victim@example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resolved.Segments) != 0 {
		t.Fatalf("a corrupt cross-tenant scim_group_members row must NOT leak org-b's group into org-a's resolution, got %+v", resolved.Segments)
	}
}
