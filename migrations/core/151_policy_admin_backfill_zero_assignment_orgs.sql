-- Migration 151: restore policy editing for orgs with ZERO role assignments (#3004)
-- Date: 2026-07-22
--
-- ============================================================================
-- Why
-- ============================================================================
-- #2996 made policy CRUD RBAC-gated: POST/PUT /api/v1/policies and
-- /policies/import now require `policy:write`, DELETE requires `policy:delete`.
-- Before that they were session-auth-only, so an org's password-login identity
-- (org_id + password) could edit policies while carrying NO role assignment.
--
-- Migration 149 closed the OWNER lockout, but only for principals who already
-- held sso:configure, and its bootstrap covers new orgs plus — via
-- ensureDeploymentOrgOwner — the single bundled deployment org. An org that
-- has ZERO role assignments is deliberately granted nothing by 149 (pinned by
-- its `zeroassign` test case), and the creation trigger fires on INSERT only.
--
-- Net, on upgrade: every pre-existing org with no assignments (every SaaS
-- customer org, every non-deployment in-vpc org) loses policy editing with no
-- in-product recovery — `sessionPermGate` denies the write, and
-- `rolesManagementGate` (roles:write) denies that same session from granting
-- itself a role. Only an out-of-band break-glass call per org could fix it.
--
-- ============================================================================
-- What this grants, and why policy_admin and NOT owner
-- ============================================================================
-- The identity is axonflow_org_login_identity(contact_email) — the SQL half of
-- Go ResolveOrgBootstrapIdentity (bootstrap_identity.go), defined by migration
-- 150. It is the ONE expression every path uses; open-coding a COALESCE here is
-- what created the #3000/#3004 conflict this migration was rewritten to resolve.
--
-- It returns the CANONICAL (trim + lowercase) contact_email, or NULL when the
-- org has none. NULL is load-bearing: for such an org the Go resolver falls back
-- to AXONFLOW_PORTAL_ADMIN_EMAIL, which is PROCESS configuration SQL cannot
-- read, so this migration CANNOT compute the identity and must not guess.
-- Keying on '' — as the first draft of this migration did — would grant
-- policy_admin to a key no session presents any more (migration 150 makes the
-- login present the resolved address), silently re-opening the very lockout
-- #3004 exists to close, AND would make the verification below pass vacuously.
-- Those orgs are therefore SKIPPED, named in a WARNING, and left to the two
-- paths that DO know the resolved value: the portal boot grant
-- (EnsureDeploymentOrgOwner) and the ADMIN_API_KEY break-glass endpoint.
--
-- The role is `policy_admin`
-- (["policy:write","policy:delete","audit:read","token:rotate:self"]) — NOT
-- `owner`. Granting owner would be a WIDENING: this identity never held
-- `sso:configure` pre-upgrade, and owner carries it. Walking policy_admin's
-- bundle against what the identity could do BEFORE #2996:
--
--   policy:write / policy:delete -> RESTORES exactly what it lost (policy CRUD
--                                   was session-auth-only, so it could do this).
--   audit:read                   -> PRESERVES tenant-wide audit reads. Load
--                                   bearing: orchestrator_proxy's
--                                   sessionHasTenantReadScope returns
--                                   tenant-wide for a session with ZERO role
--                                   assignments. Once this migration gives the
--                                   session a role that carve-out no longer
--                                   applies, so the role must itself carry
--                                   audit:read or this backfill would REMOVE
--                                   the tenant-wide reads it already had.
--   token:rotate:self            -> the one addition. It is a self-scoped,
--                                   developer-scoped token rotation that did
--                                   not exist pre-#2995 at all, and cannot
--                                   confer anything owner-reserved (the
--                                   anti-escalation gate is unaffected).
--
-- So on the PORTAL plane: capability-preserving on every axis that existed
-- before, plus one self-scoped affordance. Critically it does NOT confer
-- sso:configure, so the #2993 owner≠admin boundary is untouched.
--
-- FLEET-PLANE CONSEQUENCE (stated, not hidden). role_assignments is also read by
-- the Path-B fleet resolver (platform/shared/identity/scim_role_resolver.go),
-- and RoleCanReadTenant returns TRUE for policy_admin. So if an org runs Path B
-- (IdP/OIDC) AND an IdP identity's email equals this org's contact_email, that
-- identity now resolves to fleet role `policy_admin` and gains TENANT-WIDE
-- audit/decision REST reads on the fleet plane, where it previously resolved to
-- "" (least-privilege). That is a genuine widening on that plane, accepted
-- deliberately: the address is the org's own root credential holder, the row is
-- source='system' (so a SCIM re-sync will not strip it), and the alternative —
-- leaving the org unable to edit its own policies — is worse. Orgs that do not
-- run Path B, or whose IdP identities differ from contact_email, are unaffected.
--
-- ============================================================================
-- Scope: orgs whose LOGIN IDENTITY holds no assignment
-- ============================================================================
-- The lockout is IDENTITY-scoped, not org-scoped, so the predicate must be too:
--   NOT EXISTS (assignment for org_id AND user_email = <login identity>)
--
-- An org-scoped "has no assignments at all" test under-covers badly. An org
-- whose only assignment is, say, a SCIM-provisioned `viewer` for some employee
-- still leaves its contact_email password login with no policy:write and no
-- roles:write — exactly the permanent, no-in-product-recovery lockout this
-- migration exists to close — while an org-scoped predicate skips it. Likewise
-- after mig 149, any org that had an admin now has >=1 assignment (the owner
-- grant), which would mask every such org.
--
-- Identity-scoped is strictly SAFER, not looser: {org has zero assignments} is a
-- subset of {this identity has zero assignments}, so the change only ever adds
-- orgs that are genuinely locked out. It still never touches an identity that
-- already holds anything.
--
-- ============================================================================
-- Idempotency + reversibility
-- ============================================================================
-- The INSERT is ON CONFLICT (org_id, user_email, role_id) DO UPDATE, reviving
-- only an ALREADY-EXPIRED row (see the clause itself), and the
-- zero-assignment predicate stops matching as soon as the first row lands — so
-- a re-run inserts nothing. Rows are stamped
-- assigned_by = 'migration:151_policy_admin_backfill'; the DOWN deletes exactly
-- those and nothing else, so manual/SCIM assignments are never touched.
-- source='system' so SCIM re-sync cannot strip them (scim/service.go only
-- removes source='scim').

BEGIN;

DO $$
DECLARE
    v_granted INTEGER := 0;
    v_skipped RECORD;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'role_assignments'
    ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'organizations'
    ) THEN
        RAISE NOTICE 'Migration 151: role_assignments/organizations absent - skipping';
        RETURN;
    END IF;

    -- Hard dependency on migration 150, which defines the ONE org-login
    -- identity expression. 150 sorts before 151 so the runner always applies it
    -- first; fail loudly rather than silently open-code a divergent COALESCE if
    -- that ever stops being true.
    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'axonflow_org_login_identity') THEN
        RAISE EXCEPTION 'Migration 151 requires axonflow_org_login_identity from migration 150; apply 150 first';
    END IF;

    -- One statement: every org whose LOGIN IDENTITY holds no live policy
    -- authority gets its login
    -- identity bound to that org's SYSTEM policy_admin role. The JOIN on
    -- is_system means an org whose canonical name is occupied by a CUSTOM
    -- policy_admin role is skipped rather than bound to a role whose
    -- permissions the platform does not define (same posture as 149's
    -- no_system_owner_role outcome).
    INSERT INTO role_assignments (org_id, user_email, role_id, assigned_by, assigned_at, source)
    SELECT o.org_id,
           axonflow_org_login_identity(o.contact_email),
           cr.id,
           'migration:151_policy_admin_backfill',
           NOW(),
           'system'
      FROM organizations o
      JOIN custom_roles cr
        ON cr.org_id = o.org_id
       AND cr.name = 'policy_admin'
       AND cr.is_system
     -- Only orgs whose login identity is COMPUTABLE IN SQL. A NULL means the
     -- org has no contact_email, so the presented identity comes from
     -- AXONFLOW_PORTAL_ADMIN_EMAIL, which this migration cannot read; those are
     -- named in the WARNING loop below and left to the portal/break-glass.
     -- Without this guard the NOT EXISTS below can never match (every
     -- comparison to NULL is NULL), so the org would look uncovered forever and
     -- the INSERT would attempt a NULL user_email against a NOT NULL column.
     WHERE axonflow_org_login_identity(o.contact_email) IS NOT NULL
       AND NOT EXISTS (
               SELECT 1
                 FROM role_assignments ra
                 JOIN custom_roles rc
                   ON rc.id = ra.role_id AND rc.org_id = ra.org_id
                WHERE ra.org_id = o.org_id
                  AND axonflow_canonical_email(ra.user_email) = axonflow_org_login_identity(o.contact_email)
                  -- LIVE only (R3 H2). Every consumer filters on expiry
                  -- (roles/repository.go, scim_role_resolver.go), so an identity
                  -- whose only grant has lapsed resolves to ZERO permissions;
                  -- treating it as "already holds something" left it locked out.
                  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
                  -- POLICY AUTHORITY, not mere existence (R3 H1). viewer is
                  -- ["audit:read"], developer is ["token:rotate:self"]; neither
                  -- carries policy:write NOR roles:write, so a login identity
                  -- holding one is in exactly the permanent, no-in-product-recovery
                  -- state this migration exists to close. "*" qualifies: only
                  -- sso:configure is owner-reserved, so admin/owner do grant
                  -- policy:write.
                  AND (rc.permissions @> '["policy:write"]'::jsonb
                       OR rc.permissions @> '["*"]'::jsonb)
           )
    -- REVIVE an expired row rather than DO NOTHING (#3015 R3-combined, BLOCKER).
    --
    -- The conflict target (org_id, user_email, role_id) carries NO expiry term,
    -- so an EXPIRED policy_admin row for this identity matches it. With
    -- DO NOTHING the INSERT silently did nothing, while the verification below
    -- — which filters expires_at > NOW() — still saw the org as locked out and
    -- raised. run.go log.Fatalf's on a failed migration, so that is a permanent
    -- agent boot loop that a re-run cannot clear: repair-set was a strict
    -- SUBSET of verify-set.
    --
    -- Reachable through ordinary use: the portal RBAC API accepts expires_at on
    -- a role assignment, so "operator time-boxes policy_admin for the org's own
    -- contact address, it lapses, then they upgrade" is a supported sequence.
    --
    -- Scoped to rows that are ACTUALLY EXPIRED, so it can never extend an
    -- operator's live time-box. assigned_by is deliberately NOT rewritten
    -- (mirroring 149's revive) so the DOWN cannot mistake a human-created row
    -- for one of its own.
    ON CONFLICT (org_id, user_email, role_id) DO UPDATE
       SET expires_at = NULL,
           assigned_at = NOW(),
           source = 'system'
     WHERE role_assignments.expires_at IS NOT NULL
       AND role_assignments.expires_at <= NOW();

    GET DIAGNOSTICS v_granted = ROW_COUNT;
    RAISE NOTICE 'Migration 151: granted policy_admin to % locked-out org login identit(ies)', v_granted;

    -- Detectable, not silent (mirrors 149's no_system_owner_role posture): an org
    -- whose canonical 'policy_admin' name is occupied by a CUSTOM role gets
    -- nothing from the JOIN above, and the verification below deliberately
    -- excludes it — so without this it would be a SILENTLY permanently
    -- locked-out org. Name them.
    FOR v_skipped IN
        SELECT o.org_id
          FROM organizations o
         WHERE axonflow_org_login_identity(o.contact_email) IS NOT NULL
           AND NOT EXISTS (
                   SELECT 1
                     FROM role_assignments ra
                     JOIN custom_roles rc
                       ON rc.id = ra.role_id AND rc.org_id = ra.org_id
                    WHERE ra.org_id = o.org_id
                      AND axonflow_canonical_email(ra.user_email) = axonflow_org_login_identity(o.contact_email)
                      -- LIVE only (R3 H2). Every consumer filters on expiry
                      -- (roles/repository.go, scim_role_resolver.go), so an identity
                      -- whose only grant has lapsed resolves to ZERO permissions;
                      -- treating it as "already holds something" left it locked out.
                      AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
                      -- POLICY AUTHORITY, not mere existence (R3 H1). viewer is
                      -- ["audit:read"], developer is ["token:rotate:self"]; neither
                      -- carries policy:write NOR roles:write, so a login identity
                      -- holding one is in exactly the permanent, no-in-product-recovery
                      -- state this migration exists to close. "*" qualifies: only
                      -- sso:configure is owner-reserved, so admin/owner do grant
                      -- policy:write.
                      AND (rc.permissions @> '["policy:write"]'::jsonb
                           OR rc.permissions @> '["*"]'::jsonb)
               )
           AND NOT EXISTS (
                   SELECT 1 FROM custom_roles cr
                    WHERE cr.org_id = o.org_id AND cr.name = 'policy_admin' AND cr.is_system
               )
    LOOP
        RAISE WARNING 'Migration 151: org % has no SYSTEM policy_admin role (a custom role may occupy the name); its login identity remains without policy authority — rename that role then run: SELECT ensure_org_system_roles(%);',
            v_skipped.org_id, quote_literal(v_skipped.org_id);
    END LOOP;

    -- The OTHER skip reason, and the one the #3000/#3004 conflict turns on: the
    -- org has no contact_email, so its presented identity is
    -- AXONFLOW_PORTAL_ADMIN_EMAIL — process configuration this migration cannot
    -- read. Naming them is the whole mitigation: silently skipping is how an org
    -- stays locked out with nobody the wiser.
    FOR v_skipped IN
        SELECT o.org_id
          FROM organizations o
         WHERE axonflow_org_login_identity(o.contact_email) IS NULL
    LOOP
        RAISE WARNING 'Migration 151: org % has no contact_email, so its portal login identity is resolved at runtime from AXONFLOW_PORTAL_ADMIN_EMAIL and cannot be computed here; it was SKIPPED. The portal grants it owner on its next boot in enterprise / in-vpc modes; otherwise use POST /api/v1/admin/organizations/%/owner (ADMIN_API_KEY) — see UPGRADING.md (#3000/#3004).',
            v_skipped.org_id, v_skipped.org_id;
    END LOOP;

    -- RLS canary. Migrations run on the raw DATABASE_URL and never set
    -- app.current_org_id; organizations is FORCE RLS (mig 103). If that role is
    -- neither superuser nor BYPASSRLS this SELECT returns zero rows, the
    -- backfill silently does nothing AND the verification below passes
    -- vacuously — a silent no-op upgrade. Say so loudly rather than claim
    -- success.
    --
    -- 149's backfill loop has the same shape. That cross-reference used to say
    -- it was "noted there too" and it was not; 149 now carries the canary, and
    -- uses a ROLE/CATALOG predicate rather than COUNT(*) = 0 — a fresh install
    -- legitimately has zero orgs, so the count test below is ambiguous exactly
    -- when it fires. Worth copying here on the next touch of this file.
    IF (SELECT COUNT(*) FROM organizations) = 0 THEN
        RAISE WARNING 'Migration 151: organizations is EMPTY or invisible to the migration role (FORCE RLS + no BYPASSRLS?) — no backfill was performed; verify with a BYPASSRLS role before declaring the upgrade clean';
    END IF;
END $$;

-- Verification — no org may be left in the lockout this migration exists to
-- close: an org that still has zero assignments AND has a system policy_admin
-- role available means the backfill did not do its job (Principle 3).
DO $$
DECLARE
    v_bad INTEGER;
BEGIN
    -- Guard BOTH tables this block reads (the UP block already did): a DB with
    -- role_assignments but no organizations must skip, not abort.
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'role_assignments'
    ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'organizations'
    ) THEN
        RETURN;
    END IF;

    -- Same IDENTITY-scoped predicate as the INSERT, so verify-scope == fix-scope.
    -- The IS NOT NULL clause mirrors the INSERT's: an org whose identity is only
    -- resolvable at runtime is out of this migration's reach by construction, so
    -- failing on it would abort every upgrade that has one. It is reported as a
    -- WARNING above instead — deliberately loud, never silent.
    SELECT COUNT(*) INTO v_bad
      FROM organizations o
     WHERE axonflow_org_login_identity(o.contact_email) IS NOT NULL
       AND NOT EXISTS (
               SELECT 1
                 FROM role_assignments ra
                 JOIN custom_roles rc
                   ON rc.id = ra.role_id AND rc.org_id = ra.org_id
                WHERE ra.org_id = o.org_id
                  AND axonflow_canonical_email(ra.user_email) = axonflow_org_login_identity(o.contact_email)
                  -- LIVE only (R3 H2). Every consumer filters on expiry
                  -- (roles/repository.go, scim_role_resolver.go), so an identity
                  -- whose only grant has lapsed resolves to ZERO permissions;
                  -- treating it as "already holds something" left it locked out.
                  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
                  -- POLICY AUTHORITY, not mere existence (R3 H1). viewer is
                  -- ["audit:read"], developer is ["token:rotate:self"]; neither
                  -- carries policy:write NOR roles:write, so a login identity
                  -- holding one is in exactly the permanent, no-in-product-recovery
                  -- state this migration exists to close. "*" qualifies: only
                  -- sso:configure is owner-reserved, so admin/owner do grant
                  -- policy:write.
                  AND (rc.permissions @> '["policy:write"]'::jsonb
                       OR rc.permissions @> '["*"]'::jsonb)
           )
       AND EXISTS (
               SELECT 1 FROM custom_roles cr
                WHERE cr.org_id = o.org_id AND cr.name = 'policy_admin' AND cr.is_system
           );
    IF v_bad > 0 THEN
        RAISE EXCEPTION 'Migration 151 failed: % org(s) with a system policy_admin role still have no assignment for their login identity', v_bad;
    END IF;

    RAISE NOTICE 'Migration 151 verified: no zero-assignment org left without policy authority';
END $$;

COMMIT;
