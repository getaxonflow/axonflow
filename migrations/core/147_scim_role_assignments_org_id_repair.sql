-- Migration 147: role_assignments.org_id must hold a REAL org, never a SCIM
--                DIRECTORY ADDRESSING tenant id (#2964, epic #2919)
-- Date: 2026-07-17
-- Purpose: The SCIM privilege-grant plane (customer-portal scim.Service) keyed
--          role_assignments.org_id on the portal session's tenant id
--          (withSCIMSessionContext -> session.TenantID) and the SCIM bearer
--          token's tenant id, instead of the REAL org. role_assignments.org_id
--          is the RLS ISOLATION key (mig 111: org_id = current_setting(
--          'app.current_org_id'), USING + WITH CHECK) and is read by the fleet
--          resolver (platform/shared/identity/scim_role_resolver.go) scoped on
--          the LICENSED org. Where tenant_id != org_id (multi-tenant / in-vpc),
--          every SCIM-written assignment landed under the addressing tenant and
--          the resolver — scoped on the real org — found nothing, so every
--          Path B (IdP/OIDC) developer silently resolved to least-privilege.
--          (Latent for single-tenant orgs, where portal_default_tenant_id()
--          resolves tenant_id == org_id and the two keys coincide.)
--
--          The application change (scim.Service.orgScopeFromCtx +
--          middleware.orgForTenant + main.go withSCIMSessionContext) stops
--          writing the tenant into org_id. This migration repairs any rows a
--          divergent deployment already mis-stamped.
--
-- #2960 alignment: same bug class as mig 145 (which decoupled sso_*.org_id from
--   the '__platform__' addressing sentinel). org_id is ALWAYS a real org; a
--   tenant id is ADDRESSING and never belongs in an org_id column.
-- #2969 alignment: custom_roles.org_id is keyed on the REAL org and seeded
--   per-org by mig 146. A repaired role_assignments row must reference a role
--   that exists under the SAME real org, else the resolver's org-scoped JOIN
--   (role_assignments ra INNER JOIN custom_roles cr, both RLS-isolated on the
--   scoped org) still returns nothing — so we only migrate rows whose role
--   target exists under the real org, and leave the rest for an operator
--   re-sync rather than manufacture an unresolvable row.
--
-- The mapping is DATA-DRIVEN, not sentinel-driven: the real org for an
-- addressing tenant is tenants.org_id (core mig 062; per-org default rows +
-- portal_default_tenant_id from enterprise mig 065). No deployment
-- GUC is needed. On a deployment without the tenants table, or with no
-- divergent tenants, there is nothing to repair and this is a guarded no-op —
-- Path B has almost certainly never run in a divergent deployment, so most
-- deployments repair ZERO rows.
--
-- RLS NOTE: role_assignments is ENABLE (not FORCE) ROW LEVEL SECURITY (mig 023
-- + mig 111), so the migration runner — the table owner — already bypasses the
-- policy for the repair DML. We still toggle FORCE off/on defensively IF a
-- future migration makes the table FORCE (mirrors mig 145's posture and does
-- not rely on the runner holding BYPASSRLS). ALTER TABLE takes ACCESS EXCLUSIVE
-- inside this txn, so no concurrent session observes an un-FORCEd window.

BEGIN;

DO $$
DECLARE
    v_force_ra   BOOLEAN := false;
    v_migrated   INTEGER := 0;
    v_deleted    INTEGER := 0;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'role_assignments'
    ) THEN
        RAISE NOTICE 'Migration 147: role_assignments does not exist - skipping';
        RETURN;
    END IF;

    -- No tenants table => single-tenant / community: tenant_id == org_id, so no
    -- org_id column can hold a divergent addressing tenant. Nothing to repair.
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'tenants'
    ) THEN
        RAISE NOTICE 'Migration 147: tenants table absent (single-tenant/community) - nothing to repair';
        RETURN;
    END IF;

    -- Probe: any SCIM-written assignment whose org_id is an addressing tenant
    -- that maps to a DIFFERENT real org. If none, take the early no-op exit so
    -- a healthy deployment does no work and no ALTER TABLE lock is taken.
    IF NOT EXISTS (
        SELECT 1
        FROM role_assignments ra
        JOIN tenants t ON ra.org_id = t.tenant_id AND t.org_id <> t.tenant_id
        WHERE ra.source = 'scim'
    ) THEN
        RAISE NOTICE 'Migration 147: no tenant-keyed SCIM role_assignments rows - nothing to repair';
        RETURN;
    END IF;

    -- FORCE off (only if currently on — see RLS NOTE).
    SELECT relforcerowsecurity INTO v_force_ra
    FROM pg_class
    WHERE relname = 'role_assignments' AND relnamespace = 'public'::regnamespace;
    IF v_force_ra THEN
        ALTER TABLE role_assignments NO FORCE ROW LEVEL SECURITY;
    END IF;

    -- Migrate the RESOLVABLE mis-keyed rows to the real org. INSERT ... ON
    -- CONFLICT DO NOTHING (not UPDATE) so that:
    --   * a pre-existing correctly-keyed row for the same (org_id,user_email,
    --     role_id) is preserved, not violated;
    --   * multiple divergent tenants of one org that each carried the same
    --     (email, role) collapse to a single real-org row instead of colliding.
    -- Guarded on the role target existing under the real org (#2969) so the
    -- resolver's org-scoped JOIN can actually resolve the repaired row; the FK
    -- role_id -> custom_roles(id) is satisfied by the same EXISTS.
    INSERT INTO role_assignments (org_id, user_email, role_id, assigned_by, assigned_at, expires_at, source)
    SELECT DISTINCT t.org_id, ra.user_email, ra.role_id, ra.assigned_by, ra.assigned_at, ra.expires_at, ra.source
    FROM role_assignments ra
    JOIN tenants t ON ra.org_id = t.tenant_id AND t.org_id <> t.tenant_id
    WHERE ra.source = 'scim'
      AND EXISTS (
          SELECT 1 FROM custom_roles cr
          WHERE cr.id = ra.role_id AND cr.org_id = t.org_id
      )
    ON CONFLICT (org_id, user_email, role_id) DO NOTHING;
    GET DIAGNOSTICS v_migrated = ROW_COUNT;

    -- Delete the mis-keyed originals that now have a real-org counterpart
    -- (whether just inserted above or already present). Rows with NO real-org
    -- twin — the role target did not exist under the real org — are left in
    -- place for operator inspection / re-sync rather than silently dropped.
    DELETE FROM role_assignments ra
    USING tenants t
    WHERE ra.org_id = t.tenant_id
      AND t.org_id <> t.tenant_id
      AND ra.source = 'scim'
      AND EXISTS (
          SELECT 1 FROM role_assignments r2
          WHERE r2.org_id = t.org_id
            AND r2.user_email = ra.user_email
            AND r2.role_id = ra.role_id
      );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;

    -- FORCE back on if we turned it off.
    IF v_force_ra THEN
        ALTER TABLE role_assignments FORCE ROW LEVEL SECURITY;
    END IF;

    RAISE NOTICE 'Migration 147: re-keyed % SCIM role_assignments row(s) tenant -> real org, removed % stale tenant-keyed original(s)',
        v_migrated, v_deleted;
END $$;

-- ============================================================================
-- Verification — fail loudly if the repair left the table half-fixed or a
-- security boundary off (Principle 3).
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'role_assignments'
    ) THEN
        RETURN;
    END IF;

    -- No SCIM row may remain keyed on a divergent addressing tenant while a
    -- correctly-keyed real-org twin also exists — that would mean the cleanup
    -- DELETE did not run for a migrated row.
    IF EXISTS (
        SELECT 1
        FROM role_assignments ra
        JOIN tenants t ON ra.org_id = t.tenant_id AND t.org_id <> t.tenant_id
        WHERE ra.source = 'scim'
          AND EXISTS (
              SELECT 1 FROM role_assignments r2
              WHERE r2.org_id = t.org_id
                AND r2.user_email = ra.user_email
                AND r2.role_id = ra.role_id
          )
    ) THEN
        RAISE EXCEPTION 'Migration 147 failed: tenant-keyed SCIM role_assignments rows remain alongside their repaired real-org twin';
    END IF;

    -- RLS itself must still be ENABLED (the repair toggled only FORCE, never
    -- ENABLE, and must not have dropped the isolation policy from mig 111).
    IF NOT EXISTS (
        SELECT 1 FROM pg_class
        WHERE relname = 'role_assignments' AND relnamespace = 'public'::regnamespace
          AND relrowsecurity
    ) THEN
        RAISE EXCEPTION 'Migration 147 failed: role_assignments ROW LEVEL SECURITY is no longer enabled';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'role_assignments' AND policyname = 'role_assignments_org_id_isolation'
    ) THEN
        RAISE EXCEPTION 'Migration 147 failed: role_assignments_org_id_isolation policy missing';
    END IF;

    RAISE NOTICE 'Migration 147 verified: no divergent-tenant SCIM role_assignments rows shadow a repaired real-org row; RLS intact';
END $$;

COMMIT;
