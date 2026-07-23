-- Migration 149 DOWN: undo the owner backfill + bootstrap (#2997)
-- Date: 2026-07-22
--
-- Removes ONLY what migration 149 created:
--
--   * role_assignments rows carrying assigned_by='migration:149_owner_backfill'
--     AND source='system'. The UP's INSERT is ON CONFLICT DO NOTHING, so a
--     pre-existing owner assignment for the same (org, email, role) kept ITS
--     assigned_by and was never rewritten — only rows a run of 149 actually
--     inserted can carry that marker. Manual (source='manual') and SCIM
--     (source='scim') owner grants, and owner grants that predate 149, are
--     therefore untouched by this DELETE.
--   * the reseed_org_owner_on_contact_change trigger + its function.
--   * the owner-assignment extension to trg_ensure_org_system_roles (restored
--     to the mig 146/148 definition, which seeds role DEFINITIONS only).
--   * ensure_org_owner_backfill.
--
-- DELIBERATELY NOT removed:
--
--   * ensure_org_owner_assignment. It is a callable helper, not state, and the
--     portal bootstrap + admin break-glass API call it by name at runtime.
--     Dropping it on a down-migration would fail those paths on a stack that is
--     still running the new binaries — the opposite of a safe rollback. It is
--     inert if never called.
--   * owner assignments created by the org-creation trigger
--     ('system:org-bootstrap'), the contact-email drift guard
--     ('system:org-contact-change'), the portal bootstrap
--     ('system:portal-bootstrap') or the break-glass API ('break-glass:...').
--     Those are OPERATIONAL grants an org is actively relying on; revoking a
--     live owner from a down-migration would re-create exactly the lockout 149
--     exists to close. Remove them deliberately through the roles API if
--     required. (Same philosophy as mig 148 DOWN, which does not resurrect the
--     data it pruned.)

BEGIN;

DO $$
DECLARE
    v_deleted INTEGER := 0;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'role_assignments'
    ) THEN
        RAISE NOTICE 'Migration 149 down: role_assignments absent - skipping';
        RETURN;
    END IF;

    -- Restore the mig 146/148 trigger function: role DEFINITIONS only.
    EXECUTE $tf$
        CREATE OR REPLACE FUNCTION trg_ensure_org_system_roles()
        RETURNS TRIGGER
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $body$
        BEGIN
            PERFORM ensure_org_system_roles(NEW.org_id);
            RETURN NEW;
        END;
        $body$;
    $tf$;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        EXECUTE 'ALTER FUNCTION trg_ensure_org_system_roles() OWNER TO axonflow_platform_admin';
    END IF;

    DROP TRIGGER IF EXISTS reseed_org_owner_on_contact_change ON organizations;
    DROP FUNCTION IF EXISTS trg_reseed_org_owner_on_contact_change();
    DROP FUNCTION IF EXISTS ensure_org_owner_backfill(VARCHAR);

    -- Remove ONLY the backfilled rows (see the header for why this cannot
    -- match a legitimately pre-existing owner assignment).
    DELETE FROM role_assignments
     WHERE assigned_by = 'migration:149_owner_backfill'
       AND source = 'system';
    GET DIAGNOSTICS v_deleted = ROW_COUNT;

    -- #3000: also remove the BLANK-keyed owner grants a run of 149 could
    -- create through its other paths — the org-creation trigger
    -- ('system:org-bootstrap'), the contact-email drift guard
    -- ('system:org-contact-change') and the portal boot grant
    -- ('system:portal-bootstrap') all passed COALESCE(contact_email, '') and so
    -- wrote user_email = '' for an org with no contact_email.
    --
    -- These are exempt from the "operational grants are preserved" rule in the
    -- header, and deliberately so: an empty user_email is not a principal but a
    -- WILDCARD under UserHasPermission(org_id, user_email, perm) — every
    -- session in the org that resolves to '' matches it. Leaving one behind on
    -- a rollback would strand exactly the privilege hole #3000 closes. Nothing
    -- is stranded by removing them: the portal re-grants owner to the real
    -- bootstrap identity on its next boot, and the ADMIN_API_KEY break-glass
    -- endpoint covers every other shape.
    --
    -- Scoped to source='system' owner assignments so a manual or SCIM grant is
    -- never touched, and expressed without axonflow_is_grantable_identity so
    -- this DOWN still runs on a DB that never applied migration 150.
    DECLARE
        v_blank INTEGER := 0;
    BEGIN
        DELETE FROM role_assignments ra
        USING custom_roles cr
        WHERE cr.id = ra.role_id
          AND cr.org_id = ra.org_id
          AND cr.name = 'owner'
          AND ra.source = 'system'
          AND btrim(COALESCE(ra.user_email, '')) = '';
        GET DIAGNOSTICS v_blank = ROW_COUNT;
        v_deleted := v_deleted + v_blank;
    END;

    RAISE NOTICE 'Migration 149 down: removed % owner assignment(s) (backfilled + blank-keyed); trigger extension reverted', v_deleted;
END $$;

COMMIT;
