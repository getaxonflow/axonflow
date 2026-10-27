-- Migration 191: keep grants for core-FORCEd Portal tables in the core tree
-- Date: 2026-10-24
--
-- community_saas_registrations is FORCEd by core/105 and role_assignments can
-- be FORCEd by core/147. Their platform-admin grants were added later in
-- community-saas/190, which does not ship in every tree that receives those
-- core migrations. This corrective migration places the grants on the same
-- edition axis as the FORCE statements and reaches deployments that already
-- applied the older migrations.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        RAISE NOTICE 'Migration 191: axonflow_platform_admin is absent; grants are not needed in this deployment';
        RETURN;
    END IF;

    IF to_regclass('public.community_saas_registrations') IS NOT NULL THEN
        BEGIN
            GRANT SELECT ON community_saas_registrations TO axonflow_platform_admin;
        EXCEPTION WHEN insufficient_privilege THEN
            IF NOT has_table_privilege('axonflow_platform_admin', 'public.community_saas_registrations', 'SELECT') THEN
                RAISE;
            END IF;
        END;
    END IF;

    IF to_regclass('public.role_assignments') IS NOT NULL THEN
        BEGIN
            GRANT SELECT, INSERT, UPDATE ON role_assignments TO axonflow_platform_admin;
        EXCEPTION WHEN insufficient_privilege THEN
            IF NOT has_table_privilege('axonflow_platform_admin', 'public.role_assignments', 'SELECT,INSERT,UPDATE') THEN
                RAISE;
            END IF;
        END;
    END IF;
END
$$;

COMMIT;
