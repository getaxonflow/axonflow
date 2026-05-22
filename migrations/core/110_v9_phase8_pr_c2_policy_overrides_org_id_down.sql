-- Migration 110 DOWN: revert policy_overrides + static_policy_versions + policy_versions
-- RLS to mig 030/022 shape. Drops BOTH the new + legacy named policies for re-run safety,
-- then re-installs the legacy app.tenant_id-keyed policies.
--
-- NOTE: org_id columns added by mig 110 are NOT dropped (data preservation on re-up).
-- Operators replaying down→up should run the up migration's backfill chain again — it
-- is idempotent and the un-resolved-pre-mig110-* sentinel rows will not be re-stamped.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'policy_overrides') THEN
        DROP POLICY IF EXISTS policy_overrides_org_id_isolation ON policy_overrides;
        DROP POLICY IF EXISTS policy_overrides_tenant_isolation ON policy_overrides;
        CREATE POLICY policy_overrides_tenant_isolation ON policy_overrides
            USING (
                tenant_id = current_setting('app.tenant_id', true)
                OR organization_id IN (
                    SELECT org_id::uuid FROM organizations
                    WHERE id::text = current_setting('app.tenant_id', true)
                )
            );
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'static_policy_versions') THEN
        DROP POLICY IF EXISTS static_policy_versions_org_id_isolation ON static_policy_versions;
        DROP POLICY IF EXISTS static_policy_versions_tenant_isolation ON static_policy_versions;
        CREATE POLICY static_policy_versions_tenant_isolation ON static_policy_versions
            USING (
                policy_id IN (
                    SELECT id FROM static_policies
                    WHERE tenant_id = current_setting('app.tenant_id', true)
                       OR tier = 'system'
                )
            );
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'policy_versions') THEN
        DROP POLICY IF EXISTS policy_versions_org_id_isolation ON policy_versions;
        DROP POLICY IF EXISTS policy_versions_tenant_isolation ON policy_versions;
        CREATE POLICY policy_versions_tenant_isolation ON policy_versions
            USING (
                policy_id IN (
                    SELECT policy_id FROM dynamic_policies
                    WHERE tenant_id = current_setting('app.tenant_id', true)
                )
            );
    END IF;
END
$$;

COMMIT;
