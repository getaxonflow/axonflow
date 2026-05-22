-- Migration 102 DOWN: reverse the post-FORCE-RLS hardening on customer-facing audit tables
-- Context: reverses 102_v9_b2_audit_table_hardening.sql
--
-- The three hardening steps each have an independent reverse:
--   - Step 1: re-create the audit_retention_config_admin_access policy that
--     was in 026.
--   - Step 2: restore decision_chain_org_isolation to the get_current_org_id()
--     expression form from 025.
--   - Step 3: drop the NOT NULL constraint on mcp_query_audits.org_id (revert
--     to the post-061 nullable state).
--
-- These reversals are best-effort: the original CREATE POLICY statements were
-- in migrations 025 and 026 respectively. We re-create them here in the same
-- shape rather than calling those migrations.

BEGIN;

-- Step 3 inverse: drop NOT NULL on mcp_query_audits.org_id (only if table exists).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mcp_query_audits') THEN
        ALTER TABLE mcp_query_audits ALTER COLUMN org_id DROP NOT NULL;
        RAISE NOTICE 'Migration 102 DOWN Step 3: mcp_query_audits.org_id reverted to nullable';
    END IF;
END
$$;

-- Step 2 inverse: restore decision_chain policy to the 025 expression form.
DROP POLICY IF EXISTS decision_chain_org_isolation ON decision_chain;
CREATE POLICY decision_chain_org_isolation ON decision_chain
    FOR ALL
    USING (org_id = get_current_org_id());

-- Step 1 inverse: re-create the audit_retention_config admin_access policy
-- from migration 026 (verbatim).
CREATE POLICY audit_retention_config_admin_access ON audit_retention_config
    FOR SELECT
    USING (current_setting('app.is_admin', true)::BOOLEAN = true);

COMMIT;
