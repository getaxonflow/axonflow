-- Down migration for 090: drop policy-table client_id columns + indexes.
-- Pairs with: 090_v9_policy_tables_client_id.sql
--
-- Purely additive forward migration → drops are loss-free at the schema
-- level. Backfilled client_id values are the same as tenant_id, so any
-- row this migration touched is recoverable from tenant_id alone.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'policy_evaluations') THEN
        DROP INDEX IF EXISTS idx_policy_evaluations_org_client_time;
        DROP INDEX IF EXISTS idx_policy_evaluations_client_time;
        ALTER TABLE policy_evaluations DROP COLUMN IF EXISTS org_id;
        ALTER TABLE policy_evaluations DROP COLUMN IF EXISTS client_id;
        RAISE NOTICE 'Migration 090 DOWN: policy_evaluations.client_id + org_id + indexes dropped';
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'dynamic_policies') THEN
        DROP INDEX IF EXISTS idx_dynamic_policies_org_client;
        DROP INDEX IF EXISTS idx_dynamic_policies_client;
        ALTER TABLE dynamic_policies DROP COLUMN IF EXISTS client_id;
        RAISE NOTICE 'Migration 090 DOWN: dynamic_policies.client_id + indexes dropped';
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'static_policies') THEN
        DROP INDEX IF EXISTS idx_static_policies_org_client;
        DROP INDEX IF EXISTS idx_static_policies_client;
        ALTER TABLE static_policies DROP COLUMN IF EXISTS client_id;
        RAISE NOTICE 'Migration 090 DOWN: static_policies.client_id + indexes dropped';
    END IF;
END $$;
