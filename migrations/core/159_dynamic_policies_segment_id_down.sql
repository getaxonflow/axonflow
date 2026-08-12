-- Down migration for 159: drop dynamic_policies.segment_id + its index.
-- Pairs with: 159_dynamic_policies_segment_id.sql
--
-- Purely additive forward migration -> the drop is loss-free at the schema
-- level for every pre-P3b row (segment_id is NULL there). Any row a P3b
-- deployment DID populate loses its segment scoping on rollback -- expected
-- for a schema rollback, and the P3b selection/choke-point code paths this
-- column feeds are themselves part of the same rollback unit.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies') THEN
        DROP INDEX IF EXISTS idx_dynamic_policies_segment;
        ALTER TABLE dynamic_policies DROP COLUMN IF EXISTS segment_id;
        RAISE NOTICE 'Migration 159 DOWN: dynamic_policies.segment_id + index dropped';
    END IF;
END $$;

-- M7 (#3239 round 2): recreate get_dynamic_policies_for_tenant(), dropped by
-- the paired up migration, for a clean round-trip. Verbatim copy of its
-- original definition (010_policy_tables.sql).
CREATE OR REPLACE FUNCTION get_dynamic_policies_for_tenant(p_tenant_id VARCHAR)
RETURNS TABLE (
    policy_id VARCHAR,
    name VARCHAR,
    policy_type VARCHAR,
    conditions JSONB,
    actions JSONB,
    priority INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        dp.policy_id,
        dp.name,
        dp.policy_type,
        dp.conditions,
        dp.actions,
        dp.priority
    FROM dynamic_policies dp
    WHERE dp.enabled = true
      AND (dp.tenant_id IS NULL OR dp.tenant_id = 'global' OR dp.tenant_id = p_tenant_id)
    ORDER BY dp.priority DESC;
END;
$$ LANGUAGE plpgsql;

COMMIT;
