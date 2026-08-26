-- Migration 160 DOWN: restore high_risk_block
-- Pairs with: 160_delete_superseded_high_risk_block.sql
--
-- Re-seeds the row exactly as 010_policy_tables.sql originally inserted it.
-- This intentionally restores the PRE-036 shape (action 'block') -- 036 never
-- touched this policy_id, only sys_dyn_high_risk_block, so a faithful
-- rollback of migration 160 restores what migration 160 actually deleted,
-- not a retroactively-tuned version of it.
--
-- ON CONFLICT DO NOTHING mirrors 010's own idempotent insert style.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies') THEN
        INSERT INTO dynamic_policies (policy_id, name, description, policy_type, risk_threshold, conditions, actions, priority, tenant_id) VALUES
        ('high_risk_block', 'Block High-Risk Queries', 'Block queries with risk score above safety threshold', 'risk_based', 0.8,
            '[{"field": "risk_score", "operator": "greater_than", "value": 0.8}]',
            '[{"type": "block", "config": {"reason": "Query risk score exceeds safety threshold"}}]',
            1000, 'global')
        ON CONFLICT (policy_id) DO NOTHING;
        RAISE NOTICE 'Migration 160 DOWN: restored high_risk_block';
    END IF;
END $$;

COMMIT;
