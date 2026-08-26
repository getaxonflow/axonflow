-- Migration 160: delete high_risk_block, superseded by sys_dyn_high_risk_block
-- Date: 2026-08-20
-- Issue: #3321 (PR #3324 reviewer feedback)
--
-- 010_policy_tables.sql:268 seeded 'high_risk_block' ('Block High-Risk
-- Queries', risk_score > 0.8, action 'block', priority 1000, tenant
-- 'global') on 2025-11-20. 031_seed_system_policies.sql:339 later seeded a
-- near-duplicate, 'sys_dyn_high_risk_block' -- identical name, identical
-- description, identical conditions JSON, identical priority, identical
-- tenant -- as part of the structured system-policy pass (tier='system',
-- category='dynamic-risk'). 036_update_policy_defaults.sql then tuned ONLY
-- the sys_dyn_ row (block -> warn); high_risk_block was never touched by
-- that pass and has stayed 'block' the entire time.
--
-- Until #3321 restored risk_score as a platform-computed value, NEITHER row
-- could ever fire -- risk_score resolved only from caller-supplied
-- req.Context and defaulted to 0.0, so risk_score > 0.8 was unreachable in
-- practice. That made the duplication latent rather than harmful. With
-- risk_score now computed, high_risk_block -- still 'block', never
-- downgraded -- would have started BLOCKING production traffic on upgrade,
-- while its intentionally-tuned twin sys_dyn_high_risk_block sits right next
-- to it at 'warn'. platform/agent/detection_config.go names
-- sys_dyn_high_risk_block, not high_risk_block, as the policy this platform's
-- own documentation treats as canonical.
--
-- high_risk_block is deleted as superseded by sys_dyn_high_risk_block, not
-- the other way around: sys_dyn_high_risk_block is the row that went through
-- migration 031's structured system-policy pass and migration 036's
-- deliberate tuning, so its tier='system'/category='dynamic-risk' shape and
-- its 'warn' action are the ones that should keep governing risk_score > 0.8
-- traffic. Every existing reference to sys_dyn_high_risk_block elsewhere in
-- this codebase (detection_config.go, this branch's runtime-e2e suites)
-- already targets the surviving row and needs no change.
--
-- policy_versions.policy_id has ON DELETE CASCADE to dynamic_policies.policy_id
-- (022_policy_versioning.sql), so this delete cannot be blocked by version
-- history on the row.

BEGIN;

DO $$
DECLARE
    deleted_count INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies') THEN
        DELETE FROM dynamic_policies WHERE policy_id = 'high_risk_block';
        GET DIAGNOSTICS deleted_count = ROW_COUNT;
        RAISE NOTICE 'Migration 160: deleted % high_risk_block row(s) (superseded by sys_dyn_high_risk_block)', deleted_count;
    END IF;
END $$;

COMMIT;
