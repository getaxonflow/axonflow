-- Migration 167 DOWN: remove the single-use consumption marker (#3509).
-- Existence-guarded like the up migration.
--
-- Dropping consumed_at loses the record of which approvals were spent. That is
-- acceptable on a down migration only because the column is the ONLY thing an
-- older agent would not understand: an older binary never reads it, never
-- writes it, and holds every retry exactly as it did before. Rolling back the
-- schema without rolling back the agent is the dangerous direction and is not
-- supported - roll the images back first.

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        -- to_regclass, not information_schema: see the up migration.
        SELECT 1 WHERE to_regclass('public.hitl_approval_queue') IS NOT NULL
    ) THEN
        DROP INDEX IF EXISTS idx_hitl_unconsumed_grant;
        DROP INDEX IF EXISTS idx_hitl_open_policy_step_up;
        ALTER TABLE hitl_approval_queue DROP COLUMN IF EXISTS consumed_at;
        RAISE NOTICE 'Migration 167 down: consumed_at + both partial indexes removed';
    END IF;
END $$;

-- The history CHECK is narrowed back only when no row would violate it.
-- hitl_approval_history is an IMMUTABLE audit trail: deleting or rewriting a
-- recorded consumption to satisfy a rollback would destroy evidence, so the
-- constraint is left widened instead and the operator is told why. A widened
-- CHECK on an older binary is inert - nothing writes the value.
DO $$
DECLARE
    consumed_rows BIGINT;
BEGIN
    IF EXISTS (
        SELECT 1 WHERE to_regclass('public.hitl_approval_history') IS NOT NULL
    ) THEN
        SELECT COUNT(*) INTO consumed_rows FROM hitl_approval_history WHERE action = 'consumed';
        IF consumed_rows = 0 THEN
            ALTER TABLE hitl_approval_history
                DROP CONSTRAINT IF EXISTS hitl_history_valid_action;
            ALTER TABLE hitl_approval_history
                ADD CONSTRAINT hitl_history_valid_action
                CHECK (action IN ('created', 'approved', 'rejected', 'expired', 'overridden', 'escalated'));
            RAISE NOTICE 'Migration 167 down: hitl_history_valid_action narrowed (no consumed rows)';
        ELSE
            RAISE NOTICE 'Migration 167 down: % consumed history row(s) present - CHECK left widened rather than destroying audit evidence', consumed_rows;
        END IF;
    END IF;
END $$;

COMMIT;
