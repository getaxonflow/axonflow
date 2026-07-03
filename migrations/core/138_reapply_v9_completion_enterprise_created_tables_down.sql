-- Rollback for migration 138: re-applied v9 org_id/RLS completion + redact
-- override action.
--
-- NOTE: this migration only re-executed the (idempotent) completion steps of
-- core/106 and core/107 at a later position, so rolling it back must NOT
-- blindly drop org_id/RLS — on upgraded deploys those were applied by
-- 106/107 and remain owned by them. The only state 138 itself introduced is:
--   1. The rebuilt policy_overrides action CHECK including 'redact'
--   2. org_id/RLS on deploys where 106/107 had no-op'd (fresh enterprise)
--
-- Restoring (1) reinstates the pre-138 (core/070) CHECK. For (2) we intentionally
-- DO NOT drop org_id columns or RLS: the portal write handlers reference
-- org_id unconditionally, so dropping the column would re-break connector /
-- SSO creation. Rollback of the schema-completion half is a no-op by design.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'policy_overrides') THEN
        -- Guard: only restore the narrower CHECK if no rows use 'redact'
        -- (otherwise the ADD CONSTRAINT itself would fail).
        IF EXISTS (SELECT 1 FROM policy_overrides WHERE action_override = 'redact') THEN
            RAISE NOTICE 'Migration 138 down: redact overrides exist; keeping widened CHECK';
        ELSE
            ALTER TABLE policy_overrides DROP CONSTRAINT IF EXISTS policy_overrides_action_override_check;
            ALTER TABLE policy_overrides
                ADD CONSTRAINT policy_overrides_action_override_check
                CHECK (action_override IN (
                    'block', 'warn', 'log', 'allow', 'deny', 'require_approval', 'log_only'
                ));
            RAISE NOTICE 'Migration 138 down: restored pre-138 action CHECK';
        END IF;
    END IF;
END
$$;

COMMIT;
