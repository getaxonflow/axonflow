-- Rollback for migration 156 (#3065).
--
-- Drops the non-empty CHECK constraints and relaxes NOT NULL, restoring the
-- pre-156 column shape. The DEFAULT '' that migration 156 dropped from
-- webhook_subscriptions is NOT restored: it existed only to satisfy a NOT
-- NULL that no longer applies, and re-adding it would recreate the exploit
-- value on the very path this rollback is meant to leave inert.
--
-- The '__axonflow_unowned__' stamps are LEFT IN PLACE deliberately. Reverting
-- them to NULL would restore rows that every tenant could read and mutate —
-- a rollback must not reopen the vulnerability. Operators who genuinely need
-- one of those rows back should re-stamp it with the owning org explicitly.

BEGIN;

DO $$
DECLARE
    tbl TEXT;
    col TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['plans', 'workflows', 'workflow_checkpoints', 'execution_summaries', 'webhook_subscriptions']
    LOOP
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables
                       WHERE table_schema = 'public' AND table_name = tbl) THEN
            CONTINUE;
        END IF;
        FOREACH col IN ARRAY ARRAY['org_id', 'tenant_id']
        LOOP
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                           WHERE table_schema = 'public' AND table_name = tbl AND column_name = col) THEN
                CONTINUE;
            END IF;

            EXECUTE format('ALTER TABLE %I DROP CONSTRAINT IF EXISTS %I',
                           tbl, tbl || '_' || col || '_not_empty');

            -- webhook_subscriptions.org_id/tenant_id were ALREADY NOT NULL
            -- before 156 (mig 048 declared them NOT NULL DEFAULT ''), so
            -- dropping NOT NULL here would leave the schema in a state the
            -- pre-156 code never saw. Only the columns 156 itself made
            -- NOT NULL are relaxed.
            IF tbl <> 'webhook_subscriptions' THEN
                EXECUTE format('ALTER TABLE %I ALTER COLUMN %I DROP NOT NULL', tbl, col);
            END IF;
        END LOOP;
    END LOOP;
END
$$;

COMMIT;
