-- Migration 156: make the empty tenancy key unrepresentable (#3065)
-- Date: 2026-07-28
-- Issue: #3065 (epic #3071, Tier 2)
--
-- #3065 is the fail-open org-binding class: every by-id authorization on
-- these tables read
--
--     if callerOrg <> '' AND row.org_id <> '' AND row.org_id <> callerOrg then reject
--
-- so a row with NO tenancy key belonged to everyone. The application half of
-- the fix refuses to persist such a row and refuses to authorize one. This is
-- the database half: the empty value stops being writable at all.
--
-- Scope: plans, workflows, workflow_checkpoints, execution_summaries and
-- webhook_subscriptions — the tenant-keyed tables behind #3065's
-- confirmed-exploitable findings that have NO row-level security in any
-- posture (mig 018 does not list them), so the column constraint is the only
-- structural backstop they will ever have. workflow_checkpoints is included
-- because ResumeFromCheckpoint now authorizes the checkpoint row on its own
-- keys (F9): a checkpoint written without them would be permanently
-- non-resumable, so the empty value has to stop being writable there too.
--
-- NOT in scope: `budgets`. A budget row with no org is a deployment-global
-- spend cap that GetBudgetsForScope deliberately admits for every tenant —
-- constraining the column would silently disable those caps on upgrade,
-- loosening spend control. #3065's budget exposure is closed in the
-- application layer instead (strict equality in budgetOrgScopeSQL plus a
-- fail-closed precondition), which removes the by-id write path without
-- touching enforcement.
--
-- Staging: backfill, then constrain. Rows that predate the tenancy headers
-- are stamped with the sentinel '__axonflow_unowned__' rather than deleted:
--   * the audit/history value of the row is preserved;
--   * the sentinel is not a plausible org id (org ids come from a license
--     payload or the ORG_ID env var), and platform/shared/tenantscope refuses
--     it on BOTH sides of every comparison, so a stamped row is reachable by
--     nobody — including an operator who sets ORG_ID to the sentinel string.
--
-- BEHAVIOR CHANGE (deliberate, documented in the PR): plans / workflows /
-- checkpoints / executions / webhook subscriptions written before this
-- migration WITHOUT an org or tenant key become permanently inaccessible
-- through the by-id routes, and permanently UNWRITABLE too — the application
-- guards reject the sentinel on the row side exactly as they reject an empty
-- key, so an in-flight execution that started before the upgrade and finishes
-- after it will fail its final UpdateSummary rather than be marked completed.
-- Both are the point: they were previously accessible to EVERY tenant, which
-- is the vulnerability. The window is the upgrade itself.
--
-- LOCK SCOPE: every ALTER below runs in ONE transaction, so the ACCESS
-- EXCLUSIVE locks on all five tables are held until COMMIT — they are not
-- released incrementally per table. Size the maintenance window for the sum,
-- not the largest.
--
-- LOCKING: `ALTER TABLE ... SET NOT NULL` takes ACCESS EXCLUSIVE and scans
-- the table to verify the constraint; `ADD CONSTRAINT ... CHECK` does the
-- same. On a deployment with a large `execution_summaries` or `workflows`,
-- plan a maintenance window — the same caveat mig 142's audit_logs retype
-- carries. No table is REWRITTEN (neither operation changes on-disk row
-- format), so the scan is read-only and proportional to row count.
--
-- webhook_subscriptions note: mig 048 declared tenant_id/org_id as
-- `TEXT NOT NULL DEFAULT ''`. The NOT NULL was already there and did nothing —
-- the DEFAULT recreates the exact exploit value on every insert that omits
-- the column. The default is dropped here; the CHECK is what makes NOT NULL
-- mean something.

BEGIN;

-- Sentinel used for rows that carry no tenancy key. Must stay in lockstep
-- with tenantscope.UnownedOrgSentinel (platform/shared/tenantscope).
DO $$
DECLARE
    unowned CONSTANT TEXT := '__axonflow_unowned__';
    tbl     TEXT;
    col     TEXT;
    stamped INTEGER;
    total   INTEGER := 0;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['plans', 'workflows', 'workflow_checkpoints', 'execution_summaries', 'webhook_subscriptions']
    LOOP
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables
                       WHERE table_schema = 'public' AND table_name = tbl) THEN
            RAISE NOTICE 'Migration 156: table % absent, skipping', tbl;
            CONTINUE;
        END IF;

        FOREACH col IN ARRAY ARRAY['org_id', 'tenant_id']
        LOOP
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                           WHERE table_schema = 'public' AND table_name = tbl AND column_name = col) THEN
                RAISE NOTICE 'Migration 156: %.% absent, skipping', tbl, col;
                CONTINUE;
            END IF;

            -- 1. Backfill: stamp the unowned rows.
            EXECUTE format(
                'UPDATE %I SET %I = %L WHERE %I IS NULL OR btrim(%I) = %L',
                tbl, col, unowned, col, col, '');
            GET DIAGNOSTICS stamped = ROW_COUNT;
            total := total + stamped;
            IF stamped > 0 THEN
                RAISE WARNING 'Migration 156: %.% — % row(s) had no tenancy key and are now stamped %. They were previously reachable by EVERY tenant (#3065); they are now reachable by none.',
                    tbl, col, stamped, unowned;
            END IF;

            -- 2. Drop any DEFAULT that would recreate the empty value
            --    (webhook_subscriptions carries DEFAULT '' from mig 048).
            EXECUTE format('ALTER TABLE %I ALTER COLUMN %I DROP DEFAULT', tbl, col);

            -- 3. Constrain: NOT NULL plus a non-empty CHECK. Both are needed —
            --    NOT NULL alone still admits the empty string, which is the
            --    value the exploit actually used.
            EXECUTE format('ALTER TABLE %I ALTER COLUMN %I SET NOT NULL', tbl, col);
            EXECUTE format(
                'ALTER TABLE %I DROP CONSTRAINT IF EXISTS %I',
                tbl, tbl || '_' || col || '_not_empty');
            EXECUTE format(
                'ALTER TABLE %I ADD CONSTRAINT %I CHECK (btrim(%I) <> %L)',
                tbl, tbl || '_' || col || '_not_empty', col, '');
        END LOOP;
    END LOOP;

    RAISE NOTICE 'Migration 156: tenancy keys constrained; % unowned value(s) stamped in total', total;
END
$$;

-- Self-test: prove the invariant holds on every table/column the block
-- actually processed. Guarded on the same existence checks so a legacy schema
-- the loop skipped cannot RAISE here and boot-loop the migration runner.
DO $$
DECLARE
    tbl       TEXT;
    col       TEXT;
    offenders INTEGER;
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

            EXECUTE format(
                'SELECT COUNT(*) FROM %I WHERE %I IS NULL OR btrim(%I) = %L',
                tbl, col, col, '')
                INTO offenders;
            IF offenders > 0 THEN
                RAISE EXCEPTION 'Migration 156 failed: %.% still has % row(s) with no tenancy key', tbl, col, offenders;
            END IF;

            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = tbl
                  AND column_name = col AND is_nullable = 'NO') THEN
                RAISE EXCEPTION 'Migration 156 failed: %.% is still nullable', tbl, col;
            END IF;

            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = tbl
                  AND column_name = col AND column_default IS NOT NULL) THEN
                RAISE EXCEPTION 'Migration 156 failed: %.% still has a DEFAULT, which would recreate the empty tenancy key', tbl, col;
            END IF;

            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conrelid = format('public.%I', tbl)::regclass
                  AND conname = tbl || '_' || col || '_not_empty') THEN
                RAISE EXCEPTION 'Migration 156 failed: %.% is missing its non-empty CHECK constraint', tbl, col;
            END IF;
        END LOOP;
    END LOOP;
END
$$;

COMMIT;
