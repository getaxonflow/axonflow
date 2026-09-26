-- Migration 188: hitl_approval_queue's policy attribution holds every policy that asked (#3354)
-- Date: 2026-09-24
-- Purpose: an approval requested by MORE THAN ONE policy could not be queued.
--
-- The decision engine merges identical approval_challenge obligations into one
-- instruction whose source is EVERY demanding policy, comma-joined in canonical
-- order (platform/decision/contract/obligation.go, the merge point that
-- documents why it keeps every source). The request-plane hold (#4375) queues
-- one approval for that instruction and writes the joined source to
-- triggered_policy_id and triggered_policy_name. Those were VARCHAR(100) and
-- VARCHAR(255) (core/025), so whether a call was held or refused depended on
-- the length, in characters, of its policy ids:
--
--   * the FinCrime pack's structuring + velocity step-ups join to 104 chars:
--     the INSERT failed, and decide refused the call approval_required with the
--     driver's "value too long" text on the wire;
--   * its geo-corridor + payment-execution step-ups join to 98 chars: HELD.
--
-- The pack ships seven requirement controls (six detector step-ups and the
-- Engine B score control, #4448) at 42-52 chars each, so one request can merge
-- five or more (past 255). Both columns become TEXT.
--
-- THE RESIDUAL BOUND (analysis, not measured). TEXT removes the column's
-- length limit, but not every length limit: three btree indexes over
-- triggered_policy_id survive this migration (the verification below requires
-- them), and a btree tuple cannot exceed BTMaxItemSize, about 2704 bytes with
-- the default 8 kB page. A joined set longer than that fails the INSERT with
-- "index row size ... exceeds btree version 4 maximum", and the call is
-- refused approval_required like any other approval that could not be queued
-- (the agent's wire names no driver text; the log names the cause). Nothing
-- caps the join upstream (contract/obligation.go joins every source). Today's
-- largest reachable set, the pack's seven requirement controls, is ~360
-- bytes, over seven times inside that bound. This rests on BTMaxItemSize and
-- on reading the three index definitions, not on a Postgres run.
--
-- WHY THE WHOLE JOINED VALUE AND NOT ONE OF ITS POLICIES. The row names what a
-- reviewer was asked to approve. Naming one policy of the set would record a
-- different approval from the one granted, and would undo the merge point's
-- own fix ("which policy a merged audit was attributed to depended on delivery
-- strength and input order"). The spend is bound to the full requirement set
-- through request_context's binding digest (queue.SpendBindingGrant), so an
-- approval for one set is never spent by a call with another.
--
-- COST, AND HOW TO PREDICT IT. Measured on PostgreSQL 15.19 over a queue of
-- 300,005 rows, 494 MB total relation size:
--
--   * the TABLE is not rewritten: VARCHAR(n) -> TEXT is binary-coercible, and
--     its relfilenode is unchanged, as is core/025's idx_hitl_policy;
--   * core/167's two PARTIAL indexes (idx_hitl_unconsumed_grant,
--     idx_hitl_open_policy_step_up) ARE rebuilt. That is PostgreSQL's rule for
--     any index carrying a predicate or expressions (CheckIndexCompatible never
--     reuses one), so NO column type change avoids it - VARCHAR without a
--     length rebuilds them the same way;
--   * ACCESS EXCLUSIVE is held on the table, the three indexes over
--     triggered_policy_id and hitl_pending_summary until COMMIT: nothing reads
--     or writes the approval queue meanwhile;
--   * the migration took 1108 ms. Each rebuild scans the whole heap, so the
--     time is linear in RELATION SIZE, not in the rows the predicates match:
--     about 1.1 s per 0.5 GB, so about 10 s at 5 GB.
--
-- Before upgrading, read SELECT pg_size_pretty(pg_total_relation_size(
-- 'hitl_approval_queue')) and plan for that lock. CONCURRENTLY is not
-- available: the agent's runner sends a file as one implicit transaction
-- (core/186 says the same). The relfilenodes above are asserted in
-- platform/agent/migration_188_hitl_triggered_policy_text_realpg_test.go, so a
-- PostgreSQL that behaves differently fails it.
--
-- THE VIEW. hitl_pending_summary (core/025) selects triggered_policy_name, and
-- PostgreSQL refuses to change the type of a column a view reads. It is
-- dropped and recreated with core/025's definition in this transaction, and
-- only when it existed; its pg_get_viewdef is identical before and after
-- (asserted in the Real-PG cell named above). It is the ONLY view or rule over
-- either column in migrations/ (core/025 creates the only two views on this
-- table; eu_ai_act_hitl_metrics reads neither column), and the only rule
-- pg_depend lists on a database migrated to 187. The RLS policy reads org_id
-- alone.

BEGIN;

DO $$
DECLARE
    had_summary BOOLEAN;
BEGIN
    IF EXISTS (
        -- to_regclass, not information_schema: information_schema views are
        -- PRIVILEGE-FILTERED (see core/167).
        SELECT 1 WHERE to_regclass('public.hitl_approval_queue') IS NOT NULL
    ) THEN
        had_summary := to_regclass('public.hitl_pending_summary') IS NOT NULL;
        DROP VIEW IF EXISTS hitl_pending_summary;

        ALTER TABLE hitl_approval_queue
            ALTER COLUMN triggered_policy_id TYPE TEXT,
            ALTER COLUMN triggered_policy_name TYPE TEXT;

        COMMENT ON COLUMN hitl_approval_queue.triggered_policy_id IS
            'Every policy whose approval requirement asked for this approval, comma-joined in canonical order when the engine merged several into one (#3354). TEXT: no column length; the btree indexes over it still bound a value at about 2704 bytes (188 header).';

        IF had_summary THEN
            -- core/025's definition, unchanged.
            CREATE OR REPLACE VIEW hitl_pending_summary AS
            SELECT
                org_id,
                tenant_id,
                triggered_policy_name,
                severity,
                COUNT(*) as pending_count,
                MIN(created_at) as oldest_request,
                MAX(expires_at) as next_expiry
            FROM hitl_approval_queue
            WHERE status = 'pending'
            GROUP BY org_id, tenant_id, triggered_policy_name, severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    ELSE 4
                END,
                oldest_request ASC;
        END IF;

        RAISE NOTICE 'Migration 188: triggered_policy_id and triggered_policy_name are TEXT';
    ELSE
        RAISE NOTICE 'Migration 188: hitl_approval_queue does not exist - skipping';
    END IF;
END $$;

-- Verification - fail loudly if either column is still bounded, or an index
-- over triggered_policy_id is gone.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 WHERE to_regclass('public.hitl_approval_queue') IS NOT NULL
    ) THEN
        IF (SELECT count(*) FROM pg_attribute
             WHERE attrelid = to_regclass('public.hitl_approval_queue')
               AND attname IN ('triggered_policy_id', 'triggered_policy_name')
               AND atttypid = 'text'::regtype
               AND NOT attisdropped) <> 2 THEN
            RAISE EXCEPTION 'Migration 188 failed: triggered_policy_id and triggered_policy_name are not both TEXT';
        END IF;
        IF to_regclass('public.idx_hitl_policy') IS NULL
           OR to_regclass('public.idx_hitl_unconsumed_grant') IS NULL
           OR to_regclass('public.idx_hitl_open_policy_step_up') IS NULL THEN
            RAISE EXCEPTION 'Migration 188 failed: an index over triggered_policy_id is missing';
        END IF;
        RAISE NOTICE 'Migration 188 verified: both columns TEXT, the three indexes over triggered_policy_id present';
    END IF;
END $$;

COMMIT;
