-- Migration 167: single-use consumption marker on hitl_approval_queue (#3509)
-- Date: 2026-08-25
-- Purpose: an approval on the agent planes was a pure state flip. The reviewer
--          set status='approved', a webhook fired, and the caller's retry was
--          held again, because nothing on the enforcement path consulted the
--          approval. This column is the storage half of making an approval
--          actually admit the retry it was granted for.
--
-- Why a column on the existing row rather than a separate grant table:
--
--   * The approved queue row already carries every key the enforcement path
--     needs to match on - org_id, user_id, triggered_policy_id - and the
--     timestamp the TTL is measured from (reviewed_at). A second store would
--     have to be kept consistent with this one, and "approved here, grant
--     write failed there" is a failure mode that simply does not exist when
--     they are the same row.
--   * A compliance reviewer asking "was this approval ever used, and when?"
--     reads one row. Split across two tables that question needs a join and
--     an assumption about which side is authoritative.
--
-- SINGLE USE is the safety property, and it is enforced by the WRITE, not by
-- a read-then-write. The enforcement path consumes with a single statement --
-- see Repository.ConsumeGrant, which is the authority; this is a summary and
-- must not drift from it:
--
--     UPDATE hitl_approval_queue SET consumed_at = CURRENT_TIMESTAMP
--      WHERE id = (SELECT id FROM hitl_approval_queue
--                   WHERE org_id = $1 AND tenant_id = $2 AND client_id = $3
--                     AND user_id = $4 AND triggered_policy_id = $5
--                     AND request_type = 'policy_step_up'
--                     AND status = 'approved'
--                     AND consumed_at IS NULL
--                     AND reviewed_at IS NOT NULL
--                     AND reviewed_at > CURRENT_TIMESTAMP - $6::interval
--                     -- the approval must name a PERSON, and must not be the
--                     -- held caller's own, and must be for the request the
--                     -- reviewer actually saw. Reproduced here because a
--                     -- summary that omits the security clauses is worse than
--                     -- no summary: this is the file a DBA reads.
--                     AND reviewer_role IS NOT NULL
--                     AND reviewer_role <> 'service'
--                     AND reviewer_id IS NOT NULL
--                     AND reviewer_id <> $3 AND reviewer_id <> $4
--                     AND request_context->>'query_hash' = $7
--                   ORDER BY reviewed_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED)
--      RETURNING request_id, tenant_id
--
-- Two concurrent retries race on the same row; PostgreSQL serialises the
-- UPDATE and exactly one of them gets a RETURNING row. There is no window in
-- which both observe consumed_at IS NULL and both proceed. That is what makes
-- a generous TTL safe: a grant can never authorise more than one request, so
-- the TTL only bounds how long the single admission stays available, and does
-- not have to race a human who comes back to the portal later.
--
-- NULLABLE with no default is load-bearing: every existing row - including the
-- fincrime_review rows already in the field and every wcp_step_gate row the
-- orchestrator writes - reads consumed_at IS NULL, which is the correct
-- "never consumed" state. No backfill, and no behaviour change at deploy time:
-- nothing consumes anything until an operator upgrades the agent, and the
-- consume predicate is scoped to request_type = 'policy_step_up', a value that
-- did not exist before this release.

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        -- to_regclass, not information_schema: information_schema views are
        -- PRIVILEGE-FILTERED, so a role without a privilege on the table reads
        -- "table absent", takes the skip branch and COMMITS having done
        -- nothing. pg_catalog is not filtered. Matches migrations 161/162/163.
        SELECT 1 WHERE to_regclass('public.hitl_approval_queue') IS NOT NULL
    ) THEN
        ALTER TABLE hitl_approval_queue
            ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMP WITH TIME ZONE;

        COMMENT ON COLUMN hitl_approval_queue.consumed_at IS
            'When an approved policy_step_up entry was spent admitting exactly one request. NULL means never consumed. Set by a single atomic UPDATE guarded on consumed_at IS NULL, which is what enforces single use (#3509).';

        -- Partial index on exactly the rows the consume predicate can match.
        -- The enforcement path runs this lookup on a held request, so it is on
        -- the latency path of a governed decision; without it the scan is over
        -- every approval the org has ever had. Partial because an entry that is
        -- pending, rejected, expired, already consumed, or from another plane
        -- can never satisfy the predicate, and excluding them keeps the index
        -- proportional to "approvals waiting to be spent" rather than to queue
        -- history.
        CREATE INDEX IF NOT EXISTS idx_hitl_unconsumed_grant
            ON hitl_approval_queue (org_id, tenant_id, client_id, user_id, triggered_policy_id, reviewed_at DESC)
            WHERE status = 'approved'
              AND consumed_at IS NULL
              AND request_type = 'policy_step_up';

        -- The dedup lookup's own index. idx_hitl_unconsumed_grant above is
        -- predicated on status = 'approved' and can NEVER serve this query,
        -- which asks the opposite question ("is a reviewer already looking at
        -- this request?"). Without a second index the lookup falls back to
        -- idx_hitl_org_status and scans every pending row in the org - on the
        -- request-latency path of every held request, and on Enterprise, where
        -- MaxPendingApprovals is unlimited and nothing bounds that set.
        --
        -- The plane and query-hash discriminators live in request_context and
        -- are deliberately NOT in the index: they are a residual filter over
        -- the handful of rows this key already narrows to, and indexing JSONB
        -- expressions to save that would cost more on every write than it
        -- saves on the read.
        CREATE INDEX IF NOT EXISTS idx_hitl_open_policy_step_up
            ON hitl_approval_queue (org_id, tenant_id, client_id, user_id, triggered_policy_id, created_at DESC)
            WHERE status = 'pending'
              AND request_type = 'policy_step_up';

        RAISE NOTICE 'Migration 167: consumed_at + idx_hitl_unconsumed_grant + idx_hitl_open_policy_step_up added';
    ELSE
        RAISE NOTICE 'Migration 167: hitl_approval_queue does not exist - skipping';
    END IF;
END $$;

-- hitl_approval_history is the immutable audit trail for this queue, and a
-- consumption is a state event on the approval every bit as much as the
-- approval itself: it is the moment a human's decision was actually spent, and
-- it names which plane spent it. Recording it anywhere else would put half the
-- lifecycle in one store and half in another.
--
-- mig 025 constrains action to a closed set, so the value has to be admitted
-- here or every consumption write fails the CHECK. Widening a CHECK is
-- backward compatible in the direction that matters: an older reader sees an
-- action string it does not recognise and renders it, and an older WRITER
-- never produces one.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 WHERE to_regclass('public.hitl_approval_history') IS NOT NULL
    ) THEN
        ALTER TABLE hitl_approval_history
            DROP CONSTRAINT IF EXISTS hitl_history_valid_action;
        -- NOT VALID, then VALIDATE, as two statements rather than one.
        --
        -- To be precise about what this does and does NOT buy: this whole
        -- migration is one transaction, so the ACCESS EXCLUSIVE that
        -- DROP CONSTRAINT takes on hitl_approval_history is held until COMMIT
        -- either way. Splitting the add from the validation does not shorten
        -- that. What it buys is that the ADD is constant time and the scan is
        -- an explicit, separately readable statement, so the cost of this step
        -- is visible to whoever reads it next instead of hiding inside an ADD.
        --
        -- Skipping the validation altogether would be safe (the new predicate
        -- is a strict SUPERSET of the old one, so every existing row satisfies
        -- it by construction), but an unvalidated constraint is not trusted by
        -- the planner and reads as a loose end. Validating costs one scan of a
        -- table that is small next to audit_logs.
        ALTER TABLE hitl_approval_history
            ADD CONSTRAINT hitl_history_valid_action
            CHECK (action IN ('created', 'approved', 'rejected', 'expired', 'overridden', 'escalated', 'consumed'))
            NOT VALID;
        ALTER TABLE hitl_approval_history
            VALIDATE CONSTRAINT hitl_history_valid_action;

        RAISE NOTICE 'Migration 167: hitl_approval_history action set widened with consumed';
    ELSE
        RAISE NOTICE 'Migration 167: hitl_approval_history does not exist - skipping';
    END IF;
END $$;

-- Verification - fail loudly if the column or the index is missing.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 WHERE to_regclass('public.hitl_approval_queue') IS NOT NULL
    ) THEN
        IF NOT EXISTS (SELECT 1 FROM pg_attribute
                       WHERE attrelid = to_regclass('public.hitl_approval_queue')
                         AND attname = 'consumed_at'
                         AND NOT attisdropped) THEN
            RAISE EXCEPTION 'Migration 167 failed: consumed_at column not created';
        END IF;
        IF to_regclass('public.idx_hitl_unconsumed_grant') IS NULL THEN
            RAISE EXCEPTION 'Migration 167 failed: idx_hitl_unconsumed_grant not created';
        END IF;
        IF to_regclass('public.idx_hitl_open_policy_step_up') IS NULL THEN
            RAISE EXCEPTION 'Migration 167 failed: idx_hitl_open_policy_step_up not created';
        END IF;
        RAISE NOTICE 'Migration 167 verified: consumed_at + both partial indexes present';
    END IF;

    -- Assert the widened CHECK actually ADMITS the new value, rather than
    -- merely asserting a constraint by that name exists. A constraint whose
    -- name is right and whose predicate is stale would pass a name check and
    -- fail every consumption write at runtime.
    IF EXISTS (
        SELECT 1 WHERE to_regclass('public.hitl_approval_history') IS NOT NULL
    ) THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
             WHERE conname = 'hitl_history_valid_action'
               AND conrelid = to_regclass('public.hitl_approval_history')
               AND pg_get_constraintdef(oid) LIKE '%consumed%'
               -- convalidated too: a constraint left NOT VALID is trusted by
               -- nothing, and asserting only its definition would pass over a
               -- validation step that silently did not run.
               AND convalidated
        ) THEN
            RAISE EXCEPTION 'Migration 167 failed: hitl_history_valid_action does not admit consumed';
        END IF;
        RAISE NOTICE 'Migration 167 verified: hitl_history_valid_action admits consumed';
    END IF;
END $$;

COMMIT;
