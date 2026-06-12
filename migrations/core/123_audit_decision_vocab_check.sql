-- Migration 123: enforce the canonical audit_logs.policy_decision vocabulary
-- with a CHECK constraint, after normalizing any residual non-canonical rows.
-- Date: 2026-06-11
-- Issue: #2638 (vocabulary umbrella) — writer convergence + DB enforcement. ADR-058.
-- Depends: 122_audit_decision_vocab_backfill
--
-- WHY ----------------------------------------------------------------------
-- Migration 122 (#2643) historically normalized the legacy Decision-Mode wire
-- tokens (allow / deny / denied) that the agent /decide writer used to persist.
-- That fixed the rows that existed then, but it left two gaps this migration
-- closes now that every forward writer has converged on the shared vocabulary
-- (platform/shared/audit, #2638):
--
--   1. There is no DB-level guarantee. A future writer (or a hand-written row)
--      could still land a non-canonical value — exactly the "everything reads
--      Logged" / mislabeled-decision class #2638 exists to kill. The CHECK below
--      makes a non-canonical write fail LOUDLY at the database instead of
--      silently corrupting block-rate / compliance metrics downstream.
--   2. A residual non-canonical spelling could remain — e.g. the orchestrator
--      workflow gate wrote 'pending_approval' (LogWorkflowOperation), which is
--      neither canonical nor covered by 122's allow/deny-only backfill. That
--      writer is fixed to emit 'needs_approval' in this same change; this
--      migration normalizes any rows it (or any other diverging writer) already
--      wrote so the CHECK can be added without rejecting existing history.
--
-- CANONICAL SET ------------------------------------------------------------
-- Five verdicts + one recognized non-verdict marker (audit.All() +
-- DecisionOverrideLifecycle): allowed | blocked | redacted | needs_approval |
-- error | override_lifecycle. The marker is what the override audit writer
-- (override_audit.go) stores for grant/revoke lifecycle events; it MUST be in
-- the CHECK set or every override event would fail to persist.
--
-- NORMALIZE-THEN-CHECK ------------------------------------------------------
-- The single UPDATE below mirrors platform/shared/audit.Normalize EXACTLY:
-- every known legacy / divergent / case / whitespace spelling maps to its
-- canonical verdict, and ANY unrecognized value fails SAFE to 'error' (never
-- 'allowed') — an unclassifiable verdict is an error condition, never a clean
-- allow. It touches ONLY rows that are not already canonical-or-marker, so
-- legitimately-canonical history is left byte-for-byte untouched. Keep this CASE
-- table in lockstep with the legacyAliases map in policy_decision.go.
--
-- IDEMPOTENT ----------------------------------------------------------------
-- Re-running is a no-op: the UPDATE's WHERE matches nothing once every row is
-- canonical, and DROP CONSTRAINT IF EXISTS before ADD makes the constraint
-- re-addable. The down migration drops the CHECK (the data normalization is
-- forward-only, like 122's down — the original legacy spellings are not
-- recoverable and the canonical set is the intended steady state).
--
-- RLS POSTURE --------------------------------------------------------------
-- audit_logs is deliberately NOT FORCE-RLS (migration 101 deferred it for the
-- cross-org audit_cleanup worker). There is no WITH CHECK to satisfy, so the
-- UPDATE + ALTER run on the migration connection and succeed identically under
-- AXONFLOW_DB_USE_APP_ROLE on or off.

BEGIN;

-- 1. Normalize any residual non-canonical rows to the canonical vocabulary.
--    Mirrors audit.Normalize: known spellings → canonical; anything else →
--    'error' (fail-safe, never 'allowed'). Only non-canonical rows are touched.
UPDATE audit_logs
   SET policy_decision = CASE lower(trim(policy_decision))
       -- allowed
       WHEN 'allow'              THEN 'allowed'
       WHEN 'allowed'            THEN 'allowed'
       -- blocked
       WHEN 'deny'               THEN 'blocked'
       WHEN 'denied'             THEN 'blocked'
       WHEN 'block'              THEN 'blocked'
       WHEN 'blocked'            THEN 'blocked'
       -- redacted
       WHEN 'redact'             THEN 'redacted'
       WHEN 'masked'             THEN 'redacted'
       WHEN 'modified'           THEN 'redacted'
       WHEN 'redacted'           THEN 'redacted'
       -- needs_approval
       WHEN 'needs_approval'     THEN 'needs_approval'
       WHEN 'need_approval'      THEN 'needs_approval'
       WHEN 'needs-approval'     THEN 'needs_approval'
       WHEN 'require_approval'   THEN 'needs_approval'
       WHEN 'requires_approval'  THEN 'needs_approval'
       WHEN 'requires-approval'  THEN 'needs_approval'
       WHEN 'pending_approval'   THEN 'needs_approval'
       WHEN 'pending-approval'   THEN 'needs_approval'
       WHEN 'awaiting_approval'  THEN 'needs_approval'
       -- error
       WHEN 'error'              THEN 'error'
       WHEN 'errored'            THEN 'error'
       WHEN 'failed'             THEN 'error'
       -- recognized non-verdict marker — passes through unchanged
       WHEN 'override_lifecycle' THEN 'override_lifecycle'
       -- fail-safe: an unrecognized value is NEVER 'allowed'
       ELSE 'error'
   END
 WHERE policy_decision NOT IN
       ('allowed', 'blocked', 'redacted', 'needs_approval', 'error', 'override_lifecycle');

-- 2. Fail loudly if anything non-canonical somehow survived (Principle 3: a
--    migration that silently no-ops on partial failure is worse than one that
--    raises — and the ADD CONSTRAINT below would fail anyway, less legibly).
DO $$
DECLARE
    leftover BIGINT;
BEGIN
    SELECT count(*) INTO leftover
      FROM audit_logs
     WHERE policy_decision NOT IN
           ('allowed', 'blocked', 'redacted', 'needs_approval', 'error', 'override_lifecycle');
    IF leftover > 0 THEN
        RAISE EXCEPTION 'Migration 123 failed: % non-canonical policy_decision rows remain in audit_logs', leftover;
    END IF;
    RAISE NOTICE 'Migration 123 verified: all audit_logs.policy_decision rows are canonical-or-marker';
END
$$;

-- 3. Enforce the canonical set at the database. DROP IF EXISTS first so the
--    migration is idempotent (re-add after a previous apply).
ALTER TABLE audit_logs
    DROP CONSTRAINT IF EXISTS audit_logs_policy_decision_check;

ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_policy_decision_check
    CHECK (policy_decision IN
        ('allowed', 'blocked', 'redacted', 'needs_approval', 'error', 'override_lifecycle'));

COMMIT;
