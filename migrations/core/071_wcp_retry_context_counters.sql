-- Copyright 2026 AxonFlow
-- SPDX-License-Identifier: BUSL-1.1
--
-- Migration 071: WCP retry_context counters (Issue #1673 Phase 1)
--
-- Adds gate_count, completion_count, and last_decision columns to
-- workflow_steps so StepGateResponse can return a first-class retry_context
-- block on every gate response. Replaces the ambiguous `cached: bool` flag
-- with unambiguous execution state (how many times /gate has been called,
-- whether a prior /complete has landed, what the prior decision was).
--
-- See technical-docs/WCP_RETRY_IDEMPOTENCY_WIRE_CONTRACT.md for the full
-- response shape SDK work is built against.
--
-- Additive; all new columns have defaults. Existing rows are backfilled so
-- retry_context.gate_count >= 1 on any legacy row (a row exists ⇒ a gate
-- happened at least once) and completion_count reflects step_completed_at.

BEGIN;

ALTER TABLE workflow_steps
    ADD COLUMN IF NOT EXISTS gate_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS completion_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_decision VARCHAR(50),
    ADD COLUMN IF NOT EXISTS first_attempt_at TIMESTAMP WITH TIME ZONE;

-- Backfill legacy rows. A row in workflow_steps implies at least one gate
-- call happened (rows are created by AddStep which is called from StepGate).
-- If step_completed_at is set, /complete was called exactly once (pre-#1673
-- semantics didn't allow re-complete). last_decision equals the current
-- decision for legacy rows: we have no history of prior gate calls, and the
-- contract says last_decision on first-call == current decision.
-- first_attempt_at backfills to gate_checked_at since that was both the
-- first and only gate event for legacy rows.
UPDATE workflow_steps
SET gate_count = 1,
    completion_count = CASE WHEN step_completed_at IS NOT NULL THEN 1 ELSE 0 END,
    last_decision = decision,
    first_attempt_at = gate_checked_at
WHERE gate_count = 0;

COMMENT ON COLUMN workflow_steps.gate_count IS
    'Number of /gate calls for this (workflow_id, step_id). Incremented on every gate call. Surfaced in StepGateResponse.retry_context.gate_count (Issue #1673).';
COMMENT ON COLUMN workflow_steps.completion_count IS
    'Number of /complete calls. Normally 0 or 1. Surfaced in StepGateResponse.retry_context.completion_count (Issue #1673).';
COMMENT ON COLUMN workflow_steps.last_decision IS
    'Decision of the prior gate call. On the first call, equals the current decision. Surfaced in StepGateResponse.retry_context.last_decision (Issue #1673).';
COMMENT ON COLUMN workflow_steps.first_attempt_at IS
    'Timestamp of the first /gate call for this step. gate_checked_at is overwritten on each gate call (= last_attempt_at); this column preserves the original. Surfaced in StepGateResponse.retry_context.first_attempt_at (Issue #1673).';

DO $$
BEGIN
    RAISE NOTICE 'Migration 071: Added gate_count, completion_count, last_decision, first_attempt_at to workflow_steps for Issue #1673 Phase 1';
END $$;

COMMIT;
