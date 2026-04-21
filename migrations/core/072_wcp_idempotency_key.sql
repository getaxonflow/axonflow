-- Copyright 2026 AxonFlow
-- SPDX-License-Identifier: BUSL-1.1
--
-- Migration 072: WCP caller-supplied idempotency_key (Issue #1673 Phase 2)
--
-- Adds an optional caller-supplied idempotency_key on workflow_steps so the
-- caller can anchor a gate/complete pair to a business-level key (e.g.
-- "payment:wire:acct4471:invoice-7721"). The key is validated for match
-- between /gate and /complete; mismatch returns HTTP 409
-- IDEMPOTENCY_KEY_MISMATCH.
--
-- Phase 2 is purely same-workflow: the key is recorded and policy-reachable
-- via step.idempotency_key. Cross-workflow lookup (Phase 3, issue #1672)
-- builds on this column but is explicitly out of scope here.
--
-- Additive; column is nullable since existing rows and callers that don't
-- supply a key continue to work unchanged.

BEGIN;

ALTER TABLE workflow_steps
    ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR(255);

-- Index for audit queries filtering by idempotency_key. Partial (non-null
-- only) since most legacy rows won't have a key; keeps the index lean.
-- Phase 3 will likely add a composite (tenant_id, tool_name, idempotency_key)
-- index for cross-workflow lookup; that's a separate migration.
CREATE INDEX IF NOT EXISTS idx_workflow_steps_idempotency_key
    ON workflow_steps(idempotency_key)
    WHERE idempotency_key IS NOT NULL;

COMMENT ON COLUMN workflow_steps.idempotency_key IS
    'Caller-supplied opaque business-level key (Issue #1673 Phase 2). Recorded on the first /gate call that sets it; subsequent /gate and /complete calls must pass the same key or receive 409 IDEMPOTENCY_KEY_MISMATCH. Max 255 chars. Null when the caller did not supply one.';

DO $$
BEGIN
    RAISE NOTICE 'Migration 072: Added idempotency_key to workflow_steps for Issue #1673 Phase 2';
END $$;

COMMIT;
