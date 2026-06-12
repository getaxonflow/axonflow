-- Migration 122 DOWN: intentionally a NO-OP (#2643 / #2638).
--
-- The up migration normalizes legacy 'allow' / 'deny' / 'denied' tokens in
-- audit_logs.policy_decision to the canonical 'allowed' / 'blocked'. That
-- transformation is NOT safely reversible: rows that were ALWAYS canonical
-- ('allowed' / 'blocked' written by the orchestrator and MCP planes) are
-- indistinguishable after the fact from rows the up migration converted, so
-- blindly rewriting 'allowed' -> 'allow' would CORRUPT legitimately-canonical
-- history. We therefore deliberately do nothing on the down path rather than
-- risk data loss.
--
-- The canonical vocabulary is the intended steady state for
-- audit_logs.policy_decision; rolling back the schema/code does not require
-- de-normalizing the data (the reader paths already understand the canonical
-- set). This file exists so the migration has a paired down file; it makes no
-- changes.

BEGIN;

-- No-op: see header for why this is intentionally empty.
DO $$
BEGIN
    RAISE NOTICE 'Migration 122 DOWN is an intentional no-op (vocab normalization is forward-only; see file header)';
END
$$;

COMMIT;
