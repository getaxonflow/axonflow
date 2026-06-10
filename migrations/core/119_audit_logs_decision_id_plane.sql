-- Migration 119: audit_logs decision_id first-class column + plane discriminator
-- Date: 2026-06-09
-- Epic: #2585 (unified audit/decision log) — Phase 1 (#2592). See ADR-058.
--
-- WHY ----------------------------------------------------------------------
-- Phase 0 (#2586) made every MCP block path write the canonical audit_logs
-- decision row, matched by policy_details->>'decision_id' (a JSONB lookup).
-- Phase 1 promotes decision_id to a first-class INDEXED column — the stable
-- join key every satellite (Phase 2: mcp_query_audits / llm_call_audits /
-- policy_violations / gateway_contexts) will reference — and adds:
--   * plane  : which gateway/surface emitted the decision
--              (llm | mcp | agent | gateway | decision | openai_compat),
--              per ADR-058 §Decision-1, so a single query can return every
--              block across every plane.
--   * obligations JSONB : the structured ADR-056 / #2563 obligation contract
--              (e.g. redact_pii) instead of flattening obligations into the
--              free-text policy_details->>'reason' string.
--
-- NO FLAG-DAY --------------------------------------------------------------
-- Additive + backfilled. Writers DUAL-WRITE decision_id into BOTH the new
-- column AND the existing policy_details JSONB; the decisions reader COALESCEs
-- the column with the JSONB so JSONB-only rows (historical + any not-yet-
-- migrated writer + the explain/evidence readers that still read JSONB) keep
-- surfacing until the JSONB copy is retired in a later phase.
--
-- RLS POSTURE UNCHANGED ----------------------------------------------------
-- audit_logs is deliberately NOT FORCE-RLS (migration 101 deferred it for the
-- cross-org audit_cleanup worker, which DELETEs across tenants under the
-- master role). There is no WITH CHECK to satisfy, so these ALTERs + the
-- backfill UPDATE run on the migration connection and succeed identically
-- under AXONFLOW_DB_USE_APP_ROLE on AND off. This migration intentionally does
-- NOT add RLS to audit_logs — that is Phase 3 (SECURITY DEFINER cleanup
-- wrapper), out of scope here.

BEGIN;

-- --------------------------------------------------------------------------
-- 1. Additive columns (idempotent)
-- --------------------------------------------------------------------------
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS decision_id VARCHAR(255);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS plane VARCHAR(32);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS obligations JSONB;

-- --------------------------------------------------------------------------
-- 2. Backfill the column from the JSONB copy for every historical decision
--    row. ->>'decision_id' returns NULL when the key is absent OR is a JSON
--    null, so IS NOT NULL covers both. Idempotent: only touches rows whose
--    column is still NULL. Cross-org by design (audit_logs has no RLS) — the
--    same posture the cleanup worker relies on; safe to re-run.
-- --------------------------------------------------------------------------
UPDATE audit_logs
   SET decision_id = policy_details->>'decision_id'
 WHERE decision_id IS NULL
   AND policy_details->>'decision_id' IS NOT NULL;

-- --------------------------------------------------------------------------
-- 3. Partial index on the join key. Matches the reader predicate
--    (decision_id IS NOT NULL) so the decisions feed + Phase-2 satellite joins
--    get an index path WITHOUT bloating the index with the many non-decision
--    audit rows (plain request/response logs) that carry no decision_id.
-- --------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_audit_logs_decision_id
    ON audit_logs (decision_id)
    WHERE decision_id IS NOT NULL;

COMMENT ON COLUMN audit_logs.decision_id IS
    'First-class decision id (promoted from policy_details JSONB; #2592 / ADR-058 Phase 1). Stable satellite join key.';
COMMENT ON COLUMN audit_logs.plane IS
    'Gateway/surface that emitted the decision: llm|mcp|agent|gateway|decision|openai_compat (ADR-058 Decision-1).';
COMMENT ON COLUMN audit_logs.obligations IS
    'Structured ADR-056/#2563 obligation contract (e.g. redact_pii) instead of free-text policy_details->>reason.';

-- --------------------------------------------------------------------------
-- 4. Verification — fail loudly if any artifact is missing (Principle 3).
-- --------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'audit_logs' AND column_name = 'decision_id') THEN
        RAISE EXCEPTION 'Migration 119 failed: audit_logs.decision_id not added';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'audit_logs' AND column_name = 'plane') THEN
        RAISE EXCEPTION 'Migration 119 failed: audit_logs.plane not added';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'audit_logs' AND column_name = 'obligations') THEN
        RAISE EXCEPTION 'Migration 119 failed: audit_logs.obligations not added';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'audit_logs' AND indexname = 'idx_audit_logs_decision_id') THEN
        RAISE EXCEPTION 'Migration 119 failed: idx_audit_logs_decision_id not created';
    END IF;
    RAISE NOTICE 'Migration 119 verified: audit_logs.decision_id + plane + obligations + partial index present';
END
$$;

COMMIT;
