-- Migration 121: audit_logs correlation_id — shared key across the stages of
-- one logical request.
-- Date: 2026-06-10
-- Epic: #2585 (unified audit/decision log) — Phase 1.5 (#2598). See ADR-058.
--
-- WHY ----------------------------------------------------------------------
-- Phase 1 (#2592, migration 119) promoted decision_id to a first-class column,
-- and #2596 repointed the SEBI + EU AI Act decision-chain exports onto the
-- canonical audit_logs decision rows. But every writer mints a FRESH id per
-- decision, so no two rows share a key across the stages (llm → tool → agent)
-- of one logical request — the exports could only order rows chronologically,
-- never reconstruct a logical chain.
--
-- This migration adds correlation_id: a single value shared by every decision
-- row of one logical request (the W3C trace_id a PEP/gateway propagates across
-- its hops). The exporters GROUP BY this key to reconstruct an ordered chain;
-- rows without one (legacy + single-shot callers) group as singletons.
--
-- NO FLAG-DAY --------------------------------------------------------------
-- Additive + nullable. There is NO historical source to backfill from — the
-- trace_id was never persisted on audit_logs before this — so historical rows
-- keep correlation_id = NULL and the exporters treat each as its own singleton
-- chain. New writers dual-write correlation_id into BOTH this column AND the
-- policy_details JSONB (policy_details->>'correlation_id'); the exporters
-- COALESCE the two, mirroring the decision_id read path in #2592.
--
-- RLS POSTURE UNCHANGED ----------------------------------------------------
-- audit_logs is deliberately NOT FORCE-RLS (migration 101 deferred it for the
-- cross-org audit_cleanup worker). There is no WITH CHECK to satisfy, so this
-- ALTER + the partial index run on the migration connection and succeed
-- identically under AXONFLOW_DB_USE_APP_ROLE on AND off. Adding RLS to
-- audit_logs remains Phase 3, out of scope here.

BEGIN;

-- --------------------------------------------------------------------------
-- 1. Additive column (idempotent)
-- --------------------------------------------------------------------------
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(255);

-- --------------------------------------------------------------------------
-- 2. Partial index on the grouping key. Matches the exporter predicate
--    (correlation_id IS NOT NULL) so chain reconstruction gets an index path
--    WITHOUT bloating the index with the many non-decision audit rows (plain
--    request/response logs) and legacy decision rows that carry no
--    correlation_id.
-- --------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_audit_logs_correlation_id
    ON audit_logs (correlation_id)
    WHERE correlation_id IS NOT NULL;

COMMENT ON COLUMN audit_logs.correlation_id IS
    'Shared key across the decision rows of one logical request (the W3C trace_id a PEP propagates across its llm/tool/agent hops); NULL for legacy/single-shot rows. Exporters GROUP BY this to reconstruct an ordered chain. #2598 / ADR-058 Phase 1.5.';

-- --------------------------------------------------------------------------
-- 3. Verification — fail loudly if any artifact is missing (Principle 3).
-- --------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'audit_logs' AND column_name = 'correlation_id') THEN
        RAISE EXCEPTION 'Migration 121 failed: audit_logs.correlation_id not added';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'audit_logs' AND indexname = 'idx_audit_logs_correlation_id') THEN
        RAISE EXCEPTION 'Migration 121 failed: idx_audit_logs_correlation_id not created';
    END IF;
    RAISE NOTICE 'Migration 121 verified: audit_logs.correlation_id + partial index present';
END
$$;

COMMIT;
