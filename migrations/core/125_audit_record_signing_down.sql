-- Copyright 2026 AxonFlow
-- Licensed under the Apache License, Version 2.0

-- =============================================================================
-- Down migration for 125_audit_record_signing.sql (#2722)
-- =============================================================================
-- Drops the audit non-repudiation columns and their index. Purely additive
-- columns, so this is a clean reversal. RLS on decision_chain is unaffected.
-- =============================================================================

DROP INDEX IF EXISTS idx_decision_chain_chain_seq;

ALTER TABLE decision_chain
    DROP COLUMN IF EXISTS chain_seq,
    DROP COLUMN IF EXISTS signing_key_id,
    DROP COLUMN IF EXISTS record_signature,
    DROP COLUMN IF EXISTS prev_hash;
