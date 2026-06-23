-- Copyright 2026 AxonFlow
-- Licensed under the Apache License, Version 2.0

-- =============================================================================
-- Audit non-repudiation: per-record signature + hash chain on decision_chain
-- =============================================================================
--
-- Issue: #2722 (child of epic #2716).
--
-- Before this migration the decision_chain audit trail was tamper-EVIDENT but
-- not tamper-PROOF in the live DB: each row carried a per-entry sha256
-- `audit_hash` over its OWN fields, but there was no linkage between rows and
-- no per-record cryptographic signature. A DB-level adversary could edit a row
-- and recompute its audit_hash, and insertion / deletion / reordering of rows
-- was undetectable from the chain itself.
--
-- This migration adds the columns needed to:
--   * `prev_hash`         link each record to the previous record in its chain
--                         (genesis sentinel for the first record). Detects
--                         insertion / deletion / reordering.
--   * `record_signature`  Ed25519 signature (base64) over the record's
--                         chain-hash, proving authorship. Empty when no audit
--                         signing key is configured.
--   * `signing_key_id`    identifier of the key that produced record_signature,
--                         so verification (and key rotation) can resolve the
--                         correct public key. Empty when unsigned.
--   * `chain_seq`         monotonic per-chain sequence assigned race-free under
--                         an advisory lock at append time. This is the
--                         authoritative ordering used both to pick the
--                         "previous" record at append and to replay the chain
--                         deterministically during verification, independent of
--                         created_at (which can collide / invert under
--                         concurrency) and of step_number (caller-assigned).
--
-- decision_chain lives in core/ (migration 025) and is written by core code
-- (platform/agent/decision_chain.go), so these columns MUST live in core/.
-- Core migrations run in EVERY deployment mode (community, community-saas,
-- saas, in-vpc-*). An enterprise/-only migration would leave community installs
-- without the columns the core writer references, breaking every INSERT.
--
-- All four columns are nullable so the migration is a pure additive ALTER:
-- existing rows keep working, and the writer back-fills them on new records.
-- Row Level Security on decision_chain (mig 025 ENABLE, mig 101 FORCE, mig 102
-- normalized policy) is untouched, ADD COLUMN does not alter RLS state.
-- =============================================================================

ALTER TABLE decision_chain
    ADD COLUMN IF NOT EXISTS prev_hash        TEXT,
    ADD COLUMN IF NOT EXISTS record_signature TEXT,
    ADD COLUMN IF NOT EXISTS signing_key_id   TEXT,
    ADD COLUMN IF NOT EXISTS chain_seq        BIGINT;

-- Composite index on (chain_id, chain_seq): used to fetch the tail of a chain
-- (MAX(chain_seq)) at append time and to replay the chain in order during
-- verification. DESC on chain_seq so the tail lookup is a single index step.
CREATE INDEX IF NOT EXISTS idx_decision_chain_chain_seq
    ON decision_chain(chain_id, chain_seq DESC);

COMMENT ON COLUMN decision_chain.prev_hash IS
'Chain-hash of the previous record in this chain (sha256 over the previous '
'record digest concatenated with its own prev_hash). The first record in a '
'chain stores the genesis sentinel (64 zero hex chars). Lets verification '
'detect insertion, deletion, and reordering of records.';

COMMENT ON COLUMN decision_chain.record_signature IS
'Ed25519 signature (base64 std-encoded) over the ASCII hex of this record''s '
'chain-hash, produced by the audit signing key. Proves the record was authored '
'by the holder of that key and has not been altered. Empty when no audit '
'signing key was configured at record time.';

COMMENT ON COLUMN decision_chain.signing_key_id IS
'Identifier (hex of sha256(public key), first 16 chars) of the key that '
'produced record_signature. Lets a verifier resolve the correct public key, '
'including across key rotation. Empty when the record is unsigned.';

COMMENT ON COLUMN decision_chain.chain_seq IS
'Monotonic per-chain sequence (starts at 1) assigned race-free under a '
'transaction-scoped advisory lock at append time. Authoritative ordering for '
'both selecting the previous record and replaying the chain during '
'verification; independent of created_at and the caller-assigned step_number.';
