-- Migration 126: Cross-Border Transfer Fields on canonical audit_logs
-- Date: 2026-06-23
-- Purpose: Add transfer_basis and data_residency columns to the canonical
--          decision row (audit_logs) so the platform can AUTO-STAMP the
--          UU PDP Pasal 56 cross-border transfer basis at LLM-forward time,
--          and the OJK cross-border export can round-trip it from the same
--          decision_id/correlation_id row the audit-coverage epic standardized on.
--
-- Why audit_logs (not orchestrator_audit_logs): migration 129 added these
-- columns to the legacy agent_audit_logs / orchestrator_audit_logs tables, but
-- the canonical per-request decision row is written to audit_logs
-- (platform/orchestrator/audit_logger.go). The OJK cross-border export is
-- repointed to read this table; the mig-129 columns are left in place but
-- unused (separate cleanup follow-up).
--
-- Both columns are NULLABLE with no default: a deployment that does not declare
-- a transfer basis writes NULL (no cross-border assertion), so existing
-- behavior is byte-identical and the Phase-1 PoC (no declared basis) is safe.
--
-- Accepted transfer_basis values (validated in application code against
-- ojk.TransferBasisCanonicalForms): adequacy, safeguards, pasal_56b_dpa, consent.

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS transfer_basis VARCHAR(20),
    ADD COLUMN IF NOT EXISTS data_residency VARCHAR(2);

-- Partial index backing the cross-border export's `transfer_basis IS NOT NULL`
-- filter: only the (small) subset of decision rows that carry a declared basis
-- is indexed, so non-cross-border rows add no index weight.
CREATE INDEX IF NOT EXISTS idx_audit_logs_transfer_basis
    ON audit_logs(transfer_basis) WHERE transfer_basis IS NOT NULL;

COMMENT ON COLUMN audit_logs.transfer_basis IS 'UU PDP Pasal 56 basis (adequacy, safeguards, pasal_56b_dpa, consent); auto-stamped on the LLM-forward cross-border path';
COMMENT ON COLUMN audit_logs.data_residency IS 'ISO 3166-1 alpha-2 country code of the resolved LLM destination at forward time';
