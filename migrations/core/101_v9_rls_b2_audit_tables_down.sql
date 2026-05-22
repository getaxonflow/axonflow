-- Migration 101 DOWN: reverse FORCE RLS on customer-facing audit tables
-- Context: reverses 101_v9_rls_b2_audit_tables.sql
--
-- After this runs, the three audit tables behave the same as they did pre-101:
-- RLS is enabled and policies exist, but the table owner / RDS master bypasses
-- them (because FORCE is off).
--
-- For mcp_query_audits (which had RLS first-enabled in 101), this DOWN also
-- disables RLS and drops the policy — restoring exact pre-101 byte-equal state
-- for that table. audit_retention_config + decision_chain had RLS already
-- enabled in 026/025; we leave their RLS state intact.

BEGIN;

-- Drop FORCE first (NO FORCE) — order matters to be symmetric with the up.
ALTER TABLE mcp_query_audits       NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_retention_config NO FORCE ROW LEVEL SECURITY;
ALTER TABLE decision_chain         NO FORCE ROW LEVEL SECURITY;

-- mcp_query_audits was first-enabled in 101 — reverse that. We do NOT reverse
-- the ENABLE on audit_retention_config + decision_chain because they were
-- already enabled before 101 (by 026/025).
ALTER TABLE mcp_query_audits DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mcp_query_audits_org_isolation ON mcp_query_audits;

-- We deliberately do NOT drop the audit_retention_config_org_isolation /
-- decision_chain_org_isolation policies: those were created by 026/025; the
-- 101 migration's DO blocks only re-asserted them defensively. Dropping here
-- would leave the original migrations' state inconsistent.

COMMIT;
