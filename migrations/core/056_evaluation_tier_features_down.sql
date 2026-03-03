-- Migration 056 DOWN: Remove evaluation tier features table

DROP INDEX IF EXISTS idx_evidence_exports_tenant_date;
DROP INDEX IF EXISTS idx_evidence_exports_created;
DROP INDEX IF EXISTS idx_evidence_exports_tenant;
DROP TABLE IF EXISTS evidence_exports;
