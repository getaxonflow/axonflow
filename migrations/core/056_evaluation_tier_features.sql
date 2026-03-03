-- Migration 056: Evaluation tier features — evidence export tracking table
-- Tracks evidence exports for rate limiting and audit trail

CREATE TABLE IF NOT EXISTS evidence_exports (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    export_type VARCHAR(50) NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0,
    date_range_start TIMESTAMP,
    date_range_end TIMESTAMP,
    tier VARCHAR(50) NOT NULL,
    disclaimer TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_evidence_exports_tenant ON evidence_exports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_exports_created ON evidence_exports(created_at);
CREATE INDEX IF NOT EXISTS idx_evidence_exports_tenant_date ON evidence_exports(tenant_id, created_at);
