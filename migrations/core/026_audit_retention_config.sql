-- Migration: SEBI Audit Retention Configuration
-- Date: 2025-12-07
-- Purpose: Configurable audit log retention with SEBI 5-year compliance support
--
-- SEBI AI/ML Guidelines (June 2025) - Auditability Pillar:
-- "All AI/ML-related decisions, including input data, model outputs, and actions
--  taken, must be retained for a minimum period of 5 years for regulatory audit."
--
-- This migration creates the audit_retention_config table and supporting
-- infrastructure for configurable, compliance-aware audit log retention.

-- =============================================================================
-- Audit Retention Configuration Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS audit_retention_config (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(255) NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,

    -- Data type being configured (e.g., 'policy_violations', 'llm_calls', 'decision_chain')
    data_type VARCHAR(100) NOT NULL,

    -- Retention period in days (default 1825 = 5 years for SEBI compliance)
    retention_days INTEGER NOT NULL DEFAULT 1825,

    -- Regulatory framework requiring this retention
    -- e.g., 'SEBI_AI_ML', 'EU_AI_ACT', 'DPDP_ACT', 'CUSTOM'
    compliance_framework VARCHAR(50) NOT NULL DEFAULT 'SEBI_AI_ML',

    -- Whether this config is active
    is_active BOOLEAN NOT NULL DEFAULT true,

    -- Archive settings
    -- When true, data is moved to archive table before deletion
    archive_before_delete BOOLEAN NOT NULL DEFAULT true,

    -- Archive storage location (e.g., 's3://bucket/path', 'local_archive', NULL for default)
    archive_location TEXT,

    -- Last time cleanup ran for this config
    last_cleanup_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Ensure unique config per org and data type
    UNIQUE(org_id, data_type)
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_audit_retention_config_org ON audit_retention_config(org_id);
CREATE INDEX IF NOT EXISTS idx_audit_retention_config_active ON audit_retention_config(is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_audit_retention_config_framework ON audit_retention_config(compliance_framework);

-- =============================================================================
-- Audit Retention Defaults (System-wide defaults, applied when org has no config)
-- =============================================================================

CREATE TABLE IF NOT EXISTS audit_retention_defaults (
    id SERIAL PRIMARY KEY,

    -- Data type (same as audit_retention_config.data_type)
    data_type VARCHAR(100) NOT NULL UNIQUE,

    -- Default retention in days
    retention_days INTEGER NOT NULL,

    -- Default compliance framework
    compliance_framework VARCHAR(50) NOT NULL,

    -- Description for documentation
    description TEXT,

    -- When this default was last updated
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Insert SEBI-compliant defaults
INSERT INTO audit_retention_defaults (data_type, retention_days, compliance_framework, description) VALUES
    ('policy_violations', 1825, 'SEBI_AI_ML', 'SEBI AI/ML Guidelines: 5-year retention for policy violation records'),
    ('agent_audit_logs', 1825, 'SEBI_AI_ML', 'SEBI AI/ML Guidelines: 5-year retention for agent audit logs'),
    ('orchestrator_audit_logs', 1825, 'SEBI_AI_ML', 'SEBI AI/ML Guidelines: 5-year retention for orchestrator audit logs'),
    ('llm_call_audits', 1825, 'SEBI_AI_ML', 'SEBI AI/ML Guidelines: 5-year retention for LLM call records'),
    ('gateway_contexts', 1825, 'SEBI_AI_ML', 'SEBI AI/ML Guidelines: 5-year retention for gateway context data'),
    ('decision_chain', 2555, 'EU_AI_ACT', 'EU AI Act Article 12: 7-year retention for decision chain records'),
    ('hitl_oversight', 1825, 'SEBI_AI_ML', 'SEBI AI/ML Guidelines: 5-year retention for human oversight records')
ON CONFLICT (data_type) DO UPDATE SET
    retention_days = EXCLUDED.retention_days,
    compliance_framework = EXCLUDED.compliance_framework,
    description = EXCLUDED.description,
    updated_at = CURRENT_TIMESTAMP;

-- =============================================================================
-- Audit Archive Table (for data moved before deletion)
-- =============================================================================

CREATE TABLE IF NOT EXISTS audit_archive (
    id BIGSERIAL PRIMARY KEY,

    -- Source information
    org_id VARCHAR(255) NOT NULL,
    source_table VARCHAR(100) NOT NULL,
    source_id BIGINT NOT NULL,

    -- Original data as JSONB
    archived_data JSONB NOT NULL,

    -- Original creation timestamp
    original_created_at TIMESTAMPTZ NOT NULL,

    -- Archive metadata
    archived_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    archived_by VARCHAR(100) NOT NULL DEFAULT 'retention_cleanup',
    compliance_framework VARCHAR(50),
    retention_days_at_archive INTEGER
);

-- Indexes for archive queries
CREATE INDEX IF NOT EXISTS idx_audit_archive_org_source ON audit_archive(org_id, source_table);
CREATE INDEX IF NOT EXISTS idx_audit_archive_archived_at ON audit_archive(archived_at);
CREATE INDEX IF NOT EXISTS idx_audit_archive_original_date ON audit_archive(original_created_at);

-- Partitioning hint: Consider partitioning by archived_at for large deployments
COMMENT ON TABLE audit_archive IS 'Archive table for audit records that have exceeded retention period. Consider partitioning by archived_at for high-volume deployments.';

-- =============================================================================
-- Function: Get effective retention days for a data type
-- Returns the org-specific config or falls back to system default
-- =============================================================================

CREATE OR REPLACE FUNCTION get_effective_retention_days(
    p_org_id VARCHAR(255),
    p_data_type VARCHAR(100)
) RETURNS INTEGER AS $$
DECLARE
    v_retention_days INTEGER;
BEGIN
    -- Try org-specific config first
    SELECT retention_days INTO v_retention_days
    FROM audit_retention_config
    WHERE org_id = p_org_id
      AND data_type = p_data_type
      AND is_active = true;

    IF v_retention_days IS NOT NULL THEN
        RETURN v_retention_days;
    END IF;

    -- Fall back to system default
    SELECT retention_days INTO v_retention_days
    FROM audit_retention_defaults
    WHERE data_type = p_data_type;

    IF v_retention_days IS NOT NULL THEN
        RETURN v_retention_days;
    END IF;

    -- Ultimate fallback: 5 years (SEBI default)
    RETURN 1825;
END;
$$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- Function: Archive and cleanup expired audit records
-- =============================================================================

CREATE OR REPLACE FUNCTION cleanup_expired_audit_records(
    p_data_type VARCHAR(100),
    p_batch_size INTEGER DEFAULT 1000
) RETURNS TABLE (
    org_id VARCHAR(255),
    records_archived INTEGER,
    records_deleted INTEGER
) AS $$
DECLARE
    v_org RECORD;
    v_retention_days INTEGER;
    v_cutoff_date TIMESTAMPTZ;
    v_archived_count INTEGER := 0;
    v_deleted_count INTEGER := 0;
    v_archive_enabled BOOLEAN;
BEGIN
    -- Process each organization
    FOR v_org IN
        SELECT DISTINCT o.org_id as org_id,
               COALESCE(arc.archive_before_delete, true) as archive_before_delete,
               COALESCE(arc.retention_days, ard.retention_days, 1825) as retention_days
        FROM organizations o
        LEFT JOIN audit_retention_config arc
            ON arc.org_id = o.org_id
            AND arc.data_type = p_data_type
            AND arc.is_active = true
        LEFT JOIN audit_retention_defaults ard
            ON ard.data_type = p_data_type
    LOOP
        v_retention_days := v_org.retention_days;
        v_cutoff_date := CURRENT_TIMESTAMP - (v_retention_days || ' days')::INTERVAL;
        v_archive_enabled := v_org.archive_before_delete;

        -- Archive records if enabled
        IF v_archive_enabled AND p_data_type = 'policy_violations' THEN
            WITH archived AS (
                INSERT INTO audit_archive (
                    org_id, source_table, source_id, archived_data,
                    original_created_at, compliance_framework, retention_days_at_archive
                )
                SELECT
                    pv.org_id, 'policy_violations', pv.id,
                    jsonb_build_object(
                        'id', pv.id,
                        'org_id', pv.org_id,
                        'violation_type', pv.violation_type,
                        'severity', pv.severity,
                        'client_id', pv.client_id,
                        'user_id', pv.user_id,
                        'description', pv.description,
                        'details', pv.details,
                        'created_at', pv.created_at
                    ),
                    pv.created_at,
                    COALESCE(arc.compliance_framework, 'SEBI_AI_ML'),
                    v_retention_days
                FROM policy_violations pv
                LEFT JOIN audit_retention_config arc
                    ON arc.org_id = pv.org_id
                    AND arc.data_type = 'policy_violations'
                WHERE pv.org_id = v_org.org_id
                  AND pv.created_at < v_cutoff_date
                LIMIT p_batch_size
                RETURNING 1
            )
            SELECT COUNT(*) INTO v_archived_count FROM archived;
        END IF;

        -- Delete expired records
        IF p_data_type = 'policy_violations' THEN
            WITH deleted AS (
                DELETE FROM policy_violations
                WHERE org_id = v_org.org_id
                  AND created_at < v_cutoff_date
                  AND id IN (
                      SELECT id FROM policy_violations
                      WHERE org_id = v_org.org_id
                        AND created_at < v_cutoff_date
                      LIMIT p_batch_size
                  )
                RETURNING 1
            )
            SELECT COUNT(*) INTO v_deleted_count FROM deleted;
        END IF;

        -- Update last cleanup timestamp
        UPDATE audit_retention_config
        SET last_cleanup_at = CURRENT_TIMESTAMP
        WHERE org_id = v_org.org_id
          AND data_type = p_data_type;

        -- Return results for this org
        org_id := v_org.org_id;
        records_archived := v_archived_count;
        records_deleted := v_deleted_count;
        RETURN NEXT;

        -- Reset counters
        v_archived_count := 0;
        v_deleted_count := 0;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- View: Audit Retention Summary
-- Shows current retention configuration and compliance status per org
-- =============================================================================

CREATE OR REPLACE VIEW audit_retention_summary AS
SELECT
    o.org_id as org_id,
    o.name as org_name,
    dt.data_type,
    COALESCE(arc.retention_days, ard.retention_days, 1825) as retention_days,
    ROUND(COALESCE(arc.retention_days, ard.retention_days, 1825)::DECIMAL / 365, 1) as retention_years,
    COALESCE(arc.compliance_framework, ard.compliance_framework, 'SEBI_AI_ML') as compliance_framework,
    COALESCE(arc.is_active, true) as is_active,
    COALESCE(arc.archive_before_delete, true) as archive_before_delete,
    arc.last_cleanup_at,
    CASE
        WHEN COALESCE(arc.retention_days, ard.retention_days, 1825) >= 1825 THEN 'SEBI_COMPLIANT'
        WHEN COALESCE(arc.retention_days, ard.retention_days, 1825) >= 2555 THEN 'EU_AI_ACT_COMPLIANT'
        ELSE 'REVIEW_REQUIRED'
    END as compliance_status
FROM organizations o
CROSS JOIN (
    SELECT DISTINCT data_type FROM audit_retention_defaults
) dt
LEFT JOIN audit_retention_config arc
    ON arc.org_id = o.org_id AND arc.data_type = dt.data_type
LEFT JOIN audit_retention_defaults ard
    ON ard.data_type = dt.data_type;

-- =============================================================================
-- RLS Policies for audit_retention_config
-- =============================================================================

ALTER TABLE audit_retention_config ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their organization's config
CREATE POLICY audit_retention_config_org_isolation ON audit_retention_config
    FOR ALL
    USING (org_id = current_setting('app.current_org_id', true)::VARCHAR);

-- Policy: System admin can see all configs
CREATE POLICY audit_retention_config_admin_access ON audit_retention_config
    FOR SELECT
    USING (current_setting('app.is_admin', true)::BOOLEAN = true);

-- =============================================================================
-- Grant Permissions (only if role exists - enterprise deployments)
-- =============================================================================

DO $$
BEGIN
    -- Only grant permissions if the axonflow_app role exists (enterprise deployments)
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON audit_retention_config TO axonflow_app';
        EXECUTE 'GRANT SELECT ON audit_retention_defaults TO axonflow_app';
        EXECUTE 'GRANT SELECT, INSERT ON audit_archive TO axonflow_app';
        EXECUTE 'GRANT SELECT ON audit_retention_summary TO axonflow_app';
        EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE audit_retention_config_id_seq TO axonflow_app';
        EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE audit_retention_defaults_id_seq TO axonflow_app';
        EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE audit_archive_id_seq TO axonflow_app';
        RAISE NOTICE 'Permissions granted to axonflow_app role';
    ELSE
        RAISE NOTICE 'Skipping permission grants - axonflow_app role does not exist (OSS deployment)';
    END IF;
END $$;

-- =============================================================================
-- Success Message
-- =============================================================================

DO $$
BEGIN
    RAISE NOTICE 'SEBI Audit Retention Configuration Migration Complete';
    RAISE NOTICE '- audit_retention_config table created';
    RAISE NOTICE '- audit_retention_defaults populated with SEBI 5-year defaults';
    RAISE NOTICE '- audit_archive table created for pre-deletion archival';
    RAISE NOTICE '- get_effective_retention_days() function created';
    RAISE NOTICE '- cleanup_expired_audit_records() function created';
    RAISE NOTICE '- audit_retention_summary view created';
END $$;
