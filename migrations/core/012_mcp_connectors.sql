-- Migration 012: MCP Connectors
-- Date: 2025-11-20
-- Purpose: Add MCP connector registry table
-- Source: platform/connectors/registry/postgres_storage.go (initSchema)
-- Related: Issue #19 - AWS Marketplace schema consistency

-- =============================================================================
-- Connectors Table (MCP Connector Registry)
-- =============================================================================
-- Stores installed MCP connector configurations and health status
-- Used by agent/orchestrator for external data source connectivity
CREATE TABLE IF NOT EXISTS connectors (
    id VARCHAR(255) PRIMARY KEY,
    org_id VARCHAR(255), -- Multi-tenant isolation column for RLS
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'postgres', 'cassandra', 'amadeus', 'custom'
    tenant_id VARCHAR(255) NOT NULL,
    options JSONB NOT NULL DEFAULT '{}'::jsonb, -- Connector-specific options
    credentials JSONB NOT NULL DEFAULT '{}'::jsonb, -- Encrypted credentials
    installed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_health_check TIMESTAMP,
    health_status JSONB, -- {status: 'healthy'|'degraded'|'unhealthy', message: '...'}
    UNIQUE(name, tenant_id)
);

-- Connectors indexes
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_connectors_type ON connectors(type);
CREATE INDEX IF NOT EXISTS idx_connectors_health ON connectors(last_health_check DESC) WHERE health_status IS NOT NULL;

-- Migration complete
-- Ready for testing
