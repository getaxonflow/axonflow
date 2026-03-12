-- Migration 057: Add parameters_hash and parameter_count to MCP audit entries
-- Issue #1287: check-input parameters must be visible to the audit pipeline

ALTER TABLE mcp_query_audits ADD COLUMN IF NOT EXISTS parameters_hash VARCHAR(64);
ALTER TABLE mcp_query_audits ADD COLUMN IF NOT EXISTS parameter_count INT DEFAULT 0;
