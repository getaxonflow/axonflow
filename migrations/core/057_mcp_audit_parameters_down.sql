-- Rollback migration 057: Remove parameters_hash and parameter_count from MCP audit entries

ALTER TABLE mcp_query_audits DROP COLUMN IF EXISTS parameters_hash;
ALTER TABLE mcp_query_audits DROP COLUMN IF EXISTS parameter_count;
