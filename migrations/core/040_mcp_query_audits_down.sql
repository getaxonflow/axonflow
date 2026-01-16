-- Down Migration 040: MCP Query Audits Table
-- Rollback for migration 040_mcp_query_audits.sql

DROP VIEW IF EXISTS mcp_query_audit_summary;
DROP TABLE IF EXISTS mcp_query_audits;
