-- Migration 007 Rollback: Runtime Connector and LLM Provider Configuration
-- Date: 2025-11-28
-- WARNING: This will remove all runtime configuration data!

-- Drop helper functions first (they depend on tables)
DROP FUNCTION IF EXISTS log_config_change(VARCHAR, VARCHAR, UUID, VARCHAR, VARCHAR, JSONB, JSONB, VARCHAR, VARCHAR, VARCHAR, INET);
DROP FUNCTION IF EXISTS get_llm_providers(VARCHAR);
DROP FUNCTION IF EXISTS get_connector_config(VARCHAR, VARCHAR);

-- Drop triggers
DROP TRIGGER IF EXISTS connector_dangerous_ops_updated_at ON connector_dangerous_operations;
DROP TRIGGER IF EXISTS llm_provider_configs_updated_at ON llm_provider_configs;
DROP TRIGGER IF EXISTS connector_configs_updated_at ON connector_configs;

-- Drop tables (in reverse dependency order)
DROP TABLE IF EXISTS config_audit_log;
DROP TABLE IF EXISTS connector_dangerous_operations;
DROP TABLE IF EXISTS llm_provider_configs;
DROP TABLE IF EXISTS connector_configs;

-- Note: We don't drop update_updated_at_column() as it may be used by other tables
