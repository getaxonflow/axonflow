-- Rollback migration 027: LLM Provider Registry

-- Drop policies
DROP POLICY IF EXISTS llm_provider_usage_tenant_isolation ON llm_provider_usage;
DROP POLICY IF EXISTS llm_providers_tenant_isolation ON llm_providers;

-- Drop trigger and function
DROP TRIGGER IF EXISTS trg_llm_providers_updated_at ON llm_providers;
DROP FUNCTION IF EXISTS update_llm_providers_updated_at();

-- Drop tables (order matters due to foreign keys)
DROP TABLE IF EXISTS llm_provider_health;
DROP TABLE IF EXISTS llm_provider_usage;
DROP TABLE IF EXISTS llm_providers;
