-- Migration 046 Down: Revert llm_provider_configs provider name constraint

ALTER TABLE llm_provider_configs
    DROP CONSTRAINT IF EXISTS check_provider_name;

-- Remove provider rows that are not valid under the legacy constraint.
DELETE FROM llm_provider_configs
WHERE provider_name IN ('gemini', 'azure-openai', 'custom');

ALTER TABLE llm_provider_configs
    ADD CONSTRAINT check_provider_name CHECK (provider_name IN (
        'bedrock', 'ollama', 'openai', 'anthropic'
    ));
