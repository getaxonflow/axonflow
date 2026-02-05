-- Migration 008: Expand llm_provider_configs provider name constraint
-- Date: 2026-02-04

DO $migration$
DECLARE
    table_exists BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'llm_provider_configs'
    ) INTO table_exists;

    IF NOT table_exists THEN
        RAISE NOTICE 'Migration 008: llm_provider_configs table does not exist. Skipping.';
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_schema = 'public'
          AND table_name = 'llm_provider_configs'
          AND constraint_name = 'check_provider_name'
    ) THEN
        ALTER TABLE llm_provider_configs DROP CONSTRAINT check_provider_name;
    END IF;

    ALTER TABLE llm_provider_configs
        ADD CONSTRAINT check_provider_name CHECK (provider_name IN (
            'bedrock', 'ollama', 'openai', 'anthropic', 'gemini', 'azure-openai', 'custom'
        ));

    RAISE NOTICE 'Migration 008: Updated llm_provider_configs.check_provider_name constraint';
END $migration$;
