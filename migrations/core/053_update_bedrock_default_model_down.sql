-- Migration 053 Down: Revert Bedrock default model back to Claude 3.5 Sonnet

DO $migration$
DECLARE
    table_exists BOOLEAN;
    rows_updated INTEGER;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = 'llm_provider_configs'
    ) INTO table_exists;

    IF NOT table_exists THEN
        RAISE NOTICE 'Migration 053 down: llm_provider_configs table not found. Skipping.';
        RETURN;
    END IF;

    UPDATE llm_provider_configs
    SET config = jsonb_set(config, '{model}', '"anthropic.claude-3-5-sonnet-20240620-v1:0"')
    WHERE provider_name = 'bedrock'
      AND config->>'model' = 'anthropic.claude-sonnet-4-20250514-v1:0';

    GET DIAGNOSTICS rows_updated = ROW_COUNT;
    RAISE NOTICE 'Migration 053 down: updated % Bedrock config rows', rows_updated;
END $migration$;
