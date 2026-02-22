-- Rollback migration 009: Revert Bedrock default model ID
UPDATE llm_provider_configs
SET config = jsonb_set(config, '{model}', '"anthropic.claude-3-5-sonnet-20240620-v1:0"')
WHERE provider_name = 'bedrock'
  AND config->>'model' = 'anthropic.claude-sonnet-4-20250514-v1:0';
