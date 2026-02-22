-- Migration 009: Update default Bedrock model ID
--
-- Updates the COALESCE default for the Bedrock model in llm_provider_configs
-- from the deprecated Claude 3.5 Sonnet to Claude Sonnet 4.
--
-- Old default: anthropic.claude-3-5-sonnet-20240620-v1:0
-- New default: anthropic.claude-sonnet-4-20250514-v1:0
--
-- This only affects new deployments that haven't explicitly set a Bedrock model.
-- Existing rows with an explicit model value are NOT modified.

-- Update any llm_provider_configs rows that still reference the old default model
-- in their config->model field, but ONLY for bedrock providers where the value
-- was exactly the old default (indicating it was auto-populated by migration 007).
UPDATE llm_provider_configs
SET config = jsonb_set(config, '{model}', '"anthropic.claude-sonnet-4-20250514-v1:0"')
WHERE provider_name = 'bedrock'
  AND config->>'model' = 'anthropic.claude-3-5-sonnet-20240620-v1:0';
