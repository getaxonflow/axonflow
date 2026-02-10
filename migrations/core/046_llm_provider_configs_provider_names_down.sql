-- Migration 046 Down: Revert llm_provider_configs provider name constraint
--
-- NOTE: Migration 021 already creates the full provider name constraint including
-- gemini, azure-openai, and custom. This down migration only needs to undo what 046
-- actually added (which is nothing if 021 ran first). We intentionally do NOT narrow
-- the constraint or delete provider rows, since 021 created the full constraint.

-- No-op: 046's changes are redundant with 021. Reverting would break the schema
-- by removing provider types that 021 already provides.
