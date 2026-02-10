-- Migration 045 Down: Revert connector_configs credentials column and connector types
--
-- NOTE: Migration 021 already creates the credentials column and the full connector
-- type constraint. This down migration only needs to undo what 045 actually added
-- (which is nothing if 021 ran first). We intentionally do NOT narrow the constraint
-- or drop the credentials column, since 021 created them.

-- No-op: 045's changes are redundant with 021. Reverting would break the schema
-- by removing types and columns that 021 already provides.
