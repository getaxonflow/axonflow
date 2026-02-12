-- Down migration 050: Remove plan_id index
-- Note: Cannot remove enum values in PostgreSQL, so 'expired' status remains
-- Using non-concurrent DROP to work inside transactional migration runners
DROP INDEX IF EXISTS idx_execution_history_plan_id;
