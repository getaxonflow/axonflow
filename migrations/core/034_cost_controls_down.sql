-- Rollback Cost Controls migration

-- Drop triggers first
DROP TRIGGER IF EXISTS trigger_budget_updated_at ON budgets;

-- Drop functions
DROP FUNCTION IF EXISTS update_budget_updated_at();

-- Drop tables (in order due to foreign keys)
DROP TABLE IF EXISTS budget_alerts;
DROP TABLE IF EXISTS usage_aggregates;
DROP TABLE IF EXISTS usage_records;
DROP TABLE IF EXISTS budgets;
