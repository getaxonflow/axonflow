-- Rollback migration 069: drop workflow checkpoints table and indexes
DROP TABLE IF EXISTS workflow_checkpoints;
