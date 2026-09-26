-- Migration 186 (down): drop the (org_id, policy_id, date) unique index.
-- Rows 186 collapsed stay collapsed: their counts were summed into the row kept,
-- and splitting them again would invent a distribution nobody recorded. With
-- the index gone the agent's metrics UPSERT fails with 42P10 again, as it did
-- before 186. A legacy unique constraint or index on (policy_id, date) that 186
-- dropped is not restored: it would refuse a second organization's row.

DROP INDEX IF EXISTS idx_policy_metrics_org_policy_date;
