-- This must be the only statement in this migration. The agent executes one
-- migration file per db.Exec; a concurrent build cannot run in a transaction
-- block, and keeping it out of core/192 releases ALTER TABLE's lock first.
-- Deliberately no IF NOT EXISTS: a failed concurrent build can leave an
-- INVALID index of this name. The next boot must fail closed until an operator
-- drops that invalid index concurrently and retries the migration.
CREATE UNIQUE INDEX CONCURRENTLY ux_usage_events_capability_key
    ON usage_events (org_id, capability_tenant_id, capability_event_key)
    WHERE capability_event_key IS NOT NULL;
