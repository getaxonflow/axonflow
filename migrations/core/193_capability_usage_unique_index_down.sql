-- A concurrent drop must also be the only statement in its file.
DROP INDEX CONCURRENTLY IF EXISTS ux_usage_events_capability_key;
