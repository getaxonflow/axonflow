-- Down migration for 096_schema_migrations_dedup_composite
-- Date: 2026-05-19
--
-- Reverts to the bug shape: UNIQUE(version) only. Useful only if the Go
-- code is also reverted; otherwise the runner's composite-key logic will
-- silently double-record rows.
--
-- WARNING: if any (version, name) collisions were ever recorded as
-- distinct rows after migration 096, this down-migration will fail at
-- the ALTER TABLE ADD UNIQUE step due to duplicate version values.
-- That's the correct safety behavior — fix the duplicates by hand
-- before reverting.

DO $$
BEGIN
    -- Drop the composite UNIQUE if present.
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'schema_migrations_version_name_uniq'
    ) THEN
        ALTER TABLE schema_migrations
            DROP CONSTRAINT schema_migrations_version_name_uniq;
        RAISE NOTICE 'Dropped composite UNIQUE constraint';
    END IF;

    -- Restore the version-only UNIQUE. Will fail if duplicates exist.
    ALTER TABLE schema_migrations
        ADD CONSTRAINT schema_migrations_version_key UNIQUE (version);
    RAISE NOTICE 'Restored UNIQUE(version) constraint';
END $$;

-- Restore the plain version index 001 originally created.
CREATE INDEX IF NOT EXISTS idx_schema_migrations_version
    ON schema_migrations(version);
