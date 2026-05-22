-- Migration 001: Schema Migrations Tracking Table
-- Date: 2025-11-20
-- Description: Industry-standard migration tracking system
--
-- Purpose:
-- - Track which migrations have been applied
-- - Prevent re-running already applied migrations
-- - Record success/failure history
-- - Enable rollback capabilities in future
--
-- Following: Principle 0 (Quality Over Velocity) and Principle 11 (No Shortcuts)

-- =============================================================================
-- Schema Migrations Table Upgrade
-- =============================================================================

-- Handle upgrading from old schema_migrations table (with only version, dirty columns)
-- to new schema (with id, version, name, applied_at, success, etc.)

DO $$
DECLARE
    old_schema_exists BOOLEAN;
BEGIN
    -- Check if old schema exists (has column 'dirty' but not 'name')
    SELECT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'schema_migrations'
        AND column_name = 'dirty'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'schema_migrations'
        AND column_name = 'name'
    ) INTO old_schema_exists;

    IF old_schema_exists THEN
        -- Old schema exists, need to upgrade.
        -- IMPORTANT: this branch is a safety-net for the rare case where
        -- ensureSchemaMigrationsTable in Go failed to upgrade the v0
        -- shape. The new table must use the v9 composite UNIQUE
        -- (version, name) because the terminal self-registration INSERT
        -- + every subsequent migration's recordMigrationSuccess use
        -- ON CONFLICT (version, name). A version-only UNIQUE here would
        -- brick the deployment on this path.
        RAISE NOTICE 'Old schema_migrations table detected, upgrading...';

        -- Rename old table
        ALTER TABLE schema_migrations RENAME TO schema_migrations_old;

        -- Create new table with full schema (composite dedup key — see
        -- migrations/core/096_schema_migrations_dedup_composite.sql)
        CREATE TABLE schema_migrations (
            id SERIAL PRIMARY KEY,
            version VARCHAR(20) NOT NULL,
            name VARCHAR(255) NOT NULL,
            applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            execution_time_ms INTEGER,
            success BOOLEAN NOT NULL DEFAULT true,
            error_message TEXT,
            checksum VARCHAR(64),
            applied_by VARCHAR(100) DEFAULT 'system',
            hostname VARCHAR(255),
            git_commit VARCHAR(40),
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            CONSTRAINT schema_migrations_version_name_uniq UNIQUE (version, name)
        );

        -- Migrate data from old table (version only, mark as successful).
        -- The v0 schema had only `version` (no `name`), so the synthesized
        -- name is unique per row by construction — but defense-in-depth
        -- ON CONFLICT (version, name) DO NOTHING handles any data anomaly
        -- without crashing the upgrade.
        INSERT INTO schema_migrations (version, name, applied_at, success)
        SELECT
            version::VARCHAR(20),
            'migration_' || version::VARCHAR(20),  -- Generate name from version
            NOW() - (version::INTEGER || ' days')::INTERVAL,  -- Estimate applied_at based on version
            true  -- Assume all existing migrations succeeded
        FROM schema_migrations_old
        WHERE NOT dirty  -- Only migrate successful migrations (not dirty)
        ON CONFLICT (version, name) DO NOTHING;

        -- Drop old table
        DROP TABLE schema_migrations_old;

        RAISE NOTICE 'Schema migrations table upgraded successfully';
    ELSE
        -- New schema already exists or table doesn't exist, create if needed.
        -- Same composite-UNIQUE shape as the upgrade branch above.
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id SERIAL PRIMARY KEY,
            version VARCHAR(20) NOT NULL,
            name VARCHAR(255) NOT NULL,
            applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            execution_time_ms INTEGER,
            success BOOLEAN NOT NULL DEFAULT true,
            error_message TEXT,
            checksum VARCHAR(64),
            applied_by VARCHAR(100) DEFAULT 'system',
            hostname VARCHAR(255),
            git_commit VARCHAR(40),
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            CONSTRAINT schema_migrations_version_name_uniq UNIQUE (version, name)
        );

        RAISE NOTICE 'Schema migrations table ready (new schema)';
    END IF;
END $$;

-- Indexes for fast lookups. The composite UNIQUE backs (version, name)
-- via its supporting btree; an additional plain (version) index would
-- be redundant and is no longer created here (migration 096 also drops
-- it on existing installs).
CREATE INDEX IF NOT EXISTS idx_schema_migrations_applied_at
    ON schema_migrations(applied_at DESC);

CREATE INDEX IF NOT EXISTS idx_schema_migrations_success
    ON schema_migrations(success)
    WHERE success = false;

-- Comments
COMMENT ON TABLE schema_migrations IS 'Tracks which database migrations have been applied';
COMMENT ON COLUMN schema_migrations.version IS 'Migration version number (e.g., "006", "020")';
COMMENT ON COLUMN schema_migrations.name IS 'Human-readable migration name';
COMMENT ON COLUMN schema_migrations.applied_at IS 'When the migration was applied';
COMMENT ON COLUMN schema_migrations.execution_time_ms IS 'Migration execution time in milliseconds';
COMMENT ON COLUMN schema_migrations.success IS 'Whether the migration succeeded';
COMMENT ON COLUMN schema_migrations.error_message IS 'Error message if migration failed';
COMMENT ON COLUMN schema_migrations.checksum IS 'SHA-256 hash of migration file for integrity';

-- =============================================================================
-- Self-Registration
-- =============================================================================

-- Register this migration (001) as applied
-- This is idempotent - will only insert if not exists

INSERT INTO schema_migrations (version, name, applied_at, success) VALUES
    ('001', 'schema_migrations_tracking_table', NOW(), true)
ON CONFLICT (version, name) DO NOTHING;

-- NOTE: No historical backfill needed - this is a fresh deployment
-- Migrations 002-017 will be applied sequentially after this

-- =============================================================================
-- Migration Complete
-- =============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Migration 001 completed successfully';
    RAISE NOTICE 'Schema migrations tracking table created';
    RAISE NOTICE 'Migrations 002-017 will be applied sequentially';
END $$;
