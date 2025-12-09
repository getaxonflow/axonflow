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
        -- Old schema exists, need to upgrade
        RAISE NOTICE 'Old schema_migrations table detected, upgrading...';

        -- Rename old table
        ALTER TABLE schema_migrations RENAME TO schema_migrations_old;

        -- Create new table with full schema
        CREATE TABLE schema_migrations (
            id SERIAL PRIMARY KEY,
            version VARCHAR(20) NOT NULL UNIQUE,
            name VARCHAR(255) NOT NULL,
            applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            execution_time_ms INTEGER,
            success BOOLEAN NOT NULL DEFAULT true,
            error_message TEXT,
            checksum VARCHAR(64),
            applied_by VARCHAR(100) DEFAULT 'system',
            hostname VARCHAR(255),
            git_commit VARCHAR(40),
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        );

        -- Migrate data from old table (version only, mark as successful)
        INSERT INTO schema_migrations (version, name, applied_at, success)
        SELECT
            version::VARCHAR(20),
            'migration_' || version::VARCHAR(20),  -- Generate name from version
            NOW() - (version::INTEGER || ' days')::INTERVAL,  -- Estimate applied_at based on version
            true  -- Assume all existing migrations succeeded
        FROM schema_migrations_old
        WHERE NOT dirty;  -- Only migrate successful migrations (not dirty)

        -- Drop old table
        DROP TABLE schema_migrations_old;

        RAISE NOTICE 'Schema migrations table upgraded successfully';
    ELSE
        -- New schema already exists or table doesn't exist, create if needed
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id SERIAL PRIMARY KEY,
            version VARCHAR(20) NOT NULL UNIQUE,
            name VARCHAR(255) NOT NULL,
            applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            execution_time_ms INTEGER,
            success BOOLEAN NOT NULL DEFAULT true,
            error_message TEXT,
            checksum VARCHAR(64),
            applied_by VARCHAR(100) DEFAULT 'system',
            hostname VARCHAR(255),
            git_commit VARCHAR(40),
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        );

        RAISE NOTICE 'Schema migrations table ready (new schema)';
    END IF;
END $$;

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_schema_migrations_version
    ON schema_migrations(version);

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
ON CONFLICT (version) DO NOTHING;

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
