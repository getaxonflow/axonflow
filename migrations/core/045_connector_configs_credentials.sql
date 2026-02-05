-- Migration 045: Add connector credentials column and expand connector types
-- Date: 2026-02-03
-- Purpose: Store non-sensitive credentials in connector_configs and allow new connector types

DO $migration$
DECLARE
    configs_exists BOOLEAN;
    credentials_exists BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'connector_configs'
    ) INTO configs_exists;

    IF NOT configs_exists THEN
        RAISE NOTICE 'Migration 045: connector_configs table does not exist. Skipping.';
        RETURN;
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'connector_configs'
          AND column_name = 'credentials'
    ) INTO credentials_exists;

    IF NOT credentials_exists THEN
        ALTER TABLE connector_configs
            ADD COLUMN credentials JSONB DEFAULT '{}'::jsonb;
        RAISE NOTICE 'Added connector_configs.credentials column';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_schema = 'public'
          AND table_name = 'connector_configs'
          AND constraint_name = 'check_connector_type'
    ) THEN
        ALTER TABLE connector_configs DROP CONSTRAINT check_connector_type;
    END IF;

    ALTER TABLE connector_configs
        ADD CONSTRAINT check_connector_type CHECK (connector_type IN (
            'postgres', 'cassandra', 'salesforce', 'amadeus', 'slack', 'snowflake',
            'http', 'mysql', 'mongodb', 'redis', 's3', 'azureblob', 'gcs',
            'hubspot', 'jira', 'servicenow', 'custom'
        ));

    RAISE NOTICE 'Updated connector_configs.check_connector_type constraint';
END $migration$;
