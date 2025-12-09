-- Migration 028: Create grafana database and user for Grafana monitoring
-- This database is used by Grafana to store dashboard configurations, users, and metadata
-- Required for the monitoring stack to function properly
--
-- Note: This migration always runs (for all DEPLOYMENT_MODEs including OSS).
-- The Grafana SERVICE is optional, but the database setup is always available.
-- This allows enabling Grafana later without needing additional migrations.
--
-- Best Practice: Create a dedicated user for Grafana with limited privileges
-- This follows the principle of least privilege for database access

DO $$
DECLARE
    deploy_grafana text;
BEGIN
    -- Get environment variable (PostgreSQL cannot access env vars directly)
    -- This will be handled by the agent's migration runner
    -- For now, we'll make it unconditional and rely on CloudFormation not deploying Grafana service

    RAISE NOTICE 'Starting Grafana database migration';

    -- Step 1: Create or update grafana user with correct password
    -- Using placeholder substitution for secure password management
    -- The Agent will replace {{GRAFANA_PASSWORD}} before executing this migration
    IF NOT EXISTS (
        SELECT 1 FROM pg_user WHERE usename = 'grafana'
    ) THEN
        EXECUTE 'CREATE USER grafana WITH PASSWORD ''{{GRAFANA_PASSWORD}}''';
        RAISE NOTICE 'Created grafana database user';
    ELSE
        -- User exists, ensure password is correct
        EXECUTE 'ALTER USER grafana WITH PASSWORD ''{{GRAFANA_PASSWORD}}''';
        RAISE NOTICE 'Updated grafana user password';
    END IF;
END
$$;

-- Step 2: Create grafana database if it doesn't exist
-- PostgreSQL limitation: CREATE DATABASE cannot run inside a transaction or DO block
-- Solution: Create a function that executes CREATE DATABASE via dblink extension
-- This allows conditional database creation in a safe, idempotent way

-- First, ensure dblink extension exists (safe to run multiple times)
CREATE EXTENSION IF NOT EXISTS dblink;

-- Create helper function to create database if it doesn't exist
CREATE OR REPLACE FUNCTION create_database_if_not_exists(dbname text) RETURNS void AS $$
DECLARE
    db_exists boolean;
BEGIN
    -- Check if database already exists
    SELECT EXISTS (
        SELECT 1 FROM pg_database WHERE datname = dbname
    ) INTO db_exists;

    IF db_exists THEN
        RAISE NOTICE 'Database % already exists', dbname;
    ELSE
        -- Use dblink to execute CREATE DATABASE outside of transaction context
        -- dblink connects to the current database to execute the command
        -- Use session variable for password (set by agent before migrations)
        -- IMPORTANT: Use current_user as owner, not 'grafana' - grafana user isn't visible
        -- to the dblink connection because it's created in an uncommitted transaction
        PERFORM dblink_exec(
            'dbname=' || current_database() || ' user=' || current_user || ' password=' || current_setting('app.db_password', false),
            format('CREATE DATABASE %I WITH OWNER = %I',
                   dbname, current_user)
        );
        RAISE NOTICE 'Created database % with owner %', dbname, current_user;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Create grafana database with current user as owner (transferred to grafana below)
-- Note: Always creates the database/user pair (CloudFormation controls whether Grafana service runs)
-- This is simpler than conditional logic based on env vars that agent can't easily access
-- The database is small (~10MB) and having it present doesn't hurt when Grafana is disabled
SELECT create_database_if_not_exists('grafana');

-- Transfer ownership to grafana user (happens after DO block commits, so grafana user exists)
-- This works because the ALTER DATABASE command runs in the main transaction context
-- where the grafana user from the DO block above is visible
ALTER DATABASE grafana OWNER TO grafana;

-- Clean up helper function (keep it for future use)
-- DROP FUNCTION IF EXISTS create_database_if_not_exists(text, text);

-- Migration completed successfully
-- Security benefits:
-- 1. Separate user for Grafana (principle of least privilege)
-- 2. Grafana cannot access axonflow application data
-- 3. If Grafana is compromised, attacker can't access main database
-- 4. Easier to audit Grafana-specific database activity

-- Note: The CloudFormation template uses the grafana user:
-- GF_DATABASE_USER=grafana
-- GF_DATABASE_PASSWORD={{GRAFANA_PASSWORD}} (passed via environment variable)
-- GF_DATABASE_NAME=grafana

-- Design Decision: Always create grafana database
-- Rationale:
-- 1. Database is tiny (~10MB empty, grows to ~50-100MB with dashboards)
-- 2. Agent doesn't have easy access to CloudFormation parameters
-- 3. Simpler to always create than add conditional logic
-- 4. If Grafana disabled, database just sits there unused (negligible cost)
-- 5. Makes it easy to enable Grafana later without migration hassle
