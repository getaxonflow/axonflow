-- Migration 163: Add require_user_token to organizations (#3476)
-- Date: 2026-08-23
-- Purpose: ADR-060 (#2989) segment-scoped policies are only meaningful if a
--          caller cannot CHOOSE to arrive without an identity. Today a
--          token-less enterprise caller gets a synthetic service identity on
--          /decide, the MCP-server plane, and the four MCP REST routes, so
--          dropping a header silently switches a control off. This column is
--          the storage half of the fix: an org-level flag that, when true,
--          means a token-less enterprise caller must be REJECTED at
--          authentication rather than allowed through as a service identity.
--
-- This migration adds storage only, but the gate points consuming it landed
-- in the same train: /decide, the MCP-server session-auth plane, and the
-- four MCP REST routes read this column at authentication time (the Phase B
-- wiring tracked under #3476 shipped with the identity stack). Behaviour
-- still changes only when an org or the deployment opts in.
--
-- DEFAULT false is load-bearing: every existing deployment must be untouched
-- at deploy time. No backfill, no data migration — an org that has never
-- touched this lever keeps today's behaviour until an operator (or the
-- deployment-wide AXONFLOW_REQUIRE_USER_TOKEN env default) opts it in.

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        -- to_regclass, not information_schema: information_schema views are
        -- PRIVILEGE-FILTERED, so a role without a privilege on organizations
        -- reads "table absent", takes the skip branch and COMMITS having done
        -- nothing. pg_catalog is not filtered. Matches migrations 161/162.
        SELECT 1 WHERE to_regclass('public.organizations') IS NOT NULL
    ) THEN
        ALTER TABLE organizations
            ADD COLUMN IF NOT EXISTS require_user_token BOOLEAN NOT NULL DEFAULT false;

        RAISE NOTICE 'Migration 163: organizations.require_user_token added (default false)';
    ELSE
        RAISE NOTICE 'Migration 163: organizations does not exist - skipping';
    END IF;
END $$;

-- Verification — fail loudly if the column is missing (Principle 3).
DO $$
BEGIN
    IF EXISTS (
        -- to_regclass, not information_schema: information_schema views are
        -- PRIVILEGE-FILTERED, so a role without a privilege on organizations
        -- reads "table absent", takes the skip branch and COMMITS having done
        -- nothing. pg_catalog is not filtered. Matches migrations 161/162.
        SELECT 1 WHERE to_regclass('public.organizations') IS NOT NULL
    ) THEN
        IF NOT EXISTS (SELECT 1 FROM pg_attribute
                       WHERE attrelid = to_regclass('public.organizations')
                         AND attname = 'require_user_token'
                         AND NOT attisdropped) THEN
            RAISE EXCEPTION 'Migration 163 failed: require_user_token column not created';
        END IF;
        RAISE NOTICE 'Migration 163 verified: require_user_token present on organizations';
    END IF;
END $$;

COMMIT;
