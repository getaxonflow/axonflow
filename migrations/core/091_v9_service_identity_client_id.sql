-- Migration 091: v9 service-identity tables client_id (additive)
-- Date: 2026-05-19
--
-- Classification (credential class):
--   service_identities (016)        — service/app credential identity rows.
--                                     tenant_id is the customer/credential
--                                     scope; v9 adds client_id alongside.
--
-- service_role_assignments — table referenced in older drafts but NOT
-- PRESENT in this codebase as of 2026-05-19 (verified: `grep -rn
-- service_role_assignments migrations/`). The migration gates its ALTER on
-- IF EXISTS so it's a no-op today and forward-compatible if a future
-- migration introduces the table.
--
-- role_assignments (023) — a different RBAC table (user_email → role_id,
-- scoped by tenant_id) is intentionally NOT touched by this migration.
-- Its classification is ambiguous (RBAC role assignment is typically
-- org-scoped per industry convention, but this codebase's RLS policy uses
-- `tenant_id = current_setting('app.current_org_id', true)` which conflates
-- the two). The classification call belongs in a separate identity-inventory
-- migration, not in this additive layer.
--
-- Idempotency: standard ADD COLUMN IF NOT EXISTS + WHERE-empty UPDATE.
-- Rollback: paired _down.sql drops the column + indexes.
--
-- Depends on: 016_service_identity_system

-- ============================================================================
-- service_identities
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'service_identities') THEN
        ALTER TABLE service_identities
            ADD COLUMN IF NOT EXISTS client_id VARCHAR(255);

        UPDATE service_identities
            SET client_id = tenant_id
            WHERE (client_id IS NULL OR client_id = '')
              AND tenant_id IS NOT NULL
              AND tenant_id <> '';

        CREATE INDEX IF NOT EXISTS idx_service_identities_client_id
            ON service_identities(client_id);

        CREATE INDEX IF NOT EXISTS idx_service_identities_org_client
            ON service_identities(org_id, client_id);

        RAISE NOTICE 'Migration 091: service_identities.client_id added + backfilled';
    ELSE
        RAISE NOTICE 'Migration 091: service_identities missing — skipping';
    END IF;
END $$;

-- ============================================================================
-- service_role_assignments (forward-compatible — table does not exist today)
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'service_role_assignments') THEN
        ALTER TABLE service_role_assignments
            ADD COLUMN IF NOT EXISTS client_id VARCHAR(255);

        -- Only backfill from tenant_id if that column exists on the
        -- future-shape table. Defensive: don't assume schema.
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'service_role_assignments' AND column_name = 'tenant_id') THEN
            UPDATE service_role_assignments
                SET client_id = tenant_id
                WHERE (client_id IS NULL OR client_id = '')
                  AND tenant_id IS NOT NULL
                  AND tenant_id <> '';

            CREATE INDEX IF NOT EXISTS idx_service_role_assignments_client_id
                ON service_role_assignments(client_id);
        END IF;

        RAISE NOTICE 'Migration 091: service_role_assignments.client_id added';
    ELSE
        RAISE NOTICE 'Migration 091: service_role_assignments does not exist in this codebase (forward-compatible no-op)';
    END IF;
END $$;

-- ============================================================================
-- Column documentation
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'service_identities' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN service_identities.client_id IS ''Credential/service identity column. Mirrors tenant_id for service-to-service auth callers.''';
    END IF;
END $$;

DO $$
BEGIN
    RAISE NOTICE 'Migration 091 complete — v9 service-identity client_id additive layer';
END $$;
