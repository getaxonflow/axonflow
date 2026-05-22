-- Down migration for 091: drop service-identity client_id columns + indexes.
-- Pairs with: 091_v9_service_identity_client_id.sql

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'service_role_assignments') THEN
        DROP INDEX IF EXISTS idx_service_role_assignments_client_id;
        ALTER TABLE service_role_assignments DROP COLUMN IF EXISTS client_id;
        RAISE NOTICE 'Migration 091 DOWN: service_role_assignments.client_id + index dropped';
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'service_identities') THEN
        DROP INDEX IF EXISTS idx_service_identities_org_client;
        DROP INDEX IF EXISTS idx_service_identities_client_id;
        ALTER TABLE service_identities DROP COLUMN IF EXISTS client_id;
        RAISE NOTICE 'Migration 091 DOWN: service_identities.client_id + indexes dropped';
    END IF;
END $$;
