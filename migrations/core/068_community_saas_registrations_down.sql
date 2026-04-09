-- Down migration 068: Remove community-saas registration tables
-- WARNING: This drops all community-saas registration data.

DROP FUNCTION IF EXISTS increment_csaas_daily(VARCHAR, DATE);
DROP TABLE IF EXISTS community_saas_daily_usage;
DROP TABLE IF EXISTS community_saas_registrations;

DO $$
BEGIN
    RAISE NOTICE 'Migration 068 DOWN: community_saas_registrations + community_saas_daily_usage dropped';
END $$;
