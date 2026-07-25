-- Rollback for migration 154 (#3048).
--
-- Drops the choke-point default triggers. The backfilled org_id='global'
-- values are LEFT IN PLACE deliberately: they are the correct v9 shape (the
-- Go-side seeders write them, mig 094/153 backfilled them) and reverting them
-- would re-hide the global policy rows from every 'global'-scoped RLS read.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'static_policies') THEN
        DROP TRIGGER IF EXISTS static_policies_global_org_id_default ON static_policies;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies') THEN
        DROP TRIGGER IF EXISTS dynamic_policies_global_org_id_default ON dynamic_policies;
    END IF;
END
$$;

DROP FUNCTION IF EXISTS policy_global_org_id_default();

COMMIT;
