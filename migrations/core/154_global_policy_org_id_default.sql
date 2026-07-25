-- Migration 154: keep org_id='global' on tenant_id='global' policy rows (#3048)
-- Date: 2026-07-25
-- Issue: #3048
--
-- Mig 153 backfilled org_id='global' onto the tenant_id='global' policy rows
-- that existed at upgrade time. It could not protect rows seeded AFTER it:
-- the industry template migrations (industry/banking/300/302/401,
-- industry/travel/200) INSERT static_policies rows with tenant_id='global'
-- and NO org_id, and they apply after the core chain on banking/travel
-- deployments — leaving their global rows invisible to every 'global'-scoped
-- RLS read (mig 018 predicate org_id = get_current_org_id()) under
-- axonflow_app_role. The same failure shape recurs for any future seed that
-- forgets the org key.
--
-- Two parts, both idempotent:
--   1. Re-run the 153-shaped backfill (catches rows seeded between 153 and
--      this migration — e.g. industry templates applied on an upgraded
--      deployment).
--   2. Guard the INVARIANT at the choke point instead of per-seed: a BEFORE
--      INSERT trigger on static_policies + dynamic_policies defaults
--      org_id='global' when tenant_id='global' and no org key was supplied.
--      Rows with an explicit org_id are untouched.

BEGIN;

-- Part 1: backfill (idempotent — matches only rows still missing the key).
DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'static_policies' AND column_name = 'tenant_id')
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'static_policies' AND column_name = 'org_id') THEN
        UPDATE static_policies
            SET org_id = 'global'
            WHERE tenant_id = 'global'
              AND (org_id IS NULL OR org_id = '');
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 154: static_policies org_id=global set on % rows', rows_updated;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies' AND column_name = 'tenant_id')
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'dynamic_policies' AND column_name = 'org_id') THEN
        UPDATE dynamic_policies
            SET org_id = 'global'
            WHERE tenant_id = 'global'
              AND (org_id IS NULL OR org_id = '');
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 154: dynamic_policies org_id=global set on % rows', rows_updated;
    END IF;
END
$$;

-- Part 2: choke-point default for future seeds.
CREATE OR REPLACE FUNCTION policy_global_org_id_default() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.tenant_id = 'global' AND (NEW.org_id IS NULL OR NEW.org_id = '') THEN
        NEW.org_id := 'global';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'static_policies' AND column_name = 'tenant_id')
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'static_policies' AND column_name = 'org_id') THEN
        DROP TRIGGER IF EXISTS static_policies_global_org_id_default ON static_policies;
        CREATE TRIGGER static_policies_global_org_id_default
            BEFORE INSERT ON static_policies
            FOR EACH ROW
            EXECUTE FUNCTION policy_global_org_id_default();
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies' AND column_name = 'tenant_id')
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'dynamic_policies' AND column_name = 'org_id') THEN
        DROP TRIGGER IF EXISTS dynamic_policies_global_org_id_default ON dynamic_policies;
        CREATE TRIGGER dynamic_policies_global_org_id_default
            BEFORE INSERT ON dynamic_policies
            FOR EACH ROW
            EXECUTE FUNCTION policy_global_org_id_default();
    END IF;
END
$$;

-- Self-test: no tenant_id='global' policy row may remain without org_id, and
-- a fresh global-sentinel INSERT must acquire the key via the trigger.
-- Guarded on the same COLUMN existence checks as the backfill block so the
-- two can never disagree about which schemas this migration supports (a
-- table-only guard could RAISE on a legacy shape the backfill skipped and
-- boot-loop the runner).
DO $$
DECLARE
    remaining INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'static_policies' AND column_name = 'tenant_id')
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'static_policies' AND column_name = 'org_id') THEN
        SELECT COUNT(*) INTO remaining
        FROM static_policies
        WHERE tenant_id = 'global' AND (org_id IS NULL OR org_id = '');
        IF remaining > 0 THEN
            RAISE EXCEPTION 'Migration 154 failed: % tenant_id=global static_policies rows still lack org_id', remaining;
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies' AND column_name = 'tenant_id')
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'dynamic_policies' AND column_name = 'org_id') THEN
        SELECT COUNT(*) INTO remaining
        FROM dynamic_policies
        WHERE tenant_id = 'global' AND (org_id IS NULL OR org_id = '');
        IF remaining > 0 THEN
            RAISE EXCEPTION 'Migration 154 failed: % tenant_id=global dynamic_policies rows still lack org_id', remaining;
        END IF;
    END IF;
END
$$;

COMMIT;
