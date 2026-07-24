-- Migration 153: backfill org_id='global' on tenant_id='global' policy rows
-- Date: 2026-07-24
-- Issue: #3039
--
-- Mig 031 seeds the system dynamic policies (sys_dyn_high_risk_block,
-- sys_dyn_hipaa, sys_dyn_gdpr, ...) with tenant_id='global' and NO org_id,
-- and mig 094's org_id backfill deliberately skips tenant_id='global' rows.
-- The RLS predicate on dynamic_policies (mig 018) is strictly
-- org_id = get_current_org_id(), so under axonflow_app_role those rows are
-- invisible to EVERY scoped read — including the #3039 two-scope List/GetByID
-- reads that unlock the 'global' scope: the GUC pass reads org_id='global',
-- which never matches NULL.
--
-- The Go-side seeder (seedSystemMediaPolicies) already writes its global
-- rows WITH org_id='global' — this backfill brings the mig-031 rows to the
-- same shape. static_policies global rows get the same treatment for parity
-- (same seed pattern, same RLS predicate).
--
-- Idempotent: the WHERE clause matches only rows still missing the org key.

BEGIN;

DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies') THEN
        UPDATE dynamic_policies
            SET org_id = 'global'
            WHERE tenant_id = 'global'
              AND (org_id IS NULL OR org_id = '');
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 153: dynamic_policies org_id=global set on % rows', rows_updated;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'static_policies' AND column_name = 'tenant_id')
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'static_policies' AND column_name = 'org_id') THEN
        UPDATE static_policies
            SET org_id = 'global'
            WHERE tenant_id = 'global'
              AND (org_id IS NULL OR org_id = '');
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 153: static_policies org_id=global set on % rows', rows_updated;
    END IF;
END
$$;

-- Self-test: no tenant_id='global' dynamic policy may remain without org_id.
-- Guarded on the same existence check as the backfill block so the two can
-- never disagree about which schemas this migration supports.
DO $$
DECLARE
    remaining INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies') THEN
        SELECT COUNT(*) INTO remaining
        FROM dynamic_policies
        WHERE tenant_id = 'global' AND (org_id IS NULL OR org_id = '');
        IF remaining > 0 THEN
            RAISE EXCEPTION 'Migration 153 failed: % tenant_id=global dynamic_policies rows still lack org_id', remaining;
        END IF;
    END IF;
END
$$;

COMMIT;
