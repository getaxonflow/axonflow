-- Rollback for migration 165 (#3490).
--
-- Drops the non-empty CHECK constraints and relaxes NOT NULL on org_id
-- across static_policies, dynamic_policies and policy_overrides, restoring
-- the pre-165 column shape.
--
-- The '__axonflow_unowned__' stamps are LEFT IN PLACE deliberately, the same
-- decision migration 156's rollback took and for the same reason: reverting
-- them to NULL would restore rows with no tenancy key at all, and on the
-- pre-Decision-5 code that is a row the tenant leg of a selection predicate
-- could reach from an unbound caller. A rollback must not reopen that. An
-- operator who genuinely needs one of those policies back should re-stamp it
-- with the owning org explicitly.
--
-- The resolved backfills (steps 1-4 of the forward migration) are likewise
-- NOT reverted. They wrote the org key the row should always have had, from
-- the tenants / organizations mappings or the org_id == tenant_id identity;
-- pure SQL cannot distinguish a row 165 resolved from one that already held
-- the same value, and unsetting both would be strictly worse than leaving
-- them. This mirrors migration 094's own down-migration caveat.
--
-- No DEFAULT is restored: none of the three columns had one before 165 (mig
-- 010 declared org_id bare on static_policies and dynamic_policies, mig 110
-- added it bare on policy_overrides), so the forward migration's defensive
-- DROP DEFAULT removed nothing to put back.

BEGIN;

DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['static_policies', 'dynamic_policies', 'policy_overrides']
    LOOP
        -- pg_catalog, not information_schema: the standard views are
        -- privilege-filtered, so a role without a grant on the table would
        -- CONTINUE past its own rollback and report success having undone
        -- nothing. See the up migration's header for the measurement.
        IF to_regclass('public.' || quote_ident(tbl)) IS NULL THEN
            CONTINUE;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                       WHERE attrelid = to_regclass('public.' || quote_ident(tbl))
                         AND attname = 'org_id' AND attnum > 0 AND NOT attisdropped) THEN
            CONTINUE;
        END IF;

        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT IF EXISTS %I', tbl, tbl || '_org_id_not_empty');
        EXECUTE format('ALTER TABLE %I ALTER COLUMN org_id DROP NOT NULL', tbl);
    END LOOP;
END
$$;

COMMIT;
