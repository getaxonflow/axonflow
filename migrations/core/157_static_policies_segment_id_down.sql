-- Down migration for 157: drop static_policies.segment_id + its index.
-- Pairs with: 157_static_policies_segment_id.sql
--
-- Purely additive forward migration -> the drop is loss-free at the schema
-- level for every pre-P3 row (segment_id is NULL there). Any row a P3
-- deployment DID populate loses its segment scoping on rollback -- expected
-- for a schema rollback, and the P3 selection/combiner code paths this
-- column feeds are themselves part of the same rollback unit.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'static_policies') THEN
        DROP INDEX IF EXISTS idx_static_policies_segment;
        ALTER TABLE static_policies DROP COLUMN IF EXISTS segment_id;
        RAISE NOTICE 'Migration 157 DOWN: static_policies.segment_id + index dropped';
    END IF;
END $$;

COMMIT;
