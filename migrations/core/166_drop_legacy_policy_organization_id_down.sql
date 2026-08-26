-- Rollback for migration 166 (#3334).
--
-- Re-adds the legacy organization_id column to static_policies,
-- dynamic_policies and policy_overrides, as `text` -- the type migration 133
-- retyped it to, not the `uuid` migration 030 originally created, because 133
-- retyped it precisely BECAUSE AxonFlow org ids are free-form strings from a
-- signed licence and binding one into a uuid column threw
-- `pq: invalid input syntax for type uuid` as a hard 500 in 9.3.0.
--
-- THE COLUMN COMES BACK EMPTY, AND THAT IS THE HONEST OUTCOME, not a
-- shortcoming to work around. The forward migration reported its population
-- before dropping it; on every deployment measured that count was zero (no
-- shipped migration has ever written this column). Where it was non-zero the
-- forward migration raised a WARNING naming the count, because those values
-- are the ones this rollback cannot restore. Reconstructing them from org_id
-- would be worse than leaving them empty: org_id is populated on 100% of rows,
-- so the reconstruction would invent an org-TIER selection key for every row
-- in the table, including the tenant-tier ones that never had one -- which is
-- a different schema from the one being rolled back to, wearing its name.
--
-- THE THREE PARTIAL INDEXES ARE RESTORED, and they are the one thing here
-- that IS put back. core/030 created
--   idx_static_policies_organization  ON static_policies(organization_id)
--   idx_dynamic_policies_organization ON dynamic_policies(organization_id)
--   idx_policy_overrides_org          ON policy_overrides(organization_id)
-- each WHERE organization_id IS NOT NULL. Postgres drops an index with the
-- column it covers, so the forward migration takes all three with it without
-- naming them, and an earlier revision of this file left them dropped while
-- its header enumerated only the values and the CHECK as not-restored -- so
-- the one omission it did not disclose was the only one that was cheap to
-- undo. Rolling back to a schema that silently lacks three indexes the
-- rolled-back-to schema had is a different schema wearing its name, which is
-- the same objection this file already makes to reconstructing the values.
--
-- They are restored rather than documented-as-lost because restoring them is
-- lossless and free, which is exactly what distinguishes them from the other
-- two items: the VALUES cannot be recovered (nothing records them once
-- dropped) and the CHECK must not be recovered (it would refuse every
-- org-scoped override row). A partial index over an all-NULL column indexes
-- zero rows and occupies essentially nothing, so this costs nothing and makes
-- the rollback schema-faithful.
--
-- The valid_override_scope CHECK is NOT restored either. It read
--     (organization_id IS NOT NULL AND tenant_id IS NULL) OR (tenant_id IS NOT NULL)
-- and with the column empty on every row, restoring it would refuse every
-- org-scoped override row (tenant_id NULL, organization_id NULL) -- turning a
-- rollback into an outage on the very write path it is meant to restore.
-- Migration 165's NOT NULL on org_id guarantees the property the constraint
-- existed for, unconditionally and for every row, and that guarantee is not
-- affected by this rollback.
--
-- THE tenant_id NON-EMPTY CHECK IS DROPPED, because the forward migration is
-- what added it. policy_overrides_tenant_id_not_empty closes the one shape
-- valid_override_scope's retirement left writable (tenant_id = '', which is
-- neither tenant scope nor org scope and which no read path can reach), so it
-- belongs to 166 and goes back with it. Dropping a CHECK never fails and
-- never touches a row.
--
-- Rolling it back does NOT restore the rows the forward heal deleted, and
-- nothing here pretends otherwise -- the same disclosure this file already
-- makes about organization_id's values. Those rows were unreachable by every
-- read path before they were deleted, so their absence changes no enforcement;
-- the forward migration named them by primary key in a WARNING precisely so an
-- operator rolling back has the record.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS and DROP CONSTRAINT IF EXISTS
-- throughout.

BEGIN;

DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['static_policies', 'dynamic_policies', 'policy_overrides']
    LOOP
        -- pg_catalog, not information_schema: see the up migration's header.
        IF to_regclass('public.' || quote_ident(tbl)) IS NULL THEN
            CONTINUE;
        END IF;
        EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS organization_id text', tbl);
    END LOOP;

    -- Restore core/030's three partial indexes, which Postgres dropped along
    -- with the column. Named individually rather than derived in the loop
    -- because the names are NOT uniform -- policy_overrides' index is
    -- idx_policy_overrides_org, not idx_policy_overrides_organization -- and
    -- a format()-built name would silently create three indexes core/030
    -- never had while leaving the real ones missing.
    IF to_regclass('public.static_policies') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS idx_static_policies_organization
            ON static_policies(organization_id) WHERE organization_id IS NOT NULL;
    END IF;
    IF to_regclass('public.dynamic_policies') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS idx_dynamic_policies_organization
            ON dynamic_policies(organization_id) WHERE organization_id IS NOT NULL;
    END IF;
    IF to_regclass('public.policy_overrides') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS idx_policy_overrides_org
            ON policy_overrides(organization_id) WHERE organization_id IS NOT NULL;
    END IF;

    -- The forward migration added this; the rollback takes it away again.
    IF to_regclass('public.policy_overrides') IS NOT NULL THEN
        ALTER TABLE policy_overrides
            DROP CONSTRAINT IF EXISTS policy_overrides_tenant_id_not_empty;
    END IF;

    RAISE WARNING 'Migration 166 DOWN: organization_id restored as text on the policy tables, with NO values, core/030''s three partial indexes on it recreated, and policy_overrides_tenant_id_not_empty dropped. See this file''s header for why the values are not reconstructed from org_id, why valid_override_scope is not restored, and why the rows the forward heal deleted do not come back.';
END
$$;

-- Self-test: the column and all three indexes are back. "ADD COLUMN IF NOT
-- EXISTS ran" and "the schema is restored" are different claims, and the
-- index half of this rollback was missing entirely until it was asserted.
DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['static_policies', 'dynamic_policies', 'policy_overrides']
    LOOP
        IF to_regclass('public.' || quote_ident(tbl)) IS NULL THEN
            CONTINUE;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                       WHERE attrelid = to_regclass('public.' || quote_ident(tbl))
                         AND attname = 'organization_id' AND attnum > 0
                         AND NOT attisdropped) THEN
            RAISE EXCEPTION 'Migration 166 DOWN failed: %.organization_id was not restored', tbl;
        END IF;
    END LOOP;

    -- Spelled out one table at a time rather than looped: the index names are
    -- not derivable from the table names (policy_overrides' is
    -- idx_policy_overrides_org, not ..._organization), and a loop that built
    -- them by format() would assert the existence of names core/030 never
    -- created while missing the ones it did.
    IF to_regclass('public.static_policies') IS NOT NULL
       AND to_regclass('public.idx_static_policies_organization') IS NULL THEN
        RAISE EXCEPTION 'Migration 166 DOWN failed: idx_static_policies_organization was not restored';
    END IF;
    IF to_regclass('public.dynamic_policies') IS NOT NULL
       AND to_regclass('public.idx_dynamic_policies_organization') IS NULL THEN
        RAISE EXCEPTION 'Migration 166 DOWN failed: idx_dynamic_policies_organization was not restored';
    END IF;
    IF to_regclass('public.policy_overrides') IS NOT NULL
       AND to_regclass('public.idx_policy_overrides_org') IS NULL THEN
        RAISE EXCEPTION 'Migration 166 DOWN failed: idx_policy_overrides_org was not restored';
    END IF;

    -- And the CHECK the forward migration added is gone again.
    IF to_regclass('public.policy_overrides') IS NOT NULL
       AND EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'public.policy_overrides'::regclass
                     AND conname = 'policy_overrides_tenant_id_not_empty') THEN
        RAISE EXCEPTION 'Migration 166 DOWN failed: policy_overrides_tenant_id_not_empty survived the rollback';
    END IF;
END
$$;

COMMIT;
