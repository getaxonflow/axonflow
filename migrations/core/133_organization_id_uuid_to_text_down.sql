-- Down migration 133: revert policy-table organization_id from text back to uuid.
--
-- Safe ONLY if every organization_id value is a valid UUID or NULL (the state
-- these columns are in on all current deployments — they are effectively
-- unpopulated). If a free-form (non-UUID) org id was written after migration
-- 133 (the whole point of the up migration), the USING cast below will fail;
-- that is intentional — you cannot losslessly force a string org id back into a
-- uuid column. Idempotent: only alters a column still typed text.

DO $$
DECLARE
    tbl text;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['static_policies', 'dynamic_policies', 'policy_overrides', 'policy_evaluations']
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = tbl
              AND column_name = 'organization_id'
              AND data_type = 'text'
        ) THEN
            EXECUTE format(
                'ALTER TABLE %I ALTER COLUMN organization_id TYPE uuid USING organization_id::uuid',
                tbl
            );
        END IF;
    END LOOP;
END $$;
