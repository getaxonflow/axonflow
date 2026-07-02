-- Migration 133: retype policy-table organization_id from uuid to text
-- Date: 2026-07-02
-- Purpose: AxonFlow org ids are free-form strings sourced from the signed
--          license (e.g. "acme-eval") — they are NOT UUIDs. Four policy
--          tables carry a legacy `organization_id uuid` column (an early
--          "org = UUID" schema assumption that never matched the license
--          model). Binding a non-UUID org id into that column throws
--          `pq: invalid input syntax for type uuid`, which shipped as a hard
--          500 in 9.3.0 on the customer-portal policy-override create flow and
--          on org-tier static-policy create.
--
--          The canonical org column is the varchar `org_id` (added in v9,
--          #2230, and the RLS key `app.current_org_id`). This migration retypes
--          the legacy column to `text` so a free-form org id can be stored/
--          compared without the uuid parse error. It is the safe UNBLOCK; full
--          consolidation onto `org_id` + DROP of `organization_id` is tracked
--          separately (#2791, folds into the tenant-isolation epic #2536).
--
--          Type-transparent because: (1) the column FKs to nothing; (2) the
--          CHECK constraint `valid_override_scope` only tests NULL/NOT-NULL and
--          is type-agnostic; (3) the partial indexes on organization_id are
--          predicate-only and auto-rebuild; (4) RLS keys on `org_id`, not this
--          column; (5) every live query already casts `organization_id::text`.
--
--          Cost/locking: `ALTER COLUMN ... TYPE text USING organization_id::text`
--          is NOT a binary-coercible change (uuid and text have no assignment
--          cast), so Postgres performs a FULL TABLE REWRITE. It takes ACCESS
--          EXCLUSIVE (the lock LEVEL is constant); the rewrite work and therefore
--          the lock HOLD TIME scale with the TOTAL row count, not the (near-zero)
--          populated count. Cheap in practice because these are small tables: the
--          three policy tables are config-scale, and `policy_evaluations` has no
--          application INSERT path (only a test seed writes it) so it is
--          effectively empty. Operational note: migrations run at agent boot and
--          Fatal-fail on error, so confirm production row counts (especially
--          `policy_evaluations`) before deploying to a large/long-lived
--          deployment. Idempotent: only alters a column still typed uuid.

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
              AND data_type = 'uuid'
        ) THEN
            EXECUTE format(
                'ALTER TABLE %I ALTER COLUMN organization_id TYPE text USING organization_id::text',
                tbl
            );
        END IF;
    END LOOP;
END $$;
