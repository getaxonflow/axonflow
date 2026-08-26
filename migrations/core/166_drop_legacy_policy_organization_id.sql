-- Migration 166: drop the legacy organization_id column from the policy tables
-- Date: 2026-08-25
-- Issue: #3334 (tracked from #3490, Decision 5)
--
-- static_policies, dynamic_policies and policy_overrides each carried TWO
-- organisation keys with different types, different populations and different
-- meanings:
--
--   org_id VARCHAR(255)   (core/010, core/110) -- the RLS isolation column,
--     backfilled by mig 153, defaulted by the mig-154 trigger, populated on
--     100% of rows (verified: 101 of 101 on a fully-migrated seeded database),
--     and since #3490 the ONLY thing that selects a policy row.
--
--   organization_id       (core/030, originally UUID, retyped to text by
--     core/133) -- the org-TIER selection key GetEffective used to read.
--     No shipped MIGRATION has ever written it, and it is empty on every
--     deployment measured (0 of 101 rows on a fully-migrated seeded database).
--
--     IT IS NOT UNIVERSALLY EMPTY, and an earlier revision of this header
--     said it was. The design-partner seed bundle
--     (config/seed-data/.../policy_bundle.sql) wrote ONE static_policies row
--     carrying both organization_id and org_id, so any deployment seeded from
--     that bundle before this change holds exactly one non-null value and
--     WILL see the RAISE WARNING below fire. That is EXPECTED, not alarming,
--     and nothing is lost: the same row carries org_id, which is the key that
--     selects it, so the drop changes no scope. The bundle no longer writes
--     the column. Operators should expect the warning on upgrade and can
--     ignore it; the warning is retained because a non-zero count is still
--     worth surfacing on a deployment nobody has measured.
--
--     The only other writer was the Go create path for an explicitly org-tier
--     policy, which is Enterprise-gated and unreachable from the portal.
--
-- So the column that SCOPED rows was not the column that SELECTED them, and
-- the selecting one was empty in practice. That is not a theoretical hazard:
-- #3334 records that it produced several wrong conclusions in two separate
-- pieces of work before anyone executed a query against a real database and
-- noticed. #3490 removed the last reader. This removes the column.
--
-- NOT IN SCOPE, and both deliberately:
--
--   * policy_evaluations.organization_id. It is an evaluation LOG, not a
--     selection input, and migration 090 explicitly declined to touch its
--     legacy columns ("leave organization_id UUID for legacy callers").
--     Nothing in the Decision-5 change reads it.
--   * customers.organization_id (enterprise/100, platform/database/006). A
--     different table with a different meaning -- it is the customer's
--     organisation NAME slug, NOT_NULL UNIQUE, and db_auth.go reads it to mint
--     a licence. Sharing a column name with the thing being retired is exactly
--     the confusion this migration exists to end, so it is named here rather
--     than left for the next reader to rediscover.
--
-- policy_overrides.valid_override_scope: the CHECK constraint core/030 created
-- is
--     (organization_id IS NOT NULL AND tenant_id IS NULL) OR (tenant_id IS NOT NULL)
-- Postgres drops a CHECK constraint automatically when a column it references
-- is dropped, so this migration does not need to name it -- but it asserts
-- afterwards that it is gone, because "it should have been dropped" and "it
-- was dropped" are different claims. It is NOT replaced, and BOTH halves of
-- that need saying, because the original argument was right about what it
-- covered and silent about what it did not.
--
--   * What it covered IS replaced. valid_override_scope existed to guarantee
--     every override row carries SOME organisation key. Migration 165's
--     NOT NULL + non-empty CHECK on org_id now guarantees that
--     unconditionally, for every row, rather than only for the org-scoped
--     half. Nothing is lost there.
--
--   * What it did NOT cover is tenant_id = ''. The old CHECK's second arm,
--     `tenant_id IS NOT NULL`, was satisfied by the empty string, so that
--     shape was never rejected -- but it was also never REACHABLE, because
--     the only way to reach a row with a non-NULL tenant_id was through the
--     organization_id half of the same constraint. Dropping the constraint
--     makes tenant_id = '' newly WRITABLE while nothing rejects it: 165
--     constrains org_id only (its header says tenant_id is deliberately left
--     alone, being on its way out), and the application guards only OrgID and
--     OverrideReason on the Create path.
--
-- That shape is neither scope. Every read predicate in
-- platform/agent/policy_override_repository.go is either `tenant_id = $N` or
-- `org_id = $N AND tenant_id IS NULL`; an empty string is not NULL, so it
-- fails the org arm, and no caller passes '' as a tenant, so it fails the
-- tenant arm. buildOverrideExistsQuery is built from the same two arms, so
-- the duplicate check cannot see such a row either. The result is a row that
-- can never be applied, never listed, never superseded and never deleted
-- through any scoped predicate -- it just accumulates.
--
-- So the tenant_id axis DOES need one constraint after all, and only one:
-- present = tenant scope, NULL = org scope, both legitimate; empty = neither,
-- and now rejected. This is not a new idea on these tables -- migration 155
-- gave static_policies and dynamic_policies exactly this CHECK, and
-- policy_overrides is simply the table it left out, because at the time
-- valid_override_scope looked like it was covering the same ground.
--
-- Cost: DROP COLUMN is metadata-only in Postgres. It does not rewrite the
-- table and does not scan it; the space is reclaimed by a later VACUUM. The
-- ACCESS EXCLUSIVE lock is held for the catalogue update only.
--
-- Idempotent: DROP COLUMN IF EXISTS throughout. Re-runs are no-ops.
--
-- Catalogue probes use pg_catalog, not information_schema, for the reason
-- migration 165's header records: the standard views are privilege-filtered,
-- so a role without a grant on the table sees the column as ABSENT, skips the
-- drop, and then skips the self-test that would have caught the skip. Measured
-- on a throwaway postgres:15 for a role with schema USAGE and no table grant:
-- information_schema.columns returns 0 where pg_catalog.pg_attribute returns 1.
-- The valid_override_scope check below already used pg_constraint.

BEGIN;

DO $$
DECLARE
    tbl        TEXT;
    populated  INTEGER;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['static_policies', 'dynamic_policies', 'policy_overrides']
    LOOP
        IF to_regclass('public.' || quote_ident(tbl)) IS NULL THEN
            RAISE NOTICE 'Migration 166: table % absent, skipping', tbl;
            CONTINUE;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                       WHERE attrelid = to_regclass('public.' || quote_ident(tbl))
                         AND attname = 'organization_id' AND attnum > 0
                         AND NOT attisdropped) THEN
            RAISE NOTICE 'Migration 166: %.organization_id already absent', tbl;
            CONTINUE;
        END IF;

        -- Report what is being dropped rather than dropping it silently. The
        -- expected count is ZERO on every deployment measured so far, and a
        -- non-zero count is worth an operator's attention even though the
        -- column has had no reader since #3490: it means somebody's org-tier
        -- policies were created through the one Go path that wrote it, and
        -- the down migration cannot bring those values back.
        EXECUTE format('SELECT COUNT(*) FROM %I WHERE organization_id IS NOT NULL', tbl)
            INTO populated;
        IF populated > 0 THEN
            RAISE WARNING 'Migration 166: %.organization_id held % non-null value(s), which are being dropped. Nothing has read this column since the org-keyed policy selection change (#3490), and org_id carries the organisation key for every row, so no selection changes here -- but these values are not recoverable by the down migration.', tbl, populated;
        ELSE
            RAISE NOTICE 'Migration 166: %.organization_id held no values (as expected); dropping', tbl;
        END IF;

        EXECUTE format('ALTER TABLE %I DROP COLUMN IF EXISTS organization_id', tbl);
    END LOOP;
END
$$;

-- Self-test. Guarded on the same table existence check as the block above so a
-- legacy schema the loop skipped cannot RAISE here and boot-loop the runner.
DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['static_policies', 'dynamic_policies', 'policy_overrides']
    LOOP
        IF to_regclass('public.' || quote_ident(tbl)) IS NULL THEN
            CONTINUE;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                   WHERE attrelid = to_regclass('public.' || quote_ident(tbl))
                     AND attname = 'organization_id' AND attnum > 0
                     AND NOT attisdropped) THEN
            RAISE EXCEPTION 'Migration 166 failed: %.organization_id still exists', tbl;
        END IF;

        -- org_id must still be there and still constrained. Dropping the
        -- legacy column must not have disturbed the key that replaced it.
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                       WHERE attrelid = to_regclass('public.' || quote_ident(tbl))
                         AND attname = 'org_id' AND attnum > 0 AND NOT attisdropped
                         AND attnotnull) THEN
            RAISE EXCEPTION 'Migration 166 failed: %.org_id is missing or nullable -- migration 165 must run first', tbl;
        END IF;
    END LOOP;

    -- valid_override_scope referenced the dropped column, so Postgres removes
    -- it as a dependency. Asserted rather than assumed: "it should have been
    -- dropped" and "it was dropped" are different claims, and a surviving
    -- constraint that references a dropped column would be a schema this
    -- migration did not intend to leave behind.
    IF to_regclass('public.policy_overrides') IS NOT NULL
       AND EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'public.policy_overrides'::regclass
                     AND conname = 'valid_override_scope') THEN
        RAISE EXCEPTION 'Migration 166 failed: policy_overrides.valid_override_scope survived the drop of the column it references';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- The one constraint the dropped CHECK's retirement actually leaves missing:
-- policy_overrides.tenant_id must never be the empty string. See the header.
--
-- HEAL FIRST, because ADD CONSTRAINT VALIDATES EXISTING ROWS. An install that
-- already carries a tenant_id = '' row would otherwise fail this migration and
-- be stuck: the operator cannot find the row through the portal (no read path
-- can see it), cannot delete it through the scoped delete predicates, and
-- cannot supersede it. Failing the upgrade on a row the product gives you no
-- way to remove is a dead end, so this heals and reports rather than aborting.
--
-- THE HEAL IS A DELETE, and the two gentler options were both considered and
-- rejected on this table specifically:
--
--   * Normalize to NULL, which is what migration 155 did for static_policies.
--     WRONG HERE. On policy_overrides NULL is not an inert value: it IS the
--     org-scope shape, matched by `org_id = $N AND tenant_id IS NULL`. So
--     normalizing would take a row that has never been applied to anything and
--     ACTIVATE it across the entire organisation. That is the same hazard 155
--     hit on dynamic_policies, where a bare NULL would have flipped rows from
--     "enforced for nobody" to "enforced for every tenant".
--   * Normalize to NULL and disable, which is how 155 defused exactly that
--     hazard. NOT AVAILABLE HERE. policy_overrides has no enabled switch;
--     enabled_override is the override's PAYLOAD (the value it forces onto the
--     target policy), so writing it would change what the override MEANS
--     rather than neutralise it.
--
-- Deleting a row that no read path can reach changes no enforcement, which is
-- the property the other two cannot offer. The rows are reported by primary
-- key and policy_id before they go, so an operator who did intend them can
-- recreate them with a real tenant.
--
-- The heal predicate is btrim()-based to match the CHECK exactly. A weaker
-- `tenant_id = ''` heal would leave a whitespace-only row behind for the
-- constraint to reject, which is the failure this whole block exists to avoid.
DO $$
DECLARE
    affected     TEXT;
    rows_deleted INTEGER;
BEGIN
    IF to_regclass('public.policy_overrides') IS NULL THEN
        RAISE NOTICE 'Migration 166: policy_overrides absent, skipping the tenant_id CHECK';
        RETURN;
    END IF;

    SELECT string_agg(format('%s (policy_id %s)', id, policy_id), ', ' ORDER BY id)
      INTO affected
      FROM policy_overrides
     WHERE tenant_id IS NOT NULL AND btrim(tenant_id) = '';

    DELETE FROM policy_overrides
     WHERE tenant_id IS NOT NULL AND btrim(tenant_id) = '';
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;

    IF rows_deleted > 0 THEN
        RAISE WARNING 'Migration 166: deleted % policy_overrides row(s) whose tenant_id was empty or whitespace-only. That shape is neither tenant scope nor org scope, so no read path could ever apply, list or supersede these rows and none of them has had any effect. They are removed rather than normalized because normalizing tenant_id to NULL would have turned each one into a LIVE organisation-wide override. Recreate them with a real tenant_id if they were intended. Deleted id(s): %', rows_deleted, affected;
    END IF;

    -- Drop-then-add rather than a NOT EXISTS guard, matching migration 165's
    -- idiom for its sibling org_id constraint: re-running this migration then
    -- re-asserts the CHECK's definition rather than trusting that an existing
    -- constraint of the same name says what this migration means.
    ALTER TABLE policy_overrides DROP CONSTRAINT IF EXISTS policy_overrides_tenant_id_not_empty;
    ALTER TABLE policy_overrides
        ADD CONSTRAINT policy_overrides_tenant_id_not_empty
        CHECK (tenant_id IS NULL OR btrim(tenant_id) <> '');
END
$$;

-- Self-test for the constraint above. "ALTER TABLE ran" and "the shape is
-- rejected" are different claims.
DO $$
BEGIN
    IF to_regclass('public.policy_overrides') IS NULL THEN
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'public.policy_overrides'::regclass
                     AND conname = 'policy_overrides_tenant_id_not_empty') THEN
        RAISE EXCEPTION 'Migration 166 failed: policy_overrides_tenant_id_not_empty was not created';
    END IF;

    IF EXISTS (SELECT 1 FROM policy_overrides
               WHERE tenant_id IS NOT NULL AND btrim(tenant_id) = '') THEN
        RAISE EXCEPTION 'Migration 166 failed: a policy_overrides row with an empty tenant_id survived the heal';
    END IF;
END
$$;

COMMIT;
