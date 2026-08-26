-- Migration 165: make the empty org key unrepresentable on the policy tables
-- Date: 2026-08-25
-- Issue: #3490 (Decision 5), tracked from #2989
--
-- Migration 156 made the empty tenancy key unrepresentable on the five
-- tenant-keyed tables that have no row-level security. It deliberately did
-- NOT cover the policy tables, because at the time policy SELECTION was
-- keyed on tenant_id and org_id was only the RLS isolation column: a row
-- with no org key was still reachable through the tenant leg of every
-- selection predicate, so constraining the column would have changed
-- nothing an operator could observe.
--
-- Decision 5 (#3490) removes the tenant leg. After it, org_id is the ONLY
-- thing that selects a policy row, on every plane and in every deployment
-- posture -- app-role (where RLS also keys on it) and owner-pool (where the
-- explicit `org_id = $n` predicate is the whole boundary). A row with a NULL
-- or empty org_id is then selected by NOBODY, which for a policy row means
-- silently unenforced. This migration lands FIRST, in its own change, so
-- that state stops being representable before the code that would be
-- confused by it ships.
--
-- Scope: static_policies, dynamic_policies, policy_overrides -- the three
-- tables whose org_id keys a Decision-5 selection predicate. Column: org_id
-- only. tenant_id is deliberately NOT constrained: Decision 5 demotes it to
-- attribution (client_id has carried the same value since mig 090), and
-- constraining a column on its way out would give it a durability it is not
-- meant to have.
--
-- NOT in scope: policy_evaluations. It is an evaluation LOG, not a
-- selection input -- no predicate in the Decision-5 change reads it -- and
-- mig 090 explicitly declined to touch its legacy columns.
--
-- Prior art on these same tables: migration 155 gave static_policies and
-- dynamic_policies a `tenant_id IS NULL OR tenant_id <> ''` CHECK. That is a
-- weaker shape than what org_id gets here, and deliberately so -- 155 was
-- closing the empty-STRING tenant, and a NULL tenant_id is a legitimate row
-- shape on dynamic_policies (the loader reads it as "applies to every
-- tenant"). org_id has no such wildcard: 'global' is spelled out, so NULL
-- means nothing but "missing".
--
-- THAT ASYMMETRY IS WHY STEP 2 BELOW EXISTS, and an earlier revision of this
-- migration got it wrong. It stamped a NULL-tenant dynamic_policies row with
-- the unowned sentinel, which SILENTLY DISABLED IT: on that table a NULL
-- tenant_id is the apply-to-every-tenant shape (refreshPolicies resolves it
-- to the 'default' sentinel and the gate treats 'default' as matching every
-- caller), so those rows govern everybody, not nobody. A policy that governed
-- every caller would have gone on governing none. On static_policies the same
-- NULL is NOT a wildcard -- every selection predicate there has always been
-- an equality against tenant_id, which NULL never satisfies -- so a
-- NULL-tenant static row was already selected by nobody and the sentinel is
-- the honest answer for it.
--
-- Staging: resolve, then constrain. Rows are never deleted.
--
--   1. tenant_id = 'global' -> org_id = 'global'. Migrations 153 and 154
--      already did this and 154 installed a BEFORE INSERT trigger to keep
--      doing it; repeated here so this migration's own invariant does not
--      depend on a trigger existing.
--   2. dynamic_policies ONLY: a NULL or empty tenant_id -> org_id = 'global'.
--      On that table the absent tenant is the apply-to-every-tenant shape,
--      not an absent owner (see the asymmetry note above). Deliberately NOT
--      applied to static_policies, where the same value has never been a
--      wildcard.
--   3. org_id resolved from `tenants` by the row's tenant_id, when that
--      mapping exists. This is the ONLY step that can produce an org key
--      different from the tenant id, and it is what keeps a row belonging
--      to a tenant of a multi-tenant org attached to the right org.
--   4. legacy collapse: org_id = tenant_id verbatim. The org_id == tenant_id
--      identity every v9 backfill (mig 094) and every agent write path
--      preserves for single-tenant orgs.
--   5. policy_overrides only: org_id resolved from `organizations` by the
--      legacy organization_id column, for an org-scoped override row (which
--      carries organization_id with tenant_id NULL and so cannot be resolved
--      by steps 2 to 4). Mirrors mig 110's own backfill chain.
--
--      THIS STEP IS A NEAR-NO-OP AND IS KEPT ONLY FOR EXACT PARITY WITH THE
--      CHAIN MIG 110 RAN. It joins `o.id::text = po.organization_id::text`,
--      but organizations.id is SERIAL -- an integer -- since mig 002 and was
--      never retyped, while policy_overrides.organization_id was uuid-typed
--      from mig 030 until mig 133 retyped it to text. An integer rendered as
--      text cannot equal a UUID rendered as text, so for every value that
--      existed before 133 this join matches NOTHING. It can only resolve
--      INTEGER-shaped values, which became representable in that column only
--      after 133. It was inherited verbatim from mig 110:57-61, where it was
--      equally dead. It is retained rather than deleted because removing it
--      would change the rescue chain relative to 110 without changing any
--      outcome, and a future reader comparing the two migrations should not
--      have to rediscover why they differ. Do not read it as a general
--      organization rescue: it is not one, and never was.
--   6. anything still unresolved is stamped '__axonflow_unowned__', the same
--      sentinel mig 156 used, which platform/shared/tenantscope refuses on
--      BOTH sides of every comparison.
--
-- BEHAVIOR CHANGE (deliberate, and the reason step 6 RAISEs a WARNING that
-- names the rows): a policy row that reaches step 6 carried no org key AND
-- no tenant key AND, for an override, no organization id. It was already
-- unreachable through every org-scoped read on an app-role deployment. On an
-- owner-pool deployment it was reachable only through the tenant leg that
-- Decision 5 removes, and only by a caller who named an empty tenant. After
-- this migration it is reachable by nobody, deterministically. For a POLICY
-- row that is a loosening -- a rule that used to be able to fire no longer
-- can -- so it must not be discovered after the upgrade. The v10 preflight
-- (scripts/deployment/v9_self_hosted_preflight.sh, check 24) reports the
-- same rows read-only BEFORE the image is pulled, which is where an operator
-- is supposed to see them.
--
-- LOCK SCOPE: every ALTER below runs in ONE transaction, so the ACCESS
-- EXCLUSIVE locks on all three tables are held until COMMIT. Size a window
-- for the sum, not the largest table. No table is REWRITTEN (neither SET NOT
-- NULL nor ADD CONSTRAINT ... CHECK changes on-disk row format), so each
-- verification scan is read-only and proportional to row count. These are
-- config-scale tables.
--
-- Idempotent: every UPDATE is WHERE-empty-guarded, SET NOT NULL on an
-- already-NOT NULL column is a no-op, and the CHECK is dropped before it is
-- added.
--
-- CATALOGUE PROBES USE pg_catalog, NOT information_schema. The SQL-standard
-- views are filtered by PRIVILEGE: they show only objects the current role owns
-- or holds a grant on. Every existence probe below decides whether to CONTINUE
-- (skip a table) or to RAISE (fail the self-test), so a role that cannot SEE
-- the column would skip the work AND skip the check that the work happened,
-- and the migration would report success having applied nothing. That is the
-- worst available outcome for a migration whose entire purpose is to make a
-- state unrepresentable.
--
-- Measured on a throwaway postgres:15 with this chain applied, for a role with
-- USAGE on the schema but no grant on the table:
--     information_schema.columns -> 0 rows
--     pg_catalog.pg_attribute    -> 1 row
-- pg_catalog is visibility-filtered, not privilege-filtered, so the probe
-- answers the question actually being asked ("does this column exist?")
-- rather than "may I read this column?". The constraint probes in this file
-- already used pg_constraint for the same reason; the column probes were the
-- inconsistent half. attnum > 0 excludes system columns and NOT attisdropped
-- excludes dropped-but-not-vacuumed ones, both of which pg_attribute retains
-- and information_schema hides.

BEGIN;

-- Sentinel used for rows that carry no tenancy key at all. Must stay in
-- lockstep with tenantscope.UnownedOrgSentinel (platform/shared/tenantscope)
-- and with migration 156, which introduced it.
DO $$
DECLARE
    unowned  CONSTANT TEXT := '__axonflow_unowned__';
    tbl      TEXT;
    resolved INTEGER;
    stamped  INTEGER;
    orphans  TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['static_policies', 'dynamic_policies', 'policy_overrides']
    LOOP
        IF to_regclass('public.' || quote_ident(tbl)) IS NULL THEN
            RAISE NOTICE 'Migration 165: table % absent, skipping', tbl;
            CONTINUE;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                       WHERE attrelid = to_regclass('public.' || quote_ident(tbl))
                         AND attname = 'org_id' AND attnum > 0 AND NOT attisdropped) THEN
            RAISE NOTICE 'Migration 165: %.org_id absent, skipping', tbl;
            CONTINUE;
        END IF;

        -- Step 1: the 'global' wildcard rows (mig 153/154).
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                   WHERE attrelid = to_regclass('public.' || quote_ident(tbl))
                     AND attname = 'tenant_id' AND attnum > 0 AND NOT attisdropped) THEN
            EXECUTE format(
                'UPDATE %I SET org_id = ''global'' WHERE tenant_id = ''global'' AND (org_id IS NULL OR btrim(org_id) = '''')',
                tbl);
            GET DIAGNOSTICS resolved = ROW_COUNT;
            IF resolved > 0 THEN
                RAISE NOTICE 'Migration 165: %.org_id set to global on % row(s)', tbl, resolved;
            END IF;

            -- Step 2: dynamic_policies ONLY. On that table an absent tenant is
            -- the APPLY-TO-EVERY-TENANT shape, not an absent owner:
            -- refreshPolicies resolves a NULL tenant_id to the 'default'
            -- sentinel and the applicability gate treats 'default' as matching
            -- every caller. Stamping such a row unowned would take a policy
            -- that governed EVERYBODY and make it govern nobody, silently.
            -- 'global' is the org spelling of the same intent and is already
            -- an all-orgs sentinel at that gate.
            --
            -- Deliberately NOT applied to static_policies. The same NULL has
            -- never been a wildcard there: every selection predicate on that
            -- table is an equality against tenant_id, which NULL does not
            -- satisfy, so a NULL-tenant static row was already selected by
            -- nobody and step 6's sentinel is the honest answer for it.
            IF tbl = 'dynamic_policies' THEN
                EXECUTE format(
                    'UPDATE %I SET org_id = ''global'' WHERE (org_id IS NULL OR btrim(org_id) = '''') AND COALESCE(btrim(tenant_id), '''') = ''''',
                    tbl);
                GET DIAGNOSTICS resolved = ROW_COUNT;
                IF resolved > 0 THEN
                    RAISE NOTICE 'Migration 165: %.org_id set to global on % apply-to-every-tenant row(s) (NULL or empty tenant_id)', tbl, resolved;
                END IF;
            END IF;

            -- Step 3: resolve through the tenants mapping. The only step
            -- that can yield an org key different from the tenant id.
            IF to_regclass('public.tenants') IS NOT NULL THEN
                EXECUTE format(
                    'UPDATE %I p SET org_id = t.org_id FROM tenants t
                      WHERE (p.org_id IS NULL OR btrim(p.org_id) = '''')
                        AND p.tenant_id IS NOT NULL AND btrim(p.tenant_id) <> ''''
                        AND t.tenant_id = p.tenant_id
                        AND t.org_id IS NOT NULL AND btrim(t.org_id) <> ''''',
                    tbl);
                GET DIAGNOSTICS resolved = ROW_COUNT;
                IF resolved > 0 THEN
                    RAISE NOTICE 'Migration 165: %.org_id resolved from tenants on % row(s)', tbl, resolved;
                END IF;
            END IF;

            -- Step 4: legacy org_id == tenant_id collapse.
            EXECUTE format(
                'UPDATE %I SET org_id = tenant_id
                  WHERE (org_id IS NULL OR btrim(org_id) = '''')
                    AND tenant_id IS NOT NULL AND btrim(tenant_id) <> ''''',
                tbl);
            GET DIAGNOSTICS resolved = ROW_COUNT;
            IF resolved > 0 THEN
                RAISE NOTICE 'Migration 165: %.org_id collapsed from tenant_id on % row(s)', tbl, resolved;
            END IF;
        END IF;

        -- Step 5: policy_overrides org-scoped rows carry organization_id with
        -- tenant_id NULL, so steps 2 and 3 cannot see them. Same chain mig
        -- 110 used. Guarded on the column still existing because migration
        -- 166 drops it -- a deployment that applies 165 and 166 in one boot
        -- runs this while the column is present, but a re-run after 166 must
        -- not fail.
        IF tbl = 'policy_overrides'
           AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                       WHERE attrelid = to_regclass('public.policy_overrides')
                         AND attname = 'organization_id' AND attnum > 0 AND NOT attisdropped)
           AND to_regclass('public.organizations') IS NOT NULL THEN
            UPDATE policy_overrides po SET org_id = o.org_id
             FROM organizations o
            WHERE (po.org_id IS NULL OR btrim(po.org_id) = '')
              AND po.organization_id IS NOT NULL
              AND o.id::text = po.organization_id::text
              AND o.org_id IS NOT NULL AND btrim(o.org_id) <> '';
            GET DIAGNOSTICS resolved = ROW_COUNT;
            IF resolved > 0 THEN
                RAISE NOTICE 'Migration 165: policy_overrides.org_id resolved from organizations on % row(s)', resolved;
            END IF;
        END IF;

        -- Step 6: stamp whatever is left, and NAME it. A policy row that
        -- lands here stops being able to fire (see the header); the operator
        -- gets the identifiers, not just a count.
        EXECUTE format(
            'SELECT COUNT(*) FROM %I WHERE org_id IS NULL OR btrim(org_id) = ''''', tbl)
            INTO stamped;
        IF stamped > 0 THEN
            -- policy_overrides is reported by `id`, its UUID PRIMARY KEY.
            -- Its policy_id is a NON-UNIQUE FK to the policy being overridden
            -- (core/030:73 vs :76), so two different overrides of the same
            -- policy print the SAME identifier -- observed on a live run as
            -- `Rows: 3bfcc002-..., 3bfcc002-...`, which an operator cannot act
            -- on. static_policies and dynamic_policies keep policy_id, where it
            -- is the human-meaningful identifier.
            IF tbl <> 'policy_overrides'
               AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                       WHERE attrelid = to_regclass('public.' || quote_ident(tbl))
                         AND attname = 'policy_id' AND attnum > 0 AND NOT attisdropped) THEN
                EXECUTE format(
                    'SELECT string_agg(policy_id::text, '', '' ORDER BY policy_id::text)
                       FROM %I WHERE org_id IS NULL OR btrim(org_id) = ''''', tbl)
                    INTO orphans;
            ELSE
                EXECUTE format(
                    'SELECT string_agg(id::text, '', '' ORDER BY id::text)
                       FROM %I WHERE org_id IS NULL OR btrim(org_id) = ''''', tbl)
                    INTO orphans;
            END IF;
            EXECUTE format(
                'UPDATE %I SET org_id = %L WHERE org_id IS NULL OR btrim(org_id) = ''''', tbl, unowned);
            RAISE WARNING 'Migration 165: %.org_id -- % row(s) carried no org key, no tenant key and no resolvable organization, and are now stamped %. They can no longer be selected by any caller. Rows: %',
                tbl, stamped, unowned, orphans;
        END IF;

        -- Drop any DEFAULT that could recreate the empty value. None of the
        -- three columns carries one today (mig 010 declared org_id bare,
        -- mig 110 added it bare); this is the same defensive step mig 156
        -- took after webhook_subscriptions turned out to have DEFAULT ''.
        EXECUTE format('ALTER TABLE %I ALTER COLUMN org_id DROP DEFAULT', tbl);

        -- Constrain. NOT NULL alone still admits the empty string, which is
        -- the value that actually reaches a selection predicate.
        EXECUTE format('ALTER TABLE %I ALTER COLUMN org_id SET NOT NULL', tbl);
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT IF EXISTS %I', tbl, tbl || '_org_id_not_empty');
        EXECUTE format(
            'ALTER TABLE %I ADD CONSTRAINT %I CHECK (btrim(org_id) <> %L)',
            tbl, tbl || '_org_id_not_empty', '');
    END LOOP;
END
$$;

-- Self-test: prove the invariant on every table the block actually
-- processed. Guarded on the same existence checks so a legacy schema the
-- loop skipped cannot RAISE here and boot-loop the migration runner.
DO $$
DECLARE
    tbl       TEXT;
    offenders INTEGER;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['static_policies', 'dynamic_policies', 'policy_overrides']
    LOOP
        IF to_regclass('public.' || quote_ident(tbl)) IS NULL THEN
            CONTINUE;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                       WHERE attrelid = to_regclass('public.' || quote_ident(tbl))
                         AND attname = 'org_id' AND attnum > 0 AND NOT attisdropped) THEN
            CONTINUE;
        END IF;

        EXECUTE format('SELECT COUNT(*) FROM %I WHERE org_id IS NULL OR btrim(org_id) = ''''', tbl)
            INTO offenders;
        IF offenders > 0 THEN
            RAISE EXCEPTION 'Migration 165 failed: %.org_id still has % row(s) with no org key', tbl, offenders;
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_attribute
            WHERE attrelid = to_regclass('public.' || quote_ident(tbl))
              AND attname = 'org_id' AND attnum > 0 AND NOT attisdropped
              AND attnotnull) THEN
            RAISE EXCEPTION 'Migration 165 failed: %.org_id is still nullable', tbl;
        END IF;

        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_attribute
            WHERE attrelid = to_regclass('public.' || quote_ident(tbl))
              AND attname = 'org_id' AND attnum > 0 AND NOT attisdropped
              AND atthasdef) THEN
            RAISE EXCEPTION 'Migration 165 failed: %.org_id still has a DEFAULT, which would recreate the empty org key', tbl;
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = format('public.%I', tbl)::regclass
              AND conname = tbl || '_org_id_not_empty') THEN
            RAISE EXCEPTION 'Migration 165 failed: %.org_id is missing its non-empty CHECK constraint', tbl;
        END IF;
    END LOOP;
END
$$;

COMMIT;
