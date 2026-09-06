-- Migration 170: backfill the explicit application grants every FORCE-RLS table
--                in migrations/core was missing (#3636)
-- Date: 2026-09-02
--
-- EDITION: core. THE SPLIT IS BY WHAT FORCES A TABLE, NOT BY WHAT CREATES IT,
--          and that distinction is load-bearing rather than pedantic. Three of
--          the tables named below are created by an Enterprise migration -
--          `agent_heartbeats` (enterprise/101), `node_violations`
--          (enterprise/105) and `customers` (enterprise/100) - but each is
--          FORCED by a core, mirrored file, so the census that reads those
--          files demands a grant in every tree the census ships to, the
--          community mirror included. A grant written in enterprise/151 cannot
--          satisfy it there, because the mirror does not carry
--          migrations/enterprise at all. `to_regclass` makes each statement
--          inert where the table does not exist, so naming them here costs
--          nothing at runtime.
--
--          The remaining Enterprise tables - those forced by an Enterprise
--          migration - stay in enterprise/151, deliberately NOT here:
--          migrations/core is published to the community mirror, and naming a
--          table whose FORCE is Enterprise-only would leak the Enterprise
--          schema into the community tree for no corresponding benefit.
--
-- ════════════════════════════════════════════════════════════════════════════
-- WHY A NEW MIGRATION RATHER THAN AN EDIT TO EACH ONE
-- ════════════════════════════════════════════════════════════════════════════
--
-- Because an edit reaches fresh installs ONLY, which is the opposite of what
-- this fixes. The runner skips before it reads: in platform/agent/run.go's
-- apply loop the os.ReadFile sits AFTER
-- `if appliedMigrations[migrationKey(...)] { continue }`; the key is
-- version+"/"+name derived from the FILENAME; and schema_migrations.checksum
-- exists in the DDL but is never written by recordMigrationSuccess. So editing
-- a migration's content changes nothing about whether it runs. Every deployment
-- that already applied these would never receive the grants - and a deployment
-- that has already applied them is the only kind the scenario below could
-- affect. technical-docs/
-- MIGRATION_SYSTEM_COMPLETE_GUIDE.md states the rule; this is the measured
-- reason behind it.
--
-- ════════════════════════════════════════════════════════════════════════════
-- WHAT THIS IS, MEASURED: DEFENCE IN DEPTH, NOT A CLOSED GAP
-- ════════════════════════════════════════════════════════════════════════════
--
-- An earlier draft of this migration claimed it closed a live permission gap.
-- It does not, and the correction is recorded here rather than quietly dropped.
--
-- Rendered from a FRESH in-vpc-enterprise chain, reading has_table_privilege
-- rather than reading the migration sources: 125 tables, 26 of them under FORCE
-- ROW LEVEL SECURITY, and ZERO lacking axonflow_app_role's SELECT or INSERT.
-- core/098 grants `ON ALL TABLES` for everything that exists when it runs and
-- `ALTER DEFAULT PRIVILEGES` for everything the same owner creates afterwards,
-- so on the single-owner path - which is the only path this repository can
-- demonstrate - every table is already reachable.
--
-- The scenario these grants protect against is a deployment whose MIGRATION
-- CREDENTIAL changed between releases, leaving later tables owned by a role
-- that core/098's default privileges do not follow. That is an operations fact
-- about a live fleet, not a repository fact: each deployment carries one
-- DATABASE_URL, and whether any operator has rotated it cannot be established
-- from here. So this migration is written as insurance against a state nobody
-- has evidenced rather than as a repair of one that has been observed, and
-- every claim about it is scaled accordingly.
--
-- It is cheap insurance: the privilege set is EXACTLY what core/098 declares as
-- the default for every table, so it restores the intended baseline where that
-- baseline is missing and is a no-op everywhere else. It cannot widen anything.
--
-- THE TABLE LIST IS RENDERED, NOT GREPPED. It is the FORCE-RLS set read back
-- from a live chain, and that matters because the grep-derived list an earlier
-- draft used was wrong in both directions: it included role_assignments,
-- which the live chain does not force, and it omitted compliance_report_jobs
-- and sso_sessions, which it does. `api_keys` and `customers` are named here
-- even though the live render shows neither FORCED: core/108 forces both
-- CONDITIONALLY, so a deployment that takes that branch has them forced while
-- the rendered chain does not, and the source-reading census sees the
-- statement either way.
--
BEGIN;

DO $$
DECLARE
    t       text;
    r       text;
    attempted integer := 0;
    succeeded integer := 0;
    refused   integer := 0;
    skipped   integer := 0;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'api_keys',                       -- core/002 (core/108 forces it conditionally)
        'customers',                      -- enterprise/100, forced by core/108
        'audit_archive',                  -- core/099
        'deployment_upgrades',            -- core/099
        'saml_configurations',            -- core/099
        'audit_retention_config',         -- core/101
        'decision_chain',                 -- core/101
        'mcp_query_audits',               -- core/101
        'organizations',                  -- core/103
        'tenants',                        -- core/103
        'community_saas_registrations',   -- core/105
        'sso_configurations',             -- core/106
        'sso_login_attempts',             -- core/106
        'agent_heartbeats',               -- enterprise/101, forced by core/107
        'connector_configs',              -- core/107
        'connectors',                     -- core/107
        'node_violations',                -- enterprise/105, forced by core/107
        'idempotency_keys',               -- core/115
        'detection_action_overrides',     -- core/120
        'sso_sessions',                   -- core/145
        'identity_realm_epochs',          -- core/169
        'identity_trust_realms'           -- core/169
    ] LOOP
        IF to_regclass(t) IS NULL THEN
            skipped := skipped + 1;
            CONTINUE;
        END IF;
        FOREACH r IN ARRAY ARRAY['axonflow_app_role', 'axonflow_platform_admin'] LOOP
            CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r);
            -- A GRANT REQUIRES OWNERSHIP, AND THIS MIGRATION MAY NOT OWN THE
            -- TABLE. That is not a hypothetical: it is the very deployment this
            -- migration is for. A credential rotation leaves earlier tables
            -- owned by the previous role, and `GRANT ... ON audit_archive`
            -- raises `permission denied for table audit_archive` for the new
            -- one - which, unhandled, would ABORT the whole run and leave the
            -- deployment worse off than the gap being fixed. Measured on a live
            -- Postgres, not reasoned about.
            --
            -- Tolerating it is also CORRECT rather than merely convenient. A
            -- table this role does not own was created by the role that does,
            -- and on that deployment core/098's default privileges - which bind
            -- to that same owner - already granted it. The tables this role
            -- CAN grant are exactly the ones it created, which are exactly the
            -- ones the defaults missed.
            --
            -- Not silent: every table left unreachable is reported below with
            -- the statement its owner must run.
            --
            -- COUNTED BY OUTCOME, not by iteration. An earlier revision
            -- incremented once per TABLE regardless of whether the GRANT
            -- landed, so on the split-owner deployment this migration exists
            -- for it announced "grants ensured on N table(s)" immediately
            -- before the WARNING listing the tables it could not reach. A
            -- count that cannot distinguish success from a swallowed refusal
            -- describes the loop rather than the outcome, which is exactly
            -- what an operator reads it for.
            attempted := attempted + 1;
            BEGIN
                EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO %I', t, r);
                succeeded := succeeded + 1;
            EXCEPTION WHEN insufficient_privilege THEN
                refused := refused + 1;
            END;
        END LOOP;
    END LOOP;

    RAISE NOTICE 'migration 170: % (role, table) grant(s) attempted - % succeeded, % refused for want of ownership; % table(s) absent from this deployment and skipped. A non-zero refused count is not itself a failure: see the verification WARNING below for any pair that is STILL unreachable.',
                 attempted, succeeded, refused, skipped;
END
$$;

-- Verification: fail loudly if a table that EXISTS did not end up reachable.
--
-- has_table_privilege rather than a did-it-run flag: the question an operator
-- needs answered is whether the application role can reach the table, and only
-- the privilege itself answers that. Per table and per role, so a failure names
-- the pair rather than reporting "a grant failed".
DO $$
DECLARE
    t           text;
    r           text;
    confirmed   integer := 0;
    unreachable text[] := ARRAY[]::text[];
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'api_keys',                       -- core/002 (core/108 forces it conditionally)
        'customers',                      -- enterprise/100, forced by core/108
        'audit_archive',                  -- core/099
        'deployment_upgrades',            -- core/099
        'saml_configurations',            -- core/099
        'audit_retention_config',         -- core/101
        'decision_chain',                 -- core/101
        'mcp_query_audits',               -- core/101
        'organizations',                  -- core/103
        'tenants',                        -- core/103
        'community_saas_registrations',   -- core/105
        'sso_configurations',             -- core/106
        'sso_login_attempts',             -- core/106
        'agent_heartbeats',               -- enterprise/101, forced by core/107
        'connector_configs',              -- core/107
        'connectors',                     -- core/107
        'node_violations',                -- enterprise/105, forced by core/107
        'idempotency_keys',               -- core/115
        'detection_action_overrides',     -- core/120
        'sso_sessions',                   -- core/145
        'identity_realm_epochs',          -- core/169
        'identity_trust_realms'           -- core/169
    ] LOOP
        CONTINUE WHEN to_regclass(t) IS NULL;
        FOREACH r IN ARRAY ARRAY['axonflow_app_role', 'axonflow_platform_admin'] LOOP
            CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r);
            IF has_table_privilege(r, t, 'SELECT') AND has_table_privilege(r, t, 'INSERT') THEN
                confirmed := confirmed + 1;
                CONTINUE;
            END IF;
            -- Still unreachable. This is a WARNING and not an exception,
            -- because the one state that produces it is a table this migration
            -- role cannot grant on - and refusing to apply would leave the
            -- deployment with neither this migration nor the grants it CAN
            -- make. It carries the owner and the exact statement, because an
            -- operator reading "permission denied for table X" at runtime has
            -- no way back to this line otherwise.
            unreachable := unreachable || format('%s on %s (owned by %s)', r, t,
                COALESCE((SELECT pg_get_userbyid(relowner) FROM pg_catalog.pg_class WHERE oid = t::regclass), 'unknown'));
        END LOOP;
    END LOOP;

    IF array_length(unreachable, 1) IS NOT NULL THEN
        RAISE WARNING 'migration 170: these (role, table) pairs are STILL unreachable, because this migration role does not own the table and cannot grant on it: %. On a deployment where the migration credential never changed this cannot happen. Where it did, run as each table''s owner: GRANT SELECT, INSERT, UPDATE, DELETE ON <table> TO <role>;', array_to_string(unreachable, ', ');
    END IF;

    -- Anti-vacuity. On a deployment that has the application role AND the core
    -- schema, confirming ZERO pairs means the loop checked nothing, and this
    -- block would report success for a migration that did not run.
    IF confirmed = 0
       AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_app_role')
       AND to_regclass('organizations') IS NOT NULL THEN
        RAISE EXCEPTION 'Migration 170 failed: no (role, table) pair was verified on a deployment that has both the application role and the core schema; the verification loop checked nothing';
    END IF;

    RAISE NOTICE 'Migration 170 verified: % (role, table) pair(s) confirmed reachable', confirmed;
END
$$;

COMMIT;
