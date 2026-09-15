-- Migration 175: promote_deployment_org_license REPORTS the row it wrote
-- Date: 2026-09-10
-- Depends: 117_promote_deployment_org_license, 142_timestamp_columns_to_timestamptz
--
-- ============================================================================
-- Why this exists (#3957 item 1)
-- ============================================================================
-- The licensed tier reaches the database through exactly one path - the agent's
-- boot-time promoteDeploymentOrgTier - and until now nothing checked that it
-- arrived. Migration 094 seeds the deployment org at tier='Community',
-- max_nodes=2 with ON CONFLICT DO NOTHING; the licensed values arrive only
-- through this helper, whose failure is logged and non-fatal by design.
--
-- So a licensed Enterprise deployment whose promotion did not land reads
-- Community / 2 nodes, and ABSENCE IS DETECTABLE WHERE A PLAUSIBLE WRONG VALUE
-- IS NOT. The consequence is not cosmetic: node_enforcement/monitor.go:121
-- reads organizations.max_nodes and writes a LICENCE VIOLATION row for every
-- node past the cap, so on a fully licensed deployment holding max_nodes=2,
-- node three onwards is recorded as infringing. The portal's licence page, its
-- node pages and its admin tier read the same row.
--
-- ============================================================================
-- Why the FUNCTION reports it, and not a SELECT in the agent
-- ============================================================================
-- The obvious fix is for the agent to SELECT the row back after calling this
-- helper. That fix rests on a precondition nobody has established: `organizations`
-- carries FORCE ROW LEVEL SECURITY (mig 103) - which binds the table OWNER too,
-- not only non-owners - under a policy keyed on
-- `current_setting('app.current_org_id', true)`, and the agent's migration
-- connection never sets that GUC (it sets app.db_password, app.deployment_org_id
-- and app.deployment_kind, and nothing else - run.go setMigrationSessionVars).
--
-- If that precondition is false, a SELECT-back returns ZERO ROWS on a perfectly
-- healthy deployment and the agent reports "the licensed tier reached nothing"
-- on every boot. A guard that fires on healthy deployments is one that gets
-- switched off, which is strictly worse than the silence it replaced.
--
-- It cannot be settled by reading the tree, and this is worth stating because
-- it looks settled: migrations 146, 148, 149, 151 and 165 all read
-- `organizations` unfiltered AFTER 103 applied FORCE RLS, and every one of them
-- is SILENTLY SATISFIED by seeing nothing - 146 loops over zero organizations,
-- 149 counts zero orphans, 145 only RAISEs a WARNING. Those are vacuous
-- negatives, not evidence of visibility.
--
-- So the read moves INSIDE the SECURITY DEFINER function, where it inherits
-- EXACTLY the privilege posture the write already has. Whatever lets the INSERT
-- happen lets the SELECT see the result; if the owner cannot see the row then
-- the INSERT could not have happened either, and the function returns no rows -
-- which is the honest answer rather than a guess. One call, one posture, and no
-- dependency on a fact nobody measured.
--
-- ============================================================================
-- Why DROP + CREATE and not CREATE OR REPLACE
-- ============================================================================
-- CREATE OR REPLACE FUNCTION cannot change a function's RETURN TYPE, exactly as
-- it cannot change an argument type. Migration 142 hit the argument-type half of
-- this same wall when organizations.expires_at became TIMESTAMPTZ, and dropped
-- the old signature first for the same reason; this follows that precedent
-- rather than inventing one.
--
-- THAT REASONING APPLIED WHEN THIS MIGRATION REDEFINED THE OLD NAME, AND IT NO
-- LONGER DOES (#4007). The return type does not move: the old name keeps 142's
-- (VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ) -> VOID exactly, and the TABLE form
-- lives under promote_deployment_org_license_returning. The DROP+CREATE above
-- is still required, for a different reason - clearing BOTH overloads so the
-- name is unambiguous - and the return-type wall is why the old name is a
-- forwarder rather than a redefinition. See "TWO NAMES, ONE BODY" above.
--
-- TWO NAMES, ONE BODY (#4007). This migration first REUSED the old name with a
-- new return type, arguing that a second function promoting the same row is the
-- redundancy this repository keeps paying for. The argument was against a second
-- BODY and it still holds; what it missed is that 142 CREATES this exact
-- signature as RETURNS VOID, and seven migration tests in platform/agent re-run
-- their migration's up and down at the fully-migrated state. Redefining 142's
-- signature with a different return type makes 142 un-re-runnable
-- ("cannot change return type of existing function"), which is what the Real-PG
-- lane caught the first time it ran after #3972.
--
-- So the implementation moves to promote_deployment_org_license_returning and
-- the old name stays exactly as 142 defines it - same signature, RETURNS VOID -
-- forwarding to the new one. There is one promoter body.
--
-- A ROLLING UPGRADE IS SAFE IN BOTH DIRECTIONS:
--   - An OLD agent binary calls `SELECT promote_deployment_org_license(...)`.
--     The forwarder is VOID, exactly what that binary has always called.
--   - A NEW agent binary reads the row from the _returning name. Against a
--     schema WITHOUT this migration that name does not exist, the agent
--     classifies it as a failed promotion and reports it - correct, because
--     that deployment has not run 175.
--   - Re-running 142 replaces the forwarder with 142's own VOID body. Same
--     return type, so it succeeds; same promotion semantics, so
--     assertPromoteFunctional still holds.
--
-- ============================================================================
-- The table-exists guard, corrected
-- ============================================================================
-- 117 and 142 both guard the body with
--     IF EXISTS (SELECT 1 FROM information_schema.tables
--                WHERE table_name = 'organizations')
-- which asks about a table of that name in ANY schema the caller can see, while
-- the INSERT below targets `public.organizations` (search_path is locked to
-- public, pg_temp). The guard is qualified with table_schema = 'public' here so
-- it asks about the table the statement actually writes.
--
-- That guard is also the reason the old VOID signature could not be verified
-- from Go at all: when it was false the function RETURNED SUCCESSFULLY HAVING
-- WRITTEN NOTHING, db.Exec reported no error, and the agent logged a tick. The
-- TABLE return makes that state observable - it comes back as zero rows.
--
-- ============================================================================
-- Idempotency
-- ============================================================================
-- The upsert keeps 117's ON CONFLICT DO UPDATE ... WHERE (tier|max_nodes|
-- expires_at) IS DISTINCT FROM EXCLUDED guard, so a re-boot with the same
-- licence still writes nothing. The RETURN QUERY runs regardless, so an
-- already-correct row is reported as correct rather than as "no write
-- happened" - the two were indistinguishable before and only one of them is a
-- problem.

BEGIN;

-- BOTH SIGNATURES, NOT ONLY THE CURRENT ONE (#4007). 117 created this function
-- as (VARCHAR, VARCHAR, INTEGER, TIMESTAMP) and 142 retyped it to TIMESTAMPTZ by
-- dropping the TIMESTAMP form first. On any path where that drop did not take -
-- which the 142->133 upgrade path exercises - BOTH overloads are live when this
-- migration runs, and every unqualified reference to the name then raises
-- `function name "promote_deployment_org_license" is not unique`. Dropping the
-- pre-142 form here makes the name unambiguous by construction rather than by
-- assuming an earlier migration's drop matched.
DROP FUNCTION IF EXISTS promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMP);
DROP FUNCTION IF EXISTS promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ);

CREATE OR REPLACE FUNCTION promote_deployment_org_license_returning(
    p_org_id     VARCHAR(255),
    p_tier       VARCHAR(50),
    p_max_nodes  INTEGER,
    p_expires_at TIMESTAMPTZ DEFAULT NULL
) RETURNS TABLE (
    -- Types mirror organizations exactly (mig 002 + mig 142's retype). A
    -- mismatch here is a runtime "structure of query does not match function
    -- result type", not a migration-time error, so it would surface as a failed
    -- promotion on a live deployment.
    out_tier       VARCHAR(50),
    out_max_nodes  INTEGER,
    out_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    -- Zero rows, not an exception: a schema with no organizations table is a
    -- state the caller must be able to report, and raising here would turn a
    -- non-fatal boot step into a fatal one.
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'organizations'
    ) THEN
        RETURN;
    END IF;

    INSERT INTO organizations (org_id, name, tier, max_nodes, license_key, expires_at)
    VALUES (p_org_id, p_org_id, p_tier, p_max_nodes, '', p_expires_at)
    ON CONFLICT (org_id) DO UPDATE SET
        tier       = EXCLUDED.tier,
        max_nodes  = EXCLUDED.max_nodes,
        expires_at = EXCLUDED.expires_at,
        updated_at = CURRENT_TIMESTAMP
    WHERE organizations.tier       IS DISTINCT FROM EXCLUDED.tier
       OR organizations.max_nodes  IS DISTINCT FROM EXCLUDED.max_nodes
       OR organizations.expires_at IS DISTINCT FROM EXCLUDED.expires_at;

    -- The whole point of this migration. Read INSIDE the function, so the read
    -- has the write's privileges and not the caller's.
    RETURN QUERY
        SELECT o.tier, o.max_nodes, o.expires_at
        FROM organizations o
        WHERE o.org_id = p_org_id;
END;
$$;

-- ============================================================================
-- The OLD name, kept at 142's exact signature and RETURNS VOID (#4007)
-- ============================================================================
-- ONE BODY, TWO NAMES - not two promoters. Everything above is the single
-- implementation; this is a thin forwarder that calls it and discards the row.
--
-- WHY THE OLD NAME MUST STAY `RETURNS VOID`. Seven migration tests in
-- platform/agent re-run their migration's up and down at the FULLY MIGRATED
-- state; that is what this repository means by idempotent, and it is what makes
-- a `_down` usable for incident rollback at the current schema. 142's test pins
-- it for 142. If this migration redefined 142's own signature with a different
-- return type, re-running 142 would hit `cannot change return type of existing
-- function` - which is exactly what #4007 caught on the first run of the
-- Real-PG lane after #3972 made it reachable.
--
-- With the forwarder, a re-run of 142 does CREATE OR REPLACE ... RETURNS VOID
-- over a function that is ALREADY RETURNS VOID: the return type is unchanged,
-- so it succeeds, and 142's own body replaces this one with identical
-- promotion semantics. Callers that need the row use the _returning name.
CREATE OR REPLACE FUNCTION promote_deployment_org_license(
    p_org_id     VARCHAR(255),
    p_tier       VARCHAR(50),
    p_max_nodes  INTEGER,
    p_expires_at TIMESTAMPTZ DEFAULT NULL
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    PERFORM * FROM promote_deployment_org_license_returning(
        p_org_id, p_tier, p_max_nodes, p_expires_at);
END;
$$;

COMMENT ON FUNCTION promote_deployment_org_license_returning(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ) IS
    'SECURITY DEFINER upsert that promotes the deployment org''s organizations '
    'row to its licensed tier/max_nodes/expires_at, and RETURNS the row as it '
    'stands after the write (#3957). Bypasses FORCE RLS on organizations '
    '(mig 103) for the agent boot-time license-tier sync (#2535). The read is '
    'inside the function so it inherits the write''s privilege posture rather '
    'than the caller''s, which FORCE RLS would otherwise apply. Zero rows means '
    'the licensed values are not readable - the honest answer, and the state the '
    'previous VOID signature reported as success. '
    'p_expires_at is TIMESTAMPTZ as of mig 142 (#2876).';

-- ============================================================================
-- Privilege model: REVOKE PUBLIC + GRANT axonflow_app_role
-- ============================================================================
-- DROP discards the old grants, so they are re-established here. Same posture
-- as 117 and 142; the role probe guards local-dev installs without mig 098.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE EXECUTE ON FUNCTION promote_deployment_org_license_returning(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ) FROM PUBLIC;
        GRANT  EXECUTE ON FUNCTION promote_deployment_org_license_returning(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ) TO axonflow_app_role;
        -- The forwarder too: an old binary still calls the old name, and the
        -- DROP above discarded its grants along with the function.
        REVOKE EXECUTE ON FUNCTION promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ) FROM PUBLIC;
        GRANT  EXECUTE ON FUNCTION promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ) TO axonflow_app_role;
        RAISE NOTICE 'Migration 175: granted EXECUTE on promote_deployment_org_license to axonflow_app_role';
    ELSE
        RAISE NOTICE 'Migration 175: axonflow_app_role not present (mig 098 not yet run on this DB); promote_deployment_org_license installed but unbound';
    END IF;
END
$$;

-- ============================================================================
-- Smoke verification
-- ============================================================================
-- Asserts the three properties this migration exists to establish, at apply
-- time, so a schema that silently kept 142's VOID form fails the migration
-- rather than the boot step that depends on it.
DO $$
DECLARE
    v_secdef  BOOLEAN;
    v_retset  BOOLEAN;
    v_rettype TEXT;
    v_config  TEXT[];
    v_public  BOOLEAN;
    v_approle BOOLEAN;
BEGIN
    -- STRICT: a missing function must raise NO_DATA_FOUND here rather than
    -- leaving v_secdef NULL and relying on the IS NULL arm below, and a
    -- DUPLICATE (two overloads after a botched DROP) must raise rather than
    -- silently reporting whichever row came back first. Without STRICT this
    -- block cannot distinguish "absent" from "ambiguous".
    SELECT p.prosecdef, p.proretset, pg_catalog.format_type(p.prorettype, NULL), p.proconfig
      INTO STRICT v_secdef, v_retset, v_rettype, v_config
    FROM pg_proc p
    WHERE p.proname = 'promote_deployment_org_license_returning'
      AND p.pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');

    IF v_secdef IS NULL THEN
        RAISE EXCEPTION 'Migration 175 failed: promote_deployment_org_license_returning not found in public schema';
    END IF;
    IF NOT v_secdef THEN
        RAISE EXCEPTION 'Migration 175 failed: promote_deployment_org_license_returning is NOT SECURITY DEFINER (prosecdef=false) - the read would then run with the CALLER''s privileges, which FORCE RLS applies to';
    END IF;
    IF NOT v_retset THEN
        RAISE EXCEPTION 'Migration 175 failed: promote_deployment_org_license_returning does not return a set (proretset=false, rettype=%) - the DROP+CREATE did not take and the agent cannot verify the promotion', v_rettype;
    END IF;
    -- SECURITY DEFINER WITHOUT A PINNED search_path IS THE HAZARD, NOT A
    -- SEPARATE NICETY. The body resolves `organizations` and
    -- `information_schema.tables` unqualified; a caller who can set search_path
    -- could otherwise point those at objects of their own and have them
    -- resolved with the OWNER's privileges. 117 and 142 both pin it and so does
    -- this migration - assert the pin actually landed rather than trusting the
    -- CREATE, because a later CREATE OR REPLACE that drops the SET clause is
    -- invisible to every other check here.
    IF v_config IS NULL OR NOT (v_config @> ARRAY['search_path=public, pg_temp']) THEN
        RAISE EXCEPTION 'Migration 175 failed: promote_deployment_org_license_returning is SECURITY DEFINER with no pinned search_path (proconfig=%) - unqualified names in its body would resolve against the CALLER''s search_path with the OWNER''s privileges', v_config;
    END IF;

    -- EXECUTE must not be held by PUBLIC -- BUT ONLY WHERE THE REVOKE ACTUALLY
    -- RAN, and getting that wrong is why this assertion is written this way.
    --
    -- The first version asserted it unconditionally and ABORTED THE MIGRATION on
    -- a database with no axonflow_app_role. That is not a broken deployment: the
    -- GRANT block above is guarded by a role probe, exactly as 117 and 142 guard
    -- theirs, and their own NOTICE calls the outcome "installed but unbound" -- a
    -- local dev database that has not run mig 098. A DROP+CREATE restores the
    -- default PUBLIC grant, so where the probe skips, PUBLIC legitimately still
    -- holds EXECUTE and nothing is wrong. Asserting otherwise converted a
    -- deliberate, precedented shape into a boot-blocking failure: a fail-closed
    -- guard prescribing a remedy for a case it had misclassified.
    --
    -- Measured, not reasoned: the unconditional form failed the apply on the
    -- realpg fixture, whose schema subset omits mig 098 for the same reason.
    --
    -- So the assertion is bound to the same condition as the REVOKE. Where the
    -- role exists, BOTH halves are checked -- PUBLIC must not hold EXECUTE and
    -- the app role must -- because "revoked from everyone including the caller"
    -- and "correctly bound" are different states and only one of them works.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        SELECT has_function_privilege('public', p.oid, 'EXECUTE'),
               has_function_privilege('axonflow_app_role', p.oid, 'EXECUTE')
          INTO STRICT v_public, v_approle
        FROM pg_proc p
        WHERE p.proname = 'promote_deployment_org_license_returning'
          AND p.pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');

        IF v_public THEN
            RAISE EXCEPTION 'Migration 175 failed: PUBLIC holds EXECUTE on promote_deployment_org_license_returning - any role could promote the deployment org''s licensed tier through a SECURITY DEFINER function';
        END IF;
        IF NOT v_approle THEN
            RAISE EXCEPTION 'Migration 175 failed: axonflow_app_role does NOT hold EXECUTE on promote_deployment_org_license_returning - the DROP+CREATE discarded the grant and the agent boot-time licence sync would be refused on every deployment connecting as the app role';
        END IF;

        -- THE FORWARDER'S OWN GRANTS, asserted by the same rule (#4007 review).
        -- The DROP above discarded them too, and this migration re-establishes
        -- them a few lines up - but nothing checked that it had. An old binary
        -- calls the OLD name, so a forwarder that exists and cannot be executed
        -- by the app role is the same outage as a missing function, arriving
        -- through a different door.
        SELECT has_function_privilege('public', p.oid, 'EXECUTE'),
               has_function_privilege('axonflow_app_role', p.oid, 'EXECUTE')
          INTO STRICT v_public, v_approle
        FROM pg_proc p
        WHERE p.proname = 'promote_deployment_org_license'
          AND p.pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');

        IF v_public THEN
            RAISE EXCEPTION 'Migration 175 failed: PUBLIC holds EXECUTE on the promote_deployment_org_license forwarder - it is SECURITY DEFINER and forwards to the promoter, so PUBLIC EXECUTE on it is PUBLIC EXECUTE on the promotion';
        END IF;
        IF NOT v_approle THEN
            RAISE EXCEPTION 'Migration 175 failed: axonflow_app_role does NOT hold EXECUTE on the promote_deployment_org_license forwarder - an older agent binary calls the old name and would be refused';
        END IF;
    ELSE
        RAISE NOTICE 'Migration 175: axonflow_app_role absent (mig 098 not run here); PUBLIC EXECUTE left at the post-CREATE default, matching 117/142 -- installed but unbound.';
    END IF;

    RAISE NOTICE 'Migration 175 verified: promote_deployment_org_license_returning is SECURITY DEFINER, returns a set (%), pins search_path, and is not executable by PUBLIC.', v_rettype;
END
$$;

-- ============================================================================
-- The forwarder is verified SEPARATELY, and its assertion is the INVERSE
-- ============================================================================
-- #4007: the old name must remain RETURNS VOID at 142's signature. That is not
-- a leftover, it is the property that keeps 142's up migration re-runnable at
-- the fully-migrated state, so it is asserted rather than assumed - and it is
-- asserted as NOT set-returning, which is the opposite of what the block above
-- demands of the _returning name. A future edit that "tidies" the two into one
-- shape breaks one of them, and this pair is what says so.
DO $$
DECLARE
    v_secdef BOOLEAN;
    v_retset BOOLEAN;
    v_rettype TEXT;
BEGIN
    SELECT p.prosecdef, p.proretset, pg_catalog.format_type(p.prorettype, NULL)
      INTO STRICT v_secdef, v_retset, v_rettype
    FROM pg_proc p
    WHERE p.proname = 'promote_deployment_org_license'
      AND p.pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');

    IF v_retset THEN
        RAISE EXCEPTION 'Migration 175 failed: promote_deployment_org_license returns a SET (rettype=%) - it must stay RETURNS VOID at 142''s signature, or re-running migration 142 raises "cannot change return type of existing function" (#4007)', v_rettype;
    END IF;
    IF v_rettype IS DISTINCT FROM 'void' THEN
        RAISE EXCEPTION 'Migration 175 failed: promote_deployment_org_license returns % - 142 creates this signature as RETURNS VOID and re-running it must not have to change the return type (#4007)', v_rettype;
    END IF;
    IF NOT v_secdef THEN
        RAISE EXCEPTION 'Migration 175 failed: the promote_deployment_org_license forwarder is NOT SECURITY DEFINER - it would run with the CALLER''s privileges, which FORCE RLS applies to';
    END IF;

    RAISE NOTICE 'Migration 175 verified: promote_deployment_org_license remains RETURNS VOID at 142''s signature, forwarding to promote_deployment_org_license_returning.';
END
$$;

COMMIT;
