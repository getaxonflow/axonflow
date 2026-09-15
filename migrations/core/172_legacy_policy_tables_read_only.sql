-- Migration 172: static_policies and dynamic_policies become read-only to the application
-- Date: 2026-09-08
-- Purpose: End legacy policy AUTHORING at the storage layer. The application
--          roles keep SELECT and lose INSERT, UPDATE, DELETE and TRUNCATE on
--          both legacy policy tables.
-- Related: #3786 (one authoring model), #3776 (the model that replaces this
--          one), ADR-065 "Migration"/Phase 5, v11 decision D1.
--
-- EDITION: COMMUNITY (mirrored). The typed authoring surface that replaces
-- these tables is Enterprise, but the refusal is not: a community binary must
-- also stop writing to them, or "the new model is the only write path" is true
-- of one edition and false of the product.
--
-- ---------------------------------------------------------------------------
-- WHAT CHANGES, AND WHAT DELIBERATELY DOES NOT
-- ---------------------------------------------------------------------------
--
-- v11 decision D1 retires static/dynamic as an AUTHORING, STORAGE and UI
-- model. It does NOT retire the legacy evaluator yet: ADR-065's Phase 2 keeps
-- it as the per-plane shadow COMPARATOR until each plane's activation entry,
-- and the detector implementations are kept permanently. A comparator that
-- cannot read its own substrate compares nothing, so SELECT must survive and
-- is re-asserted below rather than merely left alone.
--
-- So: reads keep working on all twelve planes. Writes stop. There are eleven
-- write sites in Go today —
--     platform/agent/static_policy_repository.go        (1 INSERT, 3 UPDATE)
--     platform/orchestrator/policy_api_repository.go    (2 INSERT, 2 UPDATE, 1 DELETE)
--     platform/orchestrator/db_dynamic_policies.go      (2 INSERT)
-- — and after this migration each of them is refused by the database on a
-- deployment running as an application role. They are pinned as a census by
-- tests/regression-test-required/legacy_policy_write_surface_test.sh so a
-- twelfth cannot appear without a reviewed diff.
--
-- ---------------------------------------------------------------------------
-- WHY THERE IS NO TRIGGER HERE, WHEN enterprise/155 HAS ONE
-- ---------------------------------------------------------------------------
--
-- migrations/enterprise/155 backs its privilege revoke with a BEFORE UPDATE OR
-- DELETE trigger, because a privilege revoke does not bind the table OWNER and
-- nothing legitimately rewrites a content-addressed artifact.
--
-- The opposite is true here. The OWNER is exactly the identity that must keep
-- writing these tables: the seed migrations (core/010, 014, 031, 067, 135,
-- 160, 168) write rows in them - INSERTs and UPDATEs for the most part, and
-- core/160's UP is a DELETE - and their DOWN migrations write them too:
-- 031's DELETEs, 067's and 135's UPDATEs, 160's INSERT.
--
-- An earlier version of this paragraph said "every *_down.sql in that set
-- deletes from them", which is wrong four ways: 010 and 014 have NO down
-- migration, 067 and 135 UPDATE, 160 INSERTs, and 168's touches neither
-- table. Only 031's deletes. The conclusion survives and the correction
-- strengthens it — migration 155's trigger is BEFORE UPDATE OR DELETE, so
-- an UPDATE is caught by that shape as surely as a delete would be.
--
-- A trigger would therefore bind the owner and break the migration chain on a
-- fresh database, including this migration's own rollback. The population that
-- must stop writing is the APPLICATION roles, and a privilege revoke targets
-- exactly that population and nothing else.
--
-- ---------------------------------------------------------------------------
-- TWO CONSUMERS THIS REVOKE WOULD OTHERWISE BREAK, RE-HOMED FIRST
-- ---------------------------------------------------------------------------
--
-- Neither of them appears in the eleven-site enumeration above, and neither is
-- findable by any search of Go source, which is why both are dealt with HERE
-- rather than left to be discovered on a customer stack.
--
-- 1. activate_integration(), migrations/core/060. A SECURITY INVOKER plpgsql
--    function whose body does `UPDATE static_policies SET enabled = true`. The
--    agent calls it as `SELECT activate_integration(...)` - the call site's own
--    comment says "it slips past the write-audit static test because it is
--    lexically a SELECT" - from boot, from MCP `initialize`, and from EVERY
--    check_policy/check_output request. The int_claude_* and int_openclaw_*
--    policies ship DISABLED and are enabled only by this function, so under
--    the revoke they would never enforce, and the caller retries on every
--    subsequent request because it returns before marking the integration
--    activated. Re-created below as SECURITY DEFINER, which runs it as the
--    OWNER - exactly the population this migration deliberately does not bind.
--
--    WHAT THAT LEAVES, STATED PRECISELY. The bounds below remove an
--    enable-EVERYTHING primitive; they do not reduce this to enabling one
--    named integration. Any caller who may execute it can still enable every
--    disabled policy in its own org sharing any three-character prefix - and
--    'sys' is three characters. That is not a regression: before this
--    migration both application roles held a direct UPDATE on the whole table,
--    so the function's reach is strictly narrower than what it replaces. It is
--    written down because "the bounds are in the body" reads as a stronger
--    claim than the bounds actually make.
--
-- 2. The five sys_media_* governance policies. They are seeded ONLY by
--    orchestrator Go code (seedSystemMediaPolicies), on the application
--    connection, and its failure is a log line rather than an error. They
--    appear in NO migration. After the revoke a FRESH stack would never get
--    them, while every existing stack already holds them - so the gap is
--    invisible everywhere anyone would look and bites only new deployments.
--    Seeded by migrations/core/173, which runs immediately after this file.
--
--    IT IS A SEPARATE MIGRATION AND NOT A SECTION HERE, because this file's
--    down migration is a REAL rollback and says so. A data seed inside it
--    would make that down ambiguous: deleting the five rows on rollback would
--    remove policies every existing stack legitimately holds, and NOT deleting
--    them would mean the down no longer reverses the up. A privilege change
--    and a data seed have different rollback semantics and do not share a file.
--
-- ---------------------------------------------------------------------------
-- THE LIMIT OF WHAT A GRANT CAN ENFORCE
-- ---------------------------------------------------------------------------
--
-- This binds a deployment that connects as axonflow_app_role or
-- axonflow_platform_admin, which is what AXONFLOW_DB_USE_APP_ROLE=true
-- selects. A deployment still connecting as the database OWNER is unaffected,
-- for the same reason FORCE ROW LEVEL SECURITY was rolled out behind that same
-- flag: the owner is not bound by grants. That is a property of the rollout,
-- not a hole this migration could close, and it is the same boundary every
-- other RLS-era guarantee in this repository sits behind.
--
-- REVISIT WHEN: AXONFLOW_DB_USE_APP_ROLE is no longer a flag — that is, when
-- the owner-connection path is removed from the deployment templates rather
-- than merely discouraged. At that point this revoke covers every deployment
-- and the sentence above can be deleted rather than restated.
--
-- ---------------------------------------------------------------------------

BEGIN;

-- A PRECONDITION, not a summary. Both tables must exist: this migration is
-- ordered after the seeds that create them, and a revoke against a table that
-- is not there would succeed at doing nothing.
--
-- The role count is deliberately NOT computed here. An earlier version counted
-- the roles present and printed the number, which read as a check and was not
-- one - the verification block at the foot does the counting, and does it
-- against has_table_privilege rather than against pg_roles.
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['static_policies', 'dynamic_policies'] LOOP
        IF to_regclass(t) IS NULL THEN
            RAISE EXCEPTION 'Migration 172 failed: % does not exist; this migration is ordered after the seeds that create it', t;
        END IF;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- Consumer 1: activate_integration() becomes SECURITY DEFINER, WITH THE BOUND
-- IT WAS PREVIOUSLY GETTING FROM ROW-LEVEL SECURITY WRITTEN INTO ITS BODY
--
-- Same signature. The body is core/060's plus TWO added predicates, and both
-- are there because SECURITY DEFINER removes a bound that used to be supplied
-- from outside. This is a privilege change, not merely a re-homing, and the
-- differences are stated rather than waved at:
--
-- 1. THE ORG PREDICATE RESTORES WHAT RLS WAS DOING. static_policies is
--    ENABLE (not FORCE) ROW LEVEL SECURITY with
--    `tenant_isolation_update USING (org_id = get_current_org_id())`
--    (core/018:72). Under SECURITY INVOKER the app role was bound by that
--    predicate. Under SECURITY DEFINER the body runs as the OWNER, for whom an
--    un-FORCEd policy does not apply at all - so without this line the same
--    call would enable rows belonging to EVERY organization. The caller
--    already scopes to the 'global' sentinel deliberately
--    (platform/agent/integration_activation.go, #3048), so with the predicate
--    written into the body the reachable set is byte-for-byte what it was
--    before: the global platform rows, and nothing else.
--
-- 2. THE PREFIX IS NO LONGER A PATTERN AT ALL. p_policy_prefix is
--    caller-supplied and core/060 interpolated it straight into a LIKE, so the
--    caller controlled a PATTERN rather than a prefix: '' gives '%', and so do
--    '%' and '_', each of which enables every disabled policy in scope. That
--    is an arbitrary enable-everything primitive handed to both application
--    roles along with EXECUTE, and after this migration it would be the ONLY
--    write path into static_policies those roles have.
--
--    An earlier version of this file guarded `btrim(...) = ''` and claimed the
--    argument could no longer widen what the definer privilege reaches. It
--    could: the guard rejected the empty STRING while the mechanism is the
--    LIKE PATTERN, and '%' is not empty. Measured at the time: a '%' prefix
--    enabled five policies including sys_pii_email and a tenant rule, neither
--    of which has anything to do with an integration.
--
--    So the fix is structural rather than another validation. starts_with()
--    is an exact prefix test with NO pattern semantics - there is no
--    metacharacter to reject, no ESCAPE clause to get wrong, and no next
--    spelling to discover. The length floor is separate and is about width
--    rather than about patterns: a one- or two-character prefix is a very
--    wide net even when it is honest, and every real integration prefix
--    (int_claude, int_openclaw) is far longer.
--
-- Plus the hardening every SECURITY DEFINER helper in this tree carries
-- (core/109's pattern): a pinned search_path so the body cannot be redirected
-- by a caller's schema, EXECUTE revoked from PUBLIC by default, and granted
-- back only to the two application roles.
--
-- The function's WRITE is to static_policies, which is exactly what the revoke
-- below removes from those roles; running it as the owner is what keeps the
-- one legitimate writer working while every direct write stops. It stays an
-- ENABLE-ONLY operation on rows the caller's own scope already reaches.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION activate_integration(
    p_integration_id VARCHAR(50),
    p_display_name VARCHAR(100),
    p_connector_prefix VARCHAR(50),
    p_policy_prefix VARCHAR(50),
    p_activated_by VARCHAR(100) DEFAULT 'auto-detect'
) RETURNS INTEGER
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
DECLARE
    v_count  INTEGER;
    v_prefix TEXT := btrim(p_policy_prefix);
BEGIN
    -- A LENGTH FLOOR, and it is the only check needed because the match below
    -- is not a pattern. Guarding metacharacters would be guarding a spelling:
    -- '', '%' and '_' all produce a match-everything LIKE, and the next
    -- spelling is the one nobody thought of. starts_with() removes the class.
    -- What remains is width: a prefix this short is a wide net even when it is
    -- honest, and this function runs with the owner's privileges.
    --
    -- THE TRIMMED VALUE IS THE ONE THAT GETS MATCHED. An earlier version
    -- measured length(btrim(...)) and then matched the RAW argument, so the
    -- guard and the match were reading two different strings: '  int_claude'
    -- cleared a floor its own leading spaces had not been counted against, and
    -- then matched nothing at all. It failed closed and returned 0 silently,
    -- which is the kind of harmless-today divergence that stops being harmless
    -- the day the check and the use are edited apart.
    IF v_prefix IS NULL OR length(v_prefix) < 3 THEN
        RAISE EXCEPTION
            'activate_integration: a policy prefix of fewer than 3 characters would enable far more than one integration''s policies; name the integration''s prefix (for example int_claude)'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    INSERT INTO integration_activations (integration_id, display_name, connector_prefix, activated_by)
    VALUES (p_integration_id, p_display_name, p_connector_prefix, p_activated_by)
    ON CONFLICT (integration_id) DO UPDATE SET
        activated_at = NOW(),
        activated_by = p_activated_by;

    -- TWO BOUNDS, both of which SECURITY DEFINER would otherwise have removed
    -- or left to a caller.
    --
    -- starts_with(), not LIKE: an exact prefix test with no pattern
    -- semantics, so a caller-supplied '%' or '_' is a literal character that
    -- matches nothing rather than a wildcard that matches everything.
    --
    -- org_id = get_current_org_id() is tenant_isolation_update's own predicate
    -- (core/018:72), written into the body because SECURITY DEFINER means the
    -- policy no longer applies. Without it this enables rows in every org.
    UPDATE static_policies
    SET enabled = true
    WHERE starts_with(policy_id, v_prefix)
      AND enabled = false
      AND org_id = get_current_org_id();

    GET DIAGNOSTICS v_count = ROW_COUNT;

    UPDATE integration_activations
    SET policy_count = v_count
    WHERE integration_id = p_integration_id;

    RETURN v_count;
END;
$$;

REVOKE EXECUTE ON FUNCTION activate_integration(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_app_role') THEN
        GRANT EXECUTE ON FUNCTION activate_integration(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO axonflow_app_role;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        GRANT EXECUTE ON FUNCTION activate_integration(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO axonflow_platform_admin;
    END IF;
END $$;

-- Written as LITERAL statements, not format(...%I...) inside a loop, because
-- the RLS grant census (platform/agent/migration_rls_grant_census_test.go)
-- reads migration SOURCE and cannot see a statement assembled at runtime. The
-- re-stated GRANT SELECT is what keeps both tables visible to that census as
-- carrying an application grant, which they must, because the shadow
-- comparator still reads them.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON static_policies  FROM axonflow_app_role;
        REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON dynamic_policies FROM axonflow_app_role;
        GRANT SELECT ON static_policies  TO axonflow_app_role;
        GRANT SELECT ON dynamic_policies TO axonflow_app_role;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON static_policies  FROM axonflow_platform_admin;
        REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON dynamic_policies FROM axonflow_platform_admin;
        GRANT SELECT ON static_policies  TO axonflow_platform_admin;
        GRANT SELECT ON dynamic_policies TO axonflow_platform_admin;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- THE VIEW WRITE PATHS ARE NOT THIS MIGRATION'S, AND THAT IS DELIBERATE
-- ---------------------------------------------------------------------------
--
-- An auto-updatable view over static_policies is a write path that a revoke on
-- the TABLE does not close, and it is a cross-TENANT one: the view executes
-- with its OWNER's privileges, and static_policies is ENABLE - not FORCE - row
-- level security, so migration 018's org predicate does not bind it.
--
-- That is closed by migrations/core/174 (#3905), which SHIPPED SEPARATELY and
-- AHEAD of this migration. It had to: the bypass predates this work entirely -
-- core/014 creates the view, core/098 grants on it, core/018 gives ENABLE and
-- not FORCE - it is live on every deployment today, and it should not have been
-- gated behind a change this size.
--
-- WHY THE FUNCTION IS NOT ALSO DEFINED HERE. It was, briefly, and that was a
-- hazard rather than harmless redundancy: two definitions of one function whose
-- TEARDOWNS DISAGREE. This file's down migration would have dropped
-- enforce_legacy_policy_read_only(), so rolling back 172 on a deployment that
-- had taken 174 would have silently re-opened #3905 - the rollback of a table
-- revoke quietly undoing an unrelated tenant-isolation fix, with nothing in
-- either migration's diff showing it. One owner, and it is 174.
--
-- ---------------------------------------------------------------------------
-- Self-verification BEFORE COMMIT
--
-- Both directions are asserted, not just the revoke: a migration that removed
-- writes AND reads would silently break the shadow comparator on all twelve
-- planes, and the symptom would appear as a missing decision-shadow window
-- rather than as a failed migration.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    r          TEXT;
    t          TEXT;
    confirmed  INTEGER := 0;
    roles_seen INTEGER := 0;
BEGIN
    FOREACH r IN ARRAY ARRAY['axonflow_app_role', 'axonflow_platform_admin'] LOOP
        CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r);
        roles_seen := roles_seen + 1;
        FOREACH t IN ARRAY ARRAY['static_policies', 'dynamic_policies'] LOOP
            IF has_table_privilege(r, t, 'INSERT')
               OR has_table_privilege(r, t, 'UPDATE')
               OR has_table_privilege(r, t, 'DELETE')
               OR has_table_privilege(r, t, 'TRUNCATE') THEN
                RAISE EXCEPTION 'Migration 172 failed: % can still write %', r, t;
            END IF;
            -- has_table_privilege ALONE IS NOT ENOUGH. It answers for the
            -- whole relation, so a COLUMN-level `GRANT UPDATE (enabled)`
            -- passes it while leaving a live write path open - and `enabled`
            -- is precisely the column the legacy surfaces toggle. Migration
            -- 155 checks the column form for the same reason.
            -- has_any_column_privilege, not a spot-check of two columns. An
            -- earlier version named `enabled` and `policy_id` because those
            -- are what the legacy surfaces toggle, which answers "did anyone
            -- grant the columns I thought of". These tables have NO legitimate
            -- column grant at all, so the exhaustive form is both correct and
            -- simpler. (Migration 155 needs the narrow form because it HAS one:
            -- the revocation columns on the signing-key table.)
            IF has_any_column_privilege(r, t, 'UPDATE')
               OR has_any_column_privilege(r, t, 'INSERT') THEN
                RAISE EXCEPTION 'Migration 172 failed: % holds a COLUMN-level INSERT/UPDATE on %', r, t;
            END IF;
            IF NOT has_table_privilege(r, t, 'SELECT') THEN
                RAISE EXCEPTION 'Migration 172 failed: % lost SELECT on %, which breaks the ADR-065 shadow comparator', r, t;
            END IF;
            confirmed := confirmed + 1;
        END LOOP;
    END LOOP;

    -- Anti-vacuity: on a database that HAS the roles, this block must have
    -- checked something. A verification loop that ran zero times reports
    -- success for a migration that did nothing.
    IF roles_seen > 0 AND confirmed <> roles_seen * 2 THEN
        RAISE EXCEPTION 'Migration 172 failed: % role(s) present but only % (role, table) pair(s) verified', roles_seen, confirmed;
    END IF;

    RAISE NOTICE 'Migration 172 verified: static_policies and dynamic_policies are SELECT-only for % application role(s); % pair(s) checked.', roles_seen, confirmed;
END $$;

COMMIT;
