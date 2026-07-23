-- Migration 150: the owner grant requires a REAL identity (#3000)
-- Date: 2026-07-22
--
-- WHAT THIS CLOSES
--
-- Migration 149 (#2997) keyed an org's bootstrap `owner` assignment on the
-- identity its password login presents: organizations.contact_email, or '' when
-- the org has none. On a DEFAULT axonflow-install that granted owner to
-- user_email = ''.
--
-- Permission resolution is UserHasPermission(org_id, user_email, perm). An
-- empty user_email is therefore not an identity but a WILDCARD: any session in
-- that org that resolves to '' matches the grant and inherits `owner` — the top
-- role, including the owner-reserved sso:configure. Today the only empty-email
-- session is the single org-password operator, so it is contained; the risk is
-- any OTHER auth path that can yield an empty email in the same org, most
-- plausibly an SSO/OIDC session with a missing or unmapped email claim. It also
-- leaves owner actions with blank audit attribution.
--
-- THE FIX, IN TWO HALVES
--
--   1. (application, ee/platform/customer-portal/api/bootstrap_identity.go)
--      The org-level login now PRESENTS a real identity — contact_email when
--      set, else AXONFLOW_PORTAL_ADMIN_EMAIL (default
--      portal-admin@axonflow.invalid) — and the owner grant is keyed on that
--      same value. Both sides call ResolveOrgBootstrapIdentity, so the identity
--      presented and the identity granted cannot diverge (divergence is the
--      #2997 lockout).
--
--   2. (this migration) ensure_org_owner_assignment REFUSES a blank or
--      reserved-synthetic target outright, returning the new sentinel -2. The
--      guard lives in the SINGLE choke point every first-owner path already
--      routes through — the mig 149 backfill, the org-creation trigger, the
--      contact-email drift guard, the portal boot grant and the admin
--      break-glass API — so every FIRST-OWNER-CREATION path fails closed at
--      once. Defense in depth: half 1 alone would still leave the door open to
--      any future caller that forgets.
--
--      SCOPE OF THE GUARD — it is a guarded FUNCTION, not a table constraint.
--      It binds only callers that go THROUGH ensure_org_owner_assignment.
--      These still write role_assignments directly and are NOT covered:
--        * roles/repository.go AssignRole (the portal RBAC API),
--        * SCIM SyncUserRoles,
--        * any psql session with write access.
--      Those paths are gated by their own authorization (the anti-escalation
--      gate, the IdP, database grants respectively) and none of them keys a
--      grant on a blank identity today. Closing the class outright would take a
--      CHECK constraint on role_assignments.user_email; that is deliberately
--      not attempted here, because a table constraint would also reject
--      historical rows this migration is in the middle of repairing and would
--      abort the chain — the exact failure mode #3002 exists to prevent.
--
-- It also DELETES the ''-keyed and synthetic-keyed system owner grants a run of
-- 149 already created. Those rows ARE the vulnerability, so they are removed
-- rather than grandfathered. This does not strand the operator: the portal
-- re-grants owner on the real identity on its next boot
-- (EnsureDeploymentOrgOwner, enterprise / in-vpc modes), and the ADMIN_API_KEY
-- break-glass endpoint covers every other shape. The count is reported with
-- that remediation attached.
--
-- SYNTHETIC-IDENTITY LOCKSTEP
--
-- The refused-identity predicate mirrors Go's
-- platform/shared/identity.IsSharedSyntheticIdentity (the #2938 census). SQL
-- cannot call Go, so this is the one place the census is deliberately
-- duplicated. It is PINNED: TestMigration150SQLGuardMatchesGoCensus feeds every
-- census spelling through this function and asserts the SQL verdict equals the
-- Go verdict, so adding a census entry on either side without the other fails
-- CI. Do not edit one half alone.
--
-- IDEMPOTENT. No schema change; safe to re-run.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'role_assignments'
    ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'custom_roles'
    ) THEN
        RAISE NOTICE 'Migration 150: role_assignments/custom_roles absent - skipping';
        RETURN;
    END IF;

    -- ========================================================================
    -- 1. The census predicate (mirror of Go IsSharedSyntheticIdentity).
    -- ========================================================================
    -- Returns TRUE when p_email may key an owner assignment: non-blank, and not
    -- a platform-synthesized identity SHARED across callers.
    --
    -- IMMUTABLE + no table access, so it is safe to call from the choke point
    -- and from a CHECK-style verification query.
    EXECUTE $fn$
        CREATE OR REPLACE FUNCTION axonflow_is_grantable_identity(p_email VARCHAR)
        RETURNS BOOLEAN
        LANGUAGE plpgsql
        IMMUTABLE
        SET search_path = public, pg_temp
        AS $body$
        DECLARE
            v_email TEXT;
        BEGIN
            -- CanonicalEmail: trim + lowercase. Matches the Go side, so a
            -- case/whitespace variant cannot evade the check.
            v_email := axonflow_canonical_email(p_email);

            IF v_email = '' THEN
                RETURN FALSE;
            END IF;
            -- "mcp-client:<client-id>" — shared by every developer on one
            -- org:license credential.
            IF v_email LIKE 'mcp-client:%' THEN
                RETURN FALSE;
            END IF;
            -- Reserved platform domains: "<client-id>@axonflow.local",
            -- "unknown@axonflow.local", "local-dev@axonflow.local",
            -- "orchestrator@axonflow.internal", "system@axonflow.internal".
            -- Matched by SUFFIX so a future synthetic under either domain
            -- fail-closes without a further edit.
            IF v_email LIKE '%@axonflow.local' OR v_email LIKE '%@axonflow.internal' THEN
                RETURN FALSE;
            END IF;
            -- community-saas evaluator — one spelling shared by every
            -- try.getaxonflow.com evaluator.
            IF v_email = 'evaluator@try.getaxonflow.com' THEN
                RETURN FALSE;
            END IF;
            RETURN TRUE;
        END;
        $body$;
    $fn$;

    EXECUTE $c$
        COMMENT ON FUNCTION axonflow_is_grantable_identity(VARCHAR) IS
            'TRUE when an email may key a role assignment: non-blank and not a '
            'platform-synthesized SHARED identity. SQL mirror of Go '
            'platform/shared/identity.IsSharedSyntheticIdentity; the two are '
            'pinned in lockstep by TestMigration150SQLGuardMatchesGoCensus (#3000).'
    $c$;

    -- ========================================================================
    -- 1a. THE canonical-email function, in SQL.
    -- ========================================================================
    -- The SQL half of Go platform/shared/identity.CanonicalEmail
    -- (strings.ToLower(strings.TrimSpace(s))).
    --
    -- WHY NOT lower(btrim(x)) (R3 pass 2, F2). btrim() with no second argument
    -- strips ASCII space (0x20) ONLY, while Go's strings.TrimSpace strips tab,
    -- newline, vertical tab, form feed, carriage return, NEL, NBSP and every
    -- Unicode Zs separator. A contact_email carrying a leading NBSP or tab — an
    -- ordinary copy-paste into an onboarding form — therefore canonicalized to
    -- DIFFERENT values on the two sides: the migration would store (and its own
    -- verification would happily accept) a key beginning with NBSP, while the
    -- login presents the NBSP-stripped address and matches zero rows. That is
    -- the #2997 divergence this whole migration exists to abolish, re-created
    -- by its own canonicalization.
    --
    -- The character set below is exactly Go's unicode.IsSpace. Kept in lockstep
    -- with CanonicalEmail by TestSQLCanonicalEmailMatchesGo, which feeds a
    -- whitespace corpus through both and asserts they agree.
    EXECUTE $fn$
        CREATE OR REPLACE FUNCTION axonflow_canonical_email(p_email VARCHAR)
        RETURNS VARCHAR
        LANGUAGE sql
        IMMUTABLE
        SET search_path = public, pg_temp
        AS $body$
            SELECT lower(btrim(COALESCE(p_email, ''),
                -- NOTE \x0B, not \v: Postgres E'' has NO \v escape and would
                -- silently yield the LITERAL LETTER 'v' (ascii 118), putting
                -- 'v' in the trim set and stripping it off the ends of real
                -- addresses. Caught by TestSQLCanonicalEmailMatchesGo.
                E' \t\n\x0B\f\r\u0085\u00A0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u2028\u2029\u202F\u205F\u3000'))
        $body$;
    $fn$;

    EXECUTE $c$
        COMMENT ON FUNCTION axonflow_canonical_email(VARCHAR) IS
            'Canonical form of an email identity: trim + lowercase, using EXACTLY '
            'Go unicode.IsSpace''s whitespace set so it agrees with '
            'platform/shared/identity.CanonicalEmail. Pinned by '
            'TestSQLCanonicalEmailMatchesGo (#3000).'
    $c$;

    -- ========================================================================
    -- 1b. THE org-login identity expression, in SQL.
    -- ========================================================================
    -- The SQL half of Go ResolveOrgBootstrapIdentity (bootstrap_identity.go).
    -- Every migration that needs "the identity this org's password login
    -- presents" MUST call this rather than open-coding a COALESCE — that
    -- open-coding is exactly how migration 149 came to key a grant on '' while
    -- the login presented something else, which is the #2997 lockout wearing a
    -- different hat, and it is the trap any FUTURE migration needing this
    -- identity will fall into unless it calls this function.
    --
    -- Returns the CANONICAL (trim + lowercase) contact_email when the org has a
    -- real one, and NULL otherwise.
    --
    -- NULL is deliberate and load-bearing: when contact_email is blank the Go
    -- resolver falls back to AXONFLOW_PORTAL_ADMIN_EMAIL, which is PROCESS
    -- configuration that SQL cannot read. A migration therefore CANNOT compute
    -- that identity and must not guess: it returns NULL so callers skip the org
    -- loudly and leave it to the portal boot path (EnsureDeploymentOrgOwner) or
    -- the admin break-glass endpoint, both of which do know the resolved value.
    -- Returning '' here instead would silently recreate the non-identity grant
    -- this whole migration exists to abolish.
    EXECUTE $fn$
        CREATE OR REPLACE FUNCTION axonflow_org_login_identity(p_contact_email VARCHAR)
        RETURNS VARCHAR
        LANGUAGE plpgsql
        IMMUTABLE
        SET search_path = public, pg_temp
        AS $body$
        DECLARE
            v_email TEXT;
        BEGIN
            v_email := axonflow_canonical_email(p_contact_email);
            IF v_email = '' THEN
                RETURN NULL;
            END IF;
            IF NOT axonflow_is_grantable_identity(v_email) THEN
                RETURN NULL;
            END IF;
            RETURN v_email;
        END;
        $body$;
    $fn$;

    EXECUTE $c$
        COMMENT ON FUNCTION axonflow_org_login_identity(VARCHAR) IS
            'The identity an org-level (org_id + password) portal login presents, '
            'in SQL: canonical contact_email, or NULL when the org has none (the Go '
            'resolver then falls back to AXONFLOW_PORTAL_ADMIN_EMAIL, which SQL '
            'cannot read - callers must SKIP such orgs rather than key a grant on '
            'the empty string). SQL half of Go ResolveOrgBootstrapIdentity (#3000).'
    $c$;

    -- ========================================================================
    -- 1c. WHICH CALLERS MAY REVIVE AN EXPIRED OWNER ROW.
    -- ========================================================================
    -- Byte-identical to migration 149's definition (see its header for the
    -- policy and the reasoning). Re-declared here because THIS migration owns
    -- the final body of ensure_org_owner_assignment and that body calls it, so
    -- the function must exist whichever of the two files ran last.
    EXECUTE $revivefn$
        CREATE OR REPLACE FUNCTION axonflow_owner_grant_may_revive(p_assigned_by VARCHAR)
        RETURNS BOOLEAN
        LANGUAGE sql
        IMMUTABLE
        SET search_path = public, pg_temp
        AS $body$
            SELECT COALESCE(p_assigned_by, '') = 'migration:149_owner_backfill'
                OR COALESCE(p_assigned_by, '') LIKE 'break-glass:%'
        $body$;;
    $revivefn$;

    EXECUTE $c$
        COMMENT ON FUNCTION axonflow_owner_grant_may_revive(VARCHAR) IS
            'TRUE when an ensure_org_owner_assignment caller is an INTENTIONAL '
            'first-owner act (the mig-149 backfill, or the ADMIN_API_KEY '
            'break-glass endpoint) and may therefore revive an already-EXPIRED '
            'owner row. FALSE for the ambient callers (org-creation trigger, '
            'portal boot), for which a revive would silently make a lapsed '
            'time-boxed owner grant permanent. Pinned against the Go markers by '
            'TestOwnerGrantReviveMarkersMatchGo_RealPostgres (#3005).'
    $c$;

    -- ========================================================================
    -- 2. Re-define the choke point WITH the identity guard.
    -- ========================================================================
    -- Identical to migration 149's definition except for the new guard block.
    -- Return codes: 1+ granted, 0 already held, -1 no system owner role,
    -- -2 target identity refused (NEW in 150).
    EXECUTE $fn$
        CREATE OR REPLACE FUNCTION ensure_org_owner_assignment(
            p_org_id      VARCHAR,
            p_user_email  VARCHAR,
            p_assigned_by VARCHAR DEFAULT 'system',
            p_expires_at  TIMESTAMPTZ DEFAULT NULL
        )
        RETURNS INTEGER
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $body$
        DECLARE
            v_owner_role_id VARCHAR;
            v_inserted      INTEGER := 0;
            v_prev_org      TEXT;
        BEGIN
            IF p_org_id IS NULL OR p_org_id = '' THEN
                RETURN 0;
            END IF;

            -- #3000: never key the top role on a non-identity. A blank
            -- user_email is a WILDCARD under UserHasPermission(org, email,
            -- perm) — every session that resolves to '' would match it — and a
            -- reserved synthetic is shared across callers by construction.
            -- Refusing here covers EVERY first-owner path at once, because they
            -- all route through this function.
            IF NOT axonflow_is_grantable_identity(p_user_email) THEN
                RAISE WARNING 'ensure_org_owner_assignment: refusing to grant owner on org % to %, which is blank or a reserved platform synthetic identity; supply a real address (see AXONFLOW_PORTAL_ADMIN_EMAIL or the admin break-glass endpoint) (#3000)',
                    p_org_id, COALESCE(NULLIF(p_user_email, ''), '<blank>');
                RETURN -2;
            END IF;

            -- Bind the org-isolation GUC for the duration of this call, then
            -- restore it. role_assignments is ENABLE (not FORCE) RLS today, so
            -- the BYPASSRLS definer needs no GUC — but if the table is ever
            -- flipped to FORCE, or the definer degrades to the plain table
            -- owner (a DB where mig 098 never created axonflow_platform_admin),
            -- the WITH CHECK predicate would silently reject the INSERT. Saving
            -- and restoring means the caller's own withOrgScope binding is not
            -- clobbered for the rest of its transaction.
            v_prev_org := current_setting('app.current_org_id', true);
            PERFORM set_config('app.current_org_id', p_org_id, true);

            SELECT id INTO v_owner_role_id
            FROM custom_roles
            WHERE org_id = p_org_id AND name = 'owner' AND is_system
            LIMIT 1;

            IF v_owner_role_id IS NULL THEN
                PERFORM set_config('app.current_org_id', COALESCE(v_prev_org, ''), true);
                RAISE NOTICE 'ensure_org_owner_assignment: org % has no SYSTEM owner role (a custom role may occupy the name); no owner granted', p_org_id;
                RETURN -1;
            END IF;

            -- Store the CANONICAL spelling (trim + lowercase), matching the
            -- form the session/audit paths key on. Pre-150 this inserted the
            -- raw value, so a mixed-case grant could fail to match the
            -- session's canonicalized email.
            --
            -- THE EXPIRED-ROW REVIVE (#3005-B) LIVES HERE, NOT ONLY IN 149.
            -- Migration 149 defines this same function and runs BEFORE this
            -- file, so whatever 149's body does is overwritten the moment 150
            -- applies. 149 carried the revive and 150 carried a bare
            -- DO NOTHING, which meant that on any complete chain the revive did
            -- not exist: an org whose only owner row had EXPIRED conflicted on
            -- the insert, ROW_COUNT was 0, and the caller was told
            -- "already_held" while the org had ZERO live owners. The
            -- ADMIN_API_KEY break-glass endpoint — the documented way out of an
            -- owner lockout — therefore reported success and granted nothing.
            --
            -- Scoped by axonflow_owner_grant_may_revive() so the ambient
            -- callers (org-creation trigger, portal boot) keep strict
            -- DO NOTHING semantics and cannot silently make a lapsed
            -- time-boxed grant permanent. See that function's header.
            --
            -- assigned_by is deliberately NOT rewritten: migration 149's DOWN
            -- deletes on the backfill marker, and stamping it onto a row a
            -- human or SCIM created would let the rollback delete their grant.
            -- The break-glass act itself stays attributable in admin_audit_log.
            -- source is forced to 'system' so a revived row is not stripped by
            -- the next SCIM sync, which is 149's documented SCIM-safety
            -- invariant.
            INSERT INTO role_assignments (org_id, user_email, role_id, assigned_by, assigned_at, expires_at, source)
            VALUES (p_org_id, axonflow_canonical_email(p_user_email), v_owner_role_id,
                    COALESCE(NULLIF(p_assigned_by, ''), 'system'), NOW(), p_expires_at, 'system')
            ON CONFLICT (org_id, user_email, role_id) DO UPDATE
               SET expires_at  = EXCLUDED.expires_at,
                   assigned_at = NOW(),
                   source      = 'system'
             WHERE role_assignments.expires_at IS NOT NULL
               AND role_assignments.expires_at <= NOW()
               AND axonflow_owner_grant_may_revive(p_assigned_by);

            GET DIAGNOSTICS v_inserted = ROW_COUNT;
            PERFORM set_config('app.current_org_id', COALESCE(v_prev_org, ''), true);
            RETURN v_inserted;
        END;
        $body$;
    $fn$;

    EXECUTE $c$
        COMMENT ON FUNCTION ensure_org_owner_assignment(VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ) IS
            'Idempotently grants an org''s SYSTEM owner role to one REAL identity with '
            'source=''system'' (never stripped by SCIM sync). The single choke point '
            'for first-owner creation: org-creation trigger, mig 149 backfill, portal '
            'bootstrap and the admin break-glass API all route through it. Returns '
            '1=granted, 0=already held, -1=no system owner role for the org, '
            '-2=target refused as blank/reserved-synthetic (#2997, #3000).'
    $c$;

    -- Ownership + PUBLIC revoke must be re-asserted: CREATE OR REPLACE keeps
    -- the existing owner and ACL, but a DB that never ran 149's grants block
    -- (or had it revoked) would otherwise be left PUBLIC-callable.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        EXECUTE 'ALTER FUNCTION ensure_org_owner_assignment(VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ) OWNER TO axonflow_platform_admin';
        EXECUTE 'ALTER FUNCTION axonflow_is_grantable_identity(VARCHAR) OWNER TO axonflow_platform_admin';
    END IF;
    EXECUTE 'REVOKE EXECUTE ON FUNCTION ensure_org_owner_assignment(VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ) FROM PUBLIC';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION ensure_org_owner_assignment(VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ) TO axonflow_app_role';
        EXECUTE 'GRANT EXECUTE ON FUNCTION axonflow_is_grantable_identity(VARCHAR) TO axonflow_app_role';
    END IF;

    -- ========================================================================
    -- 3. Remove the non-identity owner grants migration 149 created.
    -- ========================================================================
    DECLARE
        v_deleted INTEGER := 0;
    BEGIN
        -- Scoped to source='system' owner assignments: those are exactly the
        -- rows the choke point writes. A MANUAL or SCIM grant is an operator's
        -- deliberate act and is never touched here (it also cannot be blank —
        -- those paths require a real user).
        DELETE FROM role_assignments ra
        USING custom_roles cr
        WHERE cr.id = ra.role_id
          AND cr.org_id = ra.org_id
          AND cr.name = 'owner'
          AND ra.source = 'system'
          AND NOT axonflow_is_grantable_identity(ra.user_email);
        GET DIAGNOSTICS v_deleted = ROW_COUNT;

        IF v_deleted > 0 THEN
            RAISE NOTICE 'Migration 150: removed % owner assignment(s) keyed on a blank or reserved-synthetic identity. The portal re-grants owner to the real bootstrap identity on its next boot (enterprise / in-vpc); for any other deployment use POST /api/v1/admin/organizations/{org_id}/owner (ADMIN_API_KEY) — see UPGRADING.md.', v_deleted;
        END IF;
    END;

    -- ========================================================================
    -- 4. Re-key the org-login grants migration 149 stored in RAW form.
    -- ========================================================================
    -- Half 1 of this fix makes the org-level login present
    -- CanonicalEmail(contact_email) — trim + lowercase. Migration 149's trigger
    -- inserted the RAW column value. So for any org whose contact_email carries
    -- mixed case or surrounding whitespace, the stored grant
    -- ('  Ops@Example.COM ') no longer matches the identity the session now
    -- presents ('ops@example.com'), and UserHasPermission resolves ZERO
    -- assignments — the org is locked out again, by the very change meant to
    -- harden it. Reproduced on a real 146->150 chain before this block existed.
    --
    -- Scope is deliberately narrow: source='system' rows whose key IS that
    -- org's raw contact_email — exactly the rows whose presenting session just
    -- changed. A 'manual' or 'scim' grant is keyed by whatever an operator or
    -- IdP supplied and is resolved by a different auth path that this migration
    -- does not touch; blanket-lowercasing those could break an SSO identity
    -- whose session email is genuinely mixed-case.
    DECLARE
        v_rekeyed   INTEGER := 0;
        v_collided  INTEGER := 0;
        v_inherited INTEGER := 0;
    BEGIN
        -- COLLAPSE EACH CANONICAL CLASS TO ONE SURVIVOR, then re-key it.
        --
        -- The unique constraint is (org_id, user_email, role_id). The re-key
        -- UPDATE below rewrites user_email to its canonical form, so ANY two
        -- rows in the same (org, role) whose emails canonicalize to the same
        -- value collide on that UPDATE — the migration raises
        -- duplicate key value violates unique constraint
        -- "uq_role_assignments_user_role", rolls back, is never recorded, and
        -- re-runs on the next boot. run.go log.Fatalf's on a failed migration,
        -- so that is a permanent agent crash-loop.
        --
        -- An earlier revision only handled the case where an ALREADY-CANONICAL
        -- row existed alongside a raw one. That is not the only shape, and the
        -- others are produced by mig 149's own machinery with no hand-written
        -- SQL: 149's org-creation trigger keys the grant on the RAW
        -- contact_email, and its reseed_org_owner_on_contact_change trigger
        -- ADDS another raw-keyed grant on every contact_email change without
        -- deleting the previous one. So a single case-only edit
        -- ('Ops@Example.com' -> 'ops@Example.com') leaves TWO raw rows that
        -- canonicalize identically and NEITHER is canonical — invisible to a
        -- "does a canonical twin exist" test, and fatal to the UPDATE.
        --
        -- Ranking rather than a pairwise test, so the cardinality is provable:
        -- exactly one row survives per (org_id, role_id, canonical_email), so
        -- the UPDATE cannot collide by construction, whatever the input shape.
        --
        -- Survivor preference, in order — each rule exists to avoid silently
        -- REDUCING someone's authority:
        --   1. an already-canonical row (it is the one the session matches
        --      today, so keeping it means no window where nothing matches),
        --   2. a never-expiring grant over an expiring one (dropping a NULL
        --      expires_at in favour of a dated one time-bombs the owner),
        --   3. the latest expiry,
        --   4. id, purely so the choice is deterministic across re-runs.
        --
        -- MATERIALIZED ONCE into a temp table rather than repeated as a CTE in
        -- each statement below. Three statements need the SAME ranking — the
        -- provenance transfer, the delete and (implicitly) the re-key — and two
        -- copies of a window function that must agree is precisely the kind of
        -- "these two predicates are the same, honest" coupling that produced
        -- every repair-vs-verify boot loop in this migration's history.
        -- pg_temp-qualified: unqualified, this resolves through search_path
        -- and a same-named PERMANENT table in public would be dropped instead.
        DROP TABLE IF EXISTS pg_temp.mig150_owner_login_classes;
        CREATE TEMP TABLE mig150_owner_login_classes ON COMMIT DROP AS
        WITH ranked AS (
            SELECT ra.id, ra.org_id, ra.role_id, ra.source, ra.assigned_by,
                   ra.assigned_at, ra.expires_at,
                   axonflow_canonical_email(ra.user_email) AS canonical_email,
                   row_number() OVER (
                       PARTITION BY ra.org_id, ra.role_id, axonflow_canonical_email(ra.user_email)
                       -- 1. LIVE beats expired. An expired row confers nothing
                       --    (every permission read filters expires_at), so
                       --    keeping one while deleting the live grant is
                       --    silent privilege loss. This MUST outrank the
                       --    already-canonical preference below.
                       ORDER BY (ra.expires_at IS NULL OR ra.expires_at > NOW()) DESC,
                       -- 2. NON-SYSTEM beats system. A 'manual' (portal
                       --    AssignRole) or 'scim' row is an operator's or an
                       --    IdP's deliberate act; a 'system' row is ours to
                       --    manage. Ranking operator data first means the
                       --    DELETE below never removes it.
                                (ra.source IS DISTINCT FROM 'system') DESC,
                       -- 3-4. Never-expiring, then latest expiry: dropping a
                       --    NULL expires_at in favour of a dated one
                       --    time-bombs the owner.
                                (ra.expires_at IS NULL) DESC,
                                ra.expires_at DESC NULLS LAST,
                       -- 5. Already-canonical: no window where nothing matches.
                                (ra.user_email = axonflow_canonical_email(ra.user_email)) DESC,
                       -- 6. Deterministic across re-runs.
                                ra.id
                   ) AS rn
            FROM role_assignments ra
            JOIN organizations o ON o.org_id = ra.org_id
            -- VISIBILITY IS DELIBERATELY UNFILTERED BY source (R3 pass 2, F1).
            -- The unique constraint this protects,
            -- uq_role_assignments_user_role (org_id, user_email, role_id), has
            -- NO source column. An earlier revision ranked only
            -- source='system' rows, so an ordinary portal-granted
            -- ('manual', the column DEFAULT) row already holding the canonical
            -- key was invisible to the collapse and still a live collision
            -- target for the re-key UPDATE below:
            --   duplicate key value violates unique constraint
            --   "uq_role_assignments_user_role"
            -- Reachable with no hand-written SQL: 149's trigger writes the
            -- system row on a mixed-case contact_email, then the operator
            -- grants owner to the lowercase address through the portal.
            -- Rank against EVERY row that can occupy the target key; restrict
            -- only the DELETE.
              AND axonflow_canonical_email(ra.user_email) = axonflow_org_login_identity(o.contact_email)
        )
        SELECT * FROM ranked;

        -- PROVENANCE TRANSFER — run BEFORE the delete, while the collapsed rows
        -- still exist (#3005 follow-up).
        --
        -- The class the collapse most often finds on a replay holds exactly two
        -- rows for ONE principal: the org-login identity's original owner grant
        -- (149's org-creation trigger, keyed on the RAW contact_email) and the
        -- CANONICAL row migration 149's backfill created for the same identity.
        -- Rule 5 keeps the canonical one, so the row that DISAPPEARS is the
        -- pre-existing grant and the row that SURVIVES is marked
        -- 'migration:149_owner_backfill'. Two things then break:
        --
        --   * 149's no-escalation check requires a non-backfill qualifier for
        --     every backfilled owner row. The only qualifier was the row just
        --     deleted, so a later hand re-run of 149 aborts with
        --     "N backfilled owner assignment(s) went to principals that did not
        --      hold sso:configure pre-upgrade (escalation)" — and run.go
        --     log.Fatalf's on a failed migration, so that is a boot loop.
        --   * 149's DOWN deletes exactly the rows carrying the backfill marker.
        --     After the collapse that marker sits on a grant which PREDATES the
        --     backfill, so rolling 149 back would delete the org's only owner.
        --
        -- Both are artefacts of the collapse discarding provenance. Collapsing
        -- two spellings of one grant should preserve the ORIGINAL grant's
        -- attribution, not the migration's: the principal held owner before and
        -- after, and only the key's spelling changed. So the survivor inherits
        -- it. Restricted to a survivor that carries the backfill marker (the
        -- only case where the marker is a lie) and to a donor that does not.
        UPDATE role_assignments ra
           SET assigned_by = prior.assigned_by
          FROM mig150_owner_login_classes s,
               LATERAL (
                   SELECT d.assigned_by
                   FROM mig150_owner_login_classes d
                   WHERE d.org_id = s.org_id
                     AND d.role_id = s.role_id
                     AND d.canonical_email = s.canonical_email
                     AND d.rn > 1
                     AND (d.source = 'system'
                          OR NOT (d.expires_at IS NULL OR d.expires_at > NOW()))
                     AND COALESCE(d.assigned_by, '') <> 'migration:149_owner_backfill'
                   -- Deterministic across re-runs, and prefers the most
                   -- deliberate attribution: an operator/IdP row over a system
                   -- one, then the oldest.
                   ORDER BY (d.source IS DISTINCT FROM 'system') DESC,
                            d.assigned_at, d.id
                   LIMIT 1
               ) prior
         WHERE ra.id = s.id
           AND s.rn = 1
           AND s.assigned_by = 'migration:149_owner_backfill';
        GET DIAGNOSTICS v_inherited = ROW_COUNT;

        DELETE FROM role_assignments ra
        USING mig150_owner_login_classes c
        WHERE ra.id = c.id
          AND c.rn > 1
          -- Delete only what is ours to delete: a system row (the migration
          -- created it and will re-key its surviving sibling), or an already
          -- EXPIRED duplicate of any source (it confers nothing, and leaving
          -- it would keep occupying the canonical key the re-key needs).
          -- A LIVE non-system duplicate is left untouched — and cannot cause a
          -- collision, because a live non-system row always outranks every
          -- system row in its class (rule 2), so no system row survives in
          -- that class to be re-keyed onto it.
          AND (c.source = 'system'
               OR NOT (c.expires_at IS NULL OR c.expires_at > NOW()));
        GET DIAGNOSTICS v_collided = ROW_COUNT;

        UPDATE role_assignments ra
           SET user_email = axonflow_canonical_email(ra.user_email)
          FROM organizations o
         WHERE o.org_id = ra.org_id
           AND ra.source = 'system'
           AND axonflow_canonical_email(ra.user_email) = axonflow_org_login_identity(o.contact_email)
           AND ra.user_email <> axonflow_canonical_email(ra.user_email);
        GET DIAGNOSTICS v_rekeyed = ROW_COUNT;

        IF v_rekeyed > 0 OR v_collided > 0 OR v_inherited > 0 THEN
            RAISE NOTICE 'Migration 150: re-keyed % org-login role assignment(s) to canonical form (collapsed % duplicate(s) that canonicalized onto a surviving row; % survivor(s) inherited the collapsed row''s attribution), so they match the identity the login now presents', v_rekeyed, v_collided, v_inherited;
        END IF;
    END;

    RAISE NOTICE 'Migration 150: owner grants now require a real identity';
END $$;

-- ============================================================================
-- Verification — fail loudly if the migration left an inconsistent state.
-- ============================================================================
DO $$
DECLARE
    v_bad INTEGER;
    v_rc  INTEGER;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'role_assignments'
    ) THEN
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'axonflow_is_grantable_identity') THEN
        RAISE EXCEPTION 'Migration 150 failed: axonflow_is_grantable_identity missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'ensure_org_owner_assignment') THEN
        RAISE EXCEPTION 'Migration 150 failed: ensure_org_owner_assignment missing';
    END IF;
    IF has_function_privilege('public',
        'ensure_org_owner_assignment(character varying, character varying, character varying, timestamp with time zone)',
        'EXECUTE') THEN
        RAISE EXCEPTION 'Migration 150 failed: PUBLIC can EXECUTE ensure_org_owner_assignment';
    END IF;

    -- The predicate itself behaves as specified. Cheap, and it catches a
    -- botched re-definition before any caller depends on it.
    IF axonflow_is_grantable_identity('') OR axonflow_is_grantable_identity('   ')
       OR axonflow_is_grantable_identity(NULL)
       OR axonflow_is_grantable_identity('acme@axonflow.local')
       OR axonflow_is_grantable_identity('SYSTEM@AXONFLOW.INTERNAL')
       OR axonflow_is_grantable_identity('mcp-client:abc')
       OR axonflow_is_grantable_identity('evaluator@try.getaxonflow.com') THEN
        RAISE EXCEPTION 'Migration 150 failed: axonflow_is_grantable_identity accepted a non-identity';
    END IF;
    IF NOT axonflow_is_grantable_identity('ops@example.com')
       OR NOT axonflow_is_grantable_identity('portal-admin@axonflow.invalid') THEN
        RAISE EXCEPTION 'Migration 150 failed: axonflow_is_grantable_identity rejected a real identity';
    END IF;

    -- The choke point actually refuses. Uses a non-existent org so nothing is
    -- written on any code path: the identity guard runs BEFORE the org lookup,
    -- so a refusal returns -2 while an accepted identity would fall through to
    -- -1 (no system owner role) — which is exactly the discrimination we want
    -- to assert.
    --
    -- The probes are SILENCED for the duration (#3005 R3 pass 6). The choke
    -- point RAISEs a WARNING every time it refuses an identity — correctly, for
    -- a real caller — but here the "caller" is this migration proving to itself
    -- that the refusal works. Now that the runner actually surfaces server
    -- messages, those two lines were the FIRST ⚠️ WARNINGs an operator ever saw
    -- from a migration, on a perfectly healthy fresh install, about an org that
    -- does not exist. That teaches them the marker is noise — and the marker
    -- exists so they do not scroll past migration 149's canary, which reports a
    -- silently incomplete upgrade. SET LOCAL, so it reverts at COMMIT and
    -- suppresses nothing outside these two statements; a genuine failure here
    -- still RAISEs an EXCEPTION, which is not a client message.
    SET LOCAL client_min_messages = ERROR;
    SELECT ensure_org_owner_assignment('__mig150_verify_nonexistent_org__', '') INTO v_rc;
    IF v_rc <> -2 THEN
        RESET client_min_messages;
        RAISE EXCEPTION 'Migration 150 failed: ensure_org_owner_assignment accepted a blank identity (rc=%)', v_rc;
    END IF;
    SELECT ensure_org_owner_assignment('__mig150_verify_nonexistent_org__', 'x@axonflow.local') INTO v_rc;
    IF v_rc <> -2 THEN
        RESET client_min_messages;
        RAISE EXCEPTION 'Migration 150 failed: ensure_org_owner_assignment accepted a reserved synthetic identity (rc=%)', v_rc;
    END IF;
    RESET client_min_messages;

    -- No non-identity owner grant survives.
    SELECT COUNT(*) INTO v_bad
    FROM role_assignments ra
    JOIN custom_roles cr ON cr.id = ra.role_id AND cr.org_id = ra.org_id
    WHERE cr.name = 'owner'
      AND ra.source = 'system'
      AND NOT axonflow_is_grantable_identity(ra.user_email);
    IF v_bad > 0 THEN
        RAISE EXCEPTION 'Migration 150 failed: % system owner assignment(s) still keyed on a blank or synthetic identity', v_bad;
    END IF;

    -- The revive policy exists and discriminates. Without this, migration 149's
    -- revive silently disappearing under 150's redefinition — which is exactly
    -- what shipped — leaves no trace at all: every caller still gets a plausible
    -- return code and break-glass reports "already_held" on an org with zero
    -- live owners.
    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'axonflow_owner_grant_may_revive') THEN
        RAISE EXCEPTION 'Migration 150 failed: axonflow_owner_grant_may_revive missing';
    END IF;
    IF NOT axonflow_owner_grant_may_revive('migration:149_owner_backfill')
       OR NOT axonflow_owner_grant_may_revive('break-glass:ops@example.com') THEN
        RAISE EXCEPTION 'Migration 150 failed: axonflow_owner_grant_may_revive refuses an intentional first-owner caller; break-glass cannot recover an org whose only owner row expired';
    END IF;
    IF axonflow_owner_grant_may_revive('system:portal-bootstrap')
       OR axonflow_owner_grant_may_revive('system:org-bootstrap')
       OR axonflow_owner_grant_may_revive('system:org-create-api')
       OR axonflow_owner_grant_may_revive('system')
       OR axonflow_owner_grant_may_revive('')
       OR axonflow_owner_grant_may_revive(NULL) THEN
        RAISE EXCEPTION 'Migration 150 failed: axonflow_owner_grant_may_revive accepts an AMBIENT caller; every portal restart would silently make a lapsed time-boxed owner grant permanent';
    END IF;
    -- The choke point must actually CARRY the revive. Asserted on the function
    -- SOURCE, not on behavior: a behavioral probe needs an expired owner row to
    -- exist, and on a fresh database there is none — which is precisely how the
    -- missing revive shipped green.
    IF (SELECT pg_get_functiondef(
            'ensure_org_owner_assignment(varchar,varchar,varchar,timestamptz)'::regprocedure))
        NOT LIKE '%axonflow_owner_grant_may_revive%' THEN
        RAISE EXCEPTION 'Migration 150 failed: ensure_org_owner_assignment does not call axonflow_owner_grant_may_revive — the expired-owner revive is not in the installed definition, so break-glass reports success on an org with zero live owners (#3005)';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'axonflow_org_login_identity') THEN
        RAISE EXCEPTION 'Migration 150 failed: axonflow_org_login_identity missing';
    END IF;
    -- The org-login expression: canonical when real, NULL when blank (never '').
    IF axonflow_org_login_identity('  Ops@Example.COM ') <> 'ops@example.com'
       OR axonflow_org_login_identity('') IS NOT NULL
       OR axonflow_org_login_identity('   ') IS NOT NULL
       OR axonflow_org_login_identity(NULL) IS NOT NULL
       OR axonflow_org_login_identity('x@axonflow.local') IS NOT NULL THEN
        RAISE EXCEPTION 'Migration 150 failed: axonflow_org_login_identity does not mirror ResolveOrgBootstrapIdentity';
    END IF;

    -- Every org-login system grant must now be stored canonically, or the
    -- session identity will not match it (the #3000 re-key gap).
    SELECT COUNT(*) INTO v_bad
    FROM role_assignments ra
    JOIN organizations o ON o.org_id = ra.org_id
    WHERE ra.source = 'system'
      AND ra.user_email <> axonflow_canonical_email(ra.user_email)
      AND axonflow_canonical_email(ra.user_email) = axonflow_org_login_identity(o.contact_email);
    IF v_bad > 0 THEN
        RAISE EXCEPTION 'Migration 150 failed: % org-login assignment(s) still stored in non-canonical form; the login would present a different key and resolve zero permissions', v_bad;
    END IF;

    RAISE NOTICE 'Migration 150 verified: choke point refuses non-identities, no blank-keyed owner grants remain, org-login grants canonical';
END $$;

COMMIT;
