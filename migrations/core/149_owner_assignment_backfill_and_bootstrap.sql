-- Migration 149: close the owner-assignment lockout (#2997)
-- Date: 2026-07-22
--
-- ============================================================================
-- Why
-- ============================================================================
-- The #2993 five-tier model (mig 148 + PR #2995) makes `sso:configure`
-- OWNER-RESERVED: the "*" wildcard no longer grants it, so only a principal
-- holding the `owner` role can configure SSO / SCIM / detection-posture. It
-- also adds an anti-escalation gate (roles/service.go assertMayConferPermissions)
-- so an actor may not create/update/assign a role conferring an owner-reserved
-- permission it does not itself hold.
--
-- But NOTHING assigns anyone the `owner` role. Mig 148 seeds the role
-- DEFINITION and deliberately leaves `role_assignments` untouched. On upgrade
-- that composes into a permanent lockout:
--
--     no user holds `owner`
--       -> no user holds `sso:configure`
--       -> an `admin` (wildcard only) is BLOCKED by the anti-escalation gate
--          from granting it to anyone, including itself
--       -> SSO / SCIM / detection-posture configuration is unreachable
--          through the portal, forever, with no in-product recovery.
--
-- The same gap exists at new-org creation and on a default axonflow-install
-- deployment, whose bootstrap operator logs in with org + password and carries
-- NO role assignment at all.
--
-- ============================================================================
-- What this migration does
-- ============================================================================
--   1. ensure_org_owner_assignment(org, email, assigned_by, expires_at)
--      — the ONE choke point that grants an org's system `owner` role to one
--      identity. SECURITY DEFINER / BYPASSRLS, idempotent. Every path that
--      needs to create an owner (the org-creation trigger, this migration's
--      backfill, the portal bootstrap, the admin break-glass API) routes
--      through it, so no future writer can reinvent a divergent grant.
--
--   2. ensure_org_owner_backfill(org) + a backfill loop over every existing
--      org — grants `owner` to exactly those principals who ALREADY held
--      `sso:configure` under PRE-#2995 semantics. See "the predicate" below.
--
--   3. trg_ensure_org_system_roles() is extended so a NEWLY CREATED org also
--      gets an owner ASSIGNMENT (not just the role definitions), keyed on the
--      identity that org's password login actually presents. A companion
--      AFTER UPDATE OF contact_email trigger re-seeds the owner when that
--      login identity changes, so an org can't edit itself back into lockout.
--
--      *** SUPERSEDED BY MIGRATION 150 (#3003) ***
--      That AFTER UPDATE OF contact_email trigger was a privilege-escalation
--      vector and migration 150 DROPS it. The claim further down this file —
--      that the drift re-seed "can never be driven by an unprivileged portal
--      session" — was true of the ROUTER but wrong about the AUTH BAR:
--      HandleUpdateOrganization had no strict-admin check, and admin_auth
--      passes callers through anonymously when ADMIN_API_KEY is unset (the
--      shipped default). The re-seed now happens in that handler, behind an
--      authenticated-admin check, and emits an ASSIGN_OWNER audit row.
--      The INSERT-side bootstrap below is unaffected.
--
-- ============================================================================
-- The predicate — capability-PRESERVING, never widening
-- ============================================================================
-- Granting a privileged role from a migration is only safe if it confers
-- nothing new. The backfill grants `owner` to a principal if and only if it
-- currently holds a NON-EXPIRED assignment to a role whose permission bundle
-- contains `"*"` OR `"sso:configure"`.
--
-- Under pre-#2995 semantics `"*"` granted EVERYTHING, `sso:configure`
-- included. So that predicate is exactly "held sso:configure before the
-- upgrade" — the capability #2995 took away and this restores. Nothing else.
-- Walking the role bundles as mig 148 leaves them:
--
--   admin        ["*"]                             -> qualifies. Correct: an
--                                                    admin's "*" granted
--                                                    sso:configure pre-upgrade.
--   owner        ["*","sso:configure"]             -> qualifies, and the grant
--                                                    is a self-conflict no-op.
--   policy_admin ["policy:write","policy:delete",
--                 "audit:read","token:rotate:self"] -> does NOT qualify. Correct:
--                                                    its pre-146/pre-148 bundle
--                                                    never contained
--                                                    sso:configure either.
--   developer    ["token:rotate:self"]             -> does NOT qualify. Correct.
--   viewer       ["audit:read"]                    -> does NOT qualify. Correct.
--   member       (pruned by 148, or left inert)    -> does NOT qualify. Correct.
--   CUSTOM roles (untouched by 148)                -> qualify iff they carry
--                                                    "*" or sso:configure —
--                                                    which is precisely what
--                                                    they granted before.
--
-- EXPIRY is carried, not dropped: a principal whose only qualifying assignment
-- expires next week gets an owner grant that expires at the same instant
-- (NULL — never expires — wins if ANY qualifying assignment is non-expiring).
-- Granting a permanent owner off a temporary admin would be a widening.
-- Already-expired assignments are ignored: their holder does not hold
-- sso:configure *now*, so granting them owner would be a widening too.
--
-- What this deliberately does NOT do: it does not grant `owner` broadly (e.g.
-- to every user with any assignment) and it does not weaken the anti-escalation
-- gate. The gate must keep returning 403 for an admin self-assigning owner —
-- an out-of-band migration / platform-admin path is exactly the right shape for
-- a first-owner grant, and that is what this is.
--
-- ============================================================================
-- SCIM safety
-- ============================================================================
-- Every row written here carries source='system'. SCIM group sync only removes
-- assignments with source='scim' (scim/service.go SyncUserRoles: "If Source is
-- manual or anything else, leave it alone"), so a later re-sync can never strip
-- a backfilled owner. See ee/docs/scim/group-role-mapping.md.
--
-- ============================================================================
-- Idempotency + reversibility
-- ============================================================================
-- Every INSERT is ON CONFLICT (org_id, user_email, role_id) DO NOTHING against
-- uq_role_assignments_user_role (mig 023, columns renamed by mig 111), so a
-- re-run inserts nothing and changes nothing.
--
-- The backfill stamps assigned_by = 'migration:149_owner_backfill'. The DOWN
-- deletes exactly those rows. That marker cannot collide with pre-existing
-- data: because the INSERT is ON CONFLICT DO NOTHING, a row that already
-- existed for the same (org, email, owner-role) keeps ITS assigned_by and is
-- never rewritten — so the only rows carrying the marker are ones a run of THIS
-- migration inserted. Manually- and SCIM-granted owner rows are untouched by
-- both the UP and the DOWN.
--
-- ============================================================================
-- Known org shape this cannot repair (detectable, not silent)
-- ============================================================================
-- If an org has a CUSTOM (is_system=false) role occupying the canonical name
-- 'owner', mig 148's is_system-guarded UPSERT cannot create a system owner for
-- it (uq_custom_roles_org_name). ensure_org_owner_assignment returns -1 and
-- RAISEs a NOTICE for that org rather than silently granting a role whose
-- permissions the platform does not define. The admin break-glass API surfaces
-- it as a 409 with remediation.
--
-- #3005-A: that remediation used to read "rename the custom role, RESTART THE
-- AGENT so the system-role seeder re-runs, then retry" — which never worked.
-- Nothing invoked ensure_org_system_roles at runtime; its only callers were the
-- org-creation trigger (INSERT only) and the migrations (which do not re-run),
-- so restarting repaired nothing for an existing org. The break-glass handler
-- now calls the seeder itself and retries the grant (self-healing for the
-- common "org was simply never seeded" shape), and the 409 it returns when a
-- CUSTOM role genuinely occupies the name now carries remediation that works:
--     psql "$DATABASE_URL" -c "SELECT ensure_org_system_roles('<org_id>');"
-- after renaming that role. UPGRADING.md (install repo) needs the same
-- correction — its text was copied from here.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'custom_roles'
    ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'role_assignments'
    ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'organizations'
    ) THEN
        RAISE NOTICE 'Migration 149: custom_roles/role_assignments/organizations absent - skipping';
        RETURN;
    END IF;

    -- ========================================================================
    -- 1. The choke point: grant an org's system `owner` role to ONE identity.
    -- ========================================================================
    -- Returns 1 when it inserted, 0 when the assignment already existed, and
    -- -1 when the org has no SYSTEM role named 'owner' (see the "known org
    -- shape" note above) so callers can distinguish "already fine" from
    -- "cannot be fixed here".
    --
    -- p_user_email may legitimately be the EMPTY STRING. That is not a bug: an
    -- org-level portal login (org_id + password) presents
    -- organizations.contact_email as its session user_email, or '' when the org
    -- has none (api/auth.go HandleLogin).
    --
    -- SUPERSEDED BY MIGRATION 150 (#3000). '' turned out NOT to be a real
    -- principal but a WILDCARD: permission resolution is
    -- UserHasPermission(org_id, user_email, perm), so every session in the org
    -- that resolves to '' matches a ''-keyed grant and inherits owner —
    -- including an SSO/OIDC session whose email claim is missing or unmapped.
    -- Migration 150 redefines this function with a guard that REFUSES a blank
    -- or reserved-synthetic target.
    --
    -- ========================================================================
    -- 0. The canonical-email expression (shared with migration 150).
    -- ========================================================================
    -- Defined HERE, not only in 150, so that 149 and 150 canonicalize
    -- IDENTICALLY at every point in the chain (#3015 BLOCKER 2). 149's own
    -- verification compares a repaired key against a qualifier key; if it used
    -- lower(btrim(...)) while 150's choke point stores
    -- axonflow_canonical_email(...), the two disagree on any address carrying a
    -- tab or NBSP (btrim strips ASCII space ONLY) and a hand re-run of 149
    -- aborts — which run.go turns into a permanent boot loop.
    --
    -- CREATE OR REPLACE with a body byte-identical to 150's, so whichever
    -- migration runs first installs the same function and the other is a no-op.
    EXECUTE $canonfn$
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
        $body$;;
    $canonfn$;

    -- ========================================================================
    -- 0a. WHICH CALLERS MAY REVIVE AN EXPIRED OWNER ROW.
    -- ========================================================================
    -- Defined HERE and re-defined BYTE-IDENTICALLY in migration 150, for the
    -- same reason as axonflow_canonical_email above: both migrations' copies of
    -- the choke point call it, and whichever runs first must install the same
    -- policy.
    --
    -- THE POLICY. ensure_org_owner_assignment has four callers and they split
    -- cleanly in two:
    --
    --   INTENTIONAL first-owner acts — the migration-149 backfill (an upgrade
    --   repair, carrying the pre-upgrade expiry forward) and the ADMIN_API_KEY
    --   break-glass endpoint (an operator explicitly saying "make this identity
    --   the owner"). For these, a conflicting row that is ALREADY EXPIRED is
    --   the thing they were asked to fix, so it is revived.
    --
    --   AMBIENT re-assertions — the org-creation trigger and the portal's
    --   EnsureDeploymentOrgOwner, which runs on EVERY boot. For these a revive
    --   would silently convert a deliberately time-boxed owner grant (a
    --   contractor, an incident window) into a permanent one on the next
    --   restart, attributed to whoever made the temporary grant. They keep
    --   strict DO NOTHING semantics.
    --
    -- The markers are the Go constants in
    -- ee/platform/customer-portal/api/owner_bootstrap.go; the two halves are
    -- pinned in lockstep by TestOwnerGrantReviveMarkersMatchGo_RealPostgres, so renaming a
    -- constant on either side fails CI rather than silently disabling the
    -- revive on the recovery path.
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

    -- Re-running 149 by hand is a DOCUMENTED recovery action, and a bare
    -- CREATE OR REPLACE would silently roll the function back to the unguarded
    -- pre-#3000 definition on a database that has already applied 150 —
    -- re-opening the privilege hole with no error and no trace.
    --
    -- An earlier fix SKIPPED the redefinition entirely when 150's guard was
    -- present. That is worse (#3015 BLOCKER 1): it also discards every LATER
    -- change to this function's body, so a fix-forward migration that extends
    -- the choke point is silently not installed on any stack that already ran
    -- 150 — the change appears to apply and simply does not exist.
    --
    -- So: redefine UNCONDITIONALLY, and make the guard CALL conditional.
    -- to_regprocedure() returns NULL rather than raising when the function is
    -- absent, and the call is dispatched through EXECUTE so the body does not
    -- fail to parse on a first pass where 150 has not run yet. Result: one
    -- definition, correct at every point in the chain — guarded once 150 is in,
    -- unguarded before that, exactly as 149 alone always behaved.
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
            v_grantable     BOOLEAN;
            v_email         VARCHAR;
        BEGIN
            IF p_org_id IS NULL OR p_org_id = '' THEN
                RETURN 0;
            END IF;

            -- #3000 identity guard, called only if migration 150 has installed
            -- it. EXECUTE (not a direct call) so this body parses on a chain
            -- where 150 has not run yet.
            IF to_regprocedure('axonflow_is_grantable_identity(varchar)') IS NOT NULL THEN
                EXECUTE 'SELECT axonflow_is_grantable_identity($1)'
                   INTO v_grantable USING p_user_email;
                IF NOT v_grantable THEN
                    RAISE WARNING 'ensure_org_owner_assignment: refusing to grant owner on org % to %, which is blank or a reserved platform synthetic identity (#3000)',
                        p_org_id, COALESCE(NULLIF(p_user_email, ''), '<blank>');
                    RETURN -2;
                END IF;
            END IF;

            -- Storage form follows WHETHER 150 HAS RUN, for the same reason
            -- the guard call above does.
            --
            -- Pre-150 (a first pass, or a genuinely old stack): RAW. That is
            -- what every already-deployed 149-era stack's rows look like, and
            -- it is the legacy shape 150's repair and the #3002 seeded-data
            -- gate are written against.
            --
            -- Post-150: CANONICAL. Conditionalizing the guard but NOT the
            -- storage was a real bug: 149 redefines unconditionally, so a hand
            -- re-run — the documented recovery action — rolled the choke point
            -- back to raw storage on an upgraded stack. Every later first-owner
            -- write (portal boot grant, break-glass, the org-creation trigger)
            -- then stored a raw key while HandleLogin presents the CANONICAL
            -- one, and UserHasPermission resolved zero assignments. That is the
            -- #2997 lockout, re-created by the recovery action, silently.
            --
            -- The sentinel is axonflow_is_grantable_identity, which ONLY 150
            -- defines — deliberately not axonflow_canonical_email, which THIS
            -- migration defines above and which would therefore always be
            -- present and always select the canonical branch.
            IF to_regprocedure('axonflow_is_grantable_identity(varchar)') IS NOT NULL THEN
                EXECUTE 'SELECT axonflow_canonical_email($1)'
                   INTO v_email USING p_user_email;
            ELSE
                v_email := COALESCE(p_user_email, '');
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

            -- #3005-B: revive an EXPIRED owner row instead of skipping it.
            --
            -- With a bare DO NOTHING, a principal holding a live wildcard role
            -- plus an ALREADY-EXPIRED owner row matched the conflict target and
            -- was skipped — so it was granted nothing, while the backfill's
            -- completeness check (which filters expires_at > NOW()) then saw a
            -- principal that held sso:configure pre-upgrade but holds no LIVE
            -- owner, and aborted the whole migration:
            --   "Migration 149 failed: 1 principal(s) held sso:configure
            --    pre-upgrade but hold no owner role" -> ROLLBACK.
            -- Unrecoverable without manual SQL, and a re-run failed identically
            -- while the agent runs migrations at boot.
            --
            -- DO UPDATE only when the existing row is genuinely expired, so this
            -- stays idempotent (a live row is still a no-op) and never shortens
            -- or extends a live grant. assigned_by is deliberately NOT touched:
            -- the DOWN deletes on that marker, and rewriting it would let this
            -- migration claim — and later delete — a row a human or SCIM created.
            --
            -- SCOPED TO THE INTENTIONAL FIRST-OWNER CALLERS (#3005 R3 H1).
            -- This function is a shared choke point with four callers; only the
            -- backfill and the ADMIN_API_KEY break-glass endpoint are explicit
            -- acts of establishing an owner. The org-creation trigger and the
            -- portal's EnsureDeploymentOrgOwner (every boot) are ambient, and an
            -- unguarded DO UPDATE would make every restart silently convert a
            -- LAPSED, deliberately time-boxed owner grant into a PERMANENT one,
            -- attributed in the audit trail to whoever originally made the
            -- temporary grant (assigned_by is not rewritten). An operator who
            -- time-boxes owner for a contractor or an incident window would get
            -- it quietly restored forever.
            --
            -- axonflow_owner_grant_may_revive() is that policy, defined once
            -- above and shared with migration 150's copy of this body — see its
            -- header. Sniffing the marker inline here (as an earlier revision
            -- did, hard-coding the backfill string) meant migration 150's
            -- redefinition of this function silently dropped the revive
            -- entirely, so break-glass on an org whose only owner row had
            -- expired returned "already_held" and granted nothing.
            --
            -- source is set to 'system' on the revive (#3005 R3 M2) to preserve
            -- this migration's documented SCIM-safety invariant: a revived row
            -- that kept source='scim' would be deleted by the next SCIM sync in
            -- which the user is no longer in the mapped group — re-opening the
            -- very lockout this migration exists to close, and doing so AFTER
            -- the completeness check below has already passed.
            --
            -- NOT REVERSIBLE, deliberately (#3005 R3 M1). The DOWN deletes rows
            -- carrying the backfill marker; a REVIVED row is a pre-existing row
            -- and keeps its original assigned_by, so the DOWN leaves it live.
            -- Reversing the revive would require remembering each prior
            -- expires_at, which this migration does not record. Rolling 149 back
            -- therefore restores the pre-149 row SET but not the pre-149 expiry
            -- of a revived owner. Stated here because the two headers below
            -- describe the INSERT path only.
            INSERT INTO role_assignments (org_id, user_email, role_id, assigned_by, assigned_at, expires_at, source)
            VALUES (p_org_id, v_email, v_owner_role_id,
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
            'Idempotently grants an org''s SYSTEM owner role to one identity with '
            'source=''system'' (never stripped by SCIM sync). The single choke point '
            'for first-owner creation: org-creation trigger, mig 149 backfill, portal '
            'bootstrap and the admin break-glass API all route through it. Returns '
            '1=granted, 0=already held, -1=no system owner role for the org, '
            '-2=target refused as blank/reserved-synthetic once mig 150 is applied (#2997, #3000).'
    $c$;

    -- ========================================================================
    -- 2. Per-org backfill of the capability-preserving predicate.
    -- ========================================================================
    -- SECURITY DEFINER (BYPASSRLS owner) so the reads and the write are not
    -- subject to the role_assignments / custom_roles org-isolation policies —
    -- there is no single app.current_org_id for a cross-org backfill, and the
    -- per-org call keeps each grant scoped to exactly one org anyway.
    EXECUTE $fn$
        CREATE OR REPLACE FUNCTION ensure_org_owner_backfill(p_org_id VARCHAR)
        RETURNS INTEGER
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $body$
        DECLARE
            v_row     RECORD;
            v_granted INTEGER := 0;
            v_n       INTEGER;
        BEGIN
            IF p_org_id IS NULL OR p_org_id = '' THEN
                RETURN 0;
            END IF;

            FOR v_row IN
                SELECT ra.user_email,
                       -- NULL (never expires) wins; otherwise the LATEST expiry
                       -- among the qualifying assignments. Exactly preserves the
                       -- window in which the principal held sso:configure.
                       CASE WHEN bool_or(ra.expires_at IS NULL)
                            THEN NULL
                            ELSE MAX(ra.expires_at)
                       END AS effective_expires_at
                FROM role_assignments ra
                JOIN custom_roles cr
                  ON cr.id = ra.role_id AND cr.org_id = ra.org_id
                WHERE ra.org_id = p_org_id
                  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
                  AND (cr.permissions @> '["*"]'::jsonb
                       OR cr.permissions @> '["sso:configure"]'::jsonb)
                GROUP BY ra.user_email
            LOOP
                v_n := ensure_org_owner_assignment(
                    p_org_id, v_row.user_email,
                    'migration:149_owner_backfill', v_row.effective_expires_at);
                IF v_n > 0 THEN
                    v_granted := v_granted + v_n;
                END IF;
            END LOOP;

            RETURN v_granted;
        END;
        $body$;
    $fn$;

    EXECUTE $c$
        COMMENT ON FUNCTION ensure_org_owner_backfill(VARCHAR) IS
            'Grants the owner role to every principal in an org that already held '
            'sso:configure under pre-#2995 semantics (a non-expired assignment to a '
            'role carrying "*" or "sso:configure"), carrying the expiry forward. '
            'Capability-preserving by construction — never widening (#2997).'
    $c$;

    -- ========================================================================
    -- 3. New orgs: seed the owner ASSIGNMENT, not just the definitions.
    -- ========================================================================
    -- The mig 146 trigger function seeded role DEFINITIONS only. Extend it so a
    -- newly created org's password-login identity is an owner from birth. Kept
    -- as one trigger function (rather than a second trigger) so the ordering is
    -- explicit: definitions first, then the assignment that references them.
    --
    -- The identity is COALESCE(NULLIF(contact_email,''), '') — precisely what
    -- api/auth.go HandleLogin puts in the session for an org+password login.
    -- Deriving it from the SAME column the login reads is what keeps this from
    -- granting owner to an identity that can never present itself.
    --
    -- The owner-assignment leg is EXCEPTION-guarded. This trigger runs inside
    -- the caller's `INSERT INTO organizations` transaction (the admin
    -- onboard/create-org handlers, the agent's license promotion, mig 094's
    -- seed, raw SQL), so an unhandled error here would abort ORG CREATION
    -- itself — trading a recoverable authorization gap for an unrecoverable
    -- one. Mig 146 made the same call for its seed rows. A failed grant is
    -- logged and the org is still created; the portal bootstrap re-runs on the
    -- next boot and the break-glass API remains available.
    EXECUTE $tf$
        CREATE OR REPLACE FUNCTION trg_ensure_org_system_roles()
        RETURNS TRIGGER
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $body$
        BEGIN
            PERFORM ensure_org_system_roles(NEW.org_id);
            BEGIN
                PERFORM ensure_org_owner_assignment(
                    NEW.org_id,
                    COALESCE(NULLIF(NEW.contact_email, ''), ''),
                    'system:org-bootstrap',
                    NULL);
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'trg_ensure_org_system_roles: owner assignment for org % failed (%); org created without an owner — use the admin break-glass endpoint (#2997)', NEW.org_id, SQLERRM;
            END;
            RETURN NEW;
        END;
        $body$;
    $tf$;

    -- Drift guard: an org that CHANGES its contact_email changes the identity
    -- its password login presents, which would strand the owner grant on the
    -- old identity and re-open the lockout. Re-seed on that transition. Only
    -- the admin-API-gated paths write this column (api/organizations.go
    -- HandleCreateOrganization / HandleUpdateOrganization, api/admin.go
    -- HandleOnboardCustomer), all behind ADMIN_API_KEY — so this can never be
    -- driven by an unprivileged portal session. The OLD identity's grant is
    -- left in place: revoking a live owner from a trigger is the kind of
    -- silent privilege removal that causes the outage this migration exists to
    -- prevent; prune it deliberately via the roles API if desired.
    EXECUTE $tf$
        CREATE OR REPLACE FUNCTION trg_reseed_org_owner_on_contact_change()
        RETURNS TRIGGER
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $body$
        BEGIN
            -- Same reasoning as the create trigger: never let a failed grant
            -- abort the operator's UPDATE on organizations.
            BEGIN
                PERFORM ensure_org_owner_assignment(
                    NEW.org_id,
                    COALESCE(NULLIF(NEW.contact_email, ''), ''),
                    'system:org-contact-change',
                    NULL);
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'trg_reseed_org_owner_on_contact_change: owner re-seed for org % failed (%); the new contact identity holds no owner — use the admin break-glass endpoint (#2997)', NEW.org_id, SQLERRM;
            END;
            RETURN NEW;
        END;
        $body$;
    $tf$;

    -- THE reseed_org_owner_on_contact_change TRIGGER IS NOT CREATED (#3003).
    --
    -- It used to be created here, re-seeding the owner grant onto whatever
    -- identity an org's contact_email was changed to. That confers `owner`
    -- ANONYMOUSLY: anyone able to change contact_email — including paths that
    -- are not the owner themselves — mints a top-role grant for an address of
    -- their choosing. Migration 152 drops it for stacks that already applied
    -- this file, and it is removed here so a REPLAY of 149 cannot resurrect it
    -- (#3015 BLOCKER 3).
    --
    -- Deleting the CREATE rather than leaving it for 152 to undo matters: the
    -- migration runner re-applies files during a hand recovery, and a
    -- create-then-drop pair across two migrations resurrects the behavior on
    -- every replay where 149 runs after 152 has already run.
    --
    -- trg_reseed_org_owner_on_contact_change (the FUNCTION) is still defined
    -- above and left in place: 152's down re-creates the trigger, so the
    -- function must remain callable for a rollback to work. It is inert with
    -- no trigger bound to it.
    DROP TRIGGER IF EXISTS reseed_org_owner_on_contact_change ON organizations;

    -- Re-assert the org-creation trigger so 149 is self-contained on a DB where
    -- mig 146's trigger was dropped.
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'seed_org_system_roles' AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER seed_org_system_roles
            AFTER INSERT ON organizations
            FOR EACH ROW
            EXECUTE FUNCTION trg_ensure_org_system_roles();
        RAISE NOTICE 'Migration 149: re-created seed_org_system_roles trigger';
    END IF;

    -- ========================================================================
    -- 4. Ownership + grants (mirrors mig 146/148).
    -- ========================================================================
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        EXECUTE 'ALTER FUNCTION ensure_org_owner_assignment(VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ) OWNER TO axonflow_platform_admin';
        EXECUTE 'ALTER FUNCTION ensure_org_owner_backfill(VARCHAR) OWNER TO axonflow_platform_admin';
        EXECUTE 'ALTER FUNCTION trg_ensure_org_system_roles() OWNER TO axonflow_platform_admin';
        EXECUTE 'ALTER FUNCTION trg_reseed_org_owner_on_contact_change() OWNER TO axonflow_platform_admin';
        -- The definer reads custom_roles and writes role_assignments. mig 098
        -- grants full DML on ALL tables in public; re-assert narrowly so a DB
        -- that predates 098's blanket grant (or had it revoked) still works.
        EXECUTE 'GRANT SELECT ON custom_roles TO axonflow_platform_admin';
        EXECUTE 'GRANT SELECT, INSERT ON role_assignments TO axonflow_platform_admin';
    END IF;

    -- A privileged SECURITY DEFINER that writes a privilege grant must not be
    -- PUBLIC-callable (Postgres default-grants EXECUTE on CREATE FUNCTION).
    EXECUTE 'REVOKE EXECUTE ON FUNCTION ensure_org_owner_assignment(VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION ensure_org_owner_backfill(VARCHAR) FROM PUBLIC';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        -- The portal bootstrap + break-glass API run as app_role and must be
        -- able to call the choke point. app_role is NOBYPASSRLS; the grant is
        -- what lets it create an owner without a blanket write on the table.
        EXECUTE 'GRANT EXECUTE ON FUNCTION ensure_org_owner_assignment(VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ) TO axonflow_app_role';
    END IF;

    -- ========================================================================
    -- 5. Backfill every existing org.
    -- ========================================================================
    DECLARE
        v_org     RECORD;
        v_total   INTEGER := 0;
        v_orphans INTEGER := 0;
        v_n       INTEGER;
    BEGIN
        -- Same enumeration as mig 148's reconcile loop, for the same reason: a
        -- mig-023-seeded pseudo-tenant (e.g. 'global', keyed off DISTINCT
        -- dynamic_policies.tenant_id) has system roles but NO organizations
        -- row. Iterating organizations alone would silently leave its admins
        -- without an owner — the exact under-coverage this migration exists to
        -- prevent — and the completeness check below would not catch it,
        -- because 148 would not have created an owner role there either.
        FOR v_org IN
            SELECT org_id FROM organizations
            UNION
            SELECT DISTINCT org_id FROM custom_roles WHERE is_system AND org_id IS NOT NULL AND org_id <> ''
        LOOP
            v_n := ensure_org_owner_backfill(v_org.org_id);
            v_total := v_total + v_n;
        END LOOP;

        SELECT COUNT(*) INTO v_orphans
        FROM organizations o
        WHERE NOT EXISTS (
            SELECT 1
            FROM role_assignments ra
            JOIN custom_roles cr ON cr.id = ra.role_id AND cr.org_id = ra.org_id
            WHERE ra.org_id = o.org_id
              AND cr.name = 'owner'
              AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
        );

        -- RLS CANARY (#3005 R3 pass 4). Migration 151 documents this hazard and
        -- says "149's backfill loop has the same shape; noted there too" — it
        -- was not, until now.
        --
        -- Migrations run on the raw DATABASE_URL and never set
        -- app.current_org_id, and `organizations` is ENABLE + FORCE RLS (mig
        -- 103). FORCE is what makes this bite the TABLE OWNER as well, so a
        -- migration role that is neither a Postgres superuser nor BYPASSRLS
        -- sees ZERO rows here — whether it owns the table (FORCE is what binds
        -- the owner) or not (ENABLE alone binds everyone else). Reproduced on a
        -- real Postgres: 2 orgs present, `SELECT COUNT(*) FROM organizations`
        -- as such a role returns 0, and migration 149 emits this warning
        -- (TestMigration149EmitsItsRLSCanary_RealPostgres drives the real file
        -- through the real runner connection).
        --
        -- The reachable shape is an UPGRADE whose DATABASE_URL points at such a
        -- role. A FRESH chain cannot be applied by one at all — mig 098 needs
        -- superuser to set BYPASSRLS and aborts first — so this is not a
        -- claim about any particular managed-Postgres flavour; it is a claim
        -- about the role the connection string names, which is exactly what
        -- the predicate tests.
        --
        -- The loop above then iterates nothing from the organizations leg, the
        -- orphan report below counts nothing, and the migration announces
        -- success having done nothing. The UNION's custom_roles leg still
        -- covers orgs that HAVE system roles (custom_roles is ENABLE-only, so
        -- the owner is not subject to it) — but an org that never got system
        -- roles is invisible to both legs and stays locked out silently.
        --
        -- The predicate is a ROLE/CATALOG test, deliberately NOT "COUNT(*) = 0"
        -- (151's shape): a fresh install legitimately has zero orgs, so a
        -- count-based canary is ambiguous exactly when it fires. This one
        -- cannot false-positive on an empty database.
        --
        -- A WARNING, not an EXCEPTION: run.go log.Fatalf's on a failed
        -- migration, so aborting here would crash-loop the agent at boot on
        -- every affected deployment — turning a silent under-repair into a
        -- total outage. The repair itself (making these backfills work under a
        -- non-BYPASSRLS owner) is tracked separately; this makes it impossible
        -- for the upgrade to claim success while doing nothing.
        DECLARE
            v_blind BOOLEAN := FALSE;
        BEGIN
            SELECT NOT EXISTS (
                       SELECT 1 FROM pg_roles
                       WHERE rolname = current_user AND (rolsuper OR rolbypassrls)
                   )
                   AND EXISTS (
                       SELECT 1
                       FROM pg_class c
                       JOIN pg_namespace n ON n.oid = c.relnamespace
                       WHERE n.nspname = 'public'
                         AND c.relname = 'organizations'
                         AND c.relrowsecurity
                         AND (c.relforcerowsecurity
                              OR NOT pg_has_role(current_user, c.relowner, 'MEMBER'))
                   )
                   AND COALESCE(current_setting('app.current_org_id', true), '') = ''
              INTO v_blind;

            IF v_blind THEN
                RAISE WARNING 'Migration 149: the migration role % is subject to row-level security on `organizations` (FORCE RLS, mig 103) and no app.current_org_id is bound, so this migration could not read that table. The org enumeration above saw ONLY the orgs reachable through the custom_roles leg, and the orphan report below is blind to the rest — so the owner backfill CANNOT BE CONFIRMED COMPLETE from this run, whether or not it actually missed anything. Verify with a BYPASSRLS role: psql -c "SELECT o.org_id FROM organizations o WHERE NOT EXISTS (SELECT 1 FROM role_assignments ra JOIN custom_roles cr ON cr.id=ra.role_id AND cr.org_id=ra.org_id WHERE ra.org_id=o.org_id AND cr.name=''owner'' AND (ra.expires_at IS NULL OR ra.expires_at > NOW()))" — assign the first owner for each row it returns with POST /api/v1/admin/organizations/{org_id}/owner (ADMIN_API_KEY). An empty result means nothing was missed.', current_user;
            END IF;
        END;

        RAISE NOTICE 'Migration 149: granted % owner assignment(s) across existing orgs', v_total;
        IF v_orphans > 0 THEN
            -- NOT an error: an org whose only principals were viewers never had
            -- sso:configure to preserve, so nothing regressed for it. It is
            -- surfaced so operators know the break-glass path exists.
            RAISE NOTICE 'Migration 149: % org(s) still have no owner (no principal held sso:configure pre-upgrade). Use POST /api/v1/admin/organizations/{org_id}/owner (ADMIN_API_KEY) to assign the first owner — see UPGRADING.md.', v_orphans;
        END IF;
    END;

    RAISE NOTICE 'Migration 149: owner backfill + bootstrap complete';
END $$;

-- ============================================================================
-- Verification — fail loudly if the migration left an inconsistent state.
-- ============================================================================
DO $$
DECLARE
    v_bad INTEGER;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'role_assignments'
    ) THEN
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'ensure_org_owner_assignment') THEN
        RAISE EXCEPTION 'Migration 149 failed: ensure_org_owner_assignment missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'ensure_org_owner_backfill') THEN
        RAISE EXCEPTION 'Migration 149 failed: ensure_org_owner_backfill missing';
    END IF;
    -- The reseed_org_owner_on_contact_change assertion is GONE (#3003/#3015):
    -- this migration no longer creates that trigger, so asserting its presence
    -- would abort the chain — and run.go log.Fatalf's on a failed migration,
    -- making that a permanent agent boot loop.
    IF EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'reseed_org_owner_on_contact_change' AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION 'Migration 149 failed: reseed_org_owner_on_contact_change trigger is present; it confers owner anonymously on a contact_email change (#3003) and must not exist';
    END IF;
    IF has_function_privilege('public',
        'ensure_org_owner_assignment(character varying, character varying, character varying, timestamp with time zone)',
        'EXECUTE') THEN
        RAISE EXCEPTION 'Migration 149 failed: PUBLIC can EXECUTE ensure_org_owner_assignment';
    END IF;

    -- COMPLETENESS: every principal that held sso:configure pre-upgrade must
    -- now hold owner. A miss here means the backfill under-covered and some
    -- admin silently lost SSO configuration. Rows carrying the backfill marker
    -- are excluded from the QUALIFIER set for the same reason as below — an
    -- owner grant would otherwise qualify itself and hide an under-coverage.
    SELECT COUNT(*) INTO v_bad
    FROM (
        SELECT DISTINCT ra.org_id, ra.user_email
        FROM role_assignments ra
        JOIN custom_roles cr ON cr.id = ra.role_id AND cr.org_id = ra.org_id
        WHERE COALESCE(ra.assigned_by, '') <> 'migration:149_owner_backfill'
          -- Same scoping as the reconcile loop above (#3005 R3 M3). The loop
          -- enumerates organizations UNION the non-empty system-role org_ids,
          -- and ensure_org_owner_backfill('') returns 0 by design — so an
          -- org_id='' principal can never be reconciled. Judging one here that
          -- the loop cannot reach is the loop-vs-verify mismatch that RAISEs,
          -- aborts the migration, and crash-loops the agent at boot. This is
          -- the same class #3005-C fixed in 148; 148's comment claimed it had
          -- already been closed on 149, but the qualifier set here was never
          -- scoped. Verify set must stay a subset of the loop set.
          AND ra.org_id IS NOT NULL AND ra.org_id <> ''
          AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
          AND (cr.permissions @> '["*"]'::jsonb
               OR cr.permissions @> '["sso:configure"]'::jsonb)
          AND EXISTS (
              SELECT 1 FROM custom_roles o
              WHERE o.org_id = ra.org_id AND o.name = 'owner' AND o.is_system
          )
    ) q
    WHERE NOT EXISTS (
        SELECT 1
        FROM role_assignments ra2
        JOIN custom_roles cr2 ON cr2.id = ra2.role_id AND cr2.org_id = ra2.org_id
        -- CANONICAL equality (#3000 R3 F3, #3015 BLOCKER 2). The choke point
        -- stores axonflow_canonical_email(...), while this
        -- check enumerates qualifiers by their RAW user_email (the portal
        -- AssignRole API and SCIM both store raw). Raw equality here would
        -- therefore fail to see the owner row the backfill just created for
        -- any mixed-case principal, and a hand re-run of 149 -- a documented
        -- recovery action -- would abort. Repair writes canonical, so verify
        -- must compare canonical THROUGH THE SAME FUNCTION — lower(btrim(...))
        -- is NOT the same function: btrim strips ASCII space only, so the two
        -- disagree on any address carrying a tab or NBSP and this check aborts.
        WHERE ra2.org_id = q.org_id
          AND axonflow_canonical_email(ra2.user_email) = axonflow_canonical_email(q.user_email)
          AND cr2.name = 'owner'
          AND (ra2.expires_at IS NULL OR ra2.expires_at > NOW())
    );
    IF v_bad > 0 THEN
        RAISE EXCEPTION 'Migration 149 failed: % principal(s) held sso:configure pre-upgrade but hold no owner role', v_bad;
    END IF;

    -- NO ESCALATION: every owner assignment THIS migration created must belong
    -- to a principal that qualified. A hit here means the backfill widened.
    -- The qualifier subquery EXCLUDES rows carrying the backfill marker — an
    -- owner grant obviously carries "*"/sso:configure, so without that
    -- exclusion every backfilled row would justify itself and the check would
    -- be vacuous.
    --
    -- The `ra` side is ALSO filtered on live-ness (#3005 R3 F1). Without it
    -- this check judges EXPIRED backfilled rows against a LIVE-only qualifier
    -- subquery — the same live-vs-expired mismatch as the bug this migration
    -- fixes, one row-shape further on. Concretely: alice holds `admin`
    -- expiring in 30 days at upgrade time, so 149 backfills her an owner grant
    -- with the same expiry. Thirty-one days later both rows are expired; on a
    -- re-application (DR restore into a fresh schema, clone-to-staging, a
    -- truncated schema_migrations, any manual replay) the expired backfilled
    -- row still matches, no LIVE qualifier exists, and the migration aborts —
    -- unrecoverably, because a re-run fails identically. An expired grant
    -- confers nothing, so it cannot be an escalation and has no business in
    -- this check.
    --
    -- IT ALSO TOLERATES A QUALIFIER MIGRATION 150 LEGITIMATELY COLLAPSED
    -- (#3005 follow-up). 150 collapses every (org, role, canonical-email) class
    -- down to ONE row so its re-key UPDATE cannot collide on
    -- uq_role_assignments_user_role. On a replay the class it collapses often
    -- holds exactly two rows: the org-login identity's ORIGINAL owner grant
    -- (from 149's org-creation trigger, keyed on the RAW contact_email) and the
    -- CANONICAL owner row this backfill created for the same principal. The
    -- canonical row wins, the raw one is deleted — and the deleted row was the
    -- only qualifier justifying the survivor, so a second pass of 149 aborted:
    --   "Migration 149 failed: 8 backfilled owner assignment(s) went to
    --    principals that did not hold sso:configure pre-upgrade (escalation)"
    -- Unrecoverable, and run.go log.Fatalf's on it, so a permanent boot loop.
    --
    -- Collapsing two spellings of ONE principal's owner grant is not an
    -- escalation: the principal held owner before and after, and only the key's
    -- spelling changed. So the check tolerates it — but ONLY for the identity
    -- whose qualifier the collapse can actually remove.
    --
    -- The scope comes from 150's collapse predicate, not from guesswork: 150
    -- ranks and deletes exclusively within
    --   axonflow_canonical_email(user_email) = axonflow_org_login_identity(o.contact_email)
    -- so the org-login identity is the ONLY principal whose qualifier it can
    -- delete.
    --
    -- IT IS SPELLED SLIGHTLY WIDER THAN THAT, DELIBERATELY. This clause uses
    -- axonflow_canonical_email + a non-blank test rather than
    -- axonflow_org_login_identity, because that function is defined by
    -- migration 150 and THIS file must still run standalone on a chain where
    -- 150 has not applied yet — referencing it would abort 149 on every fresh
    -- database. The delta is exactly one shape: an org whose contact_email is
    -- itself a reserved synthetic (@axonflow.local / @axonflow.internal), which
    -- axonflow_org_login_identity maps to NULL and this clause does not. So for
    -- that org the tolerance is an EXEMPTION rather than a strict consequence
    -- of the collapse. It is still not a hole: 150 DELETES every
    -- synthetic-keyed system owner grant outright and verifies that none
    -- survives, and pre-150 the org-creation trigger granted that identity
    -- owner unconditionally anyway, so the backfill is never what conferred it.
    -- Every other principal stays fully checked, and a genuine widening
    -- (a backfilled owner for someone who held no qualifying role) still aborts
    -- — pinned by TestMigration149StillCatchesGenuineEscalation_RealPostgres,
    -- which would otherwise make this a hole rather than a tolerance.
    --
    -- Nor is it a widening for that identity: 149's own org-creation trigger
    -- grants owner to the org-login identity unconditionally, and the portal
    -- re-grants it on every boot (EnsureDeploymentOrgOwner), so the backfill is
    -- never what conferred it.
    --
    -- Belt and braces: migration 150's collapse now also TRANSFERS the deleted
    -- row's provenance onto the survivor, so on a stack running the current
    -- files this shape does not arise at all. This clause repairs the databases
    -- where it already did.
    SELECT COUNT(*) INTO v_bad
    FROM role_assignments ra
    JOIN custom_roles cr ON cr.id = ra.role_id AND cr.org_id = ra.org_id
    WHERE ra.assigned_by = 'migration:149_owner_backfill'
      AND cr.name = 'owner'
      AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
      AND NOT EXISTS (
          SELECT 1 FROM organizations o
          WHERE o.org_id = ra.org_id
            AND axonflow_canonical_email(o.contact_email) <> ''
            AND axonflow_canonical_email(o.contact_email)
                = axonflow_canonical_email(ra.user_email)
      )
      AND NOT EXISTS (
          SELECT 1
          FROM role_assignments q
          JOIN custom_roles qc ON qc.id = q.role_id AND qc.org_id = q.org_id
          -- CANONICAL equality, for the same reason as the completeness
          -- check above: the grant this migration creates is stored
          -- canonically by mig 150's choke point.
          WHERE q.org_id = ra.org_id
            AND axonflow_canonical_email(q.user_email) = axonflow_canonical_email(ra.user_email)
            AND COALESCE(q.assigned_by, '') <> 'migration:149_owner_backfill'
            AND (q.expires_at IS NULL OR q.expires_at > NOW())
            AND (qc.permissions @> '["*"]'::jsonb
                 OR qc.permissions @> '["sso:configure"]'::jsonb)
      );
    IF v_bad > 0 THEN
        RAISE EXCEPTION 'Migration 149 failed: % backfilled owner assignment(s) went to principals that did not hold sso:configure pre-upgrade (escalation)', v_bad;
    END IF;

    RAISE NOTICE 'Migration 149 verified: backfill complete and non-widening, choke point installed';
END $$;

COMMIT;
