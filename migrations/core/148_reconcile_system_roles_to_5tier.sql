-- Migration 148: reconcile the seeded system roles to the #2993 five-tier model
-- Date: 2026-07-21
-- Purpose: mig 146 seeded SIX system roles (admin/owner/policy_admin/developer/
--          member/viewer) create-if-absent (ON CONFLICT DO NOTHING), with
--          permission bundles drawn from the full authoring palette — several
--          of which are not enforced anywhere on the portal plane (the #2993
--          seed-vs-enforce bug). This migration:
--            1. redefines ensure_org_system_roles to UPSERT the FIVE canonical
--               roles to the enforced-only permission bundles (source of truth:
--               ee/platform/customer-portal/api/roles/types.go CanonicalSystemRoles),
--            2. drops the seeded 'member' system role where nothing references
--               it (member left the model; a referenced member row is left
--               inert, mirroring 146-down), and
--            3. re-runs the backfill so EXISTING orgs are corrected, not just
--               new ones.
--
-- The org-creation trigger seed_org_system_roles (mig 146) is unchanged; it
-- calls ensure_org_system_roles, so redefining the function reconciles new orgs
-- automatically too.
--
-- SAFETY — never clobber customer data:
--   * The UPSERT's DO UPDATE is guarded WHERE custom_roles.is_system, so a
--     CUSTOM role (is_system=false) that happens to share a canonical name is
--     never overwritten (its row wins the conflict and is left untouched).
--   * role_assignments (manual admin grants AND SCIM-synced) and SCIM group
--     mappings are NOT touched — this migration only rewrites the system role
--     DEFINITIONS. Manual assignments are preserved by construction.
--   * The 'member' delete is guarded by NOT EXISTS on role_assignments (its FK
--     is ON DELETE CASCADE, so an unguarded delete would silently drop user
--     assignments) and wrapped so any other RESTRICT reference just skips it.
--
-- Canonical bundles (must match CanonicalSystemRoles + EnforcedPermissions):
--   admin        ["*"]                                          -- all except owner-reserved (sso:configure)
--   owner        ["*","sso:configure"]                          -- TRUE superset of admin (resolver classifies owner even with "*")
--   policy_admin ["policy:write","policy:delete","audit:read","token:rotate:self"] -- real policy admin (#2996) + tenant reads
--   developer    ["token:rotate:self"]                          -- own-rows; the write viewer lacks
--   viewer       ["audit:read"]                                 -- read-only
--
-- custom_roles is org_id-keyed, RLS-enabled; the seeder is SECURITY DEFINER
-- owned by axonflow_platform_admin (BYPASSRLS) — same posture as mig 146/145.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'custom_roles'
    ) THEN
        RAISE NOTICE 'Migration 148: custom_roles does not exist - skipping';
        RETURN;
    END IF;

    -- Redefine the workhorse: UPSERT the five canonical system roles for one
    -- org, idempotently, and prune a stray 'member'. Permission sets are the
    -- SINGLE source of truth; keep them in lockstep with roles/types.go
    -- CanonicalSystemRoles + the role_model_lockstep_test.
    EXECUTE $fn$
        CREATE OR REPLACE FUNCTION ensure_org_system_roles(p_org_id VARCHAR)
        RETURNS INTEGER
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $body$
        DECLARE
            v_changed INTEGER := 0;
        BEGIN
            IF p_org_id IS NULL OR p_org_id = '' THEN
                RETURN 0;
            END IF;

            -- (name, display_name, description, permissions) — id is omitted so
            -- new rows take the gen_random_uuid() default (no synthetic-id PK
            -- collisions). DO UPDATE corrects existing SYSTEM rows to canonical;
            -- WHERE is_system leaves a same-named custom role untouched.
            INSERT INTO custom_roles (org_id, name, display_name, description, permissions, is_system, created_by)
            VALUES
                (p_org_id, 'admin', 'Administrator',
                 'Full access except owner-reserved organization identity configuration',
                 '["*"]'::jsonb, true, 'system'),
                (p_org_id, 'owner', 'Owner',
                 'Full access (superset of admin) including SSO/SCIM/detection-posture configuration; tenant-wide reads',
                 '["*","sso:configure"]'::jsonb, true, 'system'),
                (p_org_id, 'policy_admin', 'Policy Administrator',
                 'Manages governance policies (create/edit/delete); tenant-wide audit & decision visibility; rotates own token; no identity/user administration',
                 '["policy:write","policy:delete","audit:read","token:rotate:self"]'::jsonb, true, 'system'),
                (p_org_id, 'developer', 'Developer',
                 'Own-rows access; rotates own per-user API token',
                 '["token:rotate:self"]'::jsonb, true, 'system'),
                (p_org_id, 'viewer', 'Viewer',
                 'Read-only access',
                 '["audit:read"]'::jsonb, true, 'system')
            ON CONFLICT (org_id, name) DO UPDATE
                SET display_name = EXCLUDED.display_name,
                    description  = EXCLUDED.description,
                    permissions  = EXCLUDED.permissions,
                    updated_at   = NOW()
                WHERE custom_roles.is_system;

            GET DIAGNOSTICS v_changed = ROW_COUNT;

            -- Prune the dropped 'member' SYSTEM role when unreferenced. A
            -- referenced member row is left inert (its assignments keep working
            -- as own-rows; pre-#2993 code ignored the name anyway). Two FKs point
            -- at custom_roles(id): role_assignments (ON DELETE CASCADE, so an
            -- unguarded delete would silently drop user assignments) and
            -- scim_groups.mapped_role_id (ON DELETE SET NULL, so an unguarded
            -- delete would silently NULL a SCIM group mapping). Guard BOTH — the
            -- SET-NULL one is existence-checked because scim_groups is an
            -- Enterprise table that may be absent. The BEGIN/EXCEPTION also skips
            -- the delete on any future RESTRICT reference.
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'scim_groups'
                ) THEN
                    DELETE FROM custom_roles cr
                     WHERE cr.org_id = p_org_id
                       AND cr.name = 'member' AND cr.is_system AND cr.created_by = 'system'
                       AND NOT EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.role_id = cr.id)
                       AND NOT EXISTS (SELECT 1 FROM scim_groups sg WHERE sg.mapped_role_id = cr.id);
                ELSE
                    DELETE FROM custom_roles cr
                     WHERE cr.org_id = p_org_id
                       AND cr.name = 'member' AND cr.is_system AND cr.created_by = 'system'
                       AND NOT EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.role_id = cr.id);
                END IF;
            EXCEPTION
                WHEN foreign_key_violation THEN
                    RAISE NOTICE 'ensure_org_system_roles: member role for org % still referenced; left in place', p_org_id;
                WHEN insufficient_privilege THEN
                    -- The SECURITY DEFINER runs as platform_admin; if the mig-098
                    -- SELECT grant on role_assignments/scim_groups is absent the
                    -- read raises insufficient_privilege. Skip the prune rather
                    -- than abort the whole reconcile (the member row is left inert).
                    RAISE NOTICE 'ensure_org_system_roles: member prune skipped for org % (missing SELECT grant); left in place', p_org_id;
            END;

            RETURN v_changed;
        END;
        $body$;
    $fn$;

    EXECUTE $c$
        COMMENT ON FUNCTION ensure_org_system_roles(VARCHAR) IS
            'Idempotently UPSERTs the five #2993 canonical system roles '
            '(admin/owner/policy_admin/developer/viewer) for an org and prunes a '
            'stray member. SECURITY DEFINER (BYPASSRLS via axonflow_platform_admin). '
            'DO UPDATE is is_system-guarded so custom roles are never clobbered. '
            'Permission sets are lockstep with roles/types.go CanonicalSystemRoles '
            '(#2993).'
    $c$;

    -- The org-creation trigger (mig 146) already routes through this function.
    -- Re-assert it so 148 is self-contained even on a DB where 146's trigger
    -- was dropped.
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'seed_org_system_roles' AND NOT tgisinternal
    ) THEN
        DROP TRIGGER IF EXISTS seed_org_system_roles ON organizations;
        CREATE TRIGGER seed_org_system_roles
            AFTER INSERT ON organizations
            FOR EACH ROW
            EXECUTE FUNCTION trg_ensure_org_system_roles();
        RAISE NOTICE 'Migration 148: re-created seed_org_system_roles trigger';
    END IF;

    -- Reconcile every EXISTING org.
    DECLARE
        v_org   RECORD;
        v_total INTEGER := 0;
        v_n     INTEGER;
    BEGIN
        -- Enumerate every org that HAS system roles, not just those with an
        -- `organizations` row. Migration 023 seeded system roles keyed on the
        -- DISTINCT tenant_id values in dynamic_policies — pseudo-tenants such
        -- as 'global' that never get an organizations row. Iterating
        -- organizations alone leaves those rows on their pre-148 bundles,
        -- which the verification block below then catches GLOBALLY and turns
        -- into `Migration 148 failed: N system role(s) not reconciled` — the
        -- migration aborts on any real upgrade path that ran 023. (#2997)
        FOR v_org IN
            SELECT org_id FROM organizations
            UNION
            SELECT DISTINCT org_id FROM custom_roles WHERE is_system AND org_id IS NOT NULL AND org_id <> ''
        LOOP
            v_n := ensure_org_system_roles(v_org.org_id);
            v_total := v_total + v_n;
        END LOOP;
        RAISE NOTICE 'Migration 148: reconciled % system-role row(s) across existing orgs', v_total;
    END;

    -- Owner hardening (mirrors mig 146/145): pin to axonflow_platform_admin so
    -- the definer's rights bypass the custom_roles RLS policy. Idempotent.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        EXECUTE 'ALTER FUNCTION ensure_org_system_roles(VARCHAR) OWNER TO axonflow_platform_admin';
    END IF;
    EXECUTE 'REVOKE EXECUTE ON FUNCTION ensure_org_system_roles(VARCHAR) FROM PUBLIC';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION ensure_org_system_roles(VARCHAR) TO axonflow_app_role';
    END IF;

    RAISE NOTICE 'Migration 148: system-role reconcile complete';
END $$;

-- Verification — fail loudly if the reconcile left a seed inconsistent.
DO $$
DECLARE
    v_bad INTEGER;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'custom_roles'
    ) THEN
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'ensure_org_system_roles') THEN
        RAISE EXCEPTION 'Migration 148 failed: ensure_org_system_roles missing';
    END IF;

    -- SCOPE (#3005-C): both checks below MUST be scoped to the same org set the
    -- reconcile loop enumerated — `org_id IS NOT NULL AND org_id <> ''`. The
    -- loop already excludes those rows and ensure_org_system_roles('') returns 0
    -- by design, so a system role carrying org_id = '' (or NULL) can NEVER be
    -- reconciled or pruned. Judging it here anyway aborts the whole migration
    -- with "1 system role(s) not reconciled" and crash-loops the agent — the
    -- identical loop-vs-verify mismatch already fixed twice on this file (the
    -- orphan-org case) and once on 149. Verify exactly what was reconciled.

    -- No SYSTEM 'member' role may survive UNLESS it is referenced — a referenced
    -- one is deliberately left inert. "Referenced" MUST match the delete's
    -- skip-set above (role_assignments, plus scim_groups where the table exists),
    -- or the migration false-fails. Branch on table existence so a genuinely
    -- unreferenced survivor is still caught in BOTH deployment shapes.
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'scim_groups'
    ) THEN
        SELECT COUNT(*) INTO v_bad
        FROM custom_roles cr
        WHERE cr.name = 'member' AND cr.is_system AND cr.created_by = 'system'
          AND cr.org_id IS NOT NULL AND cr.org_id <> ''
          AND NOT EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.role_id = cr.id)
          AND NOT EXISTS (SELECT 1 FROM scim_groups sg WHERE sg.mapped_role_id = cr.id);
    ELSE
        SELECT COUNT(*) INTO v_bad
        FROM custom_roles cr
        WHERE cr.name = 'member' AND cr.is_system AND cr.created_by = 'system'
          AND cr.org_id IS NOT NULL AND cr.org_id <> ''
          AND NOT EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.role_id = cr.id);
    END IF;
    IF v_bad > 0 THEN
        RAISE EXCEPTION 'Migration 148 failed: % unreferenced member system role(s) survived the prune', v_bad;
    END IF;

    -- Every system role, if present, must carry EXACTLY its canonical bundle
    -- (jsonb equality is order-insensitive). Kept in lockstep with the Go
    -- CanonicalSystemRoles source of truth.
    SELECT COUNT(*) INTO v_bad
    FROM custom_roles cr
    WHERE cr.is_system
      AND cr.org_id IS NOT NULL AND cr.org_id <> ''
      AND (
        (cr.name = 'admin'        AND cr.permissions <> '["*"]'::jsonb) OR
        (cr.name = 'owner'        AND cr.permissions <> '["*","sso:configure"]'::jsonb) OR
        (cr.name = 'policy_admin' AND cr.permissions <> '["policy:write","policy:delete","audit:read","token:rotate:self"]'::jsonb) OR
        (cr.name = 'developer'    AND cr.permissions <> '["token:rotate:self"]'::jsonb) OR
        (cr.name = 'viewer'       AND cr.permissions <> '["audit:read"]'::jsonb)
    );
    IF v_bad > 0 THEN
        RAISE EXCEPTION 'Migration 148 failed: % system role(s) not reconciled to their canonical bundle', v_bad;
    END IF;

    RAISE NOTICE 'Migration 148 verified: seeder reconciled, member pruned, policy_admin canonical';
END $$;

COMMIT;
