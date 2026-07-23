-- Migration 150 DOWN: restore the pre-#3000 owner choke point
-- Date: 2026-07-22
--
-- Reverts ensure_org_owner_assignment to migration 149's definition — the one
-- WITHOUT the real-identity guard. The helper functions 150 added are RETAINED
-- (see the note at the end of this file for why).
--
-- DELIBERATELY NOT restored: the owner assignments 150 deleted (those keyed on
-- a blank or reserved-synthetic user_email). They are unrecoverable from here —
-- the rows are gone — and re-creating them would mean a down-migration
-- re-opening the privilege hole it was rolled back from. Same philosophy as the
-- 148 and 149 DOWNs, neither of which resurrects data it pruned. An operator
-- who genuinely needs an owner after rolling back grants one deliberately via
-- POST /api/v1/admin/organizations/{org_id}/owner (ADMIN_API_KEY).
--
-- NOTE: rolling back 150 while running a post-#3000 portal binary is safe but
-- pointless — the application half of the fix (ResolveOrgBootstrapIdentity)
-- still never presents or grants a blank identity. The guard removed here is
-- the defense-in-depth half that also covers raw SQL and the DB triggers.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'role_assignments'
    ) THEN
        RAISE NOTICE 'Migration 150 down: role_assignments absent - skipping';
        RETURN;
    END IF;

    -- Restore migration 149's definition verbatim (no identity guard, raw
    -- user_email spelling).
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

            INSERT INTO role_assignments (org_id, user_email, role_id, assigned_by, assigned_at, expires_at, source)
            VALUES (p_org_id, COALESCE(p_user_email, ''), v_owner_role_id,
                    COALESCE(NULLIF(p_assigned_by, ''), 'system'), NOW(), p_expires_at, 'system')
            ON CONFLICT (org_id, user_email, role_id) DO NOTHING;

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
            '1=granted, 0=already held, -1=no system owner role for the org (#2997).'
    $c$;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        EXECUTE 'ALTER FUNCTION ensure_org_owner_assignment(VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ) OWNER TO axonflow_platform_admin';
    END IF;
    EXECUTE 'REVOKE EXECUTE ON FUNCTION ensure_org_owner_assignment(VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ) FROM PUBLIC';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION ensure_org_owner_assignment(VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ) TO axonflow_app_role';
    END IF;

    -- ALL THREE helper functions are deliberately RETAINED (#3000 R3 F2).
    --
    -- They are pure expressions, not state, and they are inert if never called
    -- — the same reasoning that preserves ensure_org_owner_assignment above.
    -- The rollback that matters is removing the GUARD CALL from inside the
    -- choke point, which the restored 149 body above already does.
    --
    -- They must be kept TOGETHER, because they form a call chain:
    --     axonflow_org_login_identity -> axonflow_is_grantable_identity
    --                                 -> axonflow_canonical_email
    -- plpgsql resolves callees at RUN time, so dropping any one of them leaves
    -- its callers installed but permanently raising
    --     function <dropped>(text) does not exist
    -- on every call — a landmine, not a rollback. An earlier revision of this
    -- file did exactly that.
    --
    -- Retention also keeps a future migration that consumes
    -- axonflow_org_login_identity (the org-login identity expression every
    -- migration should use instead of open-coding a COALESCE) working across a
    -- 150 rollback.
    --
    -- If you genuinely need them gone, drop them in dependency order:
    --   DROP FUNCTION IF EXISTS axonflow_org_login_identity(VARCHAR);
    --   DROP FUNCTION IF EXISTS axonflow_is_grantable_identity(VARCHAR);
    --   DROP FUNCTION IF EXISTS axonflow_canonical_email(VARCHAR);

    RAISE NOTICE 'Migration 150 down: pre-#3000 choke point restored, identity guard removed';
END $$;

COMMIT;
