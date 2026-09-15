-- Rollback for migration 175: promote_deployment_org_license reports the row
--
-- Restores migration 142's VOID-returning form, byte-for-byte in body and
-- privilege posture, so a rollback leaves the schema as 142 left it rather than
-- dropping the helper altogether (which would break the agent's boot-time
-- licence-tier sync entirely instead of merely un-verifying it).
--
-- DROP first for the same reason 175 and 142 do: CREATE OR REPLACE cannot
-- change a return type.
--
-- WHAT ROLLING THIS BACK COSTS. The write still happens; what is lost is the
-- agent's ability to tell a promotion that LANDED from one that returned
-- success having written nothing (#3957). An agent binary carrying the #3957
-- change reads the row from promote_deployment_org_license_RETURNING (#4007),
-- which this rollback drops - so the call errors and the agent reports a failed
-- promotion, which is the correct reading of a rolled-back schema rather than a
-- false alarm. The old name survives the rollback as 142's VOID form, so an
-- OLDER binary calling it is unaffected.
--
-- The pre-142 TIMESTAMP argument type is NOT restored: organizations.expires_at
-- is TIMESTAMPTZ from 142 onwards and this rollback does not revert 142.

BEGIN;

-- BOTH SIGNATURES, and the reason is 142's own COMMENT, not this file's (#4007
-- review). Re-running 142 - which the migration tests do at the fully-migrated
-- state - executes `COMMENT ON FUNCTION promote_deployment_org_license IS` at
-- 142:546 with no argument list. That statement raises "is not unique" the
-- moment two overloads are live, so a rollback that left the pre-142 TIMESTAMP
-- form behind would break 142's re-run rather than this file's. The ojk realpg
-- fixture censuses this name and expects exactly one overload
-- (ojk_realpg_fixture_test.go:156-168); the sebi one documents the expectation
-- without asserting it (sebi_readiness_realpg_test.go:93-98).
-- The _returning function is 175's own creation, so the rollback removes it
-- (#4007). The old name is then restored to 142's VOID body below, which is
-- what it was before this migration ran.
DROP FUNCTION IF EXISTS promote_deployment_org_license_returning(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ);

DROP FUNCTION IF EXISTS promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMP);
DROP FUNCTION IF EXISTS promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ);

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
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'organizations'
    ) THEN
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
    END IF;
END;
$$;

COMMENT ON FUNCTION promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ) IS
    'SECURITY DEFINER upsert that promotes the deployment org''s organizations '
    'row to its licensed tier/max_nodes/expires_at. Bypasses FORCE RLS on '
    'organizations (mig 103) for the agent boot-time license-tier sync (#2535). '
    'Mirrors register_org (mig 104) with an added expires_at column. '
    'p_expires_at is TIMESTAMPTZ as of mig 142 (#2876).';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE EXECUTE ON FUNCTION promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ) FROM PUBLIC;
        GRANT  EXECUTE ON FUNCTION promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ) TO axonflow_app_role;
    END IF;
END
$$;

COMMIT;
