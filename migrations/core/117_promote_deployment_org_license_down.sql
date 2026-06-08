-- Rollback for migration 117: promote_deployment_org_license
--
-- Drops the boot-time license-tier promotion helper. Safe to run: nothing
-- else references it (the only caller is the agent boot path, which no-ops if
-- the function is absent — it treats a failed SELECT as a logged warning, not
-- a fatal). Rolling this back leaves organizations.tier at whatever value the
-- last promotion wrote; it does NOT revert promoted rows to 'Community'.

BEGIN;

DROP FUNCTION IF EXISTS promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMP);

COMMIT;
