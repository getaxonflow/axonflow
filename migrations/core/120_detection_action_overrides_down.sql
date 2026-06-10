-- Migration 120 DOWN: drop the per-(org, category) detection-action override
-- table (#2581).
--
-- Reversible: the table holds only operator-set posture overrides. Dropping it
-- reverts every org to the deployment-global env config (PII_ACTION etc), which
-- is the pre-#2581 behavior. Safe to re-run.

BEGIN;

DROP POLICY IF EXISTS detection_action_overrides_org_isolation ON detection_action_overrides;
DROP TABLE IF EXISTS detection_action_overrides;

COMMIT;
