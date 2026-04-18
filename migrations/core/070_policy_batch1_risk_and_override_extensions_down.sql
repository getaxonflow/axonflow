-- Down migration for 070_policy_batch1_risk_and_override_extensions.sql

BEGIN;

DROP INDEX IF EXISTS idx_audit_decision_id;

DROP TRIGGER IF EXISTS trg_static_policies_critical_no_override ON static_policies;
DROP TRIGGER IF EXISTS trg_dynamic_policies_critical_no_override ON dynamic_policies;
DROP FUNCTION IF EXISTS enforce_critical_no_override();

DROP INDEX IF EXISTS idx_policy_overrides_expiry_v2;
DROP INDEX IF EXISTS idx_policy_overrides_lookup_v2;

ALTER TABLE policy_overrides
    DROP COLUMN IF EXISTS tool_signature,
    DROP COLUMN IF EXISTS revoked_at,
    DROP COLUMN IF EXISTS revoked_by;

ALTER TABLE policy_overrides
    DROP CONSTRAINT IF EXISTS policy_overrides_action_override_check;

ALTER TABLE policy_overrides
    ADD CONSTRAINT policy_overrides_action_override_check
    CHECK (action_override IN ('block', 'warn', 'log'));

ALTER TABLE IF EXISTS dynamic_policies
    DROP COLUMN IF EXISTS allow_override,
    DROP COLUMN IF EXISTS risk_level;

ALTER TABLE IF EXISTS static_policies
    DROP COLUMN IF EXISTS allow_override,
    DROP COLUMN IF EXISTS risk_level;

COMMIT;
