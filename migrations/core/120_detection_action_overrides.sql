-- Migration 120: per-(org, category) detection-action override table
-- Date: 2026-06-10
-- Issue: #2581 (per-tenant/org PII posture — block/redact, not deployment-global)
--
-- WHY ----------------------------------------------------------------------
-- Today PII_ACTION (and the sibling SQLI / dangerous-* levers) is resolved
-- ONCE at agent boot and cached process-wide (detection_config.go
-- InitDetectionConfigs). That gives a SINGLE detection posture for the whole
-- deployment, so two teams sharing one agent cannot coexist when one needs
-- redact-for-chat and another needs block-for-batch.
--
-- This table lets an org override the deployment-global action per detection
-- category. The agent's MCP + gateway check paths consult a SHORT-TTL cache
-- of these rows (no per-request DB hit on the hot path) and fall back to the
-- global env config when an org has no override row. A deployment that never
-- writes a row behaves byte-identically to today.
--
-- Portal UX to SET these rows is an explicit FOLLOW-UP (#2581) — this
-- migration + the agent-side resolution are the engine half only.
--
-- RLS POSTURE: ENABLE + FORCE. org_id is the isolation key, matching the v9
-- Phase 8 convention (mig 107/110). The agent always reads/writes via
-- rls.WithOrgScope so app.current_org_id matches the row's org_id. Reads work
-- identically under AXONFLOW_DB_USE_APP_ROLE on (RLS enforced, GUC matches)
-- and off (RLS bypassed by the owner role, the explicit WHERE org_id still
-- scopes). ALTER DEFAULT PRIVILEGES (mig 098) auto-grants the new table to
-- axonflow_app_role + axonflow_platform_admin, so no per-table GRANT here.

BEGIN;

CREATE TABLE IF NOT EXISTS detection_action_overrides (
    org_id     VARCHAR(255) NOT NULL,
    category   VARCHAR(64)  NOT NULL,
    action     VARCHAR(16)  NOT NULL,
    updated_by VARCHAR(255),
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, category),
    CONSTRAINT detection_action_overrides_category_chk
        CHECK (category IN ('pii', 'sqli', 'dangerous_query', 'dangerous_command')),
    CONSTRAINT detection_action_overrides_action_chk
        CHECK (action IN ('block', 'redact', 'warn', 'log'))
);

ALTER TABLE detection_action_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_action_overrides FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS detection_action_overrides_org_isolation ON detection_action_overrides;
CREATE POLICY detection_action_overrides_org_isolation ON detection_action_overrides
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

COMMENT ON TABLE detection_action_overrides IS
    'Per-(org, category) detection-action override. Consulted (short-TTL cached) by the agent MCP + gateway check paths; falls back to the deployment-global env config (PII_ACTION etc) when absent. #2581.';
COMMENT ON COLUMN detection_action_overrides.category IS
    'Detection category: pii | sqli | dangerous_query | dangerous_command.';
COMMENT ON COLUMN detection_action_overrides.action IS
    'Override action: block | redact | warn | log. redact is meaningful only for pii.';

-- Verification — fail loudly if any artifact is missing (Principle 3).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables
                   WHERE table_name = 'detection_action_overrides') THEN
        RAISE EXCEPTION 'Migration 120 failed: detection_action_overrides table not created';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies
                   WHERE tablename = 'detection_action_overrides'
                     AND policyname = 'detection_action_overrides_org_isolation') THEN
        RAISE EXCEPTION 'Migration 120 failed: RLS policy not created';
    END IF;
    IF NOT (SELECT relrowsecurity AND relforcerowsecurity
              FROM pg_class WHERE relname = 'detection_action_overrides') THEN
        RAISE EXCEPTION 'Migration 120 failed: RLS not ENABLEd + FORCEd';
    END IF;
    RAISE NOTICE 'Migration 120 verified: detection_action_overrides present, RLS enabled+forced, isolation policy installed';
END
$$;

COMMIT;
