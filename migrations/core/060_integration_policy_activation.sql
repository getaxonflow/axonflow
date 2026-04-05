-- Migration 060: Integration Policy Activation System
-- Date: 2026-04-04
-- Purpose: Enable automatic activation of integration-specific policies
--          when AxonFlow detects a connected integration (OpenClaw, Claude Code, etc.)
-- Related: Issue #1484 (Claude Code Plugin)
--
-- Architecture:
-- 1. Integration policies are pre-loaded as DISABLED in static_policies
-- 2. The integration_activations table tracks which integrations are active
-- 3. When an integration is detected (via MCP initialize, health check, or
--    AXONFLOW_INTEGRATIONS env var), its policies are enabled
-- 4. This avoids runtime migrations — only UPDATE statements on existing rows

-- =============================================================================
-- Integration Activations Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS integration_activations (
    integration_id VARCHAR(50) PRIMARY KEY,
    display_name VARCHAR(100) NOT NULL,
    activated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    activated_by VARCHAR(100) DEFAULT 'auto-detect',
    connector_prefix VARCHAR(50) NOT NULL,
    policy_count INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}'
);

-- =============================================================================
-- OpenClaw Integration Policies (pre-loaded as DISABLED)
-- Activated when: connector_type starts with "openclaw." or
--                 AXONFLOW_INTEGRATIONS includes "openclaw"
-- =============================================================================

INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, tenant_id, phase, action_request, action_response, enabled)
VALUES
  ('int_openclaw_agent_identity', 'OpenClaw Agent Identity Protection', 'security-dangerous', '(SOUL\.md|IDENTITY\.md|AGENTS\.md)', 'high', 'Block modification of OpenClaw agent identity files (prevents memory poisoning)', 'block', 'global', 'request', 'block', NULL, false),
  ('int_openclaw_agent_memory', 'OpenClaw Agent Memory Protection', 'security-dangerous', '(MEMORY\.md|\.openclaw/memory)', 'high', 'Block modification of OpenClaw agent persistent memory files', 'block', 'global', 'request', 'block', NULL, false),
  ('int_openclaw_config', 'OpenClaw Config Protection', 'security-dangerous', '(openclaw\.json|auth-profiles\.json|openclaw\.config)', 'high', 'Block modification of OpenClaw configuration and auth files', 'block', 'global', 'request', 'block', NULL, false)
ON CONFLICT (policy_id) DO NOTHING;

-- =============================================================================
-- Claude Code Integration Policies (pre-loaded as DISABLED)
-- Activated when: connector_type starts with "claude_code." or
--                 AXONFLOW_INTEGRATIONS includes "claude-code"
-- =============================================================================

INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, tenant_id, phase, action_request, action_response, enabled)
VALUES
  ('int_claude_settings', 'Claude Code Settings Protection', 'security-dangerous', '(\.claude/settings\.json|\.claude/settings\.local\.json)', 'high', 'Block modification of Claude Code settings files', 'block', 'global', 'request', 'block', NULL, false),
  ('int_claude_hooks', 'Claude Code Hooks Protection', 'security-dangerous', '(\.claude/hooks/.*\.json)', 'medium', 'Warn on modification of Claude Code hook configurations', 'warn', 'global', 'request', 'warn', NULL, false)
ON CONFLICT (policy_id) DO NOTHING;

-- =============================================================================
-- Activation function — called by the Agent when an integration is detected
-- or when AXONFLOW_INTEGRATIONS env var includes the integration
-- =============================================================================

CREATE OR REPLACE FUNCTION activate_integration(
    p_integration_id VARCHAR(50),
    p_display_name VARCHAR(100),
    p_connector_prefix VARCHAR(50),
    p_policy_prefix VARCHAR(50),
    p_activated_by VARCHAR(100) DEFAULT 'auto-detect'
) RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    -- Record the activation
    INSERT INTO integration_activations (integration_id, display_name, connector_prefix, activated_by)
    VALUES (p_integration_id, p_display_name, p_connector_prefix, p_activated_by)
    ON CONFLICT (integration_id) DO UPDATE SET
        activated_at = NOW(),
        activated_by = p_activated_by;

    -- Enable all policies for this integration.
    -- Uses p_policy_prefix (e.g., "int_openclaw", "int_claude") which matches
    -- the actual policy_id naming convention, not the integration ID which may
    -- contain dashes that don't appear in policy IDs.
    UPDATE static_policies
    SET enabled = true
    WHERE policy_id LIKE p_policy_prefix || '%'
      AND enabled = false;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    -- Update the policy count
    UPDATE integration_activations
    SET policy_count = v_count
    WHERE integration_id = p_integration_id;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql;
