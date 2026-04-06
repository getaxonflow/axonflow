-- Migration 064: Cursor IDE + OpenAI Codex Integration Policies
-- Date: 2026-04-06
-- Purpose: Pre-load integration-specific policies for Cursor IDE and OpenAI Codex.
--          Policies start disabled and are activated when the integration is detected.
-- Related: Epic #1514 (Multi-Platform Plugin Ecosystem)

-- =============================================================================
-- Cursor IDE Integration Policies (pre-loaded as DISABLED)
-- Activated when: connector_type starts with "cursor." or
--                 AXONFLOW_INTEGRATIONS includes "cursor"
-- =============================================================================

INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, tenant_id, phase, action_request, action_response, enabled)
VALUES
  ('int_cursor_settings', 'Cursor Settings Protection', 'security-dangerous', '(\.cursor/settings\.json|\.cursor/config\.json)', 'high', 'Block modification of Cursor IDE settings files', 'block', 'global', 'request', 'block', NULL, false),
  ('int_cursor_hooks', 'Cursor Hooks Protection', 'security-dangerous', '(\.cursor-plugin/.*\.json|\.cursor/hooks/.*)', 'medium', 'Warn on modification of Cursor plugin and hook configurations', 'warn', 'global', 'request', 'warn', NULL, false),
  ('int_cursor_rules', 'Cursor Rules Protection', 'security-dangerous', '(\.cursor/rules/.*\.mdc|\.cursorrules)', 'medium', 'Warn on modification of Cursor rules files', 'warn', 'global', 'request', 'warn', NULL, false)
ON CONFLICT (policy_id) DO NOTHING;

-- =============================================================================
-- OpenAI Codex Integration Policies (pre-loaded as DISABLED)
-- Activated when: connector_type starts with "codex." or
--                 AXONFLOW_INTEGRATIONS includes "codex"
-- =============================================================================

INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, tenant_id, phase, action_request, action_response, enabled)
VALUES
  ('int_codex_settings', 'Codex Plugin Settings Protection', 'security-dangerous', '(\.codex-plugin/.*\.json)', 'high', 'Block modification of Codex plugin configuration files', 'block', 'global', 'request', 'block', NULL, false)
ON CONFLICT (policy_id) DO NOTHING;

-- Note: int_codex_skills policy removed. Skill files (SKILL.md) are read-only
-- instructions that Codex reads to follow governance guidance. A regex-based
-- policy cannot distinguish reads from writes and causes false positives
-- when Codex loads its own skill files.
