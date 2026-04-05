-- Migration 059: Dangerous Command System Policies
-- Date: 2026-04-03
-- Purpose: Add system policies for blocking dangerous shell commands,
--          reverse shells, credential access, SSRF, path traversal,
--          and agent config file tampering.
-- Related: Issue #1484 (Claude Code Plugin), OpenClaw starter policies
--
-- NOTE: Go's RE2 regex engine treats \| as alternation, not literal pipe.
-- Patterns match the dangerous COMBINATION (e.g., curl+shell) rather than
-- requiring a literal pipe character.

-- Dangerous Command Execution
INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, tenant_id, phase, action_request, action_response)
VALUES
  ('sys_dangerous_reverse_shell', 'Reverse Shell Blocking', 'security-dangerous', '(nc\s+-e|bash\s+-i|/dev/tcp/|python\s+-c.*socket|perl\s+-e.*socket|ruby\s+-rsocket)', 'critical', 'Block reverse shell and remote code execution patterns', 'block', 'global', 'request', 'block', NULL),
  ('sys_dangerous_destructive_fs', 'Destructive Filesystem Operations', 'security-dangerous', '(rm\s+-rf\s+/|rm\s+-rf\s+~|dd\s+if=|mkfs\b|>\s*/dev/sd|chmod\s+-R\s+777\s+/)', 'critical', 'Block destructive filesystem operations', 'block', 'global', 'request', 'block', NULL),
  ('sys_dangerous_credential_access', 'Credential File Access', 'security-dangerous', '(cat\s+.*\.ssh/|cat\s+.*\.aws/|cat\s+.*\.env\b|cat\s+.*\.netrc|cat\s+.*\.gnupg/|printenv\s+.*KEY|printenv\s+.*SECRET|printenv\s+.*TOKEN)', 'high', 'Block credential file and environment variable access', 'block', 'global', 'request', 'block', NULL),
  ('sys_dangerous_shell_download', 'Download and Execute', 'security-dangerous', '(curl\s+\S+.*\s+(ba)?sh|wget\s+\S+.*\s+(ba)?sh|curl\s+\S+.*\spython|wget\s+\S+.*\spython)', 'critical', 'Block fetching remote content and executing via shell', 'block', 'global', 'request', 'block', NULL)
ON CONFLICT (policy_id) DO NOTHING;

-- SSRF Prevention
INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, tenant_id, phase, action_request, action_response)
VALUES
  ('sys_dangerous_cloud_metadata', 'Cloud Metadata Endpoint Access', 'security-dangerous', '(169\.254\.169\.254|metadata\.google\.internal|metadata\.aws)', 'critical', 'Block cloud metadata endpoint access (SSRF protection)', 'block', 'global', 'request', 'block', NULL),
  ('sys_dangerous_internal_network', 'Internal Network Access', 'security-dangerous', '(localhost:\d{4,5}|127\.0\.0\.1:\d{4,5}|0\.0\.0\.0:\d{4,5})', 'high', 'Block requests targeting internal network services', 'block', 'global', 'request', 'block', NULL)
ON CONFLICT (policy_id) DO NOTHING;

-- Agent Config File Protection
-- NOTE: Integration-specific config protection (OpenClaw SOUL.md, Claude Code .claude/settings)
-- is in migrations/integrations/{openclaw,claude-code}/. This core policy catches generic
-- sensitive config file patterns that apply universally.
INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, tenant_id, phase, action_request, action_response)
VALUES
  ('sys_dangerous_agent_config', 'Agent Config File Protection', 'security-dangerous', '(\.env\b|\.env\.local|\.env\.production|credentials\.json|service-account\.json)', 'high', 'Block modification of environment and credential configuration files', 'block', 'global', 'request', 'block', NULL)
ON CONFLICT (policy_id) DO NOTHING;

-- Path Traversal
INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, tenant_id, phase, action_request, action_response)
VALUES
  ('sys_dangerous_path_traversal', 'Path Traversal Detection', 'security-dangerous', '(\.\./\.\./|/etc/passwd|/etc/shadow|/proc/self)', 'high', 'Block path traversal and sensitive system file access', 'block', 'global', 'request', 'block', NULL)
ON CONFLICT (policy_id) DO NOTHING;

-- Code Execution Patterns
INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, tenant_id, phase, action_request, action_response)
VALUES
  ('sys_dangerous_eval_exec', 'Dynamic Code Execution', 'security-dangerous', '(eval\s*\(|exec\s*\(|__import__|subprocess\.call|os\.system\s*\(|os\.popen\s*\()', 'high', 'Block dynamic code execution patterns', 'block', 'global', 'request', 'block', NULL),
  ('sys_dangerous_package_install', 'Unauthorized Package Installation', 'security-dangerous', '(pip\s+install\s+--pre|npm\s+install\s+-g|gem\s+install|cargo\s+install).*(http|ftp|git://)', 'medium', 'Block package installation from untrusted remote sources', 'block', 'global', 'request', 'block', NULL)
ON CONFLICT (policy_id) DO NOTHING;
